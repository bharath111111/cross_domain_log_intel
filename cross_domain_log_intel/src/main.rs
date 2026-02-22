// Main CLI entrypoint
// Accepts two log files: qnx and android, parses, merges, classifies and emits comprehensive validation report

use anyhow::Result;
use std::env;
use std::fs;

mod models;
mod parser;
mod classifier;
mod metrics;
mod reporter;
mod decoder;
mod rules;

use models::{Domain, LogEntry};
use parser::parse_log;
use parser::parse_can_asc;
use classifier::classify_logs;
use metrics::generate_metrics;
use reporter::generate_html_report;

fn usage() {
    eprintln!("Usage: cargo run -- <qnx.log> <android.log> [--html <output.html>]");
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        usage();
        return Err(anyhow::anyhow!("expected at least two file arguments"));
    }

    let qnx_path = &args[1];
    let android_path = &args[2];

    // Parse logs
    let mut qnx_entries = parse_log(qnx_path, Domain::Qnx)?;
    let mut android_entries = parse_log(android_path, Domain::Android)?;
    
    // Optional CAN / ETH / DBC / RULES
    let mut can_frames: Option<Vec<crate::models::CanFrame>> = None;
    let mut eth_frames: Option<Vec<crate::models::EthFrame>> = None;
    let mut dbc_path: Option<String> = None;
    let mut rules_path: Option<String> = None;
    let mut i = 3;
    let mut html_path: Option<String> = None;
    while i < args.len() {
        match args[i].as_str() {
            "--can" => {
                if i + 1 < args.len() { can_frames = Some(parse_can_asc(&args[i+1])?); i += 2; continue; }
            }
            "--eth" => {
                if i + 1 < args.len() { eth_frames = Some(parser::parse_eth_log(&args[i+1])?); i += 2; continue; }
            }
            "--eth-pcapng" => {
                if i + 1 < args.len() { eth_frames = Some(parser::parse_pcapng_eth(&args[i+1])?); i += 2; continue; }
            }
            "--dbc" => { if i + 1 < args.len() { dbc_path = Some(args[i+1].clone()); i += 2; continue; } }
            "--rules" => { if i + 1 < args.len() { rules_path = Some(args[i+1].clone()); i += 2; continue; } }
            "--html" => { if i + 1 < args.len() { html_path = Some(args[i+1].clone()); i += 2; continue; } }
            _ => { i += 1; }
        }
    }

    // Merge and sort
    let mut all: Vec<LogEntry> = Vec::new();
    all.append(&mut qnx_entries);
    all.append(&mut android_entries);
    all.sort_by_key(|e| e.timestamp);

    // Extract load samples from raw entries
    let load_samples = parser::extract_load_samples(&all);

    // Classify and generate metrics
    let events = classify_logs(&all);
    let report = generate_metrics(&events, &load_samples);

    // Output JSON to console
    let json = serde_json::to_string_pretty(&report)?;
    println!("\n=== VALIDATION REPORT (JSON) ===");
    println!("{}", json);

    // Generate HTML if requested or default
    // Load DBC and rules if provided
    let mut dbc_map = None;
    if let Some(d) = dbc_path.as_deref() {
        if let Ok(m) = decoder::load_dbc(d) { dbc_map = Some(m); }
    }
    let mut loaded_rules = None;
    if let Some(rp) = rules_path.as_deref() {
        if let Ok(rs) = rules::load_rules(rp) { loaded_rules = Some(rs); }
    }

    // Run simple correlation: for each event, find matching rules triggered by CAN frames
    let mut correlations: Vec<(i64, String)> = Vec::new();
    // Impacts: rich structured data
    let mut impacts: Vec<models::ImpactDetail> = Vec::new();
    if let Some(frames) = can_frames.as_ref() {
        if let Some(ruleset) = loaded_rules.as_ref() {
            for ev in &report.events {
                let ev_ts = ev.timestamp();
                let matches = rules::correlate(frames, ev_ts, ruleset);
                for m in matches { correlations.push((ev_ts, m)); }
            }
        }
        // Also check post-message impacts for TX frames (did anything happen after sending?)
        let can_impacts = rules::post_message_impacts_can(frames, &report.events, 5000, dbc_map.as_ref());
        impacts.extend(can_impacts);
    }
    if let Some(eth) = eth_frames.as_ref() {
        let eth_impacts = rules::post_message_impacts_eth(eth, &report.events, 5000);
        impacts.extend(eth_impacts);
    }

    // Enrich impacts with load comparisons using extracted `load_samples`
    for impact in impacts.iter_mut() {
        let window = 5000;
        let before_start = impact.timestamp.saturating_sub(window);
        let after_end = impact.timestamp + window;

        let before_vals: Vec<f64> = load_samples.iter().filter_map(|s| {
            if s.timestamp >= before_start && s.timestamp < impact.timestamp { s.cpu_percent } else { None }
        }).collect();
        let after_vals: Vec<f64> = load_samples.iter().filter_map(|s| {
            if s.timestamp >= impact.timestamp && s.timestamp <= after_end { s.cpu_percent } else { None }
        }).collect();

        let avg_before = if !before_vals.is_empty() { before_vals.iter().sum::<f64>() / before_vals.len() as f64 } else { 0.0 };
        let avg_after = if !after_vals.is_empty() { after_vals.iter().sum::<f64>() / after_vals.len() as f64 } else { 0.0 };
        
        impact.cpu_before = avg_before;
        impact.cpu_after = avg_after;
        if avg_before > 0.0 {
            impact.cpu_spike_pct = ((avg_after - avg_before) / avg_before) * 100.0;
            impact.is_load_spike = impact.cpu_spike_pct > 30.0;
        }

        // Adjust causal score based on load spike
        if impact.cpu_spike_pct > 30.0 {
            let load_bonus = (impact.cpu_spike_pct.abs() / 100.0 * 20.0).min(20.0);
            impact.causal_score = (impact.causal_score + load_bonus).min(100.0);
        }
    }

    // Sort by causal score (descending) then by timestamp
    impacts.sort_by(|a, b| {
        b.causal_score.partial_cmp(&a.causal_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
    });

    let html = generate_html_report(&report, can_frames.as_ref(), eth_frames.as_ref(), Some(&correlations), Some(&impacts))?;
    if let Some(path) = html_path {
        fs::write(&path, &html)?;
        println!("\n✅ HTML report saved to: {}", &path);
    } else {
        fs::write("validation_report.html", &html)?;
        println!("\n✅ HTML report saved to: validation_report.html");
    }

    Ok(())
}
