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

use models::{Domain, LogEntry};
use parser::parse_log;
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

    // Merge and sort
    let mut all: Vec<LogEntry> = Vec::new();
    all.append(&mut qnx_entries);
    all.append(&mut android_entries);
    all.sort_by_key(|e| e.timestamp);

    // Classify and generate metrics
    let events = classify_logs(&all);
    let report = generate_metrics(&events);

    // Output JSON to console
    let json = serde_json::to_string_pretty(&report)?;
    println!("\n=== VALIDATION REPORT (JSON) ===");
    println!("{}", json);

    // Generate HTML if requested or default
    if args.len() > 3 && args[3] == "--html" {
        if args.len() > 4 {
            let html_path = &args[4];
            let html = generate_html_report(&report)?;
            fs::write(html_path, html)?;
            println!("\n✅ HTML report saved to: {}", html_path);
        } else {
            eprintln!("--html requires an output file path");
        }
    } else {
        // Default: save to validation_report.html
        let html = generate_html_report(&report)?;
        fs::write("validation_report.html", &html)?;
        println!("\n✅ HTML report saved to: validation_report.html");
    }

    Ok(())
}
