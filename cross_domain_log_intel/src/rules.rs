use anyhow::Result;
use std::fs::File;
use std::io::Read;
use serde::Deserialize;
use crate::models::{CanFrame, SystemEvent};

#[derive(Debug, Deserialize)]
pub struct SimpleRule {
    pub id: String,
    pub byte_index: usize,
    pub bit_mask: u8,
    pub value_nonzero: bool,
    pub within_ms: i64,
    pub description: String,
}

pub fn load_rules(path: &str) -> Result<Vec<SimpleRule>> {
    let mut f = File::open(path)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    let rules: Vec<SimpleRule> = serde_json::from_str(&s)?;
    Ok(rules)
}

/// Compute mean and stddev of event rates for anomaly threshold baseline
pub fn compute_event_rate_stats(events: &[SystemEvent], window_ms: i64) -> (f64, f64) {
    if events.is_empty() { return (0.0, 1.0); }

    let sorted_events = {
        let mut e = events.to_vec();
        e.sort_by_key(|ev| ev.timestamp());
        e
    };

    let mut rates: Vec<f64> = Vec::new();
    for i in 0..sorted_events.len() {
        let start = sorted_events[i].timestamp();
        let end = start + window_ms;
        let count = sorted_events.iter().filter(|e| e.timestamp() >= start && e.timestamp() <= end).count();
        rates.push(count as f64);
    }

    let mean = if !rates.is_empty() { rates.iter().sum::<f64>() / rates.len() as f64 } else { 0.0 };
    let variance = if !rates.is_empty() { rates.iter().map(|r| (r - mean).powi(2)).sum::<f64>() / rates.len() as f64 } else { 1.0 };
    let stddev = variance.sqrt();

    (mean, stddev.max(1.0))
}

/// Compute z-score for event rate: (actual_rate - mean) / stddev
pub fn compute_anomaly_zscore(event_count: f64, mean: f64, stddev: f64) -> f64 {
    (event_count - mean) / stddev
}

/// Compute composite causal score (0-100) based on:
/// - Time proximity (closer to frame = higher)
/// - Crash severity (crashes >> timeouts)
/// - Load spike magnitude
/// - Frame-event rate multiplication
pub fn compute_causal_score(
    crash_count: usize,
    timeout_count: usize,
    watchdog_count: usize,
    cpu_spike_pct: f64,
    rate_multiplier: f64,
    time_delta_ms: i64,
    window_ms: i64,
) -> f64 {
    let mut score = 0.0;

    // Crash severity component (0-50 points)
    score += (crash_count as f64 * 15.0).min(50.0);
    score += (timeout_count as f64 * 5.0).min(20.0);
    score += (watchdog_count as f64 * 3.0).min(10.0);

    // Time proximity component (0-20 points): closer = higher
    let time_proximity_bonus = if time_delta_ms <= 500 {
        20.0  // Immediate effect
    } else if time_delta_ms <= 1000 {
        15.0
    } else if time_delta_ms <= 2000 {
        10.0
    } else {
        5.0
    };
    score += time_proximity_bonus;

    // Load spike component (0-20 points)
    let cpu_spike_bonus = (cpu_spike_pct.abs() / 100.0 * 20.0).min(20.0);
    score += cpu_spike_bonus;

    // Rate multiplication component (0-10 points)
    if rate_multiplier > 1.8 {
        score += 10.0;
    } else if rate_multiplier > 1.5 {
        score += 7.0;
    } else if rate_multiplier > 1.2 {
        score += 3.0;
    }

    score.min(100.0)
}

/// Correlate frames -> events: for each event timestamp, check if any frame matching rule
/// occurred within `within_ms` before the event. Returns Vec of (event_ts, description)
pub fn correlate(frames: &[CanFrame], event_ts: i64, rules: &[SimpleRule]) -> Vec<String> {
    let mut matches = Vec::new();
    for rule in rules {
        // find frames with matching id and within window
        for f in frames {
            if f.id.to_lowercase() != rule.id.to_lowercase() { continue; }
            if f.timestamp < event_ts - rule.within_ms || f.timestamp > event_ts { continue; }
            // parse data bytes
            let data = f.data.clone();
            let mut matched = false;
            if rule.byte_index * 2 + 2 <= data.len() {
                if let Ok(b) = u8::from_str_radix(&data[rule.byte_index*2..rule.byte_index*2+2], 16) {
                    if (b & rule.bit_mask) != 0 {
                        matched = rule.value_nonzero;
                    } else {
                        matched = !rule.value_nonzero;
                    }
                }
            }
            if matched {
                matches.push(format!("Rule '{}' matched on frame {} at {}ms (event {})", rule.description, f.id, f.timestamp, event_ts));
            }
        }
    }
    matches
}

use crate::decoder;
use std::collections::HashMap;
use crate::models::{DbcMessage, ImpactDetail};

pub fn post_message_impacts_can(frames: &[CanFrame], events: &[SystemEvent], window_ms: i64, dbc: Option<&HashMap<String, DbcMessage>>) -> Vec<ImpactDetail> {
    let mut results: Vec<ImpactDetail> = Vec::new();

    // Compute baseline event rate stats for anomaly detection
    let (mean_rate, stddev_rate) = compute_event_rate_stats(events, window_ms);

    for f in frames.iter().filter(|f| f.direction.to_uppercase().contains("TX")) {
        let start = f.timestamp;
        let end = start + window_ms;

        // events after the frame within window
        let after: Vec<&SystemEvent> = events.iter().filter(|e| e.timestamp() >= start && e.timestamp() <= end).collect();
        // events before the frame in same window for baseline comparison
        let before_start = start.saturating_sub(window_ms);
        let before: Vec<&SystemEvent> = events.iter().filter(|e| e.timestamp() >= before_start && e.timestamp() < start).collect();

        let mut crashes = 0usize;
        let mut crashed_services: Vec<String> = Vec::new();
        let mut warnings = 0usize;
        let mut watchdogs = 0usize;
        let mut first_crash_ts = i64::MAX;
        
        for ev in &after {
            match ev {
                SystemEvent::ServiceCrash { process, .. } => {
                    crashes += 1;
                    crashed_services.push(process.clone());
                    first_crash_ts = first_crash_ts.min(ev.timestamp());
                }
                SystemEvent::SystemCrash { .. } => {
                    crashes += 1;
                    crashed_services.push("SYSTEM".to_string());
                    first_crash_ts = first_crash_ts.min(ev.timestamp());
                }
                SystemEvent::Timeout { service, .. } => {
                    warnings += 1;
                }
                SystemEvent::Watchdog { .. } => watchdogs += 1,
                _ => {}
            }
        }

        let after_count = after.len();
        let before_count = before.len().max(1);
        let rate_mul = (after_count as f64) / (before_count as f64);
        let spike_detected = rate_mul > 1.8 && after_count > before_count;

        // Anomaly detection: compute z-score of post-injection event rate
        let zscore = compute_anomaly_zscore(after_count as f64, mean_rate, stddev_rate);
        let is_anomaly = zscore > 2.0;

        // Time delta to first crash (if any)
        let time_delta = if crashes > 0 { first_crash_ts - start } else { window_ms };

        // Causal score: composite ranking
        let causal_score = compute_causal_score(crashes, warnings, watchdogs, 0.0, rate_mul, time_delta, window_ms);

        // Compute confidence: higher for multiple events close to frame
        let confidence = if crashes > 0 { 0.95 } else if rate_mul > 1.5 { 0.7 } else { 0.4 };

        // Determine severity
        let severity = if crashes >= 2 { "CRITICAL" } else if crashes == 1 { "HIGH" } else if warnings > 2 { "MEDIUM" } else { "LOW" }.to_string();

        // Decode signals if DBC available
        let mut decoded_signals: Vec<(String, String)> = Vec::new();
        if let Some(dmap) = dbc {
            let decoded = decoder::decode_signals(&f.id, &f.data, dmap);
            let mut items: Vec<_> = decoded.into_iter().collect();
            items.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, val) in items.into_iter().take(5) {
                decoded_signals.push((name, format!("{:.2}", val)));
            }
        }

        let raw_summary = format!("TX {}@{}ms: {} events, {} crashes, {} warnings, {} watchdogs; rate x{:.2}{}",
            f.id, start, after_count, crashes, warnings, watchdogs, rate_mul, if spike_detected { " [SPIKE]" } else { "" });

        results.push(ImpactDetail {
            frame_id: f.id.clone(),
            frame_source: "CAN".to_string(),
            timestamp: start,
            cpu_before: 0.0,
            cpu_after: 0.0,
            cpu_spike_pct: 0.0,
            is_load_spike: false,
            crash_count: crashes,
            crashed_services: crashed_services.into_iter().rev().take(3).collect(),
            timeout_count: warnings,
            watchdog_count: watchdogs,
            severity,
            confidence,
            decoded_signals,
            raw_summary,
            is_anomaly,
            anomaly_zscore: zscore,
            causal_score,
        });
    }

    results
}

use crate::models::EthFrame;

/// For each transmitted Ethernet frame, analyze events occurring after the frame within `window_ms`.
pub fn post_message_impacts_eth(frames: &[EthFrame], events: &[SystemEvent], window_ms: i64) -> Vec<ImpactDetail> {
    let mut results: Vec<ImpactDetail> = Vec::new();

    // Compute baseline event rate stats for anomaly detection
    let (mean_rate, stddev_rate) = compute_event_rate_stats(events, window_ms);

    for f in frames.iter().filter(|f| f.direction.to_uppercase().contains("TX")) {
        let start = f.timestamp;
        let end = start + window_ms;

        let after: Vec<&SystemEvent> = events.iter().filter(|e| e.timestamp() >= start && e.timestamp() <= end).collect();
        let before_start = start.saturating_sub(window_ms);
        let before: Vec<&SystemEvent> = events.iter().filter(|e| e.timestamp() >= before_start && e.timestamp() < start).collect();

        let mut crashes = 0usize;
        let mut crashed_services: Vec<String> = Vec::new();
        let mut warnings = 0usize;
        let mut watchdogs = 0usize;
        let mut first_crash_ts = i64::MAX;
        
        for ev in &after {
            match ev {
                SystemEvent::ServiceCrash { process, .. } => {
                    crashes += 1;
                    crashed_services.push(process.clone());
                    first_crash_ts = first_crash_ts.min(ev.timestamp());
                }
                SystemEvent::SystemCrash { .. } => {
                    crashes += 1;
                    crashed_services.push("SYSTEM".to_string());
                    first_crash_ts = first_crash_ts.min(ev.timestamp());
                }
                SystemEvent::Timeout { service, .. } => {
                    warnings += 1;
                }
                SystemEvent::Watchdog { .. } => watchdogs += 1,
                _ => {}
            }
        }

        let after_count = after.len();
        let before_count = before.len().max(1);
        let rate_mul = (after_count as f64) / (before_count as f64);
        let spike_detected = rate_mul > 1.8 && after_count > before_count;

        // Anomaly detection
        let zscore = compute_anomaly_zscore(after_count as f64, mean_rate, stddev_rate);
        let is_anomaly = zscore > 2.0;

        // Time delta to first crash
        let time_delta = if crashes > 0 { first_crash_ts - start } else { window_ms };

        // Causal score
        let causal_score = compute_causal_score(crashes, warnings, watchdogs, 0.0, rate_mul, time_delta, window_ms);

        let confidence = if crashes > 0 { 0.9 } else if rate_mul > 1.5 { 0.6 } else { 0.35 };
        let severity = if crashes >= 2 { "CRITICAL" } else if crashes == 1 { "HIGH" } else if warnings > 2 { "MEDIUM" } else { "LOW" }.to_string();

        let raw_summary = format!("ETH {}@{}ms iface={}: {} events, {} crashes, {} warnings, {} watchdogs; rate x{:.2}{}",
            f.summary, start, f.iface, after_count, crashes, warnings, watchdogs, rate_mul, if spike_detected { " [SPIKE]" } else { "" });

        results.push(ImpactDetail {
            frame_id: f.summary.clone(),
            frame_source: "ETH".to_string(),
            timestamp: start,
            cpu_before: 0.0,
            cpu_after: 0.0,
            cpu_spike_pct: 0.0,
            is_load_spike: false,
            crash_count: crashes,
            crashed_services: crashed_services.into_iter().rev().take(3).collect(),
            timeout_count: warnings,
            watchdog_count: watchdogs,
            severity,
            confidence,
            decoded_signals: vec![],
            raw_summary,
            is_anomaly,
            anomaly_zscore: zscore,
            causal_score,
        });
    }

    results
}
