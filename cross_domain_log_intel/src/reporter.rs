use crate::models::{MetricsReport, SystemEvent, Domain, RepetitiveError, CanFrame, EthFrame};
use anyhow::Result;
use std::collections::HashMap;

// Service health analysis removed per user request

/// Detect failure sequence patterns (e.g., crash → timeout → reset)
fn detect_failure_sequences(events: &[SystemEvent]) -> Vec<(String, usize)> {
    let mut patterns: HashMap<String, usize> = HashMap::new();
    
    // Look for common patterns
    for i in 0..events.len().saturating_sub(1) {
        let curr = &events[i];
        let next = &events[i + 1];
        
        let curr_type = match curr {
            SystemEvent::ServiceCrash { .. } => "Crash",
            SystemEvent::Timeout { .. } => "Timeout",
            SystemEvent::Reset { .. } => "Reset",
            SystemEvent::Watchdog { .. } => "Watchdog",
            _ => continue,
        };
        
        let next_type = match next {
            SystemEvent::ServiceCrash { .. } => "Crash",
            SystemEvent::Timeout { .. } => "Timeout",
            SystemEvent::Reset { .. } => "Reset",
            SystemEvent::Watchdog { .. } => "Watchdog",
            _ => continue,
        };
        
        let pattern = format!("{} → {}", curr_type, next_type);
        *patterns.entry(pattern).or_insert(0) += 1;
    }
    
    let mut result: Vec<_> = patterns.into_iter().collect();
    result.sort_by(|a, b| b.1.cmp(&a.1));
    result
}

/// Find repetitive errors and crashes
fn find_repetitive_errors(events: &[SystemEvent]) -> Vec<RepetitiveError> {
    let mut error_map: HashMap<String, Vec<i64>> = HashMap::new();
    
    for event in events {
        let key = match event {
            SystemEvent::ServiceCrash { process, domain, .. } => format!("Crash:{}/{}", domain, process),
            SystemEvent::Timeout { service, domain, .. } => format!("Timeout:{}/{}", domain, service),
            SystemEvent::Reset { reason, domain, .. } => format!("Reset:{}/{}", domain, reason),
            _ => continue,
        };
        
        error_map.entry(key).or_insert_with(Vec::new).push(event.timestamp());
    }
    
    let mut result = Vec::new();
    for (key, timestamps) in error_map {
        if timestamps.len() >= 2 {
            let parts: Vec<&str> = key.splitn(2, ':').collect();
            let error_type = parts[0].to_string();
            let service_info: Vec<&str> = parts[1].split('/').collect();
            let domain_str = service_info[0];
            let domain = if domain_str.contains("QNX") { Domain::Qnx } else { Domain::Android };
            let service = service_info[1].to_string();
            
            // Calculate avg time between failures
            let times_between: Vec<i64> = timestamps.windows(2).map(|w| w[1] - w[0]).collect();
            let avg_time = if !times_between.is_empty() {
                times_between.iter().sum::<i64>() / times_between.len() as i64
            } else {
                0
            };
            
            result.push(RepetitiveError {
                error_type,
                service_or_reason: service,
                domain,
                occurrence_count: timestamps.len(),
                occurrences_at_ms: timestamps,
                time_between_failures_avg_ms: avg_time,
            });
        }
    }
    
    result.sort_by(|a, b| b.occurrence_count.cmp(&a.occurrence_count));
    result
}

/// Generate priority recommendations based on analysis
// Priority recommendation generation removed per user request
pub fn generate_html_report(report: &MetricsReport, can_frames: Option<&Vec<CanFrame>>, _eth_frames: Option<&Vec<EthFrame>>, _correlations: Option<&Vec<(i64, String)>>, impacts: Option<&Vec<crate::models::ImpactDetail>>) -> Result<String> {
    let mut html = String::new();

    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n<title>Validation Report</title>\n<style>body{font-family:Arial,Helvetica,sans-serif;background:#fff;color:#222;margin:12px} .wrap{max-width:1400px;margin:0 auto} h1{font-size:18px;margin-bottom:6px} h2{font-size:14px;margin-top:16px;margin-bottom:8px} .row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px} .card{background:#f7f7f7;padding:10px;border-radius:6px;flex:1;min-width:140px} table{width:100%;border-collapse:collapse;margin-bottom:12px} th,td{padding:8px;border:1px solid #ddd;font-size:12px;text-align:left} th{background:#f0f0f0;font-weight:bold} .truncate{max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap} footer{font-size:11px;color:#666;margin-top:16px}</style>\n</head>\n<body>\n<div class=\"wrap\">\n");

    html.push_str(&format!("<h1>{}</h1>\n", report.report_title));
    html.push_str(&format!("<div class=\"row\"><div class=\"card\">Generated: {}</div><div class=\"card\">Boot: {} ms</div></div>\n", report.generated_at, report.boot_time_ms));

    // Key metrics
    html.push_str("<div class=\"row\">\n");
    html.push_str(&format!("<div class=\"card\">Service Crashes<br><strong>{}</strong></div>", report.total_service_crashes));
    html.push_str(&format!("<div class=\"card\">System Crashes<br><strong>{}</strong></div>", report.total_system_crashes));
    html.push_str(&format!("<div class=\"card\">Timeouts<br><strong>{}</strong></div>", report.total_timeouts));
    html.push_str(&format!("<div class=\"card\">Resets<br><strong>{}</strong></div>", report.total_resets));
    html.push_str(&format!("<div class=\"card\">Service Starts<br><strong>{}</strong></div>\n", report.total_service_starts));
    html.push_str("</div>\n");

    // Compact issues table
    html.push_str("<h2>Issues (Faults & Warnings)</h2>\n");
    html.push_str("<table><tr><th>Time (ms)</th><th>Domain</th><th>Severity</th><th>Type</th><th>Raw</th><th>CAN nearby</th></tr>\n");
    for event in &report.events {
        let sev = event.severity();
        if sev == "INFO" { continue; }
        let ev_ts = event.timestamp();
        let domain_str = format!("{}", event.domain());
        let mut raw = event.raw_log().replace('\n', " ");
        if raw.chars().count() > 140 { raw = raw.chars().take(137).collect::<String>() + "..."; }
        let mut nearby_count = 0;
        if let Some(frames) = can_frames {
            let window_start = ev_ts.saturating_sub(5000);
            nearby_count = frames.iter().filter(|f| f.timestamp >= window_start && f.timestamp <= ev_ts).count();
        }
        html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class=\"truncate\">{}</td><td>{}</td></tr>\n", ev_ts, domain_str, sev, event.event_type(), raw, nearby_count));
    }
    html.push_str("</table>\n");

    // Per-domain summary (compact)
    html.push_str("<h2>Per-Domain Summary</h2>\n<table><tr><th>Domain</th><th>Starts</th><th>Crashes</th><th>System Crashes</th><th>Timeouts</th></tr>\n");
    let mut domains: Vec<_> = report.by_domain.iter().collect();
    domains.sort_by_key(|a| a.0);
    for (domain, metrics) in domains {
        html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n", domain, metrics.service_starts, metrics.service_crashes, metrics.system_crashes, metrics.timeouts));
    }
    html.push_str("</table>\n");

    // Correlations / post-message impacts (if any) — show rich impact details
    if let Some(imps) = impacts {
        if !imps.is_empty() {
            html.push_str("<h2>Message Impacts & Correlations (Ranked by Causal Score)</h2>\n");
            html.push_str("<table><tr><th>Causal Score</th><th>Frame ID</th><th>Time (ms)</th><th>Source</th><th>Severity</th><th>Crashes</th><th>Affected Services</th><th>CPU Load</th><th>Anomaly</th><th>Signals</th></tr>\n");
            for impact in imps.iter() {
                let cpu_str = if impact.cpu_before > 0.0 || impact.cpu_after > 0.0 {
                    format!("{:.1}% → {:.1}% ({:+.1}%)", impact.cpu_before, impact.cpu_after, impact.cpu_spike_pct)
                } else {
                    "N/A".to_string()
                };

                let service_str = if impact.crashed_services.is_empty() {
                    "-".to_string()
                } else {
                    impact.crashed_services.iter().take(2).map(|s| {
                        let mut trunc = s.clone();
                        if trunc.len() > 20 { trunc = format!("{}...", &trunc[..17]); }
                        trunc
                    }).collect::<Vec<_>>().join(", ")
                };

                let signals_str = if !impact.decoded_signals.is_empty() {
                    impact.decoded_signals.iter().take(3).map(|(name, val)| format!("{}={}", name, val)).collect::<Vec<_>>().join("; ")
                } else {
                    "-".to_string()
                };

                let severity_color = match impact.severity.as_str() {
                    "CRITICAL" => "<span style='color:red;font-weight:bold'>CRITICAL</span>",
                    "HIGH" => "<span style='color:orange;font-weight:bold'>HIGH</span>",
                    "MEDIUM" => "<span style='color:gold'>MEDIUM</span>",
                    _ => "LOW",
                };

                let crash_info = if impact.crash_count > 0 {
                    format!("{} (+ {} timeout)", impact.crash_count, impact.timeout_count)
                } else if impact.timeout_count > 0 {
                    format!("{} timeout", impact.timeout_count)
                } else {
                    "None".to_string()
                };

                // Anomaly flag: high z-score + red background
                let anomaly_str = if impact.is_anomaly {
                    format!("<span style='color:red;font-weight:bold'>Z={:.2}</span>", impact.anomaly_zscore)
                } else {
                    format!("Z={:.2}", impact.anomaly_zscore)
                };

                // Causal score bar (gradient from yellow to red)
                let score_color = if impact.causal_score >= 80.0 {
                    "red"
                } else if impact.causal_score >= 60.0 {
                    "orange"
                } else if impact.causal_score >= 40.0 {
                    "gold"
                } else {
                    "gray"
                };

                html.push_str(&format!(
                    "<tr style='background-color:{};opacity:0.9'><td><strong style='color:white;font-size:14px'>{:.0}</strong></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td class='truncate'>{}</td><td>{}</td><td>{}</td><td class='truncate'>{}</td></tr>\n",
                    score_color, impact.causal_score, impact.frame_id, impact.timestamp, impact.frame_source, severity_color, crash_info, service_str, cpu_str, anomaly_str, signals_str
                ));
            }
            html.push_str("</table>\n");
        }
    }

    html.push_str("<footer>Cross-Domain Automotive Log Intelligence Engine — concise report</footer>\n</div>\n</body>\n</html>\n");

    Ok(html)
}
