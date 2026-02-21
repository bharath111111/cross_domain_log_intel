use crate::models::{MetricsReport, SystemEvent, Domain, ServiceHealth, RepetitiveError, Recommendation};
use anyhow::Result;
use std::collections::HashMap;

/// Calculate service health scores and detailed metrics
fn analyze_service_health(events: &[SystemEvent]) -> Vec<ServiceHealth> {
    let mut services: HashMap<String, ServiceHealth> = HashMap::new();
    
    for event in events {
        let (service_name, domain, event_type) = match event {
            SystemEvent::ServiceStart { name, domain, .. } => (name.clone(), *domain, "start"),
            SystemEvent::ServiceCrash { process, domain, .. } => (process.clone(), *domain, "crash"),
            SystemEvent::Timeout { service, domain, .. } => (service.clone(), *domain, "timeout"),
            SystemEvent::Discrepancy { domain, .. } => ("system".to_string(), *domain, "discrepancy"),
            SystemEvent::Deviation { domain, .. } => ("system".to_string(), *domain, "deviation"),
            _ => continue,
        };
        
        let key = format!("{}:{}", service_name, domain);
        let health = services.entry(key).or_insert_with(|| ServiceHealth {
            name: service_name.clone(),
            domain,
            total_starts: 0,
            total_crashes: 0,
            total_timeouts: 0,
            total_failures: 0,
            health_score: 100.0,
            failure_rate: 0.0,
        });
        
        match event_type {
            "start" => health.total_starts += 1,
            "crash" => {
                health.total_crashes += 1;
                health.total_failures += 1;
            }
            "timeout" => {
                health.total_timeouts += 1;
                health.total_failures += 1;
            }
            "discrepancy" | "deviation" => health.total_failures += 1,
            _ => {}
        }
    }
    
    // Calculate health scores
    for health in services.values_mut() {
        let total_events = health.total_starts + health.total_failures;
        if total_events > 0 {
            health.failure_rate = (health.total_failures as f32 / total_events as f32) * 100.0;
            // Health score: 100 - (failure_rate * 0.5 + crashes_penality)
            health.health_score = (100.0 - health.failure_rate * 0.5).max(0.0);
        }
    }
    
    let mut result: Vec<_> = services.into_values().collect();
    result.sort_by(|a, b| b.total_failures.cmp(&a.total_failures));
    result
}

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
fn generate_recommendations(health: &[ServiceHealth], repetitive: &[RepetitiveError]) -> Vec<Recommendation> {
    let mut recommendations = Vec::new();
    let mut priority = 1;
    
    // Critical: Services with multiple crashes
    for service_h in health {
        if service_h.total_crashes >= 2 {
            recommendations.push(Recommendation {
                priority,
                impact: "CRITICAL".to_string(),
                issue: format!("{} crashed {} times", service_h.name, service_h.total_crashes),
                affected_service: service_h.name.clone(),
                suggested_action: format!("Investigate root cause of {} crashes; add defensive checks in {} module", service_h.total_crashes, service_h.name),
                estimated_fix_effort: "High (2-3 days)".to_string(),
            });
            priority += 1;
        }
    }
    
    // High: Repetitive errors
    for error in repetitive {
        if error.occurrence_count >= 3 {
            recommendations.push(Recommendation {
                priority,
                impact: "HIGH".to_string(),
                issue: format!("{} occurred {} times in {} domain", error.error_type, error.occurrence_count, error.domain),
                affected_service: error.service_or_reason.clone(),
                suggested_action: format!("Pattern detected: {} repeats every ~{}ms; implement retry logic with exponential backoff", error.error_type, error.time_between_failures_avg_ms),
                estimated_fix_effort: "Medium (1-2 days)".to_string(),
            });
            priority += 1;
        }
    }
    
    // Medium: Services with timeouts
    for service_h in health {
        if service_h.total_timeouts >= 1 && service_h.total_crashes == 0 {
            recommendations.push(Recommendation {
                priority,
                impact: "MEDIUM".to_string(),
                issue: format!("{} has {} timeouts", service_h.name, service_h.total_timeouts),
                affected_service: service_h.name.clone(),
                suggested_action: "Increase timeout thresholds; optimize {} I/O operations; profile for performance bottlenecks".to_string(),
                estimated_fix_effort: "Low (1 day)".to_string(),
            });
            priority += 1;
        }
    }
    
    recommendations.sort_by_key(|r| r.priority);
    recommendations
}
pub fn generate_html_report(report: &MetricsReport) -> Result<String> {
    let mut html = String::new();
    
    html.push_str("<!DOCTYPE html>\n");
    html.push_str("<html lang=\"en\">\n");
    html.push_str("<head>\n");
    html.push_str("  <meta charset=\"UTF-8\">\n");
    html.push_str("  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n");
    html.push_str("  <title>Validation Report</title>\n");
    html.push_str("  <style>\n");
    html.push_str("    * { margin: 0; padding: 0; box-sizing: border-box; }\n");
    html.push_str("    body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f5f5f5; color: #333; }\n");
    html.push_str("    .container { max-width: 1400px; margin: 0 auto; padding: 40px 20px; }\n");
    html.push_str("    header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 8px; margin-bottom: 40px; }\n");
    html.push_str("    h1 { font-size: 32px; margin-bottom: 10px; }\n");
    html.push_str("    h2 { font-size: 22px; margin: 30px 0 15px 0; color: #333; border-bottom: 2px solid #667eea; padding-bottom: 10px; }\n");
    html.push_str("    h3 { font-size: 16px; margin: 15px 0 10px 0; color: #555; }\n");
    html.push_str("    .timestamp { font-size: 14px; opacity: 0.9; }\n");
    html.push_str("    .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 40px; }\n");
    html.push_str("    .card { background: white; padding: 25px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }\n");
    html.push_str("    .metric-label { font-size: 12px; text-transform: uppercase; color: #999; margin-bottom: 8px; font-weight: 600; }\n");
    html.push_str("    .metric-value { font-size: 36px; font-weight: bold; color: #667eea; }\n");
    html.push_str("    .card.critical .metric-value { color: #e74c3c; }\n");
    html.push_str("    .card.warning .metric-value { color: #f39c12; }\n");
    html.push_str("    .card.success .metric-value { color: #27ae60; }\n");
    html.push_str("    .details { background: white; padding: 30px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }\n");
    html.push_str("    .event-timeline { list-style: none; padding: 0; }\n");
    html.push_str("    .event-item { padding: 20px; margin: 15px 0; border-left: 4px solid #ddd; background: #f9f9f9; border-radius: 4px; }\n");
    html.push_str("    .event-item.CRITICAL { border-left-color: #e74c3c; background: #ffe8e8; }\n");
    html.push_str("    .event-item.WARNING { border-left-color: #f39c12; background: #fff8e8; }\n");
    html.push_str("    .event-item.INFO { border-left-color: #27ae60; background: #e8f9e8; }\n");
    html.push_str("    .event-time { font-size: 12px; color: #999; font-weight: 600; font-family: monospace; }\n");
    html.push_str("    .event-type { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 11px; font-weight: 600; margin: 8px 0; }\n");
    html.push_str("    .event-type.CRITICAL { background: #e74c3c; color: white; }\n");
    html.push_str("    .event-type.WARNING { background: #f39c12; color: white; }\n");
    html.push_str("    .event-type.INFO { background: #27ae60; color: white; }\n");
    html.push_str("    .event-domain { font-weight: 600; color: #667eea; }\n");
    html.push_str("    .event-log { font-family: 'Monaco', 'Menlo', monospace; font-size: 12px; background: white; padding: 12px; border-radius: 4px; margin-top: 10px; border: 1px solid #ddd; color: #555; word-break: break-all; }\n");
    html.push_str("    table { width: 100%; border-collapse: collapse; }\n");
    html.push_str("    th { background: #f8f9fa; padding: 12px; text-align: left; font-weight: 600; color: #555; border-bottom: 2px solid #ddd; }\n");
    html.push_str("    td { padding: 12px; border-bottom: 1px solid #eee; }\n");
    html.push_str("    tr:hover { background: #f8f9fa; }\n");
    html.push_str("    .status-pass { color: #27ae60; font-weight: 600; }\n");
    html.push_str("    .status-fail { color: #e74c3c; font-weight: 600; }\n");
    html.push_str("    .status-warn { color: #f39c12; font-weight: 600; }\n");
    html.push_str("    footer { text-align: center; margin-top: 40px; color: #999; font-size: 12px; }\n");
    html.push_str("  </style>\n");
    html.push_str("</head>\n");
    html.push_str("<body>\n");
    html.push_str("  <div class=\"container\">\n");
    
    // Header
    html.push_str("    <header>\n");
    html.push_str(&format!("      <h1>{}</h1>\n", report.report_title));
    html.push_str(&format!("      <p class=\"timestamp\">Generated: {}</p>\n", report.generated_at));
    html.push_str("    </header>\n");
    
    // Summary Cards
    html.push_str("    <div class=\"summary\">\n");
    html.push_str(&format!("      <div class=\"card critical\">\n        <div class=\"metric-label\">Service Crashes</div>\n        <div class=\"metric-value\">{}</div>\n      </div>\n", report.total_service_crashes));
    html.push_str(&format!("      <div class=\"card critical\">\n        <div class=\"metric-label\">System Crashes</div>\n        <div class=\"metric-value\">{}</div>\n      </div>\n", report.total_system_crashes));
    html.push_str(&format!("      <div class=\"card warning\">\n        <div class=\"metric-label\">Timeouts</div>\n        <div class=\"metric-value\">{}</div>\n      </div>\n", report.total_timeouts));
    html.push_str(&format!("      <div class=\"card critical\">\n        <div class=\"metric-label\">Resets</div>\n        <div class=\"metric-value\">{}</div>\n      </div>\n", report.total_resets));
    html.push_str(&format!("      <div class=\"card critical\">\n        <div class=\"metric-label\">Discrepancies</div>\n        <div class=\"metric-value\">{}</div>\n      </div>\n", report.total_discrepancies));
    html.push_str(&format!("      <div class=\"card critical\">\n        <div class=\"metric-label\">Deviations</div>\n        <div class=\"metric-value\">{}</div>\n      </div>\n", report.total_deviations));
    html.push_str(&format!("      <div class=\"card warning\">\n        <div class=\"metric-label\">Watchdog Triggers</div>\n        <div class=\"metric-value\">{}</div>\n      </div>\n", report.total_watchdog_triggers));
    html.push_str(&format!("      <div class=\"card success\">\n        <div class=\"metric-label\">Service Starts</div>\n        <div class=\"metric-value\">{}</div>\n      </div>\n", report.total_service_starts));
    html.push_str("    </div>\n");
    
    // Boot Time
    html.push_str("    <div class=\"details\">\n");
    html.push_str("      <h2>System Boot Analysis</h2>\n");
    html.push_str("      <table>\n");
    html.push_str("        <tr><th>Metric</th><th>Value</th></tr>\n");
    html.push_str(&format!("        <tr><td>Boot Duration</td><td>{} ms ({:.2} seconds)</td></tr>\n", report.boot_time_ms, report.boot_time_ms as f64 / 1000.0));
    html.push_str("      </table>\n");
    html.push_str("    </div>\n");
    
    // FILTERING: Show only faults/warnings/errors (skip INFO events)
    html.push_str("    <div class=\"details\">\n");
    html.push_str("      <h2>📋 Critical Issues & Warnings Timeline (FAULTS Only)</h2>\n");
    html.push_str("      <p style=\"margin-bottom: 20px; color: #e74c3c; font-weight: bold;\">⚠️ Showing ONLY Critical & Warning events (excluding successful service starts)</p>\n");
    html.push_str("      <ul class=\"event-timeline\">\n");
    
    let mut issue_count = 0;
    for event in &report.events {
        let severity = event.severity();
        // Skip INFO events
        if severity == "INFO" {
            continue;
        }
        issue_count += 1;
        
        let event_type = event.event_type();
        let timestamp_sec = event.timestamp() / 1000;
        let timestamp_ms = event.timestamp() % 1000;
        let domain_str = format!("{}", event.domain());
        
        html.push_str(&format!("        <li class=\"event-item {}\">\n", severity));
        html.push_str(&format!("          <div class=\"event-time\">⏱️  WHEN: {}ms ({}s:{}ms)</div>\n", event.timestamp(), timestamp_sec, timestamp_ms));
        html.push_str(&format!("          <div><span class=\"event-domain\">📍 WHERE: {}</span></div>\n", domain_str));
        html.push_str(&format!("          <span class=\"event-type {}\">{}</span>\n", severity, event_type));
        
        // Details specific to event type
        match event {
            crate::models::SystemEvent::ServiceStart { .. } => {
                // Skip - INFO level
            }
            crate::models::SystemEvent::ServiceCrash { process, .. } => {
                html.push_str(&format!("          <div><strong>AFFECTED SERVICE:</strong> <code>{}</code></div>\n", process));
                html.push_str(&format!("          <div><strong>HOW:</strong> Process terminated unexpectedly - memory fault, segmentation fault, or assertion failure</div>\n"));
                html.push_str(&format!("          <div><strong>ROOT CAUSE:</strong> Service process encountered a critical error and crashed</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #c0392b;\"><strong>IMPACT:</strong> Service unavailable - dependent modules unable to communicate</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #c0392b;\"><strong>SEVERITY:</strong> CRITICAL - System functionality impaired</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; background: #fff3cd; padding: 10px; border-radius: 4px;\"><strong>REMEDIATION:</strong> Service must be restarted; investigate crash logs for segfaults or out-of-memory conditions</div>\n"));
            }
            crate::models::SystemEvent::SystemCrash { reason, .. } => {
                html.push_str(&format!("          <div><strong>HOW:</strong> Core system failure detected - kernel panic or critical driver error</div>\n"));
                html.push_str(&format!("          <div><strong>ROOT CAUSE:</strong> {}</div>\n", reason));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #c0392b;\"><strong>IMPACT:</strong> Entire system unstable - reboot required</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #c0392b;\"><strong>SEVERITY:</strong> CRITICAL - System-level failure</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; background: #fff3cd; padding: 10px; border-radius: 4px;\"><strong>REMEDIATION:</strong> Immediate system reboot required; collect kernel panic logs for analysis</div>\n"));
            }
            crate::models::SystemEvent::Timeout { service, .. } => {
                html.push_str(&format!("          <div><strong>AFFECTED SERVICE:</strong> <code>{}</code></div>\n", service));
                html.push_str(&format!("          <div><strong>HOW:</strong> Operation did not complete within expected time window - blocked on I/O or infinite loop</div>\n"));
                html.push_str(&format!("          <div><strong>ROOT CAUSE:</strong> Service unresponsive or performing slow operation exceeding timeout threshold</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #f39c12;\"><strong>IMPACT:</strong> Performance degradation; caller threads blocked waiting for response</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #f39c12;\"><strong>SEVERITY:</strong> WARNING - System degraded but functional</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; background: #fff3cd; padding: 10px; border-radius: 4px;\"><strong>REMEDIATION:</strong> Increase timeout threshold if operation is legitimately slow; identify I/O bottlenecks or deadlocks</div>\n"));
            }
            crate::models::SystemEvent::Watchdog { .. } => {
                html.push_str(&format!("          <div><strong>HOW:</strong> Watchdog timer expired - system became unresponsive</div>\n"));
                html.push_str(&format!("          <div><strong>ROOT CAUSE:</strong> System did not service watchdog within expected interval</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #f39c12;\"><strong>IMPACT:</strong> Automatic recovery activated - system reset initiated</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #f39c12;\"><strong>SEVERITY:</strong> WARNING - Recovery mechanism triggered</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; background: #fff3cd; padding: 10px; border-radius: 4px;\"><strong>REMEDIATION:</strong> Reduce system load; identify interrupt latency issues; check for CPU-bound processes blocking watchdog</div>\n"));
            }
            crate::models::SystemEvent::Reset { reason, .. } => {
                html.push_str(&format!("          <div><strong>HOW:</strong> System restarted - all services reset and reinitialized</div>\n"));
                html.push_str(&format!("          <div><strong>ROOT CAUSE:</strong> {}</div>\n", reason));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #c0392b;\"><strong>IMPACT:</strong> All services terminated and restarted; pending operations lost</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #c0392b;\"><strong>SEVERITY:</strong> CRITICAL - System reset</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; background: #fff3cd; padding: 10px; border-radius: 4px;\"><strong>REMEDIATION:</strong> Analyze logs before reset to identify root cause; implement watchdog timeout extensions if legitimate</div>\n"));
            }
            crate::models::SystemEvent::Discrepancy { details, .. } => {
                html.push_str(&format!("          <div><strong>HOW:</strong> Cross-domain state mismatch detected during validation</div>\n"));
                html.push_str(&format!("          <div><strong>ROOT CAUSE:</strong> {}</div>\n", details));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #c0392b;\"><strong>IMPACT:</strong> QNX and Android domains have inconsistent internal state - coordination failed</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #c0392b;\"><strong>SEVERITY:</strong> CRITICAL - Data consistency violation</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; background: #fff3cd; padding: 10px; border-radius: 4px;\"><strong>REMEDIATION:</strong> Implement state synchronization; add consistency checks; review message passing protocol</div>\n"));
            }
            crate::models::SystemEvent::Deviation { details, .. } => {
                html.push_str(&format!("          <div><strong>HOW:</strong> Unexpected system behavior detected outside normal operating parameters</div>\n"));
                html.push_str(&format!("          <div><strong>ROOT CAUSE:</strong> {}</div>\n", details));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #c0392b;\"><strong>IMPACT:</strong> System exhibiting abnormal behavior - may indicate underlying defect</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; color: #c0392b;\"><strong>SEVERITY:</strong> CRITICAL - Potential system defect</div>\n"));
                html.push_str(&format!("          <div style=\"margin-top: 8px; background: #fff3cd; padding: 10px; border-radius: 4px;\"><strong>REMEDIATION:</strong> Enable detailed logging; profile system behavior; unit test affected modules</div>\n"));
            }
        }
        
        // Raw log message
        html.push_str(&format!("          <div class=\"event-log\">📄 <strong>Raw Log:</strong> {}</div>\n", event.raw_log()));
        html.push_str("        </li>\n");
    }
    
    if issue_count == 0 {
        html.push_str("        <li style=\"padding: 20px; background: #e8f9e8; border-left: 4px solid #27ae60; border-radius: 4px;\">\n");
        html.push_str("          <span class=\"event-type INFO\" style=\"background: #27ae60;\">✅ NO FAULTS</span>\n");
        html.push_str("          <div style=\"margin-top: 10px;\"><strong>Status:</strong> All systems operational - no warnings or errors detected</div>\n");
        html.push_str("        </li>\n");
    }
    
    html.push_str("      </ul>\n");
    html.push_str("    </div>\n");
    
    // CALCULATE ANALYTICS
    let service_health = analyze_service_health(&report.events);
    let failure_sequences = detect_failure_sequences(&report.events);
    let repetitive_errors = find_repetitive_errors(&report.events);
    let recommendations = generate_recommendations(&service_health, &repetitive_errors);
    
    // SERVICE HEALTH SCORES SECTION
    if !service_health.is_empty() {
        html.push_str("    <div class=\"details\">\n");
        html.push_str("      <h2>💚 Service Health Scores & Reliability Analysis</h2>\n");
        html.push_str("      <p style=\"margin-bottom: 15px;\">Health score (0-100): Based on crash frequency, timeouts, and reliability. Higher is better.</p>\n");
        html.push_str("      <table style=\"width: 100%;\">\n");
        html.push_str("        <tr><th>Service Name</th><th>Domain</th><th>Starts</th><th>Crashes</th><th>Timeouts</th><th>Total Failures</th><th>Failure Rate</th><th>Health Score</th></tr>\n");
        
        for service in &service_health {
            let score_color = if service.health_score >= 80.0 {
                "#27ae60"
            } else if service.health_score >= 50.0 {
                "#f39c12"
            } else {
                "#e74c3c"
            };
            
            html.push_str(&format!(
                "        <tr><td><strong>{}</strong></td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.1}%</td><td style=\"color: {}; font-weight: bold;\">{:.1}/100</td></tr>\n",
                service.name, service.domain, service.total_starts, service.total_crashes, service.total_timeouts,
                service.total_failures, service.failure_rate, score_color, service.health_score
            ));
        }
        
        html.push_str("      </table>\n");
        html.push_str("    </div>\n");
    }
    
    // REPETITIVE ERRORS SECTION
    if !repetitive_errors.is_empty() {
        html.push_str("    <div class=\"details\">\n");
        html.push_str("      <h2>🔄 Repetitive Errors & Crash Patterns</h2>\n");
        html.push_str("      <p style=\"margin-bottom: 15px;\">⚠️ These errors occurred multiple times, indicating a systematic issue requiring root cause analysis.</p>\n");
        
        for error in &repetitive_errors {
            let severity_color = if error.occurrence_count >= 5 {
                "#e74c3c"
            } else if error.occurrence_count >= 3 {
                "#f39c12"
            } else {
                "#3498db"
            };
            
            html.push_str(&format!(
                "      <div style=\"margin-bottom: 20px; border-left: 4px solid {}; padding: 15px; background: #f8f8f8; border-radius: 4px;\">\n",
                severity_color
            ));
            html.push_str(&format!("        <div style=\"color: {}; font-weight: bold; font-size: 16px; margin-bottom: 8px;\">{}x {} in {}</div>\n", 
                severity_color, error.occurrence_count, error.error_type, error.domain));
            html.push_str(&format!("        <div><strong>Affected Service:</strong> <code>{}</code></div>\n", error.service_or_reason));
            html.push_str(&format!("        <div><strong>Average Time Between Failures:</strong> {}ms ({:.1} seconds)</div>\n", 
                error.time_between_failures_avg_ms, error.time_between_failures_avg_ms as f64 / 1000.0));
            
            html.push_str("        <div style=\"margin-top: 8px;\"><strong>Occurrences at (ms):</strong> ");
            for ts in &error.occurrences_at_ms {
                html.push_str(&format!("{} ", ts));
            }
            html.push_str("</div>\n");
            html.push_str("        <div style=\"margin-top: 8px; color: #e74c3c;\"><strong>Action Required:</strong> This pattern indicates the issue is systematic and needs architectural fix, not just restart.</div>\n");
            html.push_str("      </div>\n");
        }
        
        html.push_str("    </div>\n");
    }
    
    // FAILURE SEQUENCE PATTERNS SECTION
    if !failure_sequences.is_empty() && failure_sequences[0].1 > 1 {
        html.push_str("    <div class=\"details\">\n");
        html.push_str("      <h2>⛔ Failure Sequence Patterns (Event Correlations)</h2>\n");
        html.push_str("      <p style=\"margin-bottom: 15px;\">These sequences show how failures cascade - when one event triggers another predictable sequence.</p>\n");
        
        for (pattern, count) in failure_sequences.iter().take(8) {
            if *count < 2 {
                continue;
            }
            
            let severity = if *count >= 3 { "CRITICAL" } else { "WARNING" };
            let color = if *count >= 3 { "#e74c3c" } else { "#f39c12" };
            
            html.push_str(&format!(
                "      <div style=\"margin-bottom: 15px; padding: 12px; background: #fff3cd; border-left: 4px solid {}; border-radius: 4px;\">\n",
                color
            ));
            html.push_str(&format!("        <span style=\"color: {}; font-weight: bold;\">[{}]</span> {} (occurred {} times)\n", 
                color, severity, pattern, count));
            if *count >= 3 {
                html.push_str("        <div style=\"margin-top: 8px; color: #c0392b;\"><strong>⚠️ PATTERN DETECTED:</strong> This sequence repeats regularly - implement prevention logic</div>\n");
            }
            html.push_str("      </div>\n");
        }
        
        html.push_str("    </div>\n");
    }
    
    // PRIORITY RECOMMENDATIONS SECTION
    if !recommendations.is_empty() {
        html.push_str("    <div class=\"details\">\n");
        html.push_str("      <h2>🎯 Priority Recommendations (Action Plan)</h2>\n");
        html.push_str("      <p style=\"margin-bottom: 15px;\">Ranked by impact and criticality. Address items in order for maximum system stability improvement.</p>\n");
        
        for rec in &recommendations {
            let color = if rec.impact == "CRITICAL" {
                "#e74c3c"
            } else if rec.impact == "HIGH" {
                "#f39c12"
            } else {
                "#3498db"
            };
            
            html.push_str(&format!(
                "      <div style=\"margin-bottom: 20px; border: 2px solid {}; padding: 15px; border-radius: 4px; background: #fafafa;\">\n",
                color
            ));
            html.push_str(&format!("        <div style=\"color: {}; font-weight: bold; font-size: 14px; margin-bottom: 8px;\">PRIORITY #{} - {} IMPACT</div>\n", 
                color, rec.priority, rec.impact));
            html.push_str(&format!("        <div><strong>Issue:</strong> {}</div>\n", rec.issue));
            html.push_str(&format!("        <div><strong>Affected Service:</strong> <code>{}</code></div>\n", rec.affected_service));
            html.push_str(&format!("        <div style=\"margin-top: 8px; background: #e8f4f8; padding: 10px; border-radius: 4px;\"><strong>Suggested Action:</strong> {}</div>\n", rec.suggested_action));
            html.push_str(&format!("        <div style=\"margin-top: 8px; color: #555;\"><strong>Estimated Effort:</strong> {}</div>\n", rec.estimated_fix_effort));
            html.push_str("      </div>\n");
        }
        
        html.push_str("    </div>\n");
    }
    
    html.push_str("    <div class=\"details\">\n");
    html.push_str("      <h2>📚 What Are Services? (System Architecture Reference)</h2>\n");
    html.push_str("      <p style=\"margin-bottom: 15px;\">Services are independent software components running on the automotive platform that provide specific functionality. They communicate with each other and enable the vehicle to function correctly.</p>\n");
    html.push_str("      \n");
    html.push_str("      <h3>Common Automotive Services:</h3>\n");
    html.push_str("      <table style=\"margin-top: 15px;\">\n");
    html.push_str("        <tr><th>Service Name</th><th>Purpose</th><th>Domain</th><th>Impact if Failed</th></tr>\n");
    html.push_str("        <tr><td><strong>NetworkManager</strong></td><td>Manages network connectivity and communication</td><td>QNX/Android</td><td>Loss of network communication; system isolation</td></tr>\n");
    html.push_str("        <tr><td><strong>SystemServer</strong></td><td>Core OS system services (sensors, hardware)</td><td>Android</td><td>Hardware access lost; sensor data unavailable</td></tr>\n");
    html.push_str("        <tr><td><strong>MediaServer</strong></td><td>Audio/video streaming and multimedia</td><td>Android</td><td>No multimedia; infotainment unavailable</td></tr>\n");
    html.push_str("        <tr><td><strong>AudioFlinger</strong></td><td>Audio engine and sound processing</td><td>Android</td><td>No audio output; critical alerts silent</td></tr>\n");
    html.push_str("        <tr><td><strong>GpsService</strong></td><td>GPS/navigation and location services</td><td>QNX</td><td>Navigation unavailable; location unknown</td></tr>\n");
    html.push_str("        <tr><td><strong>StorageManager</strong></td><td>File system and data storage management</td><td>QNX</td><td>Data loss; cannot access files</td></tr>\n");
    html.push_str("        <tr><td><strong>zygote</strong></td><td>Android app process spawner</td><td>Android</td><td>Cannot launch apps; system broken</td></tr>\n");
    html.push_str("      </table>\n");
    html.push_str("    </div>\n");
    
    // ISSUE SUMMARY
    html.push_str("    <div class=\"details\">\n");
    html.push_str(&format!("      <h2>🚨 Summary: {} Issues Detected</h2>\n", issue_count));
    html.push_str("      <p style=\"margin-bottom: 15px;\">Review each issue above and follow the remediation steps to restore system stability.</p>\n");
    html.push_str("    </div>\n");
    
    // Per-Domain Breakdown
    html.push_str("    <div class=\"details\">\n");
    html.push_str("      <h2>Per-Domain Breakdown</h2>\n");
    html.push_str("      <table>\n");
    html.push_str("        <tr>\n");
    html.push_str("          <th>Domain</th>\n");
    html.push_str("          <th>Service Starts</th>\n");
    html.push_str("          <th>Service Crashes</th>\n");
    html.push_str("          <th>System Crashes</th>\n");
    html.push_str("          <th>Timeouts</th>\n");
    html.push_str("          <th>Watchdog</th>\n");
    html.push_str("          <th>Resets</th>\n");
    html.push_str("          <th>Discrepancies</th>\n");
    html.push_str("          <th>Deviations</th>\n");
    html.push_str("        </tr>\n");
    
    let mut domains: Vec<_> = report.by_domain.iter().collect();
    domains.sort_by_key(|a| a.0);
    
    for (domain, metrics) in domains {
        let _issue_count = metrics.service_crashes + metrics.system_crashes + metrics.timeouts + metrics.resets + metrics.discrepancies + metrics.deviations;
        let _row_class = if _issue_count > 3 { "class=\"status-fail\"" } else if _issue_count > 0 { "class=\"status-warn\"" } else { "class=\"status-pass\"" };
        html.push_str("        <tr>\n");
        html.push_str(&format!("          <td><strong>{}</strong></td>\n", domain));
        html.push_str(&format!("          <td>{}</td>\n", metrics.service_starts));
        html.push_str(&format!("          <td {}>{}</td>\n", if metrics.service_crashes > 0 { "class=\"status-fail\"" } else { "" }, metrics.service_crashes));
        html.push_str(&format!("          <td {}>{}</td>\n", if metrics.system_crashes > 0 { "class=\"status-fail\"" } else { "" }, metrics.system_crashes));
        html.push_str(&format!("          <td {}>{}</td>\n", if metrics.timeouts > 0 { "class=\"status-warn\"" } else { "" }, metrics.timeouts));
        html.push_str(&format!("          <td>{}</td>\n", metrics.watchdog_triggers));
        html.push_str(&format!("          <td {}>{}</td>\n", if metrics.resets > 0 { "class=\"status-warn\"" } else { "" }, metrics.resets));
        html.push_str(&format!("          <td {}>{}</td>\n", if metrics.discrepancies > 0 { "class=\"status-fail\"" } else { "" }, metrics.discrepancies));
        html.push_str(&format!("          <td {}>{}</td>\n", if metrics.deviations > 0 { "class=\"status-fail\"" } else { "" }, metrics.deviations));
        html.push_str("        </tr>\n");
    }
    
    html.push_str("      </table>\n");
    html.push_str("    </div>\n");
    
    // Summary
    html.push_str("    <div class=\"details\">\n");
    html.push_str("      <h2>Executive Summary</h2>\n");
    let total_issues = report.total_service_crashes + report.total_system_crashes + report.total_timeouts + report.total_resets + report.total_discrepancies + report.total_deviations;
    let status = if total_issues == 0 { "✅ PASS" } else if total_issues <= 5 { "⚠️  WARNING" } else { "❌ FAIL" };
    html.push_str(&format!("      <p><strong>Overall Status: {}</strong></p>\n", status));
    html.push_str(&format!("      <p>Total Issues Found: <strong>{}</strong></p>\n", total_issues));
    html.push_str(&format!("      <p>Boot Time: <strong>{} ms</strong></p>\n", report.boot_time_ms));
    html.push_str(&format!("      <p>Services Started: <strong>{}</strong></p>\n", report.total_service_starts));
    html.push_str("    </div>\n");
    
    html.push_str("    <footer>\n");
    html.push_str("      <p>Cross-Domain Automotive Log Intelligence Engine</p>\n");
    html.push_str("      <p>For support, contact the validation team</p>\n");
    html.push_str("    </footer>\n");
    html.push_str("  </div>\n");
    html.push_str("</body>\n");
    html.push_str("</html>\n");
    
    Ok(html)
}
