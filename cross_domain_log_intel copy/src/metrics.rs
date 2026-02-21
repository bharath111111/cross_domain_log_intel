use crate::models::{MetricsReport, SystemEvent, Domain, DomainMetrics};
use std::collections::HashMap;
use chrono::Local;

/// Generate a comprehensive `MetricsReport` from the detected events.
pub fn generate_metrics(events: &[SystemEvent]) -> MetricsReport {
    let mut service_starts = 0usize;
    let mut service_crashes = 0usize;
    let mut system_crashes = 0usize;
    let mut timeouts = 0usize;
    let mut watchdog_triggers = 0usize;
    let mut resets = 0usize;
    let mut discrepancies = 0usize;
    let mut deviations = 0usize;

    let mut service_timestamps: Vec<i64> = Vec::new();
    let mut by_domain: HashMap<String, DomainMetrics> = HashMap::new();

    for ev in events.iter() {
        let domain_name = extract_domain_name(ev).to_string();
        let metrics = by_domain.entry(domain_name).or_insert_with(|| DomainMetrics {
            service_starts: 0,
            service_crashes: 0,
            system_crashes: 0,
            timeouts: 0,
            watchdog_triggers: 0,
            resets: 0,
            discrepancies: 0,
            deviations: 0,
        });

        match ev {
            SystemEvent::ServiceStart { timestamp, .. } => {
                service_starts += 1;
                metrics.service_starts += 1;
                service_timestamps.push(*timestamp);
            }
            SystemEvent::ServiceCrash { .. } => {
                service_crashes += 1;
                metrics.service_crashes += 1;
            }
            SystemEvent::SystemCrash { .. } => {
                system_crashes += 1;
                metrics.system_crashes += 1;
            }
            SystemEvent::Timeout { .. } => {
                timeouts += 1;
                metrics.timeouts += 1;
            }
            SystemEvent::Watchdog { .. } => {
                watchdog_triggers += 1;
                metrics.watchdog_triggers += 1;
            }
            SystemEvent::Reset { .. } => {
                resets += 1;
                metrics.resets += 1;
            }
            SystemEvent::Discrepancy { .. } => {
                discrepancies += 1;
                metrics.discrepancies += 1;
            }
            SystemEvent::Deviation { .. } => {
                deviations += 1;
                metrics.deviations += 1;
            }
        }
    }

    service_timestamps.sort();
    let boot_time_ms = if service_timestamps.len() >= 2 {
        let first = service_timestamps.first().copied().unwrap_or(0);
        let last = service_timestamps.last().copied().unwrap_or(0);
        last - first
    } else {
        0
    };

    let generated_at = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    MetricsReport {
        report_title: "Cross-Domain Automotive Log Validation Report".to_string(),
        generated_at,
        boot_time_ms,
        total_service_starts: service_starts,
        total_service_crashes: service_crashes,
        total_system_crashes: system_crashes,
        total_timeouts: timeouts,
        total_watchdog_triggers: watchdog_triggers,
        total_resets: resets,
        total_discrepancies: discrepancies,
        total_deviations: deviations,
        by_domain,
        events: events.to_vec(),
    }
}

fn extract_domain_name(event: &SystemEvent) -> &str {
    match event {
        SystemEvent::ServiceStart { domain, .. } => match domain { Domain::Qnx => "QNX", Domain::Android => "Android" },
        SystemEvent::ServiceCrash { domain, .. } => match domain { Domain::Qnx => "QNX", Domain::Android => "Android" },
        SystemEvent::SystemCrash { domain, .. } => match domain { Domain::Qnx => "QNX", Domain::Android => "Android" },
        SystemEvent::Timeout { domain, .. } => match domain { Domain::Qnx => "QNX", Domain::Android => "Android" },
        SystemEvent::Watchdog { domain, .. } => match domain { Domain::Qnx => "QNX", Domain::Android => "Android" },
        SystemEvent::Reset { domain, .. } => match domain { Domain::Qnx => "QNX", Domain::Android => "Android" },
        SystemEvent::Discrepancy { domain, .. } => match domain { Domain::Qnx => "QNX", Domain::Android => "Android" },
        SystemEvent::Deviation { domain, .. } => match domain { Domain::Qnx => "QNX", Domain::Android => "Android" },
    }
}
