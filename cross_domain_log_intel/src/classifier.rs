use crate::models::{LogEntry, SystemEvent};

/// Classify log entries into `SystemEvent`s using case-insensitive substring matching.
pub fn classify_logs(entries: &[LogEntry]) -> Vec<SystemEvent> {
    let mut events = Vec::new();

    for e in entries.iter() {
        let msg = e.message.to_lowercase();

        // Service start events
        if msg.contains("service started") || msg.contains("service start") {
            events.push(SystemEvent::ServiceStart { domain: e.domain.clone(), name: e.process.clone(), timestamp: e.timestamp, raw_log: e.message.clone() });
            continue;
        }

        // Service crash events
        if (msg.contains("service") && msg.contains("crash")) || msg.contains("service panic") {
            events.push(SystemEvent::ServiceCrash { domain: e.domain.clone(), process: e.process.clone(), timestamp: e.timestamp, raw_log: e.message.clone() });
            continue;
        }

        // System crashes
        if msg.contains("segfault") || msg.contains("panic") || (msg.contains("crash") && !msg.contains("service")) {
            events.push(SystemEvent::SystemCrash { domain: e.domain.clone(), reason: e.message.clone(), timestamp: e.timestamp, raw_log: e.message.clone() });
            continue;
        }

        // Resets
        if msg.contains("reset") || msg.contains("rebooted") || msg.contains("reboot") {
            events.push(SystemEvent::Reset { domain: e.domain.clone(), reason: e.message.clone(), timestamp: e.timestamp, raw_log: e.message.clone() });
            continue;
        }

        // Timeout events
        if msg.contains("timeout") {
            events.push(SystemEvent::Timeout { domain: e.domain.clone(), service: e.process.clone(), timestamp: e.timestamp, raw_log: e.message.clone() });
            continue;
        }

        // Watchdog events
        if msg.contains("watchdog") {
            events.push(SystemEvent::Watchdog { domain: e.domain.clone(), timestamp: e.timestamp, raw_log: e.message.clone() });
            continue;
        }

        // Discrepancies
        if msg.contains("discrepancy") || msg.contains("mismatch") || msg.contains("inconsistent") {
            events.push(SystemEvent::Discrepancy { domain: e.domain.clone(), details: e.message.clone(), timestamp: e.timestamp, raw_log: e.message.clone() });
            continue;
        }

        // Deviations
        if msg.contains("deviation") || msg.contains("unexpected") || msg.contains("abnormal") {
            events.push(SystemEvent::Deviation { domain: e.domain.clone(), details: e.message.clone(), timestamp: e.timestamp, raw_log: e.message.clone() });
            continue;
        }
    }

    events
}
