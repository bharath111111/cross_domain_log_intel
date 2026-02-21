use anyhow::Result;
use crate::models::{Domain, LogEntry};
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader};
use chrono::Utc;

/// Parse a log file into unified `LogEntry`s.
/// Attempts to extract a numeric timestamp (10-13 digits) and normalizes to milliseconds.
pub fn parse_log(file_path: &str, domain: Domain) -> Result<Vec<LogEntry>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let ts_re = Regex::new(r"(\d{9,13})")?; // accept 9-13 digit timestamps

    let mut entries = Vec::new();
    for line in reader.lines() {
        let line = line?;

        // extract first numeric timestamp-looking token
        let timestamp_ms = if let Some(cap) = ts_re.captures(&line) {
            if let Some(m) = cap.get(1) {
                let s = m.as_str();
                // Parse and normalize to milliseconds
                if s.len() >= 13 {
                    s.parse::<i64>().unwrap_or_else(|_| Utc::now().timestamp_millis())
                } else if s.len() == 10 {
                    // seconds -> ms
                    s.parse::<i64>().map(|v| v * 1000).unwrap_or_else(|_| Utc::now().timestamp_millis())
                } else {
                    // <13 but >10, scale to ms (pad to 13)
                    let mut val = s.parse::<i64>().unwrap_or_else(|_| Utc::now().timestamp_millis());
                    while s.len() < 13 {
                        // naive scaling: multiply by 10 for each missing digit
                        val *= 10;
                        break;
                    }
                    val
                }
            } else {
                Utc::now().timestamp_millis()
            }
        } else {
            // fallback to current time
            Utc::now().timestamp_millis()
        };

        // process name heuristic: third whitespace token
        let process = line.split_whitespace().nth(2).map(|s| s.to_string()).unwrap_or_else(|| "unknown".to_string());

        entries.push(LogEntry {
            timestamp: timestamp_ms,
            domain: domain.clone(),
            process,
            message: line.clone(),
        });
    }

    Ok(entries)
}
