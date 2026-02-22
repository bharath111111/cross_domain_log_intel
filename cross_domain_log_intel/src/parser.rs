use anyhow::Result;
use crate::models::{Domain, LogEntry, CanFrame, EthFrame, LoadSample};
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

/// Extract simple CPU/memory samples from a set of `LogEntry`s.
/// Looks for tokens like `CPU: 12.3%`, `cpu=12.3%`, `Mem: 123MB`, `mem=123MB`.
pub fn extract_load_samples(entries: &[LogEntry]) -> Vec<LoadSample> {
    use regex::Regex;
    let cpu_re = Regex::new(r"(?i)\b(?:cpu[:=]\s*|cpu%[:=]\s*)([0-9]+(?:\.[0-9]+)?)%?").ok();
    let mem_re = Regex::new(r"(?i)\b(?:mem[:=]\s*|mem_mb[:=]\s*|rss[:=]\s*)([0-9]+(?:\.[0-9]+)?)\s*(mb|gb)?").ok();

    let mut samples: Vec<LoadSample> = Vec::new();
    for e in entries.iter() {
        let mut cpu: Option<f64> = None;
        let mut mem: Option<f64> = None;
        if let Some(re) = &cpu_re {
            if let Some(cap) = re.captures(&e.message) {
                if let Some(m) = cap.get(1) {
                    if let Ok(v) = m.as_str().parse::<f64>() { cpu = Some(v); }
                }
            }
        }
        if let Some(re2) = &mem_re {
            if let Some(cap) = re2.captures(&e.message) {
                if let Some(m) = cap.get(1) {
                    if let Ok(mut v) = m.as_str().parse::<f64>() {
                        // if GB unit, convert
                        if let Some(unit) = cap.get(2) {
                            let u = unit.as_str().to_lowercase();
                            if u == "gb" { v *= 1024.0; }
                        }
                        mem = Some(v);
                    }
                }
            }
        }
        if cpu.is_some() || mem.is_some() {
            samples.push(LoadSample { timestamp: e.timestamp, cpu_percent: cpu, mem_mb: mem });
        }
    }
    samples
}

/// Parse a CAN ASCII (.asc) log into `CanFrame`s.
pub fn parse_can_asc(file_path: &str) -> Result<Vec<CanFrame>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let num_re = Regex::new(r"(\d+\.\d+|\d{9,13})")?;
    let id_re = Regex::new(r"([0-9A-Fa-f]+)#([0-9A-Fa-f]+)")?;

    let mut frames = Vec::new();
    for line in reader.lines() {
        let line = line?;
        // Try to extract timestamp token
        let timestamp_ms = if let Some(cap) = num_re.captures(&line) {
            let s = cap.get(1).unwrap().as_str();
            if s.contains('.') {
                // seconds with fraction
                let f: f64 = s.parse().unwrap_or_else(|_| chrono::Utc::now().timestamp_millis() as f64 / 1000.0);
                (f * 1000.0) as i64
            } else {
                let v = s.parse::<i64>().unwrap_or_else(|_| chrono::Utc::now().timestamp_millis());
                if s.len() >= 13 { v } else if s.len() == 10 { v * 1000 } else { v }
            }
        } else {
            chrono::Utc::now().timestamp_millis()
        };

        // channel/identifier heuristics
        let channel = line.split_whitespace().nth(1).map(|s| s.to_string()).unwrap_or_else(|| "can0".to_string());
        let mut id = "unknown".to_string();
        let mut data = "".to_string();
        if let Some(cap) = id_re.captures(&line) {
            id = cap.get(1).unwrap().as_str().to_string();
            data = cap.get(2).unwrap().as_str().to_string();
        }

        frames.push(CanFrame {
            timestamp: timestamp_ms,
            channel,
            id,
            data,
            direction: "-".to_string(),
            raw: line.clone(),
        });
    }

    Ok(frames)
}

/// Parse a simple ethernet textual log into `EthFrame`s.
pub fn parse_eth_log(file_path: &str) -> Result<Vec<EthFrame>> {
    // Try to detect if it's a pcapng file
    if file_path.ends_with(".pcapng") || file_path.ends_with(".pcap") {
        return parse_pcapng_eth(file_path);
    }

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let ts_re = Regex::new(r"(\d{9,13})")?;

    let mut frames = Vec::new();
    for line in reader.lines() {
        let line = line?;
        let timestamp_ms = if let Some(cap) = ts_re.captures(&line) {
            let s = cap.get(1).unwrap().as_str();
            if s.len() == 10 { s.parse::<i64>().map(|v| v*1000).unwrap_or_else(|_| chrono::Utc::now().timestamp_millis()) } else { s.parse::<i64>().unwrap_or_else(|_| chrono::Utc::now().timestamp_millis()) }
        } else {
            chrono::Utc::now().timestamp_millis()
        };

        // simple split: iface direction summary
        let parts: Vec<&str> = line.split_whitespace().collect();
        let iface = parts.get(1).map(|s| s.to_string()).unwrap_or_else(|| "eth0".to_string());
        let direction = parts.get(2).map(|s| s.to_string()).unwrap_or_else(|| "-".to_string());
        let summary = parts.get(3..).map(|s| s.join(" ")).unwrap_or_else(|| "".to_string());

        frames.push(EthFrame {
            timestamp: timestamp_ms,
            iface,
            direction,
            summary,
            raw: line.clone(),
        });
    }

    Ok(frames)
}

/// Parse a .pcapng (PCAP Next Generation) file into `EthFrame`s
/// Extracts IP/TCP header info and timestamps from packet capture data
pub fn parse_pcapng_eth(file_path: &str) -> Result<Vec<EthFrame>> {
    use std::fs;

    let data = fs::read(file_path)?;
    if data.len() < 4 {
        return Ok(Vec::new());
    }

    // Check pcapng magic number (0x0A0D0D0A in little-endian or big-endian)
    let is_pcap_ng = (data[0] == 0x0A && data[1] == 0x0D && data[2] == 0x0D && data[3] == 0x0A) ||
                    (data[0] == 0x1A && data[1] == 0x2B && data[2] == 0x3C && data[3] == 0x4D);

    if !is_pcap_ng {
        // Fallback: try classic PCAP magic (0xA1B2C3D4 or 0xD4C3B2A1)
        let classic_le = data.len() >= 4 && data[0] == 0xD4 && data[1] == 0xC3 && data[2] == 0xB2 && data[3] == 0xA1;
        let classic_be = data.len() >= 4 && data[0] == 0xA1 && data[1] == 0xB2 && data[2] == 0xC3 && data[3] == 0xD4;
        
        if !classic_le && !classic_be {
            return Err(anyhow::anyhow!("Not a valid pcapng or pcap file: invalid magic number"));
        }
    }

    let mut frames = Vec::new();
    let mut pos = 0;

    // Skip past the section header block
    while pos < data.len() {
        if data[pos] == 0x0A && pos + 3 < data.len() && data[pos+1] == 0x0D && data[pos+2] == 0x0D && data[pos+3] == 0x0A {
            // Found section header; skip 28 bytes minimum
            pos += 28;
            break;
        }
        pos += 1;
    }

    // Parse packet blocks
    while pos + 16 <= data.len() {
        let block_type = u32::from_le_bytes(data[pos..pos+4].try_into()?);
        let block_len = u32::from_le_bytes(data[pos+4..pos+8].try_into()?) as usize;

        if block_type == 6 {
            // Enhanced Packet Block
            if pos + 36 > data.len() { break; }

            // Timestamp (seconds and microseconds)
            let ts_sec = u32::from_le_bytes(data[pos+12..pos+16].try_into()?);
            let ts_usec = u32::from_le_bytes(data[pos+16..pos+20].try_into()?);
            let timestamp_ms = (ts_sec as i64) * 1000 + (ts_usec as i64) / 1000;

            let caplen = u32::from_le_bytes(data[pos+20..pos+24].try_into()?) as usize;
            let _origlen = u32::from_le_bytes(data[pos+24..pos+28].try_into()?) as usize;

            let packet_start = pos + 28;
            if packet_start + caplen <= data.len() {
                let packet_data = &data[packet_start..packet_start + caplen];

                // Simple Ethernet frame extraction: look for IPv4 header (4500 in hex)
                let mut summary = String::from("ETH packet");
                let mut direction = "-".to_string();

                // Skip Ethernet header (14 bytes) and check for IP
                if caplen >= 34 && packet_data[12] == 0x08 && packet_data[13] == 0x00 {
                    // IPv4 detected
                    let ip_start = 14;
                    if packet_data[ip_start] >> 4 == 4 {
                        // IPv4
                        if ip_start + 20 <= packet_data.len() {
                            let src_ip = format!("{}.{}.{}.{}", packet_data[ip_start+12], packet_data[ip_start+13], packet_data[ip_start+14], packet_data[ip_start+15]);
                            let dst_ip = format!("{}.{}.{}.{}", packet_data[ip_start+16], packet_data[ip_start+17], packet_data[ip_start+18], packet_data[ip_start+19]);
                            let proto = packet_data[ip_start+9];

                            if proto == 6 && ip_start + 40 <= packet_data.len() {
                                // TCP
                                let src_port = u16::from_be_bytes([packet_data[ip_start+20], packet_data[ip_start+21]]);
                                let dst_port = u16::from_be_bytes([packet_data[ip_start+22], packet_data[ip_start+23]]);
                                let flags = packet_data[ip_start+33];
                                let flag_str = if flags & 0x01 != 0 { "FIN" } else if flags & 0x02 != 0 { "SYN" } else if flags & 0x10 != 0 { "ACK" } else { "DATA" };
                                summary = format!("TCP {}:{} -> {}:{} {}", src_ip, src_port, dst_ip, dst_port, flag_str);
                                direction = "RX".to_string();
                            } else if proto == 17 && ip_start + 28 <= packet_data.len() {
                                // UDP
                                let src_port = u16::from_be_bytes([packet_data[ip_start+20], packet_data[ip_start+21]]);
                                let dst_port = u16::from_be_bytes([packet_data[ip_start+22], packet_data[ip_start+23]]);
                                summary = format!("UDP {}:{} -> {}:{}", src_ip, src_port, dst_ip, dst_port);
                                direction = "RX".to_string();
                            }
                        }
                    }
                }

                frames.push(EthFrame {
                    timestamp: timestamp_ms,
                    iface: "eth0".to_string(),
                    direction,
                    summary,
                    raw: format!("pcapng packet @{}ms len={}", timestamp_ms, caplen),
                });
            }
        }

        pos += block_len;
        if pos % 4 != 0 {
            pos += 4 - (pos % 4); // align to 4-byte boundary
        }
    }

    Ok(frames)
}
