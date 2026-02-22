use anyhow::Result;
use std::fs::File;
use std::io::Read;
use std::collections::HashMap;
use crate::models::{DbcMessage};

/// Load a simple DBC-like JSON file into a map of id -> DbcMessage
pub fn load_dbc(path: &str) -> Result<HashMap<String, DbcMessage>> {
    let mut f = File::open(path)?;
    let mut s = String::new();
    f.read_to_string(&mut s)?;
    let msgs: Vec<DbcMessage> = serde_json::from_str(&s)?;
    let mut map = HashMap::new();
    for m in msgs { map.insert(m.id.clone(), m); }
    Ok(map)
}

/// Decode simple signals from a hex data string using the provided DBC mapping.
/// Returns map signal_name -> value (as f64)
pub fn decode_signals(id: &str, data_hex: &str, dbc: &HashMap<String, DbcMessage>) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    if let Some(msg) = dbc.get(id) {
        // parse data_hex into bytes
        let clean = data_hex.trim();
        let mut bytes: Vec<u8> = Vec::new();
        for i in (0..clean.len()).step_by(2) {
            if i+2 <= clean.len() {
                if let Ok(b) = u8::from_str_radix(&clean[i..i+2], 16) {
                    bytes.push(b);
                }
            }
        }
        for sig in &msg.signals {
            // crude extraction: read bytes at start_bit/8
            let byte_index = sig.start_bit / 8;
            if byte_index < bytes.len() {
                let raw = bytes[byte_index] as f64;
                let factor = sig.factor.unwrap_or(1.0);
                let offset = sig.offset.unwrap_or(0.0);
                out.insert(sig.name.clone(), raw * factor + offset);
            }
        }
    }
    out
}
