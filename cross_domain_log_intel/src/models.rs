use serde::Serialize;
use std::collections::HashMap;

/// Domain of the log entry
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq, Hash)]
pub enum Domain {
    Qnx,
    Android,
}

impl std::fmt::Display for Domain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Domain::Qnx => write!(f, "QNX"),
            Domain::Android => write!(f, "Android"),
        }
    }
}

/// Unified log entry used across parsers
#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: i64, // ms since epoch
    pub domain: Domain,
    pub process: String,
    pub message: String,
}

/// High level system events detected from logs
#[derive(Debug, Clone, Serialize)]
pub enum SystemEvent {
    ServiceStart { domain: Domain, name: String, timestamp: i64, raw_log: String },
    ServiceCrash { domain: Domain, process: String, timestamp: i64, raw_log: String },
    SystemCrash { domain: Domain, reason: String, timestamp: i64, raw_log: String },
    Timeout { domain: Domain, service: String, timestamp: i64, raw_log: String },
    Watchdog { domain: Domain, timestamp: i64, raw_log: String },
    Reset { domain: Domain, reason: String, timestamp: i64, raw_log: String },
    Discrepancy { domain: Domain, details: String, timestamp: i64, raw_log: String },
    Deviation { domain: Domain, details: String, timestamp: i64, raw_log: String },
}

impl SystemEvent {
    pub fn timestamp(&self) -> i64 {
        match self {
            SystemEvent::ServiceStart { timestamp, .. } => *timestamp,
            SystemEvent::ServiceCrash { timestamp, .. } => *timestamp,
            SystemEvent::SystemCrash { timestamp, .. } => *timestamp,
            SystemEvent::Timeout { timestamp, .. } => *timestamp,
            SystemEvent::Watchdog { timestamp, .. } => *timestamp,
            SystemEvent::Reset { timestamp, .. } => *timestamp,
            SystemEvent::Discrepancy { timestamp, .. } => *timestamp,
            SystemEvent::Deviation { timestamp, .. } => *timestamp,
        }
    }

    pub fn domain(&self) -> &Domain {
        match self {
            SystemEvent::ServiceStart { domain, .. } => domain,
            SystemEvent::ServiceCrash { domain, .. } => domain,
            SystemEvent::SystemCrash { domain, .. } => domain,
            SystemEvent::Timeout { domain, .. } => domain,
            SystemEvent::Watchdog { domain, .. } => domain,
            SystemEvent::Reset { domain, .. } => domain,
            SystemEvent::Discrepancy { domain, .. } => domain,
            SystemEvent::Deviation { domain, .. } => domain,
        }
    }

    pub fn event_type(&self) -> &str {
        match self {
            SystemEvent::ServiceStart { .. } => "Service Start",
            SystemEvent::ServiceCrash { .. } => "Service Crash",
            SystemEvent::SystemCrash { .. } => "System Crash",
            SystemEvent::Timeout { .. } => "Timeout",
            SystemEvent::Watchdog { .. } => "Watchdog Trigger",
            SystemEvent::Reset { .. } => "Reset/Reboot",
            SystemEvent::Discrepancy { .. } => "Discrepancy",
            SystemEvent::Deviation { .. } => "Deviation",
        }
    }

    pub fn severity(&self) -> &str {
        match self {
            SystemEvent::ServiceStart { .. } => "INFO",
            SystemEvent::ServiceCrash { .. } => "CRITICAL",
            SystemEvent::SystemCrash { .. } => "CRITICAL",
            SystemEvent::Timeout { .. } => "WARNING",
            SystemEvent::Watchdog { .. } => "WARNING",
            SystemEvent::Reset { .. } => "CRITICAL",
            SystemEvent::Discrepancy { .. } => "CRITICAL",
            SystemEvent::Deviation { .. } => "CRITICAL",
        }
    }

    pub fn raw_log(&self) -> &str {
        match self {
            SystemEvent::ServiceStart { raw_log, .. } => raw_log,
            SystemEvent::ServiceCrash { raw_log, .. } => raw_log,
            SystemEvent::SystemCrash { raw_log, .. } => raw_log,
            SystemEvent::Timeout { raw_log, .. } => raw_log,
            SystemEvent::Watchdog { raw_log, .. } => raw_log,
            SystemEvent::Reset { raw_log, .. } => raw_log,
            SystemEvent::Discrepancy { raw_log, .. } => raw_log,
            SystemEvent::Deviation { raw_log, .. } => raw_log,
        }
    }
}

/// Comprehensive metrics report output
#[derive(Serialize, Debug)]
pub struct MetricsReport {
    pub report_title: String,
    pub generated_at: String,
    pub boot_time_ms: i64,
    pub total_service_starts: usize,
    pub total_service_crashes: usize,
    pub total_system_crashes: usize,
    pub total_timeouts: usize,
    pub total_watchdog_triggers: usize,
    pub total_resets: usize,
    pub total_discrepancies: usize,
    pub total_deviations: usize,
    pub by_domain: HashMap<String, DomainMetrics>,
    #[serde(skip)]
    pub events: Vec<SystemEvent>,  // For detailed reporting, not serialized
    #[serde(skip)]
    pub load_samples: Vec<LoadSample>,
}

#[derive(Serialize, Debug)]
pub struct DomainMetrics {
    pub service_starts: usize,
    pub service_crashes: usize,
    pub system_crashes: usize,
    pub timeouts: usize,
    pub watchdog_triggers: usize,
    pub resets: usize,
    pub discrepancies: usize,
    pub deviations: usize,
}

/// CAN frame representation (simple)
#[derive(Debug, Clone, Serialize)]
pub struct CanFrame {
    pub timestamp: i64, // ms
    pub channel: String,
    pub id: String,
    pub data: String,
    pub direction: String, // "RX" or "TX" or "-"
    pub raw: String,
}

/// Ethernet frame (simple representation)
#[derive(Debug, Clone, Serialize)]
pub struct EthFrame {
    pub timestamp: i64,
    pub iface: String,
    pub direction: String,
    pub summary: String,
    pub raw: String,
}

/// Simple load sample (cpu % and memory MB) extracted from logs when available
#[derive(Debug, Clone, Serialize)]
pub struct LoadSample {
    pub timestamp: i64,
    pub cpu_percent: Option<f64>,
    pub mem_mb: Option<f64>,
}

/// Simplified DBC mapping structure (JSON)
use serde::Deserialize;
#[derive(Debug, Clone, Deserialize)]
pub struct DbcSignal {
    pub name: String,
    pub start_bit: usize,
    pub length: usize,
    pub factor: Option<f64>,
    pub offset: Option<f64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DbcMessage {
    pub id: String,
    pub signals: Vec<DbcSignal>,
}

/// Failure sequence pattern
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct FailureSequence {
    pub description: String,
    pub events: Vec<String>,
    pub count: usize,
    pub severity: String,
}

/// Repetitive error/crash
#[derive(Debug, Clone)]
pub struct RepetitiveError {
    pub error_type: String,      // ServiceCrash, Timeout, etc
    pub service_or_reason: String,
    pub domain: Domain,
    pub occurrence_count: usize,
    pub occurrences_at_ms: Vec<i64>,
    pub time_between_failures_avg_ms: i64,
}

/// Rich impact detail for a TX frame (CAN/ETH) showing correlated events
#[derive(Debug, Clone)]
pub struct ImpactDetail {
    pub frame_id: String,           // CAN ID or ETH summary
    pub frame_source: String,       // "CAN" or "ETH"
    pub timestamp: i64,
    pub cpu_before: f64,
    pub cpu_after: f64,
    pub cpu_spike_pct: f64,
    pub is_load_spike: bool,
    pub crash_count: usize,
    pub crashed_services: Vec<String>, // [ServiceName, ServiceName, ...]
    pub timeout_count: usize,
    pub watchdog_count: usize,
    pub severity: String,           // "CRITICAL", "HIGH", "MEDIUM", "LOW"
    pub confidence: f64,            // 0.0-1.0 (based on time delta, rate spike)
    pub decoded_signals: Vec<(String, String)>, // [(SignalName, Value), ...]
    pub raw_summary: String,
    pub is_anomaly: bool,           // True if event rate is > 2 std-dev above mean
    pub anomaly_zscore: f64,        // Z-score of event rate (>2.0 = anomalous)
    pub causal_score: f64,          // 0-100: combined ranking for likely causation
}

// NOTE: Service health scores and priority recommendations removed as requested

// TODO: Multi-run statistical comparison
// TODO: HTML report export
// TODO: Advanced timestamp normalization
// TODO: State machine-based event modeling
// TODO: SOME/IP correlation extension
