// Library exports for shared functionality between CLI and Web
pub mod models;
pub mod parser;
pub mod classifier;
pub mod metrics;
pub mod reporter;
pub mod decoder;
pub mod rules;

pub use models::{Domain, LogEntry, SystemEvent, MetricsReport, ImpactDetail};
pub use parser::{parse_log, parse_can_asc, extract_load_samples, parse_pcapng_eth, parse_eth_log};
pub use classifier::classify_logs;
pub use metrics::generate_metrics;
pub use reporter::generate_html_report;
pub use decoder::load_dbc;
pub use rules::{load_rules, post_message_impacts_can, post_message_impacts_eth, correlate};
