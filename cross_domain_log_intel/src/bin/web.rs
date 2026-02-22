use actix_web::{web, App, HttpServer, HttpResponse, middleware, Result as ActixResult};
use actix_multipart::Multipart;
use futures_util::StreamExt;
use std::io::Write;
use uuid::Uuid;

use cross_domain_log_intel::{
    parse_log, parse_can_asc, classify_logs, generate_metrics, extract_load_samples,
    generate_html_report, load_dbc, load_rules, post_message_impacts_can, post_message_impacts_eth,
    correlate, Domain, ImpactDetail,
};

/// Handle file uploads and generate analysis report
async fn upload_and_analyze(mut payload: Multipart) -> ActixResult<HttpResponse> {
    let mut qnx_path: Option<String> = None;
    let mut android_path: Option<String> = None;
    let mut can_path: Option<String> = None;
    let mut eth_path: Option<String> = None;
    let mut dbc_path: Option<String> = None;
    let mut rules_path: Option<String> = None;
    let temp_dir = format!("/tmp/log_intel_{}", Uuid::new_v4());
    let _ = std::fs::create_dir_all(&temp_dir);

    // Extract uploaded files
    // Store all uploaded files with their field names
    let mut uploaded_files: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    
    while let Some(item) = payload.next().await {
        if let Ok(mut field) = item {
            let content_disp = field.content_disposition();
            
            // ContentDisposition stores the field name internally
            // We'll use the string representation to extract field name
            let field_info = format!("{:?}", content_disp);
            let field_name_str = if field_info.contains("qnx_file") {
                "qnx_file"
            } else if field_info.contains("android_file") {
                "android_file"
            } else if field_info.contains("can_file") {
                "can_file"
            } else if field_info.contains("eth_file") {
                "eth_file"
            } else if field_info.contains("dbc_file") {
                "dbc_file"
            } else if field_info.contains("rules_file") {
                "rules_file"
            } else {
                "unknown"
            };
            
            // Get the filename
            let filename: String = content_disp
                .get_filename()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("upload_{}", Uuid::new_v4()));
            
            let file_path = format!("{}/{}", temp_dir, filename);
            
            if let Ok(mut f) = std::fs::File::create(&file_path) {
                while let Some(chunk) = field.next().await {
                    if let Ok(data) = chunk {
                        let _ = f.write_all(&data);
                    }
                }
                
                // Store the association: field_name -> file_path
                uploaded_files.insert(field_name_str.to_string(), file_path);
            }
        }
    }
    
    // Now categorize files by their form field names
    let qnx_path = uploaded_files.get("qnx_file").cloned();
    let android_path = uploaded_files.get("android_file").cloned();
    let can_path = uploaded_files.get("can_file").cloned();
    let eth_path = uploaded_files.get("eth_file").cloned();
    let dbc_path = uploaded_files.get("dbc_file").cloned();
    let rules_path = uploaded_files.get("rules_file").cloned();

    // Validate required files
    if qnx_path.is_none() || android_path.is_none() {
        return Ok(HttpResponse::BadRequest().body(
            "<html><body style='font-family:Arial;margin:40px'><h2>❌ Error</h2><p>QNX and Android log files are required.</p>\
            <p><a href='/'>← Back to upload</a></p></body></html>"
        ));
    }

    // Run analysis
    match run_analysis(
        qnx_path.as_ref().unwrap(),
        android_path.as_ref().unwrap(),
        can_path.as_deref(),
        eth_path.as_deref(),
        dbc_path.as_deref(),
        rules_path.as_deref(),
    ) {
        Ok(html_report) => {
            let _ = std::fs::remove_dir_all(&temp_dir);
            Ok(HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html_report))
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&temp_dir);
            Ok(HttpResponse::InternalServerError().body(
                format!(
                    "<html><body style='font-family:Arial;margin:40px'><h2>Analysis Error</h2><p><code>{}</code></p><p><a href='/'>← Try again</a></p></body></html>",
                    html_escape(&e)
                )
            ))
        }
    }
}

/// Run the full analysis pipeline
fn run_analysis(
    qnx_path: &str,
    android_path: &str,
    can_path: Option<&str>,
    eth_path: Option<&str>,
    dbc_path: Option<&str>,
    rules_path: Option<&str>,
) -> Result<String, String> {
    // Parse logs
    let mut qnx_entries = parse_log(qnx_path, Domain::Qnx).map_err(|e| e.to_string())?;
    let mut android_entries = parse_log(android_path, Domain::Android).map_err(|e| e.to_string())?;

    let mut all: Vec<_> = Vec::new();
    all.append(&mut qnx_entries);
    all.append(&mut android_entries);
    all.sort_by_key(|e| e.timestamp);

    // Extract load samples
    let load_samples = extract_load_samples(&all);

    // Classify events
    let events = classify_logs(&all);
    let report = generate_metrics(&events, &load_samples);

    // Load optional files
    let mut can_frames: Option<Vec<cross_domain_log_intel::models::CanFrame>> = None;
    let mut eth_frames: Option<Vec<cross_domain_log_intel::models::EthFrame>> = None;
    let mut dbc_map = None;
    let mut loaded_rules = None;

    if let Some(path) = can_path {
        can_frames = parse_can_asc(path).ok();
    }
    if let Some(path) = eth_path {
        eth_frames = parse_eth_log(path).ok();
    }
    if let Some(path) = dbc_path {
        dbc_map = load_dbc(path).ok();
    }
    if let Some(path) = rules_path {
        loaded_rules = load_rules(path).ok();
    }

    // Correlations
    let mut correlations: Vec<(i64, String)> = Vec::new();
    let mut impacts: Vec<ImpactDetail> = Vec::new();

    if let Some(frames) = can_frames.as_ref() {
        if let Some(ruleset) = loaded_rules.as_ref() {
            for ev in &report.events {
                let ev_ts = ev.timestamp();
                let matches = correlate(frames, ev_ts, ruleset);
                for m in matches {
                    correlations.push((ev_ts, m));
                }
            }
        }
        let can_impacts = post_message_impacts_can(frames, &report.events, 5000, dbc_map.as_ref());
        impacts.extend(can_impacts);
    }

    if let Some(eth) = eth_frames.as_ref() {
        let eth_impacts = post_message_impacts_eth(eth, &report.events, 5000);
        impacts.extend(eth_impacts);
    }

    // Enrich with CPU load
    for impact in impacts.iter_mut() {
        let window = 5000;
        let before_start = impact.timestamp.saturating_sub(window);
        let after_end = impact.timestamp + window;

        let before_vals: Vec<f64> = load_samples.iter().filter_map(|s| {
            if s.timestamp >= before_start && s.timestamp < impact.timestamp { s.cpu_percent } else { None }
        }).collect();
        let after_vals: Vec<f64> = load_samples.iter().filter_map(|s| {
            if s.timestamp >= impact.timestamp && s.timestamp <= after_end { s.cpu_percent } else { None }
        }).collect();

        let avg_before = if !before_vals.is_empty() { before_vals.iter().sum::<f64>() / before_vals.len() as f64 } else { 0.0 };
        let avg_after = if !after_vals.is_empty() { after_vals.iter().sum::<f64>() / after_vals.len() as f64 } else { 0.0 };

        impact.cpu_before = avg_before;
        impact.cpu_after = avg_after;
        if avg_before > 0.0 {
            impact.cpu_spike_pct = ((avg_after - avg_before) / avg_before) * 100.0;
            impact.is_load_spike = impact.cpu_spike_pct > 30.0;
        }

        if impact.cpu_spike_pct > 30.0 {
            let load_bonus = (impact.cpu_spike_pct.abs() / 100.0 * 20.0).min(20.0);
            impact.causal_score = (impact.causal_score + load_bonus).min(100.0);
        }
    }

    impacts.sort_by(|a, b| {
        b.causal_score.partial_cmp(&a.causal_score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.timestamp.cmp(&b.timestamp))
    });

    // Generate HTML
    let html = generate_html_report(&report, can_frames.as_ref(), eth_frames.as_ref(), Some(&correlations), Some(&impacts))
        .map_err(|e| e.to_string())?;

    Ok(html)
}

/// Simple Ethernet log parser (text format)
fn parse_eth_log(file_path: &str) -> Result<Vec<cross_domain_log_intel::models::EthFrame>, String> {
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use regex::Regex;

    let file = File::open(file_path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);
    let ts_re = Regex::new(r"(\d{9,13})").map_err(|e| e.to_string())?;

    let mut frames = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|e| e.to_string())?;
        let timestamp_ms = if let Some(cap) = ts_re.captures(&line) {
            let s = cap.get(1).unwrap().as_str();
            if s.len() == 10 { s.parse::<i64>().map(|v| v*1000).unwrap_or_else(|_| chrono::Utc::now().timestamp_millis()) } else { s.parse::<i64>().unwrap_or_else(|_| chrono::Utc::now().timestamp_millis()) }
        } else {
            chrono::Utc::now().timestamp_millis()
        };

        let parts: Vec<&str> = line.split_whitespace().collect();
        let iface = parts.get(1).map(|s| s.to_string()).unwrap_or_else(|| "eth0".to_string());
        let direction = parts.get(2).map(|s| s.to_string()).unwrap_or_else(|| "-".to_string());
        let summary = parts.get(3..).map(|s| s.join(" ")).unwrap_or_else(|| "".to_string());

        frames.push(cross_domain_log_intel::models::EthFrame {
            timestamp: timestamp_ms,
            iface,
            direction,
            summary,
            raw: line.clone(),
        });
    }

    Ok(frames)
}

/// Serve the upload form
async fn index() -> HttpResponse {
    let html = r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Log Analysis Upload</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); margin: 0; padding: 20px; min-height: 100vh; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 40px; border-radius: 10px; box-shadow: 0 10px 40px rgba(0,0,0,0.2); }
        h1 { color: #333; margin: 0 0 5px 0; font-size: 2.2em; }
        .subtitle { color: #666; margin-bottom: 30px; font-size: 14px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: 600; color: #333; }
        input[type="file"] { padding: 10px; border: 2px solid #ddd; border-radius: 6px; width: 100%; box-sizing: border-box; cursor: pointer; transition: border-color 0.3s; }
        input[type="file"]:hover { border-color: #667eea; }
        .required { color: #e74c3c; }
        .optional { color: #999; font-size: 12px; }
        button { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 14px 32px; border: none; border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: 600; width: 100%; transition: transform 0.2s, box-shadow 0.2s; }
        button:hover { transform: translateY(-2px); box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4); }
        button:active { transform: translateY(0); }
        .file-group { border: 2px dashed #ddd; padding: 25px; border-radius: 8px; margin-bottom: 25px; background: #f9f9f9; }
        .file-group h3 { margin-top: 0; color: #333; font-size: 1.1em; }
        .info { background: linear-gradient(135deg, #e3f2fd 0%, #f3e5f5 100%); border-left: 4px solid #667eea; padding: 15px; margin-bottom: 25px; border-radius: 6px; }
        .info strong { color: #667eea; }
        .warning { color: #e74c3c; margin: 10px 0; }
        .features { background: #f5f5f5; padding: 15px; border-radius: 6px; margin-top: 25px; }
        .features ul { margin: 10px 0; padding-left: 20px; }
        .features li { margin: 8px 0; color: #555; }
        .beta { display: inline-block; background: #f39c12; color: white; padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-left: 8px; }
        footer { margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee; color: #999; font-size: 12px; text-align: center; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🚗 Automotive Log Analyzer <span class="beta">LOCAL</span></h1>
        <div class="subtitle">Secure offline forensic analysis of QNX, Android, CAN & Ethernet logs</div>
        
        <div class="info">
            <strong>✓ 100% Local Processing:</strong> All files stay on your computer. No data is uploaded to any server. This is a standalone application for your organization.
        </div>

        <form method="POST" enctype="multipart/form-data" action="/upload">
            <div class="file-group">
                <h3>📋 Required System Logs <span class="required">*</span></h3>
                <div class="form-group">
                    <label for="qnx">QNX System Log <span class="required">*</span></label>
                    <input type="file" id="qnx" name="qnx_file" accept=".log,.txt" required>
                    <p style="font-size:11px;color:#999;margin:5px 0 0 0">Any filename accepted (e.g., system.log, qnx_debug.txt, etc.)</p>
                </div>
                <div class="form-group">
                    <label for="android">Android System Log <span class="required">*</span></label>
                    <input type="file" id="android" name="android_file" accept=".log,.txt" required>
                    <p style="font-size:11px;color:#999;margin:5px 0 0 0">Any filename accepted (e.g., logcat.log, android_sys.txt, etc.)</p>
                </div>
            </div>

            <div class="file-group">
                <h3>🔌 Optional Network & Diagnostic Data</h3>
                <div class="form-group">
                    <label for="can">CAN Frame Log (.asc, .log)</label>
                    <input type="file" id="can" name="can_file" accept=".asc,.log,.txt">
                    <p style="font-size:11px;color:#999;margin:5px 0 0 0">Any filename accepted</p>
                </div>
                <div class="form-group">
                    <label for="eth">Ethernet Log (.log) or PCAPNG (.pcapng)</label>
                    <input type="file" id="eth" name="eth_file" accept=".log,.pcapng,.txt">
                    <p style="font-size:11px;color:#999;margin:5px 0 0 0">Any filename accepted</p>
                </div>
                <div class="form-group">
                    <label for="dbc">DBC Signal Definitions (.json)</label>
                    <input type="file" id="dbc" name="dbc_file" accept=".json">
                    <p style="font-size:11px;color:#999;margin:5px 0 0 0">Any filename accepted</p>
                </div>
                <div class="form-group">
                    <label for="rules">Correlation Rules (.json)</label>
                    <input type="file" id="rules" name="rules_file" accept=".json">
                    <p style="font-size:11px;color:#999;margin:5px 0 0 0">Any filename accepted</p>
                </div>
            </div>

            <button type="submit">📊 Analyze & Generate Report</button>
        </form>

        <div class="features">
            <strong>Report Includes:</strong>
            <ul>
                <li><strong>Executive Summary:</strong> Total crashes, timeouts, watchdog triggers per domain</li>
                <li><strong>Issues Forensics:</strong> Detailed fault/warning timeline with timestamps</li>
                <li><strong>Domain Breakdown:</strong> QNX vs Android impact comparison</li>
                <li><strong>Message Impact Analysis:</strong> Which CAN/ETH frames caused failures (ranked by causal score)</li>
                <li><strong>Anomaly Detection:</strong> Statistical z-score detection of unusual event rates</li>
                <li><strong>Load Tracking:</strong> CPU spike correlation with message injection</li>
            </ul>
        </div>

        <footer>
            <p><strong>🔒 Privacy:</strong> This application runs entirely on your machine. No internet connection required. No telemetry.</p>
            <p>Version 1.0 | Automotive Forensics Suite</p>
        </footer>
    </div>
</body>
</html>"#;
    HttpResponse::Ok().content_type("text/html; charset=utf-8").body(html)
}

/// Simple HTML escape
fn html_escape(s: &str) -> String {
    s.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace("\"", "&quot;")
        .replace("'", "&#39;")
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║   🚗 Cross-Domain Automotive Log Analyzer                     ║");
    println!("║   ✓ Offline | ✓ Secure | ✓ Enterprise-Ready                  ║");
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║                                                                ║");
    println!("║   🌐 Open your browser to:   http://localhost:8080           ║");
    println!("║                                                                ║");
    println!("║   📂 Features:                                                 ║");
    println!("║      • Upload QNX, Android, CAN, & Ethernet logs             ║");
    println!("║      • Causal impact analysis (message → crash correlation)  ║");
    println!("║      • Anomaly detection (z-score statistics)                ║");
    println!("║      • Load spike tracking (CPU timeline)                    ║");
    println!("║      • Professional HTML forensic report                     ║");
    println!("║                                                                ║");
    println!("║   🔒 All processing is LOCAL - no internet, no cloud         ║");
    println!("║                                                                ║");
    println!("║   Press Ctrl+C to stop the server                            ║");
    println!("║                                                                ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");

    HttpServer::new(|| {
        App::new()
            .wrap(middleware::NormalizePath::trim())
            .route("/", web::get().to(index))
            .route("/upload", web::post().to(upload_and_analyze))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
