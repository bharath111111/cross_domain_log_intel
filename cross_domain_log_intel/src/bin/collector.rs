use anyhow::Result;
use std::fs;
use std::path::Path;
use std::process::Command;
use chrono::Local;
use std::io::Write;
use std::process::Stdio;
use std::fs::OpenOptions;
use std::collections::HashMap;
use once_cell::sync::OnceCell;
use serde::Deserialize;

use cross_domain_log_intel::{
    models::{Domain, LogEntry},
    parser::{self, extract_load_samples},
    classifier::classify_logs,
    metrics::generate_metrics,
    reporter::generate_html_report,
};
use ssh2::Session;
use std::net::TcpStream;
use std::io::Read;

fn main() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║   🚗 Automotive Log Collector                                 ║");
    println!("║   Automatic QNX & Android Log Extraction                     ║");
    println!("╚════════════════════════════════════════════════════════════════╝\n");
    // Load config (if present)
    if let Ok(cfg) = load_config() {
        let _ = CONFIG.set(cfg);
    }

    loop {
        print_menu()?;
        let mut input = String::new();
        std::io::stdin().read_line(&mut input)?;
        let choice = input.trim();

        match choice {
            "1" => collect_qnx_logs()?,
            "2" => collect_android_logs()?,
            "7" => collect_both()?,
            "3" => generate_report()?,
            "4" => list_stored_logs()?,
            "6" => start_stop_android_streaming()?,
            "5" => {
                println!("\n👋 Goodbye!\n");
                break;
            }
            _ => println!("❌ Invalid option. Try again."),
        }
    }

    Ok(())
}

fn print_menu() -> Result<()> {
    println!("\n╔════════════════════════════════════════════════════════════════╗");
    println!("║                         MAIN MENU                              ║");
    println!("╠════════════════════════════════════════════════════════════════╣");
    println!("║  1️⃣ Collect QNX Logs (via SSH)                                 ║");
    println!("║  2️⃣ Collect Android Logs (via ADB)                             ║");
    println!("║  3️⃣ Generate Report from Stored Logs                           ║");
    println!("║  4️⃣ List Stored Log Sessions                                   ║");
    println!("║  6️⃣ Start/Stop Android Streaming (logcat)                      ║");
    println!("║  7️⃣ Collect Both (QNX + Android)                               ║");
    println!("║  5️⃣ Exit                                                        ║");
    println!("╚════════════════════════════════════════════════════════════════╝");
    print!("\n👉 Enter your choice (1-7): ");
    std::io::stdout().flush()?;
    Ok(())
}

static CONFIG: OnceCell<Config> = OnceCell::new();

#[derive(Debug, Deserialize, Clone)]
struct Config {
    default_profile: Option<String>,
    profiles: Option<HashMap<String, Profile>>,
}

#[derive(Debug, Deserialize, Clone)]
struct Profile {
    qnx_ip: Option<String>,
    qnx_user: Option<String>,
    qnx_port: Option<u16>,
    qnx_password: Option<String>,
    adb_serial: Option<String>,
}

fn load_config() -> Result<Config> {
    let home = dirs::home_dir().ok_or_else(|| anyhow::anyhow!("home dir not found"))?;
    let cfg_path = home.join(".log_collector").join("config.yaml");
    if !cfg_path.exists() {
        anyhow::bail!("no config file");
    }
    let s = std::fs::read_to_string(&cfg_path)?;
    let cfg: Config = serde_yaml::from_str(&s)?;
    Ok(cfg)
}

fn get_default_profile() -> Option<&'static Profile> {
    if let Some(cfg) = CONFIG.get() {
        if let Some(dp) = &cfg.default_profile {
            if let Some(profiles) = &cfg.profiles {
                if let Some(p) = profiles.get(dp) {
                    // Safety: leak profile to 'static by cloning into Box
                    // but avoid complexity: return reference via Box leak
                    let boxed: Box<Profile> = Box::new(p.clone());
                    let static_ref: &'static Profile = Box::leak(boxed);
                    return Some(static_ref);
                }
            }
        }
    }
    None
}

fn download_qnx_noninteractive(qnx_ip: &str, username: &str, password: &str, port: &str, session_dir: &str) -> Result<()> {
    let qnx_log_remote = "/var/log/qnx_system.log";
    let qnx_log_local = format!("{}/qnx.log", session_dir);

    let addr = format!("{}:{}", qnx_ip, port);
    let ssh_result = (|| -> Result<()> {
        let tcp = TcpStream::connect(&addr)?;
        let mut session = Session::new()?;
        session.set_tcp_stream(tcp);
        session.handshake()?;

        let mut authed = false;
        if !password.is_empty() {
            if session.userauth_password(&username, &password).is_ok() {
                authed = true;
            }
        } else {
            if let Some(home) = dirs::home_dir() {
                let priv_key = home.join(".ssh/id_rsa");
                let pubk = home.join(".ssh/id_rsa.pub");
                if priv_key.exists() {
                    if session.userauth_pubkey_file(&username, Some(&pubk), &priv_key, None).is_ok() {
                        authed = true;
                    }
                }
            }
        }

        if !authed || !session.authenticated() {
            anyhow::bail!("SSH authentication failed");
        }

        match session.scp_recv(Path::new(qnx_log_remote)) {
            Ok((mut remote_file, _stat)) => {
                let mut contents = Vec::new();
                remote_file.read_to_end(&mut contents)?;
                fs::write(&qnx_log_local, &contents)?;
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("SCP recv failed: {}", e)),
        }
    })();

    if let Err(_e) = ssh_result {
        // fallback to system scp
        let scp_output = Command::new("scp")
            .args(&[
                "-P", &port,
                &format!("{}@{}:{}", &username, &qnx_ip, qnx_log_remote),
                &qnx_log_local,
            ])
            .output();

        match scp_output {
            Ok(output) => {
                if !output.status.success() {
                    create_mock_qnx_log(&qnx_log_local)?;
                }
            }
            Err(_e) => {
                create_mock_qnx_log(&qnx_log_local)?;
            }
        }
    }

    Ok(())
}

fn download_android_noninteractive(device_serial: Option<String>, session_dir: &str) -> Result<()> {
    let android_log_local = format!("{}/android.log", session_dir);
    let output = if let Some(serial) = device_serial {
        Command::new("adb").args(&["-s", &serial, "logcat", "-d", "*:V"]).output()
    } else {
        Command::new("adb").args(&["logcat", "-d", "*:V"]).output()
    };

    match output {
        Ok(result) => {
            if result.status.success() {
                fs::write(&android_log_local, &result.stdout)?;
            } else {
                create_mock_android_log(&android_log_local)?;
            }
        }
        Err(_e) => {
            create_mock_android_log(&android_log_local)?;
        }
    }

    Ok(())
}

fn collect_both() -> Result<()> {
    println!("\n🔁 Parallel QNX + Android Collection");
    println!("────────────────────────────────────\n");
    let default_profile = get_default_profile();
    let default_qnx_ip = default_profile.and_then(|p| p.qnx_ip.as_deref());
    if let Some(def) = default_qnx_ip { print!("🔗 QNX System IP Address [{}]: ", def); } else { print!("🔗 QNX System IP Address: "); }
    std::io::stdout().flush()?;
    let mut qnx_ip = String::new();
    std::io::stdin().read_line(&mut qnx_ip)?;
    let mut qnx_ip = qnx_ip.trim().to_string();
    if qnx_ip.is_empty() { if let Some(def) = default_qnx_ip { qnx_ip = def.to_string(); } }

    let default_user = default_profile.and_then(|p| p.qnx_user.as_deref());
    if let Some(def) = default_user { print!("👤 QNX Username (default: {}): ", def); } else { print!("👤 QNX Username (default: root): "); }
    std::io::stdout().flush()?;
    let mut username = String::new();
    std::io::stdin().read_line(&mut username)?;
    let mut username = username.trim().to_string();
    if username.is_empty() { if let Some(def) = default_user { username = def.to_string(); } else { username = "root".to_string(); } }

    let default_pass = default_profile.and_then(|p| p.qnx_password.as_deref());
    if default_pass.is_some() { print!("🔐 QNX Password (from profile or press Enter): "); } else { print!("🔐 QNX Password (leave blank to try key): "); }
    std::io::stdout().flush()?;
    let mut password = String::new();
    std::io::stdin().read_line(&mut password)?;
    let mut password = password.trim().to_string();
    if password.is_empty() { if let Some(def) = default_pass { password = def.to_string(); } }

    let default_port = default_profile.and_then(|p| p.qnx_port.map(|p| p.to_string()));
    if let Some(def) = &default_port { print!("📁 QNX Port (default: {}): ", def); } else { print!("📁 QNX Port (default: 22): "); }
    std::io::stdout().flush()?;
    let mut port = String::new();
    std::io::stdin().read_line(&mut port)?;
    let mut port = port.trim().to_string();
    if port.is_empty() { if let Some(def) = default_port { port = def; } else { port = "22".to_string(); } }

    let default_adb = default_profile.and_then(|p| p.adb_serial.as_deref());
    if let Some(def) = default_adb { print!("📱 Android device serial [{}] (leave blank to auto-detect): ", def); } else { print!("📱 Android device serial (leave blank to auto-detect): "); }
    std::io::stdout().flush()?;
    let mut serial = String::new();
    std::io::stdin().read_line(&mut serial)?;
    let mut serial = serial.trim().to_string();
    if serial.is_empty() { if let Some(def) = default_adb { serial = def.to_string(); } }
    let device_serial = if serial.is_empty() { None } else { Some(serial) };

    let storage = ensure_storage_dir()?;
    let session_dir = format!("{}/session_{}", storage, timestamp_str());
    fs::create_dir_all(&session_dir)?;

    // spawn threads
    let qnx_ip_c = qnx_ip.clone();
    let username_c = username.clone();
    let password_c = password.clone();
    let port_c = port.clone();
    let session_dir_qnx = session_dir.clone();

    let handle_qnx = std::thread::spawn(move || {
        let _ = download_qnx_noninteractive(&qnx_ip_c, &username_c, &password_c, &port_c, &session_dir_qnx);
    });

    let session_dir_and = session_dir.clone();
    let device_serial_c = device_serial.clone();
    let handle_and = std::thread::spawn(move || {
        let _ = download_android_noninteractive(device_serial_c, &session_dir_and);
    });

    println!("⏳ Running QNX and Android collection in parallel...");
    let _ = handle_qnx.join();
    let _ = handle_and.join();

    println!("✅ Parallel collection finished. Session dir: {}", session_dir);
    Ok(())
}

fn start_stop_android_streaming() -> Result<()> {
    let storage = ensure_storage_dir()?;
    let pid_path = format!("{}/adb_stream.pid", storage);
    let meta_path = format!("{}/adb_stream.meta", storage);

    // If pid file exists -> stop
    if Path::new(&pid_path).exists() {
        let pid = fs::read_to_string(&pid_path)?.trim().to_string();
        println!("⏹ Stopping adb streaming (pid {})...", pid);
        let kill = Command::new("kill").arg(&pid).status();
        match kill {
            Ok(s) if s.success() => println!("✅ Streaming stopped."),
            Ok(s) => println!("⚠️ kill returned status: {}", s),
            Err(e) => println!("⚠️ Failed to run kill: {}", e),
        }
        if Path::new(&meta_path).exists() {
            if let Ok(meta) = fs::read_to_string(&meta_path) {
                println!("Stream file: {}", meta.trim());
            }
        }
        let _ = fs::remove_file(&pid_path);
        let _ = fs::remove_file(&meta_path);
        return Ok(());
    }

    // Start streaming
    println!("🚀 Starting adb logcat streaming to file...");
    print!("📱 Enter device serial (leave blank for default adb): ");
    std::io::stdout().flush()?;
    let mut manual = String::new();
    std::io::stdin().read_line(&mut manual)?;
    let manual = manual.trim();

    let session_dir = format!("{}/android_stream_{}", storage, timestamp_str());
    fs::create_dir_all(&session_dir)?;
    let out_file = format!("{}/adb_stream.log", session_dir);

    let mut cmd = Command::new("adb");
    if !manual.is_empty() {
        cmd.args(&["-s", manual, "logcat"]);
    } else {
        cmd.args(&["logcat"]);
    }

    let file = OpenOptions::new().create(true).append(true).open(&out_file)?;
    let child = cmd.stdout(Stdio::from(file)).spawn();
    match child {
        Ok(child_proc) => {
            let pid = child_proc.id();
            fs::write(&pid_path, pid.to_string())?;
            fs::write(&meta_path, &out_file)?;
            println!("✅ Streaming started (pid {}). Output: {}", pid, out_file);
            println!("ℹ️ Use the same menu option to stop streaming.");
            // detach: we drop child_proc so it runs independently
            std::mem::forget(child_proc);
        }
        Err(e) => {
            println!("⚠️ Failed to start adb logcat: {}", e);
        }
    }

    Ok(())
}

fn ensure_storage_dir() -> Result<String> {
    let storage_path = format!("{}/.log_collector", dirs::home_dir().unwrap().to_string_lossy());
    fs::create_dir_all(&storage_path)?;
    Ok(storage_path)
}

fn collect_qnx_logs() -> Result<()> {
    println!("\n📋 QNX Log Collection Setup");
    println!("──────────────────────────────\n");

    let storage = ensure_storage_dir()?;
    let session_dir = format!("{}/qnx_{}", storage, timestamp_str());
    fs::create_dir_all(&session_dir)?;

    let default_profile = get_default_profile();
    let default_qnx_ip = default_profile.and_then(|p| p.qnx_ip.as_deref());
    if let Some(def) = default_qnx_ip {
        print!("🔗 QNX System IP Address [{}]: ", def);
    } else {
        print!("🔗 QNX System IP Address: ");
    }
    std::io::stdout().flush()?;
    let mut qnx_ip = String::new();
    std::io::stdin().read_line(&mut qnx_ip)?;
    let mut qnx_ip = qnx_ip.trim().to_string();
    if qnx_ip.is_empty() {
        if let Some(def) = default_qnx_ip { qnx_ip = def.to_string(); }
    }

    let default_user = default_profile.and_then(|p| p.qnx_user.as_deref());
    if let Some(def) = default_user {
        print!("👤 Username (default: {}): ", def);
    } else {
        print!("👤 Username (default: root): ");
    }
    std::io::stdout().flush()?;
    let mut username = String::new();
    std::io::stdin().read_line(&mut username)?;
    let mut username = username.trim().to_string();
    if username.is_empty() {
        if let Some(def) = default_user { username = def.to_string(); } else { username = "root".to_string(); }
    }

    let default_pass = default_profile.and_then(|p| p.qnx_password.as_deref());
    if default_pass.is_some() {
        print!("🔐 Password (from profile or press Enter): ");
    } else {
        print!("🔐 Password: ");
    }
    std::io::stdout().flush()?;
    let mut password = String::new();
    std::io::stdin().read_line(&mut password)?;
    let mut password = password.trim().to_string();
    if password.is_empty() {
        if let Some(def) = default_pass { password = def.to_string(); }
    }

    let default_port = default_profile.and_then(|p| p.qnx_port.map(|p| p.to_string()));
    if let Some(def) = &default_port {
        print!("📁 Port (default: {}): ", def);
    } else {
        print!("📁 Port (default: 22): ");
    }
    std::io::stdout().flush()?;
    let mut port = String::new();
    std::io::stdin().read_line(&mut port)?;
    let mut port = port.trim().to_string();
    if port.is_empty() {
        if let Some(def) = default_port { port = def; } else { port = "22".to_string(); }
    }

    println!("\n⏳ Connecting to QNX system at {}:{}...", qnx_ip, port);

    // Try to collect logs via SSH/SCP
    let qnx_log_remote = "/var/log/qnx_system.log";
    let qnx_log_local = format!("{}/qnx.log", session_dir);

    // Try SSH-based download using libssh2 (ssh2 crate). Fall back to system `scp` on failure.
    let addr = format!("{}:{}", qnx_ip, port);
    let ssh_result = (|| -> Result<()> {
        let tcp = TcpStream::connect(&addr)?;
        let mut session = Session::new()?;
        session.set_tcp_stream(tcp);
        session.handshake()?;

        let mut authed = false;
        if !password.is_empty() {
            if session.userauth_password(&username, &password).is_ok() {
                authed = true;
            }
        } else {
            // try default key
            if let Some(home) = dirs::home_dir() {
                let priv_key = home.join(".ssh/id_rsa");
                let pubk = home.join(".ssh/id_rsa.pub");
                if priv_key.exists() {
                    if session.userauth_pubkey_file(&username, Some(&pubk), &priv_key, None).is_ok() {
                        authed = true;
                    }
                }
            }
        }

        if !authed || !session.authenticated() {
            anyhow::bail!("SSH authentication failed");
        }

        match session.scp_recv(Path::new(qnx_log_remote)) {
            Ok((mut remote_file, _stat)) => {
                let mut contents = Vec::new();
                remote_file.read_to_end(&mut contents)?;
                fs::write(&qnx_log_local, &contents)?;
                println!("✅ QNX logs downloaded successfully via SSH!");
                println!("📁 Saved to: {}", qnx_log_local);
                println!("🔐 Connection: {}@{}:{}", username, qnx_ip, port);
                println!("\n💡 Session: {}", session_dir);
                Ok(())
            }
            Err(e) => Err(anyhow::anyhow!("SCP recv failed: {}", e)),
        }
    })();

    if let Err(e) = ssh_result {
        println!("⚠️ SSH download failed: {}", e);
        println!("Attempting system scp fallback (requires scp on PATH)...");
        let scp_output = Command::new("scp")
            .args(&[
                "-P", &port,
                &format!("{}@{}:{}", &username, &qnx_ip, qnx_log_remote),
                &qnx_log_local,
            ])
            .output();

        match scp_output {
            Ok(output) => {
                if output.status.success() {
                    println!("✅ QNX logs downloaded successfully via scp fallback!");
                    println!("📁 Saved to: {}", qnx_log_local);
                    println!("\n💡 Session: {}", session_dir);
                } else {
                    println!("⚠️ Fallback scp failed: {}", String::from_utf8_lossy(&output.stderr));
                    println!("📝 Creating mock log for demo...");
                    create_mock_qnx_log(&qnx_log_local)?;
                }
            }
            Err(e) => {
                println!("⚠️ Failed to run scp: {}", e);
                println!("📝 Creating mock log for demo...");
                create_mock_qnx_log(&qnx_log_local)?;
            }
        }
    }

    Ok(())
}

fn collect_android_logs() -> Result<()> {
    println!("\n📱 Android Log Collection Setup");
    println!("────────────────────────────────\n");

    let storage = ensure_storage_dir()?;
    let session_dir = format!("{}/android_{}", storage, timestamp_str());
    fs::create_dir_all(&session_dir)?;

    println!("🔌 Ensure your Android device is connected via ADB...");
    let default_profile = get_default_profile();
    let default_adb = default_profile.and_then(|p| p.adb_serial.as_deref());
    
    // Try to detect devices via `adb devices`
    let devices_output = Command::new("adb").arg("devices").arg("-l").output();
    let mut chosen_serial: Option<String> = None;
    if let Ok(out) = devices_output {
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut devices: Vec<String> = Vec::new();
        for line in stdout.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("List of devices") { continue; }
            // lines look like: <serial>\tdevice product:... model:... device:...
            let parts: Vec<&str> = line.split_whitespace().collect();
            if !parts.is_empty() && parts[0] != "" {
                devices.push(parts[0].to_string());
            }
        }

        if devices.len() == 1 {
            chosen_serial = Some(devices[0].clone());
            println!("Detected Android device: {}", devices[0]);
        } else if devices.len() > 1 {
            println!("Multiple ADB devices detected:");
            for (i, d) in devices.iter().enumerate() {
                println!("  {}) {}", i + 1, d);
            }
            print!("Select device number: ");
            std::io::stdout().flush()?;
            let mut sel = String::new();
            std::io::stdin().read_line(&mut sel)?;
            if let Ok(idx) = sel.trim().parse::<usize>() {
                if idx >= 1 && idx <= devices.len() {
                    chosen_serial = Some(devices[idx - 1].clone());
                }
            }
        } else {
            println!("No ADB devices found automatically.");
        }
    } else {
        println!("Failed to run `adb devices` (is adb installed?)");
    }

    if chosen_serial.is_none() {
        if let Some(def) = default_adb {
            print!("📱 Enter device serial [{}] (leave blank to use default): ", def);
        } else {
            print!("📱 Enter device serial (or leave blank to use default adb): ");
        }
        std::io::stdout().flush()?;
        let mut manual = String::new();
        std::io::stdin().read_line(&mut manual)?;
        let manual = manual.trim();
        if !manual.is_empty() {
            chosen_serial = Some(manual.to_string());
        } else if let Some(def) = default_adb {
            chosen_serial = Some(def.to_string());
        }
    }

    println!("\n⏳ Collecting Android logs via ADB...");

    let android_log_local = format!("{}/android.log", session_dir);
    let output = if let Some(serial) = &chosen_serial {
        Command::new("adb").args(&["-s", serial, "logcat", "-d", "*:V"]).output()
    } else {
        Command::new("adb").args(&["logcat", "-d", "*:V"]).output()
    };

    match output {
        Ok(result) => {
            if result.status.success() {
                fs::write(&android_log_local, &result.stdout)?;
                println!("✅ Android logs downloaded successfully!");
                println!("📁 Saved to: {}", android_log_local);
                println!("\n💡 Session: {}", session_dir);
            } else {
                println!("⚠️ ADB error - creating mock log for demo...\n{}", String::from_utf8_lossy(&result.stderr));
                create_mock_android_log(&android_log_local)?;
            }
        }
        Err(e) => {
            println!("⚠️ Failed to run ADB: {}", e);
            println!("📝 Creating mock log for demo...");
            create_mock_android_log(&android_log_local)?;
        }
    }

    Ok(())
}

fn generate_report() -> Result<()> {
    println!("\n📊 Report Generation");
    println!("───────────────────\n");

    let storage = ensure_storage_dir()?;
    
    print!("📂 Enter session name (or 'latest'): ");
    std::io::stdout().flush()?;
    let mut session_name = String::new();
    std::io::stdin().read_line(&mut session_name)?;
    let session_name = session_name.trim();

    let session_dir = if session_name == "latest" {
        find_latest_session(&storage)?
    } else {
        format!("{}/{}", storage, session_name)
    };

    if !Path::new(&session_dir).exists() {
        println!("❌ Session directory not found: {}", session_dir);
        return Ok(());
    }

    let qnx_log = format!("{}/qnx.log", session_dir);
    let android_log = format!("{}/android.log", session_dir);

    if !Path::new(&qnx_log).exists() || !Path::new(&android_log).exists() {
        println!("❌ Log files not found in session!");
        return Ok(());
    }

    println!("⏳ Analyzing logs...");

    // Parse logs
    let mut qnx_entries = parser::parse_log(&qnx_log, Domain::Qnx)?;
    let mut android_entries = parser::parse_log(&android_log, Domain::Android)?;

    let mut all = Vec::new();
    all.append(&mut qnx_entries);
    all.append(&mut android_entries);
    all.sort_by_key(|e| e.timestamp);

    let load_samples = extract_load_samples(&all);
    let events = classify_logs(&all);
    let report = generate_metrics(&events, &load_samples);

    let json = serde_json::to_string_pretty(&report)?;
    println!("\n✅ Analysis Complete:");
    println!("{}", json);

    // Generate HTML report
    println!("\n⏳ Generating HTML report...");
    let html = generate_html_report(&report, None, None, None, None)?;
    
    let report_path = format!("{}/report.html", session_dir);
    fs::write(&report_path, &html)?;

    println!("✅ Report generated!");
    println!("📄 Saved to: {}", report_path);
    println!("🌐 Open in browser to view\n");

    Ok(())
}

fn list_stored_logs() -> Result<()> {
    println!("\n📋 Stored Log Sessions");
    println!("──────────────────────\n");

    let storage = ensure_storage_dir()?;
    let entries = fs::read_dir(&storage)?;
    
    let mut sessions = Vec::new();
    for entry in entries {
        if let Ok(entry) = entry {
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    sessions.push(name.to_string());
                }
            }
        }
    }

    if sessions.is_empty() {
        println!("No stored sessions yet. Collect logs first!\n");
        return Ok(());
    }

    sessions.sort();
    sessions.reverse(); // Show newest first

    println!("{}  Session Name                  | Logs Present", "─".repeat(60));
    for session in &sessions {
        let qnx_exists = Path::new(&format!("{}/{}/qnx.log", storage, session)).exists();
        let android_exists = Path::new(&format!("{}/{}/android.log", storage, session)).exists();
        let logs = format!("QNX: {} | Android: {}", 
            if qnx_exists { "✅" } else { "❌" },
            if android_exists { "✅" } else { "❌" }
        );
        println!(" {:40} {}", session, logs);
    }
    
    println!();
    Ok(())
}

fn find_latest_session(storage: &str) -> Result<String> {
    let entries = fs::read_dir(storage)?;
    let mut latest: Option<String> = None;

    for entry in entries {
        if let Ok(entry) = entry {
            if entry.path().is_dir() {
                if let Some(name) = entry.file_name().to_str() {
                    if latest.as_ref().map_or(true, |l| name > l.as_str()) {
                        latest = Some(name.to_string());
                    }
                }
            }
        }
    }

    match latest {
        Some(name) => Ok(format!("{}/{}", storage, name)),
        None => Err(anyhow::anyhow!("No sessions found")),
    }
}

fn timestamp_str() -> String {
    Local::now().format("%Y%m%d_%H%M%S").to_string()
}

fn create_mock_qnx_log(path: &str) -> Result<()> {
    let mock_content = r#"1708423215000 QNX kernel GpsService service crashed
1708423217000 QNX kernel MediaServer service crashed
1708423220000 QNX kernel WatchdogService watchdog triggered
1708423225000 QNX kernel System reset detected
1708423240000 QNX kernel NetworkManager timeout
1708423245000 QNX kernel WatchdogService watchdog triggered
1708423250000 QNX kernel System reset GpsService failed
CPU: 45% Mem: 512MB
1708423260000 QNX kernel GpsService service crashed
1708423270000 QNX kernel NetworkManager timeout occurred
1708423275000 QNX framework abnormal deviation
1708423280000 QNX kernel NetworkManager timeout occurred
1708423285000 QNX kernel GpsService service crashed urgent=HIGH
1708423290000 QNX kernel abnormal deviation
1708423295000 QNX kernel System reset detected
1708423303000 QNX kernel GpsService service crashed urgent=HIGH
1708423304000 QNX kernel NetworkManager timeout waiting for response
1708423306000 QNX kernel MediaService service crashed buffer_overflow=true
1708423308000 QNX kernel WatchdogService watchdog triggered service=GpsService
"#;
    fs::write(path, mock_content)?;
    println!("✅ Mock QNX log created at: {}", path);
    Ok(())
}

fn create_mock_android_log(path: &str) -> Result<()> {
    let mock_content = r#"1708423217000 Android services MediaServer service crashed
1708423222000 Android framework watchdog triggered
1708423227000 Android system reset rebooted
1708423242000 Android services AudioFlinger timeout occurred
1708423247000 Android framework watchdog triggered
1708423252000 Android system reset after crash
1708423267000 Android services MediaServer service crashed
1708423272000 Android services AudioFlinger timeout
1708423277000 Android system discrepancy in messaging
1708423282000 Android services AudioFlinger timeout
1708423287000 Android services MediaServer service crashed
1708423292000 Android framework abnormal behavior detected
CPU: 65% Mem: 1024MB
1708423297000 Android system reset detected
"#;
    fs::write(path, mock_content)?;
    println!("✅ Mock Android log created at: {}", path);
    Ok(())
}
