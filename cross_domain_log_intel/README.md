# 🚗 Cross-Domain Automotive Log Analyzer

A **production-ready, offline forensic analysis tool** for automotive system logs (QNX, Android, CAN, Ethernet).

**100% Local Processing • Enterprise Security • Single Executable**

## 🚀 Quick Start

### Option 1: Web Interface (Recommended)
```bash
./START_ANALYZER.sh
# Opens http://localhost:8080 - upload logs, get instant report
```

### Option 2: Command-Line
```bash
./target/release/cli qnx.log android.log --can sample_can.asc --html report.html
```

## ✨ Features

- **Web Interface**: User-friendly file upload form with instant analysis
- **Offline Processing**: Zero internet required, enterprise-secure
- **System Log Analysis**: Parse QNX & Android logs simultaneously
- **CAN Correlation**: Identify which CAN frames caused system failures
- **Ethernet Support**: Analyze network impacts (text or PCAPNG binary format)
- **Signal Decoding**: Optional DBC file for CAN signal interpretation
- **Load Tracking**: CPU/memory spike correlation with messages
- **Causal Scoring**: 0-100 ranking of frame→crash likelihood
- **Anomaly Detection**: Z-score statistical analysis of unusual events
- **Professional Reports**: Color-coded HTML forensic analysis
- **Standalone Binary**: Single executable, deploy anywhere

## 📋 Web Interface Usage

**Start application:**
```bash
./START_ANALYZER.sh
```

**Then in browser (http://localhost:8080):**

1. Upload QNX system log ✅ (required)
2. Upload Android system log ✅ (required)  
3. Upload CAN/Ethernet logs ⭕ (optional)
4. Upload DBC/Rules JSON ⭕ (optional)
5. Click "Analyze & Generate Report"
6. View instant forensic analysis with:
   - Executive summary
   - Issues timeline (faults & warnings)
   - **Message Impacts & Correlations** (ranked by causal score)
   - Anomaly detection results
   - CPU load correlation

## 📂 Input Formats

**Required:** 
- **QNX Log**: Text file with timestamps, crash events, watchdog triggers
- **Android Log**: Text file with service crashes, timeouts, system events

**Optional:**
- **CAN Log** (.asc): Vector CANoe ASCII format
- **Ethernet** (.log): Text format or **PCAPNG binary** from Wireshark/tcpdump
- **DBC (JSON)**: CAN signal definitions for decoding
- **Rules (JSON)**: Custom correlation rules

**Log Format Example:**
```
1708423215000 QNX kernel GpsService service crashed
1708423217000 Android services MediaServer service crashed  
1708423220000 QNX kernel WatchdogService watchdog triggered
```

Include optional tokens like: `CPU: 65%`, `Mem: 512MB`

## 🎯 Understanding Your Report

### Causal Score (0-100)
Higher score = Message more likely caused the failures

**Scoring combines:**
- Crash severity (crashes = +30, timeouts = +5 each)
- Time proximity (<500ms = +20, scales to +5 at 5s)
- CPU spike magnitude (each 1% → +0.2)
- Event rate multiplication (1.8x+ baseline = +10)

**Color Coding:**
- 🔴 Red (80-100): **CRITICAL** - Very likely cause
- 🟠 Orange (60-79): **HIGH** - Probable cause  
- 🟡 Gold (40-59): **MEDIUM** - Possible cause
- ⚪ Gray (<40): **LOW** - Unlikely cause

### Anomaly Z-Score
Detects statistically unusual event rates
- **Z > 2.0** = Unusual spike (marked with 🚩)
- Indicates frame triggered abnormal system behavior

### Example Impact Row
```
CAN Frame 0x123 @ 1708423.6s
├─ Severity: CRITICAL
├─ Causal Score: 85 ← ROOT CAUSE LIKELY
├─ Crashes: GpsService, LocationManager (2 services)
├─ CPU Load: 20% → 65% (↑45%)
├─ Anomaly Z-Score: 2.8 🚩 (UNUSUAL)
└─ Timeline: Frame → 50ms crash → 200ms CPU spike
```

## 📊 Report Output

### Web Browser Report
Displays in browser within seconds:
- **Executive Summary**: Total crashes, timeouts, watchdog triggers, boot time
- **Issues Table**: All faults & warnings with timestamps, sorted by severity
- **Domain Breakdown**: Side-by-side QNX vs Android comparison
- **Message Impacts & Correlations**: 
  - Ranked by causal score (highest risk first)
  - Color-coded severity
  - Crashed service names
  - CPU spike magnitude  
  - Anomaly detection flags
  - Decoded CAN signals (if DBC provided)

### Command-Line Report
```bash
./target/release/cli qnx.log android.log --can sample_can.asc --html report.html
```
Generates: `report.html` (same as web version)

JSON metrics also printed to console:
```json
{
  "total_service_crashes": 14,
  "total_system_crashes": 2,
  "total_timeouts": 9,
  "total_watchdog_triggers": 6,
  "generated_at": "2026-02-21 02:52:55"
}
```

## 🔐 Security & Privacy

- ✅ **100% Offline**: No cloud, no server
- ✅ **Zero Telemetry**: Doesn't phone home
- ✅ **Enterprise Safe**: Can process classified logs
- ✅ **Self-Contained**: Single ~5MB executable
- ✅ **Local Processing**: All analysis on your machine

## 📁 File Structure

```
cross_domain_log_intel/
├── START_ANALYZER.sh           ← Easy launcher
├── target/release/
│   ├── web                     ← Web application (5.3 MB)
│   └── cli                     ← Command-line tool
├── qnx.log                     ← Sample QNX log
├── android.log                 ← Sample Android log
├── sample_can.asc              ← Sample CAN frames
├── sample_eth.log              ← Sample Ethernet
├── sample_dbc.json             ← Sample signal definitions
├── sample_rules.json           ← Sample correlation rules
└── validation_report.html      ← Example report output
```

## 🆘 Troubleshooting

### "Address already in use" error
```bash
killall web    # Kill existing process
sleep 2
./START_ANALYZER.sh
```

### Report shows no impacts
- Add optional CAN/Ethernet files
- Ensure events occur near frame timestamps
- Impact window is 5 seconds before/after frame

### Low causal scores
- Expected if no crashes near frames
- Scores based on actual system failures detected
- Check Issues table to confirm events exist

## 📦 Deployment

**Share with your organization:**
```bash
# Copy just the executable
cp target/release/web /path/to/distribution/

# Or the startup script + executable
cp START_ANALYZER.sh target/release/web /path/to/distribution/
```

Works on any macOS/Linux system without additional dependencies!

## 🏗️ Building from Source

```bash
# Requires Rust 1.56+
cargo build --release --bin web    # Web application
cargo build --release --bin cli    # Command-line tool
```

## 📝 License & Compliance

This tool is designed for:
- ✅ Automotive diagnostics
- ✅ Security research
- ✅ Root cause analysis
- ✅ System validation
- ✅ Enterprise compliance

**Version**: 1.0  
**Status**: Production Ready ✅  
**Date**: February 2026

## Key Algorithms

- **Load Spikes**: Detects >30% CPU increase in 5s post-injection window → `[LOAD SPIKE]`
- **Impact Detection**: Counts crashes/timeouts after each TX frame, flags rate anomalies
- **Signal Decoding**: Extracts and scales CAN signal values (if DBC provided)

## Options

```
--can FILE              CAN ASCII log
--eth FILE              Ethernet text log
--eth-pcapng FILE       PCAPNG binary capture
--dbc FILE              DBC signal definitions (JSON)
--rules FILE            Correlation rules (JSON)
--html OUTPUT           HTML report path
```
