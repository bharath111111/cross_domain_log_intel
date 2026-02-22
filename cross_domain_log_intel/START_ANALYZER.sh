#!/bin/bash

# Cross-Domain Automotive Log Analyzer - Local Application Launcher
# Secure offline forensic analysis - 100% local processing

echo ""
echo "╔════════════════════════════════════════════════════════════════╗"
echo "║   🚗 Cross-Domain Automotive Log Analyzer                     ║"
echo "║                                                                ║"
echo "║   ✓ 100% Local Processing                                     ║"
echo "║   ✓ No Internet Required                                      ║"
echo "║   ✓ Enterprise-Ready Security                                 ║"
echo "╠════════════════════════════════════════════════════════════════╣"
echo "║                                                                ║"
echo "║   Starting server...                                           ║"
echo "║                                                                ║"
echo "║   Open your browser to:  http://localhost:8080               ║"
echo "║                                                                ║"
echo "║   Features:                                                    ║"
echo "║   • Upload QNX & Android system logs                          ║"
echo "║   • Analyze CAN & Ethernet message impacts                    ║"
echo "║   • Causal scoring & anomaly detection                        ║"
echo "║   • CPU load tracking                                         ║"
echo "║   • Professional HTML forensic report                         ║"
echo "║                                                                ║"
echo "║   Press Ctrl+C to stop the server                             ║"
echo "║                                                                ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""

# Kill any existing processes on port 8080
lsof -i :8080 2>/dev/null | grep -v COMMAND | awk '{print $2}' | xargs kill -9 2>/dev/null

# Wait a moment for the port to be released
sleep 1

# Get the script's directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Start the server
"$SCRIPT_DIR/target/release/web"
