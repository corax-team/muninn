#!/bin/bash
# Muninn Quick Start Guide
# This script demonstrates basic Muninn usage with the included example files.
#
# Prerequisites: build Muninn first
#   cargo build --release --features cli
#
# The binary will be at: target/release/muninn

set -e

MUNINN="cargo run --features cli --"
EXAMPLES_DIR="$(cd "$(dirname "$0")" && pwd)"
LOGS_DIR="$EXAMPLES_DIR/logs"
RULES_DIR="$EXAMPLES_DIR/rules"

echo "=== Muninn Quick Start ==="
echo ""

# 1. Parse and show stats for Sysmon JSON events
echo "--- 1. Parse Sysmon JSON events and show stats ---"
$MUNINN "$LOGS_DIR/sysmon_events.json" --stats
echo ""

# 2. Keyword search
echo "--- 2. Keyword search for 'whoami' ---"
$MUNINN "$LOGS_DIR/sysmon_events.json" -k whoami
echo ""

# 3. Run SIGMA rules against Sysmon events
echo "--- 3. Run SIGMA rules against Sysmon events ---"
$MUNINN "$LOGS_DIR/sysmon_events.json" -r "$RULES_DIR"
echo ""

# 4. Parse Windows Security events and search
echo "--- 4. Parse Windows Security JSON events ---"
$MUNINN "$LOGS_DIR/windows_security.json" --stats
echo ""

# 5. Run SIGMA rules against Windows Security events
echo "--- 5. Run SIGMA rules against Windows Security events ---"
$MUNINN "$LOGS_DIR/windows_security.json" -r "$RULES_DIR"
echo ""

# 6. Parse CSV firewall logs
echo "--- 6. Parse CSV firewall logs ---"
$MUNINN "$LOGS_DIR/firewall.csv" --stats
echo ""

# 7. Parse syslog auth.log
echo "--- 7. Parse syslog auth.log and search for brute force ---"
$MUNINN "$LOGS_DIR/auth.log" -k "Failed password"
echo ""

# 8. Run SIGMA against auth.log
echo "--- 8. Run SIGMA against auth.log ---"
$MUNINN "$LOGS_DIR/auth.log" -r "$RULES_DIR"
echo ""

# 9. Parse CEF web access logs
echo "--- 9. Parse CEF logs ---"
$MUNINN "$LOGS_DIR/web_access.log" --stats
echo ""

# 10. Parse XML Windows events
echo "--- 10. Parse XML events ---"
$MUNINN "$LOGS_DIR/windows_events.xml" --stats
echo ""

# 11. Export to SQLite database for further analysis
echo "--- 11. Export Sysmon events to SQLite DB ---"
$MUNINN "$LOGS_DIR/sysmon_events.json" --dbfile /tmp/muninn_example.db
echo "Database saved to /tmp/muninn_example.db"
echo "You can query it with: sqlite3 /tmp/muninn_example.db 'SELECT * FROM events'"
echo ""

# 12. JSON output
echo "--- 12. JSON output ---"
$MUNINN "$LOGS_DIR/sysmon_events.json" -r "$RULES_DIR" -o json
echo ""

echo "=== Done! ==="
