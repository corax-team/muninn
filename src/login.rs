use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;

use crate::search::SearchEngine;

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct LoginAnalysis {
    pub total_success: usize,
    pub total_failure: usize,
    pub by_user: Vec<UserLoginStats>,
    pub by_source_ip: Vec<SourceIpStats>,
    pub brute_force_candidates: Vec<BruteForceCandidate>,
    pub unusual_hours: Vec<UnusualLogin>,
    pub lateral_movement: Vec<LateralMovement>,
    pub privilege_escalation: Vec<PrivilegeEscalation>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UserLoginStats {
    pub username: String,
    pub success_count: usize,
    pub failure_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceIpStats {
    pub ip_address: String,
    pub success_count: usize,
    pub failure_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct BruteForceCandidate {
    pub username: String,
    pub source_ip: String,
    pub failure_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnusualLogin {
    pub username: String,
    pub timestamp: String,
    pub logon_type: String,
    pub source_ip: String,
    pub hour: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct LateralMovement {
    pub username: String,
    pub source_ip: String,
    pub logon_type: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PrivilegeEscalation {
    pub username: String,
    pub token_count: usize,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns true if the username looks like a machine account (ends with `$`)
/// or is a well-known noise account that should be filtered.
fn is_machine_account(name: &str) -> bool {
    name.ends_with('$') || name == "-" || name.is_empty()
}

/// Safely parse a decimal string into usize, defaulting to 0.
fn parse_count(s: &str) -> usize {
    s.parse::<usize>().unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Core analysis
// ---------------------------------------------------------------------------

pub fn analyze_logins(engine: &SearchEngine) -> Result<LoginAnalysis> {
    let has_field = |name: &str| engine.fields().iter().any(|f| f == name);

    // We need at least EventID to do anything useful.
    let has_event_id = has_field("EventID");

    // ------------------------------------------------------------------
    // (a) Success / Failure counts per user
    // ------------------------------------------------------------------
    let mut user_map: HashMap<String, (usize, usize)> = HashMap::new();
    let mut total_success: usize = 0;
    let mut total_failure: usize = 0;

    if has_event_id && has_field("TargetUserName") {
        let result = engine.query_sql(
            "SELECT \"TargetUserName\", \"EventID\", CAST(COUNT(*) AS TEXT) as cnt \
             FROM \"events\" \
             WHERE \"EventID\" IN ('4624','4625') \
             AND \"TargetUserName\" IS NOT NULL AND \"TargetUserName\" != '' \
             GROUP BY \"TargetUserName\", \"EventID\"",
        )?;

        for row in &result.rows {
            let user = match row.get("TargetUserName") {
                Some(u) => u.clone(),
                None => continue,
            };
            if is_machine_account(&user) {
                continue;
            }
            let eid = row.get("EventID").map(|s| s.as_str()).unwrap_or("");
            let cnt = row.get("cnt").map(|s| parse_count(s)).unwrap_or(0);

            let entry = user_map.entry(user).or_insert((0, 0));
            match eid {
                "4624" => {
                    entry.0 += cnt;
                    total_success += cnt;
                }
                "4625" => {
                    entry.1 += cnt;
                    total_failure += cnt;
                }
                _ => {}
            }
        }
    }

    let mut by_user: Vec<UserLoginStats> = user_map
        .into_iter()
        .map(|(username, (s, f))| UserLoginStats {
            username,
            success_count: s,
            failure_count: f,
        })
        .collect();
    // Sort by total activity descending
    by_user.sort_by(|a, b| {
        (b.success_count + b.failure_count).cmp(&(a.success_count + a.failure_count))
    });

    // ------------------------------------------------------------------
    // (b) Source IP analysis
    // ------------------------------------------------------------------
    let mut ip_map: HashMap<String, (usize, usize)> = HashMap::new();

    if has_event_id && has_field("IpAddress") {
        let result = engine.query_sql(
            "SELECT \"IpAddress\", \"EventID\", CAST(COUNT(*) AS TEXT) as cnt \
             FROM \"events\" \
             WHERE \"EventID\" IN ('4624','4625') \
             AND \"IpAddress\" IS NOT NULL AND \"IpAddress\" != '' AND \"IpAddress\" != '-' \
             GROUP BY \"IpAddress\", \"EventID\"",
        )?;

        for row in &result.rows {
            let ip = match row.get("IpAddress") {
                Some(v) => v.clone(),
                None => continue,
            };
            let eid = row.get("EventID").map(|s| s.as_str()).unwrap_or("");
            let cnt = row.get("cnt").map(|s| parse_count(s)).unwrap_or(0);

            let entry = ip_map.entry(ip).or_insert((0, 0));
            match eid {
                "4624" => entry.0 += cnt,
                "4625" => entry.1 += cnt,
                _ => {}
            }
        }
    }

    let mut by_source_ip: Vec<SourceIpStats> = ip_map
        .into_iter()
        .map(|(ip_address, (s, f))| SourceIpStats {
            ip_address,
            success_count: s,
            failure_count: f,
        })
        .collect();
    by_source_ip.sort_by(|a, b| {
        (b.success_count + b.failure_count).cmp(&(a.success_count + a.failure_count))
    });

    // ------------------------------------------------------------------
    // (c) Brute force detection (>=5 failures from same source)
    // ------------------------------------------------------------------
    let mut brute_force_candidates: Vec<BruteForceCandidate> = Vec::new();

    if has_event_id {
        // Try with IpAddress first; fall back to query without if field missing
        let query = if has_field("IpAddress") && has_field("TargetUserName") {
            "SELECT \"TargetUserName\", \"IpAddress\", CAST(COUNT(*) AS TEXT) as cnt \
             FROM \"events\" \
             WHERE \"EventID\" = '4625' \
             AND \"TargetUserName\" IS NOT NULL AND \"TargetUserName\" != '' \
             GROUP BY \"TargetUserName\", \"IpAddress\" \
             HAVING COUNT(*) >= 5 \
             ORDER BY cnt DESC"
        } else if has_field("TargetUserName") {
            "SELECT \"TargetUserName\", '' as \"IpAddress\", CAST(COUNT(*) AS TEXT) as cnt \
             FROM \"events\" \
             WHERE \"EventID\" = '4625' \
             AND \"TargetUserName\" IS NOT NULL AND \"TargetUserName\" != '' \
             GROUP BY \"TargetUserName\" \
             HAVING COUNT(*) >= 5 \
             ORDER BY cnt DESC"
        } else {
            ""
        };

        if !query.is_empty() {
            let result = engine.query_sql(query)?;
            for row in &result.rows {
                let user = row.get("TargetUserName").cloned().unwrap_or_default();
                if is_machine_account(&user) {
                    continue;
                }
                let ip = row.get("IpAddress").cloned().unwrap_or_default();
                let cnt = row.get("cnt").map(|s| parse_count(s)).unwrap_or(0);
                brute_force_candidates.push(BruteForceCandidate {
                    username: user,
                    source_ip: if ip.is_empty() { "N/A".into() } else { ip },
                    failure_count: cnt,
                });
            }
        }
    }

    // ------------------------------------------------------------------
    // (d) Unusual hours logins (outside 06:00-20:00)
    // ------------------------------------------------------------------
    let mut unusual_hours: Vec<UnusualLogin> = Vec::new();

    if has_event_id && has_field("SystemTime") {
        let result = engine.query_sql(
            "SELECT \"TargetUserName\", \"SystemTime\", \"LogonType\", \"IpAddress\", \
             CAST(CAST(SUBSTR(\"SystemTime\", 12, 2) AS INTEGER) AS TEXT) as hour \
             FROM \"events\" \
             WHERE \"EventID\" = '4624' \
             AND \"SystemTime\" IS NOT NULL AND \"SystemTime\" != '' \
             AND (CAST(SUBSTR(\"SystemTime\", 12, 2) AS INTEGER) < 6 \
                  OR CAST(SUBSTR(\"SystemTime\", 12, 2) AS INTEGER) >= 20)",
        )?;

        for row in &result.rows {
            let user = row.get("TargetUserName").cloned().unwrap_or_default();
            if is_machine_account(&user) {
                continue;
            }
            let timestamp = row.get("SystemTime").cloned().unwrap_or_default();
            let logon_type = row.get("LogonType").cloned().unwrap_or_default();
            let source_ip = row.get("IpAddress").cloned().unwrap_or_default();
            let hour = row
                .get("hour")
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0);

            unusual_hours.push(UnusualLogin {
                username: user,
                timestamp,
                logon_type,
                source_ip: if source_ip.is_empty() || source_ip == "-" {
                    "N/A".into()
                } else {
                    source_ip
                },
                hour,
            });
        }
    }

    // ------------------------------------------------------------------
    // (e) Lateral movement indicators
    // ------------------------------------------------------------------
    let mut lateral_movement: Vec<LateralMovement> = Vec::new();

    if has_event_id && has_field("LogonType") {
        let result = engine.query_sql(
            "SELECT DISTINCT \"TargetUserName\", \"IpAddress\", \"LogonType\" \
             FROM \"events\" \
             WHERE \"EventID\" = '4624' \
             AND \"LogonType\" IN ('3','10') \
             AND \"IpAddress\" IS NOT NULL \
             AND \"IpAddress\" NOT IN ('-','127.0.0.1','::1','')",
        )?;

        for row in &result.rows {
            let user = row.get("TargetUserName").cloned().unwrap_or_default();
            if is_machine_account(&user) {
                continue;
            }
            let ip = row.get("IpAddress").cloned().unwrap_or_default();
            let logon_type = row.get("LogonType").cloned().unwrap_or_default();

            lateral_movement.push(LateralMovement {
                username: user,
                source_ip: ip,
                logon_type,
            });
        }
    }

    // ------------------------------------------------------------------
    // (f) Privilege escalation — EventID 4672
    // ------------------------------------------------------------------
    let mut privilege_escalation: Vec<PrivilegeEscalation> = Vec::new();

    if has_event_id && has_field("SubjectUserName") {
        let result = engine.query_sql(
            "SELECT \"SubjectUserName\", CAST(COUNT(*) AS TEXT) as cnt \
             FROM \"events\" \
             WHERE \"EventID\" = '4672' \
             AND \"SubjectUserName\" IS NOT NULL AND \"SubjectUserName\" != '' \
             GROUP BY \"SubjectUserName\" \
             ORDER BY cnt DESC",
        )?;

        for row in &result.rows {
            let user = row.get("SubjectUserName").cloned().unwrap_or_default();
            if is_machine_account(&user) {
                continue;
            }
            let cnt = row.get("cnt").map(|s| parse_count(s)).unwrap_or(0);
            privilege_escalation.push(PrivilegeEscalation {
                username: user,
                token_count: cnt,
            });
        }
    }

    Ok(LoginAnalysis {
        total_success,
        total_failure,
        by_user,
        by_source_ip,
        brute_force_candidates,
        unusual_hours,
        lateral_movement,
        privilege_escalation,
    })
}

// ---------------------------------------------------------------------------
// Render
// ---------------------------------------------------------------------------

pub fn render_login_analysis(analysis: &LoginAnalysis) -> String {
    let mut out = String::new();
    let sep = "=".repeat(72);

    // ---- Login Summary ----
    out.push_str("\n  Login Analysis Report\n");
    out.push_str(&format!("  {}\n", sep));

    let total = analysis.total_success + analysis.total_failure;
    let fail_ratio = if total > 0 {
        analysis.total_failure as f64 / total as f64 * 100.0
    } else {
        0.0
    };

    out.push_str(&format!("  Total logon events:  {}\n", total));
    out.push_str(&format!(
        "  Successful (4624):   {}\n",
        analysis.total_success
    ));
    out.push_str(&format!(
        "  Failed     (4625):   {}\n",
        analysis.total_failure
    ));
    out.push_str(&format!("  Failure ratio:       {:.1}%\n", fail_ratio));
    out.push_str(&format!("  {}\n\n", sep));

    // ---- Top Users ----
    if !analysis.by_user.is_empty() {
        out.push_str("  Top Users by Login Activity\n");
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        out.push_str(&format!(
            "  {:<30} {:>10} {:>10} {:>10}\n",
            "Username", "Success", "Failure", "Total"
        ));
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        for u in analysis.by_user.iter().take(20) {
            let total = u.success_count + u.failure_count;
            out.push_str(&format!(
                "  {:<30} {:>10} {:>10} {:>10}\n",
                truncate(&u.username, 30),
                u.success_count,
                u.failure_count,
                total
            ));
        }
        out.push('\n');
    }

    // ---- Top Source IPs ----
    if !analysis.by_source_ip.is_empty() {
        out.push_str("  Top Source IPs\n");
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        out.push_str(&format!(
            "  {:<40} {:>10} {:>10}\n",
            "IP Address", "Success", "Failure"
        ));
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        for ip in analysis.by_source_ip.iter().take(20) {
            out.push_str(&format!(
                "  {:<40} {:>10} {:>10}\n",
                truncate(&ip.ip_address, 40),
                ip.success_count,
                ip.failure_count
            ));
        }
        out.push('\n');
    }

    // ---- Brute Force Candidates ----
    if !analysis.brute_force_candidates.is_empty() {
        out.push_str("  [!] Brute Force Candidates\n");
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        out.push_str(&format!(
            "  {:<25} {:<30} {:>10}\n",
            "Username", "Source IP", "Failures"
        ));
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        for bf in &analysis.brute_force_candidates {
            out.push_str(&format!(
                "  {:<25} {:<30} {:>10}\n",
                truncate(&bf.username, 25),
                truncate(&bf.source_ip, 30),
                bf.failure_count
            ));
        }
        out.push('\n');
    }

    // ---- Unusual Hours ----
    if !analysis.unusual_hours.is_empty() {
        out.push_str(&format!(
            "  [!] Unusual Hours Logins ({} events outside 06:00-20:00)\n",
            analysis.unusual_hours.len()
        ));
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        out.push_str(&format!(
            "  {:<20} {:<26} {:>5} {:<15}\n",
            "Username", "Timestamp", "Hour", "Source IP"
        ));
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        for ul in analysis.unusual_hours.iter().take(50) {
            out.push_str(&format!(
                "  {:<20} {:<26} {:>5} {:<15}\n",
                truncate(&ul.username, 20),
                truncate(&ul.timestamp, 26),
                ul.hour,
                truncate(&ul.source_ip, 15)
            ));
        }
        if analysis.unusual_hours.len() > 50 {
            out.push_str(&format!(
                "  ... and {} more\n",
                analysis.unusual_hours.len() - 50
            ));
        }
        out.push('\n');
    }

    // ---- Lateral Movement ----
    if !analysis.lateral_movement.is_empty() {
        out.push_str(&format!(
            "  [!] Lateral Movement Indicators ({} unique sessions)\n",
            analysis.lateral_movement.len()
        ));
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        out.push_str(&format!(
            "  {:<25} {:<30} {:>12}\n",
            "Username", "Source IP", "Logon Type"
        ));
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        for lm in analysis.lateral_movement.iter().take(50) {
            let lt_label = match lm.logon_type.as_str() {
                "3" => "3 (Network)",
                "10" => "10 (RDP)",
                other => other,
            };
            out.push_str(&format!(
                "  {:<25} {:<30} {:>12}\n",
                truncate(&lm.username, 25),
                truncate(&lm.source_ip, 30),
                lt_label
            ));
        }
        if analysis.lateral_movement.len() > 50 {
            out.push_str(&format!(
                "  ... and {} more\n",
                analysis.lateral_movement.len() - 50
            ));
        }
        out.push('\n');
    }

    // ---- Privilege Escalation ----
    if !analysis.privilege_escalation.is_empty() {
        out.push_str("  Privilege Escalation (Event 4672 — Special Privileges Assigned)\n");
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        out.push_str(&format!("  {:<40} {:>10}\n", "Username", "Token Count"));
        out.push_str(&format!("  {}\n", "-".repeat(72)));
        for pe in analysis.privilege_escalation.iter().take(20) {
            out.push_str(&format!(
                "  {:<40} {:>10}\n",
                truncate(&pe.username, 40),
                pe.token_count
            ));
        }
        out.push('\n');
    }

    // ---- Empty state ----
    if analysis.total_success == 0
        && analysis.total_failure == 0
        && analysis.brute_force_candidates.is_empty()
        && analysis.unusual_hours.is_empty()
        && analysis.lateral_movement.is_empty()
        && analysis.privilege_escalation.is_empty()
    {
        out.push_str("  No login/authentication events found in the dataset.\n");
    }

    out.push_str(&format!("  {}\n", sep));
    out
}

/// Truncate a string to `max` characters, appending ".." if needed.
fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}..", &s[..max.saturating_sub(2)])
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Event, SourceFormat};

    fn make_event(fields: &[(&str, &str)]) -> Event {
        let mut event = Event::new("test.evtx", SourceFormat::Evtx);
        for (k, v) in fields {
            event.set(*k, *v);
        }
        event.raw = serde_json::to_string(
            &fields
                .iter()
                .map(|(k, v)| (*k, *v))
                .collect::<HashMap<_, _>>(),
        )
        .unwrap();
        event.fields.insert("_raw".into(), event.raw.clone());
        event
    }

    #[test]
    fn test_login_analysis_basic() {
        let mut engine = SearchEngine::new().unwrap();
        let mut events = Vec::new();

        // 3 successful logins for "alice"
        for _ in 0..3 {
            events.push(make_event(&[
                ("EventID", "4624"),
                ("TargetUserName", "alice"),
                ("IpAddress", "10.0.0.5"),
                ("LogonType", "3"),
                ("SystemTime", "2025-06-15T14:30:00.000Z"),
            ]));
        }

        // 6 failed logins for "alice" from attacker IP (brute force)
        for _ in 0..6 {
            events.push(make_event(&[
                ("EventID", "4625"),
                ("TargetUserName", "alice"),
                ("IpAddress", "192.168.1.100"),
                ("SystemTime", "2025-06-15T03:15:00.000Z"),
            ]));
        }

        // 2 successful logins for "bob" at unusual hours
        for _ in 0..2 {
            events.push(make_event(&[
                ("EventID", "4624"),
                ("TargetUserName", "bob"),
                ("IpAddress", "10.0.0.8"),
                ("LogonType", "10"),
                ("SystemTime", "2025-06-15T02:00:00.000Z"),
            ]));
        }

        // 1 machine account login (should be filtered out)
        events.push(make_event(&[
            ("EventID", "4624"),
            ("TargetUserName", "WORKSTATION01$"),
            ("IpAddress", "10.0.0.1"),
            ("LogonType", "3"),
            ("SystemTime", "2025-06-15T10:00:00.000Z"),
        ]));

        // 4 privilege escalation events
        for _ in 0..4 {
            events.push(make_event(&[
                ("EventID", "4672"),
                ("SubjectUserName", "alice"),
            ]));
        }

        engine.load_events(&events).unwrap();
        let analysis = analyze_logins(&engine).unwrap();

        // Verify totals (machine account excluded)
        assert_eq!(analysis.total_success, 5); // 3 alice + 2 bob
        assert_eq!(analysis.total_failure, 6); // 6 alice

        // Verify user stats
        assert!(!analysis.by_user.is_empty());
        let alice_stats = analysis
            .by_user
            .iter()
            .find(|u| u.username == "alice")
            .expect("alice should be in user stats");
        assert_eq!(alice_stats.success_count, 3);
        assert_eq!(alice_stats.failure_count, 6);

        let bob_stats = analysis
            .by_user
            .iter()
            .find(|u| u.username == "bob")
            .expect("bob should be in user stats");
        assert_eq!(bob_stats.success_count, 2);
        assert_eq!(bob_stats.failure_count, 0);

        // Machine account must be excluded
        assert!(analysis.by_user.iter().all(|u| !u.username.ends_with('$')));

        // Brute force: alice from 192.168.1.100 with 6 failures
        assert_eq!(analysis.brute_force_candidates.len(), 1);
        assert_eq!(analysis.brute_force_candidates[0].username, "alice");
        assert_eq!(
            analysis.brute_force_candidates[0].source_ip,
            "192.168.1.100"
        );
        assert_eq!(analysis.brute_force_candidates[0].failure_count, 6);

        // Unusual hours: bob at 02:00
        assert!(!analysis.unusual_hours.is_empty());
        assert!(analysis
            .unusual_hours
            .iter()
            .any(|u| u.username == "bob" && u.hour == 2));

        // Lateral movement: bob via RDP from non-localhost, alice via Network
        assert!(!analysis.lateral_movement.is_empty());
        assert!(analysis
            .lateral_movement
            .iter()
            .any(|lm| lm.username == "bob" && lm.logon_type == "10"));
        assert!(analysis
            .lateral_movement
            .iter()
            .any(|lm| lm.username == "alice" && lm.logon_type == "3"));

        // Privilege escalation
        assert_eq!(analysis.privilege_escalation.len(), 1);
        assert_eq!(analysis.privilege_escalation[0].username, "alice");
        assert_eq!(analysis.privilege_escalation[0].token_count, 4);

        // Source IPs
        assert!(!analysis.by_source_ip.is_empty());
    }

    #[test]
    fn test_render_produces_output() {
        let analysis = LoginAnalysis {
            total_success: 10,
            total_failure: 3,
            by_user: vec![UserLoginStats {
                username: "admin".into(),
                success_count: 10,
                failure_count: 3,
            }],
            by_source_ip: vec![SourceIpStats {
                ip_address: "10.0.0.1".into(),
                success_count: 10,
                failure_count: 3,
            }],
            brute_force_candidates: vec![BruteForceCandidate {
                username: "admin".into(),
                source_ip: "10.0.0.99".into(),
                failure_count: 15,
            }],
            unusual_hours: vec![UnusualLogin {
                username: "admin".into(),
                timestamp: "2025-06-15T03:00:00Z".into(),
                logon_type: "10".into(),
                source_ip: "10.0.0.1".into(),
                hour: 3,
            }],
            lateral_movement: vec![LateralMovement {
                username: "admin".into(),
                source_ip: "10.0.0.50".into(),
                logon_type: "3".into(),
            }],
            privilege_escalation: vec![PrivilegeEscalation {
                username: "admin".into(),
                token_count: 42,
            }],
        };

        let rendered = render_login_analysis(&analysis);
        assert!(rendered.contains("Login Analysis Report"));
        assert!(rendered.contains("Successful (4624):   10"));
        assert!(rendered.contains("Failed     (4625):   3"));
        assert!(rendered.contains("Brute Force Candidates"));
        assert!(rendered.contains("Unusual Hours Logins"));
        assert!(rendered.contains("Lateral Movement Indicators"));
        assert!(rendered.contains("Privilege Escalation"));
        assert!(rendered.contains("admin"));
    }

    #[test]
    fn test_empty_dataset() {
        let engine = SearchEngine::new().unwrap();
        let analysis = analyze_logins(&engine).unwrap();

        assert_eq!(analysis.total_success, 0);
        assert_eq!(analysis.total_failure, 0);
        assert!(analysis.by_user.is_empty());
        assert!(analysis.brute_force_candidates.is_empty());
        assert!(analysis.unusual_hours.is_empty());
        assert!(analysis.lateral_movement.is_empty());
        assert!(analysis.privilege_escalation.is_empty());

        let rendered = render_login_analysis(&analysis);
        assert!(rendered.contains("No login/authentication events found"));
    }

    #[test]
    fn test_machine_accounts_filtered() {
        let mut engine = SearchEngine::new().unwrap();
        let events = vec![
            make_event(&[
                ("EventID", "4624"),
                ("TargetUserName", "MACHINE01$"),
                ("IpAddress", "10.0.0.1"),
                ("LogonType", "3"),
                ("SystemTime", "2025-06-15T10:00:00Z"),
            ]),
            make_event(&[("EventID", "4672"), ("SubjectUserName", "SYSTEM$")]),
        ];
        engine.load_events(&events).unwrap();
        let analysis = analyze_logins(&engine).unwrap();

        // Machine accounts should be excluded from all user-facing stats
        assert_eq!(analysis.total_success, 0);
        assert!(analysis.by_user.is_empty());
        assert!(analysis.lateral_movement.is_empty());
        assert!(analysis.privilege_escalation.is_empty());
    }

    #[test]
    fn test_truncate_helper() {
        assert_eq!(truncate("short", 10), "short");
        assert_eq!(truncate("a very long string", 10), "a very l..");
        assert_eq!(truncate("exact_ten!", 10), "exact_ten!");
        assert_eq!(truncate("", 5), "");
    }
}
