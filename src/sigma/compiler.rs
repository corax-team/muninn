use anyhow::Result;
use regex::Regex;
use std::collections::HashMap;

use super::parser::{Detection, Rule};

const TABLE: &str = "events";

pub fn compile(rule: &Rule) -> Result<String> {
    if let Some(tf) = rule.detection.selections.get("timeframe") {
        log::warn!(
            "Rule '{}': timeframe ({:?}) is not supported in stateless SQL mode — ignoring",
            rule.title,
            tf
        );
    }

    let where_clause = compile_detection(&rule.detection)?;
    let logsource_clause = compile_logsource(&rule.logsource);

    if let Some(ls) = logsource_clause {
        Ok(format!(
            "SELECT * FROM \"{}\" WHERE ({}) AND ({})",
            TABLE, ls, where_clause
        ))
    } else {
        Ok(format!(
            "SELECT * FROM \"{}\" WHERE {}",
            TABLE, where_clause
        ))
    }
}

/// Map SIGMA logsource to SQL constraints on Channel/Provider/format fields.
/// Returns None if no constraint can be derived (rule runs against all events).
fn compile_logsource(ls: &super::parser::LogSource) -> Option<String> {
    let product = ls.product.as_deref().unwrap_or("").to_lowercase();
    let _service = ls.service.as_deref().unwrap_or("").to_lowercase();
    let category = ls.category.as_deref().unwrap_or("").to_lowercase();

    // Non-Windows products: filter by source format
    match product.as_str() {
        "zeek" => {
            return Some(
                "\"_source_format\" = 'ZeekTsv' OR \"_source_format\" = 'Zeek'".into(),
            )
        }
        "linux" | "macos" => {
            return Some(
                "\"_source_format\" = 'Syslog' OR \"_source_format\" = 'SyslogRfc5424'".into(),
            )
        }
        "cisco" | "juniper" | "fortinet" | "paloalto" => {
            return Some(
                "\"_source_format\" = 'CEF' OR \"_source_format\" = 'LEEF' OR \"_source_format\" = 'Syslog'".into(),
            )
        }
        "aws" | "azure" | "gcp" | "google_workspace" | "m365" | "okta" | "github"
        | "onelogin" | "qualys" => return Some("\"_source_format\" = 'JSON'".into()),
        "apache" => {
            return Some(
                "\"_source_format\" = 'W3C' OR \"_source_format\" = 'ApacheCombined'".into(),
            )
        }
        _ => {}
    }

    // Windows service: do NOT add a Channel constraint to SQL.
    // Channel filtering here is too strict — it excludes forwarded events
    // (e.g., Sysmon events in Kaspersky.evtx retain their original Channel).
    // Instead we rely on confidence scoring (compute_confidence) to flag
    // detections where the matched event's Channel doesn't match the expected
    // service Channel. This matches Zircolite's behavior of finding all matches
    // and leaving false-positive filtering to the analyst.

    // Windows category → EventID constraints (matches Sysmon + Security audit event IDs)
    // Only applied when product=windows or product is unset (assume windows for evtx-only datasets)
    if product.is_empty() || product == "windows" {
        if let Some(filter) = category_to_eventid_filter(&category) {
            return Some(filter);
        }
    }

    // Catch-all category-based channel constraints (non-Windows specific)
    if category.as_str() == "antivirus" {
        return Some(
            "(\"Channel\" LIKE '%Defender%' OR \"Channel\" LIKE '%Virus%' OR \"Channel\" LIKE '%Endpoint%' OR \"Channel\" LIKE '%Antivirus%')".into(),
        );
    }

    None
}

/// Map SIGMA logsource category (Windows) to SQL EventID constraints.
/// Returns filters matching all standard sources for each category.
fn category_to_eventid_filter(category: &str) -> Option<String> {
    match category {
        // Process execution: Sysmon EID 1, Security EID 4688.
        // Restrict Sysmon EID 1 by Provider_Name to avoid false positives from other
        // logs that also use EID 1 (e.g. Exchange ManagedAvailability monitoring).
        "process_creation" => Some(
            "((\"EventID\" = '1' AND \"Provider_Name\" LIKE '%Sysmon%') OR \"EventID\" = '4688')"
                .into(),
        ),
        // File events: Sysmon EID 11 (create), 23 (delete), 26 (shred)
        "file_event"
        | "file_creation"
        | "file_change"
        | "file_delete"
        | "file_delete_detected"
        | "file_rename" => Some("\"EventID\" IN ('11', '23', '26')".into()),
        // Network connections: Sysmon EID 3, WFP EID 5156
        "network_connection" | "network_connection_detection" => {
            Some("\"EventID\" IN ('3', '5156')".into())
        }
        // Image load (DLL): Sysmon EID 7
        "image_load" => Some("\"EventID\" = '7'".into()),
        // Registry: Sysmon EID 12 (create/delete), 13 (set), 14 (rename)
        "registry_add"
        | "registry_delete"
        | "registry_event"
        | "registry_rename"
        | "registry_set"
        | "registry_key_rename"
        | "registry_value_set" => Some("\"EventID\" IN ('12', '13', '14')".into()),
        // Process injection / remote thread: Sysmon EID 8
        "create_remote_thread" => Some("\"EventID\" = '8'".into()),
        // Raw disk read: Sysmon EID 9
        "raw_access_read" => Some("\"EventID\" = '9'".into()),
        // Process access (OpenProcess): Sysmon EID 10
        "process_access" => Some("\"EventID\" = '10'".into()),
        // Named pipes: Sysmon EID 17 (create), 18 (connect)
        "pipe_creation" | "pipe_connected" => Some("\"EventID\" IN ('17', '18')".into()),
        // DNS query: Sysmon EID 22
        "dns_query" | "dns" => Some("\"EventID\" = '22'".into()),
        // Process tampering: Sysmon EID 25
        "process_tampering" => Some("\"EventID\" = '25'".into()),
        // Driver load: Sysmon EID 6
        "driver_load" => Some("\"EventID\" = '6'".into()),
        // PowerShell module / ScriptBlock logging
        "ps_module" => Some("\"EventID\" = '4103'".into()),
        "ps_script" => Some("\"EventID\" IN ('4103', '4104')".into()),
        "ps_classic_start" | "ps_classic_provider_start" => {
            Some("\"EventID\" IN ('400', '600')".into())
        }
        // Windows account / logon events
        "account_login" | "user_accounts" => {
            Some("\"EventID\" IN ('4624', '4625', '4648', '4768', '4769', '4771', '4776')".into())
        }
        _ => None,
    }
}

/// Map SIGMA logsource service name to Windows Event Log Channel.
fn service_to_channel(service: &str) -> Option<&'static str> {
    match service {
        "sysmon" => Some("Microsoft-Windows-Sysmon/Operational"),
        "security" => Some("Security"),
        "system" => Some("System"),
        "application" => Some("Application"),
        "windefend" => Some("Microsoft-Windows-Windows Defender/Operational"),
        "powershell" => Some("Microsoft-Windows-PowerShell/Operational"),
        "powershell-classic" => Some("Windows PowerShell"),
        "codeintegrity-operational" => Some("Microsoft-Windows-CodeIntegrity/Operational"),
        "taskscheduler" => Some("Microsoft-Windows-TaskScheduler/Operational"),
        "wmi" => Some("Microsoft-Windows-WMI-Activity/Operational"),
        "dns-server" => Some("DNS Server"),
        "bits-client" => Some("Microsoft-Windows-Bits-Client/Operational"),
        "firewall-as" => Some("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"),
        "ntlm" => Some("Microsoft-Windows-NTLM/Operational"),
        "openssh" => Some("OpenSSH/Operational"),
        "ldap_debug" => Some("Microsoft-Windows-LDAP-Client/Debug"),
        "msexchange-management" => Some("MSExchange Management"),
        "terminalservices-localsessionmanager" => {
            Some("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")
        }
        _ => None,
    }
}

/// Public accessor for confidence scoring — returns expected Channel for a service.
pub fn expected_channel_for_service(service: &str) -> Option<&'static str> {
    service_to_channel(&service.to_lowercase())
}

fn compile_detection(det: &Detection) -> Result<String> {
    let conditions = det.condition.as_vec();
    let condition_str = conditions.first().copied().unwrap_or("selection");

    let mut fragments: HashMap<String, String> = HashMap::new();
    for (name, value) in &det.selections {
        if name == "condition" || name == "timeframe" {
            continue;
        }
        fragments.insert(name.clone(), selection_to_sql(value)?);
    }

    parse_condition(condition_str, &fragments)
}

fn selection_to_sql(value: &serde_yaml::Value) -> Result<String> {
    match value {
        serde_yaml::Value::Mapping(map) => {
            let mut parts = Vec::new();
            for (key, val) in map {
                let field_raw = key.as_str().unwrap_or("").to_string();
                let (field, mods) = parse_field_modifiers(&field_raw);
                parts.push(value_to_sql(&field, val, &mods)?);
            }
            if parts.is_empty() {
                Ok("1=1".into())
            } else {
                Ok(format!("({})", parts.join(" AND ")))
            }
        }
        serde_yaml::Value::Sequence(seq) => {
            let mut or_parts = Vec::new();
            for item in seq {
                or_parts.push(selection_to_sql(item)?);
            }
            Ok(format!("({})", or_parts.join(" OR ")))
        }
        serde_yaml::Value::String(s) => {
            let e = escape(s);
            Ok(format!("\"_raw\" LIKE '%{}%' ESCAPE '\\'", e))
        }
        _ => Ok("1=1".into()),
    }
}

fn parse_field_modifiers(field: &str) -> (String, Vec<String>) {
    let parts: Vec<&str> = field.split('|').collect();
    let name = parts[0].to_string();
    let mods = parts[1..].iter().map(|s| s.to_lowercase()).collect();
    (name, mods)
}

fn transform_value(s: &str, mods: &[String]) -> Vec<String> {
    let has = |m: &str| mods.contains(&m.to_string());
    let mut values = vec![s.to_string()];

    if has("windash") {
        let mut expanded = Vec::new();
        for v in &values {
            expanded.push(v.clone());
            if v.contains('-') {
                expanded.push(v.replace('-', "/"));
            }
        }
        values = expanded;
    }

    if has("base64") {
        use base64_engine::Engine;
        values = values
            .iter()
            .map(|v| base64_engine::general_purpose::STANDARD.encode(v.as_bytes()))
            .collect();
    }

    if has("base64offset") {
        use base64_engine::Engine;
        let mut all = Vec::new();
        for v in &values {
            let bytes = v.as_bytes();
            for offset in 0..3 {
                let mut padded = vec![0u8; offset];
                padded.extend_from_slice(bytes);
                let encoded = base64_engine::general_purpose::STANDARD.encode(&padded);
                let skip = (offset * 4).div_ceil(3);
                if skip < encoded.len() {
                    let trimmed = &encoded[skip..];
                    let trimmed = trimmed.trim_end_matches('=');
                    if !trimmed.is_empty() {
                        all.push(trimmed.to_string());
                    }
                }
            }
        }
        if !all.is_empty() {
            values = all;
        }
    }

    values
}

fn value_to_sql(field: &str, value: &serde_yaml::Value, mods: &[String]) -> Result<String> {
    let has = |m: &str| mods.contains(&m.to_string());
    let qf = format!("\"{}\"", field);

    match value {
        serde_yaml::Value::Null => Ok(format!("({q} IS NULL OR {q} = '')", q = qf)),
        serde_yaml::Value::Bool(b) => Ok(format!("{} = {}", qf, if *b { 1 } else { 0 })),
        serde_yaml::Value::Number(n) => {
            let ns = n.to_string();
            if has("gt") {
                Ok(format!("CAST({} AS REAL) > {}", qf, ns))
            } else if has("gte") {
                Ok(format!("CAST({} AS REAL) >= {}", qf, ns))
            } else if has("lt") {
                Ok(format!("CAST({} AS REAL) < {}", qf, ns))
            } else if has("lte") {
                Ok(format!("CAST({} AS REAL) <= {}", qf, ns))
            } else {
                // Use string equality — SQLite columns are TEXT type
                Ok(format!("{} = '{}'", qf, ns))
            }
        }
        serde_yaml::Value::String(s) => string_to_sql(&qf, s, mods),
        serde_yaml::Value::Sequence(seq) => {
            let mut parts = Vec::new();
            for item in seq {
                match item {
                    serde_yaml::Value::String(s) => {
                        parts.push(string_to_sql(&qf, s, mods)?);
                    }
                    serde_yaml::Value::Number(n) => {
                        // Use string equality — SQLite columns are TEXT type
                        parts.push(format!("{} = '{}'", qf, n));
                    }
                    serde_yaml::Value::Null => {
                        parts.push(format!("({q} IS NULL OR {q} = '')", q = qf));
                    }
                    _ => {
                        // Coerce unknown YAML variants (Tagged, Mapping, etc.) to string.
                        // Handles values like $DoIt that serde_yaml may not parse as String.
                        let raw = serde_yaml::to_string(item).unwrap_or_default();
                        let s = raw.trim().trim_start_matches("---").trim();
                        if !s.is_empty() {
                            parts.push(string_to_sql(&qf, s, mods)?);
                        }
                    }
                }
            }
            if parts.is_empty() {
                return Ok("1=0".into());
            }
            let joiner = if has("all") { " AND " } else { " OR " };
            Ok(format!("({})", parts.join(joiner)))
        }
        _ => {
            // Coerce unknown top-level YAML variants to string
            let raw = serde_yaml::to_string(value).unwrap_or_default();
            let s = raw.trim().trim_start_matches("---").trim().to_string();
            if s.is_empty() {
                Ok("1=0".into())
            } else {
                string_to_sql(&qf, &s, mods)
            }
        }
    }
}

fn string_to_sql(qf: &str, s: &str, mods: &[String]) -> Result<String> {
    let has = |m: &str| mods.contains(&m.to_string());

    // Guard: empty string without wildcards should not generate match-all LIKE '%%'
    if s.is_empty() && !s.contains('*') && !s.contains('?') {
        return Ok(format!("({q} IS NULL OR {q} = '')", q = qf));
    }

    if has("re") {
        return Ok(format!("{} REGEXP '{}'", qf, escape(s)));
    }

    if has("cidr") {
        return Ok(cidr_to_sql(qf, s));
    }

    let transformed = transform_value(s, mods);
    // Filter out empty transformed values to prevent LIKE '%%' match-all
    let transformed: Vec<String> = transformed.into_iter().filter(|v| !v.is_empty()).collect();
    if transformed.is_empty() {
        return Ok("1=0".into());
    }

    if transformed.len() == 1 {
        let like = to_like(
            &transformed[0],
            has("contains"),
            has("startswith"),
            has("endswith"),
        );
        if like.is_empty() {
            return Ok("1=0".into());
        }
        Ok(format!("{} LIKE '{}' ESCAPE '\\'", qf, like))
    } else {
        let parts: Vec<String> = transformed
            .iter()
            .filter_map(|v| {
                let like = to_like(v, has("contains"), has("startswith"), has("endswith"));
                if like.is_empty() {
                    None
                } else {
                    Some(format!("{} LIKE '{}' ESCAPE '\\'", qf, like))
                }
            })
            .collect();
        if parts.is_empty() {
            return Ok("1=0".into());
        }
        Ok(format!("({})", parts.join(" OR ")))
    }
}

fn cidr_to_sql(qf: &str, cidr: &str) -> String {
    let parts: Vec<&str> = cidr.split('/').collect();
    let ip = parts[0];
    let mask_bits: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(32);

    // IPv6: simple prefix match (best effort)
    if ip.contains(':') {
        let prefix = ip.trim_end_matches(':').trim_end_matches(':');
        return format!("{} LIKE '{}%' ESCAPE '\\'", qf, escape(prefix));
    }

    let octets: Vec<u32> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
    if octets.len() != 4 || mask_bits > 32 {
        return format!("{} LIKE '{}%' ESCAPE '\\'", qf, escape(ip));
    }

    // Exact match
    if mask_bits == 32 {
        return format!("{} = '{}'", qf, ip);
    }

    let full_octets = (mask_bits / 8) as usize;

    // Octet-aligned: simple LIKE prefix
    if mask_bits.is_multiple_of(8) {
        let prefix: Vec<String> = octets[..full_octets]
            .iter()
            .map(|o| o.to_string())
            .collect();
        return format!("{} LIKE '{}.%' ESCAPE '\\'", qf, prefix.join("."));
    }

    // Non-octet-aligned: generate LIKE patterns for the range
    // e.g., 172.16.0.0/12 → 172.16.% through 172.31.%
    let partial_octet = full_octets; // the octet that is partially masked
    let bits_in_partial = mask_bits % 8;
    let base = octets[partial_octet] & (0xFF << (8 - bits_in_partial));
    let range_size = 1u32 << (8 - bits_in_partial);

    let prefix: Vec<String> = octets[..full_octets]
        .iter()
        .map(|o| o.to_string())
        .collect();
    let prefix_str = if prefix.is_empty() {
        String::new()
    } else {
        format!("{}.", prefix.join("."))
    };

    let mut or_parts = Vec::new();
    for i in 0..range_size {
        let octet_val = base + i;
        if partial_octet == 3 {
            // Last octet: exact match
            or_parts.push(format!("{} = '{}{}'", qf, prefix_str, octet_val));
        } else {
            or_parts.push(format!(
                "{} LIKE '{}{}.%' ESCAPE '\\'",
                qf, prefix_str, octet_val
            ));
        }
    }

    if or_parts.len() == 1 {
        or_parts.into_iter().next().unwrap()
    } else {
        format!("({})", or_parts.join(" OR "))
    }
}

fn to_like(s: &str, contains: bool, startswith: bool, endswith: bool) -> String {
    let escaped = s
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
        .replace('\'', "''");
    let w = escaped.replace('*', "%").replace('?', "_");
    // Guard: if value is empty after escaping, don't generate match-all pattern
    if w.is_empty() {
        return String::new();
    }
    if contains {
        format!("%{}%", w)
    } else if startswith {
        format!("{}%", w)
    } else if endswith {
        format!("%{}", w)
    } else {
        w
    }
}

fn escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "''")
}

fn parse_condition(cond: &str, fragments: &HashMap<String, String>) -> Result<String> {
    let mut expr = cond.trim().to_string();

    let of_re = Regex::new(r"(\d+|all)\s+of\s+(\w+\*|them)").unwrap();
    let mut iterations = 0;
    while let Some(caps) = of_re.captures(&expr.clone()) {
        iterations += 1;
        if iterations > 100 {
            anyhow::bail!("SIGMA condition expansion exceeded 100 iterations");
        }
        let full = caps.get(0).unwrap().as_str();
        let quant = caps.get(1).unwrap().as_str();
        let target = caps.get(2).unwrap().as_str();

        let keys: Vec<&String> = if target == "them" {
            fragments.keys().collect()
        } else {
            let prefix = target.trim_end_matches('*');
            fragments.keys().filter(|k| k.starts_with(prefix)).collect()
        };

        let replacement = if keys.is_empty() {
            "1=0".into()
        } else {
            let parts: Vec<String> = keys.iter().map(|k| fragments[*k].clone()).collect();
            if quant == "all" {
                format!("({})", parts.join(" AND "))
            } else {
                let n: usize = quant.parse().unwrap_or(1);
                if n <= 1 {
                    format!("({})", parts.join(" OR "))
                } else {
                    // N of selection*: at least N selections must match
                    let case_parts: Vec<String> = parts
                        .iter()
                        .map(|p| format!("CASE WHEN ({}) THEN 1 ELSE 0 END", p))
                        .collect();
                    format!("({} >= {})", case_parts.join(" + "), n)
                }
            }
        };
        expr = expr.replace(full, &replacement);
    }

    let mut keys: Vec<&String> = fragments.keys().collect();
    keys.sort_by_key(|b| std::cmp::Reverse(b.len()));
    for key in keys {
        let pat = format!(r"\b{}\b", regex::escape(key));
        let re = Regex::new(&pat).unwrap();
        // Use NoExpand to prevent $ in SQL (e.g. '$DoIt') from being
        // interpreted as a regex capture group reference in the replacement.
        expr = re
            .replace_all(&expr, regex::NoExpand(fragments[key].as_str()))
            .to_string();
    }

    expr = expr
        .replace(" and ", " AND ")
        .replace(" or ", " OR ")
        .replace(" not ", " NOT ");
    if expr.starts_with("not ") || expr.starts_with("NOT ") {
        expr = format!("NOT {}", &expr[4..]);
    }

    Ok(expr)
}

mod base64_engine {
    pub use base64::engine::general_purpose;
    pub use base64::Engine;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sigma::parser::Rule;

    fn compile_yaml(yaml: &str) -> String {
        let rule: Rule = serde_yaml::from_str(yaml).unwrap();
        compile(&rule).unwrap()
    }

    fn assert_valid_sql(sql: &str) {
        let conn = rusqlite::Connection::open_in_memory().unwrap();
        conn.create_scalar_function(
            "REGEXP",
            2,
            rusqlite::functions::FunctionFlags::SQLITE_UTF8
                | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
            |ctx| {
                let pattern: String = ctx.get(0)?;
                let text: String = ctx.get::<String>(1).unwrap_or_default();
                let re = regex::Regex::new(&pattern)
                    .map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;
                Ok(re.is_match(&text))
            },
        )
        .unwrap();
        conn.execute("CREATE TABLE events (\"_raw\" TEXT, \"CommandLine\" TEXT, \"Image\" TEXT, \"ParentImage\" TEXT, \"EventID\" TEXT, \"TargetFilename\" TEXT, \"SourceIp\" TEXT, \"User\" TEXT, \"count\" TEXT)", []).unwrap();
        conn.prepare(sql).unwrap();
    }

    #[test]
    fn test_to_like_contains() {
        assert_eq!(to_like("cmd.exe", true, false, false), "%cmd.exe%");
    }

    #[test]
    fn test_to_like_wildcards() {
        assert_eq!(to_like("*.exe", false, false, false), "%.exe");
    }

    #[test]
    fn test_to_like_startswith() {
        assert_eq!(to_like("C:\\Windows", false, true, false), "C:\\\\Windows%");
    }

    #[test]
    fn test_to_like_endswith() {
        assert_eq!(to_like(".exe", false, false, true), "%.exe");
    }

    #[test]
    fn test_simple_selection() {
        let sql = compile_yaml(
            r#"
title: Test Rule
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'whoami'
  condition: selection
"#,
        );
        assert!(sql.contains("LIKE '%whoami%'"));
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_selection_and_not_filter() {
        let sql = compile_yaml(
            r#"
title: Test Rule
level: medium
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'net'
  filter:
    Image|endswith: '\net.exe'
  condition: selection and not filter
"#,
        );
        assert!(sql.contains("AND NOT"));
        assert!(sql.contains("LIKE '%net%'"));
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_one_of_selection_wildcard() {
        let sql = compile_yaml(
            r#"
title: Test Rule
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    CommandLine|contains: 'whoami'
  selection2:
    CommandLine|contains: 'ipconfig'
  condition: 1 of selection*
"#,
        );
        assert!(sql.contains("OR"));
        assert!(sql.contains("whoami"));
        assert!(sql.contains("ipconfig"));
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_all_of_them() {
        let sql = compile_yaml(
            r#"
title: Test Rule
level: critical
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'whoami'
  filter:
    Image|endswith: '\cmd.exe'
  condition: all of them
"#,
        );
        assert!(sql.contains("AND"));
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_selection1_or_selection2() {
        let sql = compile_yaml(
            r#"
title: Test Rule
level: medium
logsource:
  category: process_creation
  product: windows
detection:
  selection1:
    CommandLine|contains: 'mimikatz'
  selection2:
    Image|endswith: '\procdump.exe'
  condition: selection1 or selection2
"#,
        );
        assert!(sql.contains("OR"));
        assert!(sql.contains("mimikatz"));
        assert!(sql.contains("procdump"));
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_modifier_contains() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    CommandLine|contains: 'test'
  condition: selection
"#,
        );
        assert!(sql.contains("LIKE '%test%'"));
    }

    #[test]
    fn test_modifier_startswith() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    CommandLine|startswith: 'cmd'
  condition: selection
"#,
        );
        assert!(sql.contains("LIKE 'cmd%'"));
    }

    #[test]
    fn test_modifier_endswith() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    Image|endswith: '.exe'
  condition: selection
"#,
        );
        assert!(sql.contains("LIKE '%.exe'"));
    }

    #[test]
    fn test_modifier_re() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    CommandLine|re: '.*whoami.*'
  condition: selection
"#,
        );
        assert!(sql.contains("REGEXP"));
        assert!(sql.contains(".*whoami.*"));
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_modifier_all() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    CommandLine|contains|all:
      - 'net'
      - 'user'
  condition: selection
"#,
        );
        assert!(sql.contains("AND"));
        assert!(sql.contains("LIKE '%net%'"));
        assert!(sql.contains("LIKE '%user%'"));
    }

    #[test]
    fn test_modifier_cidr() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    SourceIp|cidr: '10.0.0.0/8'
  condition: selection
"#,
        );
        assert!(sql.contains("LIKE '10.%'"));
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_modifier_gt_gte_lt_lte() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    count|gt: 10
  condition: selection
"#,
        );
        assert!(sql.contains("> 10"));

        let sql2 = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    count|lte: 5
  condition: selection
"#,
        );
        assert!(sql2.contains("<= 5"));
    }

    #[test]
    fn test_modifier_base64() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    CommandLine|base64: 'whoami'
  condition: selection
"#,
        );
        assert!(
            sql.contains("d2hvYW1p"),
            "Expected base64 of 'whoami', got: {}",
            sql
        );
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_modifier_base64offset() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    CommandLine|base64offset|contains: 'test'
  condition: selection
"#,
        );
        assert!(
            sql.contains("OR"),
            "Expected OR for base64offset variants, got: {}",
            sql
        );
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_modifier_windash() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    CommandLine|windash|contains: '-encoded'
  condition: selection
"#,
        );
        assert!(
            sql.contains("-encoded") || sql.contains("\\-encoded"),
            "sql: {}",
            sql
        );
        assert!(
            sql.contains("/encoded"),
            "Expected /encoded variant, got: {}",
            sql
        );
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_timeframe_warning() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    CommandLine|contains: 'test'
  timeframe: 5m
  condition: selection
"#,
        );
        assert!(sql.contains("test"));
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_null_value() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    CommandLine:
  condition: selection
"#,
        );
        assert!(sql.contains("IS NULL") || sql.contains("= ''"));
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_list_or_values() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
  condition: selection
"#,
        );
        assert!(sql.contains("OR"));
        assert!(sql.contains("cmd.exe"));
        assert!(sql.contains("powershell.exe"));
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_sigma_wildcards() {
        let sql = compile_yaml(
            r#"
title: Test
level: low
logsource: {}
detection:
  selection:
    CommandLine: 'C:\Windows\*\cmd.exe'
  condition: selection
"#,
        );
        assert!(
            sql.contains("C:\\\\Windows\\\\%\\\\cmd.exe"),
            "sql: {}",
            sql
        );
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_doit_no_match_all() {
        // Regression: $DoIt must not produce LIKE '%%' due to regex replacement
        let sql = compile_yaml(
            r#"
title: Test
level: critical
logsource: {}
detection:
  selection:
    Payload|contains:
      - '$DoIt'
      - 'harmj0y'
  condition: selection
"#,
        );
        assert!(
            sql.contains("$DoIt"),
            "Expected $DoIt literal in SQL, got: {}",
            sql
        );
        assert!(
            !sql.contains("LIKE '%%'"),
            "Should not generate match-all pattern, got: {}",
            sql
        );
        assert_valid_sql(&sql);
    }

    #[test]
    fn test_n_of_selections() {
        let sql = compile_yaml(
            r#"
title: Test N of selections
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection_a:
    CommandLine|contains: 'whoami'
  selection_b:
    CommandLine|contains: 'ipconfig'
  selection_c:
    CommandLine|contains: 'net user'
  condition: 2 of selection*
"#,
        );
        // Must use CASE/SUM approach, requiring at least 2 matches
        assert!(
            sql.contains("CASE WHEN"),
            "Expected CASE WHEN for N-of, got: {}",
            sql
        );
        assert!(
            sql.contains(">= 2"),
            "Expected >= 2 threshold, got: {}",
            sql
        );
        // Should NOT be a simple OR (that would match if any 1 matches)
        assert!(
            !sql.contains(" OR ") || sql.contains("CASE WHEN"),
            "Should not use simple OR for 2-of, got: {}",
            sql
        );
        assert_valid_sql(&sql);
    }
}
