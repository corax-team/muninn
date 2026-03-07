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
    Ok(format!(
        "SELECT * FROM \"{}\" WHERE {}",
        TABLE, where_clause
    ))
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
                Ok(format!("{} = {}", qf, ns))
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
                        parts.push(format!("{} = {}", qf, n));
                    }
                    serde_yaml::Value::Null => {
                        parts.push(format!("({q} IS NULL OR {q} = '')", q = qf));
                    }
                    _ => {}
                }
            }
            if parts.is_empty() {
                return Ok("1=1".into());
            }
            let joiner = if has("all") { " AND " } else { " OR " };
            Ok(format!("({})", parts.join(joiner)))
        }
        _ => Ok("1=1".into()),
    }
}

fn string_to_sql(qf: &str, s: &str, mods: &[String]) -> Result<String> {
    let has = |m: &str| mods.contains(&m.to_string());

    if has("re") {
        return Ok(format!("{} REGEXP '{}'", qf, escape(s)));
    }

    if has("cidr") {
        return Ok(cidr_to_sql(qf, s));
    }

    let transformed = transform_value(s, mods);

    if transformed.len() == 1 {
        let like = to_like(
            &transformed[0],
            has("contains"),
            has("startswith"),
            has("endswith"),
        );
        Ok(format!("{} LIKE '{}' ESCAPE '\\'", qf, like))
    } else {
        let parts: Vec<String> = transformed
            .iter()
            .map(|v| {
                let like = to_like(v, has("contains"), has("startswith"), has("endswith"));
                format!("{} LIKE '{}' ESCAPE '\\'", qf, like)
            })
            .collect();
        Ok(format!("({})", parts.join(" OR ")))
    }
}

fn cidr_to_sql(qf: &str, cidr: &str) -> String {
    let parts: Vec<&str> = cidr.split('/').collect();
    let ip = parts[0];
    let mask_bits: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(32);

    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 || mask_bits > 32 {
        return format!("{} LIKE '{}%' ESCAPE '\\'", qf, escape(ip));
    }

    let full_octets = (mask_bits / 8) as usize;
    if mask_bits.is_multiple_of(8) && full_octets <= 4 {
        let prefix = octets[..full_octets].join(".");
        if full_octets == 4 {
            format!("{} = '{}'", qf, prefix)
        } else {
            format!("{} LIKE '{}.%' ESCAPE '\\'", qf, prefix)
        }
    } else {
        let prefix = octets[..full_octets].join(".");
        if prefix.is_empty() {
            format!("{} LIKE '%' ESCAPE '\\'", qf)
        } else {
            format!("{} LIKE '{}.%' ESCAPE '\\'", qf, prefix)
        }
    }
}

fn to_like(s: &str, contains: bool, startswith: bool, endswith: bool) -> String {
    let escaped = s
        .replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
        .replace('\'', "''");
    let w = escaped.replace('*', "%").replace('?', "_");
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
    s.replace('\'', "''")
}

fn parse_condition(cond: &str, fragments: &HashMap<String, String>) -> Result<String> {
    let mut expr = cond.trim().to_string();

    let of_re = Regex::new(r"(\d+|all)\s+of\s+(\w+\*|them)").unwrap();
    while let Some(caps) = of_re.captures(&expr.clone()) {
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
            let joiner = if quant == "all" { " AND " } else { " OR " };
            format!("({})", parts.join(joiner))
        };
        expr = expr.replace(full, &replacement);
    }

    let mut keys: Vec<&String> = fragments.keys().collect();
    keys.sort_by_key(|b| std::cmp::Reverse(b.len()));
    for key in keys {
        let pat = format!(r"\b{}\b", regex::escape(key));
        let re = Regex::new(&pat).unwrap();
        expr = re.replace_all(&expr, fragments[key].as_str()).to_string();
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
}
