use serde_json::Value;
use std::collections::HashMap;

use crate::model::{Event, SourceFormat};

pub fn flatten_json(value: &Value, source_file: &str, format: SourceFormat) -> Event {
    let mut event = Event::new(source_file, format);
    event.raw = serde_json::to_string(value).unwrap_or_default();

    let mut flat = HashMap::new();
    flatten_recursive(value, String::new(), &mut flat);

    // SIGMA field aliases: map flattened XML attribute paths to SIGMA-standard names.
    // e.g., Provider_#attributes_Name → Provider_Name (used by SIGMA rules)
    apply_sigma_aliases(&mut flat);

    // EXTEND, don't replace: Event::new() seeded the map with the
    // metadata fields that compile_logsource() filters on
    // (`_source_format`, `_source_file`). A naive `event.fields = flat`
    // would obliterate them and silently break every SIGMA rule whose
    // logsource maps to `_source_format = '<X>'` (all 205+ AWS / Azure /
    // GCP / M365 / Okta / Cisco / Apache / Linux rules).
    for (k, v) in flat {
        event.fields.insert(k, v);
    }
    event.fields.insert("_raw".to_string(), event.raw.clone());
    event
}

/// Add SIGMA-compatible field aliases for Windows EVTX flattened fields.
/// Maps EVTX JSON flattened paths to SIGMA-standard field names used by
/// pysigma windows/sysmon pipelines. Aliases are added without removing
/// originals so both forms work in SQL queries.
fn apply_sigma_aliases(fields: &mut HashMap<String, String>) {
    // System element aliases: XML attribute paths → short names
    //
    // EVTX <System> sub-elements like <EventID Qualifiers="32770">7045</EventID>
    // serialize to {"EventID": {"#attributes": {"Qualifiers": "32770"},
    // "#text": "7045"}}. The flattener stores them as `EventID_#text` and
    // `EventID_#attributes_Qualifiers`. SIGMA rules expect short names (e.g.
    // `EventID: 7045`), so we alias the `_#text` form back to the bare name.
    // Without this, every SIGMA rule keyed on EventID, Level, Task, Opcode or
    // Keywords silently fails on events where those fields carry XML
    // attributes (e.g. all System.evtx and Kaspersky avp logs).
    const SYSTEM_ALIASES: &[(&str, &str)] = &[
        ("Provider_#attributes_Name", "Provider_Name"),
        ("Provider_#attributes_Guid", "Provider_Guid"),
        ("Execution_#attributes_ProcessID", "ExecutionProcessID"),
        ("Execution_#attributes_ThreadID", "ExecutionThreadID"),
        ("TimeCreated_#attributes_SystemTime", "TimeCreated"),
        ("Security_#attributes_UserID", "SecurityUserID"),
        ("EventID_#text", "EventID"),
        ("Level_#text", "Level"),
        ("Task_#text", "Task"),
        ("Opcode_#text", "Opcode"),
        ("Keywords_#text", "Keywords"),
        ("Version_#text", "Version"),
        ("Correlation_#text", "Correlation"),
    ];

    // Security EventID 4688 → SIGMA process_creation field mapping
    // SIGMA uses Sysmon-style names; Security log uses different names
    const SECURITY_4688_ALIASES: &[(&str, &str)] = &[
        ("NewProcessName", "Image"),
        ("ParentProcessName", "ParentImage"),
        ("SubjectUserName", "User"),
        ("SubjectUserSid", "UserSid"),
        ("SubjectDomainName", "UserDomain"),
        ("SubjectLogonId", "LogonId"),
        ("NewProcessId", "ProcessId"),
        ("CreatorProcessId", "ParentProcessId"),
        ("TokenElevationType", "IntegrityLevel"),
    ];

    // Security logon (4624/4625) aliases
    const LOGON_ALIASES: &[(&str, &str)] = &[
        ("TargetUserName", "User"),
        ("IpAddress", "SourceIp"),
        ("IpPort", "SourcePort"),
        ("WorkstationName", "Workstation"),
    ];

    // EventXML prefix removal (some EVTX parsers add EventXML_ prefix)
    const EVENTXML_ALIASES: &[(&str, &str)] = &[
        ("EventXML_ServiceName", "ServiceName"),
        ("EventXML_Version", "ServiceVersion"),
        ("EventXML_ImagePath", "ServiceImagePath"),
        ("EventXML_Param1", "param1"),
        ("EventXML_Param2", "param2"),
        ("EventXML_Param3", "param3"),
    ];

    // Windows Defender specific field aliases
    const DEFENDER_ALIASES: &[(&str, &str)] = &[
        ("Threat Name", "ThreatName"),
        ("Threat ID", "ThreatID"),
        ("Detection Source", "DetectionSource"),
        ("Process Name", "ProcessName"),
        ("Detection User", "DetectionUser"),
        ("Action Name", "ActionName"),
        ("Severity Name", "SeverityName"),
        ("Category Name", "CategoryName"),
        ("FWLink", "FWLink"),
        ("Path", "Path"),
        ("Product Name", "ProductName"),
        ("Product Version", "ProductVersion"),
    ];

    let mut to_add = Vec::new();

    // Apply all alias tables
    let tables: &[&[(&str, &str)]] = &[
        SYSTEM_ALIASES,
        SECURITY_4688_ALIASES,
        LOGON_ALIASES,
        EVENTXML_ALIASES,
        DEFENDER_ALIASES,
    ];
    for table in tables {
        for &(long, short) in *table {
            if let Some(val) = fields.get(long) {
                if !fields.contains_key(&short.to_string()) {
                    to_add.push((short.to_string(), val.clone()));
                }
            }
        }
    }

    // Also strip "EventXML_" prefix for any remaining EventXML_ fields
    let eventxml_fields: Vec<(String, String)> = fields
        .iter()
        .filter(|(k, _)| k.starts_with("EventXML_") && !k.contains("#attributes"))
        .map(|(k, v)| (k[9..].to_string(), v.clone()))
        .collect();
    for (short, val) in eventxml_fields {
        if !fields.contains_key(&short) {
            to_add.push((short, val));
        }
    }

    for (k, v) in to_add {
        fields.insert(k, v);
    }
}

fn flatten_recursive(value: &Value, prefix: String, out: &mut HashMap<String, String>) {
    flatten_recursive_dual(value, prefix.clone(), prefix, out);
}

/// Recursive flattener that maintains TWO parallel prefixes simultaneously:
/// underscore form (`userIdentity_arn`, our historical convention) AND dot
/// form (`userIdentity.arn`, the SIGMA spec convention used by every
/// SigmaHQ cloud rule). Both keys point at the same value, so a SIGMA rule
/// matching `userIdentity.arn` and a Muninn-native one matching
/// `userIdentity_arn` both resolve.
///
/// Without this, all 205+ SIGMA AWS / Azure / GCP / M365 rules silently
/// fail to match against CloudTrail / AAD / Audit Log inputs because
/// their `.`-separated field names never resolve.
fn flatten_recursive_dual(
    value: &Value,
    prefix_us: String,
    prefix_dot: String,
    out: &mut HashMap<String, String>,
) {
    match value {
        Value::Object(map) => {
            if map.contains_key("Event") {
                if let Some(ev) = map.get("Event") {
                    flatten_windows_event(ev, out);
                    return;
                }
            }
            for (key, val) in map {
                let (new_us, new_dot) = if prefix_us.is_empty() {
                    (key.clone(), key.clone())
                } else {
                    (
                        format!("{}_{}", prefix_us, key),
                        format!("{}.{}", prefix_dot, key),
                    )
                };
                match val {
                    Value::Object(_) | Value::Array(_) => {
                        flatten_recursive_dual(val, new_us, new_dot, out)
                    }
                    _ => {
                        let s = val_to_string(val);
                        if !s.is_empty() {
                            out.insert(new_us.clone(), s.clone());
                            // Only store dot alias when the path actually
                            // descended into a nested object — keeps the row
                            // wide-but-not-doubled for top-level keys.
                            if new_dot != new_us {
                                out.insert(new_dot, s.clone());
                            }
                            if !prefix_us.is_empty() {
                                out.entry(key.clone()).or_insert(s);
                            }
                        }
                    }
                }
            }
        }
        Value::Array(arr) => {
            let strings: Vec<String> = arr
                .iter()
                .filter_map(|v| {
                    let s = val_to_string(v);
                    if s.is_empty() {
                        None
                    } else {
                        Some(s)
                    }
                })
                .collect();

            if !strings.is_empty() {
                out.insert(prefix_us.clone(), strings.join(", "));
                if prefix_dot != prefix_us {
                    out.insert(prefix_dot.clone(), strings.join(", "));
                }
            } else {
                for (i, val) in arr.iter().enumerate() {
                    flatten_recursive_dual(
                        val,
                        format!("{}_{}", prefix_us, i),
                        format!("{}.{}", prefix_dot, i),
                        out,
                    );
                }
            }
        }
        _ => {
            let s = val_to_string(value);
            if !prefix_us.is_empty() && !s.is_empty() {
                out.insert(prefix_us.clone(), s.clone());
                if prefix_dot != prefix_us {
                    out.insert(prefix_dot, s);
                }
            }
        }
    }
}

fn flatten_windows_event(event: &Value, out: &mut HashMap<String, String>) {
    if let Value::Object(map) = event {
        if let Some(system) = map.get("System") {
            flatten_recursive(system, String::new(), out);
        }
        if let Some(ed) = map.get("EventData") {
            flatten_event_data(ed, out);
        }
        if let Some(ud) = map.get("UserData") {
            flatten_recursive(ud, String::new(), out);
        }
        for (key, val) in map {
            if key != "System" && key != "EventData" && key != "UserData" {
                flatten_recursive(val, key.clone(), out);
            }
        }
    }
}

fn flatten_event_data(ed: &Value, out: &mut HashMap<String, String>) {
    if let Value::Object(map) = ed {
        if let Some(data) = map.get("Data") {
            match data {
                Value::Array(arr) => {
                    // Mixed array: each element might be a named param (Sysmon-style)
                    // OR a bare string (Kaspersky/Application/older event styles).
                    // Named params populate their own field; bare strings + nameless
                    // objects are joined into EventData_Text so the message body
                    // is searchable / IOC-extractable. Without this, Kaspersky
                    // events come through with only system metadata and the actual
                    // message vanishes — the bug that hid threat hashes.
                    let mut bare_strings: Vec<String> = Vec::new();
                    let mut indexed_idx = 0usize;
                    for item in arr {
                        match item {
                            Value::Object(dm) => {
                                let name =
                                    dm.get("@Name").or(dm.get("Name")).and_then(|v| v.as_str());
                                let text = dm.get("#text").or(dm.get("text")).or(dm.get("$"));
                                match (name, text) {
                                    (Some(n), Some(t)) => {
                                        out.insert(n.to_string(), val_to_string(t));
                                    }
                                    (None, Some(t)) => {
                                        // Nameless: collect by position so the
                                        // analyst still has Data_0, Data_1, etc.
                                        out.insert(
                                            format!("Data_{}", indexed_idx),
                                            val_to_string(t),
                                        );
                                        indexed_idx += 1;
                                        bare_strings.push(val_to_string(t));
                                    }
                                    _ => {
                                        // {@Name: x, no text} — keep at least the name
                                        if let Some(n) = name {
                                            out.insert(n.to_string(), String::new());
                                        }
                                    }
                                }
                            }
                            // Bare strings inside Data array — common in Application
                            // and many provider-specific channels (Kaspersky, McAfee,
                            // various security vendors).
                            Value::String(s) => {
                                out.insert(format!("Data_{}", indexed_idx), s.clone());
                                indexed_idx += 1;
                                bare_strings.push(s.clone());
                            }
                            other => {
                                let s = val_to_string(other);
                                if !s.is_empty() {
                                    out.insert(format!("Data_{}", indexed_idx), s.clone());
                                    indexed_idx += 1;
                                    bare_strings.push(s);
                                }
                            }
                        }
                    }
                    if !bare_strings.is_empty() {
                        out.insert("EventData_Text".into(), bare_strings.join("\n"));
                    }
                }
                // Single Data object — could be a named param (Sysmon)
                // OR a Kaspersky-style `Data: {"#text": [...]}` payload.
                Value::Object(dm) => {
                    let name = dm.get("@Name").or(dm.get("Name")).and_then(|v| v.as_str());
                    let text = dm.get("#text").or(dm.get("text"));
                    match (name, text) {
                        (Some(n), Some(t)) => {
                            out.insert(n.to_string(), val_to_string(t));
                        }
                        (None, Some(t)) => {
                            // Kaspersky pattern: { "#text": ["msg1", "msg2", ...] }
                            // Surface the joined text as EventData_Text so the
                            // message body becomes searchable.
                            let joined = match t {
                                Value::Array(arr) => arr
                                    .iter()
                                    .map(val_to_string)
                                    .filter(|s| !s.is_empty())
                                    .collect::<Vec<_>>()
                                    .join("\n"),
                                _ => val_to_string(t),
                            };
                            if !joined.is_empty() {
                                out.insert("EventData_Text".into(), joined);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {
                    out.insert("Data".into(), val_to_string(data));
                }
            }
        }
        for (k, v) in map {
            if k != "Data" {
                out.insert(k.clone(), val_to_string(v));
            }
        }
    }
}

fn val_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        _ => serde_json::to_string(v).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_flatten_windows_event() {
        let input = json!({
            "Event": {
                "System": { "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational" },
                "EventData": {
                    "Data": [
                        { "@Name": "CommandLine", "#text": "cmd.exe /c whoami" },
                        { "@Name": "Image", "#text": "C:\\Windows\\System32\\cmd.exe" }
                    ]
                }
            }
        });
        let ev = flatten_json(&input, "test.evtx", SourceFormat::Evtx);
        assert_eq!(ev.get("CommandLine"), Some("cmd.exe /c whoami"));
        assert_eq!(ev.get("Image"), Some("C:\\Windows\\System32\\cmd.exe"));
    }

    #[test]
    fn kaspersky_data_text_array_surfaces_as_eventdata_text() {
        // Regression test: Kaspersky / Application-style events use a single
        // unnamed `Data` object with `#text` carrying an array of message
        // strings. The flattener must surface the joined text so the message
        // body reaches SIGMA + IOC pipelines. Before the fix, this content
        // was silently dropped because the gate required an @Name field.
        let input = serde_json::json!({
            "Event": {
                "System": { "EventID": 2078, "Channel": "Kaspersky Endpoint Security" },
                "EventData": {
                    "Data": {
                        "#text": [
                            "Положение о KSN было обновлено.",
                            "Хеш заражённого файла: ac298dcf92ac4de9a4521e0596a9cef5"
                        ]
                    }
                }
            }
        });
        let ev = flatten_json(&input, "test.evtx", SourceFormat::Evtx);
        let text = ev
            .get("EventData_Text")
            .expect("EventData_Text must be set");
        assert!(text.contains("KSN"), "joined message should be present");
        assert!(
            text.contains("ac298dcf92ac4de9a4521e0596a9cef5"),
            "hash inside the message must be discoverable for IOC extraction"
        );
    }

    #[test]
    fn nameless_data_array_items_get_indexed_keys() {
        // Bare strings inside a Data array (some Application providers do this)
        // should land as Data_0, Data_1, ... AND be joined into EventData_Text.
        let input = serde_json::json!({
            "Event": {
                "System": { "EventID": 1000, "Channel": "Application" },
                "EventData": {
                    "Data": ["param-a", "param-b", "param-c"]
                }
            }
        });
        let ev = flatten_json(&input, "test.evtx", SourceFormat::Evtx);
        assert_eq!(ev.get("Data_0"), Some("param-a"));
        assert_eq!(ev.get("Data_2"), Some("param-c"));
        let joined = ev.get("EventData_Text").expect("joined text must be set");
        assert!(joined.contains("param-a"));
        assert!(joined.contains("param-c"));
    }
}
