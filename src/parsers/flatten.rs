use serde_json::Value;
use std::collections::HashMap;

use crate::model::{Event, SourceFormat};

pub fn flatten_json(value: &Value, source_file: &str, format: SourceFormat) -> Event {
    let mut event = Event::new(source_file, format);
    event.raw = serde_json::to_string(value).unwrap_or_default();

    let mut flat = HashMap::new();
    flatten_recursive(value, String::new(), &mut flat);
    event.fields = flat;

    event.fields.insert("_raw".to_string(), event.raw.clone());
    event
}

fn flatten_recursive(value: &Value, prefix: String, out: &mut HashMap<String, String>) {
    match value {
        Value::Object(map) => {
            if map.contains_key("Event") {
                if let Some(ev) = map.get("Event") {
                    flatten_windows_event(ev, out);
                    return;
                }
            }
            for (key, val) in map {
                let new_key = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{}_{}", prefix, key)
                };
                match val {
                    Value::Object(_) | Value::Array(_) => flatten_recursive(val, new_key, out),
                    _ => {
                        let s = val_to_string(val);
                        if !s.is_empty() {
                            out.insert(new_key.clone(), s.clone());
                            if !prefix.is_empty() {
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
                out.insert(prefix.clone(), strings.join(", "));
            } else {
                for (i, val) in arr.iter().enumerate() {
                    flatten_recursive(val, format!("{}_{}", prefix, i), out);
                }
            }
        }
        _ => {
            let s = val_to_string(value);
            if !prefix.is_empty() && !s.is_empty() {
                out.insert(prefix, s);
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
                    for item in arr {
                        if let Value::Object(dm) = item {
                            let name = dm.get("@Name").or(dm.get("Name")).and_then(|v| v.as_str());
                            let text = dm.get("#text").or(dm.get("text")).or(dm.get("$"));
                            if let (Some(n), Some(t)) = (name, text) {
                                out.insert(n.to_string(), val_to_string(t));
                            }
                        }
                    }
                }
                Value::Object(dm) => {
                    let name = dm.get("@Name").or(dm.get("Name")).and_then(|v| v.as_str());
                    let text = dm.get("#text").or(dm.get("text"));
                    if let (Some(n), Some(t)) = (name, text) {
                        out.insert(n.to_string(), val_to_string(t));
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
}
