use super::flatten::flatten_json;
use crate::model::{Event, SourceFormat};
use anyhow::Result;
use std::io::{BufRead, BufReader};
use std::path::Path;

/// AWS CloudTrail (`{"Records":[…]}`), Azure Activity (`{"records":[…]}`),
/// and similar cloud audit-log wrappers ship one JSON object that contains
/// many events under a single key. Treating the whole envelope as a single
/// event hides every individual API call. Detect the pattern and expand.
fn expand_wrapped_records(val: &serde_json::Value) -> Option<Vec<serde_json::Value>> {
    let obj = val.as_object()?;
    if obj.len() != 1 {
        return None;
    }
    let (key, inner) = obj.iter().next()?;
    let lower = key.to_ascii_lowercase();
    if lower != "records" {
        return None;
    }
    let arr = inner.as_array()?;
    Some(arr.clone())
}

fn push_value(
    val: serde_json::Value,
    source_file: &str,
    format: SourceFormat,
    out: &mut Vec<Event>,
) {
    if let Some(records) = expand_wrapped_records(&val) {
        for rec in records {
            out.push(flatten_json(&rec, source_file, format.clone()));
        }
    } else {
        out.push(flatten_json(&val, source_file, format));
    }
}

pub fn parse_jsonl(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    // Format detection sends every file that starts with `{` here, including
    // multi-line CloudTrail/Azure wrappers that line-by-line parsing chokes on
    // (line 1 is `{"Records":[` — not a complete JSON value). Try a full-file
    // parse first; fall back to line-by-line only when the root isn't a valid
    // single JSON value (i.e. genuine NDJSON / one-object-per-line).
    let raw = std::fs::read_to_string(path)?;
    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
        let mut events = Vec::new();
        match val {
            serde_json::Value::Array(arr) => {
                for v in arr {
                    push_value(v, source_file, SourceFormat::JsonLines, &mut events);
                }
            }
            other => push_value(other, source_file, SourceFormat::JsonLines, &mut events),
        }
        return Ok(events);
    }

    // Genuine line-delimited JSON: each line is its own value.
    let reader = BufReader::new(std::fs::File::open(path)?);
    let mut events = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(t) {
            Ok(val) => push_value(val, source_file, SourceFormat::JsonLines, &mut events),
            Err(e) => log::debug!("Skipping malformed JSON line: {}", e),
        }
    }
    Ok(events)
}

pub fn parse_json_array(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    // First try parsing as a top-level JSON value of any shape: an array of
    // events, a single event object, or a CloudTrail-style `{"Records": [...]}`
    // wrapper. We can't blindly assume `Vec<Value>` because real CloudTrail
    // files start with an object, not an array.
    let val: serde_json::Value = serde_json::from_reader(reader)?;
    let mut events = Vec::new();
    match val {
        serde_json::Value::Array(arr) => {
            for v in arr {
                push_value(v, source_file, SourceFormat::JsonArray, &mut events);
            }
        }
        other => push_value(other, source_file, SourceFormat::JsonArray, &mut events),
    }
    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_tmp(ext: &str, body: &str) -> NamedTempFile {
        let suffix = format!(".{ext}");
        let mut f = tempfile::Builder::new().suffix(&suffix).tempfile().unwrap();
        f.write_all(body.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn cloudtrail_records_expanded_into_events() {
        let body = r#"{"Records":[
            {"eventName":"CreateAccessKey","sourceIPAddress":"192.168.1.10"},
            {"eventName":"AttachUserPolicy","sourceIPAddress":"192.168.1.11"},
            {"eventName":"DeleteUser","sourceIPAddress":"192.168.1.12"}
        ]}"#;
        let f = write_tmp("json", body);
        let events = parse_json_array(f.path(), "cloudtrail.json").unwrap();
        assert_eq!(events.len(), 3, "Records[] should be expanded");
        assert!(events
            .iter()
            .any(|e| e.fields.get("eventName").is_some_and(|v| v == "DeleteUser")));
    }

    #[test]
    fn azure_records_lowercase_expanded() {
        let body = r#"{"records":[{"name":"a"},{"name":"b"}]}"#;
        let f = write_tmp("json", body);
        let events = parse_json_array(f.path(), "azure.json").unwrap();
        assert_eq!(events.len(), 2);
    }

    #[test]
    fn jsonl_with_records_wrappers() {
        let body = r#"{"Records":[{"eventName":"E1"},{"eventName":"E2"}]}
{"Records":[{"eventName":"E3"}]}"#;
        let f = write_tmp("jsonl", body);
        let events = parse_jsonl(f.path(), "ct.jsonl").unwrap();
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn plain_jsonl_unchanged() {
        let body = "{\"a\":1}\n{\"b\":2}\n";
        let f = write_tmp("jsonl", body);
        let events = parse_jsonl(f.path(), "plain.jsonl").unwrap();
        assert_eq!(events.len(), 2);
    }
}
