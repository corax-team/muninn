use crate::model::{Event, SourceFormat};
use anyhow::Result;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn parse(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let reader = BufReader::new(std::fs::File::open(path)?);
    let mut events = Vec::new();
    let mut separator = '\t';
    let mut empty_field = "(empty)".to_string();
    let mut unset_field = "-".to_string();
    let mut log_path = String::new();
    let mut fields: Vec<String> = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }

        if t.starts_with('#') {
            if let Some(r) = t.strip_prefix("#separator ") {
                separator = parse_zeek_char(r.trim());
            } else if let Some(r) = t.strip_prefix("#empty_field") {
                empty_field = r.trim_start_matches(separator).trim().to_string();
            } else if let Some(r) = t.strip_prefix("#unset_field") {
                unset_field = r.trim_start_matches(separator).trim().to_string();
            } else if let Some(r) = t.strip_prefix("#path") {
                log_path = r.trim_start_matches(separator).trim().to_string();
            } else if let Some(r) = t.strip_prefix("#fields") {
                fields = r
                    .trim_start_matches(separator)
                    .split(separator)
                    .map(|f| f.trim().replace('.', "_"))
                    .collect();
            }
            continue;
        }
        if fields.is_empty() {
            continue;
        }

        let values: Vec<&str> = t.split(separator).collect();
        let mut event = Event::new(source_file, SourceFormat::ZeekTsv);
        event.raw = t.to_string();
        if !log_path.is_empty() {
            event.set("_zeek_log_type", &log_path);
        }

        for (i, field) in fields.iter().enumerate() {
            let val = values.get(i).copied().unwrap_or("");
            if val != unset_field && val != empty_field && !val.is_empty() {
                event.set(field.clone(), val);
            }
        }
        event.fields.insert("_raw".into(), event.raw.clone());
        events.push(event);
    }
    Ok(events)
}

fn parse_zeek_char(s: &str) -> char {
    if s.starts_with("\\x") && s.len() >= 4 {
        if let Ok(b) = u8::from_str_radix(&s[2..4], 16) {
            return b as char;
        }
    }
    s.chars().next().unwrap_or('\t')
}
