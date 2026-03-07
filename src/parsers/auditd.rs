use crate::model::{Event, SourceFormat};
use anyhow::Result;
use regex::Regex;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn parse(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let reader = BufReader::new(std::fs::File::open(path)?);
    let kv_re = Regex::new(r#"(\w+)=("(?:[^"\\]|\\.)*"|\S+)"#).unwrap();
    let mut events = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let mut event = Event::new(source_file, SourceFormat::Auditd);
        event.raw = t.to_string();

        for cap in kv_re.captures_iter(t) {
            let key = cap[1].to_string();
            let mut val = cap[2].to_string();
            if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
                val = val[1..val.len() - 1].to_string();
            }
            event.set(key, val);
        }
        event.fields.insert("_raw".into(), event.raw.clone());
        if !event.fields.is_empty() {
            events.push(event);
        }
    }
    Ok(events)
}
