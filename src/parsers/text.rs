use crate::model::{Event, SourceFormat};
use anyhow::Result;
use regex::Regex;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn parse(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let reader = BufReader::new(std::fs::File::open(path)?);
    let level_re = Regex::new(
        r"\b(TRACE|DEBUG|INFO|NOTICE|WARNING|WARN|ERROR|CRITICAL|FATAL|ALERT|EMERGENCY)\b",
    )
    .unwrap();
    let ts_re = Regex::new(
        r"(\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)",
    )
    .unwrap();
    let apache_re = Regex::new(
        r#"^(\S+)\s+\S+\s+(\S+)\s+\[([^\]]+)\]\s+"(\S+)\s+(\S+)\s+(\S+)"\s+(\d+)\s+(\S+)"#,
    )
    .unwrap();
    let mut events = Vec::new();
    let mut lineno: u64 = 0;

    for line in reader.lines().map_while(Result::ok) {
        lineno += 1;
        let t = line.trim();
        if t.is_empty() {
            continue;
        }

        let mut event = Event::new(source_file, SourceFormat::PlainText);
        event.raw = t.to_string();
        event.set("message", t);
        event.set("_line", lineno.to_string());

        if let Some(c) = ts_re.captures(t) {
            event.set("timestamp", &c[1]);
        }
        if let Some(c) = level_re.captures(t) {
            event.set("level", c[1].to_uppercase());
        }

        if let Some(c) = apache_re.captures(t) {
            event.set("c-ip", &c[1]);
            event.set("cs-username", &c[2]);
            event.set("timestamp", &c[3]);
            event.set("cs-method", &c[4]);
            event.set("cs-uri-stem", &c[5]);
            event.set("cs-version", &c[6]);
            event.set("sc-status", &c[7]);
            event.set("sc-bytes", &c[8]);
        }

        event.fields.insert("_raw".into(), event.raw.clone());
        events.push(event);
    }
    Ok(events)
}
