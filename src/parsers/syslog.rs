use crate::model::{Event, SourceFormat};
use anyhow::Result;
use regex::Regex;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn parse(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let reader = BufReader::new(std::fs::File::open(path)?);
    let mut events = Vec::new();

    let re_5424 =
        Regex::new(r"^<(\d+)>(\d+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S*)\s*(.*)")
            .unwrap();
    let re_3164 = Regex::new(r"^(?:<(\d+)>)?(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+(\S+?)(?:\[(\d+)\])?:\s*(.*)").unwrap();
    let kv_re = Regex::new(r#"(\w+)=("(?:[^"\\]|\\.)*"|\S+)"#).unwrap();

    for line in reader.lines().map_while(Result::ok) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let mut event = Event::new(source_file, SourceFormat::Syslog);
        event.raw = t.to_string();

        if let Some(c) = re_5424.captures(t) {
            let pri: u32 = c.get(1).unwrap().as_str().parse().unwrap_or(0);
            event.set("priority", pri.to_string());
            event.set("facility", (pri / 8).to_string());
            event.set("severity", (pri % 8).to_string());
            event.set("version", c.get(2).map(|m| m.as_str()).unwrap_or(""));
            event.set("timestamp", c.get(3).map(|m| m.as_str()).unwrap_or(""));
            event.set("hostname", c.get(4).map(|m| m.as_str()).unwrap_or(""));
            event.set("app_name", c.get(5).map(|m| m.as_str()).unwrap_or(""));
            event.set("procid", c.get(6).map(|m| m.as_str()).unwrap_or(""));
            event.set("msgid", c.get(7).map(|m| m.as_str()).unwrap_or(""));
            event.set("message", c.get(9).map(|m| m.as_str()).unwrap_or(""));
        } else if let Some(c) = re_3164.captures(t) {
            if let Some(pri_m) = c.get(1) {
                let pri: u32 = pri_m.as_str().parse().unwrap_or(0);
                event.set("priority", pri.to_string());
                event.set("facility", (pri / 8).to_string());
                event.set("severity", (pri % 8).to_string());
            }
            event.set("timestamp", c.get(2).map(|m| m.as_str()).unwrap_or(""));
            event.set("hostname", c.get(3).map(|m| m.as_str()).unwrap_or(""));
            event.set("app_name", c.get(4).map(|m| m.as_str()).unwrap_or(""));
            if let Some(pid) = c.get(5) {
                event.set("procid", pid.as_str());
            }
            let msg = c.get(6).map(|m| m.as_str()).unwrap_or("");
            event.set("message", msg);
            for cap in kv_re.captures_iter(msg) {
                let mut val = cap[2].to_string();
                if val.starts_with('"') && val.ends_with('"') && val.len() >= 2 {
                    val = val[1..val.len() - 1].to_string();
                }
                event.fields.entry(cap[1].to_string()).or_insert(val);
            }
        } else {
            event.set("message", t);
        }
        event.fields.insert("_raw".into(), event.raw.clone());
        events.push(event);
    }
    Ok(events)
}
