use crate::model::{Event, SourceFormat};
use anyhow::Result;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn parse(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let reader = BufReader::new(std::fs::File::open(path)?);
    let mut events = Vec::new();
    let mut fields: Vec<String> = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with('#') {
            if let Some(rest) = t.strip_prefix("#Fields:") {
                fields = rest
                    .split_whitespace()
                    .map(|f| f.replace('(', "-").replace(')', "").to_lowercase())
                    .collect();
            }
            continue;
        }
        if fields.is_empty() {
            continue;
        }

        let values: Vec<&str> = t.split_whitespace().collect();
        let mut event = Event::new(source_file, SourceFormat::W3cExtended);
        event.raw = t.to_string();

        for (i, field) in fields.iter().enumerate() {
            let val = values.get(i).copied().unwrap_or("-");
            if val != "-" {
                event.set(field.clone(), val);
            }
        }
        if let (Some(d), Some(tm)) = (
            event.get("date").map(String::from),
            event.get("time").map(String::from),
        ) {
            event.set("timestamp", format!("{}T{}", d, tm));
        }
        event.fields.insert("_raw".into(), event.raw.clone());
        events.push(event);
    }
    Ok(events)
}
