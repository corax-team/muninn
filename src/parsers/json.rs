use super::flatten::flatten_json;
use crate::model::{Event, SourceFormat};
use anyhow::Result;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn parse_jsonl(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let reader = BufReader::new(std::fs::File::open(path)?);
    let mut events = Vec::new();
    for line in reader.lines().map_while(Result::ok) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        match serde_json::from_str::<serde_json::Value>(t) {
            Ok(val) => events.push(flatten_json(&val, source_file, SourceFormat::JsonLines)),
            Err(e) => log::debug!("Skipping malformed JSON line: {}", e),
        }
    }
    Ok(events)
}

pub fn parse_json_array(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let content = std::fs::read_to_string(path)?;
    let arr: Vec<serde_json::Value> = serde_json::from_str(&content)?;
    Ok(arr
        .iter()
        .map(|v| flatten_json(v, source_file, SourceFormat::JsonArray))
        .collect())
}
