use super::flatten::flatten_json;
use crate::model::{Event, SourceFormat};
use anyhow::Result;
use std::path::Path;

pub fn parse(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let content = std::fs::read_to_string(path)?;
    let trimmed = content.trim();

    let raw_events: Vec<serde_json::Value> = if trimmed.starts_with('[') {
        serde_json::from_str(trimmed)?
    } else {
        trimmed
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str(l).ok())
            .collect()
    };

    Ok(raw_events
        .iter()
        .map(|v| {
            let mut ev = flatten_json(v, source_file, SourceFormat::MacosUnifiedLog);
            if let Some(v) = ev.fields.get("processImagePath").cloned() {
                ev.fields.entry("Image".into()).or_insert(v);
            }
            if let Some(v) = ev.fields.get("processID").cloned() {
                ev.fields.entry("ProcessId".into()).or_insert(v);
            }
            if let Some(v) = ev.fields.get("eventMessage").cloned() {
                ev.fields.entry("message".into()).or_insert(v);
            }
            ev
        })
        .collect())
}
