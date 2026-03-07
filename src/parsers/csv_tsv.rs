use crate::model::{Event, SourceFormat};
use anyhow::Result;
use std::path::Path;

pub fn parse(path: &Path, source_file: &str, format: &SourceFormat) -> Result<Vec<Event>> {
    let delimiter = if *format == SourceFormat::Tsv {
        b'\t'
    } else {
        b','
    };
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .has_headers(true)
        .delimiter(delimiter)
        .from_path(path)?;

    let headers: Vec<String> = reader.headers()?.iter().map(|h| h.to_string()).collect();
    let mut events = Vec::new();

    for record in reader.records() {
        let record = match record {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut event = Event::new(source_file, format.clone());
        let mut raw_parts = Vec::new();
        for (i, field) in record.iter().enumerate() {
            let key = headers
                .get(i)
                .cloned()
                .unwrap_or_else(|| format!("field_{}", i));
            raw_parts.push(field.to_string());
            event.set(key, field);
        }
        event.raw = raw_parts.join(if *format == SourceFormat::Tsv {
            "\t"
        } else {
            ","
        });
        event.fields.insert("_raw".into(), event.raw.clone());
        events.push(event);
    }
    Ok(events)
}
