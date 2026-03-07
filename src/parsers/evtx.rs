use super::flatten::flatten_json;
use crate::model::{Event, SourceFormat};
use anyhow::Result;
use std::path::Path;

pub fn parse(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let mut parser = ::evtx::EvtxParser::from_path(path)?;
    let mut events = Vec::new();

    for record in parser.records_json_value() {
        match record {
            Ok(r) => events.push(flatten_json(&r.data, source_file, SourceFormat::Evtx)),
            Err(e) => log::debug!("Skipping malformed EVTX record: {}", e),
        }
    }
    Ok(events)
}
