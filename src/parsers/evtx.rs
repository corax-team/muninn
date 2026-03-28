use super::flatten::flatten_json;
use crate::model::{Event, SourceFormat};
use anyhow::Result;
use std::path::Path;
use std::sync::mpsc;

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

/// Streaming EVTX parser: spawns a thread that parses records lazily
/// and sends them over a bounded channel. Peak memory: ~7 MB buffer
/// instead of entire file's events in RAM.
pub fn parse_streaming(path: &Path) -> Result<mpsc::Receiver<Event>> {
    // Validate file is accessible before spawning thread
    let _ = std::fs::File::open(path)?;
    let path = path.to_path_buf();
    let (tx, rx) = mpsc::sync_channel(2048);
    std::thread::spawn(move || {
        let source = path.display().to_string();
        match ::evtx::EvtxParser::from_path(&path) {
            Ok(mut parser) => {
                for record in parser.records_json_value() {
                    match record {
                        Ok(r) => {
                            let ev = flatten_json(&r.data, &source, SourceFormat::Evtx);
                            if tx.send(ev).is_err() {
                                break; // receiver dropped, stop parsing
                            }
                        }
                        Err(e) => log::debug!("Skipping malformed EVTX record: {}", e),
                    }
                }
            }
            Err(e) => log::error!("Failed to open EVTX {:?}: {}", path, e),
        }
    });
    Ok(rx)
}
