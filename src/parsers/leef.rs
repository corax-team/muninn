use crate::model::{Event, SourceFormat};
use anyhow::Result;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn parse(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let reader = BufReader::new(std::fs::File::open(path)?);
    let mut events = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }

        let leef_start = if let Some(pos) = t.find("LEEF:") {
            pos
        } else {
            continue;
        };
        let leef_part = &t[leef_start..];

        let parts: Vec<&str> = leef_part.splitn(6, '|').collect();
        if parts.len() < 5 {
            continue;
        }

        let version_part = parts[0].strip_prefix("LEEF:").unwrap_or("");

        let mut event = Event::new(source_file, SourceFormat::Leef);
        event.raw = t.to_string();
        event.set("leef_version", version_part);
        event.set("DeviceVendor", parts[1]);
        event.set("DeviceProduct", parts[2]);
        event.set("DeviceVersion", parts[3]);

        let (event_id, extension) = if parts.len() >= 6 {
            (parts[4], parts[5])
        } else if let Some(tab_pos) = parts[4].find('\t') {
            (&parts[4][..tab_pos], &parts[4][tab_pos + 1..])
        } else {
            (parts[4], "")
        };

        event.set("DeviceEventClassID", event_id);

        let delim = if version_part.starts_with('2') && !extension.is_empty() {
            let d = extension.chars().next().unwrap_or('\t');
            let ext = &extension[d.len_utf8()..];
            parse_extension(&mut event, ext, d);
            d
        } else {
            parse_extension(&mut event, extension, '\t');
            '\t'
        };

        let _ = delim;
        event.fields.insert("_raw".into(), event.raw.clone());
        events.push(event);
    }
    Ok(events)
}

fn parse_extension(event: &mut Event, extension: &str, delim: char) {
    for pair in extension.split(delim) {
        let p = pair.trim();
        if let Some(eq) = p.find('=') {
            event.set(&p[..eq], &p[eq + 1..]);
        }
    }
}
