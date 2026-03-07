use crate::model::{Event, SourceFormat};
use anyhow::Result;
use regex::Regex;
use std::io::{BufRead, BufReader};
use std::path::Path;

pub fn parse(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let reader = BufReader::new(std::fs::File::open(path)?);
    let header_re = Regex::new(
        r"^(?:.*?\s)?CEF:(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)",
    )
    .unwrap();
    let key_re = Regex::new(r"(?:^|\s)(\w+)=").unwrap();
    let mut events = Vec::new();

    for line in reader.lines().map_while(Result::ok) {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        let Some(c) = header_re.captures(t) else {
            continue;
        };

        let mut event = Event::new(source_file, SourceFormat::Cef);
        event.raw = t.to_string();
        event.set("cef_version", &c[1]);
        event.set("DeviceVendor", &c[2]);
        event.set("DeviceProduct", &c[3]);
        event.set("DeviceVersion", &c[4]);
        event.set("DeviceEventClassID", &c[5]);
        event.set("Name", &c[6]);
        event.set("Severity", &c[7]);

        let ext = &c[8];
        let mut positions: Vec<(usize, String)> = Vec::new();
        for m in key_re.find_iter(ext) {
            let s = m.as_str().trim();
            if let Some(eq) = s.find('=') {
                positions.push((m.end(), s[..eq].to_string()));
            }
        }
        for i in 0..positions.len() {
            let (start, ref key) = positions[i];
            let end = if i + 1 < positions.len() {
                positions[i + 1].0 - positions[i + 1].1.len() - 1
            } else {
                ext.len()
            };
            if start <= end && start <= ext.len() {
                let val = ext[start..end.min(ext.len())].trim();
                event.set(key.clone(), val.replace("\\=", "=").replace("\\\\", "\\"));
            }
        }
        event.fields.insert("_raw".into(), event.raw.clone());
        events.push(event);
    }
    Ok(events)
}
