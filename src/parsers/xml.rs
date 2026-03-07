use crate::model::{Event, SourceFormat};
use anyhow::Result;
use quick_xml::events::Event as XmlEvent;
use quick_xml::Reader;
use std::collections::HashMap;
use std::path::Path;

pub fn parse(path: &Path, source_file: &str) -> Result<Vec<Event>> {
    let content = std::fs::read_to_string(path)?;
    let mut events = Vec::new();

    if content.contains("<Event>") || content.contains("<Event ") {
        let mut reader = Reader::from_str(&content);
        let mut buf = Vec::new();
        let mut in_event = false;
        let mut event_xml = String::new();
        let mut depth = 0;

        loop {
            match reader.read_event_into(&mut buf) {
                Ok(XmlEvent::Start(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if name == "Event" {
                        in_event = true;
                        depth = 1;
                        event_xml.clear();
                        event_xml.push_str("<Event>");
                    } else if in_event {
                        depth += 1;
                        event_xml.push('<');
                        event_xml.push_str(&name);
                        for a in e.attributes().flatten() {
                            let akey = String::from_utf8_lossy(a.key.as_ref());
                            let aval = String::from_utf8_lossy(&a.value);
                            event_xml.push(' ');
                            event_xml.push_str(&akey);
                            event_xml.push_str("=\"");
                            event_xml.push_str(&aval);
                            event_xml.push('"');
                        }
                        event_xml.push('>');
                    }
                }
                Ok(XmlEvent::End(ref e)) => {
                    let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                    if in_event {
                        if name == "Event" && depth == 1 {
                            event_xml.push_str("</Event>");
                            match xml_block_to_event(&event_xml, source_file) {
                                Ok(ev) => events.push(ev),
                                Err(e) => log::debug!("Skipping malformed XML event: {}", e),
                            }
                            in_event = false;
                        } else {
                            event_xml.push_str("</");
                            event_xml.push_str(&name);
                            event_xml.push('>');
                            depth -= 1;
                        }
                    }
                }
                Ok(XmlEvent::Text(ref e)) => {
                    if in_event {
                        let text = e.unescape().unwrap_or_default().to_string();
                        event_xml.push_str(&quick_xml::escape::escape(&text));
                    }
                }
                Ok(XmlEvent::Empty(ref e)) => {
                    if in_event {
                        let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                        event_xml.push('<');
                        event_xml.push_str(&name);
                        for a in e.attributes().flatten() {
                            let akey = String::from_utf8_lossy(a.key.as_ref());
                            let aval = String::from_utf8_lossy(&a.value);
                            event_xml.push(' ');
                            event_xml.push_str(&akey);
                            event_xml.push_str("=\"");
                            event_xml.push_str(&aval);
                            event_xml.push('"');
                        }
                        event_xml.push_str("/>");
                    }
                }
                Ok(XmlEvent::Eof) => break,
                Err(_) => break,
                _ => {}
            }
            buf.clear();
        }
    } else {
        for line in content.lines() {
            let t = line.trim();
            if t.is_empty() || !t.starts_with('<') {
                continue;
            }
            if t.starts_with("<?") {
                continue;
            }
            let xml_str = format!("<Event>{}</Event>", t);
            match xml_block_to_event(&xml_str, source_file) {
                Ok(ev) => events.push(ev),
                Err(e) => log::debug!("Skipping malformed XML line: {}", e),
            }
        }
    }
    Ok(events)
}

fn xml_block_to_event(xml: &str, source_file: &str) -> Result<Event> {
    let mut reader = Reader::from_str(xml);
    let mut map: HashMap<String, String> = HashMap::new();
    let mut current_key = String::new();
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(XmlEvent::Start(ref e)) => {
                current_key = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if current_key == "Data" {
                    for a in e.attributes().flatten() {
                        let akey = String::from_utf8_lossy(a.key.as_ref());
                        if akey == "Name" {
                            current_key = String::from_utf8_lossy(&a.value).to_string();
                            break;
                        }
                    }
                }
            }
            Ok(XmlEvent::Text(ref e)) => {
                let text = e.unescape().unwrap_or_default().to_string();
                let t = text.trim();
                if !current_key.is_empty() && !t.is_empty() {
                    map.insert(current_key.clone(), t.to_string());
                }
            }
            Ok(XmlEvent::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    let mut event = Event::new(source_file, SourceFormat::Xml);
    event.raw = xml.to_string();
    event.fields = map;
    event.fields.insert("_raw".to_string(), event.raw.clone());
    Ok(event)
}
