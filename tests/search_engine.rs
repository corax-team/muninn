use muninn::model::{Event, SourceFormat};
use muninn::search::SearchEngine;
use std::collections::HashMap;

fn make_event(fields: &[(&str, &str)]) -> Event {
    let mut event = Event::new("test.log", SourceFormat::JsonLines);
    for (k, v) in fields {
        event.set(*k, *v);
    }
    event.raw = serde_json::to_string(
        &fields
            .iter()
            .map(|(k, v)| (*k, *v))
            .collect::<HashMap<_, _>>(),
    )
    .unwrap();
    event.fields.insert("_raw".into(), event.raw.clone());
    event
}

#[test]
fn test_load_and_query_1000_events() {
    let mut engine = SearchEngine::new().unwrap();

    let events: Vec<Event> = (0..1000)
        .map(|i| {
            make_event(&[
                ("EventID", &format!("{}", i % 10)),
                (
                    "Image",
                    if i % 3 == 0 {
                        "cmd.exe"
                    } else {
                        "powershell.exe"
                    },
                ),
                ("CommandLine", &format!("command_{}", i)),
                ("User", if i % 5 == 0 { "admin" } else { "user" }),
            ])
        })
        .collect();

    let loaded = engine.load_events(&events).unwrap();
    assert_eq!(loaded, 1000);
    engine.create_indexes().unwrap();

    let result = engine
        .query_sql("SELECT * FROM events WHERE \"EventID\" = '1'")
        .unwrap();
    assert_eq!(result.count, 100);

    let result = engine.search_field("Image", "cmd.exe").unwrap();
    assert_eq!(result.count, 334);

    let result = engine.search_field("Image", "%powershell%").unwrap();
    assert_eq!(result.count, 666);

    let result = engine.search_keyword("command_42").unwrap();
    assert!(result.count >= 1);

    let result = engine.search_regex("CommandLine", r"command_4\d$").unwrap();
    assert!(result.count >= 10);
}

#[test]
fn test_incremental_load_different_schemas() {
    let mut engine = SearchEngine::new().unwrap();

    let events_a = vec![
        make_event(&[("EventID", "1"), ("Image", "cmd.exe")]),
        make_event(&[("EventID", "2"), ("Image", "notepad.exe")]),
    ];
    engine.load_events(&events_a).unwrap();
    assert_eq!(engine.event_count(), 2);

    let events_b = vec![
        make_event(&[("SourceIp", "10.0.0.1"), ("DestinationIp", "192.168.1.1")]),
        make_event(&[("SourceIp", "10.0.0.2"), ("DestinationIp", "172.16.0.1")]),
    ];
    engine.load_events(&events_b).unwrap();
    assert_eq!(engine.event_count(), 4);

    let r1 = engine.search_field("Image", "cmd.exe").unwrap();
    assert_eq!(r1.count, 1);

    let r2 = engine.search_field("SourceIp", "10.0.0.1").unwrap();
    assert_eq!(r2.count, 1);
}

#[test]
fn test_export_and_from_file() {
    let mut engine = SearchEngine::new().unwrap();
    let events = vec![
        make_event(&[("EventID", "1"), ("CommandLine", "whoami")]),
        make_event(&[("EventID", "4624"), ("LogonType", "3")]),
    ];
    engine.load_events(&events).unwrap();

    let tmp = tempfile::NamedTempFile::new().unwrap();
    engine.export_db(tmp.path()).unwrap();

    let engine2 = SearchEngine::from_file(tmp.path()).unwrap();
    assert_eq!(engine2.event_count(), 2);

    let result = engine2.search_field("CommandLine", "whoami").unwrap();
    assert_eq!(result.count, 1);
}

#[test]
fn test_distinct_values() {
    let mut engine = SearchEngine::new().unwrap();
    let events = vec![
        make_event(&[("EventID", "1")]),
        make_event(&[("EventID", "1")]),
        make_event(&[("EventID", "4624")]),
        make_event(&[("EventID", "4688")]),
    ];
    engine.load_events(&events).unwrap();

    let distinct = engine.distinct_values("EventID").unwrap();
    assert_eq!(distinct.len(), 3);
    assert!(distinct.contains(&"1".to_string()));
    assert!(distinct.contains(&"4624".to_string()));
    assert!(distinct.contains(&"4688".to_string()));
}

#[test]
fn test_stats() {
    let mut engine = SearchEngine::new().unwrap();
    let events = vec![
        make_event(&[("EventID", "1"), ("Image", "cmd.exe")]),
        make_event(&[("EventID", "2")]),
    ];
    engine.load_events(&events).unwrap();

    let stats = engine.stats().unwrap();
    assert_eq!(stats.total_events, 2);
    assert!(stats.total_fields > 0);
    assert_eq!(*stats.populated_fields.get("EventID").unwrap(), 2);
    assert_eq!(*stats.populated_fields.get("Image").unwrap(), 1);
}

#[test]
fn test_regexp_works() {
    let mut engine = SearchEngine::new().unwrap();
    let events = vec![
        make_event(&[("CommandLine", "powershell.exe -enc ZQBjAGgAbwA=")]),
        make_event(&[("CommandLine", "cmd.exe /c whoami")]),
        make_event(&[("CommandLine", "notepad.exe")]),
    ];
    engine.load_events(&events).unwrap();

    let result = engine
        .search_regex("CommandLine", r".*\-enc\s+[A-Za-z0-9+/=]+")
        .unwrap();
    assert_eq!(result.count, 1);

    let result2 = engine
        .search_regex("CommandLine", r"^(cmd|powershell)\.exe")
        .unwrap();
    assert_eq!(result2.count, 2);
}

#[test]
fn test_performance_100k_events() {
    let mut engine = SearchEngine::new().unwrap();
    let events: Vec<Event> = (0..100_000)
        .map(|i| {
            make_event(&[
                ("EventID", &format!("{}", i % 100)),
                ("Image", "svchost.exe"),
                ("CommandLine", &format!("cmd /c task_{}", i)),
            ])
        })
        .collect();

    let start = std::time::Instant::now();
    engine.load_events(&events).unwrap();
    let load_time = start.elapsed();

    assert!(
        load_time.as_secs() < 5,
        "Loading 100K events took {:?} (should be < 5s)",
        load_time
    );

    engine.create_indexes().unwrap();

    let result = engine
        .query_sql("SELECT * FROM events WHERE \"EventID\" = '42'")
        .unwrap();
    assert_eq!(result.count, 1000);
}

#[test]
fn test_run_queries_batch() {
    let mut engine = SearchEngine::new().unwrap();
    let events = vec![
        make_event(&[("EventID", "1"), ("CommandLine", "whoami")]),
        make_event(&[("EventID", "1"), ("CommandLine", "ipconfig")]),
        make_event(&[("EventID", "4624"), ("LogonType", "3")]),
    ];
    engine.load_events(&events).unwrap();

    let queries = vec![
        (
            "whoami_detect",
            "SELECT * FROM events WHERE \"CommandLine\" LIKE '%whoami%'",
        ),
        (
            "logon_detect",
            "SELECT * FROM events WHERE \"EventID\" = '4624'",
        ),
        (
            "no_match",
            "SELECT * FROM events WHERE \"EventID\" = '9999'",
        ),
    ];
    let results = engine.run_queries(&queries);
    assert_eq!(results.len(), 2);
    assert!(results.iter().any(|(l, _)| l == "whoami_detect"));
    assert!(results.iter().any(|(l, _)| l == "logon_detect"));
}

#[test]
fn test_lightweight_engine_equivalent_queries() {
    // Lightweight engine must produce identical results to full engine
    let events: Vec<Event> = (0..10_000)
        .map(|i| {
            make_event(&[
                ("EventID", &format!("{}", i % 10)),
                ("Image", if i % 3 == 0 { "cmd.exe" } else { "svchost.exe" }),
                ("CommandLine", &format!("task_{}", i)),
            ])
        })
        .collect();

    let mut full = SearchEngine::new().unwrap();
    full.load_events(&events).unwrap();
    full.create_indexes().unwrap();

    let mut light = SearchEngine::new_lightweight().unwrap();
    light.load_events(&events).unwrap();
    light.create_indexes().unwrap();

    // Same event count
    assert_eq!(full.event_count(), light.event_count());

    // Same SQL query results
    let sql = "SELECT * FROM events WHERE \"EventID\" = '5'";
    let r_full = full.query_sql(sql).unwrap();
    let r_light = light.query_sql(sql).unwrap();
    assert_eq!(r_full.count, r_light.count);
    assert_eq!(r_full.count, 1000);

    // Same field search
    let r_full = full.search_field("Image", "cmd.exe").unwrap();
    let r_light = light.search_field("Image", "cmd.exe").unwrap();
    assert_eq!(r_full.count, r_light.count);

    // Same regex search
    let r_full = full.search_regex("CommandLine", r"task_4\d$").unwrap();
    let r_light = light.search_regex("CommandLine", r"task_4\d$").unwrap();
    assert_eq!(r_full.count, r_light.count);
}
