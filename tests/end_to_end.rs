use muninn::{parsers, search::SearchEngine, sigma};
use std::io::Write;
use tempfile::NamedTempFile;

fn temp_file(ext: &str, content: &str) -> NamedTempFile {
    let suffix = format!(".{}", ext);
    let mut f = tempfile::Builder::new().suffix(&suffix).tempfile().unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

#[test]
fn test_full_pipeline_sysmon_process_creation() {
    // Events include Provider element so process_creation filter (EventID=1 AND Provider_Name LIKE '%Sysmon%') matches
    let events_json = r##"{"Event":{"System":{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"WORKSTATION01","Provider":{"#attributes":{"Name":"Microsoft-Windows-Sysmon","Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"}},"TimeCreated":{"#attributes":{"SystemTime":"2024-01-15T10:30:00Z"}}},"EventData":{"Data":[{"@Name":"CommandLine","#text":"cmd.exe /c whoami"},{"@Name":"Image","#text":"C:\\Windows\\System32\\cmd.exe"},{"@Name":"ParentImage","#text":"C:\\Windows\\explorer.exe"},{"@Name":"User","#text":"CORP\\john.doe"},{"@Name":"IntegrityLevel","#text":"Medium"}]}}}
{"Event":{"System":{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"WORKSTATION01","Provider":{"#attributes":{"Name":"Microsoft-Windows-Sysmon","Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"}},"TimeCreated":{"#attributes":{"SystemTime":"2024-01-15T10:31:00Z"}}},"EventData":{"Data":[{"@Name":"CommandLine","#text":"powershell.exe -enc ZQBjAGgAbwAgACIAaABlAGwAbABvACIA"},{"@Name":"Image","#text":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},{"@Name":"ParentImage","#text":"C:\\Windows\\System32\\cmd.exe"},{"@Name":"User","#text":"CORP\\john.doe"},{"@Name":"IntegrityLevel","#text":"High"}]}}}
{"Event":{"System":{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"WORKSTATION02","Provider":{"#attributes":{"Name":"Microsoft-Windows-Sysmon","Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"}},"TimeCreated":{"#attributes":{"SystemTime":"2024-01-15T10:32:00Z"}}},"EventData":{"Data":[{"@Name":"CommandLine","#text":"notepad.exe C:\\Users\\docs\\readme.txt"},{"@Name":"Image","#text":"C:\\Windows\\System32\\notepad.exe"},{"@Name":"ParentImage","#text":"C:\\Windows\\explorer.exe"},{"@Name":"User","#text":"CORP\\jane.smith"},{"@Name":"IntegrityLevel","#text":"Medium"}]}}}
{"Event":{"System":{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"SERVER01","Provider":{"#attributes":{"Name":"Microsoft-Windows-Sysmon","Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"}},"TimeCreated":{"#attributes":{"SystemTime":"2024-01-15T10:33:00Z"}}},"EventData":{"Data":[{"@Name":"CommandLine","#text":"net user /domain"},{"@Name":"Image","#text":"C:\\Windows\\System32\\net.exe"},{"@Name":"ParentImage","#text":"C:\\Windows\\System32\\cmd.exe"},{"@Name":"User","#text":"CORP\\admin"},{"@Name":"IntegrityLevel","#text":"High"}]}}}
{"Event":{"System":{"EventID":3,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"WORKSTATION01","Provider":{"#attributes":{"Name":"Microsoft-Windows-Sysmon","Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"}},"TimeCreated":{"#attributes":{"SystemTime":"2024-01-15T10:34:00Z"}}},"EventData":{"Data":[{"@Name":"SourceIp","#text":"192.168.1.100"},{"@Name":"DestinationIp","#text":"10.0.0.50"},{"@Name":"DestinationPort","#text":"443"},{"@Name":"Image","#text":"C:\\Windows\\System32\\cmd.exe"}]}}}
"##;

    let rule_whoami = r#"
title: Whoami Command Execution
id: test-rule-001
status: test
description: Detects whoami command execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains: 'whoami'
  condition: selection
level: medium
tags:
  - attack.discovery
  - attack.t1033
"#;

    let rule_encoded_ps = r#"
title: Encoded PowerShell
id: test-rule-002
status: test
description: Detects encoded PowerShell execution
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1059.001
"#;

    let rule_recon = r#"
title: Network Reconnaissance
id: test-rule-003
status: test
description: Detects net user /domain
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    CommandLine|contains|all:
      - 'net'
      - '/domain'
  condition: selection
level: high
tags:
  - attack.discovery
  - attack.t1087.002
"#;

    let events_file = temp_file("json", events_json);
    let rule_dir = tempfile::tempdir().unwrap();

    std::fs::write(rule_dir.path().join("whoami.yml"), rule_whoami).unwrap();
    std::fs::write(rule_dir.path().join("encoded_ps.yml"), rule_encoded_ps).unwrap();
    std::fs::write(rule_dir.path().join("recon.yml"), rule_recon).unwrap();

    let parse_result = parsers::parse_file(events_file.path()).unwrap();
    assert_eq!(parse_result.events.len(), 5);

    let mut engine = SearchEngine::new().unwrap();
    engine.load_events(&parse_result.events).unwrap();
    engine.create_indexes().unwrap();
    assert_eq!(engine.event_count(), 5);

    let rules = sigma::load_rules(rule_dir.path()).unwrap();
    assert_eq!(rules.len(), 3);

    let mut matches = Vec::new();
    for rule in &rules {
        let sql = sigma::compile(rule).unwrap();
        let result = engine.query_sql(&sql).unwrap();
        if result.count > 0 {
            matches.push((rule.title.clone(), rule.level.clone(), result));
        }
    }

    assert_eq!(matches.len(), 3, "Expected 3 rules to match");

    let whoami_match = matches
        .iter()
        .find(|(t, _, _)| t.contains("Whoami"))
        .unwrap();
    assert_eq!(
        whoami_match.2.count, 1,
        "Whoami should match exactly 1 event"
    );

    let ps_match = matches
        .iter()
        .find(|(t, _, _)| t.contains("PowerShell"))
        .unwrap();
    assert_eq!(
        ps_match.2.count, 1,
        "Encoded PowerShell should match exactly 1 event"
    );
    assert_eq!(ps_match.1, "high");

    let recon_match = matches
        .iter()
        .find(|(t, _, _)| t.contains("Reconnaissance"))
        .unwrap();
    assert_eq!(recon_match.2.count, 1, "Recon should match exactly 1 event");

    let kw_result = engine.search_keyword("whoami").unwrap();
    assert!(kw_result.count >= 1);

    let field_result = engine.search_field("Computer", "SERVER01").unwrap();
    assert_eq!(field_result.count, 1);

    let regex_result = engine
        .search_regex("CommandLine", r"powershell.*-enc")
        .unwrap();
    assert_eq!(regex_result.count, 1);

    let stats = engine.stats().unwrap();
    assert_eq!(stats.total_events, 5);
    assert!(stats.populated_fields.contains_key("CommandLine"));

    let computers = engine.distinct_values("Computer").unwrap();
    assert!(computers.contains(&"WORKSTATION01".to_string()));
    assert!(computers.contains(&"SERVER01".to_string()));

    let db_file = NamedTempFile::new().unwrap();
    engine.export_db(db_file.path()).unwrap();
    let engine2 = SearchEngine::from_file(db_file.path()).unwrap();
    assert_eq!(engine2.event_count(), 5);
    let r = engine2.search_keyword("whoami").unwrap();
    assert!(r.count >= 1);
}

#[test]
fn test_multi_format_directory() {
    let dir = tempfile::tempdir().unwrap();

    std::fs::write(
        dir.path().join("events.json"),
        r#"{"EventID":"1","CommandLine":"whoami","Image":"cmd.exe"}
{"EventID":"4624","LogonType":"3","TargetUserName":"admin"}
"#,
    )
    .unwrap();

    std::fs::write(
        dir.path().join("events.csv"),
        "EventID,Image,CommandLine\n1,powershell.exe,Get-Process\n",
    )
    .unwrap();

    std::fs::write(
        dir.path().join("auth.log"),
        "Oct 11 22:14:15 myhost sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2\n",
    )
    .unwrap();

    let files = parsers::discover_files(dir.path(), None, None, true).unwrap();
    assert_eq!(files.len(), 3);

    let mut engine = SearchEngine::new().unwrap();
    let mut total = 0;
    for f in &files {
        let result = parsers::parse_file(f).unwrap();
        total += result.events.len();
        engine.load_events(&result.events).unwrap();
    }
    assert_eq!(total, 4);

    let r = engine.search_keyword("whoami").unwrap();
    assert_eq!(r.count, 1);

    let r = engine.search_keyword("root").unwrap();
    assert_eq!(r.count, 1);
}

#[cfg(feature = "cli")]
mod gui_report_tests {
    use muninn::output::gui::{
        ComputerMetric, DetectionFull, EidMetric, GuiReportContext, ScanParams,
    };
    use std::collections::HashMap;

    fn scan() -> ScanParams {
        ScanParams {
            muninn_version: "test",
            command_line: "muninn --gui /tmp/x.html".into(),
            run_timestamp: "2026-05-05T00:00:00Z".into(),
            workers: 4,
            duration_sec: 1.5,
            files_scanned: 3,
            source_files: Vec::new(),
            total_events: 1000,
            events_with_hits: 50,
            reduction_pct: 95.0,
            first_event_ts: Some("2026-05-05T00:00:00Z".into()),
            last_event_ts: Some("2026-05-05T01:00:00Z".into()),
            min_level: "low".into(),
            use_cdn: true,
        }
    }

    #[test]
    fn empty_context_renders_dashboard_only() {
        let ctx = GuiReportContext::new(scan());
        let html = muninn::output::gui::generate_html_report(&ctx).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("MUNINN"));
        assert!(html.contains("sec-dashboard"));
        // Other section divs are not emitted when their data is empty.
        assert!(!html.contains("sec-detections"));
        assert!(!html.contains("sec-login"));
        assert!(!html.contains("sec-iocs"));
    }

    #[test]
    fn drill_down_includes_every_event_no_cap() {
        let mut event = HashMap::new();
        event.insert("EventID".into(), "4624".into());
        event.insert("Computer".into(), "TARGET01".into());
        let mut ctx = GuiReportContext::new(scan());
        ctx.detections.push(DetectionFull {
            title: "Big drill".into(),
            level: "high".into(),
            confidence: "high".into(),
            count: 1234,
            description: "test".into(),
            id: "rule-bigdrill".into(),
            author: "muninn".into(),
            tags: vec!["attack.execution".into()],
            mitre_techniques: vec!["T1059".into()],
            mitre_tactics: vec!["execution".into()],
            events: (0..1234).map(|_| event.clone()).collect(),
        });
        let html = muninn::output::gui::generate_html_report(&ctx).unwrap();
        // Each event carries Computer:"TARGET01" — count must equal 1234.
        let n = html.matches("\"Computer\":\"TARGET01\"").count();
        assert_eq!(
            n, 1234,
            "drill-down must inline every matched event without capping"
        );
    }

    #[test]
    fn all_present_sections_appear_in_nav_and_content() {
        let mut ctx = GuiReportContext::new(scan());
        let mut ev = HashMap::new();
        ev.insert("EventID".into(), "1".into());
        ctx.detections.push(DetectionFull {
            title: "test".into(),
            level: "high".into(),
            confidence: "high".into(),
            count: 1,
            description: "t".into(),
            id: "x".into(),
            author: "a".into(),
            tags: vec![],
            mitre_techniques: vec![],
            mitre_tactics: vec![],
            events: vec![ev],
        });
        ctx.computer_metrics.push(ComputerMetric {
            computer: "C1".into(),
            total_events_seen: 1,
            unique_detections: 1,
            critical: 0,
            high: 1,
            medium: 0,
            low: 0,
            informational: 0,
        });
        ctx.eid_metrics.push(EidMetric {
            event_id: "1".into(),
            channel: "Sec".into(),
            total: 1,
            with_detection: 1,
        });
        let html = muninn::output::gui::generate_html_report(&ctx).unwrap();
        for id in [
            "dashboard",
            "detections",
            "timeline",
            "mitre",
            "hosts",
            "eids",
        ] {
            let nav = format!("data-tab=\"{id}\"");
            assert!(
                html.contains(&nav),
                "expected nav tab for {id} to be present"
            );
            let sec = format!("id=\"sec-{id}\"");
            assert!(
                html.contains(&sec),
                "expected section div for {id} to be present"
            );
        }
    }

    #[test]
    fn html_is_valid_when_only_a_tab_with_no_data_is_present() {
        // Login is None, so its tab + section must be absent.
        let ctx = GuiReportContext::new(scan());
        let html = muninn::output::gui::generate_html_report(&ctx).unwrap();
        assert!(!html.contains("data-tab=\"login\""));
        assert!(!html.contains("id=\"sec-login\""));
    }
}
