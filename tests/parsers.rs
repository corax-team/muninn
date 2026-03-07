use muninn::model::SourceFormat;
use muninn::parsers;
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
fn test_parse_jsonl() {
    let data = r#"{"EventID":"1","CommandLine":"cmd.exe /c whoami","Image":"C:\\Windows\\System32\\cmd.exe"}
{"EventID":"4624","LogonType":"3","TargetUserName":"admin"}
"#;
    let f = temp_file("jsonl", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert_eq!(result.source_format, SourceFormat::JsonLines);
    assert_eq!(result.events.len(), 2);
    assert_eq!(result.events[0].get("EventID"), Some("1"));
    assert_eq!(
        result.events[0].get("CommandLine"),
        Some("cmd.exe /c whoami")
    );
    assert_eq!(result.events[1].get("TargetUserName"), Some("admin"));
}

#[test]
fn test_parse_json_array() {
    let data = r#"[
        {"EventID":"1","Image":"powershell.exe"},
        {"EventID":"3","DestinationIp":"10.0.0.1"}
    ]"#;
    let f = temp_file("json", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert_eq!(result.source_format, SourceFormat::JsonArray);
    assert_eq!(result.events.len(), 2);
    assert_eq!(result.events[0].get("Image"), Some("powershell.exe"));
}

#[test]
fn test_parse_csv() {
    let data = "EventID,Image,CommandLine\n1,cmd.exe,whoami\n4624,lsass.exe,\n";
    let f = temp_file("csv", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert_eq!(result.source_format, SourceFormat::Csv);
    assert_eq!(result.events.len(), 2);
    assert_eq!(result.events[0].get("EventID"), Some("1"));
    assert_eq!(result.events[0].get("Image"), Some("cmd.exe"));
    assert_eq!(result.events[0].get("CommandLine"), Some("whoami"));
}

#[test]
fn test_parse_syslog_rfc3164() {
    let data = "<34>Oct 11 22:14:15 mymachine su[234]: pam_unix: session opened for user root\n";
    let f = temp_file("log", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert_eq!(result.source_format, SourceFormat::Syslog);
    assert_eq!(result.events.len(), 1);
    let ev = &result.events[0];
    assert_eq!(ev.get("hostname"), Some("mymachine"));
    assert_eq!(ev.get("app_name"), Some("su"));
    assert_eq!(ev.get("procid"), Some("234"));
    assert_eq!(ev.get("priority"), Some("34"));
    assert_eq!(ev.get("facility"), Some("4"));
    assert_eq!(ev.get("severity"), Some("2"));
}

#[test]
fn test_parse_syslog_rfc5424() {
    let data = "<165>1 2023-08-11T22:14:15.003Z mymachine.example.com evntslog - ID47 - BOMAn application event\n";
    let f = temp_file("log", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert_eq!(result.source_format, SourceFormat::Syslog);
    assert_eq!(result.events.len(), 1);
    let ev = &result.events[0];
    assert_eq!(ev.get("hostname"), Some("mymachine.example.com"));
    assert_eq!(ev.get("app_name"), Some("evntslog"));
    assert_eq!(ev.get("version"), Some("1"));
    assert_eq!(ev.get("priority"), Some("165"));
}

#[test]
fn test_parse_cef() {
    let data = "CEF:0|Security|Firewall|1.0|100|Connection dropped|7|src=10.0.0.1 dst=192.168.1.1 spt=1234 dpt=80 proto=TCP\n";
    let f = temp_file("cef", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert_eq!(result.source_format, SourceFormat::Cef);
    assert_eq!(result.events.len(), 1);
    let ev = &result.events[0];
    assert_eq!(ev.get("DeviceVendor"), Some("Security"));
    assert_eq!(ev.get("DeviceProduct"), Some("Firewall"));
    assert_eq!(ev.get("Severity"), Some("7"));
    assert_eq!(ev.get("src"), Some("10.0.0.1"));
    assert_eq!(ev.get("dst"), Some("192.168.1.1"));
    assert_eq!(ev.get("dpt"), Some("80"));
}

#[test]
fn test_parse_leef() {
    let data = "LEEF:1.0|Vendor|Product|1.0|EventID1\tsrc=10.0.0.1\tdst=192.168.1.1\tsev=5\n";
    let f = temp_file("leef", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert_eq!(result.source_format, SourceFormat::Leef);
    assert_eq!(result.events.len(), 1);
    let ev = &result.events[0];
    assert_eq!(ev.get("DeviceVendor"), Some("Vendor"));
    assert_eq!(ev.get("src"), Some("10.0.0.1"));
    assert_eq!(ev.get("dst"), Some("192.168.1.1"));
}

#[test]
fn test_parse_w3c() {
    let data = r#"#Software: Microsoft Internet Information Services
#Version: 1.0
#Fields: date time s-ip cs-method cs-uri-stem sc-status sc-bytes
2023-10-01 12:00:00 192.168.1.1 GET /index.html 200 1234
2023-10-01 12:00:01 192.168.1.1 POST /api/login 401 567
"#;
    let f = temp_file("log", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert_eq!(result.source_format, SourceFormat::W3cExtended);
    assert_eq!(result.events.len(), 2);
    let ev = &result.events[0];
    assert_eq!(ev.get("cs-method"), Some("GET"));
    assert_eq!(ev.get("cs-uri-stem"), Some("/index.html"));
    assert_eq!(ev.get("sc-status"), Some("200"));
    assert_eq!(ev.get("timestamp"), Some("2023-10-01T12:00:00"));
}

#[test]
fn test_parse_zeek_dns() {
    let data = "#separator \\x09
#set_separator\t,
#empty_field\t(empty)
#unset_field\t-
#path\tdns
#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tqtype\trcode
#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tstring\tstring
1695000000.000000\tCtest123\t10.0.0.1\t12345\t8.8.8.8\t53\tudp\tevil.com\tA\tNOERROR
";
    let f = temp_file("log", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert_eq!(result.source_format, SourceFormat::ZeekTsv);
    assert_eq!(result.events.len(), 1);
    let ev = &result.events[0];
    assert_eq!(ev.get("query"), Some("evil.com"));
    assert_eq!(ev.get("id_orig_h"), Some("10.0.0.1"));
    assert_eq!(ev.get("_zeek_log_type"), Some("dns"));
}

#[test]
fn test_parse_auditd() {
    let data = r#"type=SYSCALL msg=audit(1631000000.000:100): arch=c000003e syscall=59 success=yes exit=0 a0=55b pid=12345 ppid=1234 uid=0 gid=0 euid=0 comm="bash" exe="/bin/bash"
type=EXECVE msg=audit(1631000000.000:100): argc=3 a0="bash" a1="-c" a2="whoami"
"#;
    let f = temp_file("log", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert_eq!(result.source_format, SourceFormat::Auditd);
    assert_eq!(result.events.len(), 2);
    assert_eq!(result.events[0].get("type"), Some("SYSCALL"));
    assert_eq!(result.events[0].get("comm"), Some("bash"));
    assert_eq!(result.events[0].get("exe"), Some("/bin/bash"));
    assert_eq!(result.events[1].get("type"), Some("EXECVE"));
    assert_eq!(result.events[1].get("a2"), Some("whoami"));
}

#[test]
fn test_parse_xml() {
    let data = r#"<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event><System><EventID>1</EventID><Channel>Sysmon</Channel></System><EventData><Data Name="CommandLine">cmd.exe /c whoami</Data><Data Name="Image">C:\Windows\System32\cmd.exe</Data></EventData></Event>
<Event><System><EventID>3</EventID><Channel>Sysmon</Channel></System><EventData><Data Name="DestinationIp">10.0.0.1</Data></EventData></Event>
</Events>"#;
    let f = temp_file("xml", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert!(
        result.source_format == SourceFormat::Xml
            || result.source_format == SourceFormat::SysmonLinux,
        "Expected Xml or SysmonLinux, got {:?}",
        result.source_format
    );
    assert!(result.events.len() >= 2);
    assert_eq!(
        result.events[0].get("CommandLine"),
        Some("cmd.exe /c whoami")
    );
    assert_eq!(result.events[0].get("EventID"), Some("1"));
}

#[test]
fn test_parse_apache_combined() {
    let data = r#"192.168.1.100 - admin [10/Oct/2023:13:55:36 -0700] "GET /admin/config HTTP/1.1" 200 5326
10.0.0.50 - - [10/Oct/2023:13:55:37 -0700] "POST /api/upload HTTP/1.1" 403 0
"#;
    let f = temp_file("txt", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert_eq!(result.source_format, SourceFormat::PlainText);
    assert_eq!(result.events.len(), 2);
    let ev = &result.events[0];
    assert_eq!(ev.get("c-ip"), Some("192.168.1.100"));
    assert_eq!(ev.get("cs-method"), Some("GET"));
    assert_eq!(ev.get("cs-uri-stem"), Some("/admin/config"));
    assert_eq!(ev.get("sc-status"), Some("200"));
}

#[test]
fn test_flatten_nested_event() {
    let data = r##"{"Event":{"System":{"EventID":1,"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"WORKSTATION01"},"EventData":{"Data":[{"@Name":"CommandLine","#text":"powershell.exe -enc ZQBj"},{"@Name":"Image","#text":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},{"@Name":"ParentImage","#text":"C:\\Windows\\explorer.exe"}]}}}
"##;
    let f = temp_file("json", data);
    let result = parsers::parse_file(f.path()).unwrap();
    assert_eq!(result.events.len(), 1);
    let ev = &result.events[0];
    assert_eq!(ev.get("CommandLine"), Some("powershell.exe -enc ZQBj"));
    assert_eq!(
        ev.get("Image"),
        Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
    );
    assert_eq!(ev.get("ParentImage"), Some("C:\\Windows\\explorer.exe"));
    assert_eq!(
        ev.get("Channel"),
        Some("Microsoft-Windows-Sysmon/Operational")
    );
}

#[test]
fn test_detect_format_jsonl() {
    let f = temp_file("json", r#"{"key":"value"}"#);
    assert_eq!(
        parsers::detect_format(f.path()).unwrap(),
        SourceFormat::JsonLines
    );
}

#[test]
fn test_detect_format_json_array() {
    let f = temp_file("json", r#"[{"key":"value"}]"#);
    assert_eq!(
        parsers::detect_format(f.path()).unwrap(),
        SourceFormat::JsonArray
    );
}

#[test]
fn test_detect_format_csv() {
    let f = temp_file("csv", "a,b,c\n1,2,3\n");
    assert_eq!(parsers::detect_format(f.path()).unwrap(), SourceFormat::Csv);
}

#[test]
fn test_detect_format_tsv() {
    let f = temp_file("log", "a\tb\tc\n1\t2\t3\n");
    assert_eq!(parsers::detect_format(f.path()).unwrap(), SourceFormat::Tsv);
}

#[test]
fn test_detect_format_syslog_rfc5424() {
    let f = temp_file(
        "log",
        "<165>1 2023-08-11T22:14:15.003Z host app - ID47 - msg\n",
    );
    assert_eq!(
        parsers::detect_format(f.path()).unwrap(),
        SourceFormat::Syslog
    );
}

#[test]
fn test_detect_format_syslog_bsd() {
    let f = temp_file(
        "log",
        "Oct 11 22:14:15 myhost sshd[1234]: Accepted publickey\n",
    );
    assert_eq!(
        parsers::detect_format(f.path()).unwrap(),
        SourceFormat::Syslog
    );
}

#[test]
fn test_detect_format_cef() {
    let f = temp_file("log", "CEF:0|Vendor|Product|1.0|100|Name|5|src=1.2.3.4\n");
    assert_eq!(parsers::detect_format(f.path()).unwrap(), SourceFormat::Cef);
}

#[test]
fn test_detect_format_leef() {
    let f = temp_file("log", "LEEF:1.0|Vendor|Product|1.0|Event\tsrc=1.2.3.4\n");
    assert_eq!(
        parsers::detect_format(f.path()).unwrap(),
        SourceFormat::Leef
    );
}

#[test]
fn test_detect_format_w3c() {
    let f = temp_file(
        "log",
        "#Fields: date time s-ip cs-method\n2023-01-01 00:00:00 1.2.3.4 GET\n",
    );
    assert_eq!(
        parsers::detect_format(f.path()).unwrap(),
        SourceFormat::W3cExtended
    );
}

#[test]
fn test_detect_format_zeek() {
    let f = temp_file("log", "#separator \\x09\n#fields\tts\tuid\n1234\tCabc\n");
    assert_eq!(
        parsers::detect_format(f.path()).unwrap(),
        SourceFormat::ZeekTsv
    );
}

#[test]
fn test_detect_format_auditd() {
    let f = temp_file("log", "type=SYSCALL msg=audit(1234.0:1): arch=c000003e\n");
    assert_eq!(
        parsers::detect_format(f.path()).unwrap(),
        SourceFormat::Auditd
    );
}

#[test]
fn test_detect_format_xml() {
    let f = temp_file(
        "xml",
        "<Events><Event><EventID>1</EventID></Event></Events>",
    );
    assert_eq!(parsers::detect_format(f.path()).unwrap(), SourceFormat::Xml);
}

#[test]
fn test_detect_format_plain_text() {
    let f = temp_file("txt", "Just a plain log line without any special format\n");
    assert_eq!(
        parsers::detect_format(f.path()).unwrap(),
        SourceFormat::PlainText
    );
}
