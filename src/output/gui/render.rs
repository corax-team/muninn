//! Full HTML report renderer.
//!
//! Single-file interactive SOC dashboard that integrates every analysis Muninn
//! can run. Sections render only when their backing data is non-empty.
//! CSS and JS are loaded from sibling files via `include_str!` so the same
//! source compiles identically on Linux and Windows.

use anyhow::Result;
use serde::Serialize;

use super::context::GuiReportContext;

const STYLES: &str = include_str!("styles.css");
const SCRIPT: &str = include_str!("script.js");

/// CDN URLs are kept stable for both `--gui` (default) and `--gui-cdn` paths.
/// Embedded mode is reserved for a future vendoring step that drops jQuery,
/// DataTables and vis-timeline into `vendor/` and inlines them via include_str!.
const ASSETS_CDN: &str = r#"<link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
<link rel="stylesheet" href="https://unpkg.com/vis-timeline@7.7.3/styles/vis-timeline-graph2d.min.css">
<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
<script src="https://unpkg.com/vis-timeline@7.7.3/standalone/umd/vis-timeline-graph2d.min.js"></script>"#;

#[derive(Serialize)]
struct VerdictView<'a> {
    verdict: &'a str,
    risk_score: f64,
    summary_text: &'a str,
    recommendations: &'a [String],
}

pub fn render(ctx: &GuiReportContext) -> Result<String> {
    let active_tabs = active_tabs(ctx);
    let data_json = build_data_json(ctx)?;
    let scan = &ctx.scan;
    let verdict_html = build_verdict_banner(ctx);
    let nav_html = build_nav(&active_tabs);
    let sections_html = build_sections(&active_tabs);
    let footer_html = build_footer(ctx);

    Ok(format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Muninn — Forensic Report</title>
{assets}
<style>
{styles}
</style>
</head>
<body>
{verdict}
<div class="header">
  <div>
    <div class="header-logo">MUNINN</div>
    <div class="header-sub">Memory of Corax &mdash; Forensic Detection Report</div>
  </div>
  <div class="header-meta">
    <span><b>v{version}</b></span>
    <span>{files} file(s) &middot; {events_total} events &middot; {events_hits} hits ({reduction:.2}% reduction)</span>
    <span>{ts_first} &mdash; {ts_last}</span>
  </div>
</div>
<div class="nav">
  {nav}
</div>
<div class="content">
  {sections}
</div>
<div class="modal-overlay" id="eventModal">
  <div class="modal">
    <div class="modal-header">
      <h3 id="modalTitle">Events</h3>
      <button class="modal-close" onclick="closeModal()">&times;</button>
    </div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>
{footer}

<script>
const DATA = {data};
{script}
</script>
</body>
</html>"##,
        assets = ASSETS_CDN,
        styles = STYLES,
        verdict = verdict_html,
        version = scan.muninn_version,
        files = scan.files_scanned,
        events_total = format_thousands(scan.total_events),
        events_hits = format_thousands(scan.events_with_hits),
        reduction = scan.reduction_pct,
        ts_first = scan.first_event_ts.as_deref().unwrap_or("(no timestamps)"),
        ts_last = scan.last_event_ts.as_deref().unwrap_or(""),
        nav = nav_html,
        sections = sections_html,
        footer = footer_html,
        data = data_json,
        script = SCRIPT,
    ))
}

#[derive(Clone, Copy)]
struct TabSpec {
    id: &'static str,
    label: &'static str,
    active: bool,
}

fn active_tabs(ctx: &GuiReportContext) -> Vec<TabSpec> {
    let mut tabs = vec![
        TabSpec {
            id: "dashboard",
            label: "Dashboard",
            active: true,
        },
        TabSpec {
            id: "detections",
            label: "Detections",
            active: !ctx.detections.is_empty(),
        },
        TabSpec {
            id: "timeline",
            label: "Timeline",
            active: !ctx.detections.is_empty(),
        },
        TabSpec {
            id: "mitre",
            label: "MITRE ATT&amp;CK",
            active: !ctx.detections.is_empty(),
        },
        TabSpec {
            id: "hosts",
            label: "Hosts",
            active: !ctx.computer_metrics.is_empty(),
        },
        TabSpec {
            id: "eids",
            label: "Event IDs",
            active: !ctx.eid_metrics.is_empty(),
        },
        TabSpec {
            id: "login",
            label: "Logon",
            active: ctx.login.is_some(),
        },
        TabSpec {
            id: "anomalies",
            label: "Anomalies",
            active: !ctx.anomalies.is_empty(),
        },
        TabSpec {
            id: "hunt",
            label: "Hunt",
            active: !ctx.hunt_findings.is_empty(),
        },
        TabSpec {
            id: "iocs",
            label: "IOCs",
            active: !ctx.iocs.is_empty(),
        },
        TabSpec {
            id: "chains",
            label: "Chains",
            active: !ctx.chains.is_empty(),
        },
    ];
    tabs.retain(|t| t.id == "dashboard" || t.active);
    tabs
}

fn build_nav(tabs: &[TabSpec]) -> String {
    tabs.iter()
        .enumerate()
        .map(|(i, t)| {
            let cls = if i == 0 { "nav-tab active" } else { "nav-tab" };
            format!(
                r#"<div class="{cls}" data-tab="{id}">{label}</div>"#,
                cls = cls,
                id = t.id,
                label = t.label
            )
        })
        .collect::<Vec<_>>()
        .join("\n  ")
}

fn build_sections(tabs: &[TabSpec]) -> String {
    tabs.iter()
        .enumerate()
        .map(|(i, t)| {
            let cls = if i == 0 { "section active" } else { "section" };
            let body = match t.id {
                "dashboard" => SEC_DASHBOARD,
                "detections" => SEC_DETECTIONS,
                "timeline" => SEC_TIMELINE,
                "mitre" => SEC_MITRE,
                "hosts" => SEC_HOSTS,
                "eids" => SEC_EIDS,
                "login" => SEC_LOGIN,
                "anomalies" => SEC_ANOMALIES,
                "hunt" => SEC_HUNT,
                "iocs" => SEC_IOCS,
                "chains" => SEC_CHAINS,
                _ => "",
            };
            format!(
                r#"<div class="{cls}" id="sec-{id}">{body}</div>"#,
                cls = cls,
                id = t.id,
                body = body
            )
        })
        .collect::<Vec<_>>()
        .join("\n  ")
}

fn build_verdict_banner(ctx: &GuiReportContext) -> String {
    let Some(s) = &ctx.summary else {
        return String::new();
    };
    let v = format!("{:?}", s.verdict);
    let css_class = match v.as_str() {
        "Clean" => "verdict-clean",
        "Suspicious" => "verdict-suspicious",
        "LikelyCompromised" => "verdict-likely",
        "ConfirmedBreach" => "verdict-confirmed",
        _ => "verdict-clean",
    };
    let label = match v.as_str() {
        "Clean" => "\u{2713} CLEAN",
        "Suspicious" => "\u{26A0} SUSPICIOUS",
        "LikelyCompromised" => "\u{26A0} LIKELY COMPROMISED",
        "ConfirmedBreach" => "\u{2717} CONFIRMED BREACH",
        _ => "—",
    };
    format!(
        r#"<div class="verdict-banner {cls}">
  <div class="verdict-label">{label}</div>
  <div class="verdict-score">Risk score: <b>{score:.1}</b> / 100</div>
  <div class="verdict-text">{text}</div>
</div>"#,
        cls = css_class,
        label = label,
        score = s.risk_score,
        text = html_escape(&s.summary_text),
    )
}

fn build_footer(ctx: &GuiReportContext) -> String {
    format!(
        r#"<div class="footer">
  Generated by <a href="https://github.com/corax-team/muninn">Muninn</a> v{version}
  &middot; Workers: {workers}
  &middot; Duration: {dur:.1}s
  &middot; Run: {ts}<br>
  Command: <code>{cmd}</code>
</div>"#,
        version = ctx.scan.muninn_version,
        workers = ctx.scan.workers,
        dur = ctx.scan.duration_sec,
        ts = html_escape(&ctx.scan.run_timestamp),
        cmd = html_escape(&ctx.scan.command_line),
    )
}

fn build_data_json(ctx: &GuiReportContext) -> Result<String> {
    let mut root = serde_json::Map::new();
    root.insert("scan".into(), serde_json::to_value(&ctx.scan)?);
    root.insert("detections".into(), serde_json::to_value(&ctx.detections)?);
    root.insert(
        "severity_rollup".into(),
        serde_json::to_value(&ctx.severity_rollup)?,
    );
    root.insert(
        "computer_metrics".into(),
        serde_json::to_value(&ctx.computer_metrics)?,
    );
    root.insert(
        "eid_metrics".into(),
        serde_json::to_value(&ctx.eid_metrics)?,
    );
    root.insert("killchain".into(), serde_json::to_value(&ctx.killchain)?);
    if let Some(ref login) = ctx.login {
        root.insert("login".into(), serde_json::to_value(login)?);
    }
    if let Some(ref summary) = ctx.summary {
        let verdict_dbg = format!("{:?}", summary.verdict);
        let v = VerdictView {
            verdict: variant_name(&verdict_dbg),
            risk_score: summary.risk_score,
            summary_text: &summary.summary_text,
            recommendations: &summary.recommendations,
        };
        root.insert("summary".into(), serde_json::to_value(&v)?);
        root.insert("summary_full".into(), serde_json::to_value(summary)?);
    }
    root.insert("anomalies".into(), serde_json::to_value(&ctx.anomalies)?);
    root.insert(
        "hunt_findings".into(),
        serde_json::to_value(&ctx.hunt_findings)?,
    );
    root.insert("iocs".into(), serde_json::to_value(&ctx.iocs)?);
    #[cfg(feature = "ioc-enrich")]
    {
        root.insert(
            "opentip".into(),
            serde_json::to_value(&ctx.opentip_results)?,
        );
        root.insert(
            "enriched_iocs".into(),
            serde_json::to_value(&ctx.enriched_iocs)?,
        );
    }
    root.insert("scores".into(), serde_json::to_value(&ctx.scores)?);
    root.insert("chains".into(), serde_json::to_value(&ctx.chains)?);
    root.insert("timeline".into(), serde_json::to_value(&ctx.timeline)?);
    Ok(serde_json::to_string(&serde_json::Value::Object(root))?)
}

fn variant_name(s: &str) -> &str {
    match s {
        "Clean" => "Clean",
        "Suspicious" => "Suspicious",
        "LikelyCompromised" => "Likely Compromised",
        "ConfirmedBreach" => "Confirmed Breach",
        _ => "—",
    }
}

fn format_thousands(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            out.insert(0, ',');
        }
        out.insert(0, c);
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

const SEC_DASHBOARD: &str = r#"
<div class="investigation-panel">
  <h3 class="invest-title">Investigation Summary</h3>
  <div id="investigationNarrative"></div>
</div>
<div class="dash-card key-findings-card">
  <h3>Key Findings <span class="muted">(auto-curated, low-noise)</span></h3>
  <div id="keyFindings"></div>
</div>
<div class="cards" id="summaryCards"></div>
<div class="sev-bar" id="sevBar"></div>
<div class="dashboard-grid">
  <div class="dash-card"><h3>Top Detections</h3><div id="topDetections"></div></div>
  <div class="dash-card"><h3>Top Hosts</h3><div id="topHosts"></div></div>
  <div class="dash-card"><h3>Top Event IDs</h3><div id="topEids"></div></div>
  <div class="dash-card" id="recCard" style="display:none"><h3>Recommendations</h3><div id="recList"></div></div>
  <div class="dash-card" id="authorsCard"><h3>Top Rule Authors</h3><div id="topAuthors"></div></div>
</div>
"#;

const SEC_DETECTIONS: &str = r#"
<div class="filter-bar">
  <select id="sevFilter" onchange="filterDetections()">
    <option value="">All Severities</option>
    <option value="critical">Critical</option>
    <option value="high">High</option>
    <option value="medium">Medium</option>
    <option value="low">Low</option>
    <option value="informational">Informational</option>
  </select>
  <select id="tacticFilter" onchange="filterDetections()"><option value="">All Tactics</option></select>
</div>
<table id="detectionsTable" class="display" style="width:100%">
  <thead><tr>
    <th>Severity</th><th>Rule</th><th>Description</th><th>Count</th>
    <th>Author</th><th>Techniques</th><th>Tags</th><th>Actions</th>
  </tr></thead><tbody></tbody>
</table>
"#;

const SEC_TIMELINE: &str = r#"
<div class="timeline-controls">
  <button class="btn btn-accent" onclick="tlFit()">Fit All</button>
  <button class="btn" onclick="tlZoomIn()">Zoom In</button>
  <button class="btn" onclick="tlZoomOut()">Zoom Out</button>
  <span class="timeline-hint">Click any item to view its events. Scroll to zoom, drag to pan.</span>
</div>
<div id="timeline"></div>
"#;

const SEC_MITRE: &str = r#"
<p class="section-lede">MITRE ATT&amp;CK coverage from detected techniques. Hover any cell for the rule list.</p>
<div class="mitre-matrix" id="mitreMatrix"></div>
"#;

const SEC_HOSTS: &str = r#"
<p class="section-lede">Hosts ranked by severity-weighted detection volume.</p>
<table id="hostsTable" class="display" style="width:100%">
  <thead><tr>
    <th>Computer</th><th>Events</th><th>Unique rules</th>
    <th class="sev-col critical">Critical</th>
    <th class="sev-col high">High</th>
    <th class="sev-col medium">Medium</th>
    <th class="sev-col low">Low</th>
    <th class="sev-col info">Info</th>
  </tr></thead><tbody></tbody>
</table>
"#;

const SEC_EIDS: &str = r#"
<p class="section-lede">Event IDs that fired at least one detection, ordered by frequency.</p>
<table id="eidsTable" class="display" style="width:100%">
  <thead><tr><th>Event ID</th><th>Channel</th><th>Total</th><th>With detection</th></tr></thead>
  <tbody></tbody>
</table>
"#;

const SEC_LOGIN: &str = r#"
<div class="cards" id="loginCards"></div>
<div class="dashboard-grid">
  <div class="dash-card"><h3>Brute Force Candidates</h3><div id="loginBrute"></div></div>
  <div class="dash-card"><h3>Lateral Movement</h3><div id="loginLateral"></div></div>
  <div class="dash-card"><h3>Privilege Escalation</h3><div id="loginPriv"></div></div>
  <div class="dash-card"><h3>Unusual Hours</h3><div id="loginUnusual"></div></div>
</div>
<div class="dashboard-grid">
  <div class="dash-card"><h3>Top Source IPs</h3><div id="loginSrc"></div></div>
  <div class="dash-card"><h3>Top Users</h3><div id="loginUsers"></div></div>
</div>
"#;

const SEC_ANOMALIES: &str = r#"
<p class="section-lede">Statistical anomalies detected in the dataset.</p>
<table id="anomaliesTable" class="display" style="width:100%">
  <thead><tr><th>Severity</th><th>Category</th><th>Description</th><th>Score</th><th>Evidence</th></tr></thead>
  <tbody></tbody>
</table>
"#;

const SEC_HUNT: &str = r#"
<p class="section-lede">Runtime hunt transforms that fired during streaming.</p>
<table id="huntTable" class="display" style="width:100%">
  <thead><tr><th>Severity</th><th>Transform</th><th>Description</th><th>Count</th><th>Tactic</th><th>Technique</th></tr></thead>
  <tbody></tbody>
</table>
"#;

const SEC_IOCS: &str = r#"
<div class="cards" id="iocCards"></div>
<div id="iocPanels"></div>
"#;

const SEC_CHAINS: &str = r#"
<p class="section-lede">Correlated attack chains (events linked by entity within proximity windows).</p>
<div id="chainsList"></div>
"#;
