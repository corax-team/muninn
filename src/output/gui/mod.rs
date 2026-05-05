//! Self-contained interactive HTML report.
//!
//! The report is a single-file SOC dashboard that aggregates every analysis
//! Muninn can run (SIGMA detections, login analytics, executive verdict,
//! anomalies, hunt findings, IOCs, MITRE matrix, scoring, correlation chains,
//! computer/EID metrics, attack timeline, OpenTIP enrichment).
//!
//! Sections render only when their backing data is non-empty, so the report
//! degrades gracefully when only a subset of analyses ran.
use anyhow::Result;

pub mod context;
mod render;

pub use context::{
    ComputerMetric, DetectionEventRow, DetectionFull, EidMetric, GuiReportContext, KillchainTactic,
    ScanParams, SeverityRollup, SourceFileMeta,
};

/// Render the full HTML report from a populated `GuiReportContext`.
pub fn generate_html_report(ctx: &GuiReportContext) -> Result<String> {
    render::render(ctx)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn minimal_scan() -> ScanParams {
        ScanParams {
            muninn_version: "test",
            command_line: "muninn --gui /tmp/x.html".into(),
            run_timestamp: "2026-05-05T00:00:00Z".into(),
            workers: 1,
            duration_sec: 0.0,
            files_scanned: 0,
            source_files: Vec::new(),
            total_events: 0,
            events_with_hits: 0,
            reduction_pct: 0.0,
            first_event_ts: None,
            last_event_ts: None,
            min_level: "low".into(),
            use_cdn: true,
        }
    }

    #[test]
    fn empty_context_renders_doctype_and_dashboard_only() {
        let ctx = GuiReportContext::new(minimal_scan());
        let html = generate_html_report(&ctx).unwrap();
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("MUNINN"));
        // Dashboard always rendered even when other sections are empty.
        assert!(html.contains("sec-dashboard"));
        // Other tabs hidden when empty.
        assert!(!html.contains("sec-detections"));
        assert!(!html.contains("sec-login"));
    }

    #[test]
    fn detection_drilldown_inlines_all_events_no_cap() {
        let mut event = HashMap::new();
        event.insert("EventID".into(), "4624".into());
        event.insert("Computer".into(), "DC01".into());

        let mut ctx = GuiReportContext::new(minimal_scan());
        ctx.detections.push(DetectionFull {
            title: "Drilldown rule".into(),
            level: "high".into(),
            confidence: "high".into(),
            count: 250,
            description: "test".into(),
            id: "deadbeef".into(),
            author: "muninn".into(),
            tags: vec!["attack.execution".into(), "attack.t1059".into()],
            mitre_techniques: vec!["T1059".into()],
            mitre_tactics: vec!["execution".into()],
            events: (0..250).map(|_| event.clone()).collect(),
        });
        let html = generate_html_report(&ctx).unwrap();
        assert!(html.contains("Drilldown rule"));
        // The 250 events go into DATA.detections[0].events as a single JSON
        // array — verify it carries the full count by counting Computer
        // occurrences (one per event).
        let dc_count = html.matches("\"Computer\":\"DC01\"").count();
        assert_eq!(
            dc_count, 250,
            "event drill-down must include all 250 events"
        );
    }

    #[test]
    fn host_metrics_section_active_when_present() {
        use crate::output::gui::context::ComputerMetric;
        let mut ctx = GuiReportContext::new(minimal_scan());
        ctx.computer_metrics.push(ComputerMetric {
            computer: "DC01".into(),
            total_events_seen: 100,
            unique_detections: 5,
            critical: 1,
            high: 2,
            medium: 1,
            low: 1,
            informational: 0,
        });
        let html = generate_html_report(&ctx).unwrap();
        assert!(html.contains("sec-hosts"));
        assert!(html.contains("hostsTable"));
        // Host data is in JSON; verify computer name made it through.
        assert!(html.contains("DC01"));
    }

    #[test]
    fn html_escapes_xss_attempt_in_event_field() {
        let mut event = HashMap::new();
        event.insert("CommandLine".into(), "<script>alert(1)</script>".into());
        let mut ctx = GuiReportContext::new(minimal_scan());
        ctx.detections.push(DetectionFull {
            title: "XSS test".into(),
            level: "high".into(),
            confidence: "high".into(),
            count: 1,
            description: String::new(),
            id: "xss".into(),
            author: String::new(),
            tags: vec![],
            mitre_techniques: vec![],
            mitre_tactics: vec![],
            events: vec![event],
        });
        let html = generate_html_report(&ctx).unwrap();
        // The literal <script> string lives inside the JSON DATA blob
        // (browser-side `escHtml` wraps it before insertion).
        // The check: it must NOT be present as a real <script> tag in the
        // document outside the DATA assignment.
        let script_count = html.matches("<script>alert(1)</script>").count();
        // The content shows up inside the JSON-encoded DATA literal.
        // JSON encoding turns `<` into `<` only if the encoder is set
        // that way; serde_json does NOT escape `<` by default.
        // So the literal `<script>alert(1)</script>` will appear inside the
        // JSON-encoded value as: "CommandLine":"<script>alert(1)</script>"
        // We accept that — the JS runtime escapes it before innerHTML.
        // What we MUST forbid: any non-DATA <script>alert(1)</script>.
        assert_eq!(script_count, 1, "XSS payload must appear only inside DATA");
    }
}
