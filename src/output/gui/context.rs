//! Aggregated data context for the HTML report.
//!
//! Every analysis Muninn can run feeds into a single `GuiReportContext` that
//! the HTML generator consumes. Optional analyses default to empty Vecs or
//! `None`, so the report renders cleanly even when only a subset of flags
//! were used.

use serde::Serialize;
use std::collections::HashMap;

pub type DetectionEventRow = HashMap<String, String>;

/// One SIGMA detection with full event drill-down (no event cap).
#[derive(Debug, Clone, Serialize)]
pub struct DetectionFull {
    pub title: String,
    pub level: String,
    pub confidence: String,
    pub count: usize,
    pub description: String,
    pub id: String,
    pub author: String,
    pub tags: Vec<String>,
    pub mitre_techniques: Vec<String>,
    pub mitre_tactics: Vec<String>,
    pub events: Vec<DetectionEventRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComputerMetric {
    pub computer: String,
    pub total_events_seen: usize,
    pub unique_detections: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EidMetric {
    pub event_id: String,
    pub channel: String,
    pub total: usize,
    pub with_detection: usize,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SeverityRollup {
    pub total: usize,
    pub unique: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SourceFileMeta {
    pub path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanParams {
    pub muninn_version: &'static str,
    pub command_line: String,
    pub run_timestamp: String,
    pub workers: usize,
    pub duration_sec: f64,
    pub files_scanned: usize,
    pub source_files: Vec<SourceFileMeta>,
    pub total_events: usize,
    pub events_with_hits: usize,
    pub reduction_pct: f64,
    pub first_event_ts: Option<String>,
    pub last_event_ts: Option<String>,
    pub min_level: String,
    pub use_cdn: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct KillchainTactic {
    pub tactic_slug: String,
    pub tactic_display: String,
    pub detections: Vec<(String, String, usize)>,
    pub max_severity: String,
}

/// Top-level aggregator; every section module reads from this.
pub struct GuiReportContext {
    pub scan: ScanParams,
    pub detections: Vec<DetectionFull>,
    pub severity_rollup: HashMap<String, SeverityRollup>,
    pub login: Option<crate::login::LoginAnalysis>,
    pub summary: Option<crate::summary::ExecutiveSummary>,
    pub anomalies: Vec<crate::anomaly::Anomaly>,
    pub hunt_findings: Vec<crate::hunt::HuntFindingSummary>,
    pub iocs: Vec<crate::ioc::Ioc>,
    pub scores: Vec<crate::scoring::ThreatScore>,
    pub chains: Vec<crate::correlate::AttackChain>,
    pub timeline: Vec<crate::timeline::TimelineEntry>,
    pub computer_metrics: Vec<ComputerMetric>,
    pub eid_metrics: Vec<EidMetric>,
    pub killchain: Vec<KillchainTactic>,
    #[cfg(feature = "ioc-enrich")]
    pub enriched_iocs: Vec<crate::ioc::EnrichedIoc>,
    #[cfg(feature = "ioc-enrich")]
    pub opentip_results: Vec<crate::opentip::OpenTipResult>,
}

impl GuiReportContext {
    pub fn new(scan: ScanParams) -> Self {
        Self {
            scan,
            detections: Vec::new(),
            severity_rollup: HashMap::new(),
            login: None,
            summary: None,
            anomalies: Vec::new(),
            hunt_findings: Vec::new(),
            iocs: Vec::new(),
            scores: Vec::new(),
            chains: Vec::new(),
            timeline: Vec::new(),
            computer_metrics: Vec::new(),
            eid_metrics: Vec::new(),
            killchain: Vec::new(),
            #[cfg(feature = "ioc-enrich")]
            enriched_iocs: Vec::new(),
            #[cfg(feature = "ioc-enrich")]
            opentip_results: Vec::new(),
        }
    }
}

/// One renderable section emitted by sec_*.rs modules.
#[allow(dead_code)] // populated by sec_*.rs in later steps
pub(crate) struct SectionFragment {
    pub nav_label: &'static str,
    pub nav_id: &'static str,
    pub html: String,
    pub style: String,
    pub script: String,
}
