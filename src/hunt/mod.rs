pub mod commandline;
pub mod dns;
pub mod file_access;
pub mod image;
pub mod parent;
pub mod registry;
pub mod tactic;

use crate::search::SearchEngine;
use crate::transforms::Transform;
use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;
use std::fmt;

// ── Hunt categories ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HuntCategory {
    CommandLine,
    Image,
    Parent,
    Registry,
    FileAccess,
    Tactic,
    Dns,
}

impl HuntCategory {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "commandline" | "cmd" => Some(Self::CommandLine),
            "image" | "process" => Some(Self::Image),
            "parent" => Some(Self::Parent),
            "registry" | "reg" => Some(Self::Registry),
            "file" | "fileaccess" | "file_access" => Some(Self::FileAccess),
            "tactic" | "tactics" => Some(Self::Tactic),
            "dns" => Some(Self::Dns),
            "all" => None, // special: means all categories
            _ => None,
        }
    }

    pub fn all() -> &'static [HuntCategory] {
        &[
            Self::CommandLine,
            Self::Image,
            Self::Parent,
            Self::Registry,
            Self::FileAccess,
            Self::Tactic,
            Self::Dns,
        ]
    }
}

// ── Hunt severity ──────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum HuntSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for HuntSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ── Hunt finding ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct HuntFindingSummary {
    pub transform: String,
    pub severity: HuntSeverity,
    pub description: String,
    pub count: usize,
    pub mitre_technique: String,
    pub mitre_tactic: String,
}

// ── Helper: write a hunt finding field ─────────────────────────────

pub fn set_hunt_finding(
    fields: &mut HashMap<String, String>,
    transform: &str,
    severity: HuntSeverity,
    description: &str,
) {
    let finding = format!("{}:{}:{}", transform, severity, description);
    // Append to existing findings (multiple transforms can fire on same event)
    if let Some(existing) = fields.get("hunt_finding") {
        fields.insert("hunt_finding".into(), format!("{}|{}", existing, finding));
    } else {
        fields.insert("hunt_finding".into(), finding);
    }
}

// ── Factory: build hunt transforms by category ─────────────────────

pub fn hunt_transforms(
    categories: Option<&[HuntCategory]>,
    fast_mode: bool,
) -> Vec<Box<dyn Transform>> {
    let cats = categories.unwrap_or(HuntCategory::all());
    let mut transforms: Vec<Box<dyn Transform>> = Vec::new();

    for cat in cats {
        match cat {
            HuntCategory::Image => {
                if !fast_mode {
                    transforms.push(Box::new(image::ProcessTyposquatting));
                }
                transforms.push(Box::new(image::ProcessMasquerade));
                transforms.push(Box::new(image::ProcessPathAnomaly));
                transforms.push(Box::new(image::DoubleExtension));
            }
            HuntCategory::CommandLine => {
                transforms.push(Box::new(commandline::C2FrameworkIndicator));
                transforms.push(Box::new(commandline::DownloadCradleDetector));
                transforms.push(Box::new(commandline::CredentialExtraction));
                transforms.push(Box::new(commandline::ShellcodeIndicator));
                transforms.push(Box::new(commandline::PowerShellReflection));
                transforms.push(Box::new(commandline::CommandDeobfuscator));
            }
            HuntCategory::Parent => {
                transforms.push(Box::new(parent::ParentProcessAnomaly));
            }
            HuntCategory::Registry => {
                transforms.push(Box::new(registry::SuspiciousRegistryPath));
            }
            HuntCategory::FileAccess => {
                transforms.push(Box::new(file_access::SensitiveFileAccess));
            }
            HuntCategory::Tactic => {
                transforms.push(Box::new(tactic::LateralMovementIndicator));
                transforms.push(Box::new(tactic::PersistenceClassifier));
                transforms.push(Box::new(tactic::ReconIndicator));
                transforms.push(Box::new(tactic::DataStagingDetector));
            }
            HuntCategory::Dns => {
                transforms.push(Box::new(dns::DnsSubdomainAnalysis));
            }
        }
    }

    transforms
}

// ── Collect findings from SQLite ───────────────────────────────────

pub fn collect_hunt_findings(engine: &SearchEngine) -> Result<Vec<HuntFindingSummary>> {
    if !engine.fields().iter().any(|f| f == "hunt_finding") {
        return Ok(Vec::new());
    }

    let result = engine.query_sql(
        "SELECT \"hunt_finding\", COUNT(*) as cnt \
         FROM \"events\" \
         WHERE \"hunt_finding\" IS NOT NULL AND \"hunt_finding\" != '' \
         GROUP BY \"hunt_finding\" \
         ORDER BY cnt DESC",
    )?;

    let mut findings: Vec<HuntFindingSummary> = Vec::new();

    for row in &result.rows {
        let raw = match row.get("hunt_finding") {
            Some(v) => v,
            None => continue,
        };
        let count: usize = row.get("cnt").and_then(|c| c.parse().ok()).unwrap_or(1);

        // Each finding can contain multiple pipe-delimited entries
        for entry in raw.split('|') {
            let parts: Vec<&str> = entry.splitn(3, ':').collect();
            if parts.len() < 3 {
                continue;
            }
            let transform = parts[0].to_string();
            let severity = match parts[1] {
                "critical" => HuntSeverity::Critical,
                "high" => HuntSeverity::High,
                "medium" => HuntSeverity::Medium,
                "low" => HuntSeverity::Low,
                _ => HuntSeverity::Info,
            };
            let description = parts[2].to_string();

            // Merge with existing or add new
            if let Some(existing) = findings
                .iter_mut()
                .find(|f| f.transform == transform && f.description == description)
            {
                existing.count += count;
            } else {
                let (tactic, technique) = mitre_for_transform(&transform);
                findings.push(HuntFindingSummary {
                    transform,
                    severity,
                    description,
                    count,
                    mitre_technique: technique.into(),
                    mitre_tactic: tactic.into(),
                });
            }
        }
    }

    // Sort: critical first, then by count
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.count.cmp(&a.count)));
    Ok(findings)
}

fn mitre_for_transform(transform: &str) -> (&'static str, &'static str) {
    match transform {
        "ProcessTyposquatting" => ("defense-evasion", "T1036.004"),
        "ProcessMasquerade" => ("defense-evasion", "T1036.005"),
        "ProcessPathAnomaly" => ("execution", "T1204"),
        "DoubleExtension" => ("defense-evasion", "T1036.007"),
        "C2Framework" => ("command-and-control", "T1071"),
        "DownloadCradle" => ("command-and-control", "T1105"),
        "CredentialExtraction" => ("credential-access", "T1078"),
        "ShellcodeIndicator" => ("execution", "T1055"),
        "PowerShellReflection" => ("defense-evasion", "T1620"),
        "ParentProcessAnomaly" => ("execution", "T1204.002"),
        "SuspiciousRegistryPath" => ("persistence", "T1547"),
        "SensitiveFileAccess" => ("credential-access", "T1003"),
        "LateralMovement" => ("lateral-movement", "T1021"),
        "PersistenceClassifier" => ("persistence", "T1053"),
        "ReconIndicator" => ("discovery", "T1082"),
        "DataStaging" => ("collection", "T1074"),
        "DnsSubdomain" => ("command-and-control", "T1071.004"),
        _ => ("unknown", ""),
    }
}

// ── Render findings to console ─────────────────────────────────────

pub fn render_hunt_findings(findings: &[HuntFindingSummary]) -> String {
    if findings.is_empty() {
        return String::new();
    }

    let mut output = String::new();
    output.push_str("\n  Hunt Findings\n");
    output.push_str(&format!("  {}\n", "═".repeat(70)));

    let mut counts = [0usize; 5]; // info, low, medium, high, critical

    for f in findings {
        let marker = match f.severity {
            HuntSeverity::Critical | HuntSeverity::High => "●",
            HuntSeverity::Medium => "●",
            _ => "○",
        };
        let sev_str = format!("{}", f.severity).to_uppercase();
        let technique = if f.mitre_technique.is_empty() {
            String::new()
        } else {
            format!(" ({})", f.mitre_technique)
        };
        output.push_str(&format!(
            "  {} {:<8} {} event(s): {}{}\n",
            marker, sev_str, f.count, f.description, technique,
        ));

        match f.severity {
            HuntSeverity::Critical => counts[4] += f.count,
            HuntSeverity::High => counts[3] += f.count,
            HuntSeverity::Medium => counts[2] += f.count,
            HuntSeverity::Low => counts[1] += f.count,
            HuntSeverity::Info => counts[0] += f.count,
        }
    }

    output.push_str(&format!("  {}\n", "═".repeat(70)));
    let total: usize = counts.iter().sum();
    output.push_str(&format!(
        "  Hunt Summary: {} CRITICAL  {} HIGH  {} MEDIUM  {} LOW  {} INFO = {} findings\n",
        counts[4], counts[3], counts[2], counts[1], counts[0], total,
    ));

    output
}

// ── Levenshtein distance (inline, no dependency) ───────────────────

pub fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_levenshtein() {
        assert_eq!(levenshtein("svchost", "svch0st"), 1);
        assert_eq!(levenshtein("svchost", "svchost"), 0);
        assert_eq!(levenshtein("lsass", "lssas"), 2);
        assert_eq!(levenshtein("csrss", "cssrs"), 2);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
    }

    #[test]
    fn test_hunt_category_from_str() {
        assert_eq!(
            HuntCategory::parse("commandline"),
            Some(HuntCategory::CommandLine)
        );
        assert_eq!(HuntCategory::parse("image"), Some(HuntCategory::Image));
        assert_eq!(HuntCategory::parse("dns"), Some(HuntCategory::Dns));
        assert_eq!(HuntCategory::parse("all"), None);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(HuntSeverity::Critical > HuntSeverity::High);
        assert!(HuntSeverity::High > HuntSeverity::Medium);
        assert!(HuntSeverity::Medium > HuntSeverity::Low);
        assert!(HuntSeverity::Low > HuntSeverity::Info);
    }
}
