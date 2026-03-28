use serde::Serialize;

use crate::mitre::{MitreMapper, TACTIC_DISPLAY};
use crate::scoring::ThreatScore;

// ─── Input Adapter ─────────────────────────────────────────────────────────────
// The binary-level `Detection` struct lives in src/bin/muninn.rs and is not
// importable from the library crate.  We define our own lightweight input
// struct so callers can convert easily.

/// Minimal detection record fed into the summary generator.
#[derive(Debug, Clone)]
pub struct DetectionInput {
    pub title: String,
    pub level: String,
    pub description: String,
    pub tags: Vec<String>,
    pub count: usize,
    pub confidence: String,
}

// ─── Public Structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize)]
pub struct ExecutiveSummary {
    pub verdict: Verdict,
    pub risk_score: f64,
    pub summary_text: String,
    pub key_findings: Vec<Finding>,
    pub affected_entities: Vec<String>,
    pub attack_window: Option<(String, String)>,
    pub recommendations: Vec<String>,
    pub stats: SummaryStats,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum Verdict {
    Clean,
    Suspicious,
    LikelyCompromised,
    ConfirmedBreach,
}

impl std::fmt::Display for Verdict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Verdict::Clean => write!(f, "CLEAN"),
            Verdict::Suspicious => write!(f, "SUSPICIOUS"),
            Verdict::LikelyCompromised => write!(f, "LIKELY COMPROMISED"),
            Verdict::ConfirmedBreach => write!(f, "CONFIRMED BREACH"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub severity: String,
    pub title: String,
    pub description: String,
    pub mitre_tactics: Vec<String>,
    pub affected_count: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct SummaryStats {
    pub total_events: usize,
    pub total_detections: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
}

// ─── Helpers ────────────────────────────────────────────────────────────────────

fn severity_rank(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

/// Map a tactic slug (e.g. "credential-access") to its display name.
fn tactic_display(slug: &str) -> &str {
    for (key, display) in TACTIC_DISPLAY {
        if *key == slug {
            return display;
        }
    }
    slug
}

/// Extract human-readable MITRE tactic names from SIGMA tags.
fn extract_tactics(tags: &[String]) -> Vec<String> {
    let refs = MitreMapper::parse_tags(tags);
    let mapper = MitreMapper::new();

    let mut tactics: Vec<String> = Vec::new();

    for r in &refs {
        // Tactic-level tags (e.g. attack.credential-access)
        if let Some(ref t) = r.tactic {
            let display = tactic_display(t).to_string();
            if !tactics.contains(&display) {
                tactics.push(display);
            }
        }
        // Technique-level tags — resolve to tactic via the mapper
        if let Some(ref id) = r.technique_id {
            if let Some(tech) = mapper.resolve(id) {
                let display = tactic_display(&tech.tactic).to_string();
                if !tactics.contains(&display) {
                    tactics.push(display);
                }
            }
        }
    }
    tactics
}

/// Determine whether a set of tags maps to a particular tactic slug.
fn tags_contain_tactic(tags: &[String], tactic_slug: &str) -> bool {
    let refs = MitreMapper::parse_tags(tags);
    let mapper = MitreMapper::new();

    for r in &refs {
        if let Some(ref t) = r.tactic {
            if t == tactic_slug {
                return true;
            }
        }
        if let Some(ref id) = r.technique_id {
            if let Some(tech) = mapper.resolve(id) {
                if tech.tactic == tactic_slug {
                    return true;
                }
            }
        }
    }
    false
}

/// Count how many distinct MITRE tactics appear across all detections.
fn count_unique_tactics(detections: &[DetectionInput]) -> usize {
    let mut seen: Vec<String> = Vec::new();
    for det in detections {
        for t in extract_tactics(&det.tags) {
            if !seen.contains(&t) {
                seen.push(t);
            }
        }
    }
    seen.len()
}

// ─── Core Logic ─────────────────────────────────────────────────────────────────

/// Compute severity counts from detections.
fn compute_stats(detections: &[DetectionInput], total_events: usize) -> SummaryStats {
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;

    for det in detections {
        match det.level.to_lowercase().as_str() {
            "critical" => critical += 1,
            "high" => high += 1,
            "medium" => medium += 1,
            "low" => low += 1,
            _ => {}
        }
    }

    SummaryStats {
        total_events,
        total_detections: detections.len(),
        critical_count: critical,
        high_count: high,
        medium_count: medium,
        low_count: low,
    }
}

/// Determine verdict from severity counts and tactic coverage.
fn determine_verdict(stats: &SummaryStats, tactic_count: usize) -> Verdict {
    // ConfirmedBreach: >= 3 critical OR (>= 1 critical AND >= 5 high)
    if stats.critical_count >= 3 || (stats.critical_count >= 1 && stats.high_count >= 5) {
        return Verdict::ConfirmedBreach;
    }

    // LikelyCompromised: >= 1 critical OR >= 3 high OR attack chain with >= 3 tactics
    if stats.critical_count >= 1 || stats.high_count >= 3 || tactic_count >= 3 {
        return Verdict::LikelyCompromised;
    }

    // Suspicious: 0 critical, <= 2 high OR > 2 medium
    if stats.high_count > 0 || stats.medium_count > 2 {
        return Verdict::Suspicious;
    }

    // Clean: 0 critical, 0 high, <= 2 medium
    Verdict::Clean
}

/// Compute an aggregate risk score (0--100).
fn compute_risk_score(stats: &SummaryStats, scores: &[ThreatScore]) -> f64 {
    // Start from severity-weighted detection count
    let detection_score = (stats.critical_count as f64 * 10.0)
        + (stats.high_count as f64 * 5.0)
        + (stats.medium_count as f64 * 2.0)
        + (stats.low_count as f64 * 1.0);

    // Incorporate top entity score if available
    let entity_max = scores.iter().map(|s| s.score).fold(0.0_f64, f64::max);

    // Blend: 60 % detection-based, 40 % entity-based (when entity scores exist)
    let blended = if entity_max > 0.0 {
        detection_score * 0.6 + entity_max * 0.4
    } else {
        detection_score
    };

    blended.clamp(0.0, 100.0)
}

/// Build the top-5 key findings sorted by severity then count.
fn build_findings(detections: &[DetectionInput]) -> Vec<Finding> {
    let mut sorted: Vec<&DetectionInput> = detections.iter().collect();
    sorted.sort_by(|a, b| {
        severity_rank(&b.level)
            .cmp(&severity_rank(&a.level))
            .then_with(|| b.count.cmp(&a.count))
    });

    sorted
        .iter()
        .take(5)
        .map(|det| Finding {
            severity: det.level.to_lowercase(),
            title: det.title.clone(),
            description: det.description.clone(),
            mitre_tactics: extract_tactics(&det.tags),
            affected_count: det.count,
        })
        .collect()
}

/// Generate context-aware recommendations based on observed tactics.
fn build_recommendations(detections: &[DetectionInput]) -> Vec<String> {
    let mut recs: Vec<String> = Vec::new();

    let has_cred = detections
        .iter()
        .any(|d| tags_contain_tactic(&d.tags, "credential-access"));
    let has_lateral = detections
        .iter()
        .any(|d| tags_contain_tactic(&d.tags, "lateral-movement"));
    let has_persist = detections
        .iter()
        .any(|d| tags_contain_tactic(&d.tags, "persistence"));
    let has_c2 = detections
        .iter()
        .any(|d| tags_contain_tactic(&d.tags, "command-and-control"));

    if has_cred {
        recs.push("Immediately reset all credentials on affected hosts".into());
    }
    if has_lateral {
        recs.push("Isolate affected hosts from network".into());
    }
    if has_persist {
        recs.push("Audit startup items, services, and scheduled tasks".into());
    }
    if has_c2 {
        recs.push("Block identified C2 IPs/domains at firewall".into());
    }

    // Always-present baseline recommendation
    recs.push("Conduct full forensic investigation of affected hosts".into());

    recs
}

/// Produce entity list with scores.
fn build_entity_list(scores: &[ThreatScore]) -> Vec<String> {
    scores
        .iter()
        .take(10)
        .map(|s| format!("{} (score: {:.0}/100)", s.entity, s.score))
        .collect()
}

/// Build a plain-language narrative.
fn build_narrative(
    verdict: &Verdict,
    stats: &SummaryStats,
    entities: &[String],
    window: &Option<(String, String)>,
    detections: &[DetectionInput],
) -> String {
    let verdict_phrase = match verdict {
        Verdict::Clean => "No significant threats detected.",
        Verdict::Suspicious => "Suspicious activity detected that warrants investigation.",
        Verdict::LikelyCompromised => "Evidence indicates likely compromise.",
        Verdict::ConfirmedBreach => "Strong evidence of confirmed breach.",
    };

    let mut parts: Vec<String> = vec![verdict_phrase.to_string()];

    if stats.total_detections > 0 {
        let sev = format!(
            "{} critical and {} high severity detections found",
            stats.critical_count, stats.high_count
        );
        let entity_part = if entities.is_empty() {
            String::new()
        } else {
            format!(" across {} entities", entities.len())
        };
        parts.push(format!("{}{}", sev, entity_part));
    }

    if let Some((first, last)) = window {
        let first_short = if first.len() > 16 {
            &first[..16]
        } else {
            first
        };
        let last_short = if last.len() > 16 { &last[..16] } else { last };
        parts.push(format!("in the window {} to {}", first_short, last_short));
    }

    // Mention key indicators
    let all_tactics: Vec<String> = detections
        .iter()
        .flat_map(|d| extract_tactics(&d.tags))
        .collect::<Vec<_>>();
    let mut unique_tactics: Vec<String> = Vec::new();
    for t in &all_tactics {
        if !unique_tactics.contains(t) {
            unique_tactics.push(t.clone());
        }
    }
    if !unique_tactics.is_empty() {
        let display: Vec<&str> = unique_tactics.iter().take(4).map(|s| s.as_str()).collect();
        parts.push(format!("Key indicators include {}.", display.join(", ")));
    }

    // Join with punctuation
    let mut text = String::new();
    for (i, part) in parts.iter().enumerate() {
        if i == 0 {
            text.push_str(part);
        } else if part.ends_with('.') {
            text.push(' ');
            text.push_str(part);
        } else {
            // Continue the sentence with proper punctuation
            if text.ends_with('.') {
                text.push(' ');
                // Capitalize first letter
                let mut chars = part.chars();
                if let Some(first) = chars.next() {
                    text.push(first.to_uppercase().next().unwrap_or(first));
                    text.extend(chars);
                }
                text.push('.');
            } else {
                text.push_str(". ");
                let mut chars = part.chars();
                if let Some(first) = chars.next() {
                    text.push(first.to_uppercase().next().unwrap_or(first));
                    text.extend(chars);
                }
                text.push('.');
            }
        }
    }

    text
}

// ─── Public API ─────────────────────────────────────────────────────────────────

/// Generate an executive-level incident assessment summary.
///
/// * `detections` — flattened detection inputs (title, level, tags, count, ...)
/// * `scores`     — per-entity threat scores from `crate::scoring`
/// * `total_events` — total number of log events ingested
pub fn generate_summary(
    detections: &[DetectionInput],
    scores: &[ThreatScore],
    total_events: usize,
) -> ExecutiveSummary {
    let stats = compute_stats(detections, total_events);
    let tactic_count = count_unique_tactics(detections);
    let verdict = determine_verdict(&stats, tactic_count);
    let risk_score = compute_risk_score(&stats, scores);
    let findings = build_findings(detections);
    let entities = build_entity_list(scores);
    let recommendations = build_recommendations(detections);

    // Attack window — not available from counts alone; callers may populate later.
    let attack_window: Option<(String, String)> = None;

    let summary_text = build_narrative(&verdict, &stats, &entities, &attack_window, detections);

    ExecutiveSummary {
        verdict,
        risk_score,
        summary_text,
        key_findings: findings,
        affected_entities: entities,
        attack_window,
        recommendations,
        stats,
    }
}

/// Generate an executive summary with an explicit attack time window.
pub fn generate_summary_with_window(
    detections: &[DetectionInput],
    scores: &[ThreatScore],
    total_events: usize,
    window: Option<(String, String)>,
) -> ExecutiveSummary {
    let stats = compute_stats(detections, total_events);
    let tactic_count = count_unique_tactics(detections);
    let verdict = determine_verdict(&stats, tactic_count);
    let risk_score = compute_risk_score(&stats, scores);
    let findings = build_findings(detections);
    let entities = build_entity_list(scores);
    let recommendations = build_recommendations(detections);
    let summary_text = build_narrative(&verdict, &stats, &entities, &window, detections);

    ExecutiveSummary {
        verdict,
        risk_score,
        summary_text,
        key_findings: findings,
        affected_entities: entities,
        attack_window: window,
        recommendations,
        stats,
    }
}

// ─── Render ─────────────────────────────────────────────────────────────────────

/// Render the executive summary as a formatted plain-text block.
pub fn render_summary(summary: &ExecutiveSummary) -> String {
    let mut out = String::new();

    // ── Header box ──────────────────────────────────────────────────────────
    let width = 56;
    out.push_str(&format!(
        "\n  {}{}{}\n",
        "\u{2554}",
        "\u{2550}".repeat(width),
        "\u{2557}"
    ));
    out.push_str(&format!(
        "  \u{2551}{:^width$}\u{2551}\n",
        "INCIDENT ASSESSMENT SUMMARY",
        width = width
    ));
    out.push_str(&format!(
        "  {}{}{}\n",
        "\u{2560}",
        "\u{2550}".repeat(width),
        "\u{2563}"
    ));
    out.push_str(&format!(
        "  \u{2551}  Verdict: {:<w$}\u{2551}\n",
        summary.verdict,
        w = width - 12
    ));
    out.push_str(&format!(
        "  \u{2551}  Risk Score: {:<w$.0}/100{}\u{2551}\n",
        summary.risk_score,
        " ".repeat(
            width
                .saturating_sub(18)
                .saturating_sub(format!("{:.0}", summary.risk_score).len())
        ),
        w = 1
    ));
    out.push_str(&format!(
        "  {}{}{}\n",
        "\u{255a}",
        "\u{2550}".repeat(width),
        "\u{255d}"
    ));

    // ── Summary narrative ───────────────────────────────────────────────────
    out.push_str("\n  Summary:\n");
    // Word-wrap to ~68 cols
    let words: Vec<&str> = summary.summary_text.split_whitespace().collect();
    let mut line = String::from("  ");
    for word in &words {
        if line.len() + word.len() + 1 > 70 {
            out.push_str(&line);
            out.push('\n');
            line = String::from("  ");
        }
        if line.len() > 2 {
            line.push(' ');
        }
        line.push_str(word);
    }
    if line.len() > 2 {
        out.push_str(&line);
        out.push('\n');
    }

    // ── Key Findings ────────────────────────────────────────────────────────
    if !summary.key_findings.is_empty() {
        out.push_str("\n  Key Findings:\n");
        for (i, finding) in summary.key_findings.iter().enumerate() {
            let label = finding.severity.to_uppercase();
            out.push_str(&format!("  {}. [{}] {}\n", i + 1, label, finding.title));
            let tactics_str = if finding.mitre_tactics.is_empty() {
                "-".to_string()
            } else {
                finding.mitre_tactics.join(", ")
            };
            out.push_str(&format!(
                "     -> {} events, MITRE: {}\n",
                finding.affected_count, tactics_str
            ));
        }
    }

    // ── Affected Entities ───────────────────────────────────────────────────
    if !summary.affected_entities.is_empty() {
        out.push_str("\n  Affected Entities:\n");
        for entity in &summary.affected_entities {
            out.push_str(&format!("  * {}\n", entity));
        }
    }

    // ── Attack Window ───────────────────────────────────────────────────────
    if let Some((ref first, ref last)) = summary.attack_window {
        out.push_str(&format!("\n  Attack Window: {} to {}\n", first, last));
    }

    // ── Recommendations ─────────────────────────────────────────────────────
    if !summary.recommendations.is_empty() {
        out.push_str("\n  Recommendations:\n");
        for rec in &summary.recommendations {
            out.push_str(&format!("  * {}\n", rec));
        }
    }

    // ── Stats footer ────────────────────────────────────────────────────────
    out.push_str(&format!(
        "\n  Stats: {} events analysed, {} detections ({} critical, {} high, {} medium, {} low)\n",
        summary.stats.total_events,
        summary.stats.total_detections,
        summary.stats.critical_count,
        summary.stats.high_count,
        summary.stats.medium_count,
        summary.stats.low_count,
    ));

    out
}

// ─── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scoring::ThreatScore;

    fn make_detection(title: &str, level: &str, tags: Vec<&str>, count: usize) -> DetectionInput {
        DetectionInput {
            title: title.into(),
            level: level.into(),
            description: format!("{} description", title),
            tags: tags.into_iter().map(String::from).collect(),
            count,
            confidence: "high".into(),
        }
    }

    fn make_score(entity: &str, score: f64) -> ThreatScore {
        ThreatScore {
            entity: entity.into(),
            entity_type: "host".into(),
            score,
            rules: vec![],
        }
    }

    // ── Verdict tests ───────────────────────────────────────────────────────

    #[test]
    fn test_verdict_clean_zero_detections() {
        let summary = generate_summary(&[], &[], 10000);
        assert_eq!(summary.verdict, Verdict::Clean);
        assert_eq!(summary.risk_score, 0.0);
        assert!(summary.key_findings.is_empty());
    }

    #[test]
    fn test_verdict_clean_few_low() {
        let dets = vec![
            make_detection("Low rule 1", "low", vec![], 2),
            make_detection("Low rule 2", "low", vec![], 1),
        ];
        let summary = generate_summary(&dets, &[], 5000);
        assert_eq!(summary.verdict, Verdict::Clean);
    }

    #[test]
    fn test_verdict_clean_two_medium() {
        let dets = vec![
            make_detection("Med 1", "medium", vec![], 3),
            make_detection("Med 2", "medium", vec![], 1),
        ];
        let summary = generate_summary(&dets, &[], 5000);
        assert_eq!(summary.verdict, Verdict::Clean);
    }

    #[test]
    fn test_verdict_suspicious_high() {
        let dets = vec![
            make_detection("High rule", "high", vec!["attack.execution"], 5),
            make_detection("Low rule", "low", vec![], 2),
        ];
        let summary = generate_summary(&dets, &[], 5000);
        assert_eq!(summary.verdict, Verdict::Suspicious);
    }

    #[test]
    fn test_verdict_suspicious_many_medium() {
        let dets = vec![
            make_detection("Med 1", "medium", vec![], 3),
            make_detection("Med 2", "medium", vec![], 1),
            make_detection("Med 3", "medium", vec![], 2),
        ];
        let summary = generate_summary(&dets, &[], 5000);
        assert_eq!(summary.verdict, Verdict::Suspicious);
    }

    #[test]
    fn test_verdict_likely_compromised_one_critical() {
        let dets = vec![
            make_detection(
                "LSASS Memory Access",
                "critical",
                vec!["attack.credential-access"],
                12,
            ),
            make_detection(
                "Suspicious Service",
                "high",
                vec!["attack.lateral-movement", "attack.execution"],
                5,
            ),
        ];
        let scores = vec![make_score("DC01", 92.0), make_score("WS-FINANCE03", 67.0)];
        let summary = generate_summary(&dets, &scores, 50000);
        assert_eq!(summary.verdict, Verdict::LikelyCompromised);
    }

    #[test]
    fn test_verdict_likely_compromised_two_crit_three_high() {
        let dets = vec![
            make_detection("Crit 1", "critical", vec!["attack.credential-access"], 10),
            make_detection("Crit 2", "critical", vec!["attack.execution"], 5),
            make_detection("High 1", "high", vec!["attack.lateral-movement"], 3),
            make_detection("High 2", "high", vec!["attack.persistence"], 2),
            make_detection("High 3", "high", vec!["attack.defense-evasion"], 1),
        ];
        let summary = generate_summary(&dets, &[], 50000);
        assert_eq!(summary.verdict, Verdict::LikelyCompromised);
    }

    #[test]
    fn test_verdict_likely_compromised_three_plus_tactics() {
        // No critical or high, but 3+ tactics → LikelyCompromised
        let dets = vec![
            make_detection("Recon", "medium", vec!["attack.discovery"], 3),
            make_detection("Persist", "medium", vec!["attack.persistence"], 2),
            make_detection("Evasion", "low", vec!["attack.defense-evasion"], 1),
        ];
        let summary = generate_summary(&dets, &[], 5000);
        assert_eq!(summary.verdict, Verdict::LikelyCompromised);
    }

    #[test]
    fn test_verdict_confirmed_breach_three_critical() {
        let dets = vec![
            make_detection("Crit 1", "critical", vec!["attack.credential-access"], 10),
            make_detection("Crit 2", "critical", vec!["attack.execution"], 8),
            make_detection("Crit 3", "critical", vec!["attack.lateral-movement"], 6),
        ];
        let summary = generate_summary(&dets, &[], 100_000);
        assert_eq!(summary.verdict, Verdict::ConfirmedBreach);
    }

    #[test]
    fn test_verdict_confirmed_breach_crit_plus_five_high() {
        let dets = vec![
            make_detection("Crit", "critical", vec!["attack.execution"], 10),
            make_detection("High 1", "high", vec!["attack.persistence"], 5),
            make_detection("High 2", "high", vec!["attack.lateral-movement"], 4),
            make_detection("High 3", "high", vec!["attack.credential-access"], 3),
            make_detection("High 4", "high", vec!["attack.defense-evasion"], 2),
            make_detection("High 5", "high", vec!["attack.discovery"], 1),
        ];
        let summary = generate_summary(&dets, &[], 100_000);
        assert_eq!(summary.verdict, Verdict::ConfirmedBreach);
    }

    // ── Key findings tests ──────────────────────────────────────────────────

    #[test]
    fn test_key_findings_sorted_by_severity_then_count() {
        let dets = vec![
            make_detection("Low big", "low", vec![], 100),
            make_detection("Crit small", "critical", vec!["attack.execution"], 2),
            make_detection("High mid", "high", vec!["attack.persistence"], 10),
        ];
        let summary = generate_summary(&dets, &[], 1000);

        assert_eq!(summary.key_findings.len(), 3);
        assert_eq!(summary.key_findings[0].severity, "critical");
        assert_eq!(summary.key_findings[1].severity, "high");
        assert_eq!(summary.key_findings[2].severity, "low");
    }

    #[test]
    fn test_key_findings_capped_at_five() {
        let dets: Vec<DetectionInput> = (0..8)
            .map(|i| make_detection(&format!("Rule {}", i), "high", vec![], i + 1))
            .collect();
        let summary = generate_summary(&dets, &[], 5000);
        assert_eq!(summary.key_findings.len(), 5);
    }

    // ── Recommendations tests ───────────────────────────────────────────────

    #[test]
    fn test_recommendations_credential_access() {
        let dets = vec![make_detection(
            "LSASS dump",
            "critical",
            vec!["attack.credential-access"],
            5,
        )];
        let summary = generate_summary(&dets, &[], 1000);
        assert!(summary
            .recommendations
            .iter()
            .any(|r| r.contains("reset all credentials")));
    }

    #[test]
    fn test_recommendations_lateral_movement() {
        let dets = vec![make_detection(
            "PsExec",
            "high",
            vec!["attack.lateral-movement"],
            3,
        )];
        let summary = generate_summary(&dets, &[], 1000);
        assert!(summary
            .recommendations
            .iter()
            .any(|r| r.contains("Isolate affected hosts")));
    }

    #[test]
    fn test_recommendations_persistence() {
        let dets = vec![make_detection(
            "New service",
            "high",
            vec!["attack.persistence"],
            2,
        )];
        let summary = generate_summary(&dets, &[], 1000);
        assert!(summary
            .recommendations
            .iter()
            .any(|r| r.contains("startup items")));
    }

    #[test]
    fn test_recommendations_c2() {
        let dets = vec![make_detection(
            "Beacon",
            "high",
            vec!["attack.command-and-control"],
            4,
        )];
        let summary = generate_summary(&dets, &[], 1000);
        assert!(summary
            .recommendations
            .iter()
            .any(|r| r.contains("C2 IPs/domains")));
    }

    #[test]
    fn test_recommendations_always_include_baseline() {
        let summary = generate_summary(&[], &[], 1000);
        assert!(summary
            .recommendations
            .iter()
            .any(|r| r.contains("full forensic investigation")));
    }

    // ── Entity / scores tests ───────────────────────────────────────────────

    #[test]
    fn test_affected_entities_from_scores() {
        let scores = vec![make_score("DC01", 92.0), make_score("WS01", 45.0)];
        let summary = generate_summary(&[], &scores, 1000);
        assert_eq!(summary.affected_entities.len(), 2);
        assert!(summary.affected_entities[0].contains("DC01"));
        assert!(summary.affected_entities[1].contains("WS01"));
    }

    // ── Risk score tests ────────────────────────────────────────────────────

    #[test]
    fn test_risk_score_zero_for_clean() {
        let summary = generate_summary(&[], &[], 1000);
        assert_eq!(summary.risk_score, 0.0);
    }

    #[test]
    fn test_risk_score_capped_at_100() {
        let dets: Vec<DetectionInput> = (0..20)
            .map(|i| make_detection(&format!("Crit {}", i), "critical", vec![], 10))
            .collect();
        let summary = generate_summary(&dets, &[], 100_000);
        assert!(summary.risk_score <= 100.0);
    }

    // ── Stats tests ─────────────────────────────────────────────────────────

    #[test]
    fn test_stats_counts() {
        let dets = vec![
            make_detection("C", "critical", vec![], 1),
            make_detection("H", "high", vec![], 1),
            make_detection("M", "medium", vec![], 1),
            make_detection("L", "low", vec![], 1),
        ];
        let summary = generate_summary(&dets, &[], 9999);
        assert_eq!(summary.stats.total_events, 9999);
        assert_eq!(summary.stats.total_detections, 4);
        assert_eq!(summary.stats.critical_count, 1);
        assert_eq!(summary.stats.high_count, 1);
        assert_eq!(summary.stats.medium_count, 1);
        assert_eq!(summary.stats.low_count, 1);
    }

    // ── Render tests ────────────────────────────────────────────────────────

    #[test]
    fn test_render_contains_verdict() {
        let dets = vec![make_detection(
            "Critical alert",
            "critical",
            vec!["attack.credential-access"],
            12,
        )];
        let scores = vec![make_score("DC01", 92.0)];
        let summary = generate_summary(&dets, &scores, 50000);
        let rendered = render_summary(&summary);

        assert!(rendered.contains("INCIDENT ASSESSMENT SUMMARY"));
        assert!(rendered.contains("Verdict:"));
        assert!(rendered.contains("Risk Score:"));
        assert!(rendered.contains("Key Findings:"));
        assert!(rendered.contains("Critical alert"));
        assert!(rendered.contains("DC01"));
        assert!(rendered.contains("Recommendations:"));
    }

    #[test]
    fn test_render_clean_verdict() {
        let summary = generate_summary(&[], &[], 1000);
        let rendered = render_summary(&summary);
        assert!(rendered.contains("CLEAN"));
        assert!(rendered.contains("No significant threats detected"));
    }

    // ── Attack window test ──────────────────────────────────────────────────

    #[test]
    fn test_summary_with_window() {
        let dets = vec![make_detection(
            "Crit",
            "critical",
            vec!["attack.execution"],
            5,
        )];
        let window = Some((
            "2026-03-15T08:12:00".to_string(),
            "2026-03-15T12:45:00".to_string(),
        ));
        let summary = generate_summary_with_window(&dets, &[], 10000, window.clone());
        assert!(summary.attack_window.is_some());
        let rendered = render_summary(&summary);
        assert!(rendered.contains("Attack Window:"));
        assert!(rendered.contains("2026-03-15T08:12"));
    }

    // ── Serialization test ──────────────────────────────────────────────────

    #[test]
    fn test_summary_serializes_to_json() {
        let dets = vec![make_detection(
            "Test rule",
            "high",
            vec!["attack.discovery"],
            3,
        )];
        let summary = generate_summary(&dets, &[], 5000);
        let json = serde_json::to_string(&summary);
        assert!(json.is_ok());
        let json_str = json.unwrap();
        assert!(json_str.contains("\"verdict\":"));
        assert!(json_str.contains("\"risk_score\":"));
        assert!(json_str.contains("\"key_findings\":"));
    }
}
