use anyhow::{Context, Result};
use chrono::Local;
use clap::Parser;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;

use muninn::{parsers, search::SearchEngine, sigma};

#[derive(serde::Serialize, Clone)]
struct SourceFile {
    path: String,
    sha256: String,
    size_bytes: u64,
}

fn hash_file_sha256(path: &std::path::Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let n = std::io::Read::read(&mut file, &mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[derive(serde::Deserialize, Default)]
#[allow(dead_code)]
struct Config {
    events: Option<PathBuf>,
    rules: Option<PathBuf>,
    min_level: Option<String>,
    limit: Option<usize>,
    hashes: Option<bool>,
    quiet: Option<bool>,
    no_report: Option<bool>,
    stats: Option<bool>,
    select: Option<String>,
    avoid: Option<String>,
    output: Option<PathBuf>,
    dbfile: Option<PathBuf>,
    load_db: Option<PathBuf>,
    distinct: Option<String>,
    rulefilter: Option<Vec<String>>,
    profile_rules: Option<bool>,
    after: Option<String>,
    before: Option<String>,
    transforms: Option<bool>,
    timeline: Option<bool>,
    anomalies: Option<bool>,
    ioc_extract: Option<bool>,
    threat_score: Option<bool>,
    correlate: Option<bool>,
    killchain: Option<bool>,
    max_events: Option<usize>,
    workers: Option<usize>,
    batch_size: Option<usize>,
}

#[derive(Parser)]
#[command(
    name = "muninn",
    version,
    about = "Muninn — memory of Corax. Universal log parser, SIGMA detection engine, and search tool. 15+ formats, one binary, zero dependencies."
)]
struct Cli {
    #[arg(short = 'e', long = "events", required_unless_present = "load_db")]
    events: Option<PathBuf>,

    #[arg(short = 'r', long = "rules")]
    rules: Option<PathBuf>,

    #[arg(long = "sql-file")]
    sql_file: Option<PathBuf>,

    #[arg(long = "sql")]
    sql: Option<String>,

    #[arg(short = 'k', long = "keyword")]
    keyword: Option<String>,

    #[arg(short = 'f', long = "field")]
    field_search: Option<String>,

    #[arg(long = "regex")]
    regex_search: Option<String>,

    #[arg(short = 'o', long = "output")]
    output: Option<PathBuf>,

    #[arg(long = "dbfile", default_missing_value = "auto", num_args = 0..=1)]
    dbfile: Option<PathBuf>,

    #[arg(
        long = "load-db",
        help = "Load previously saved SQLite database (skip parsing)",
        conflicts_with = "events"
    )]
    load_db: Option<PathBuf>,

    #[arg(short = 's', long = "select")]
    select: Option<String>,

    #[arg(short = 'a', long = "avoid")]
    avoid: Option<String>,

    #[arg(long = "hashes")]
    hashes: bool,

    #[arg(long = "stats")]
    stats: bool,

    #[arg(long = "distinct")]
    distinct: Option<String>,

    #[arg(long = "min-level", default_value = "low")]
    min_level: String,

    #[arg(short = 'q', long = "quiet")]
    quiet: bool,

    #[arg(long = "no-report")]
    no_report: bool,

    // --- Phase 1 features ---
    #[arg(long = "limit", help = "Limit number of result rows")]
    limit: Option<usize>,

    #[arg(
        long = "rulefilter",
        help = "Exclude rules matching pattern (repeatable)"
    )]
    rulefilter: Vec<String>,

    #[arg(long = "profile-rules", help = "Show rule execution time ranking")]
    profile_rules: bool,

    #[arg(long = "after", help = "Only events after timestamp (ISO 8601)")]
    after: Option<String>,

    #[arg(long = "before", help = "Only events before timestamp (ISO 8601)")]
    before: Option<String>,

    #[arg(long = "config", help = "YAML config file")]
    config: Option<PathBuf>,

    // --- Phase 2 features ---
    #[arg(long = "add-index", num_args = 1.., help = "Create index on field(s)")]
    add_index: Vec<String>,

    #[arg(long = "remove-index", num_args = 1.., help = "Remove index by name")]
    remove_index: Vec<String>,

    #[arg(long = "field-map", help = "YAML field rename mapping file")]
    field_map: Option<PathBuf>,

    #[arg(long = "keepflat", help = "Export flattened events as JSONL", default_missing_value = "auto", num_args = 0..=1)]
    keepflat: Option<PathBuf>,

    // --- Phase 3 features ---
    #[arg(long = "navigator", help = "Export ATT&CK Navigator layer JSON", default_missing_value = "auto", num_args = 0..=1)]
    navigator: Option<PathBuf>,

    #[arg(long = "killchain", help = "Show kill chain view and save to file", default_missing_value = "auto", num_args = 0..=1)]
    killchain: Option<PathBuf>,

    // --- Phase 4 features ---
    #[arg(
        long = "template",
        help = "Output template: splunk, elk, timesketch, csv, sarif"
    )]
    template: Option<String>,

    #[arg(long = "template-output", help = "Template output file path", default_missing_value = "auto", num_args = 0..=1)]
    template_output: Option<PathBuf>,

    #[arg(long = "gui", help = "Generate self-contained HTML report", default_missing_value = "auto", num_args = 0..=1)]
    gui: Option<PathBuf>,

    // --- Phase 5 features ---
    #[arg(
        long = "transforms",
        help = "Apply field transforms (base64 decode, IOC extract, LOLBin detect)"
    )]
    transforms: bool,

    #[arg(long = "timeline", help = "Show attack timeline and save to file", default_missing_value = "auto", num_args = 0..=1)]
    timeline: Option<PathBuf>,

    #[arg(long = "anomalies", help = "Detect statistical anomalies and save to file", default_missing_value = "auto", num_args = 0..=1)]
    anomalies: Option<PathBuf>,

    #[arg(long = "ioc-extract", help = "Extract IOCs from events and save to file", default_missing_value = "auto", num_args = 0..=1)]
    ioc_extract: Option<PathBuf>,

    #[arg(
        long = "ioc-max",
        help = "Maximum number of unique IOCs to track (default: 100000)",
        default_value = "100000"
    )]
    ioc_max: usize,

    #[arg(long = "vt-key", help = "VirusTotal API key for IOC enrichment")]
    vt_key: Option<String>,

    #[arg(long = "abuseipdb-key", help = "AbuseIPDB API key for IP enrichment")]
    abuseipdb_key: Option<String>,

    #[arg(
        long = "opentip-key",
        help = "Kaspersky OpenTIP API key for IOC enrichment"
    )]
    opentip_key: Option<String>,

    #[cfg(feature = "ioc-enrich")]
    #[arg(
        long = "opentip-check",
        help = "Check extracted IOCs against Kaspersky OpenTIP (provide API key)"
    )]
    opentip_check: Option<String>,

    #[cfg(feature = "ioc-enrich")]
    #[arg(
        long = "opentip-max",
        help = "Max IOCs to check via OpenTIP (default: all, daily quota: 2000)",
        default_value = "2000"
    )]
    opentip_max: usize,

    #[cfg(feature = "ioc-enrich")]
    #[arg(
        long = "opentip-types",
        help = "IOC types to check: hash,ip,domain,url (comma-separated, default: all)",
        default_value = "all"
    )]
    opentip_types: String,

    #[arg(long = "threat-score", help = "Compute per-host/user threat scores and save to file", default_missing_value = "auto", num_args = 0..=1)]
    threat_score: Option<PathBuf>,

    // --- Phase 6 features ---
    #[arg(long = "diff", help = "Compare with second evidence set")]
    diff: Option<PathBuf>,

    #[arg(long = "correlate", help = "Correlate events into attack chains and save to file", default_missing_value = "auto", num_args = 0..=1)]
    correlate: Option<PathBuf>,

    #[arg(long = "login-analysis", help = "Analyze login events (4624/4625/4672) and save report", default_missing_value = "auto", num_args = 0..=1)]
    login_analysis: Option<PathBuf>,

    #[arg(long = "summary", help = "Generate executive incident assessment summary", default_missing_value = "auto", num_args = 0..=1)]
    summary: Option<PathBuf>,

    #[arg(
        long = "per-file",
        help = "Process each file in separate DB (parallel)"
    )]
    per_file: bool,

    // --- Phase 7 features ---
    #[cfg(feature = "download")]
    #[arg(
        long = "download-rules",
        help = "Download SIGMA rules: core, core+, all, emerging"
    )]
    download_rules: Option<String>,

    #[cfg(feature = "download")]
    #[arg(long = "rules-dir", help = "Directory to save downloaded rules")]
    rules_dir: Option<PathBuf>,

    #[cfg(feature = "tui")]
    #[arg(long = "tui", help = "Launch interactive terminal UI")]
    tui: bool,

    #[cfg(feature = "live")]
    #[arg(
        long = "live",
        help = "Watch directory for changes and detect in real-time"
    )]
    live: bool,

    #[arg(
        long = "archive-password",
        help = "Password for encrypted archives (zip, rar, 7z)"
    )]
    archive_password: Option<String>,

    // --- Performance controls ---
    #[arg(long = "max-events", help = "Maximum events to load (memory control)")]
    max_events: Option<usize>,

    #[arg(long = "workers", help = "Number of parallel workers (default: 4)")]
    workers: Option<usize>,

    #[arg(
        long = "batch-size",
        help = "Events per batch for loading (default: 50000)"
    )]
    batch_size: Option<usize>,
}

struct Detection {
    title: String,
    level: String,
    description: String,
    id: String,
    author: String,
    tags: Vec<String>,
    result: muninn::SearchResult,
    confidence: String,
}

fn compute_confidence(
    rule: &muninn::sigma::Rule,
    rows: &[std::collections::HashMap<String, String>],
) -> String {
    let service = match rule.logsource.service.as_deref() {
        Some(s) if !s.is_empty() => s.to_lowercase(),
        _ => return "high".to_string(),
    };

    let expected = match muninn::sigma::expected_channel_for_service(&service) {
        Some(ch) => ch.to_lowercase(),
        None => return "high".to_string(),
    };

    let mismatched = rows.iter().any(|row| {
        row.get("Channel")
            .map(|ch| ch.to_lowercase() != expected)
            .unwrap_or(false)
    });

    if mismatched {
        "low".to_string()
    } else {
        "high".to_string()
    }
}

fn level_rank(level: &str) -> u8 {
    match level.to_lowercase().as_str() {
        "critical" => 5,
        "high" => 4,
        "medium" => 3,
        "low" => 2,
        "informational" | "info" => 1,
        _ => 0,
    }
}

fn level_color(level: &str) -> colored::ColoredString {
    match level.to_lowercase().as_str() {
        "critical" => level.to_uppercase().bold().red(),
        "high" => level.to_uppercase().bold().magenta(),
        "medium" => level.to_uppercase().bold().yellow(),
        "low" => level.to_uppercase().green(),
        _ => level.to_uppercase().dimmed(),
    }
}

fn main() -> Result<()> {
    env_logger::Builder::new()
        .filter_level(log::LevelFilter::Error)
        .filter_module("muninn", log::LevelFilter::Warn)
        .init();
    let mut cli = Cli::parse();

    // Download rules and exit if requested
    #[cfg(feature = "download")]
    if let Some(ref ruleset_name) = cli.download_rules {
        let ruleset = muninn::download::RuleSet::from_name(ruleset_name)?;
        let output_dir = cli
            .rules_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("sigma-rules"));

        if !cli.quiet {
            println!();
            println!(
                "  {} Downloading {} ...",
                "▶".green().bold(),
                ruleset.display_name()
            );
            println!("  {} Source: {}", "[>]".cyan(), ruleset.url());
            println!("  {} Target: {:?}", "[>]".cyan(), output_dir);
            println!();
        }

        let result = muninn::download::download_rules(ruleset, &output_dir)?;

        if !cli.quiet {
            println!(
                "  {} Downloaded {} rules ({:.1} MB) → {:?}",
                "✓".green().bold(),
                result.rules_count,
                result.bytes_downloaded as f64 / 1_048_576.0,
                result.output_dir
            );
            println!();
            println!(
                "  {} Use with: muninn -e <logs> -r {:?}",
                "→".cyan(),
                result.output_dir
            );
        }

        return Ok(());
    }

    let start = Instant::now();
    let run_timestamp = Local::now();

    // Merge YAML config if provided
    if let Some(ref config_path) = cli.config {
        let content = std::fs::read_to_string(config_path)
            .context(format!("Failed to read config {:?}", config_path))?;
        let cfg: Config = serde_yaml::from_str(&content)
            .context(format!("Failed to parse config {:?}", config_path))?;
        // CLI flags take precedence over config
        if cli.rules.is_none() {
            cli.rules = cfg.rules;
        }
        if cli.min_level == "low" {
            if let Some(ml) = cfg.min_level {
                cli.min_level = ml;
            }
        }
        if cli.limit.is_none() {
            cli.limit = cfg.limit;
        }
        if !cli.hashes {
            cli.hashes = cfg.hashes.unwrap_or(false);
        }
        if !cli.quiet {
            cli.quiet = cfg.quiet.unwrap_or(false);
        }
        if !cli.no_report {
            cli.no_report = cfg.no_report.unwrap_or(false);
        }
        if !cli.stats {
            cli.stats = cfg.stats.unwrap_or(false);
        }
        if cli.select.is_none() {
            cli.select = cfg.select;
        }
        if cli.avoid.is_none() {
            cli.avoid = cfg.avoid;
        }
        if cli.output.is_none() {
            cli.output = cfg.output;
        }
        if cli.dbfile.is_none() {
            cli.dbfile = cfg.dbfile;
        }
        if cli.load_db.is_none() {
            cli.load_db = cfg.load_db;
        }
        if cli.distinct.is_none() {
            cli.distinct = cfg.distinct;
        }
        if cli.rulefilter.is_empty() {
            cli.rulefilter = cfg.rulefilter.unwrap_or_default();
        }
        if !cli.profile_rules {
            cli.profile_rules = cfg.profile_rules.unwrap_or(false);
        }
        if cli.after.is_none() {
            cli.after = cfg.after;
        }
        if cli.before.is_none() {
            cli.before = cfg.before;
        }
        if !cli.transforms {
            cli.transforms = cfg.transforms.unwrap_or(false);
        }
        if cli.timeline.is_none() && cfg.timeline.unwrap_or(false) {
            cli.timeline = Some(PathBuf::from("auto"));
        }
        if cli.anomalies.is_none() && cfg.anomalies.unwrap_or(false) {
            cli.anomalies = Some(PathBuf::from("auto"));
        }
        if cli.ioc_extract.is_none() && cfg.ioc_extract.unwrap_or(false) {
            cli.ioc_extract = Some(PathBuf::from("auto"));
        }
        if cli.threat_score.is_none() && cfg.threat_score.unwrap_or(false) {
            cli.threat_score = Some(PathBuf::from("auto"));
        }
        if cli.correlate.is_none() && cfg.correlate.unwrap_or(false) {
            cli.correlate = Some(PathBuf::from("auto"));
        }
        if cli.killchain.is_none() && cfg.killchain.unwrap_or(false) {
            cli.killchain = Some(PathBuf::from("auto"));
        }
    }

    // Resolve "auto" paths to timestamped filenames
    let ts = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S");
    if cli.dbfile.as_ref().is_some_and(|p| p.as_os_str() == "auto") {
        cli.dbfile = Some(PathBuf::from(format!("muninn_db_{}.db", ts)));
    }
    if cli
        .keepflat
        .as_ref()
        .is_some_and(|p| p.as_os_str() == "auto")
    {
        cli.keepflat = Some(PathBuf::from(format!("muninn_events_{}.jsonl", ts)));
    }
    if cli
        .navigator
        .as_ref()
        .is_some_and(|p| p.as_os_str() == "auto")
    {
        cli.navigator = Some(PathBuf::from(format!("muninn_navigator_{}.json", ts)));
    }
    if cli.gui.as_ref().is_some_and(|p| p.as_os_str() == "auto") {
        cli.gui = Some(PathBuf::from(format!("muninn_report_{}.html", ts)));
    }
    if cli
        .timeline
        .as_ref()
        .is_some_and(|p| p.as_os_str() == "auto")
    {
        cli.timeline = Some(PathBuf::from(format!("muninn_timeline_{}.txt", ts)));
    }
    if cli
        .killchain
        .as_ref()
        .is_some_and(|p| p.as_os_str() == "auto")
    {
        cli.killchain = Some(PathBuf::from(format!("muninn_killchain_{}.txt", ts)));
    }
    if cli
        .anomalies
        .as_ref()
        .is_some_and(|p| p.as_os_str() == "auto")
    {
        cli.anomalies = Some(PathBuf::from(format!("muninn_anomalies_{}.txt", ts)));
    }
    if cli
        .ioc_extract
        .as_ref()
        .is_some_and(|p| p.as_os_str() == "auto")
    {
        cli.ioc_extract = Some(PathBuf::from(format!("muninn_iocs_{}.txt", ts)));
    }
    if cli
        .correlate
        .as_ref()
        .is_some_and(|p| p.as_os_str() == "auto")
    {
        cli.correlate = Some(PathBuf::from(format!("muninn_correlate_{}.txt", ts)));
    }
    if cli
        .threat_score
        .as_ref()
        .is_some_and(|p| p.as_os_str() == "auto")
    {
        cli.threat_score = Some(PathBuf::from(format!("muninn_scores_{}.txt", ts)));
    }
    if cli
        .login_analysis
        .as_ref()
        .is_some_and(|p| p.as_os_str() == "auto")
    {
        cli.login_analysis = Some(PathBuf::from(format!("muninn_logins_{}.txt", ts)));
    }
    if cli
        .summary
        .as_ref()
        .is_some_and(|p| p.as_os_str() == "auto")
    {
        cli.summary = Some(PathBuf::from(format!("muninn_summary_{}.txt", ts)));
    }
    if cli
        .template_output
        .as_ref()
        .is_some_and(|p| p.as_os_str() == "auto")
    {
        let ext = match cli.template.as_deref() {
            Some("csv") => "csv",
            Some("sarif") => "sarif.json",
            _ => "json",
        };
        cli.template_output = Some(PathBuf::from(format!("muninn_export_{}.{}", ts, ext)));
    }

    /// Save report to file: .html → HTML table, .json → JSON, else plain text.
    fn save_report(
        path: &std::path::Path,
        title: &str,
        text: &str,
        data: &impl serde::Serialize,
    ) -> Result<()> {
        match path.extension().and_then(|e| e.to_str()) {
            Some("html") | Some("htm") => {
                let json = serde_json::to_string(data)?;
                let html = muninn::output::render_html_table(title, &json);
                std::fs::write(path, html)?;
            }
            Some("json") => {
                std::fs::write(path, serde_json::to_string_pretty(data)?)?;
            }
            _ => {
                std::fs::write(path, text)?;
            }
        }
        Ok(())
    }

    // Load field mapping if provided
    let field_map: Option<HashMap<String, String>> = if let Some(ref map_path) = cli.field_map {
        let content = std::fs::read_to_string(map_path)
            .context(format!("Failed to read field map {:?}", map_path))?;
        Some(
            serde_yaml::from_str(&content)
                .context(format!("Failed to parse field map {:?}", map_path))?,
        )
    } else {
        None
    };

    if !cli.quiet {
        println!();
        // Norse/Corax banner: frost → steel → deep night gradient
        let b = "\u{2588}"; // █
        let banner_lines: Vec<String> = vec![
            format!("{b}{b}{b}    {b}{b}{b}  {b}{b}    {b}{b}  {b}{b}{b}    {b}{b}  {b}{b}  {b}{b}{b}    {b}{b}  {b}{b}{b}    {b}{b}"),
            format!("{b}{b}{b}{b}  {b}{b}{b}{b}  {b}{b}    {b}{b}  {b}{b}{b}{b}   {b}{b}  {b}{b}  {b}{b}{b}{b}   {b}{b}  {b}{b}{b}{b}   {b}{b}"),
            format!("{b}{b} {b}{b}{b}{b} {b}{b}  {b}{b}    {b}{b}  {b}{b} {b}{b}  {b}{b}  {b}{b}  {b}{b} {b}{b}  {b}{b}  {b}{b} {b}{b}  {b}{b}"),
            format!("{b}{b}  {b}{b}  {b}{b}  {b}{b}    {b}{b}  {b}{b}  {b}{b} {b}{b}  {b}{b}  {b}{b}  {b}{b} {b}{b}  {b}{b}  {b}{b} {b}{b}"),
            format!("{b}{b}  {b}{b}  {b}{b}  {b}{b}    {b}{b}  {b}{b}   {b}{b}{b}{b}  {b}{b}  {b}{b}   {b}{b}{b}{b}  {b}{b}   {b}{b}{b}{b}"),
            format!("{b}{b}      {b}{b}   {b}{b}{b}{b}{b}{b}   {b}{b}    {b}{b}{b}  {b}{b}  {b}{b}    {b}{b}{b}  {b}{b}    {b}{b}{b}"),
        ];
        let colors: [(u8, u8, u8); 6] = [
            (210, 225, 240), // frost
            (175, 195, 225), // pale ice
            (140, 165, 205), // silver steel
            (100, 130, 180), // cold blue
            (65, 95, 150),   // deep steel
            (35, 60, 115),   // night
        ];
        for (line, &(r, g, b)) in banner_lines.iter().zip(colors.iter()) {
            println!("  {}", line.truecolor(r, g, b).bold());
        }
        println!(
            "              {}",
            "Memory of Corax".truecolor(160, 175, 200)
        );
        println!(
            "  {}",
            format!(
                "-= SIGMA Detection Engine for EVTX/JSON/Syslog/CEF/Zeek v{} =-",
                env!("CARGO_PKG_VERSION")
            )
            .truecolor(90, 110, 145)
        );
        println!();
    }

    // Pre-compile SIGMA rules if provided (needed before streaming and load-db)
    let compiled_rules: Option<Vec<(muninn::sigma::Rule, String)>> =
        if let Some(ref rules_path) = cli.rules {
            let mut rules = sigma::load_rules(rules_path)
                .context(format!("Failed to load SIGMA rules from {:?}", rules_path))?;
            let min_rank = level_rank(&cli.min_level);

            if !cli.rulefilter.is_empty() {
                let before_count = rules.len();
                rules.retain(|r| {
                    !cli.rulefilter
                        .iter()
                        .any(|pat| r.title.to_lowercase().contains(&pat.to_lowercase()))
                });
                if !cli.quiet && rules.len() < before_count {
                    println!(
                        "  {} Filtered {} rules (excluded {})",
                        "✓".green(),
                        rules.len(),
                        before_count - rules.len()
                    );
                }
            }

            if !cli.quiet {
                println!(
                    "  {} {} SIGMA rules loaded",
                    "[+]".green().bold(),
                    rules.len().to_string().bold()
                );
            }

            let compile_start = Instant::now();
            let compiled: Vec<_> = {
                use rayon::prelude::*;
                rules
                    .par_iter()
                    .filter(|r| level_rank(&r.level) >= min_rank)
                    .filter_map(|r| match sigma::compile(r) {
                        Ok(sql) => Some((r.clone(), sql)),
                        Err(e) => {
                            log::debug!("Rule '{}' compile error: {}", r.title, e);
                            None
                        }
                    })
                    .collect()
            };

            if !cli.quiet && compiled.len() > 50 {
                println!(
                    "  {} Pre-compiled {} rules in {:.0}ms",
                    "✓".green(),
                    compiled.len(),
                    compile_start.elapsed().as_millis()
                );
            }
            Some(compiled)
        } else {
            None
        };

    let mut total_events = 0usize;
    let filtered_events = 0usize;
    let mut format_stats: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut parse_errors: Vec<String> = Vec::new();
    let mut merged_ioc_collector: Option<muninn::ioc::IocCollector> = None;
    let field_counts: std::sync::Mutex<HashMap<String, usize>> =
        std::sync::Mutex::new(HashMap::new());

    // Branch: load from saved database or parse from files
    let (engine, mut results, files, source_files, workers) = if let Some(ref db_path) = cli.load_db
    {
        // --load-db: skip all parsing, load pre-saved SQLite database
        if !cli.quiet {
            println!("  {} Loading database from {:?}...", "▶".cyan(), db_path);
        }
        let eng = muninn::search::SearchEngine::from_file(db_path)
            .context(format!("Failed to load database from {:?}", db_path))?;
        total_events = eng.event_count();
        if !cli.quiet {
            println!(
                "  {} Loaded {} events from {:?}",
                "✓".green(),
                eng.event_count(),
                db_path
            );
        }

        // Run SIGMA rules against the loaded engine
        let mut db_results: Vec<Detection> = Vec::new();
        if let Some(ref compiled) = compiled_rules {
            let sigma_limit = cli.limit;
            let sigma_pb = if !cli.quiet {
                let pb = ProgressBar::new(compiled.len() as u64);
                pb.set_style(
                    ProgressStyle::default_bar()
                        .template(
                            "  \u{1f50d} SIGMA rules [{bar:40.cyan/blue}] {pos}/{len} | {msg}",
                        )
                        .unwrap()
                        .progress_chars("\u{2588}\u{2591} "),
                );
                Some(pb)
            } else {
                None
            };
            for (rule, sql) in compiled {
                if let Some(ref pb) = sigma_pb {
                    let title: String = rule.title.chars().take(40).collect();
                    pb.set_message(title);
                    pb.inc(1);
                }
                let effective_limit = sigma_limit.unwrap_or(200);
                let query_result = eng.query_sql_with_limit(sql, effective_limit);
                if let Ok(r) = query_result {
                    if r.count > 0 {
                        let confidence = compute_confidence(rule, &r.rows);
                        db_results.push(Detection {
                            title: rule.title.clone(),
                            level: rule.level.clone(),
                            description: rule.description.clone(),
                            id: rule.id.clone(),
                            author: rule.author.clone(),
                            tags: rule.tags.clone(),
                            result: r,
                            confidence,
                        });
                    }
                }
            }
            if let Some(pb) = sigma_pb {
                pb.finish_and_clear();
            }
            if !cli.quiet {
                println!(
                    "  {} Executing ruleset: {} rules matched\n",
                    "[+]".green().bold(),
                    db_results.len().to_string().bold(),
                );
            }
        }

        let workers = cli.workers.unwrap_or(1);
        let files: Vec<PathBuf> = Vec::new();
        let source_files: Vec<SourceFile> = Vec::new();
        (eng, db_results, files, source_files, workers)
    } else {
        // Normal flow: parse events from files
        let events_path = cli
            .events
            .as_ref()
            .expect("events required when --load-db not set");

        let mut files = parsers::discover_files(
            events_path,
            cli.select.as_deref(),
            cli.avoid.as_deref(),
            true,
        )?;

        // Extract archives and discover log files inside them
        #[cfg(feature = "archive")]
        let _archive_temps: Vec<tempfile::TempDir> = {
            let mut temps = Vec::new();
            let mut extra_files = Vec::new();
            let archive_paths: Vec<_> = files
                .iter()
                .filter(|f| parsers::archive::is_archive(f))
                .cloned()
                .collect();
            for archive_path in &archive_paths {
                match parsers::archive::extract_to_temp_with_password(
                    archive_path,
                    cli.archive_password.as_deref(),
                ) {
                    Ok((tmp_dir, extracted)) => {
                        log::info!(
                            "Extracted {} files from {:?}",
                            extracted.len(),
                            archive_path
                        );
                        extra_files.extend(extracted);
                        temps.push(tmp_dir);
                    }
                    Err(e) => {
                        log::warn!("Failed to extract archive {:?}: {}", archive_path, e);
                    }
                }
            }
            // Remove archive files from the file list and add extracted files
            files.retain(|f| !parsers::archive::is_archive(f));
            files.extend(extra_files);
            temps
        };

        // Sort files largest-first so big files start early and don't overlap at the end
        files.sort_by(|a, b| {
            let sa = std::fs::metadata(a).map(|m| m.len()).unwrap_or(0);
            let sb = std::fs::metadata(b).map(|m| m.len()).unwrap_or(0);
            sb.cmp(&sa)
        });

        if files.is_empty() {
            if !cli.quiet {
                println!("  {} No log files found in {:?}", "✗".red(), events_path);
            }
            return Ok(());
        }

        // Evidence integrity: SHA-256 hash all source files
        let hash_pb = if !cli.quiet && files.len() > 10 {
            let pb = ProgressBar::new(files.len() as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("  \u{1f512} Hashing [{bar:40.cyan/blue}] {pos}/{len} files")
                    .unwrap()
                    .progress_chars("\u{2588}\u{2591} "),
            );
            Some(pb)
        } else {
            None
        };
        let source_files: Vec<SourceFile> = files
            .iter()
            .filter_map(|f| {
                let size_bytes = std::fs::metadata(f).map(|m| m.len()).unwrap_or(0);
                let result = match hash_file_sha256(f) {
                    Ok(sha256) => Some(SourceFile {
                        path: f.to_string_lossy().to_string(),
                        sha256,
                        size_bytes,
                    }),
                    Err(e) => {
                        log::warn!("Failed to hash {:?}: {}", f, e);
                        None
                    }
                };
                if let Some(ref pb) = hash_pb {
                    pb.inc(1);
                }
                result
            })
            .collect();
        if let Some(pb) = hash_pb {
            pb.finish_and_clear();
        }
        if !cli.quiet {
            println!(
                "  {} Evidence integrity: {} files hashed (SHA-256)",
                "\u{2713}".green(),
                source_files.len()
            );
        }

        // Pre-compute file sizes for progress tracking
        let file_sizes: Vec<u64> = files
            .iter()
            .map(|f| std::fs::metadata(f).map(|m| m.len()).unwrap_or(0))
            .collect();
        let total_size_bytes: u64 = file_sizes.iter().sum();

        let pb = if !cli.quiet {
            let pb = ProgressBar::new(total_size_bytes);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template(
                        "  {spinner:.green} [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}) | {msg}",
                    )
                    .unwrap()
                    .progress_chars("█▉▊▋▌▍▎▏ "),
            );
            Some(pb)
        } else {
            None
        };

        // Build early event filter from rules (if available)
        let event_filter = if let Some(ref rules_path) = cli.rules {
            match sigma::load_rules(rules_path) {
                Ok(rules) => {
                    let filter = muninn::EventFilter::from_rules(&rules);
                    if !filter.is_pass_all() && !cli.quiet {
                        println!(
                            "  {} Early filter active ({} field constraints)",
                            "✓".green(),
                            filter.field_count()
                        );
                    }
                    Some(filter)
                }
                Err(_) => None,
            }
        } else {
            None
        };

        // Configure thread pool: default to half of available cores (min 1, max 4)
        let workers = cli.workers.unwrap_or_else(|| {
            let cpus = std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(2);
            (cpus / 2).clamp(1, 4)
        });
        rayon::ThreadPoolBuilder::new()
            .num_threads(workers)
            .build_global()
            .ok();

        let batch_size = cli.batch_size.unwrap_or(50_000);
        let max_events = cli.max_events;

        // Use on-disk SQLite when --dbfile is specified (no RAM limit)
        let mut engine = if let Some(ref dbpath) = cli.dbfile {
            if !cli.quiet {
                println!(
                    "  {} Writing directly to {:?} (disk-backed, no RAM limit)",
                    "\u{25b6}".cyan(),
                    dbpath
                );
            }
            SearchEngine::new_on_disk(dbpath)?
        } else {
            SearchEngine::new()?
        };

        // Determine if unified SQLite engine is needed (for search/SQL/anomaly features)
        let needs_unified_engine = cli.keyword.is_some()
            || cli.field_search.is_some()
            || cli.sql.is_some()
            || cli.sql_file.is_some()
            || cli.regex_search.is_some()
            || cli.distinct.is_some()
            || cli.dbfile.is_some()
            || cli.anomalies.is_some()
            || !cli.add_index.is_empty()
            || !cli.remove_index.is_empty()
            || cli.keepflat.is_some()
            || cli.after.is_some()
            || cli.before.is_some()
            || cli.login_analysis.is_some();

        // Streaming pipeline: parse + SIGMA + stats per file, free memory after each
        let do_transforms = cli.transforms;
        let do_hashes = cli.hashes;
        let do_stats = cli.stats;
        let do_ioc_extract = cli.ioc_extract.is_some();
        let ioc_max = cli.ioc_max;

        use rayon::prelude::*;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let atomic_total_events = AtomicUsize::new(0);
        let sigma_limit = cli.limit;
        let pb_ref = &pb;
        let file_sizes_ref = &file_sizes;

        // Per-file results: (file_path, event_count, format, detections, parse_error, ioc_collector)
        type FileResult = (
            PathBuf,
            usize,
            Option<String>,
            Vec<Detection>,
            Option<String>,
            Option<muninn::ioc::IocCollector>,
        );

        let file_results: Vec<FileResult> = files
            .par_iter()
            .enumerate()
            .map(|(file_idx, file)| {
                let fname = file
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let file_size = file_sizes_ref[file_idx];

                if let Some(ref bar) = pb_ref {
                    bar.set_message(fname.clone());
                }

                // Detect format to decide streaming vs batch
                let format = parsers::detect_format(file).ok();
                let is_evtx = matches!(format, Some(muninn::model::SourceFormat::Evtx));
                let format_name = format
                    .as_ref()
                    .map(|f| f.to_string())
                    .unwrap_or_else(|| "unknown".to_string());

                // Helper: process a batch of events (transforms, hashes, filter, stats)
                let process_batch = |batch: &mut Vec<muninn::model::Event>| {
                    if let Some(ref fmap) = field_map {
                        for ev in batch.iter_mut() {
                            ev.apply_field_map(fmap);
                        }
                    }
                    if do_transforms {
                        muninn::transforms::apply_transforms(
                            batch,
                            &muninn::transforms::default_transforms(),
                        );
                    }
                    if do_hashes {
                        for ev in batch.iter_mut() {
                            ev.compute_hash();
                        }
                    }
                    if let Some(ref filter) = event_filter {
                        batch.retain(|ev| filter.matches(ev));
                    }
                    if do_stats {
                        let mut local_counts: HashMap<String, usize> = HashMap::new();
                        for ev in batch.iter() {
                            for (k, v) in &ev.fields {
                                if !v.is_empty() {
                                    *local_counts.entry(k.clone()).or_default() += 1;
                                }
                            }
                        }
                        if let Ok(mut global) = field_counts.lock() {
                            for (k, c) in local_counts {
                                *global.entry(k).or_default() += c;
                            }
                        }
                    }
                };

                // Create per-file SIGMA engine if rules are provided
                let mut file_engine = if compiled_rules.is_some() {
                    match SearchEngine::new() {
                        Ok(e) => Some(e),
                        Err(_) => {
                            if let Some(ref bar) = pb_ref {
                                bar.inc(file_size);
                            }
                            return (file.clone(), 0, Some(format_name), Vec::new(), None, None);
                        }
                    }
                } else {
                    None
                };

                let mut event_count = 0usize;
                let mut ioc_collector = if do_ioc_extract {
                    Some(muninn::ioc::IocCollector::with_max_entries(ioc_max))
                } else {
                    None
                };

                if is_evtx {
                    // STREAMING path for EVTX: never hold all events in RAM
                    let rx = match muninn::parsers::evtx::parse_streaming(file) {
                        Ok(rx) => rx,
                        Err(e) => {
                            let msg = format!("{}: {}", fname, e);
                            if let Some(ref bar) = pb_ref {
                                bar.inc(file_size);
                            }
                            return (
                                file.clone(),
                                0,
                                Some(format_name),
                                Vec::new(),
                                Some(msg),
                                None,
                            );
                        }
                    };

                    // Track progress within file: estimate bytes from event count
                    let mut reported_bytes: u64 = 0;

                    let mut batch: Vec<muninn::model::Event> = Vec::with_capacity(batch_size);
                    for ev in rx {
                        // Check max_events
                        if let Some(max) = max_events {
                            if atomic_total_events.load(Ordering::Relaxed) >= max {
                                break;
                            }
                        }
                        batch.push(ev);
                        if batch.len() >= batch_size {
                            process_batch(&mut batch);
                            if let Some(ref mut col) = ioc_collector {
                                col.process_events(&batch);
                            }
                            event_count += batch.len();
                            atomic_total_events.fetch_add(batch.len(), Ordering::Relaxed);
                            if let Some(ref mut eng) = file_engine {
                                let _ = eng.load_events(&batch);
                            }
                            // Incremental progress: estimate bytes from raw sizes
                            if let Some(ref bar) = pb_ref {
                                let batch_bytes: u64 =
                                    batch.iter().map(|e| e.raw.len() as u64 + 200).sum();
                                let increment = batch_bytes.min(file_size - reported_bytes);
                                bar.inc(increment);
                                reported_bytes += increment;
                            }
                            batch.clear();
                        }
                    }
                    // Flush remaining
                    if !batch.is_empty() {
                        process_batch(&mut batch);
                        if let Some(ref mut col) = ioc_collector {
                            col.process_events(&batch);
                        }
                        event_count += batch.len();
                        atomic_total_events.fetch_add(batch.len(), Ordering::Relaxed);
                        if let Some(ref mut eng) = file_engine {
                            let _ = eng.load_events(&batch);
                        }
                    }
                    // Correct to exact file size
                    if let Some(ref bar) = pb_ref {
                        if reported_bytes < file_size {
                            bar.inc(file_size - reported_bytes);
                        }
                    }
                } else {
                    // BATCH path for non-EVTX (typically small files)
                    let mut pr = match parsers::parse_file(file) {
                        Ok(pr) => pr,
                        Err(e) => {
                            let msg = format!("{}: {}", fname, e);
                            if let Some(ref bar) = pb_ref {
                                bar.inc(file_size);
                            }
                            return (file.clone(), 0, None, Vec::new(), Some(msg), None);
                        }
                    };

                    // Apply max_events limit
                    if let Some(max) = max_events {
                        let current = atomic_total_events.load(Ordering::Relaxed);
                        if current >= max {
                            if let Some(ref bar) = pb_ref {
                                bar.inc(file_size);
                            }
                            return (file.clone(), 0, Some(format_name), Vec::new(), None, None);
                        }
                        let remaining = max - current;
                        if pr.events.len() > remaining {
                            pr.events.truncate(remaining);
                        }
                    }

                    process_batch(&mut pr.events);
                    if let Some(ref mut col) = ioc_collector {
                        col.process_events(&pr.events);
                    }
                    event_count = pr.events.len();
                    atomic_total_events.fetch_add(event_count, Ordering::Relaxed);

                    if let Some(ref mut eng) = file_engine {
                        let _ = eng.load_events(&pr.events);
                    }
                    drop(pr);
                }

                // Run SIGMA rules
                let detections = if let Some(ref mut eng) = file_engine {
                    let _ = eng.create_indexes();
                    let mut file_detections = Vec::new();
                    if let Some(ref compiled) = compiled_rules {
                        for (rule, sql) in compiled {
                            let effective_limit = sigma_limit.unwrap_or(200);
                            let query_result = eng.query_sql_with_limit(sql, effective_limit);
                            if let Ok(r) = query_result {
                                if r.count > 0 {
                                    let confidence = compute_confidence(rule, &r.rows);
                                    file_detections.push(Detection {
                                        title: rule.title.clone(),
                                        level: rule.level.clone(),
                                        description: rule.description.clone(),
                                        id: rule.id.clone(),
                                        author: rule.author.clone(),
                                        tags: rule.tags.clone(),
                                        result: r,
                                        confidence,
                                    });
                                }
                            }
                        }
                    }
                    file_detections
                } else {
                    Vec::new()
                };

                // Non-EVTX: report full file size at once (EVTX already reported incrementally)
                if !is_evtx {
                    if let Some(ref bar) = pb_ref {
                        bar.inc(file_size);
                    }
                }

                (
                    file.clone(),
                    event_count,
                    Some(format_name),
                    detections,
                    None,
                    ioc_collector,
                )
            })
            .collect();

        // Aggregate results from streaming pipeline
        for (_file, count, fmt, _, err, _) in &file_results {
            if let Some(ref msg) = err {
                parse_errors.push(msg.clone());
                if !cli.quiet {
                    eprintln!("  {} {}", "✗".red(), msg);
                }
            }
            if let Some(ref f) = fmt {
                *format_stats.entry(f.clone()).or_default() += count;
            }
            total_events += count;
        }

        // Merge SIGMA detections and IOC collectors from per-file results
        let results: Vec<Detection>;
        {
            let mut merged: HashMap<String, Detection> = HashMap::new();
            for (_, _, _, detections, _, file_ioc) in file_results {
                // Merge IOC collectors
                if let Some(col) = file_ioc {
                    match merged_ioc_collector {
                        Some(ref mut m) => m.merge(col),
                        None => merged_ioc_collector = Some(col),
                    }
                }
                for det in detections {
                    let entry = merged.entry(det.title.clone()).or_insert(Detection {
                        title: det.title.clone(),
                        level: det.level.clone(),
                        description: det.description.clone(),
                        id: det.id.clone(),
                        author: det.author.clone(),
                        tags: det.tags.clone(),
                        result: muninn::SearchResult {
                            rows: Vec::new(),
                            count: 0,
                            query: det.result.query.clone(),
                            duration_ms: 0,
                        },
                        confidence: det.confidence.clone(),
                    });
                    // Any low-confidence file → merged detection is low
                    if det.confidence == "low" {
                        entry.confidence = "low".to_string();
                    }
                    entry.result.count += det.result.count;
                    entry.result.duration_ms += det.result.duration_ms;
                    if entry.result.rows.len() < 200 {
                        let take = (200 - entry.result.rows.len()).min(det.result.rows.len());
                        entry
                            .result
                            .rows
                            .extend(det.result.rows.into_iter().take(take));
                    }
                }
            }
            results = merged.into_values().collect();

            if compiled_rules.is_some() && !cli.quiet {
                println!(
                    "  {} Executing ruleset: {} rules matched across {} files\n",
                    "[+]".green().bold(),
                    results.len().to_string().bold(),
                    files.len()
                );
            }
        }

        // Load unified engine only if features require it (sequential, after streaming)
        // Skip if engine is already on-disk (--dbfile) — events were written during streaming
        let skip_unified_load = cli.dbfile.is_some();
        if needs_unified_engine && !skip_unified_load {
            let load_pb = if !cli.quiet && total_size_bytes > 0 {
                let pb = ProgressBar::new(total_size_bytes);
                pb.set_style(
                    ProgressStyle::default_bar()
                        .template("  \u{25b6} Loading into DB [{bar:40.cyan/blue}] {bytes}/{total_bytes} | {msg}")
                        .unwrap()
                        .progress_chars("\u{2588}\u{2591} "),
                );
                Some(pb)
            } else {
                if !cli.quiet {
                    println!(
                        "  {} Loading events into search engine...",
                        "\u{25b6}".cyan()
                    );
                }
                None
            };

            for file in &files {
                let file_size = std::fs::metadata(file).map(|m| m.len()).unwrap_or(0);
                if let Some(ref pb) = load_pb {
                    let fname = file
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();
                    pb.set_message(fname);
                }

                let is_evtx = file
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("evtx"));
                if is_evtx {
                    if let Ok(rx) = muninn::parsers::evtx::parse_streaming(file) {
                        let mut batch = Vec::with_capacity(batch_size);
                        for ev in rx {
                            batch.push(ev);
                            if batch.len() >= batch_size {
                                engine.load_events(&batch)?;
                                batch.clear();
                            }
                        }
                        if !batch.is_empty() {
                            engine.load_events(&batch)?;
                        }
                    }
                } else if let Ok(pr) = parsers::parse_file(file) {
                    let n = pr.events.len();
                    if n > batch_size {
                        for chunk in pr.events.chunks(batch_size) {
                            engine.load_events(chunk)?;
                        }
                    } else {
                        engine.load_events(&pr.events)?;
                    }
                }

                if let Some(ref pb) = load_pb {
                    pb.inc(file_size);
                }
            }

            if let Some(pb) = load_pb {
                pb.finish_and_clear();
            }
        }

        if let Some(pb) = pb {
            pb.set_position(total_size_bytes);
            pb.finish_and_clear();
        }

        (engine, results, files, source_files, workers)
    };

    // Apply time filter
    if cli.after.is_some() || cli.before.is_some() {
        if let Some(time_field) = engine.detect_time_field() {
            let deleted = engine.apply_time_filter(
                &time_field,
                cli.after.as_deref(),
                cli.before.as_deref(),
            )?;
            if !cli.quiet && deleted > 0 {
                println!(
                    "  {} Filtered {} events by time range (field: {})",
                    "✓".green(),
                    deleted,
                    time_field
                );
            }
        } else if !cli.quiet {
            println!(
                "  {} No timestamp field detected, --after/--before ignored",
                "⚠".yellow()
            );
        }
    }

    // Create indexes only when queries/analysis will use them
    let needs_indexes = cli.keyword.is_some()
        || cli.field_search.is_some()
        || cli.sql.is_some()
        || cli.sql_file.is_some()
        || cli.regex_search.is_some()
        || cli.distinct.is_some()
        || cli.anomalies.is_some()
        || cli.login_analysis.is_some()
        || cli.ioc_extract.is_some()
        || compiled_rules.is_some()
        || !cli.add_index.is_empty();

    if needs_indexes {
        if !cli.quiet && total_events > 10000 {
            let idx_pb = ProgressBar::new_spinner();
            idx_pb.set_style(
                ProgressStyle::default_spinner()
                    .template("  {spinner:.green} Creating indexes...")
                    .unwrap(),
            );
            idx_pb.enable_steady_tick(std::time::Duration::from_millis(80));
            engine.create_indexes()?;
            idx_pb.finish_and_clear();
        } else {
            engine.create_indexes()?;
        }
    }

    // Custom index management
    for field in &cli.add_index {
        engine.create_index_on(field)?;
        if !cli.quiet {
            println!("  {} Index created on \"{}\"", "✓".green(), field);
        }
    }
    for idx in &cli.remove_index {
        engine.drop_index(idx)?;
        if !cli.quiet {
            println!("  {} Index \"{}\" removed", "✓".green(), idx);
        }
    }

    // Export flattened JSONL
    if let Some(ref flat_path) = cli.keepflat {
        let count = engine.export_jsonl(flat_path)?;
        if !cli.quiet {
            println!(
                "  {} Exported {} events → {:?}",
                "✓".green(),
                count,
                flat_path
            );
        }
    }

    if !cli.quiet {
        let formats: Vec<String> = format_stats
            .iter()
            .map(|(f, c)| format!("{} {}", c, f))
            .collect();

        // Zircolite-style Processing section
        println!(
            "  {} {}",
            "[+]".green().bold(),
            "Processing".bold().underline()
        );
        println!(
            "    {} Files       {}",
            "[>]".cyan(),
            format!("{}", files.len()).bold()
        );
        println!(
            "    {} Events      {}",
            "[>]".cyan(),
            format!("{}", total_events).bold()
        );
        println!("    {} Formats     {}", "[>]".cyan(), formats.join(", "));
        if filtered_events > 0 {
            println!(
                "    {} Filtered    {} events excluded by early filter",
                "[>]".cyan(),
                filtered_events
            );
        }
        println!(
            "    {} Duration    {:.2}s ({:.0} events/s)",
            "[>]".cyan(),
            start.elapsed().as_secs_f64(),
            if start.elapsed().as_secs_f64() > 0.0 {
                total_events as f64 / start.elapsed().as_secs_f64()
            } else {
                total_events as f64
            }
        );
        let worker_count = workers;
        println!(
            "    {} Workers     {} threads",
            "[>]".cyan(),
            format!("{}", worker_count).bold()
        );
        if let Some(max) = cli.max_events {
            println!(
                "    {} Max Events  {}",
                "[>]".cyan(),
                format!("{}", max).bold()
            );
        }
        println!();
    }

    if let Some(ref dbfile) = cli.dbfile {
        // If engine is already on-disk (new_on_disk was used), no export needed
        // Otherwise, export in-memory DB to file
        if cli.load_db.is_some() {
            // --load-db + --dbfile: skip (already loaded from file)
        } else if !dbfile.exists() {
            // In-memory engine: export to disk
            engine.export_db(dbfile)?;
        }
        // else: already written on disk via new_on_disk
        if !cli.quiet {
            let size = std::fs::metadata(dbfile).map(|m| m.len()).unwrap_or(0);
            let size_mb = size as f64 / 1_048_576.0;
            println!(
                "  {} Database → {:?} ({:.1} MB, {} events)",
                "✓".green(),
                dbfile,
                size_mb,
                engine.event_count()
            );
        }
    }

    if cli.stats {
        // Stats computed during streaming pipeline
        let fc = field_counts.into_inner().unwrap_or_default();
        println!("\n  {:<40} {}", "Field".bold(), "Count".bold());
        println!("  {}", "─".repeat(52));
        let mut fields: Vec<_> = fc.iter().collect();
        fields.sort_by(|a, b| b.1.cmp(a.1));
        for (name, count) in fields.iter().take(30) {
            if name.starts_with('_') {
                continue;
            }
            println!("  {:<40} {}", name, count);
        }
        println!("  {}", "─".repeat(52));
        println!("  {} fields, {} events\n", fc.len(), total_events);
    }

    if let Some(ref field) = cli.distinct {
        let values = engine.distinct_values(field)?;
        println!("\n  Distinct \"{}\" ({} values):", field, values.len());
        for v in &values {
            println!("    {}", v);
        }
        println!();
    }

    if compiled_rules.is_some() {
        // Profile rules: show sorted execution time table
        if cli.profile_rules && !cli.quiet && !results.is_empty() {
            let mut profile: Vec<(&str, u64, usize)> = results
                .iter()
                .map(|d| (d.title.as_str(), d.result.duration_ms, d.result.count))
                .collect();
            profile.sort_by(|a, b| b.1.cmp(&a.1));

            println!("  {}", "Rule Performance Profile".bold().underline());
            println!(
                "  {:<50} {:>8} {:>8}",
                "Rule".bold(),
                "Time(ms)".bold(),
                "Matches".bold()
            );
            println!("  {}", "─".repeat(68));
            for (title, ms, count) in &profile {
                let title_display: String = title.chars().take(48).collect();
                let time_str = if *ms >= 500 {
                    format!("{}", ms).red().to_string()
                } else if *ms >= 100 {
                    format!("{}", ms).yellow().to_string()
                } else {
                    format!("{}", ms)
                };
                println!("  {:<50} {:>8} {:>8}", title_display, time_str, count);
            }
            println!("  {}\n", "─".repeat(68));
        }
    }

    if let Some(ref sql_path) = cli.sql_file {
        let content = std::fs::read_to_string(sql_path)?;
        for line in content.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            let (label, sql) = if t.contains("|||") {
                let mut parts = t.splitn(2, "|||");
                (
                    parts.next().unwrap_or("rule").to_string(),
                    parts.next().unwrap_or("").to_string(),
                )
            } else {
                ("sql".to_string(), t.to_string())
            };

            match engine.query_sql(&sql) {
                Ok(r) if r.count > 0 => results.push(Detection {
                    title: label,
                    level: "medium".into(),
                    description: String::new(),
                    id: String::new(),
                    author: String::new(),
                    tags: Vec::new(),
                    result: r,
                    confidence: "high".into(),
                }),
                Ok(_) => {}
                Err(e) => {
                    if !cli.quiet {
                        eprintln!("  {} {}: {}", "✗".red(), label, e);
                    }
                }
            }
        }
    }

    if let Some(ref sql) = cli.sql {
        let r = engine.query_sql(sql)?;
        results.push(Detection {
            title: "SQL query".into(),
            level: "medium".into(),
            description: String::new(),
            id: String::new(),
            author: String::new(),
            tags: Vec::new(),
            result: r,
            confidence: "high".into(),
        });
    }

    if let Some(ref kw) = cli.keyword {
        let r = engine.search_keyword(kw)?;
        results.push(Detection {
            title: format!("keyword: {}", kw),
            level: "medium".into(),
            description: String::new(),
            id: String::new(),
            author: String::new(),
            tags: Vec::new(),
            result: r,
            confidence: "high".into(),
        });
    }

    if let Some(ref fs) = cli.field_search {
        if let Some((field, pattern)) = fs.split_once('=') {
            let r = engine.search_field(field, pattern)?;
            results.push(Detection {
                title: format!("{}={}", field, pattern),
                level: "medium".into(),
                description: String::new(),
                id: String::new(),
                author: String::new(),
                tags: Vec::new(),
                result: r,
                confidence: "high".into(),
            });
        } else {
            anyhow::bail!("--field requires format FIELD=PATTERN, got: {:?}", fs);
        }
    }

    if let Some(ref rs) = cli.regex_search {
        if let Some((field, pattern)) = rs.split_once('=') {
            let r = engine.search_regex(field, pattern)?;
            results.push(Detection {
                title: format!("{} =~ /{}/", field, pattern),
                level: "medium".into(),
                description: String::new(),
                id: String::new(),
                author: String::new(),
                tags: Vec::new(),
                result: r,
                confidence: "high".into(),
            });
        } else {
            anyhow::bail!("--regex requires format FIELD=PATTERN, got: {:?}", rs);
        }
    }

    if !results.is_empty() {
        results.sort_by(|a, b| {
            level_rank(&b.level)
                .cmp(&level_rank(&a.level))
                .then(b.result.count.cmp(&a.result.count))
        });

        let mapper = muninn::mitre::MitreMapper::new();

        if !cli.quiet {
            let total_matches: usize = results.iter().map(|d| d.result.count).sum();
            let total_rules_loaded = if let Some(ref rules_path) = cli.rules {
                sigma::load_rules(rules_path).map(|r| r.len()).unwrap_or(0)
            } else {
                0
            };

            // Detection table header
            println!(
                "  {}",
                "┌──────────────┬────────────────────────────────────────────────────┬────────┬──────────────┐"
                    .cyan()
            );
            println!(
                "  {} {:<12} {} {:<50} {} {:>6} {} {:<12} {}",
                "│".cyan(),
                "Severity".bold(),
                "│".cyan(),
                "Rule".bold(),
                "│".cyan(),
                "Events".bold(),
                "│".cyan(),
                "ATT&CK".bold(),
                "│".cyan()
            );
            println!(
                "  {}",
                "├──────────────┼────────────────────────────────────────────────────┼────────┼──────────────┤"
                    .cyan()
            );

            for d in &results {
                let mitre_refs = muninn::mitre::MitreMapper::parse_tags(&d.tags);
                let techniques = mapper.resolve_refs(&mitre_refs);
                let mitre_str = if techniques.is_empty() {
                    String::new()
                } else {
                    techniques
                        .iter()
                        .map(|t| t.id.clone())
                        .collect::<Vec<_>>()
                        .join(",")
                };

                let title_display: String = d.title.chars().take(50).collect();
                let mitre_display: String = mitre_str.chars().take(12).collect();
                let sev_display = if d.confidence == "low" {
                    format!("{}~", level_color(&d.level))
                } else {
                    level_color(&d.level).to_string()
                };

                println!(
                    "  {} {:<12} {} {:<50} {} {:>6} {} {:<12} {}",
                    "│".cyan(),
                    sev_display,
                    "│".cyan(),
                    title_display,
                    "│".cyan(),
                    d.result.count,
                    "│".cyan(),
                    mitre_display,
                    "│".cyan()
                );
            }

            println!(
                "  {}",
                "└──────────────┴────────────────────────────────────────────────────┴────────┴──────────────┘"
                    .cyan()
            );
            println!();

            // Summary box
            let elapsed = start.elapsed().as_secs_f64();
            let throughput = if elapsed > 0.0 {
                total_events as f64 / elapsed
            } else {
                total_events as f64
            };

            let coverage_pct = if total_rules_loaded > 0 {
                (results.len() as f64 / total_rules_loaded as f64) * 100.0
            } else {
                0.0
            };

            // Count by severity
            let crit_count = results.iter().filter(|d| level_rank(&d.level) == 5).count();
            let high_count = results.iter().filter(|d| level_rank(&d.level) == 4).count();
            let med_count = results.iter().filter(|d| level_rank(&d.level) == 3).count();
            let low_count = results.iter().filter(|d| level_rank(&d.level) <= 2).count();

            // Coverage bar
            let bar_width = 30;
            let filled = ((coverage_pct / 100.0) * bar_width as f64) as usize;
            let bar: String = format!(
                "{}{}",
                "█".repeat(filled.min(bar_width)),
                "░".repeat(bar_width - filled.min(bar_width))
            );

            println!("  {} {}", "✦".cyan().bold(), "Summary".bold().underline());
            println!(
                "  {}",
                "╭──────────────────────────────────────────────────────────────╮".dimmed()
            );
            println!(
                "  {}  {} Duration      {}",
                "│".dimmed(),
                "⏱".dimmed(),
                format!("{:.2}s", elapsed).bold()
            );
            println!(
                "  {}  {} Files         {}",
                "│".dimmed(),
                "📁".dimmed(),
                format!("{}", files.len()).bold()
            );
            println!(
                "  {}  {} Events        {}",
                "│".dimmed(),
                "📊".dimmed(),
                format!("{}", total_events).bold()
            );
            println!(
                "  {}  {} Throughput    {}",
                "│".dimmed(),
                "⚡".dimmed(),
                format!("{:.0} events/s", throughput).bold()
            );
            println!(
                "  {}  {} Detections    {}{}{}{}",
                "│".dimmed(),
                "🔥".dimmed(),
                if crit_count > 0 {
                    format!("{} CRITICAL ", crit_count).red().bold().to_string()
                } else {
                    String::new()
                },
                if high_count > 0 {
                    format!("{} HIGH ", high_count).magenta().bold().to_string()
                } else {
                    String::new()
                },
                if med_count > 0 {
                    format!("{} MEDIUM ", med_count).yellow().bold().to_string()
                } else {
                    String::new()
                },
                if low_count > 0 {
                    format!("{} LOW", low_count).green().to_string()
                } else {
                    String::new()
                },
            );
            println!(
                "  {}  {} Coverage      {}/{} rules matched ({:.1}%)  {}",
                "│".dimmed(),
                "📋".dimmed(),
                results.len().to_string().bold(),
                total_rules_loaded,
                coverage_pct,
                bar.cyan()
            );
            println!(
                "  {}  {} Matched       {} events across {} rules",
                "│".dimmed(),
                "🎯".dimmed(),
                total_matches.to_string().bold(),
                results.len().to_string().bold()
            );

            // Top hits
            if !results.is_empty() {
                println!("  {}  {} Top Hits", "│".dimmed(), "🏆".dimmed(),);
                for d in results.iter().take(5) {
                    println!(
                        "  {}                {} {} ({})",
                        "│".dimmed(),
                        level_color(&d.level),
                        d.title,
                        d.result.count
                    );
                }
            }

            println!(
                "  {}",
                "╰──────────────────────────────────────────────────────────────╯".dimmed()
            );
            println!();

            // ATT&CK Coverage mini-view (like Zircolite)
            let mut tactic_hits: std::collections::HashMap<String, (usize, usize)> =
                std::collections::HashMap::new();
            for d in &results {
                let refs = muninn::mitre::MitreMapper::parse_tags(&d.tags);
                let techs = mapper.resolve_refs(&refs);
                for t in &techs {
                    let entry = tactic_hits.entry(t.tactic.clone()).or_insert((0, 0));
                    entry.0 += 1; // technique count
                    entry.1 += d.result.count; // hit count
                }
            }

            if !tactic_hits.is_empty() {
                println!(
                    "  {} {}",
                    "🛡".dimmed(),
                    "ATT&CK Coverage".bold().underline()
                );
                let max_hits = tactic_hits.values().map(|v| v.1).max().unwrap_or(1);
                let tactic_order = [
                    "reconnaissance",
                    "resource-development",
                    "initial-access",
                    "execution",
                    "persistence",
                    "privilege-escalation",
                    "defense-evasion",
                    "credential-access",
                    "discovery",
                    "lateral-movement",
                    "collection",
                    "command-and-control",
                    "exfiltration",
                    "impact",
                ];
                for tactic in &tactic_order {
                    if let Some(&(tech_count, hit_count)) = tactic_hits.get(*tactic) {
                        let tactic_name = muninn::mitre::tactic_display_name(tactic);
                        let bar_len = ((hit_count as f64 / max_hits as f64) * 20.0) as usize;
                        let bar_len = bar_len.clamp(1, 20);
                        let bar_str: String = "█".repeat(bar_len);
                        let pad: String = " ".repeat(20 - bar_len);
                        println!(
                            "  {:<24} {}{}  {} technique(s) ({} hits)",
                            tactic_name,
                            bar_str.truecolor(70, 110, 170),
                            pad,
                            tech_count,
                            hit_count
                        );
                    }
                }
                println!();
            }
        }

        // Kill Chain View
        if let Some(ref kc_path) = cli.killchain {
            let kc_data: Vec<_> = results
                .iter()
                .map(|d| {
                    let refs = muninn::mitre::MitreMapper::parse_tags(&d.tags);
                    (d.title.clone(), refs, d.level.clone(), d.result.count)
                })
                .collect();
            let kc_output = muninn::mitre::render_killchain(&kc_data, &mapper);
            if !cli.quiet {
                print!("{}", kc_output);
            }
            let kc_json: Vec<serde_json::Value> = kc_data
                .iter()
                .map(|(title, refs, level, count)| {
                    serde_json::json!({
                        "title": title,
                        "level": level,
                        "count": count,
                        "techniques": refs.iter().filter_map(|r| r.technique_id.as_ref()).collect::<Vec<_>>(),
                    })
                })
                .collect();
            save_report(kc_path, "Kill Chain View", &kc_output, &kc_json)?;
            if !cli.quiet {
                println!("  {} Kill chain → {:?}", "✓".green(), kc_path);
            }
        }

        // Attack Timeline
        if let Some(ref tl_path) = cli.timeline {
            let tl_data: Vec<_> = results
                .iter()
                .map(|d| {
                    (
                        d.title.clone(),
                        d.level.clone(),
                        d.tags.clone(),
                        d.result.rows.clone(),
                    )
                })
                .collect();
            let entries = muninn::timeline::build_timeline(&tl_data);
            let tl_output = muninn::timeline::render_ascii_timeline(&entries);
            if !cli.quiet {
                print!("{}", tl_output);
            }
            save_report(tl_path, "Attack Timeline", &tl_output, &entries)?;
            if !cli.quiet {
                println!("  {} Timeline → {:?}", "✓".green(), tl_path);
            }
        }

        // Correlation Engine
        if let Some(ref corr_path) = cli.correlate {
            let corr_data: Vec<_> = results
                .iter()
                .map(|d| {
                    (
                        d.title.clone(),
                        d.level.clone(),
                        d.tags.clone(),
                        d.result.rows.clone(),
                    )
                })
                .collect();
            let chains = muninn::correlate::correlate(&corr_data);
            if !chains.is_empty() {
                let corr_output = muninn::correlate::render_chains(&chains);
                if !cli.quiet {
                    print!("{}", corr_output);
                }
                save_report(corr_path, "Attack Chains", &corr_output, &chains)?;
                if !cli.quiet {
                    println!("  {} Correlations → {:?}", "✓".green(), corr_path);
                }
            }
        }

        // Threat Score
        if let Some(ref score_path) = cli.threat_score {
            let score_data: Vec<_> = results
                .iter()
                .map(|d| (d.title.clone(), d.level.clone(), d.result.rows.clone()))
                .collect();
            let scores = muninn::scoring::compute_scores(&score_data);
            if !scores.is_empty() {
                let score_output = muninn::scoring::render_scores(&scores);
                if !cli.quiet {
                    print!("{}", score_output);
                }
                save_report(score_path, "Threat Scores", &score_output, &scores)?;
                if !cli.quiet {
                    println!("  {} Threat scores → {:?}", "✓".green(), score_path);
                }
            }
        }

        // ATT&CK Navigator export
        if let Some(ref nav_path) = cli.navigator {
            let nav_data: Vec<_> = results
                .iter()
                .map(|d| {
                    let refs = muninn::mitre::MitreMapper::parse_tags(&d.tags);
                    (refs, d.level.clone(), d.result.count)
                })
                .collect();
            let layer = muninn::mitre::export_navigator_layer(&nav_data, &mapper);
            save_report(
                nav_path,
                "ATT&CK Navigator",
                &serde_json::to_string_pretty(&layer)?,
                &layer,
            )?;
            if !cli.quiet {
                println!("  {} Navigator layer → {:?}", "✓".green(), nav_path);
            }
        }

        // Template-based output
        if let Some(ref template_name) = cli.template {
            let format = muninn::output::templates::OutputFormat::from_name(template_name)?;
            let det_data: Vec<muninn::output::templates::DetectionData> = results
                .iter()
                .map(|d| muninn::output::templates::DetectionData {
                    title: d.title.clone(),
                    level: d.level.clone(),
                    count: d.result.count,
                    duration_ms: d.result.duration_ms,
                    tags: d.tags.clone(),
                    events: d.result.rows.clone(),
                })
                .collect();
            let rendered = format.render(&det_data)?;
            let out_path = if let Some(ref p) = cli.template_output {
                p.clone()
            } else {
                PathBuf::from(format!(
                    "muninn_export_{}.{}",
                    run_timestamp.format("%Y-%m-%d_%H-%M-%S"),
                    format.default_extension()
                ))
            };
            std::fs::write(&out_path, &rendered)?;
            if !cli.quiet {
                println!(
                    "  {} Template ({}) → {:?}",
                    "✓".green(),
                    template_name,
                    out_path
                );
            }
        }

        // Mini-GUI HTML report
        if let Some(ref gui_path) = cli.gui {
            let total_matches: usize = results.iter().map(|d| d.result.count).sum();
            const GUI_EVENT_LIMIT: usize = 50;
            const GUI_VALUE_MAX: usize = 500;
            const GUI_FIELDS: &[&str] = &[
                "SystemTime",
                "timestamp",
                "@timestamp",
                "TimeCreated",
                "UtcTime",
                "EventTime",
                "date",
                "_time",
                "time",
                "datetime",
                "EventID",
                "Channel",
                "Computer",
                "User",
                "LogonType",
                "Image",
                "ParentImage",
                "CommandLine",
                "ParentCommandLine",
                "ProcessId",
                "ParentProcessId",
                "TargetObject",
                "TargetFilename",
                "SourceIp",
                "DestinationIp",
                "SourcePort",
                "DestinationPort",
                "ServiceName",
                "ServiceFileName",
                "hostname",
                "app_name",
                "message",
                "level",
                "src_ip",
                "dst_ip",
                "_source_file",
            ];
            let gui_data: Vec<_> = results
                .iter()
                .map(|d| {
                    let limited_rows: Vec<HashMap<String, String>> = d
                        .result
                        .rows
                        .iter()
                        .take(GUI_EVENT_LIMIT)
                        .map(|row| {
                            row.iter()
                                .filter(|(k, _)| {
                                    GUI_FIELDS.iter().any(|f| f.eq_ignore_ascii_case(k))
                                })
                                .map(|(k, v)| {
                                    let truncated = if v.len() > GUI_VALUE_MAX {
                                        format!(
                                            "{}...[truncated {} chars]",
                                            &v[..GUI_VALUE_MAX],
                                            v.len() - GUI_VALUE_MAX
                                        )
                                    } else {
                                        v.clone()
                                    };
                                    (k.clone(), truncated)
                                })
                                .collect()
                        })
                        .collect();
                    (
                        d.title.clone(),
                        d.level.clone(),
                        d.result.count,
                        d.tags.clone(),
                        limited_rows,
                        d.description.clone(),
                        d.id.clone(),
                        d.confidence.clone(),
                    )
                })
                .collect();
            let summary = serde_json::json!({
                "files_scanned": files.len(),
                "total_events": total_events,
                "rules_matched": results.len(),
                "total_detections": total_matches,
            });
            let html = muninn::output::gui::generate_html_report(&gui_data, &summary)?;
            std::fs::write(gui_path, &html)?;
            if !cli.quiet {
                println!("  {} HTML report → {:?}", "✓".green(), gui_path);
            }
        }
    } else if !cli.stats && cli.distinct.is_none() && cli.dbfile.is_none() && !cli.quiet {
        println!("  {} No matches found.\n", "[*]".yellow());
    }

    // Anomaly Detection (independent of SIGMA results)
    if let Some(ref anom_path) = cli.anomalies {
        let anom_spinner = if !cli.quiet {
            let sp = ProgressBar::new_spinner();
            sp.set_style(
                ProgressStyle::default_spinner()
                    .template("  {spinner:.green} Detecting anomalies...")
                    .unwrap(),
            );
            sp.enable_steady_tick(std::time::Duration::from_millis(100));
            Some(sp)
        } else {
            None
        };
        let anomalies = muninn::anomaly::detect_anomalies(&engine)?;
        if let Some(sp) = anom_spinner {
            sp.finish_and_clear();
        }
        let output = muninn::anomaly::render_anomalies(&anomalies);
        if !cli.quiet {
            print!("{}", output);
        }
        save_report(anom_path, "Anomaly Detection", &output, &anomalies)?;
        if !cli.quiet {
            println!("  {} Anomalies → {:?}", "✓".green(), anom_path);
        }
    }

    // Login Analysis (requires unified engine with Security events)
    if let Some(ref login_path) = cli.login_analysis {
        let login_spinner = if !cli.quiet {
            let sp = ProgressBar::new_spinner();
            sp.set_style(
                ProgressStyle::default_spinner()
                    .template("  {spinner:.green} Analyzing logins (4624/4625/4672)...")
                    .unwrap(),
            );
            sp.enable_steady_tick(std::time::Duration::from_millis(100));
            Some(sp)
        } else {
            None
        };
        let login_result = muninn::login::analyze_logins(&engine);
        if let Some(sp) = login_spinner {
            sp.finish_and_clear();
        }
        match login_result {
            Ok(analysis) => {
                let output = muninn::login::render_login_analysis(&analysis);
                if !cli.quiet {
                    print!("{}", output);
                }
                save_report(login_path, "Login Analysis", &output, &analysis)?;
                if !cli.quiet {
                    println!("  {} Login analysis → {:?}", "✓".green(), login_path);
                }
            }
            Err(e) => {
                if !cli.quiet {
                    eprintln!("  {} Login analysis failed: {}", "✗".red(), e);
                }
            }
        }
    }

    // Executive Summary (uses detection results + scores)
    if let Some(ref summary_path) = cli.summary {
        let det_inputs: Vec<muninn::summary::DetectionInput> = results
            .iter()
            .map(|d| muninn::summary::DetectionInput {
                title: d.title.clone(),
                level: d.level.clone(),
                description: d.description.clone(),
                tags: d.tags.clone(),
                count: d.result.count,
                confidence: d.confidence.clone(),
            })
            .collect();
        let score_data: Vec<_> = results
            .iter()
            .map(|d| (d.title.clone(), d.level.clone(), d.result.rows.clone()))
            .collect();
        let scores = muninn::scoring::compute_scores(&score_data);
        let summary = muninn::summary::generate_summary(&det_inputs, &scores, total_events);
        let output = muninn::summary::render_summary(&summary);
        if !cli.quiet {
            print!("{}", output);
        }
        save_report(summary_path, "Executive Summary", &output, &summary)?;
        if !cli.quiet {
            println!("  {} Summary → {:?}", "✓".green(), summary_path);
        }
    }

    // IOC Extraction (streaming — already collected during file processing)
    if let Some(ref ioc_path) = cli.ioc_extract {
        let ioc_spinner = if !cli.quiet {
            let sp = ProgressBar::new_spinner();
            sp.set_style(
                ProgressStyle::default_spinner()
                    .template("  {spinner:.green} Extracting IOCs...")
                    .unwrap(),
            );
            sp.enable_steady_tick(std::time::Duration::from_millis(100));
            Some(sp)
        } else {
            None
        };
        let iocs = if let Some(collector) = merged_ioc_collector {
            collector.finalize()
        } else {
            // Fallback: extract from unified engine if streaming didn't run
            muninn::ioc::extract_iocs(&engine)?
        };
        if let Some(sp) = ioc_spinner {
            sp.finish_and_clear();
        }
        let output = muninn::ioc::render_iocs(&iocs);
        if !cli.quiet {
            print!("{}", output);
        }

        // IOC Enrichment via external APIs (feature-gated)
        #[cfg(feature = "ioc-enrich")]
        {
            let mut all_enriched = Vec::new();

            if let Some(ref vt_key) = cli.vt_key {
                if !cli.quiet {
                    println!("  {} Enriching IOCs via VirusTotal...", "▶".cyan());
                }
                match muninn::ioc::enrich_virustotal(&iocs, vt_key) {
                    Ok(enriched) => all_enriched.extend(enriched),
                    Err(e) => {
                        if !cli.quiet {
                            eprintln!("  {} VT enrichment failed: {}", "✗".red(), e);
                        }
                    }
                }
            }

            if let Some(ref abuse_key) = cli.abuseipdb_key {
                if !cli.quiet {
                    println!("  {} Enriching IPs via AbuseIPDB...", "▶".cyan());
                }
                match muninn::ioc::enrich_abuseipdb(&iocs, abuse_key) {
                    Ok(enriched) => all_enriched.extend(enriched),
                    Err(e) => {
                        if !cli.quiet {
                            eprintln!("  {} AbuseIPDB enrichment failed: {}", "✗".red(), e);
                        }
                    }
                }
            }

            if let Some(ref opentip_key) = cli.opentip_key {
                if !cli.quiet {
                    println!("  {} Enriching IOCs via Kaspersky OpenTIP...", "▶".cyan());
                }
                match muninn::ioc::enrich_opentip(&iocs, opentip_key) {
                    Ok(enriched) => all_enriched.extend(enriched),
                    Err(e) => {
                        if !cli.quiet {
                            eprintln!("  {} OpenTIP enrichment failed: {}", "✗".red(), e);
                        }
                    }
                }
            }

            if !all_enriched.is_empty() && !cli.quiet {
                let output = muninn::ioc::render_enriched(&all_enriched);
                print!("{}", output);
            }
        }

        // Comprehensive OpenTIP check (--opentip-check)
        #[cfg(feature = "ioc-enrich")]
        if let Some(ref opentip_key) = cli.opentip_check {
            if !cli.quiet {
                println!(
                    "  {} Checking IOCs via Kaspersky OpenTIP...",
                    "\u{25b6}".cyan()
                );
            }
            let client = muninn::opentip::OpenTipClient::new(opentip_key);
            let opentip_results =
                client.check_iocs(&iocs, cli.opentip_max, cli.quiet, &cli.opentip_types);
            if !opentip_results.is_empty() {
                // Save reports
                let report = muninn::opentip::render_opentip_report(&opentip_results);
                let opentip_txt = ioc_path.with_extension("opentip.txt");
                save_report(&opentip_txt, "OpenTIP Report", &report, &opentip_results)?;
                let opentip_html_path = ioc_path.with_extension("opentip.html");
                std::fs::write(
                    &opentip_html_path,
                    muninn::opentip::render_opentip_html(&opentip_results),
                )?;
                let opentip_json = ioc_path.with_extension("opentip.json");
                std::fs::write(
                    &opentip_json,
                    serde_json::to_string_pretty(&opentip_results)?,
                )?;
                // Console: one-line summary
                if !cli.quiet {
                    let (mut red, mut orange, mut yellow, mut green, mut grey) =
                        (0usize, 0, 0, 0, 0);
                    for r in &opentip_results {
                        match r.zone {
                            muninn::opentip::Zone::Red => red += 1,
                            muninn::opentip::Zone::Orange => orange += 1,
                            muninn::opentip::Zone::Yellow => yellow += 1,
                            muninn::opentip::Zone::Green => green += 1,
                            muninn::opentip::Zone::Grey => grey += 1,
                        }
                    }
                    println!(
                        "  {} OpenTIP: {} checked \u{2014} {} RED, {} ORANGE, {} YELLOW, {} GREEN, {} GREY \u{2192} {:?}",
                        "\u{2713}".green(), opentip_results.len(),
                        red, orange, yellow, green, grey,
                        opentip_html_path
                    );
                }
            }
        }

        let file_output = muninn::ioc::render_iocs_full(&iocs);
        save_report(ioc_path, "IOC Extraction", &file_output, &iocs)?;
        // Also save CSV
        let csv_path = ioc_path.with_extension("csv");
        std::fs::write(&csv_path, muninn::ioc::render_iocs_csv(&iocs))?;
        if !cli.quiet {
            println!("  {} IOCs → {:?}, {:?}", "✓".green(), ioc_path, csv_path);
        }
    }

    // Diff Mode
    if let Some(ref diff_path) = cli.diff {
        let diff_files =
            parsers::discover_files(diff_path, cli.select.as_deref(), cli.avoid.as_deref(), true)?;
        let mut engine_b = SearchEngine::new()?;
        for file in &diff_files {
            if let Ok(result) = parsers::parse_file(file) {
                let _ = engine_b.load_events(&result.events);
            }
        }
        let rules = if let Some(ref rules_path) = cli.rules {
            muninn::sigma::load_rules(rules_path).unwrap_or_default()
        } else {
            Vec::new()
        };
        let diff_result = muninn::diff::diff_evidence(&engine, &engine_b, &rules)?;
        if !cli.quiet {
            let output = muninn::diff::render_diff(&diff_result);
            print!("{}", output);
        }
    }

    let has_any_output =
        !results.is_empty() || cli.stats || cli.distinct.is_some() || cli.dbfile.is_some();

    if has_any_output || !parse_errors.is_empty() {
        let output_path = if let Some(ref output) = cli.output {
            output.clone()
        } else if !cli.no_report {
            PathBuf::from(format!(
                "muninn_report_{}.json",
                run_timestamp.format("%Y-%m-%d_%H-%M-%S")
            ))
        } else {
            PathBuf::new()
        };

        if !output_path.as_os_str().is_empty() {
            let total_matches: usize = results.iter().map(|d| d.result.count).sum();
            let elapsed = start.elapsed().as_secs_f64();

            let report = serde_json::json!({
                "tool": "muninn",
                "version": env!("CARGO_PKG_VERSION"),
                "timestamp": run_timestamp.to_rfc3339(),
                "duration_sec": format!("{:.1}", elapsed),
                "source": cli.load_db.as_ref().or(cli.events.as_ref()).map(|p| p.to_string_lossy().to_string()).unwrap_or_default(),
                "summary": {
                    "files_scanned": files.len(),
                    "total_events": total_events,
                    "rules_matched": results.len(),
                    "total_detections": total_matches,
                    "formats": &format_stats,
                    "errors": parse_errors.len(),
                },
                "detections": results.iter().map(|d| {
                    let report_mapper = muninn::mitre::MitreMapper::new();
                    let mitre_refs = muninn::mitre::MitreMapper::parse_tags(&d.tags);
                    let mitre_techniques = report_mapper.resolve_refs(&mitre_refs);
                    let mut det = serde_json::json!({
                        "title": d.title,
                        "level": d.level,
                        "count": d.result.count,
                        "duration_ms": d.result.duration_ms,
                        "query": d.result.query,
                        "events": d.result.rows,
                    });
                    if !d.id.is_empty() {
                        det["id"] = serde_json::json!(d.id);
                    }
                    if !d.description.is_empty() {
                        det["description"] = serde_json::json!(d.description);
                    }
                    if !d.author.is_empty() {
                        det["author"] = serde_json::json!(d.author);
                    }
                    if !d.tags.is_empty() {
                        det["tags"] = serde_json::json!(d.tags);
                    }
                    if !mitre_techniques.is_empty() {
                        det["mitre"] = serde_json::json!(mitre_techniques);
                    }
                    if !d.confidence.is_empty() {
                        det["confidence"] = serde_json::json!(d.confidence);
                    }
                    det
                }).collect::<Vec<_>>(),
                "source_files": &source_files,
                "errors": parse_errors,
            });

            std::fs::write(&output_path, serde_json::to_string_pretty(&report)?)?;
            if !cli.quiet {
                println!(
                    "  {} Output: {}",
                    "→".cyan().bold(),
                    output_path.display().to_string().bold()
                );
                println!();
            }
        }
    }

    // Interactive TUI
    #[cfg(feature = "tui")]
    if cli.tui && !results.is_empty() {
        let tui_detections: Vec<muninn::tui::DetectionInfo> = results
            .iter()
            .map(|d| muninn::tui::DetectionInfo {
                title: d.title.clone(),
                level: d.level.clone(),
                count: d.result.count,
                tags: d.tags.clone(),
                rows: d.result.rows.clone(),
            })
            .collect();
        muninn::tui::run_tui(tui_detections)?;
    }

    // Live monitoring mode
    #[cfg(feature = "live")]
    if cli.live {
        if let Some(ref rules_path) = cli.rules {
            println!(
                "  {} Entering live monitoring mode (Ctrl+C to stop)...",
                "▶".green()
            );
            if let Some(ref events_path) = cli.events {
                muninn::live::watch_directory(events_path, rules_path)?;
            } else if !cli.quiet {
                println!("  {} --live requires --events to be specified", "✗".red());
            }
        } else if !cli.quiet {
            println!("  {} --live requires --rules to be specified", "✗".red());
        }
    }

    Ok(())
}
