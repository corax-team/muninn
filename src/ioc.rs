use anyhow::Result;
use psl::Psl;
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};

use crate::model::Event;
use crate::search::SearchEngine;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum IocType {
    Ipv4,
    Ipv6,
    Domain,
    Url,
    Md5,
    Sha1,
    Sha256,
    Email,
    FilePath,
    RegistryKey,
    ServiceName,
    TaskName,
    PipeName,
}

impl std::fmt::Display for IocType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IocType::Ipv4 => write!(f, "IPv4"),
            IocType::Ipv6 => write!(f, "IPv6"),
            IocType::Domain => write!(f, "Domain"),
            IocType::Url => write!(f, "URL"),
            IocType::Md5 => write!(f, "MD5"),
            IocType::Sha1 => write!(f, "SHA1"),
            IocType::Sha256 => write!(f, "SHA256"),
            IocType::Email => write!(f, "Email"),
            IocType::FilePath => write!(f, "FilePath"),
            IocType::RegistryKey => write!(f, "Registry"),
            IocType::ServiceName => write!(f, "Service"),
            IocType::TaskName => write!(f, "Task"),
            IocType::PipeName => write!(f, "Pipe"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Ioc {
    pub ioc_type: IocType,
    pub value: String,
    pub count: usize,
    pub source_fields: Vec<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub source_files: Vec<String>,
}

// ─── Internal state for streaming accumulation ────────────────────────────

struct IocState {
    count: usize,
    first_seen: Option<String>,
    last_seen: Option<String>,
    source_files: HashSet<String>,
    source_fields: HashSet<String>,
}

impl IocState {
    fn new() -> Self {
        Self {
            count: 0,
            first_seen: None,
            last_seen: None,
            source_files: HashSet::new(),
            source_fields: HashSet::new(),
        }
    }

    fn record(&mut self, ts: Option<&str>, source_file: &str, field_name: &str) {
        self.count += 1;
        if !source_file.is_empty() {
            self.source_files.insert(source_file.to_string());
        }
        if !field_name.is_empty() {
            self.source_fields.insert(field_name.to_string());
        }
        if let Some(t) = ts {
            if !t.is_empty() {
                match &self.first_seen {
                    None => self.first_seen = Some(t.to_string()),
                    Some(cur) if t < cur.as_str() => self.first_seen = Some(t.to_string()),
                    _ => {}
                }
                match &self.last_seen {
                    None => self.last_seen = Some(t.to_string()),
                    Some(cur) if t > cur.as_str() => self.last_seen = Some(t.to_string()),
                    _ => {}
                }
            }
        }
    }

    fn merge(&mut self, other: IocState) {
        self.count += other.count;
        self.source_files.extend(other.source_files);
        self.source_fields.extend(other.source_fields);
        if let Some(t) = other.first_seen {
            match &self.first_seen {
                None => self.first_seen = Some(t),
                Some(cur) if t < *cur => self.first_seen = Some(t),
                _ => {}
            }
        }
        if let Some(t) = other.last_seen {
            match &self.last_seen {
                None => self.last_seen = Some(t),
                Some(cur) if t > *cur => self.last_seen = Some(t),
                _ => {}
            }
        }
    }
}

// ─── Timestamp field candidates ───────────────────────────────────────────

const TIME_FIELDS: &[&str] = &[
    "SystemTime",
    "TimeCreated",
    "UtcTime",
    "@timestamp",
    "timestamp",
    "EventTime",
    "date",
    "_time",
    "time",
    "datetime",
];

fn extract_timestamp(ev: &Event) -> Option<&str> {
    for f in TIME_FIELDS {
        if let Some(v) = ev.fields.get(*f) {
            if !v.is_empty() {
                return Some(v.as_str());
            }
        }
    }
    None
}

// ─── IP field names (case-insensitive matching) ───────────────────────────

/// Returns true if this field name is known to hold IP addresses.
fn is_ip_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // Exact known fields
    matches!(
        lower.as_str(),
        "sourceip"
            | "destinationip"
            | "src_ip"
            | "dst_ip"
            | "ipaddress"
            | "clientipaddress"
            | "serveripaddress"
            | "remoteaddress"
            | "localaddress"
            | "sourceaddress"
            | "destinationaddress"
            | "calleripaddress"
            | "clientip"
            | "serverip"
            | "source_ip"
            | "dest_ip"
            | "src"
            | "dst"
            | "id_orig_h"
            | "id_resp_h"
            | "c-ip"
            | "s-ip"
            | "shost"
            | "dhost"
    ) || (lower.contains("ip")
        && !lower.contains("script")
        && !lower.contains("descript")
        && !lower.contains("pip")
        && !lower.contains("zip")
        && !lower.contains("tip"))
        || (lower.contains("address")
            && !lower.contains("email")
            && !lower.contains("mail")
            && !lower.contains("street"))
}

// ─── Field-type detection for new IOC types ──────────────────────────────

/// Returns true if this field is known to hold file paths.
fn is_filepath_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "image"
            | "parentimage"
            | "targetfilename"
            | "sourcefilename"
            | "imageloaded"
            | "servicefilename"
    )
}

/// Returns true if this field is known to hold registry keys.
fn is_registry_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(lower.as_str(), "targetobject" | "objectname")
}

/// Returns true if this field is known to hold service names.
fn is_service_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(lower.as_str(), "servicename" | "service_name")
}

/// Returns true if this field is known to hold scheduled task names.
fn is_task_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "taskname"
}

/// Returns true if this field is known to hold named pipe names.
fn is_pipe_field(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower == "pipename"
}

/// Returns true if the file path is a well-known system binary (noise).
fn is_noise_filepath(path: &str) -> bool {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "-" || trimmed.len() < 4 {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase().replace('/', "\\");
    // Known system binaries
    const NOISE_PATHS: &[&str] = &[
        "c:\\windows\\system32\\svchost.exe",
        "c:\\windows\\system32\\services.exe",
        "c:\\windows\\system32\\lsass.exe",
        "c:\\windows\\explorer.exe",
        "c:\\windows\\system32\\wininit.exe",
        "c:\\windows\\system32\\csrss.exe",
        "c:\\windows\\system32\\smss.exe",
        "c:\\windows\\system32\\conhost.exe",
        "c:\\windows\\system32\\dwm.exe",
        "c:\\windows\\system32\\taskhostw.exe",
        "c:\\windows\\system32\\runtimebroker.exe",
        "c:\\windows\\system32\\searchindexer.exe",
        "c:\\windows\\system32\\wmiprvse.exe",
        "c:\\windows\\system32\\spoolsv.exe",
        "c:\\windows\\system32\\msiexec.exe",
        "c:\\windows\\system32\\dllhost.exe",
        "c:\\windows\\system32\\backgroundtaskhost.exe",
    ];
    for noise in NOISE_PATHS {
        if lower == *noise {
            return true;
        }
    }
    // Same binaries under alternate paths (wbem, SysWOW64, etc.)
    let fname = lower.rsplit('\\').next().unwrap_or("");
    const NOISE_FILENAMES: &[&str] = &[
        "svchost.exe",
        "services.exe",
        "lsass.exe",
        "csrss.exe",
        "smss.exe",
        "wininit.exe",
        "conhost.exe",
        "dwm.exe",
        "taskhostw.exe",
        "runtimebroker.exe",
        "searchindexer.exe",
        "wmiprvse.exe",
        "spoolsv.exe",
        "dllhost.exe",
        "backgroundtaskhost.exe",
        "sihost.exe",
        "fontdrvhost.exe",
        "logonui.exe",
        "winlogon.exe",
        "ctfmon.exe",
        "searchprotocolhost.exe",
        "searchfilterhost.exe",
    ];
    if lower.starts_with("c:\\windows\\") && NOISE_FILENAMES.contains(&fname) {
        return true;
    }
    // Noisy prefix directories
    if lower.starts_with("c:\\windows\\winsxs\\")
        || lower.starts_with("c:\\windows\\assembly\\")
        || lower.starts_with("c:\\windows\\microsoft.net\\")
        || lower.starts_with("c:\\windows\\syswow64\\")
        || lower.starts_with("c:\\windows\\servicing\\")
    {
        return true;
    }
    false
}

/// Returns true if the registry key is a known noisy path.
fn is_noise_registry(key: &str) -> bool {
    let trimmed = key.trim();
    if trimmed.is_empty() || trimmed == "-" {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("\\currentcontrolset\\services\\bam\\") {
        return true;
    }
    if lower.contains("\\deliveryoptimization\\") {
        return true;
    }
    if lower.contains("\\tracing\\") {
        return true;
    }
    false
}

// ─── Streaming IOC Collector ──────────────────────────────────────────────

/// Streaming IOC collector — accumulates IOCs from events without loading into SQLite.
pub struct IocCollector {
    entries: HashMap<(IocType, String), IocState>,
    max_entries: usize,
    ipv4_re: Regex,
    md5_re: Regex,
    sha1_re: Regex,
    sha256_re: Regex,
    url_re: Regex,
    email_re: Regex,
    domain_re: Regex,
}

impl Default for IocCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl IocCollector {
    pub fn new() -> Self {
        Self::with_max_entries(100_000)
    }

    pub fn with_max_entries(max: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: max,
            ipv4_re: Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b").unwrap(),
            md5_re: Regex::new(r"\b([a-fA-F0-9]{32})\b").unwrap(),
            sha1_re: Regex::new(r"\b([a-fA-F0-9]{40})\b").unwrap(),
            sha256_re: Regex::new(r"\b([a-fA-F0-9]{64})\b").unwrap(),
            url_re: Regex::new(r#"https?://[^\s'"<>\])}]+"#).unwrap(),
            email_re: Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap(),
            domain_re: Regex::new(
                r#"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,63}))\b"#,
            )
            .unwrap(),
        }
    }

    /// Process a batch of events, extracting IOCs incrementally.
    pub fn process_events(&mut self, events: &[Event]) {
        for ev in events {
            let ts = extract_timestamp(ev);
            let src = &ev.source_file;

            // ── Field-aware extraction ──
            for (field_name, field_value) in &ev.fields {
                // IPv4 from known IP fields
                if is_ip_field(field_name) {
                    for cap in self.ipv4_re.captures_iter(field_value) {
                        let ip = cap[1].to_string();
                        if is_valid_public_ip(&ip) {
                            let key = (IocType::Ipv4, ip);
                            if !self.entries.contains_key(&key)
                                && self.entries.len() >= self.max_entries
                            {
                                continue;
                            }
                            self.entries
                                .entry(key)
                                .or_insert_with(IocState::new)
                                .record(ts, src, field_name);
                        }
                    }
                }
                // File paths from process/file event fields
                if is_filepath_field(field_name) {
                    let path = field_value.trim().to_string();
                    if !path.is_empty() && !is_noise_filepath(&path) {
                        let key = (IocType::FilePath, path);
                        if !self.entries.contains_key(&key)
                            && self.entries.len() >= self.max_entries
                        {
                            continue;
                        }
                        self.entries
                            .entry(key)
                            .or_insert_with(IocState::new)
                            .record(ts, src, field_name);
                    }
                }
                // Registry keys from registry event fields
                if is_registry_field(field_name) {
                    let reg_key = field_value.trim().to_string();
                    if !reg_key.is_empty() && !is_noise_registry(&reg_key) {
                        let key = (IocType::RegistryKey, reg_key);
                        if !self.entries.contains_key(&key)
                            && self.entries.len() >= self.max_entries
                        {
                            continue;
                        }
                        self.entries
                            .entry(key)
                            .or_insert_with(IocState::new)
                            .record(ts, src, field_name);
                    }
                }
                // Service names
                if is_service_field(field_name) {
                    let svc = field_value.trim().to_string();
                    if !svc.is_empty() && svc != "-" {
                        let key = (IocType::ServiceName, svc);
                        if !self.entries.contains_key(&key)
                            && self.entries.len() >= self.max_entries
                        {
                            continue;
                        }
                        self.entries
                            .entry(key)
                            .or_insert_with(IocState::new)
                            .record(ts, src, field_name);
                    }
                }
                // Scheduled task names
                if is_task_field(field_name) {
                    let task = field_value.trim().to_string();
                    if !task.is_empty() && task != "-" {
                        let key = (IocType::TaskName, task);
                        if !self.entries.contains_key(&key)
                            && self.entries.len() >= self.max_entries
                        {
                            continue;
                        }
                        self.entries
                            .entry(key)
                            .or_insert_with(IocState::new)
                            .record(ts, src, field_name);
                    }
                }
                // Named pipes
                if is_pipe_field(field_name) {
                    let pipe = field_value.trim().to_string();
                    if !pipe.is_empty() && pipe != "-" && pipe != "\\" {
                        let key = (IocType::PipeName, pipe);
                        if !self.entries.contains_key(&key)
                            && self.entries.len() >= self.max_entries
                        {
                            continue;
                        }
                        self.entries
                            .entry(key)
                            .or_insert_with(IocState::new)
                            .record(ts, src, field_name);
                    }
                }
            }

            // ── Other IOCs: from all fields + raw ──
            let mut text = ev.raw.clone();
            for v in ev.fields.values() {
                text.push(' ');
                text.push_str(v);
            }

            self.extract_non_ip(&text, ts, src);
        }
    }

    fn extract_non_ip(&mut self, text: &str, ts: Option<&str>, source_file: &str) {
        // SHA256 (before SHA1/MD5 to avoid substring matches)
        for cap in self.sha256_re.captures_iter(text) {
            let hash = cap[1].to_lowercase();
            if is_plausible_hash(&hash) {
                let key = (IocType::Sha256, hash);
                if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
                    continue;
                }
                self.entries
                    .entry(key)
                    .or_insert_with(IocState::new)
                    .record(ts, source_file, "");
            }
        }
        // SHA1
        for cap in self.sha1_re.captures_iter(text) {
            let hash = cap[1].to_lowercase();
            if hash.len() == 40 && is_plausible_hash(&hash) {
                let key = (IocType::Sha1, hash);
                if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
                    continue;
                }
                self.entries
                    .entry(key)
                    .or_insert_with(IocState::new)
                    .record(ts, source_file, "");
            }
        }
        // MD5
        for cap in self.md5_re.captures_iter(text) {
            let hash = cap[1].to_lowercase();
            if hash.len() == 32 && is_plausible_hash(&hash) {
                let key = (IocType::Md5, hash);
                if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
                    continue;
                }
                self.entries
                    .entry(key)
                    .or_insert_with(IocState::new)
                    .record(ts, source_file, "");
            }
        }
        // URLs
        for m in self.url_re.find_iter(text) {
            let url = m.as_str().to_string();
            if !is_noise_url(&url) {
                let key = (IocType::Url, url);
                if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
                    continue;
                }
                self.entries
                    .entry(key)
                    .or_insert_with(IocState::new)
                    .record(ts, source_file, "");
            }
        }
        // Emails
        for cap in self.email_re.captures_iter(text) {
            let email = cap[0].to_lowercase();
            if !is_noise_email(&email) {
                let key = (IocType::Email, email);
                if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
                    continue;
                }
                self.entries
                    .entry(key)
                    .or_insert_with(IocState::new)
                    .record(ts, source_file, "");
            }
        }
        // Domains — use PSL (Mozilla Public Suffix List) for validation
        for cap in self.domain_re.captures_iter(text) {
            let domain = cap[1].to_lowercase();
            // Validate via PSL: only real domains with known TLDs
            if psl::List.suffix(domain.as_bytes()).is_none() {
                continue;
            }
            if !is_noise_domain(&domain) {
                let key = (IocType::Domain, domain);
                if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
                    continue;
                }
                self.entries
                    .entry(key)
                    .or_insert_with(IocState::new)
                    .record(ts, source_file, "");
            }
        }
    }

    /// Merge another collector into this one (for parallel file processing).
    pub fn merge(&mut self, other: IocCollector) {
        for (key, state) in other.entries {
            if !self.entries.contains_key(&key) && self.entries.len() >= self.max_entries {
                continue;
            }
            self.entries
                .entry(key)
                .or_insert_with(IocState::new)
                .merge(state);
        }
    }

    /// Finalize and return sorted IOCs.
    pub fn finalize(self) -> Vec<Ioc> {
        let mut iocs: Vec<Ioc> = self
            .entries
            .into_iter()
            .map(|((ioc_type, value), state)| {
                let mut source_files: Vec<String> = state.source_files.into_iter().collect();
                source_files.sort();
                let mut source_fields: Vec<String> = state.source_fields.into_iter().collect();
                source_fields.sort();
                Ioc {
                    ioc_type,
                    value,
                    count: state.count,
                    source_fields,
                    first_seen: state.first_seen,
                    last_seen: state.last_seen,
                    source_files,
                }
            })
            .collect();
        iocs.sort_by(|a, b| b.count.cmp(&a.count));
        iocs
    }
}

// ─── Legacy extract_iocs (for unified engine fallback) ────────────────────

pub fn extract_iocs(engine: &SearchEngine) -> Result<Vec<Ioc>> {
    let _raw_query = engine.query_sql(
        "SELECT \"_raw\" FROM \"events\" WHERE \"_raw\" IS NOT NULL AND \"_raw\" != ''",
    )?;

    let mut ioc_counts: HashMap<(IocType, String), usize> = HashMap::new();

    let ipv4_re = Regex::new(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")?;
    let md5_re = Regex::new(r"\b([a-fA-F0-9]{32})\b")?;
    let sha1_re = Regex::new(r"\b([a-fA-F0-9]{40})\b")?;
    let sha256_re = Regex::new(r"\b([a-fA-F0-9]{64})\b")?;
    let url_re = Regex::new(r#"https?://[^\s'"<>\])}]+"#)?;
    let email_re = Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")?;
    let domain_re =
        Regex::new(r#"\b([a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.([a-zA-Z]{2,63}))\b"#)?;

    let raw_result = engine.query_sql("SELECT * FROM \"events\"")?;

    for row in &raw_result.rows {
        let text: String = row.values().cloned().collect::<Vec<_>>().join(" ");

        for cap in ipv4_re.captures_iter(&text) {
            let ip = cap[1].to_string();
            if is_valid_public_ip(&ip) {
                *ioc_counts.entry((IocType::Ipv4, ip)).or_default() += 1;
            }
        }
        for cap in sha256_re.captures_iter(&text) {
            let hash = cap[1].to_lowercase();
            if is_plausible_hash(&hash) {
                *ioc_counts.entry((IocType::Sha256, hash)).or_default() += 1;
            }
        }
        for cap in sha1_re.captures_iter(&text) {
            let hash = cap[1].to_lowercase();
            if hash.len() == 40 && is_plausible_hash(&hash) {
                *ioc_counts.entry((IocType::Sha1, hash)).or_default() += 1;
            }
        }
        for cap in md5_re.captures_iter(&text) {
            let hash = cap[1].to_lowercase();
            if hash.len() == 32 && is_plausible_hash(&hash) {
                *ioc_counts.entry((IocType::Md5, hash)).or_default() += 1;
            }
        }
        for m in url_re.find_iter(&text) {
            let url = m.as_str().to_string();
            if !is_noise_url(&url) {
                *ioc_counts.entry((IocType::Url, url)).or_default() += 1;
            }
        }
        for cap in email_re.captures_iter(&text) {
            let email = cap[0].to_lowercase();
            if !is_noise_email(&email) {
                *ioc_counts.entry((IocType::Email, email)).or_default() += 1;
            }
        }
        for cap in domain_re.captures_iter(&text) {
            let domain = cap[1].to_lowercase();
            if psl::List.suffix(domain.as_bytes()).is_none() {
                continue;
            }
            if !is_noise_domain(&domain) {
                *ioc_counts.entry((IocType::Domain, domain)).or_default() += 1;
            }
        }
    }

    let mut iocs: Vec<Ioc> = ioc_counts
        .into_iter()
        .map(|((ioc_type, value), count)| Ioc {
            ioc_type,
            value,
            count,
            source_fields: vec![],
            first_seen: None,
            last_seen: None,
            source_files: vec![],
        })
        .collect();

    iocs.sort_by(|a, b| b.count.cmp(&a.count));
    Ok(iocs)
}

// ═══════════════════════════════════════════════════════════════════════════
// Validation & noise filters
// ═══════════════════════════════════════════════════════════════════════════

fn is_valid_public_ip(ip: &str) -> bool {
    // Reject leading zeros in any octet (dates like 03.10.21.57)
    for octet_str in ip.split('.') {
        if octet_str.len() > 1 && octet_str.starts_with('0') {
            return false;
        }
    }
    let parts: Vec<u16> = ip.split('.').filter_map(|p| p.parse().ok()).collect();
    if parts.len() != 4 || parts.iter().any(|&p| p > 255) {
        return false;
    }
    let (a, b, c, d) = (
        parts[0] as u8,
        parts[1] as u8,
        parts[2] as u8,
        parts[3] as u8,
    );
    // Private, loopback, link-local (169.254.x.x), multicast, reserved
    if a == 10
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 169 && b == 254)
        || a == 127
        || a == 0
        || a >= 224
    {
        return false;
    }
    // Network/broadcast addresses
    if (c == 0 && d == 0) || d == 255 {
        return false;
    }
    // Known OID prefixes (SNMP, X.509, etc.)
    if (a == 1 && b == 3 && (c == 6 || c == 14)) // 1.3.6.x / 1.3.14.x
        || (a == 2 && b == 5) // 2.5.x.x — X.500 OID
        || (a == 5 && b == 5 && c == 7) // 5.5.7.x — PKIX OID
        || (a == 101 && b == 3 && c == 4)
    // 101.3.4.x — NIST OID
    {
        return false;
    }
    // CGNAT range (100.64-127.x.x.x)
    if a == 100 && (64..=127).contains(&b) {
        return false;
    }
    true
}

/// Whitelist of domains that are benign infrastructure noise.
const NOISE_DOMAINS: &[&str] = &[
    // Microsoft
    "microsoft.com",
    "windows.com",
    "windowsupdate.com",
    "microsoftonline.com",
    "microsoftonline.cn",
    "office.com",
    "office365.com",
    "azure.com",
    "msocsp.com",
    "msn.com",
    "live.com",
    "bing.com",
    "aka.ms",
    "msol-test.com",
    "ccsctp.com",
    "live-int.com",
    "spoppe.com",
    "passport.net",
    // PKI / CAs
    "w3.org",
    "globalsign.com",
    "digicert.com",
    "verisign.com",
    "symantec.com",
    "thawte.com",
    "geotrust.com",
    "letsencrypt.org",
    // Standards / specs
    "oasis-open.org",
    "xmlsoap.org",
    "dmtf.org",
    // Common providers
    "outlook.com",
    "outlook.cn",
    "gmail.com",
    "google.com",
    "yandex.net",
    "yandex.ru",
    "cloudapp.net",
    "localhost.com",
    // Kaspersky (common in monitored envs)
    "kaspersky.com",
    "microsoft.net",
];

fn is_noise_url(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    // XML schema namespaces
    if lower.contains("schemas.microsoft.com")
        || lower.contains("www.w3.org")
        || lower.contains("schemas.openxmlformats.org")
        || lower.contains("purl.org")
        || lower.contains("docs.oasis-open.org")
        || lower.contains("xmlsoap.org")
    {
        return true;
    }
    // Localhost / loopback
    if lower.contains("://localhost") || lower.contains("://127.0.0.1") {
        return true;
    }
    // .local / .internal hostnames
    if lower.contains(".local/")
        || lower.contains(".local:")
        || lower.contains(".local\\")
        || lower.ends_with(".local")
        || lower.contains(".internal/")
        || lower.contains(".internal:")
        || lower.ends_with(".internal")
    {
        return true;
    }
    // Private IP URLs
    if lower.contains("://192.168.")
        || lower.contains("://10.")
        || lower.contains("://172.16.")
        || lower.contains("://172.17.")
        || lower.contains("://172.18.")
        || lower.contains("://172.19.")
        || lower.contains("://172.2")
        || lower.contains("://172.30.")
        || lower.contains("://172.31.")
    {
        return true;
    }
    // Malformed URLs (extraction artifacts)
    if lower.contains("\\r\\n")
        || lower.contains("&#13;")
        || lower.contains("&#10;")
        || lower.contains("replace_percent_sign")
    {
        return true;
    }
    // Unsubscribe / tracking links
    if lower.contains("/unsubscribe") || lower.contains("/unsub/") {
        return true;
    }
    // Domain whitelist
    for d in NOISE_DOMAINS {
        if lower.contains(d) {
            return true;
        }
    }
    false
}

fn is_noise_domain(domain: &str) -> bool {
    let lower = domain.to_ascii_lowercase();
    // Noise whitelist
    for d in NOISE_DOMAINS {
        if lower == *d || lower.ends_with(&format!(".{}", d)) {
            return true;
        }
    }
    // .local / .internal
    if lower.ends_with(".local") || lower.ends_with(".internal") {
        return true;
    }
    // False positives: file extensions caught as TLD (svchost.exe, config.json, etc.)
    const FALSE_TLDS: &[&str] = &[
        "exe",
        "dll",
        "sys",
        "bat",
        "cmd",
        "ps1",
        "vbs",
        "js",
        "wsf",
        "msi",
        "msp",
        "scr",
        "com", // com is ambiguous but too noisy from file paths
        "log",
        "txt",
        "cfg",
        "ini",
        "xml",
        "json",
        "yaml",
        "yml",
        "csv",
        "tsv",
        "tmp",
        "bak",
        "old",
        "dat",
        "db",
        "sqlite",
        "png",
        "jpg",
        "gif",
        "bmp",
        "ico",
        "svg",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "pdf",
        "ppt",
        "pptx",
        "zip",
        "rar",
        "gz",
        "tar",
        "7z",
        "cab",
        "evtx",
        "etl",
        "dmp",
        // Web file extensions (webshells caught as domains)
        "aspx",
        "asp",
        "php",
        "jsp",
        "cgi",
        "htm",
        "html",
        "js",
        "css",
        // Code / config
        "cs",
        "java",
        "py",
        "rb",
        "go",
        "rs",
        "cpp",
        "c",
        "h",
        "ps1",
        "psm1",
        "psd1",
        "conf",
        "config",
        "properties",
        "env",
        "toml",
        "lock",
        // AV detection name fragments (Kaspersky, etc.)
        "gen",
        "heur",
        "script",
    ];
    if let Some(tld) = lower.rsplit('.').next() {
        if FALSE_TLDS.contains(&tld) {
            return true;
        }
    }
    // AV detection names: Trojan.Win32.xxx, HEUR:Exploit.xxx, not-a-virus:xxx
    if lower.starts_with("trojan.")
        || lower.starts_with("exploit.")
        || lower.starts_with("heur:")
        || lower.starts_with("not-a-virus:")
        || lower.starts_with("backdoor.")
        || lower.starts_with("worm.")
        || lower.starts_with("virus.")
        || lower.starts_with("adware.")
        || lower.starts_with("riskware.")
        || lower.starts_with("hacktool.")
        || lower.starts_with("ransom.")
        || lower.starts_with("rootkit.")
        || lower.starts_with("bss:")
        || lower.contains(".proxyshell")
        || lower.contains(".generic")
    {
        return true;
    }
    // Truncated internal hostnames (no valid TLD part)
    if lower.starts_with("schemas.") || lower.starts_with("mail.") && !lower.contains('.') {
        // handled by psl check already, but extra guard
    }
    // Too short to be a real domain (a.bc)
    if lower.len() < 4 {
        return true;
    }
    // Single-word "domains" without subdomain that are just words (e.g., "test.log")
    if !lower.contains('.') {
        return true;
    }
    false
}

fn is_noise_email(email: &str) -> bool {
    let lower = email.to_ascii_lowercase();
    // Exchange health monitoring
    if lower.starts_with("healthmailbox") {
        return true;
    }
    // .local / .internal / @doesntexist / @localhost
    if lower.ends_with(".local")
        || lower.ends_with(".internal")
        || lower.contains("@doesntexist.")
        || lower.contains("@localhost")
    {
        return true;
    }
    // Functional addresses
    if lower.starts_with("abuse@")
        || lower.starts_with("postmaster@")
        || lower.starts_with("noreply@")
        || lower.starts_with("no-reply@")
        || lower.starts_with("nobody@")
        || lower.starts_with("dummy@")
        || lower.starts_with("bookingmailbox@")
        || lower.starts_with("mailer-daemon@")
    {
        return true;
    }
    // ESP auto-generated: postman<digits>@
    if lower.starts_with("postman") {
        if let Some(rest) = lower.strip_prefix("postman") {
            if let Some(at_pos) = rest.find('@') {
                if at_pos > 0 && rest[..at_pos].chars().all(|c| c.is_ascii_digit()) {
                    return true;
                }
            }
        }
    }
    // Template variables (%m@, %s@)
    if lower.starts_with('%') {
        return true;
    }

    if let Some(local) = lower.split('@').next() {
        // UUID-shaped local parts (8-4-4-4-12)
        if local.len() == 36 && local.chars().filter(|c| *c == '-').count() == 4 {
            return true;
        }
        // Machine-generated: all hex 32+ chars
        if local.len() >= 32 && local.chars().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }
        // Embedded timestamps (20260324093419...@)
        if local.len() >= 14 && local[..14].chars().all(|c| c.is_ascii_digit()) {
            return true;
        }
    }
    false
}

/// Reject hex strings that look like encoded data rather than real hashes.
fn is_plausible_hash(hash: &str) -> bool {
    let bytes = hash.as_bytes();
    let len = bytes.len();
    // Count distinct hex characters — real hashes have high entropy
    let mut seen = [false; 16];
    for &b in bytes {
        let idx = match b {
            b'0'..=b'9' => (b - b'0') as usize,
            b'a'..=b'f' => (b - b'a' + 10) as usize,
            _ => continue,
        };
        seen[idx] = true;
    }
    let distinct = seen.iter().filter(|&&s| s).count();
    // Real hashes use ≥8 distinct hex chars; encoded data often uses fewer
    if distinct < 8 {
        return false;
    }
    // Reject if >40% zeros (common in padding/network data)
    let zero_count = bytes.iter().filter(|&&b| b == b'0').count();
    if zero_count * 5 > len * 2 {
        return false;
    }
    // Reject all-digit strings (timestamps, numeric IDs)
    if bytes.iter().all(|b| b.is_ascii_digit()) {
        return false;
    }
    true
}

// ═══════════════════════════════════════════════════════════════════════════
// Rendering
// ═══════════════════════════════════════════════════════════════════════════

/// Render IOCs for terminal display (truncated to top 50).
pub fn render_iocs(iocs: &[Ioc]) -> String {
    render_iocs_inner(iocs, 50, 40, true)
}

/// Render all IOCs with full values — for file output.
pub fn render_iocs_full(iocs: &[Ioc]) -> String {
    render_iocs_inner(iocs, usize::MAX, usize::MAX, false)
}

/// Render IOCs as CSV.
pub fn render_iocs_csv(iocs: &[Ioc]) -> String {
    let mut output =
        String::from("Type,Value,Count,First Seen,Last Seen,Source Fields,Source Files\n");
    for ioc in iocs {
        let value = ioc.value.replace('"', "\"\"");
        let fields = ioc.source_fields.join("; ");
        let files: Vec<String> = ioc
            .source_files
            .iter()
            .map(|s| {
                std::path::Path::new(s)
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        output.push_str(&format!(
            "{},\"{}\",{},{},{},\"{}\",\"{}\"\n",
            ioc.ioc_type,
            value,
            ioc.count,
            ioc.first_seen.as_deref().unwrap_or(""),
            ioc.last_seen.as_deref().unwrap_or(""),
            fields,
            files.join("; "),
        ));
    }
    output
}

fn render_iocs_inner(iocs: &[Ioc], max_rows: usize, max_value_len: usize, compact: bool) -> String {
    if iocs.is_empty() {
        return "  No IOCs extracted.\n".into();
    }

    let mut output = String::new();
    output.push_str(&format!("\n  Extracted IOCs ({})\n", iocs.len()));

    if compact {
        // Terminal: compact columns
        let w = 110;
        output.push_str(&format!("  {}\n", "═".repeat(w)));
        output.push_str(&format!(
            "  {:<8} {:<40} {:>6}  {:<22} {}\n",
            "Type", "Value", "Count", "First Seen", "Source"
        ));
        output.push_str(&format!("  {}\n", "─".repeat(w)));
        for ioc in iocs.iter().take(max_rows) {
            let val: String = ioc.value.chars().take(max_value_len).collect();
            let ts = ioc
                .first_seen
                .as_deref()
                .map(|t| t.chars().take(19).collect::<String>())
                .unwrap_or_default();
            let src = ioc
                .source_files
                .first()
                .map(|s| {
                    std::path::Path::new(s)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                })
                .unwrap_or_default();
            let src_display: String = src.chars().take(28).collect();
            output.push_str(&format!(
                "  {:<8} {:<40} {:>6}  {:<22} {}\n",
                ioc.ioc_type.to_string(),
                val,
                ioc.count,
                ts,
                src_display,
            ));
        }
    } else {
        // File: full columns
        let w = 160;
        output.push_str(&format!("  {}\n", "═".repeat(w)));
        output.push_str(&format!(
            "  {:<8} {:<70} {:>6}  {:<22} {:<22} {}\n",
            "Type", "Value", "Count", "First Seen", "Last Seen", "Source Files"
        ));
        output.push_str(&format!("  {}\n", "─".repeat(w)));
        for ioc in iocs.iter().take(max_rows) {
            let val: String = ioc.value.chars().take(max_value_len).collect();
            let first = ioc.first_seen.as_deref().unwrap_or("");
            let last = ioc.last_seen.as_deref().unwrap_or("");
            let sources: String = ioc
                .source_files
                .iter()
                .map(|s| {
                    std::path::Path::new(s)
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string()
                })
                .collect::<Vec<_>>()
                .join(", ");
            output.push_str(&format!(
                "  {:<8} {:<70} {:>6}  {:<22} {:<22} {}\n",
                ioc.ioc_type.to_string(),
                val,
                ioc.count,
                &first[..first.len().min(19)],
                &last[..last.len().min(19)],
                sources,
            ));
        }
    }

    if iocs.len() > max_rows {
        output.push_str(&format!("  ... and {} more\n", iocs.len() - max_rows));
    }

    let w = if compact { 110 } else { 160 };
    output.push_str(&format!("  {}\n", "═".repeat(w)));
    output
}

// ═══════════════════════════════════════════════════════════════════════════
// IOC Enrichment (feature-gated behind ioc-enrich)
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct EnrichedIoc {
    pub ioc: Ioc,
    pub verdict: String,
    pub source: String,
    pub details: String,
    pub score: Option<f64>,
    pub raw_response: Option<String>,
}

#[cfg(feature = "ioc-enrich")]
pub fn enrich_virustotal(iocs: &[Ioc], api_key: &str) -> Result<Vec<EnrichedIoc>> {
    let mut enriched = Vec::new();
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .build();

    for ioc in iocs.iter().take(25) {
        let endpoint = match ioc.ioc_type {
            IocType::Ipv4 => format!(
                "https://www.virustotal.com/api/v3/ip_addresses/{}",
                ioc.value
            ),
            IocType::Domain => format!("https://www.virustotal.com/api/v3/domains/{}", ioc.value),
            IocType::Url => {
                let url_id = base64::Engine::encode(
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                    ioc.value.as_bytes(),
                );
                format!("https://www.virustotal.com/api/v3/urls/{}", url_id)
            }
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 => {
                format!("https://www.virustotal.com/api/v3/files/{}", ioc.value)
            }
            _ => continue,
        };

        match agent.get(&endpoint).set("x-apikey", api_key).call() {
            Ok(resp) => {
                let body = resp.into_string().unwrap_or_default();
                let (verdict, score, details) = parse_vt_response(&body, &ioc.ioc_type);
                enriched.push(EnrichedIoc {
                    ioc: ioc.clone(),
                    verdict,
                    source: "VirusTotal".into(),
                    details,
                    score: Some(score),
                    raw_response: Some(body),
                });
            }
            Err(ureq::Error::Status(404, _)) => {
                enriched.push(EnrichedIoc {
                    ioc: ioc.clone(),
                    verdict: "unknown".into(),
                    source: "VirusTotal".into(),
                    details: "Not found in VT database".into(),
                    score: None,
                    raw_response: None,
                });
            }
            Err(ureq::Error::Status(429, _)) => {
                enriched.push(EnrichedIoc {
                    ioc: ioc.clone(),
                    verdict: "unknown".into(),
                    source: "VirusTotal".into(),
                    details: "Rate limit exceeded".into(),
                    score: None,
                    raw_response: None,
                });
                break;
            }
            Err(e) => {
                log::debug!("VT request failed for {}: {}", ioc.value, e);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(15500));
    }

    Ok(enriched)
}

#[cfg(feature = "ioc-enrich")]
fn parse_vt_response(body: &str, ioc_type: &IocType) -> (String, f64, String) {
    let json: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => return ("unknown".into(), 0.0, "Failed to parse response".into()),
    };

    let attrs = &json["data"]["attributes"];

    match ioc_type {
        IocType::Md5 | IocType::Sha1 | IocType::Sha256 => {
            let stats = &attrs["last_analysis_stats"];
            let malicious = stats["malicious"].as_u64().unwrap_or(0);
            let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
            let undetected = stats["undetected"].as_u64().unwrap_or(0);
            let total = malicious + suspicious + undetected;
            let score = if total > 0 {
                (malicious as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let verdict = if malicious >= 5 {
                "malicious"
            } else if malicious >= 1 || suspicious >= 3 {
                "suspicious"
            } else {
                "clean"
            };
            (
                verdict.into(),
                score,
                format!(
                    "{}/{} malicious, {}/{} suspicious",
                    malicious, total, suspicious, total
                ),
            )
        }
        IocType::Ipv4 | IocType::Domain => {
            let stats = &attrs["last_analysis_stats"];
            let malicious = stats["malicious"].as_u64().unwrap_or(0);
            let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
            let harmless = stats["harmless"].as_u64().unwrap_or(0);
            let total = malicious + suspicious + harmless;
            let score = if total > 0 {
                (malicious as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let verdict = if malicious >= 3 {
                "malicious"
            } else if malicious >= 1 || suspicious >= 2 {
                "suspicious"
            } else {
                "clean"
            };
            let rep = attrs["reputation"].as_i64().unwrap_or(0);
            (
                verdict.into(),
                score,
                format!(
                    "{} malicious, {} suspicious, reputation: {}",
                    malicious, suspicious, rep
                ),
            )
        }
        IocType::Url => {
            let stats = &attrs["last_analysis_stats"];
            let malicious = stats["malicious"].as_u64().unwrap_or(0);
            let suspicious = stats["suspicious"].as_u64().unwrap_or(0);
            let total = malicious + suspicious + stats["harmless"].as_u64().unwrap_or(0);
            let score = if total > 0 {
                (malicious as f64 / total as f64) * 100.0
            } else {
                0.0
            };
            let verdict = if malicious >= 3 {
                "malicious"
            } else if malicious >= 1 {
                "suspicious"
            } else {
                "clean"
            };
            (
                verdict.into(),
                score,
                format!("{}/{} malicious", malicious, total),
            )
        }
        _ => ("unknown".into(), 0.0, String::new()),
    }
}

#[cfg(feature = "ioc-enrich")]
pub fn enrich_abuseipdb(iocs: &[Ioc], api_key: &str) -> Result<Vec<EnrichedIoc>> {
    let mut enriched = Vec::new();
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .build();

    let ip_iocs: Vec<&Ioc> = iocs
        .iter()
        .filter(|i| i.ioc_type == IocType::Ipv4)
        .take(25)
        .collect();

    for ioc in &ip_iocs {
        let url = format!(
            "https://api.abuseipdb.com/api/v2/check?ipAddress={}&maxAgeInDays=90",
            ioc.value
        );

        match agent
            .get(&url)
            .set("Key", api_key)
            .set("Accept", "application/json")
            .call()
        {
            Ok(resp) => {
                let body = resp.into_string().unwrap_or_default();
                let json: serde_json::Value =
                    serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);
                let data = &json["data"];
                let abuse_score = data["abuseConfidenceScore"].as_u64().unwrap_or(0);
                let total_reports = data["totalReports"].as_u64().unwrap_or(0);
                let isp = data["isp"].as_str().unwrap_or("unknown");
                let country = data["countryCode"].as_str().unwrap_or("??");

                let verdict = if abuse_score >= 75 {
                    "malicious"
                } else if abuse_score >= 25 {
                    "suspicious"
                } else {
                    "clean"
                };

                enriched.push(EnrichedIoc {
                    ioc: (*ioc).clone(),
                    verdict: verdict.into(),
                    source: "AbuseIPDB".into(),
                    details: format!(
                        "abuse score: {}%, {} reports, ISP: {}, country: {}",
                        abuse_score, total_reports, isp, country
                    ),
                    score: Some(abuse_score as f64),
                    raw_response: Some(body),
                });
            }
            Err(ureq::Error::Status(429, _)) => {
                enriched.push(EnrichedIoc {
                    ioc: (*ioc).clone(),
                    verdict: "unknown".into(),
                    source: "AbuseIPDB".into(),
                    details: "Rate limit exceeded".into(),
                    score: None,
                    raw_response: None,
                });
                break;
            }
            Err(e) => {
                log::debug!("AbuseIPDB request failed for {}: {}", ioc.value, e);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(1100));
    }

    Ok(enriched)
}

#[cfg(feature = "ioc-enrich")]
pub fn enrich_opentip(iocs: &[Ioc], api_key: &str) -> Result<Vec<EnrichedIoc>> {
    let mut enriched = Vec::new();
    let agent = ureq::AgentBuilder::new()
        .timeout(std::time::Duration::from_secs(15))
        .build();

    for ioc in iocs.iter().take(25) {
        let (endpoint, request_body) = match ioc.ioc_type {
            IocType::Md5 | IocType::Sha1 | IocType::Sha256 => (
                "https://opentip.kaspersky.com/api/v1/search/hash",
                serde_json::json!({"request": [{"hash": &ioc.value}]}),
            ),
            IocType::Ipv4 => (
                "https://opentip.kaspersky.com/api/v1/search/ip",
                serde_json::json!({"request": [{"ip": &ioc.value}]}),
            ),
            IocType::Domain => (
                "https://opentip.kaspersky.com/api/v1/search/domain",
                serde_json::json!({"request": [{"domain": &ioc.value}]}),
            ),
            IocType::Url => (
                "https://opentip.kaspersky.com/api/v1/search/url",
                serde_json::json!({"request": [{"url": &ioc.value}]}),
            ),
            _ => continue,
        };

        match agent
            .post(endpoint)
            .set("x-api-key", api_key)
            .set("Content-Type", "application/json")
            .send_string(&request_body.to_string())
        {
            Ok(resp) => {
                let body = resp.into_string().unwrap_or_default();
                let json: serde_json::Value =
                    serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);

                let zone = json["response"][0]["zone"].as_str().unwrap_or("Grey");

                let (verdict, score) = match zone {
                    "Red" => ("malicious", 90.0),
                    "Orange" => ("suspicious", 60.0),
                    "Yellow" => ("suspicious", 40.0),
                    "Green" => ("clean", 5.0),
                    _ => ("unknown", 0.0),
                };

                let categories: Vec<String> = json["response"][0]["categories"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();

                let details = if categories.is_empty() {
                    format!("zone: {}", zone)
                } else {
                    format!("zone: {}, categories: {}", zone, categories.join(", "))
                };

                enriched.push(EnrichedIoc {
                    ioc: ioc.clone(),
                    verdict: verdict.into(),
                    source: "OpenTIP".into(),
                    details,
                    score: Some(score),
                    raw_response: Some(body),
                });
            }
            Err(ureq::Error::Status(429, _)) => {
                enriched.push(EnrichedIoc {
                    ioc: ioc.clone(),
                    verdict: "unknown".into(),
                    source: "OpenTIP".into(),
                    details: "Rate limit exceeded".into(),
                    score: None,
                    raw_response: None,
                });
                break;
            }
            Err(ureq::Error::Status(404, _)) => {
                enriched.push(EnrichedIoc {
                    ioc: ioc.clone(),
                    verdict: "unknown".into(),
                    source: "OpenTIP".into(),
                    details: "Not found".into(),
                    score: None,
                    raw_response: None,
                });
            }
            Err(e) => {
                log::debug!("OpenTIP request failed for {}: {}", ioc.value, e);
            }
        }

        std::thread::sleep(std::time::Duration::from_millis(500));
    }

    Ok(enriched)
}

pub fn render_enriched(enriched: &[EnrichedIoc]) -> String {
    if enriched.is_empty() {
        return "  No enrichment results.\n".into();
    }

    let mut output = String::new();
    output.push_str("\n  IOC Enrichment Results\n");
    output.push_str(&format!("  {}\n", "═".repeat(80)));
    output.push_str(&format!(
        "  {:<10} {:<8} {:<40} {:<12} {}\n",
        "Verdict", "Type", "Value", "Source", "Details"
    ));
    output.push_str(&format!("  {}\n", "─".repeat(80)));

    for e in enriched {
        let verdict_display = match e.verdict.as_str() {
            "malicious" => "MALICIOUS",
            "suspicious" => "SUSPECT",
            "clean" => "CLEAN",
            _ => "UNKNOWN",
        };
        let value_display: String = e.ioc.value.chars().take(38).collect();
        let details_display: String = e.details.chars().take(40).collect();
        output.push_str(&format!(
            "  {:<10} {:<8} {:<40} {:<12} {}\n",
            verdict_display,
            e.ioc.ioc_type.to_string(),
            value_display,
            e.source,
            details_display,
        ));
    }

    output.push_str(&format!("  {}\n", "═".repeat(80)));
    output
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Event, SourceFormat};

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
    fn test_extract_ipv4() {
        let mut engine = SearchEngine::new().unwrap();
        let events = vec![make_event(&[
            ("DestinationIp", "8.8.8.8"),
            ("SourceIp", "192.168.1.1"),
        ])];
        engine.load_events(&events).unwrap();
        let iocs = extract_iocs(&engine).unwrap();
        assert!(iocs
            .iter()
            .any(|i| i.ioc_type == IocType::Ipv4 && i.value == "8.8.8.8"));
        assert!(!iocs.iter().any(|i| i.value == "192.168.1.1"));
    }

    #[test]
    fn test_extract_hash() {
        let mut engine = SearchEngine::new().unwrap();
        let events = vec![make_event(&[("Hash", "d41d8cd98f00b204e9800998ecf8427e")])];
        engine.load_events(&events).unwrap();
        let iocs = extract_iocs(&engine).unwrap();
        assert!(iocs.iter().any(|i| i.ioc_type == IocType::Md5));
    }

    #[test]
    fn test_is_valid_public_ip() {
        // Valid public IPs
        assert!(is_valid_public_ip("8.8.8.8"));
        assert!(is_valid_public_ip("1.2.3.4"));
        assert!(is_valid_public_ip("89.191.225.226"));
        assert!(is_valid_public_ip("217.77.111.31"));
        // Private / reserved
        assert!(!is_valid_public_ip("10.0.0.1"));
        assert!(!is_valid_public_ip("192.168.1.1"));
        assert!(!is_valid_public_ip("127.0.0.1"));
        // Network / broadcast
        assert!(!is_valid_public_ip("15.0.0.0"));
        assert!(!is_valid_public_ip("8.8.0.0"));
        assert!(!is_valid_public_ip("1.2.3.255"));
        // Leading zeros (dates)
        assert!(!is_valid_public_ip("03.10.21.57"));
        assert!(!is_valid_public_ip("08.09.17.54"));
        assert!(!is_valid_public_ip("01.24.16.46"));
        // OID fragments
        assert!(!is_valid_public_ip("1.3.6.1"));
        assert!(!is_valid_public_ip("5.5.7.3"));
        assert!(!is_valid_public_ip("1.3.14.3"));
        assert!(!is_valid_public_ip("101.3.4.2"));
        assert!(!is_valid_public_ip("2.5.4.3"));
    }

    #[test]
    fn test_noise_filters() {
        // URLs
        assert!(is_noise_url(
            "http://schemas.microsoft.com/win/2004/08/events/"
        ));
        assert!(is_noise_url("https://localhost/OWA/"));
        assert!(is_noise_url(
            "https://mail.vnii-np.local:444/rpc/rpcproxy.dll"
        ));
        assert!(is_noise_url("http://192.168.0.23:13000"));
        assert!(is_noise_url("http://docs.oasis-open.org/wss/2004/XX/oasis"));
        assert!(is_noise_url(
            "https://localhost/AutoDiscover/\\r\\n[000,000"
        ));
        assert!(is_noise_url(
            "https://umail51.com/ru/v5/unsubscribe/immediately"
        ));
        assert!(!is_noise_url("https://evil-c2.xyz/payload.exe"));
        // Domains
        assert!(is_noise_domain("microsoft.com"));
        assert!(is_noise_domain("update.microsoft.com"));
        assert!(is_noise_domain("server.local"));
        assert!(is_noise_domain("outlook.com"));
        assert!(is_noise_domain("gmail.com"));
        assert!(is_noise_domain("oasis-open.org"));
        assert!(is_noise_domain("msol-test.com"));
        assert!(is_noise_domain("localhost.com"));
        assert!(!is_noise_domain("evil-c2.xyz"));
        assert!(!is_noise_domain("rosneft.ru"));
        // Emails
        assert!(is_noise_email("healthmailboxa549@vnii-np.local"));
        assert!(is_noise_email(
            "82ec3c51-1fa3-41e7-917e-6d10f866a02d@example.com"
        ));
        assert!(is_noise_email("dummy@localhost.com"));
        assert!(is_noise_email("abuse@umail51.com"));
        assert!(is_noise_email("nobody@host.superjob.ru"));
        assert!(is_noise_email("postman6134245@umail51.com"));
        assert!(is_noise_email("bookingmailbox@doesntexist.nonexistenttld"));
        assert!(is_noise_email("%m@vniinp.ru"));
        assert!(is_noise_email(
            "12391522b37ba2cc4c22b645003316de@icecer.com"
        ));
        assert!(is_noise_email(
            "20260324093419.0.20260324093419_eui_@503.15417.23371.pl"
        ));
        assert!(!is_noise_email("user@evil-c2.xyz"));
        assert!(!is_noise_email("fulladmin@vniinp.rosneft.ru"));
        // Hashes
        assert!(is_plausible_hash("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(!is_plausible_hash("020001bdc0a800250000000000000000"));
        assert!(!is_plausible_hash("02000000c0a800190000000000000000"));
        assert!(!is_plausible_hash("01126805131833587686824187554612")); // all-digit
        assert!(!is_plausible_hash("52182716077268156717685368086654")); // all-digit
    }

    #[test]
    fn test_streaming_collector_field_aware() {
        let mut collector = IocCollector::new();
        let events = vec![
            make_event(&[
                ("DestinationIp", "8.8.8.8"),
                ("SourceIp", "192.168.1.1"),
                ("SystemTime", "2026-03-15T08:12:33Z"),
            ]),
            make_event(&[
                ("url", "https://evil.xyz/malware"),
                ("domain", "evil.xyz"),
                ("Description", "OID 1.3.6.1.4.1.311 seen in cert"),
            ]),
        ];
        collector.process_events(&events);
        let iocs = collector.finalize();
        // Real IP from DestinationIp field
        assert!(iocs
            .iter()
            .any(|i| i.ioc_type == IocType::Ipv4 && i.value == "8.8.8.8"));
        // Private IP excluded
        assert!(!iocs.iter().any(|i| i.value == "192.168.1.1"));
        // OID not extracted as IP (field-aware: not in IP field; raw contains it but leading zeros or OID filter)
        assert!(!iocs
            .iter()
            .any(|i| i.ioc_type == IocType::Ipv4 && i.value == "1.3.6.1"));
        // URL found
        assert!(iocs.iter().any(|i| i.ioc_type == IocType::Url));
        // Context: first_seen populated
        let ip_ioc = iocs
            .iter()
            .find(|i| i.ioc_type == IocType::Ipv4 && i.value == "8.8.8.8")
            .unwrap();
        assert!(ip_ioc.first_seen.is_some());
        assert!(ip_ioc.source_files.contains(&"test.log".to_string()));
    }

    #[test]
    fn test_ip_field_detection() {
        assert!(is_ip_field("SourceIp"));
        assert!(is_ip_field("DestinationIp"));
        assert!(is_ip_field("ClientIPAddress"));
        assert!(is_ip_field("RemoteAddress"));
        assert!(is_ip_field("src_ip"));
        assert!(!is_ip_field("Description"));
        assert!(!is_ip_field("Script"));
        assert!(!is_ip_field("EmailAddress"));
    }

    #[test]
    fn test_extract_filepath() {
        let mut collector = IocCollector::new();
        let events = vec![make_event(&[
            ("Image", r"C:\Users\admin\Desktop\malware.exe"),
            ("ParentImage", r"C:\Windows\System32\cmd.exe"),
            ("SystemTime", "2026-03-20T14:00:00Z"),
        ])];
        collector.process_events(&events);
        let iocs = collector.finalize();
        assert!(iocs
            .iter()
            .any(|i| i.ioc_type == IocType::FilePath
                && i.value == r"C:\Users\admin\Desktop\malware.exe"));
        assert!(iocs
            .iter()
            .any(|i| i.ioc_type == IocType::FilePath && i.value == r"C:\Windows\System32\cmd.exe"));
        // Source field is recorded
        let malware_ioc = iocs
            .iter()
            .find(|i| i.value == r"C:\Users\admin\Desktop\malware.exe")
            .unwrap();
        assert!(malware_ioc.source_fields.contains(&"Image".to_string()));
    }

    #[test]
    fn test_noise_filepath_filtered() {
        let mut collector = IocCollector::new();
        let events = vec![make_event(&[
            ("Image", r"C:\Windows\System32\svchost.exe"),
            ("ParentImage", r"C:\Windows\System32\services.exe"),
            (
                "ImageLoaded",
                r"C:\Windows\WinSxS\amd64_something\ntdll.dll",
            ),
        ])];
        collector.process_events(&events);
        let iocs = collector.finalize();
        // All noise paths should be filtered out — no FilePath IOCs
        assert!(
            !iocs.iter().any(|i| i.ioc_type == IocType::FilePath),
            "Expected no FilePath IOCs but found: {:?}",
            iocs.iter()
                .filter(|i| i.ioc_type == IocType::FilePath)
                .map(|i| &i.value)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_extract_registry() {
        let mut collector = IocCollector::new();
        let events = vec![make_event(&[
            (
                "TargetObject",
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Backdoor",
            ),
            ("SystemTime", "2026-03-20T14:00:00Z"),
        ])];
        collector.process_events(&events);
        let iocs = collector.finalize();
        assert!(iocs.iter().any(|i| i.ioc_type == IocType::RegistryKey
            && i.value == r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Backdoor"));
    }

    #[test]
    fn test_noise_registry_filtered() {
        let mut collector = IocCollector::new();
        let events = vec![make_event(&[(
            "TargetObject",
            r"HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\S-1-5-21",
        )])];
        collector.process_events(&events);
        let iocs = collector.finalize();
        assert!(!iocs.iter().any(|i| i.ioc_type == IocType::RegistryKey));
    }

    #[test]
    fn test_extract_service() {
        let mut collector = IocCollector::new();
        let events = vec![make_event(&[
            ("ServiceName", "EvilService"),
            ("SystemTime", "2026-03-20T14:00:00Z"),
        ])];
        collector.process_events(&events);
        let iocs = collector.finalize();
        assert!(iocs
            .iter()
            .any(|i| i.ioc_type == IocType::ServiceName && i.value == "EvilService"));
    }

    #[test]
    fn test_extract_task() {
        let mut collector = IocCollector::new();
        let events = vec![make_event(&[
            ("TaskName", r"\MaliciousTask"),
            ("SystemTime", "2026-03-20T14:00:00Z"),
        ])];
        collector.process_events(&events);
        let iocs = collector.finalize();
        assert!(iocs
            .iter()
            .any(|i| i.ioc_type == IocType::TaskName && i.value == r"\MaliciousTask"));
    }

    #[test]
    fn test_extract_pipe() {
        let mut collector = IocCollector::new();
        let events = vec![make_event(&[
            ("PipeName", r"\evil_pipe"),
            ("SystemTime", "2026-03-20T14:00:00Z"),
        ])];
        collector.process_events(&events);
        let iocs = collector.finalize();
        assert!(iocs
            .iter()
            .any(|i| i.ioc_type == IocType::PipeName && i.value == r"\evil_pipe"));
    }

    #[test]
    fn test_pipe_noise_filtered() {
        let mut collector = IocCollector::new();
        let events = vec![
            make_event(&[("PipeName", "-")]),
            make_event(&[("PipeName", "")]),
            make_event(&[("PipeName", r"\")]),
        ];
        collector.process_events(&events);
        let iocs = collector.finalize();
        assert!(!iocs.iter().any(|i| i.ioc_type == IocType::PipeName));
    }

    #[test]
    fn test_field_detection_helpers() {
        // filepath fields
        assert!(is_filepath_field("Image"));
        assert!(is_filepath_field("image"));
        assert!(is_filepath_field("ParentImage"));
        assert!(is_filepath_field("TargetFilename"));
        assert!(is_filepath_field("ImageLoaded"));
        assert!(is_filepath_field("ServiceFileName"));
        assert!(!is_filepath_field("CommandLine"));
        assert!(!is_filepath_field("Hashes"));
        assert!(!is_filepath_field("Description"));
        // registry fields
        assert!(is_registry_field("TargetObject"));
        assert!(is_registry_field("ObjectName"));
        assert!(!is_registry_field("Image"));
        // service fields
        assert!(is_service_field("ServiceName"));
        assert!(is_service_field("Service_Name"));
        assert!(!is_service_field("Image"));
        // task fields
        assert!(is_task_field("TaskName"));
        assert!(!is_task_field("ServiceName"));
        // pipe fields
        assert!(is_pipe_field("PipeName"));
        assert!(!is_pipe_field("TaskName"));
    }
}
