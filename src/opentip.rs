//! Kaspersky OpenTIP integration — comprehensive IOC lookup via the OpenTIP REST API.
//!
//! This module provides a client that checks hashes, IPs, domains, and URLs
//! against Kaspersky's Open Threat Intelligence Portal, returning structured
//! threat-zone results with detailed metadata.
//!
//! Feature-gated behind `ioc-enrich`.

use serde::Serialize;
use std::collections::HashSet;

use crate::ioc::{Ioc, IocType};

// ═══════════════════════════════════════════════════════════════════════════
// Zone
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Zone {
    Red,
    Orange,
    Yellow,
    Grey,
    Green,
}

impl Zone {
    pub fn from_str_zone(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "red" => Zone::Red,
            "orange" => Zone::Orange,
            "yellow" => Zone::Yellow,
            "green" => Zone::Green,
            _ => Zone::Grey,
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Zone::Red => 5,
            Zone::Orange => 4,
            Zone::Yellow => 3,
            Zone::Grey => 2,
            Zone::Green => 1,
        }
    }
}

impl std::fmt::Display for Zone {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Zone::Red => write!(f, "RED"),
            Zone::Orange => write!(f, "ORANGE"),
            Zone::Yellow => write!(f, "YELLOW"),
            Zone::Grey => write!(f, "GREY"),
            Zone::Green => write!(f, "GREEN"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Detail structs
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct HashDetails {
    pub sha256: Option<String>,
    pub sha1: Option<String>,
    pub md5: Option<String>,
    pub file_type: Option<String>,
    pub file_size: Option<u64>,
    pub signer: Option<String>,
    pub packer: Option<String>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub hits_count: Option<u64>,
    pub detection_name: Option<String>,
    pub dynamic_detections: Vec<String>,
    pub suspicious_activities: usize,
    pub network_activities: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct IpDetails {
    pub country_code: Option<String>,
    pub asn: Option<String>,
    pub as_description: Option<String>,
    pub net_name: Option<String>,
    pub net_range: Option<String>,
    pub categories: Vec<String>,
    pub hits_count: Option<u64>,
    pub first_seen: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DomainDetails {
    pub files_count: Option<u64>,
    pub urls_count: Option<u64>,
    pub hits_count: Option<u64>,
    pub ipv4_count: Option<u64>,
    pub categories: Vec<String>,
    pub created: Option<String>,
    pub expires: Option<String>,
    pub registrar: Option<String>,
    pub name_servers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UrlDetails {
    pub host: Option<String>,
    pub ipv4_count: Option<u64>,
    pub files_count: Option<u64>,
    pub categories: Vec<String>,
    pub domain_created: Option<String>,
    pub registrar: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub enum OpenTipDetails {
    Hash(HashDetails),
    Ip(IpDetails),
    Domain(DomainDetails),
    Url(UrlDetails),
}

// ═══════════════════════════════════════════════════════════════════════════
// Result
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize)]
pub struct OpenTipResult {
    pub ioc_type: String,
    pub value: String,
    pub zone: Zone,
    pub details: OpenTipDetails,
    pub portal_url: String,
    pub raw_response: Option<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Client
// ═══════════════════════════════════════════════════════════════════════════

const BASE_URL: &str = "https://opentip.kaspersky.com/api/v1/search";
const PORTAL_URL: &str = "https://opentip.kaspersky.com";

pub struct OpenTipClient {
    api_key: String,
}

impl OpenTipClient {
    pub fn new(api_key: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
        }
    }

    /// Check IOCs against OpenTIP. Deduplicates values, prioritizes by type.
    /// `max_checks` limits total API calls (daily quota is 2000).
    /// `type_filter` controls which IOC types to check: "all", or comma-separated "hash,ip,domain,url".
    pub fn check_iocs(
        &self,
        iocs: &[Ioc],
        max_checks: usize,
        quiet: bool,
        type_filter: &str,
    ) -> Vec<OpenTipResult> {
        // Parse type filter
        let filter_all = type_filter == "all";
        let filter_hash = filter_all || type_filter.contains("hash");
        let filter_ip = filter_all || type_filter.contains("ip");
        let filter_domain = filter_all || type_filter.contains("domain");
        let filter_url = filter_all || type_filter.contains("url");

        // Deduplicate by (type_label, value)
        let mut seen = HashSet::new();
        let mut unique: Vec<(&str, &str, &IocType)> = Vec::new();

        for ioc in iocs {
            let type_label = match ioc.ioc_type {
                IocType::Sha256 if filter_hash => "hash",
                IocType::Sha1 if filter_hash => "hash",
                IocType::Md5 if filter_hash => "hash",
                IocType::Ipv4 if filter_ip => "ip",
                IocType::Domain if filter_domain => "domain",
                IocType::Url if filter_url => "url",
                _ => continue,
            };
            let key = (type_label, ioc.value.as_str());
            if seen.insert(key.to_owned()) {
                unique.push((type_label, &ioc.value, &ioc.ioc_type));
            }
        }

        // Prioritize: SHA256 first, then SHA1, MD5, IPv4, Domain, URL
        unique.sort_by_key(|(_, _, ioc_type)| match ioc_type {
            IocType::Sha256 => 0,
            IocType::Sha1 => 1,
            IocType::Md5 => 2,
            IocType::Ipv4 => 3,
            IocType::Domain => 4,
            IocType::Url => 5,
            _ => 6,
        });

        let total = unique.len().min(max_checks);
        let concurrency = 10; // parallel workers

        // Prepare work items
        let work_items: Vec<(String, String, String)> = unique
            .iter()
            .take(max_checks)
            .map(|(type_label, value, ioc_type)| {
                let ioc_type_display = match ioc_type {
                    IocType::Sha256 => "SHA256",
                    IocType::Sha1 => "SHA1",
                    IocType::Md5 => "MD5",
                    IocType::Ipv4 => "IPv4",
                    IocType::Domain => "Domain",
                    IocType::Url => "URL",
                    _ => "Unknown",
                };
                (
                    type_label.to_string(),
                    value.to_string(),
                    ioc_type_display.to_string(),
                )
            })
            .collect();

        // Progress output is handled by the caller (spinner in muninn.rs)

        // Parallel execution with bounded concurrency
        let (tx, rx) = std::sync::mpsc::channel::<Option<OpenTipResult>>();
        let api_key = self.api_key.clone();
        let stopped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let progress = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let chunks: Vec<Vec<(String, String, String)>> = work_items
            .chunks(work_items.len().div_ceil(concurrency).max(1))
            .map(|c| c.to_vec())
            .collect();

        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| {
                let tx = tx.clone();
                let api_key = api_key.clone();
                let stopped = stopped.clone();
                let progress = progress.clone();
                let _thread_total = total;
                let is_quiet = quiet;

                std::thread::spawn(move || {
                    let agent = ureq::AgentBuilder::new()
                        .timeout(std::time::Duration::from_secs(15))
                        .build();

                    for (type_label, value, ioc_type_display) in &chunk {
                        if stopped.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }

                        progress.fetch_add(1, std::sync::atomic::Ordering::Relaxed);

                        let endpoint = format!("{}/{}?request={}", BASE_URL, type_label, value);

                        match agent.get(&endpoint).set("x-api-key", &api_key).call() {
                            Ok(resp) => {
                                let body = resp.into_string().unwrap_or_default();
                                let json: serde_json::Value =
                                    serde_json::from_str(&body).unwrap_or(serde_json::Value::Null);

                                let zone_str = json["Zone"].as_str().unwrap_or("Grey");
                                let zone = Zone::from_str_zone(zone_str);

                                let details = match type_label.as_str() {
                                    "hash" => parse_hash_details(&json),
                                    "ip" => parse_ip_details(&json),
                                    "domain" => parse_domain_details(&json),
                                    "url" => parse_url_details(&json),
                                    _ => continue,
                                };

                                let _ = tx.send(Some(OpenTipResult {
                                    ioc_type: ioc_type_display.clone(),
                                    value: value.clone(),
                                    zone,
                                    details,
                                    portal_url: format!("{}/{}", PORTAL_URL, value),
                                    raw_response: Some(body),
                                }));
                            }
                            Err(ureq::Error::Status(403, _)) | Err(ureq::Error::Status(429, _)) => {
                                if !is_quiet {
                                    eprintln!("  [!] API quota/rate limit reached. Stopping.");
                                }
                                stopped.store(true, std::sync::atomic::Ordering::Relaxed);
                                break;
                            }
                            Err(ureq::Error::Status(404, _)) => {
                                // Not found — skip
                            }
                            Err(e) => {
                                log::debug!("OpenTIP request failed for {}: {}", value, e);
                            }
                        }
                    }
                })
            })
            .collect();

        drop(tx); // Close sender so rx iterator terminates

        // Collect results from all workers
        let mut results: Vec<OpenTipResult> = rx.into_iter().flatten().collect();

        // Wait for all threads
        for h in handles {
            let _ = h.join();
        }

        let checked = progress.load(std::sync::atomic::Ordering::Relaxed);
        let was_stopped = stopped.load(std::sync::atomic::Ordering::Relaxed);
        if !quiet {
            if was_stopped {
                let skipped = total.saturating_sub(checked);
                eprintln!(
                    "  [!] OpenTIP daily quota exhausted after {} checks. {} IOCs were NOT checked.",
                    checked, skipped
                );
                eprintln!(
                    "  [!] Quota resets daily. Re-run tomorrow or use --opentip-types to prioritize."
                );
            } else {
                println!("  Checked {} IOCs", checked);
            }
        }

        // Sort results: Red first, then Orange, Yellow, Grey, Green
        results.sort_by(|a, b| b.zone.rank().cmp(&a.zone.rank()));

        results
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Response parsers
// ═══════════════════════════════════════════════════════════════════════════

fn parse_hash_details(json: &serde_json::Value) -> OpenTipDetails {
    let info = &json["FileGeneralInfo"];

    let detection_name = json["DetectionsInfo"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|d| d["DetectionName"].as_str())
        .map(|s| s.to_string());

    let dynamic = &json["DynamicAnalisysResults"];
    let dynamic_detections: Vec<String> = dynamic["DynamicDetections"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|d| d["Threat"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let suspicious_activities = dynamic["SuspiciousActivities"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|a| a["Count"].as_u64()).sum::<u64>() as usize)
        .unwrap_or(0);

    let network_activities = dynamic["NetworkActivities"]
        .as_array()
        .map(|arr| arr.iter().filter_map(|a| a["Count"].as_u64()).sum::<u64>() as usize)
        .unwrap_or(0);

    OpenTipDetails::Hash(HashDetails {
        sha256: info["Sha256"].as_str().map(|s| s.to_string()),
        sha1: info["Sha1"].as_str().map(|s| s.to_string()),
        md5: info["Md5"].as_str().map(|s| s.to_string()),
        file_type: info["Type"].as_str().map(|s| s.to_string()),
        file_size: info["Size"].as_u64(),
        signer: info["Signer"].as_str().map(|s| s.to_string()),
        packer: info["Packer"].as_str().map(|s| s.to_string()),
        first_seen: info["FirstSeen"].as_str().map(|s| s.to_string()),
        last_seen: info["LastSeen"].as_str().map(|s| s.to_string()),
        hits_count: info["HitsCount"].as_u64(),
        detection_name,
        dynamic_detections,
        suspicious_activities,
        network_activities,
    })
}

fn parse_ip_details(json: &serde_json::Value) -> OpenTipDetails {
    let info = &json["IpGeneralInfo"];
    let whois = &json["IpWhoIs"];

    let asn = whois["Asn"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|a| a["Number"].as_u64())
        .map(|n| format!("AS{}", n));

    let as_description = whois["Asn"]
        .as_array()
        .and_then(|arr| arr.first())
        .and_then(|a| a["Description"].as_str())
        .map(|s| s.to_string());

    let net_name = whois["Net"]["Name"].as_str().map(|s| s.to_string());

    let net_range = match (
        whois["Net"]["RangeStart"].as_str(),
        whois["Net"]["RangeEnd"].as_str(),
    ) {
        (Some(start), Some(end)) => Some(format!("{} - {}", start, end)),
        _ => None,
    };

    let categories = extract_categories_with_zone(json);

    OpenTipDetails::Ip(IpDetails {
        country_code: info["CountryCode"].as_str().map(|s| s.to_string()),
        asn,
        as_description,
        net_name,
        net_range,
        categories,
        hits_count: info["HitsCount"].as_u64(),
        first_seen: info["FirstSeen"].as_str().map(|s| s.to_string()),
    })
}

fn parse_domain_details(json: &serde_json::Value) -> OpenTipDetails {
    let info = &json["DomainGeneralInfo"];
    let whois = &json["DomainWhoIsInfo"];

    let categories = extract_categories_from_general_info(info);

    let name_servers: Vec<String> = whois["NameServers"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let registrar = whois["Registrar"]["Info"]
        .as_str()
        .or_else(|| whois["Registrar"].as_str())
        .map(|s| s.to_string());

    OpenTipDetails::Domain(DomainDetails {
        files_count: info["FilesCount"].as_u64(),
        urls_count: info["UrlsCount"].as_u64(),
        hits_count: info["HitsCount"].as_u64(),
        ipv4_count: info["Ipv4Count"].as_u64(),
        categories,
        created: whois["Created"].as_str().map(|s| s.to_string()),
        expires: whois["Expires"].as_str().map(|s| s.to_string()),
        registrar,
        name_servers,
    })
}

fn parse_url_details(json: &serde_json::Value) -> OpenTipDetails {
    let info = &json["UrlGeneralInfo"];
    let whois = &json["UrlDomainWhoIs"];

    let categories = extract_categories_from_general_info(info);

    let registrar = whois["Registrar"]["Info"]
        .as_str()
        .or_else(|| whois["Registrar"].as_str())
        .map(|s| s.to_string());

    OpenTipDetails::Url(UrlDetails {
        host: info["Host"].as_str().map(|s| s.to_string()),
        ipv4_count: info["Ipv4Count"].as_u64(),
        files_count: info["FilesCount"].as_u64(),
        categories,
        domain_created: whois["Created"].as_str().map(|s| s.to_string()),
        registrar,
    })
}

/// Extract category names from CategoriesWithZone array at root level (IP endpoint).
fn extract_categories_with_zone(json: &serde_json::Value) -> Vec<String> {
    json["CategoriesWithZone"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c["Name"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Extract category names from CategoriesWithZone within a GeneralInfo object (domain/URL).
fn extract_categories_from_general_info(info: &serde_json::Value) -> Vec<String> {
    info["CategoriesWithZone"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|c| c["Name"].as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

// ═══════════════════════════════════════════════════════════════════════════
// Render
// ═══════════════════════════════════════════════════════════════════════════

fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(ch);
    }
    result.chars().rev().collect()
}

/// Render full report (for file output).
pub fn render_opentip_report(results: &[OpenTipResult]) -> String {
    render_opentip_inner(results, false)
}

/// Render console report — only RED/ORANGE/YELLOW + summary.
pub fn render_opentip_console(results: &[OpenTipResult]) -> String {
    render_opentip_inner(results, true)
}

fn render_opentip_inner(results: &[OpenTipResult], console_only: bool) -> String {
    if results.is_empty() {
        return "  No OpenTIP results.\n".into();
    }

    let mut output = String::new();
    output.push_str("\n  Kaspersky OpenTIP Report\n");
    output.push_str(&format!("  {}\n\n", "\u{2550}".repeat(56)));

    for r in results {
        // Console mode: skip GREEN and GREY (clean/unknown)
        if console_only && matches!(r.zone, Zone::Green | Zone::Grey) {
            continue;
        }
        output.push_str(&format!("  [{}] {} {}\n", r.zone, r.ioc_type, r.value));

        match &r.details {
            OpenTipDetails::Hash(h) => {
                if let Some(ref det) = h.detection_name {
                    output.push_str(&format!("        Detection: {}\n", det));
                }
                let file_type = h.file_type.as_deref().unwrap_or("unknown");
                let size_str = h
                    .file_size
                    .map(|s| format!("{} bytes", format_number(s)))
                    .unwrap_or_else(|| "unknown".into());
                output.push_str(&format!(
                    "        File type: {}, Size: {}\n",
                    file_type, size_str
                ));
                let signer = h.signer.as_deref().unwrap_or("(unsigned)");
                let packer = h.packer.as_deref().unwrap_or("(none)");
                output.push_str(&format!("        Signer: {}, Packer: {}\n", signer, packer));
                let first = h.first_seen.as_deref().unwrap_or("N/A");
                let last = h.last_seen.as_deref().unwrap_or("N/A");
                output.push_str(&format!(
                    "        First seen: {}, Last seen: {}\n",
                    first, last
                ));
                let hits = h
                    .hits_count
                    .map(format_number)
                    .unwrap_or_else(|| "0".into());
                output.push_str(&format!(
                    "        Hits: {} | Dynamic: {} detections, {} suspicious\n",
                    hits,
                    h.dynamic_detections.len(),
                    h.suspicious_activities
                ));
            }
            OpenTipDetails::Ip(ip) => {
                let country = ip.country_code.as_deref().unwrap_or("??");
                let asn_str = ip.asn.as_deref().unwrap_or("N/A");
                let as_desc = ip.as_description.as_deref().unwrap_or("");
                if as_desc.is_empty() {
                    output.push_str(&format!(
                        "        Country: {} | ASN: {}\n",
                        country, asn_str
                    ));
                } else {
                    output.push_str(&format!(
                        "        Country: {} | ASN: {} ({})\n",
                        country, asn_str, as_desc
                    ));
                }
                if let Some(ref range) = ip.net_range {
                    output.push_str(&format!("        Net: {}\n", range));
                }
                let cats = if ip.categories.is_empty() {
                    "(none)".to_string()
                } else {
                    ip.categories.join(", ")
                };
                output.push_str(&format!("        Categories: {}\n", cats));
                let hits = ip
                    .hits_count
                    .map(format_number)
                    .unwrap_or_else(|| "0".into());
                let first = ip.first_seen.as_deref().unwrap_or("N/A");
                output.push_str(&format!("        Hits: {} | First seen: {}\n", hits, first));
            }
            OpenTipDetails::Domain(d) => {
                let files = d.files_count.unwrap_or(0);
                let urls = d.urls_count.unwrap_or(0);
                let ips = d.ipv4_count.unwrap_or(0);
                output.push_str(&format!(
                    "        Files: {} | URLs: {} | IPs: {}\n",
                    files, urls, ips
                ));
                if let Some(ref reg) = d.registrar {
                    output.push_str(&format!("        Registrar: {}\n", reg));
                }
                let created = d.created.as_deref().unwrap_or("N/A");
                let expires = d.expires.as_deref().unwrap_or("N/A");
                output.push_str(&format!(
                    "        Created: {} | Expires: {}\n",
                    created, expires
                ));
                let cats = if d.categories.is_empty() {
                    "(none)".to_string()
                } else {
                    d.categories.join(", ")
                };
                output.push_str(&format!("        Categories: {}\n", cats));
            }
            OpenTipDetails::Url(u) => {
                let host = u.host.as_deref().unwrap_or("N/A");
                let ips = u.ipv4_count.unwrap_or(0);
                let files = u.files_count.unwrap_or(0);
                output.push_str(&format!(
                    "        Host: {} | IPs: {} | Files: {}\n",
                    host, ips, files
                ));
                if let Some(ref reg) = u.registrar {
                    output.push_str(&format!("        Registrar: {}\n", reg));
                }
                if let Some(ref created) = u.domain_created {
                    output.push_str(&format!("        Domain created: {}\n", created));
                }
                let cats = if u.categories.is_empty() {
                    "(none)".to_string()
                } else {
                    u.categories.join(", ")
                };
                output.push_str(&format!("        Categories: {}\n", cats));
            }
        }

        output.push_str(&format!("        {}\n\n", r.portal_url));
    }

    // Summary line
    let mut red = 0usize;
    let mut orange = 0usize;
    let mut yellow = 0usize;
    let mut green = 0usize;
    let mut grey = 0usize;
    for r in results {
        match r.zone {
            Zone::Red => red += 1,
            Zone::Orange => orange += 1,
            Zone::Yellow => yellow += 1,
            Zone::Green => green += 1,
            Zone::Grey => grey += 1,
        }
    }

    output.push_str(&format!("  {}\n", "\u{2550}".repeat(56)));
    output.push_str(&format!(
        "  Summary: {} RED, {} ORANGE, {} YELLOW, {} GREEN, {} GREY ({} checked)\n",
        red,
        orange,
        yellow,
        green,
        grey,
        results.len()
    ));

    output
}

/// Generate interactive HTML report for OpenTIP results.
pub fn render_opentip_html(results: &[OpenTipResult]) -> String {
    let mut rows = String::new();
    for r in results {
        let zone_class = match r.zone {
            Zone::Red => "zone-red",
            Zone::Orange => "zone-orange",
            Zone::Yellow => "zone-yellow",
            Zone::Green => "zone-green",
            Zone::Grey => "zone-grey",
        };
        let (details_html, detection) = match &r.details {
            OpenTipDetails::Hash(h) => {
                let det = h.detection_name.as_deref().unwrap_or("-");
                let info = format!(
                    "Type: {} | Size: {} | Signer: {} | Packer: {} | Hits: {} | First: {} | Last: {}",
                    h.file_type.as_deref().unwrap_or("-"),
                    h.file_size.map(format_number).unwrap_or_else(|| "-".into()),
                    h.signer.as_deref().unwrap_or("-"),
                    h.packer.as_deref().unwrap_or("-"),
                    h.hits_count.map(format_number).unwrap_or_else(|| "0".into()),
                    h.first_seen.as_deref().unwrap_or("-"),
                    h.last_seen.as_deref().unwrap_or("-"),
                );
                (info, det.to_string())
            }
            OpenTipDetails::Ip(ip) => {
                let info = format!(
                    "Country: {} | ASN: {} {} | Net: {} | Hits: {} | First: {} | Categories: {}",
                    ip.country_code.as_deref().unwrap_or("??"),
                    ip.asn.as_deref().unwrap_or("-"),
                    ip.as_description.as_deref().unwrap_or(""),
                    ip.net_range.as_deref().unwrap_or("-"),
                    ip.hits_count
                        .map(format_number)
                        .unwrap_or_else(|| "0".into()),
                    ip.first_seen.as_deref().unwrap_or("-"),
                    if ip.categories.is_empty() {
                        "-".to_string()
                    } else {
                        ip.categories.join(", ")
                    },
                );
                (info, "-".to_string())
            }
            OpenTipDetails::Domain(d) => {
                let info = format!(
                    "Files: {} | URLs: {} | IPs: {} | Hits: {} | Registrar: {} | Created: {} | Expires: {} | Categories: {}",
                    d.files_count.unwrap_or(0),
                    d.urls_count.unwrap_or(0),
                    d.ipv4_count.unwrap_or(0),
                    d.hits_count.map(format_number).unwrap_or_else(|| "0".into()),
                    d.registrar.as_deref().unwrap_or("-"),
                    d.created.as_deref().unwrap_or("-"),
                    d.expires.as_deref().unwrap_or("-"),
                    if d.categories.is_empty() { "-".to_string() } else { d.categories.join(", ") },
                );
                (info, "-".to_string())
            }
            OpenTipDetails::Url(u) => {
                let info = format!(
                    "Host: {} | IPs: {} | Files: {} | Registrar: {} | Categories: {}",
                    u.host.as_deref().unwrap_or("-"),
                    u.ipv4_count.unwrap_or(0),
                    u.files_count.unwrap_or(0),
                    u.registrar.as_deref().unwrap_or("-"),
                    if u.categories.is_empty() {
                        "-".to_string()
                    } else {
                        u.categories.join(", ")
                    },
                );
                (info, "-".to_string())
            }
        };
        rows.push_str(&format!(
            "<tr class=\"{zc}\"><td><span class=\"zone-badge {zc}\">{zone}</span></td><td>{ioc_type}</td><td><a href=\"{url}\" target=\"_blank\">{value}</a></td><td>{detection}</td><td>{details}</td></tr>\n",
            zc = zone_class,
            zone = r.zone,
            ioc_type = r.ioc_type,
            url = r.portal_url,
            value = r.value,
            detection = detection,
            details = details_html,
        ));
    }

    // Zone summary counts
    let (mut red, mut orange, mut yellow, mut green, mut grey) = (0, 0, 0, 0, 0);
    for r in results {
        match r.zone {
            Zone::Red => red += 1,
            Zone::Orange => orange += 1,
            Zone::Yellow => yellow += 1,
            Zone::Green => green += 1,
            Zone::Grey => grey += 1,
        }
    }

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Muninn — Kaspersky OpenTIP Report</title>
<link rel="stylesheet" href="https://cdn.datatables.net/1.13.7/css/jquery.dataTables.min.css">
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 20px; background: #1a1a2e; color: #e0e0e0; }}
h1 {{ color: #00d4ff; margin-bottom: 5px; }}
.subtitle {{ color: #888; margin-bottom: 20px; }}
.summary-bar {{ display: flex; gap: 15px; margin: 15px 0; flex-wrap: wrap; }}
.summary-item {{ padding: 8px 16px; border-radius: 6px; font-weight: bold; font-size: 1.1em; }}
.summary-red {{ background: #5c1a1a; color: #ff4444; border: 1px solid #ff4444; }}
.summary-orange {{ background: #5c3a1a; color: #ff8800; border: 1px solid #ff8800; }}
.summary-yellow {{ background: #5c5c1a; color: #ffcc00; border: 1px solid #ffcc00; }}
.summary-green {{ background: #1a5c1a; color: #44ff44; border: 1px solid #44ff44; }}
.summary-grey {{ background: #3a3a3a; color: #aaa; border: 1px solid #666; }}
table.dataTable {{ background: #16213e; color: #e0e0e0; }}
table.dataTable thead {{ background: #0f3460; }}
table.dataTable tbody tr:hover {{ background: #1a1a4e !important; }}
a {{ color: #00d4ff; text-decoration: none; }}
a:hover {{ text-decoration: underline; }}
.zone-badge {{ padding: 2px 8px; border-radius: 3px; font-weight: bold; font-size: 0.85em; }}
.zone-red {{ color: #ff4444; }}
.zone-red .zone-badge {{ background: #5c1a1a; }}
.zone-orange {{ color: #ff8800; }}
.zone-orange .zone-badge {{ background: #5c3a1a; }}
.zone-yellow {{ color: #ffcc00; }}
.zone-yellow .zone-badge {{ background: #5c5c1a; }}
.zone-green {{ color: #44ff44; }}
.zone-green .zone-badge {{ background: #1a5c1a; }}
.zone-grey {{ color: #aaa; }}
.zone-grey .zone-badge {{ background: #3a3a3a; }}
td {{ max-width: 400px; word-wrap: break-word; overflow-wrap: break-word; }}
</style>
</head>
<body>
<h1>Muninn &mdash; Kaspersky OpenTIP Report</h1>
<p class="subtitle">{total} indicators checked</p>

<div class="summary-bar">
  <div class="summary-item summary-red">{red} Red</div>
  <div class="summary-item summary-orange">{orange} Orange</div>
  <div class="summary-item summary-yellow">{yellow} Yellow</div>
  <div class="summary-item summary-green">{green} Green</div>
  <div class="summary-item summary-grey">{grey} Grey</div>
</div>

<table id="otipTable" class="display" style="width:100%">
<thead>
<tr><th>Zone</th><th>Type</th><th>Value</th><th>Detection</th><th>Details</th></tr>
</thead>
<tbody>
{rows}
</tbody>
</table>

<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
<script src="https://cdn.datatables.net/1.13.7/js/jquery.dataTables.min.js"></script>
<script>
$(document).ready(function() {{
    $('#otipTable').DataTable({{
        pageLength: 50,
        order: [[0, 'asc']],
        columnDefs: [{{ targets: 4, width: '40%' }}]
    }});
}});
</script>
</body>
</html>"#,
        total = results.len(),
        red = red,
        orange = orange,
        yellow = yellow,
        green = green,
        grey = grey,
        rows = rows,
    )
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zone_from_str() {
        assert_eq!(Zone::from_str_zone("Red"), Zone::Red);
        assert_eq!(Zone::from_str_zone("red"), Zone::Red);
        assert_eq!(Zone::from_str_zone("Orange"), Zone::Orange);
        assert_eq!(Zone::from_str_zone("ORANGE"), Zone::Orange);
        assert_eq!(Zone::from_str_zone("Yellow"), Zone::Yellow);
        assert_eq!(Zone::from_str_zone("Green"), Zone::Green);
        assert_eq!(Zone::from_str_zone("grey"), Zone::Grey);
        assert_eq!(Zone::from_str_zone("Grey"), Zone::Grey);
        assert_eq!(Zone::from_str_zone("unknown_junk"), Zone::Grey);
    }

    #[test]
    fn test_zone_display() {
        assert_eq!(Zone::Red.to_string(), "RED");
        assert_eq!(Zone::Orange.to_string(), "ORANGE");
        assert_eq!(Zone::Yellow.to_string(), "YELLOW");
        assert_eq!(Zone::Grey.to_string(), "GREY");
        assert_eq!(Zone::Green.to_string(), "GREEN");
    }

    #[test]
    fn test_parse_hash_response() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "Zone": "Red",
            "FileGeneralInfo": {
                "Sha256": "abc123def456",
                "Sha1": "aabbccdd",
                "Md5": "d41d8cd98f00b204e9800998ecf8427e",
                "FirstSeen": "2024-03-15",
                "LastSeen": "2026-03-27",
                "Signer": "Evil Corp",
                "Packer": "UPX",
                "Type": "PE32 executable",
                "Size": 245760,
                "HitsCount": 1247
            },
            "DetectionsInfo": [
                {"Zone": "Red", "DetectionName": "HEUR:Trojan.Win32.Generic"}
            ],
            "DynamicAnalisysResults": {
                "Detections": [{"Zone": "Red", "Count": 2}],
                "SuspiciousActivities": [{"Zone": "Orange", "Count": 5}],
                "ExtractedFiles": [],
                "NetworkActivities": [{"Zone": "Yellow", "Count": 3}],
                "DynamicDetections": [
                    {"Zone": "Red", "Threat": "Trojan.GenericKD"},
                    {"Zone": "Red", "Threat": "Backdoor.Win32.Agent"}
                ],
                "TriggeredNetworkRules": [{"Zone": "Orange", "RuleName": "C2 Beacon"}]
            }
        }"#,
        )
        .unwrap();

        let details = parse_hash_details(&json);
        match details {
            OpenTipDetails::Hash(h) => {
                assert_eq!(h.sha256.as_deref(), Some("abc123def456"));
                assert_eq!(h.sha1.as_deref(), Some("aabbccdd"));
                assert_eq!(h.md5.as_deref(), Some("d41d8cd98f00b204e9800998ecf8427e"));
                assert_eq!(h.file_type.as_deref(), Some("PE32 executable"));
                assert_eq!(h.file_size, Some(245760));
                assert_eq!(h.signer.as_deref(), Some("Evil Corp"));
                assert_eq!(h.packer.as_deref(), Some("UPX"));
                assert_eq!(h.first_seen.as_deref(), Some("2024-03-15"));
                assert_eq!(h.last_seen.as_deref(), Some("2026-03-27"));
                assert_eq!(h.hits_count, Some(1247));
                assert_eq!(
                    h.detection_name.as_deref(),
                    Some("HEUR:Trojan.Win32.Generic")
                );
                assert_eq!(h.dynamic_detections.len(), 2);
                assert_eq!(h.suspicious_activities, 5);
                assert_eq!(h.network_activities, 3);
            }
            _ => panic!("Expected Hash details"),
        }
    }

    #[test]
    fn test_parse_ip_response() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "Zone": "Orange",
            "IpGeneralInfo": {
                "Status": "active",
                "CountryCode": "RU",
                "Ip": "185.173.176.71",
                "HitsCount": 342,
                "FirstSeen": "2025-11-20"
            },
            "IpWhoIs": {
                "Asn": [{"Number": 48693, "Description": "Selectel Ltd"}],
                "Net": {
                    "RangeStart": "185.173.176.0",
                    "RangeEnd": "185.173.176.255",
                    "Name": "SELECTEL-NET",
                    "Description": "Selectel network"
                }
            },
            "Categories": ["Malware distribution"],
            "CategoriesWithZone": [
                {"Name": "Malware distribution", "Zone": "Red"},
                {"Name": "C&C server", "Zone": "Red"}
            ]
        }"#,
        )
        .unwrap();

        let details = parse_ip_details(&json);
        match details {
            OpenTipDetails::Ip(ip) => {
                assert_eq!(ip.country_code.as_deref(), Some("RU"));
                assert_eq!(ip.asn.as_deref(), Some("AS48693"));
                assert_eq!(ip.as_description.as_deref(), Some("Selectel Ltd"));
                assert_eq!(ip.net_name.as_deref(), Some("SELECTEL-NET"));
                assert_eq!(
                    ip.net_range.as_deref(),
                    Some("185.173.176.0 - 185.173.176.255")
                );
                assert_eq!(ip.categories.len(), 2);
                assert!(ip.categories.contains(&"Malware distribution".to_string()));
                assert!(ip.categories.contains(&"C&C server".to_string()));
                assert_eq!(ip.hits_count, Some(342));
                assert_eq!(ip.first_seen.as_deref(), Some("2025-11-20"));
            }
            _ => panic!("Expected Ip details"),
        }
    }

    #[test]
    fn test_parse_domain_response() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "Zone": "Green",
            "DomainGeneralInfo": {
                "Domain": "rosneft.ru",
                "FilesCount": 0,
                "UrlsCount": 12,
                "HitsCount": 88,
                "Ipv4Count": 4,
                "Categories": [],
                "CategoriesWithZone": []
            },
            "DomainWhoIsInfo": {
                "DomainName": "rosneft.ru",
                "Created": "2000-10-16",
                "Updated": "2023-09-01",
                "Expires": "2027-10-16",
                "NameServers": ["ns1.rosneft.ru", "ns2.rosneft.ru"],
                "Registrar": {"Info": "RU-CENTER-REG-RIPN", "IanaId": "0"},
                "RegistrationOrganization": "Rosneft Oil Company"
            }
        }"#,
        )
        .unwrap();

        let details = parse_domain_details(&json);
        match details {
            OpenTipDetails::Domain(d) => {
                assert_eq!(d.files_count, Some(0));
                assert_eq!(d.urls_count, Some(12));
                assert_eq!(d.hits_count, Some(88));
                assert_eq!(d.ipv4_count, Some(4));
                assert!(d.categories.is_empty());
                assert_eq!(d.created.as_deref(), Some("2000-10-16"));
                assert_eq!(d.expires.as_deref(), Some("2027-10-16"));
                assert_eq!(d.registrar.as_deref(), Some("RU-CENTER-REG-RIPN"));
                assert_eq!(d.name_servers.len(), 2);
                assert!(d.name_servers.contains(&"ns1.rosneft.ru".to_string()));
            }
            _ => panic!("Expected Domain details"),
        }
    }

    #[test]
    fn test_parse_url_response() {
        let json: serde_json::Value = serde_json::from_str(
            r#"{
            "Zone": "Red",
            "UrlGeneralInfo": {
                "Url": "http://evil.example.com/malware.exe",
                "Host": "evil.example.com",
                "Ipv4Count": 2,
                "FilesCount": 5,
                "Categories": [],
                "CategoriesWithZone": [
                    {"Name": "Phishing", "Zone": "Red"}
                ]
            },
            "UrlDomainWhoIs": {
                "DomainName": "evil.example.com",
                "Created": "2025-01-10",
                "Updated": "2025-06-01",
                "Expires": "2026-01-10",
                "NameServers": ["ns1.evil.com"],
                "Registrar": {"Info": "NameCheap Inc", "IanaId": "1068"},
                "RegistrationOrganization": "WhoisGuard"
            }
        }"#,
        )
        .unwrap();

        let details = parse_url_details(&json);
        match details {
            OpenTipDetails::Url(u) => {
                assert_eq!(u.host.as_deref(), Some("evil.example.com"));
                assert_eq!(u.ipv4_count, Some(2));
                assert_eq!(u.files_count, Some(5));
                assert_eq!(u.categories.len(), 1);
                assert!(u.categories.contains(&"Phishing".to_string()));
                assert_eq!(u.domain_created.as_deref(), Some("2025-01-10"));
                assert_eq!(u.registrar.as_deref(), Some("NameCheap Inc"));
            }
            _ => panic!("Expected Url details"),
        }
    }

    #[test]
    fn test_deduplication() {
        // Create multiple IOCs with the same value — should deduplicate to 1
        let iocs = vec![
            Ioc {
                ioc_type: IocType::Sha256,
                value: "abc123".to_string(),
                count: 100,
                source_fields: vec![],
                first_seen: None,
                last_seen: None,
                source_files: vec![],
            },
            Ioc {
                ioc_type: IocType::Sha256,
                value: "abc123".to_string(),
                count: 200,
                source_fields: vec![],
                first_seen: None,
                last_seen: None,
                source_files: vec![],
            },
            Ioc {
                ioc_type: IocType::Md5,
                value: "def456".to_string(),
                count: 50,
                source_fields: vec![],
                first_seen: None,
                last_seen: None,
                source_files: vec![],
            },
            Ioc {
                ioc_type: IocType::FilePath,
                value: "C:\\Windows\\System32\\cmd.exe".to_string(),
                count: 10,
                source_fields: vec![],
                first_seen: None,
                last_seen: None,
                source_files: vec![],
            },
        ];

        // We can't call check_iocs without a real API key,
        // so we test the dedup logic manually
        let mut seen = HashSet::new();
        let mut unique_count = 0usize;
        for ioc in &iocs {
            let type_label = match ioc.ioc_type {
                IocType::Sha256 => "hash",
                IocType::Sha1 => "hash",
                IocType::Md5 => "hash",
                IocType::Ipv4 => "ip",
                IocType::Domain => "domain",
                IocType::Url => "url",
                _ => continue,
            };
            let key = (type_label.to_string(), ioc.value.clone());
            if seen.insert(key) {
                unique_count += 1;
            }
        }

        // abc123 (sha256) deduplicated + def456 (md5) + FilePath skipped = 2
        assert_eq!(unique_count, 2);
    }

    #[test]
    fn test_render_output() {
        let results = vec![
            OpenTipResult {
                ioc_type: "SHA256".into(),
                value: "d41d8cd98f00b204e9800998ecf8427e".into(),
                zone: Zone::Red,
                details: OpenTipDetails::Hash(HashDetails {
                    sha256: Some("d41d8cd98f00b204e9800998ecf8427e".into()),
                    sha1: None,
                    md5: None,
                    file_type: Some("PE32 executable".into()),
                    file_size: Some(245760),
                    signer: None,
                    packer: Some("UPX".into()),
                    first_seen: Some("2024-03-15".into()),
                    last_seen: Some("2026-03-27".into()),
                    hits_count: Some(1247),
                    detection_name: Some("HEUR:Trojan.Win32.Generic".into()),
                    dynamic_detections: vec!["Trojan.GenericKD".into()],
                    suspicious_activities: 5,
                    network_activities: 3,
                }),
                portal_url: "https://opentip.kaspersky.com/d41d8cd98f00b204e9800998ecf8427e".into(),
                raw_response: None,
            },
            OpenTipResult {
                ioc_type: "IPv4".into(),
                value: "185.173.176.71".into(),
                zone: Zone::Green,
                details: OpenTipDetails::Ip(IpDetails {
                    country_code: Some("RU".into()),
                    asn: Some("AS48693".into()),
                    as_description: Some("Selectel Ltd".into()),
                    net_name: None,
                    net_range: Some("185.173.176.0 - 185.173.176.255".into()),
                    categories: vec![],
                    hits_count: Some(342),
                    first_seen: Some("2025-11-20".into()),
                }),
                portal_url: "https://opentip.kaspersky.com/185.173.176.71".into(),
                raw_response: None,
            },
        ];

        let report = render_opentip_report(&results);

        // Key elements
        assert!(report.contains("Kaspersky OpenTIP Report"));
        assert!(report.contains("[RED]"));
        assert!(report.contains("[GREEN]"));
        assert!(report.contains("HEUR:Trojan.Win32.Generic"));
        assert!(report.contains("PE32 executable"));
        assert!(report.contains("245,760 bytes"));
        assert!(report.contains("UPX"));
        assert!(report.contains("AS48693"));
        assert!(report.contains("Selectel Ltd"));
        assert!(report.contains("opentip.kaspersky.com"));
        assert!(report.contains("Summary:"));
        assert!(report.contains("1 RED"));
        assert!(report.contains("1 GREEN"));
        assert!(report.contains("2 checked"));
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1,000");
        assert_eq!(format_number(1247), "1,247");
        assert_eq!(format_number(245760), "245,760");
        assert_eq!(format_number(1000000), "1,000,000");
    }

    #[test]
    fn test_zone_ranking() {
        let mut zones = vec![
            Zone::Green,
            Zone::Grey,
            Zone::Red,
            Zone::Yellow,
            Zone::Orange,
        ];
        zones.sort_by(|a, b| b.rank().cmp(&a.rank()));
        assert_eq!(
            zones,
            vec![
                Zone::Red,
                Zone::Orange,
                Zone::Yellow,
                Zone::Grey,
                Zone::Green,
            ]
        );
    }
}
