use crate::hunt::{set_hunt_finding, HuntSeverity};
use crate::model::Event;
use crate::transforms::Transform;
use std::sync::OnceLock;

pub struct DnsSubdomainAnalysis;

impl DnsSubdomainAnalysis {
    fn hex_regex() -> &'static regex::Regex {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^[0-9a-f]{16,}$").unwrap())
    }

    fn base64_regex() -> &'static regex::Regex {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r"^[A-Za-z0-9+/]{20,}={0,2}$").unwrap())
    }
}

impl Transform for DnsSubdomainAnalysis {
    fn name(&self) -> &str {
        "dns_subdomain_analysis"
    }

    fn apply(&self, event: &mut Event) {
        let query = match event.fields.get("QueryName") {
            Some(v) if v.len() > 5 => v.clone(),
            _ => return,
        };

        let mut anomalies = Vec::new();

        // 1. Total query length (DNS tunneling indicator)
        if query.len() > 100 {
            anomalies.push("VERY_LONG_QUERY");
        }

        let labels: Vec<&str> = query.trim_end_matches('.').split('.').collect();

        // 2. Deep subdomain nesting (>4 levels)
        if labels.len() > 4 {
            anomalies.push("DEEP_NESTING");
        }

        // 3. Check individual subdomain labels (skip TLD and SLD)
        if labels.len() >= 3 {
            for label in &labels[..labels.len().saturating_sub(2)] {
                // Long subdomain labels
                if label.len() > 30 {
                    anomalies.push("LONG_SUBDOMAIN");
                }
                // Hex patterns in subdomains
                if label.len() >= 16 && Self::hex_regex().is_match(label) {
                    anomalies.push("HEX_SUBDOMAIN");
                }
                // Base64-like patterns
                if label.len() >= 20 && Self::base64_regex().is_match(label) {
                    anomalies.push("BASE64_SUBDOMAIN");
                }
                // High entropy per label
                if label.len() >= 8 {
                    let entropy = label_entropy(label);
                    if entropy > 3.5 {
                        anomalies.push("HIGH_ENTROPY_LABEL");
                    }
                }
                // Mostly numeric (>50% digits)
                if label.len() >= 8 {
                    let digit_count = label.chars().filter(|c| c.is_ascii_digit()).count();
                    if digit_count * 2 > label.len() {
                        anomalies.push("NUMERIC_SUBDOMAIN");
                    }
                }
            }
        }

        // Deduplicate
        anomalies.sort_unstable();
        anomalies.dedup();

        if !anomalies.is_empty() {
            let severity = if anomalies.contains(&"VERY_LONG_QUERY")
                || anomalies.contains(&"HEX_SUBDOMAIN")
                || anomalies.contains(&"BASE64_SUBDOMAIN")
            {
                HuntSeverity::High
            } else {
                HuntSeverity::Medium
            };

            event
                .fields
                .insert("hunt_dns_anomaly".into(), anomalies.join(", "));
            event
                .fields
                .insert("hunt_dns_subdomain_depth".into(), labels.len().to_string());
            set_hunt_finding(
                &mut event.fields,
                "DnsSubdomain",
                severity,
                &format!("DNS anomaly: {}", anomalies.join(", ")),
            );
        }
    }
}

fn label_entropy(s: &str) -> f64 {
    let mut freq = [0u32; 256];
    let len = s.len() as f64;
    if len == 0.0 {
        return 0.0;
    }
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::SourceFormat;

    fn make_event(fields: &[(&str, &str)]) -> Event {
        let mut event = Event::new("test.log", SourceFormat::JsonLines);
        for (k, v) in fields {
            event.set(*k, *v);
        }
        event
    }

    #[test]
    fn test_dns_tunneling_long_query() {
        let long_domain =
            "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff.evil.com";
        let mut event = make_event(&[("QueryName", long_domain)]);
        DnsSubdomainAnalysis.apply(&mut event);
        assert!(event.get("hunt_dns_anomaly").is_some());
    }

    #[test]
    fn test_dns_hex_subdomain() {
        let mut event = make_event(&[("QueryName", "aabbccddeeff00112233.evil.com")]);
        DnsSubdomainAnalysis.apply(&mut event);
        let anomaly = event.get("hunt_dns_anomaly").unwrap_or_default();
        assert!(anomaly.contains("HEX_SUBDOMAIN"));
    }

    #[test]
    fn test_dns_normal_no_alert() {
        let mut event = make_event(&[("QueryName", "www.google.com")]);
        DnsSubdomainAnalysis.apply(&mut event);
        assert!(event.get("hunt_dns_anomaly").is_none());
    }

    #[test]
    fn test_dns_deep_nesting() {
        let mut event = make_event(&[("QueryName", "a.b.c.d.e.evil.com")]);
        DnsSubdomainAnalysis.apply(&mut event);
        let anomaly = event.get("hunt_dns_anomaly").unwrap_or_default();
        assert!(anomaly.contains("DEEP_NESTING"));
    }
}
