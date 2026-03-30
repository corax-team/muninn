# Best SIGMA Rule Sources Worldwide

Curated list of the highest-quality SIGMA detection rule sources. Use these to expand Muninn's detection coverage or contribute rules adapted from these sources (respecting licenses).

**Current baseline**: 3,273 rules (3,234 SigmaHQ + 24 Head Mare/PhantomCore + 15 APT Corax Team)

---

## Priority Integration Matrix

Sources ranked by impact, feasibility, and license compatibility:

| # | Source | New Rules | Format | License | Effort |
|---|--------|-----------|--------|---------|--------|
| 1 | **Hayabusa (Yamato Security)** | ~800 unique | Native SIGMA | DRL/permissive | LOW |
| 2 | **Splunk Security Content** | ~500 convertible | SPL → SIGMA | Apache 2.0 | MEDIUM |
| 3 | **Microsoft 365 Defender Queries** | ~200 convertible | KQL → SIGMA | MIT | MEDIUM |
| 4 | **Panther Labs (AWS/SaaS)** | ~150 convertible | Python → SIGMA | AGPL-3.0 | MEDIUM |
| 5 | **Sekoia.io Community** | ~100 native | SIGMA | MIT | LOW |
| 6 | **The DFIR Report** | ~60 curated | Native SIGMA | Permissive | LOW |
| 7 | **Nextron aurora-agent-rules** | ~100 unique | Native SIGMA | DRL | LOW |
| 8 | **JPCERT Tool Analysis** | ~50 convertible | CSV → SIGMA | BSD-2 | MEDIUM |
| 9 | **CISA advisories** | ~30 curated | Native SIGMA | Public domain | LOW |
| 10 | **Aqua Tracee (containers)** | ~50 convertible | Rego → SIGMA | Apache 2.0 | HIGH |

**Estimated net-new rules from all compatible sources: ~2,000–2,500** (total: 5,300–5,800)

---

## License Compatibility

| License | AGPL-3.0 Compatible? | Can Ship in Repo? | Sources |
|---------|---------------------|-------------------|---------|
| DRL 1.1 | Yes | Yes | SigmaHQ, Hayabusa, Nextron |
| Apache 2.0 | Yes | Yes | Splunk, Panther, Tracee, Datadog, Chronicle |
| MIT | Yes | Yes | Microsoft KQL, Sekoia, OSSEM |
| BSD-2/3 | Yes | Yes | JPCERT, ESET, CCCS |
| Public Domain | Yes | Yes | CISA, HHS |
| CC-BY | Yes (with attribution) | Yes | ASD/ACSC |
| Elastic License 2.0 | **No** | No | Elastic detection-rules |
| GPL-2.0 (no "or later") | **No** | No | Wazuh |
| Commercial | **No** | No | VALHALLA, SOC Prime Premium, Dragos |

---

## Tier 1 — Direct SIGMA Import (Highest Priority)

### SigmaHQ (already included)
- **URL**: https://github.com/SigmaHQ/sigma
- **Rules**: 3,200+ (included as r2026-01-01)
- **License**: DRL 1.1
- **Status**: Already integrated

### Hayabusa / Yamato Security (TOP PRIORITY)
- **URL**: https://github.com/Yamato-Security/hayabusa-rules
- **Rules**: 4,000+ total (SigmaHQ base + ~800 unique originals)
- **Coverage**: Deep Windows event log analysis, Japanese threat landscape
- **License**: DRL 1.1 for SigmaHQ-derived; permissive for originals
- **Format**: Native SIGMA YAML — direct import
- **Unique value**: ~800 rules NOT in SigmaHQ, strong DFIR focus, unique Event ID correlations
- **Integration**: Filter out SigmaHQ duplicates, import ~800 unique rules
- **Effort**: LOW — same format, just dedup

### Sekoia.io Community
- **URL**: https://github.com/SEKOIA-IO/Community
- **Rules**: ~200+ detection rules
- **Coverage**: European threat landscape, ransomware-as-a-service, initial access brokers, credential stealers
- **License**: MIT
- **Format**: Mix of native SIGMA and proprietary
- **Effort**: LOW–MEDIUM

### The DFIR Report
- **URL**: https://thedfirreport.com / https://github.com/The-DFIR-Report
- **Rules**: ~60–80 SIGMA rules alongside intrusion reports
- **Coverage**: Full kill chains: Conti, BazarLoader, IcedID, QakBot, Cobalt Strike, Play, Akira
- **License**: Permissive for published rules
- **Format**: Native SIGMA
- **Unique value**: Every rule = confirmed attacker behavior from real incidents
- **Effort**: LOW — manual curation from blog posts and GitHub

### Nextron aurora-agent-rules
- **URL**: https://github.com/Neo23x0 (aurora and god-mode repos)
- **Rules**: ~100–200 unique rules not in SigmaHQ
- **Coverage**: APT tools, webshells, lateral movement, high-confidence detections
- **License**: DRL / BSD
- **Format**: Native SIGMA
- **Effort**: LOW

### CISA Advisory Rules
- **URL**: https://github.com/cisagov / CISA advisories
- **Rules**: ~30 SIGMA rules in select advisories + Malcolm network rules
- **Coverage**: Confirmed actively-exploited vulnerabilities
- **License**: Public domain (US government)
- **Format**: Native SIGMA in advisories
- **Effort**: LOW — highest confidence when available

---

## Tier 2 — Conversion Projects (Medium Effort, High Value)

### Splunk Security Content (ESCU)
- **URL**: https://github.com/splunk/security_content
- **Rules**: 1,800+ detections (analytics stories)
- **Coverage**: Windows, Linux, Cloud, Network, Application — excellent ransomware and supply chain stories
- **License**: Apache 2.0 — **compatible**
- **Format**: SPL queries in YAML manifests — YAML metadata ports cleanly, SPL needs manual conversion
- **Unique value**: Full kill chain narratives, detection + response combined
- **Priority targets**: Cloud rules, ransomware stories, supply chain detections

### Microsoft 365 Defender Hunting Queries
- **URL**: https://github.com/microsoft/Microsoft-365-Defender-Hunting-Queries
- **Rules**: 400+ KQL hunting queries
- **Coverage**: Azure, M365, Windows endpoints — STORM groups, Midnight Blizzard, etc.
- **License**: MIT — **compatible**
- **Format**: KQL — maps reasonably to SIGMA conditions
- **Priority targets**: Identity/M365 threats, Azure AD abuse

### Panther Labs Analysis
- **URL**: https://github.com/panther-labs/panther-analysis
- **Rules**: 500+ detections
- **Coverage**: Best-in-class AWS (CloudTrail, GuardDuty, S3, IAM), Okta, GitHub audit logs, Slack
- **License**: AGPL-3.0 — **perfectly compatible**
- **Format**: Python detection functions — readable logic
- **Priority targets**: AWS rules (biggest gap in Muninn's cloud coverage)

### Chronicle/Google Security Operations
- **URL**: https://github.com/chronicle/detection-rules
- **Rules**: 300+
- **Coverage**: GCP, Google Workspace
- **License**: Apache 2.0 — **compatible**
- **Format**: YARA-L — structurally different, medium conversion effort

### JPCERT/CC Tool Analysis
- **URL**: https://github.com/JPCERTCC
- **Notable**: `ToolAnalysisResultSheet` — maps ~50 hacking tools to specific Event IDs
- **Coverage**: Lateral movement tools, credential dumping, remote execution
- **License**: BSD-2 — **compatible**
- **Format**: CSV/Excel → manual conversion to SIGMA
- **Unique value**: Gold mine for tool-based detection rules

---

## Tier 3 — Government & CERT Sources

### CISA (USA)
- **URL**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **KEV catalog** — every entry is a potential SIGMA rule
- **Malcolm** (https://github.com/cisagov/Malcolm) — 100+ Suricata/SIGMA rules
- **License**: Public domain

### MITRE CAR (Cyber Analytics Repository)
- **URL**: https://car.mitre.org
- **Rules**: 100+ analytics in pseudocode
- **License**: Apache 2.0
- **Unique value**: Academically rigorous, ATT&CK-native

### ANSSI (France)
- **URL**: https://github.com/ANSSI-FR
- **Coverage**: AD lateral movement, Chinese/Russian APTs
- **~30–50 SIGMA rules** in published reports (PDF extraction needed)

### JPCERT/CC (Japan)
- **URL**: https://github.com/JPCERTCC
- **Coverage**: Chinese and North Korean APTs targeting APAC
- **Notable tools**: LogonTracer, EmoCheck, MalConfScan

### BSI (Germany)
- **URL**: https://www.bsi.bund.de
- **Coverage**: Critical infrastructure, OT/ICS, Exchange server attacks

### NCSC (UK)
- **URL**: https://github.com/ukncsc
- **License**: OGL (Open Government License)
- **Coverage**: Five Eyes intelligence-backed, nation-state focus

### NCSC-NL (Netherlands)
- **URL**: https://github.com/NCSC-NL
- **Coverage**: Supply chain, cloud

### ASD/ACSC (Australia)
- **URL**: https://www.cyber.gov.au
- **License**: CC-BY
- **Coverage**: Chinese APTs targeting APAC

### CERT-EU
- **Coverage**: Espionage targeting European institutions

### CCCS (Canada)
- **URL**: https://github.com/CybercentreCanada
- **Notable**: `CCCS-Yara` (2,000+ YARA rules)
- **License**: MIT

---

## Tier 4 — Specialized & Industry-Specific

### Container / Kubernetes
- **Aqua Tracee**: https://github.com/aquasecurity/tracee — 150+ eBPF detections (Apache 2.0)
- **Datadog Security Labs**: https://github.com/DataDog/security-labs-pocs — cloud runtime (Apache 2.0)
- **Stratus Red Team**: https://github.com/DataDog/stratus-red-team — AWS/Azure/GCP/K8s attack simulation (Apache 2.0)

### Testing & Validation
- **Atomic Red Team**: https://github.com/redcanaryco/atomic-red-team — 1,500+ ATT&CK tests (MIT)
- **EVTX-ATTACK-SAMPLES** (Samir Bousseaden): https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES — real EVTX evidence for ~60 techniques
- **OSSEM** (Roberto Rodriguez): https://github.com/OTRF/OSSEM — field mapping framework (MIT)
- **Security-Datasets**: https://github.com/OTRF/Security-Datasets — attack simulation telemetry (MIT)

### Living-off-the-Land
- **LOLBAS**: https://lolbas-project.github.io — Windows LOLBins
- **GTFOBins**: https://gtfobins.github.io — Linux LOLBins
- **LOLDrivers**: https://www.loldrivers.io — Vulnerable drivers (BYOVD)

### OT/ICS
- **MITRE ATT&CK for ICS**: https://attack.mitre.org/techniques/ics/ — 80+ ICS techniques
- CISA ICS-CERT advisories — critical infrastructure detections

### Research & Meta-Resources
- **ThreatHunting Keywords**: https://github.com/mthcht/ThreatHunting-Keywords — keyword lists
- **Awesome Threat Detection**: https://github.com/0x4D31/awesome-threat-detection — curated links
- **Red Canary Threat Detection Report**: https://redcanary.com/threat-detection-report/ — annual top techniques

---

## Tier 5 — Vendor Threat Research Blogs

Ideal for writing original rules — these publish TTPs and detection logic but not formal SIGMA rules:

| Vendor | URL | Specialty |
|--------|-----|-----------|
| Kaspersky SecureList | securelist.com | APT campaigns, malware analysis |
| Mandiant / Google TAG | cloud.google.com/blog/topics/threat-intelligence | Nation-state APTs, UNC groups |
| Microsoft Threat Intel | microsoft.com/en-us/security/blog | STORM groups, Windows, Azure |
| CrowdStrike | crowdstrike.com/blog | eCrime, targeted intrusions |
| Unit 42 (Palo Alto) | unit42.paloaltonetworks.com | Malware, cloud threats |
| SentinelOne Labs | sentinelone.com/labs | macOS, Linux, cloud threats |
| Trend Micro Research | trendmicro.com/en_us/research | Asian APTs, ransomware |
| ESET Research | welivesecurity.com | European perspective, APTs |
| Check Point Research | research.checkpoint.com | Middle East APTs, mobile |
| Group-IB | group-ib.com/blog | Russian-speaking threat actors |
| Positive Technologies | ptsecurity.com/ww-en/analytics | Russian infrastructure, APTs |
| Recorded Future | recordedfuture.com/blog | Threat intelligence |
| Cisco Talos | blog.talosintelligence.com | Network threats, malware |
| Volexity | volexity.com/blog | Zero-day discovery, first-to-report |
| Huntress Labs | huntresslabs.com/blog | SMB/MSP attacks, RMM tool abuse |

---

## Critical Coverage Gaps

Areas where we need the most help from the community:

| Gap | Current | Target | Best Sources |
|-----|---------|--------|-------------|
| AWS CloudTrail | ~12 | 80+ | Panther Labs, Splunk, Stratus Red Team |
| GCP | ~5 | 30+ | Chronicle, Splunk, Panther |
| Container / K8s | ~3 | 50+ | Aqua Tracee, Datadog |
| Linux endpoint | 147 | 250+ | Hayabusa, ESET, Splunk |
| macOS | 48 | 80+ | SentinelOne, Elastic (study) |
| Identity / OAuth | 20 | 60+ | Microsoft KQL, Panther (Okta) |
| Supply chain | ~5 | 30+ | Splunk, DFIR Report |
| Ransomware families | ~30 | 100+ | Splunk ESCU, DFIR Report, Hayabusa |
| GitHub / CI-CD | 0 | 20+ | Panther Labs |
| OT / ICS | 0 | 50+ | CISA, BSI, MITRE ICS |

---

## Integration Roadmap

### Phase 1 — Quick Wins (direct SIGMA import)
1. Hayabusa unique rules (~800 rules)
2. Sekoia.io community rules (~100 rules)
3. DFIR Report curated rules (~60 rules)
4. Nextron aurora-agent-rules (~100 rules)
5. CISA advisory rules (~30 rules)

### Phase 2 — Conversion Projects
6. Splunk ESCU → SIGMA (cloud + ransomware stories)
7. Microsoft KQL → SIGMA (identity + M365 threats)
8. JPCERT Tool Analysis → SIGMA

### Phase 3 — Gap Filling (manual rule creation)
9. AWS/GCP rules using Panther + Stratus Red Team as reference
10. Container/K8s rules using Tracee + Datadog as reference
11. Supply chain rules using DFIR Report + Splunk narratives

### Phase 4 — Ongoing Monitoring
12. Track SigmaHQ releases (quarterly)
13. Monitor Hayabusa releases for new unique rules
14. RSS/feed monitoring for CISA, ANSSI, NCSC advisories

---

**Know a source we're missing? Open an [issue](https://github.com/corax-team/muninn/issues) or submit a PR to update this file.**
