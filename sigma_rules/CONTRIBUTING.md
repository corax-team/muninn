# Contributing SIGMA Rules to Muninn

Thank you for your interest in improving threat detection for the security community. This guide explains how to contribute high-quality SIGMA detection rules to the Muninn project.

## Who Should Contribute?

- **Detection Engineers** — write rules from SOC experience
- **Threat Researchers** — convert threat intel into actionable detections
- **Incident Responders** — share patterns from real investigations
- **Red Teamers / Pentesters** — contribute rules for techniques you use
- **Malware Analysts** — create rules for malware behaviors you reverse

## Quick Start

1. **Fork** the repository
2. **Create a rule** using the appropriate [template](templates/)
3. **Validate** your rule (see [Validation](#validation))
4. **Submit a PR** using the rule submission template

## Rule Requirements

### Must Have

| Requirement | Details |
|-------------|---------|
| Valid SIGMA YAML | Passes `sigmac` / SIGMA specification |
| Unique UUID | Generate with `uuidgen` or `python -c "import uuid; print(uuid.uuid4())"` |
| MITRE ATT&CK tags | At least one `attack.tXXXX` technique ID |
| Accurate logsource | Correct `product`, `category`, `service` |
| False positives | At least one documented false positive scenario |
| Severity level | `critical`, `high`, `medium`, or `low` |
| References | Links to research, CVE, threat intel, or blog posts |
| Description | What it detects and why it matters |
| Author | Your name or handle |
| Date | Creation date in `YYYY-MM-DD` format |

### Should Have

- Multiple detection selections for robustness
- Test data or a description of how to trigger the rule
- Related rule IDs if part of a detection chain
- `modified` date if updating an existing rule

### Must Not Have

- Duplicate logic of an existing rule (check first!)
- Overly broad patterns that generate excessive false positives
- Hardcoded environment-specific values (usernames, hostnames, IP addresses)
- Sensitive information (credentials, internal infrastructure details)

---

## Rule Placement

Place your rule in the correct directory based on the logsource:

```
sigma_rules/
├── windows/
│   ├── process_creation/    # Sysmon EID 1, Security 4688
│   ├── builtin/             # Windows Event Log channels
│   ├── registry/            # Registry modifications
│   │   ├── registry_set/
│   │   ├── registry_add/
│   │   ├── registry_delete/
│   │   └── registry_event/
│   ├── powershell/          # PowerShell logging
│   │   ├── powershell_script/
│   │   └── powershell_module/
│   ├── file/                # File system events
│   │   ├── file_event/
│   │   ├── file_delete/
│   │   └── file_rename/
│   ├── image_load/          # DLL/image loading
│   ├── network_connection/  # Sysmon EID 3
│   ├── process_access/      # Sysmon EID 10
│   ├── dns_query/           # Sysmon EID 22
│   ├── pipe_created/        # Named pipe events
│   ├── create_remote_thread/ # Sysmon EID 8
│   ├── driver_load/         # Driver loading
│   ├── create_stream_hash/  # ADS creation
│   ├── sysmon/              # Sysmon status
│   └── wmi_event/           # WMI subscriptions
├── linux/                   # Linux-specific
├── macos/                   # macOS-specific
├── cloud/                   # AWS, Azure, GCP, M365, Okta
├── network/                 # Zeek, DNS, firewall
├── web/                     # Web server logs
├── application/             # Application frameworks
├── identity/                # Identity providers
└── YYYY/                    # CVE exploit rules by year
    ├── Exploits/
    │   └── CVE-YYYY-NNNNN/
    └── Malware/
        └── MalwareName/
```

**Threat actor-specific rules** go in:
```
windows/process_creation/threat_actor/
```

---

## File Naming Convention

```
{logsource_category}_{product}_{description}.yml
```

Examples:
- `proc_creation_win_apt_headmare_phantomcore_rat.yml`
- `registry_set_win_persistence_run_key_suspicious.yml`
- `file_event_win_malware_lockbit_ransomware_note.yml`
- `net_dns_apt_phantomcore_ngrok_c2.yml`
- `web_exploit_cve_2025_30406_centrestack.yml`

---

## Rule Template

```yaml
title: Short Descriptive Title
id: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx  # uuidgen
status: experimental  # experimental → test → stable
description: |
    Detects [what] by monitoring [data source] for [pattern].
    [Why this is suspicious / threat context].
references:
    - https://example.com/threat-research
    - https://attack.mitre.org/techniques/TXXXX/
author: Your Name (@handle)
date: YYYY-MM-DD
tags:
    - attack.tactic-name        # e.g., attack.defense-evasion
    - attack.tXXXX              # technique ID
    - attack.tXXXX.YYY          # sub-technique if applicable
    - detection.emerging-threats # for CVE/exploit rules
    - cve.YYYY-NNNNN            # for CVE-specific rules
    - threat-actor.name          # for APT-specific rules
logsource:
    product: windows             # windows, linux, macos, aws, azure, gcp
    category: process_creation   # event category
    # service: sysmon            # optional: specific service
detection:
    selection_main:
        FieldName|modifier: 'value'
    selection_optional:
        AnotherField|contains:
            - 'value1'
            - 'value2'
    filter_legitimate:
        Image|endswith: '\legitimate_tool.exe'
    condition: (selection_main or selection_optional) and not filter_legitimate
falsepositives:
    - Legitimate use of [tool/technique] by administrators
    - Known software [name] that exhibits similar behavior
level: high  # critical, high, medium, low
```

See the [templates/](templates/) directory for ready-to-use templates for each rule category.

---

## Validation

### Local Validation

Before submitting, validate your rule:

```bash
# 1. Syntax check — rule must be valid YAML
python -c "import yaml; yaml.safe_load(open('your_rule.yml'))"

# 2. Test with Muninn — rule must compile to SQL
muninn -e /dev/null -r your_rule.yml --stats 2>&1 | grep -i error

# 3. Check for duplicates — ensure no similar rule exists
grep -r "your_key_detection_value" sigma_rules/
```

### CI Validation

All pull requests are automatically validated:
- YAML syntax check
- SIGMA specification compliance
- Muninn SIGMA-to-SQL compilation
- Duplicate detection

---

## Contribution Categories

### 1. New Detection Rules

The most impactful contribution. We especially need rules for:

- **Cloud-native threats** — AWS, Azure, GCP, Kubernetes
- **Linux threats** — container escapes, supply chain, rootkits
- **macOS threats** — increasingly targeted by APTs
- **Ransomware TTPs** — pre-encryption behavior, lateral movement
- **Supply chain attacks** — package managers, CI/CD, dependencies
- **Zero-day exploitation** — detection of post-exploitation behavior
- **Living-off-the-land** — abuse of legitimate tools
- **Identity attacks** — Okta, Azure AD, SAML/OAuth abuse

### 2. Rule Improvements

- Reduce false positives with better filters
- Add missing MITRE ATT&CK mappings
- Improve detection logic for edge cases
- Add references to new threat research
- Promote rules from `experimental` to `test` or `stable`

### 3. Threat Actor Campaigns

If you track specific threat actors, we welcome rule sets that detect their TTPs:

```yaml
tags:
    - threat-actor.actor-name
```

Current tracked actors: **Head Mare**, **PhantomCore**. We want to expand to more.

### 4. CVE Exploit Detection

For new CVEs, create a directory and add rules:

```
sigma_rules/YYYY/Exploits/CVE-YYYY-NNNNN/
├── proc_creation_win_exploit_cve_YYYY_NNNNN.yml
├── web_exploit_cve_YYYY_NNNNN.yml
└── ...
```

---

## Pull Request Process

1. **Title**: `sigma: add [category] detection for [what]`
   - Example: `sigma: add process_creation rule for BlackCat ransomware lateral movement`

2. **Description**: Include:
   - What threat/technique the rule detects
   - How you tested it (if possible)
   - Links to relevant threat intelligence
   - Any known false positives you've observed

3. **Review**: A maintainer will review for:
   - Detection logic correctness
   - False positive risk
   - Proper ATT&CK mapping
   - Rule placement and naming

4. **Merge**: Once approved, your rule becomes part of Muninn's detection engine.

---

## Recognition

All contributors are:
- Credited in the `author` field of their rules
- Listed in the [README.md](README.md) top contributors table
- Acknowledged in release notes when their rules ship

**For significant contributions** (10+ rules, threat actor campaign, or critical detections), contributors are featured in the project's acknowledgments.

---

## Code of Conduct

- Share knowledge freely — threat detection is a public good
- Respect other contributors' work
- Report security issues responsibly
- Don't submit rules containing sensitive/classified information
- Attribute original research and prior work

---

## Questions?

- Open a [Discussion](https://github.com/corax-team/muninn/discussions) for general questions
- Open an [Issue](https://github.com/corax-team/muninn/issues/new?template=sigma-rule-request.yml) to request a detection rule
- Tag `@corax-team` in your PR for review

---

**Every rule you contribute makes the security community stronger. Start today.**
