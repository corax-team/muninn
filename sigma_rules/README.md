<p align="center">
  <img src="https://raw.githubusercontent.com/corax-team/muninn/main/.github/assets/muninn-sigma-banner.png" alt="Muninn SIGMA Rules" width="600">
</p>

<h1 align="center">Muninn SIGMA Detection Rules</h1>

<p align="center">
  <b>3,273 detection rules | 377 ATT&CK techniques | 14 MITRE tactics | 430 CVE exploits</b><br>
  <i>Community-driven threat detection for incident response</i>
</p>

<p align="center">
  <a href="CONTRIBUTING.md">Contribute</a> &bull;
  <a href="#coverage">Coverage</a> &bull;
  <a href="#structure">Structure</a> &bull;
  <a href="#unique-rules">Unique Rules</a> &bull;
  <a href="SOURCES.md">Sources</a> &bull;
  <a href="#usage">Usage</a>
</p>

---

## Why Contribute Here?

Unlike generic SIGMA rule repositories, Muninn rules are **battle-tested against a real detection engine** — every rule compiles to SQL and runs against log data during CI. This means:

- **Immediate feedback** — your rule is validated syntactically and logically before merge
- **Real-world testing** — rules are tested against the Muninn SIGMA-to-SQL compiler
- **Broad format support** — rules run against EVTX, Syslog, CEF, LEEF, Zeek, W3C, JSON, CSV
- **Threat actor intelligence** — we maintain original rules for tracked APT campaigns (Head Mare, PhantomCore) alongside SigmaHQ community rules
- **CVE exploit detection** — 430 rules organized by CVE year, from 2010 to 2025

**We welcome contributions from detection engineers, threat researchers, SOC analysts, and incident responders worldwide.**

---

## Coverage

### Platforms

| Platform | Rules | Key Sources |
|----------|------:|-------------|
| Windows | 2,253 | Sysmon, Security, PowerShell, System, WMI |
| Cloud | 204 | AWS CloudTrail, Azure, GCP, M365, Okta |
| Linux | 147 | auditd, syslog, process creation |
| Application | 77 | JVM, Python, Django, Spring, Ruby, Node.js |
| macOS | 48 | process creation, file events |
| Network | 45 | Zeek, DNS, firewall |
| Web | 42 | IIS, Apache, Nginx, proxy |
| Identity | 20 | Okta, Azure AD |
| Category | 7 | Cross-platform generics |

### Windows Breakdown (2,253 rules)

| Category | Rules | Description |
|----------|------:|-------------|
| Process Creation | 1,131 | Command-line, parent-child, image path |
| Built-in Logs | 283 | Security, System, Application channels |
| Registry | 241 | Keys, values, persistence |
| PowerShell | 180 | Script block, module logging |
| File Events | 177 | Creation, modification, deletion |
| Image Load | 96 | DLL side-loading, injection |
| Network Connection | 51 | Outbound, C2, beaconing |
| Process Access | 22 | Memory access, credential dumping |
| DNS Query | 17 | Suspicious domain resolution |
| Named Pipes | 16 | IPC, lateral movement |
| Remote Thread | 11 | Code injection |
| Driver Load | 9 | Rootkits, BYOVD |
| Stream Hash | 9 | ADS abuse |
| Sysmon Status | 6 | Tamper detection |
| WMI Events | 3 | Persistence via WMI |
| Process Tampering | 1 | Process hollowing |

### MITRE ATT&CK Tactics

All **14 ATT&CK tactics** are covered:

| Tactic | Description |
|--------|-------------|
| Reconnaissance | Scanning, active probing |
| Resource Development | Infrastructure, tooling |
| Initial Access | Phishing, exploitation, supply chain |
| Execution | Command-line, scripting, WMI |
| Persistence | Registry, scheduled tasks, services |
| Privilege Escalation | Token manipulation, UAC bypass |
| Defense Evasion | Masquerading, obfuscation, log clearing |
| Credential Access | Dumping, brute force, Kerberoasting |
| Discovery | Network, system, account enumeration |
| Lateral Movement | RDP, SMB, WinRM, PsExec |
| Collection | Screen capture, clipboard, staging |
| Command & Control | Tunneling, proxy, encrypted channels |
| Exfiltration | Cloud storage, alternative protocols |
| Impact | Ransomware, data destruction, DoS |

**377 unique ATT&CK technique/sub-technique IDs** mapped across all rules.

### Rule Severity Distribution

| Level | Count | Percentage |
|-------|------:|------------|
| High | 1,695 | 51.8% |
| Medium | 1,397 | 42.7% |
| Critical | 176 | 5.4% |
| Low | 2 | 0.1% |

### CVE Exploit Detection by Year

| Year | Rules | Notable CVEs |
|------|------:|-------------|
| 2025 | 40 | CVE-2025-30406, CVE-2025-53770, CVE-2025-4427 |
| 2024 | 38 | CVE-2024-43451 (NTLM) |
| 2023 | 122 | CVE-2023-38831 (WinRAR), CVE-2023-34362 (MOVEit) |
| 2022 | 37 | Follina, ProxyNotShell |
| 2021 | 84 | Log4Shell, ProxyShell, PrintNightmare |
| 2020 | 35 | Zerologon, SolarWinds |
| 2019 | 32 | BlueKeep, SharePoint |
| 2018 | 17 | Drupalgeddon, Cisco Smart Install |
| 2017 | 19 | EternalBlue, Struts |
| 2014-2015 | 5 | Shellshock, Heartbleed |
| 2010 | 1 | MODx directory traversal |

---

<a id="unique-rules"></a>
## Unique & Original Rules

Beyond the SigmaHQ community rules, this repository contains **original threat intelligence rules** developed by the Corax Team:

### APT Head Mare / PhantomCore (24 rules)

Targeted rules for the Head Mare hacktivist group and their PhantomCore RAT toolset, based on direct incident response and Kaspersky SecureList analysis:

- PhantomCore RAT execution from AppData (`srvhost.exe`, `srvhostt.exe`)
- PhantomDL downloader execution patterns
- CobInt loader detection
- WinRAR CVE-2023-38831 exploitation (as used by Head Mare)
- NTLM relay via CVE-2024-43451
- Ngrok tunneling for C2
- Sliver C2 beacon activity
- Credential dumping (ntdsutil)
- Log clearing and anti-forensics
- Rclone-based exfiltration
- Scheduled task persistence (`MicrosoftUpdateCore`)
- PhantomJitter service masquerading

### Custom APT Rules (15 rules)

Additional rules targeting specific APT campaigns observed during incident response engagements by the Corax Team.

### Emerging Threat Rules (430 rules)

CVE-specific exploit detection rules organized by year, covering web application attacks, privilege escalation, remote code execution, and supply chain compromises.

---

<a id="structure"></a>
## Repository Structure

```
sigma_rules/
├── windows/              # 2,253 rules — Windows event sources
│   ├── process_creation/ #   1,131 — Sysmon EID 1, Security 4688
│   ├── builtin/          #     283 — Security, System, Application
│   ├── registry/         #     241 — Registry modification
│   ├── powershell/       #     180 — Script block & module logging
│   ├── file/             #     177 — File system events
│   ├── image_load/       #      96 — DLL/image loading
│   ├── network_connection/ #    51 — Sysmon EID 3
│   ├── process_access/   #      22 — Sysmon EID 10
│   ├── dns_query/        #      17 — Sysmon EID 22
│   ├── pipe_created/     #      16 — Named pipe creation
│   ├── create_remote_thread/ #  11 — Sysmon EID 8
│   ├── driver_load/      #       9 — Driver/rootkit loading
│   ├── create_stream_hash/ #     9 — ADS creation
│   ├── sysmon/           #       6 — Sysmon status/config
│   ├── wmi_event/        #       3 — WMI persistence
│   └── process_tampering/ #      1 — Hollowing/doppelganging
├── cloud/                # 204 rules — AWS, Azure, GCP, M365, Okta
├── linux/                # 147 rules — auditd, syslog, process
├── application/          #  77 rules — JVM, web frameworks
├── macos/                #  48 rules — macOS-specific
├── network/              #  45 rules — Zeek, DNS, firewall
├── web/                  #  42 rules — Web server logs
├── identity/             #  20 rules — Identity providers
├── category/             #   7 rules — Cross-platform
├── 2010-2025/            # 430 rules — CVE exploits by year
├── templates/            # Rule templates for contributors
├── CONTRIBUTING.md       # How to contribute
└── README.md             # This file
```

---

<a id="usage"></a>
## Usage with Muninn

```bash
# Run all rules against evidence
muninn -e ./evidence/ -r sigma_rules/ --stats

# Run only Windows rules
muninn -e ./evidence/ -r sigma_rules/windows/ --stats

# Run only CVE/exploit rules for 2024-2025
muninn -e ./evidence/ -r sigma_rules/2024/ -r sigma_rules/2025/ --stats

# Run specific threat actor rules
muninn -e ./evidence/ -r sigma_rules/windows/process_creation/threat_actor/ --stats
```

Every rule in this repository is compiled by Muninn's SIGMA-to-SQL engine and executed against loaded events. Rules that fail compilation are flagged during analysis.

---

## Quality Standards

All rules in this repository must:

1. **Follow the [SIGMA specification](https://sigmahq.io/docs/basics/rules.html)** — valid YAML, proper field names
2. **Include MITRE ATT&CK tags** — at minimum one `attack.tXXXX` technique ID
3. **Specify accurate logsource** — correct `product`, `category`, and `service`
4. **Document false positives** — at least one `falsepositives` entry
5. **Set appropriate severity** — `critical`, `high`, `medium`, or `low`
6. **Provide references** — links to threat intelligence, CVE, or research
7. **Include a meaningful description** — what the rule detects and why it matters

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contribution guide and rule templates.

---

## Top Contributors

| Author | Rules |
|--------|------:|
| Nasreddine Bencherchali (Nextron Systems) | 579 |
| Florian Roth (Nextron Systems) | 371 |
| frack113 | 262 |
| Swachchhanda Shrawan Poudel (Nextron Systems) | 85 |
| Austin Songer | 74 |
| X__Junior (Nextron Systems) | 43 |
| Christian Burkard (Nextron Systems) | 36 |
| Roberto Rodriguez (Cyb3rWard0g) | 30 |
| Bhabesh Raj | 29 |
| Corax Team | 39 |

*And 200+ more contributors from the global SIGMA community.*

---

## License

All rules in this repository are distributed under **[DRL 1.1](https://github.com/SigmaHQ/sigma/blob/master/LICENSE.Detection.Rules.md)** (Detection Rule License) for SigmaHQ-sourced rules, and **AGPL-3.0** for original Corax Team rules.

---

<p align="center">
  <b>Your detection rule could be the one that catches the next breach.</b><br>
  <a href="CONTRIBUTING.md">Start contributing today &rarr;</a>
</p>
