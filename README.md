<p align="center">
  <img src="https://github.com/corax-security/muninn/blob/main/.github/logo.png?raw=true" alt="Muninn" width="120">
</p>

<h1 align="center">Muninn</h1>

<p align="center">
  <b>Log parser &bull; SIGMA engine &bull; Search tool</b><br>
  <i>by corax team</i>
</p>

<p align="center">
  <a href="#english">English</a> &bull; <a href="#russian">Русский</a>
</p>

---

<a id="english"></a>

## Overview

Muninn is a standalone forensic tool for log analysis and threat detection. One binary, 15+ log formats, 3100+ SIGMA rules, zero dependencies. No SIEM required.

Feed it a directory of logs — EVTX, JSON, Syslog, Zeek, CSV, XML, CEF, LEEF, Auditd, W3C — Muninn auto-detects the format, loads everything into an in-memory SQLite database, and runs SIGMA rules or your custom queries against it.

### What can you analyze

| Source | Examples |
|---|---|
| **Windows Event Logs** | Security (4624/4625/4688/4720), Sysmon (1/3/11/13/22), PowerShell (4104), System (7045), `.evtx` files |
| **Linux / Unix** | auth.log, syslog, auditd, journald exports |
| **Network** | Zeek/Bro (dns, http, conn, ssl), Suricata EVE JSON, Snort |
| **Firewalls** | iptables, Palo Alto, Fortinet, Check Point — CSV/Syslog/CEF/LEEF |
| **Cloud** | AWS CloudTrail, Azure Activity, GCP Audit, M365, Okta — JSON |
| **Web** | IIS (W3C), Apache/Nginx access logs, proxy logs |
| **EDR / XDR** | Any telemetry exported as JSON, CSV, or Syslog |

## Download & Run

Pre-built binaries: [Releases](https://github.com/corax-security/muninn/releases)

**Linux:**
```bash
curl -sL https://github.com/corax-security/muninn/releases/latest/download/muninn-linux-amd64 -o muninn
chmod +x muninn
./muninn -e /path/to/logs/ -r rules/ --stats
```

**Windows:**
```powershell
Invoke-WebRequest -Uri "https://github.com/corax-security/muninn/releases/latest/download/muninn-windows-amd64.exe" -OutFile muninn.exe
.\muninn.exe -e C:\Logs\ -r rules\windows\ --stats
```

## Quick Start

```bash
# SIGMA detection
muninn -e ./evidence/ -r rules/ --stats

# Keyword search
muninn -e ./evidence/ -k "mimikatz"

# Field search
muninn -e ./evidence/ -f "EventID=4624"

# SQL query
muninn -e ./evidence/ --sql "SELECT * FROM events WHERE \"CommandLine\" LIKE '%whoami%'"

# Regex
muninn -e ./evidence/ --regex "CommandLine=.*-enc\s+[A-Za-z0-9+/=]+"

# Unique values
muninn -e ./evidence/ --distinct EventID

# Export to SQLite
muninn -e ./evidence/ --dbfile evidence.db
```

## Features

| | |
|---|---|
| **15+ formats** | EVTX, JSON, CSV, XML, Syslog, CEF, LEEF, Zeek, W3C, Auditd, macOS — auto-detected |
| **3100+ SIGMA rules** | Full [SigmaHQ](https://github.com/SigmaHQ/sigma) ruleset included |
| **SIGMA compiler** | YAML → SQL with modifiers: `contains`, `endswith`, `startswith`, `re`, `base64`, `base64offset`, `windash`, `cidr`, `all`, `gt/gte/lt/lte` |
| **Search engine** | SQLite-backed: keyword, field, regex, raw SQL |
| **~5 MB binary** | Static, no runtime dependencies |
| **Cross-platform** | Linux x86_64, Windows x86_64 |
| **Auto-report** | JSON report with timestamp generated automatically |
| **Library + CLI** | Use as Rust crate, CLI tool, or Python module |

## Search Examples

<details>
<summary><b>Incident Response — lateral movement</b></summary>

```bash
# Remote logons (network + RDP)
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '4624' AND \"LogonType\" IN ('3','10')"

# PsExec
muninn -e evidence/ -k "psexec"

# Pass-the-hash
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '4624' AND \"LogonType\" = '3' AND \"AuthenticationPackageName\" = 'NTLM'"
```
</details>

<details>
<summary><b>Threat Hunting — suspicious processes</b></summary>

```bash
# Encoded PowerShell
muninn -e evidence/ --regex "CommandLine=.*-[eE]nc[oO]?d?e?d?C?o?m?m?a?n?d?\s+[A-Za-z0-9+/=]{20,}"

# LOLBins downloading files
muninn -e evidence/ --sql "SELECT \"Image\",\"CommandLine\" FROM events WHERE \"CommandLine\" LIKE '%http%' AND (\"Image\" LIKE '%certutil%' OR \"Image\" LIKE '%mshta%' OR \"Image\" LIKE '%regsvr32%')"

# Office spawning processes
muninn -e evidence/ --sql "SELECT \"Image\",\"CommandLine\",\"ParentImage\" FROM events WHERE \"ParentImage\" LIKE '%WINWORD%' OR \"ParentImage\" LIKE '%EXCEL%' OR \"ParentImage\" LIKE '%OUTLOOK%'"

# Reconnaissance
muninn -e evidence/ --sql "SELECT \"CommandLine\",\"User\" FROM events WHERE \"Image\" LIKE '%whoami%' OR \"Image\" LIKE '%net.exe' OR \"Image\" LIKE '%ipconfig%' OR \"Image\" LIKE '%systeminfo%'"
```
</details>

<details>
<summary><b>Persistence</b></summary>

```bash
# Scheduled tasks
muninn -e evidence/ --sql "SELECT \"CommandLine\" FROM events WHERE \"EventID\" = '1' AND \"CommandLine\" LIKE '%schtasks%create%'"

# New services
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '7045'"

# Registry Run keys
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '13' AND \"TargetObject\" LIKE '%\\Run\\%'"
```
</details>

<details>
<summary><b>Credential Access</b></summary>

```bash
# LSASS access
muninn -e evidence/ --sql "SELECT \"SourceImage\",\"GrantedAccess\" FROM events WHERE \"EventID\" = '10' AND \"TargetImage\" LIKE '%lsass.exe'"

# Kerberoasting
muninn -e evidence/ --sql "SELECT \"TargetUserName\",\"ServiceName\",\"TicketEncryptionType\" FROM events WHERE \"EventID\" = '4769' AND \"TicketEncryptionType\" = '0x17'"

# SSH brute force
muninn -e auth.log -k "Invalid user" --stats
```
</details>

<details>
<summary><b>Network — external IPs & domains</b></summary>

```bash
# External IPs (exclude RFC1918)
muninn -e evidence/ --sql "
  SELECT DISTINCT \"DestinationIp\" FROM events
  WHERE \"DestinationIp\" IS NOT NULL AND \"DestinationIp\" != ''
    AND \"DestinationIp\" NOT LIKE '10.%'
    AND \"DestinationIp\" NOT LIKE '172.16.%' AND \"DestinationIp\" NOT LIKE '172.17.%'
    AND \"DestinationIp\" NOT LIKE '172.18.%' AND \"DestinationIp\" NOT LIKE '172.19.%'
    AND \"DestinationIp\" NOT LIKE '172.2_.%' AND \"DestinationIp\" NOT LIKE '172.30.%'
    AND \"DestinationIp\" NOT LIKE '172.31.%'
    AND \"DestinationIp\" NOT LIKE '192.168.%' AND \"DestinationIp\" NOT LIKE '127.%'
"

# C2 ports
muninn -e evidence/ --sql "
  SELECT \"DestinationIp\",\"DestinationPort\",\"Image\" FROM events
  WHERE \"DestinationPort\" IN ('4444','5555','8080','8443','1337','9001')
"

# Suspicious TLDs
muninn -e evidence/ --sql "
  SELECT \"QueryName\",\"Image\" FROM events WHERE \"EventID\" = '22'
    AND (\"QueryName\" LIKE '%.xyz' OR \"QueryName\" LIKE '%.top' OR \"QueryName\" LIKE '%.tk'
      OR \"QueryName\" LIKE '%.pw' OR \"QueryName\" LIKE '%.onion')
"

# All unique domains
muninn -e evidence/ --distinct QueryName
```
</details>

<details>
<summary><b>Data exploration</b></summary>

```bash
muninn -e evidence/ --distinct EventID
muninn -e evidence/ --distinct Image
muninn -e evidence/ --stats
muninn -e evidence/ --dbfile case.db
sqlite3 case.db "SELECT \"Image\", COUNT(*) as cnt FROM events WHERE \"EventID\" = '1' GROUP BY \"Image\" ORDER BY cnt DESC LIMIT 20"
```
</details>

## Example Output

```
$ muninn -e ./evidence/ -r ./rules/windows/

  Muninn by corax team
  2026-03-07 14:30:00

  ✓ 847293 events from 42 files in 3.2s (312450 EVTX, 52441 Syslog, 482402 JSON Lines)
  ✓ Loaded 2384 SIGMA rule(s)
  ✓ 12 rule(s) matched

  ══════════════════════════════════════════════════════════════════════
  ●     CRITICAL  Mimikatz Command Line — 14 matches (8ms)
  ●         HIGH  Suspicious Encoded PowerShell — 23 matches (12ms)
  ●         HIGH  Remote Thread in LSASS — 3 matches (15ms)
  ●       MEDIUM  WhoAmi Execution — 47 matches (6ms)
  ●       MEDIUM  Scheduled Task Created via CLI — 8 matches (5ms)
  ●          LOW  Sysmon Configuration Change — 2 matches (3ms)
  ══════════════════════════════════════════════════════════════════════
  12 rules matched, 116 total events flagged

  ✓ Report → "muninn_report_2026-03-07_14-30-00.json"
```

## SIGMA Rules

3100+ rules from [SigmaHQ](https://github.com/SigmaHQ/sigma) included in `rules/`:

| Category | Rules |
|----------|-------|
| Windows | 2384 |
| Cloud (AWS, Azure, GCP, M365) | 226 |
| Linux | 207 |
| Application | 92 |
| macOS | 69 |
| Network | 52 |
| Web | 45 |
| Identity | 24 |

```bash
muninn -e events.json -r rules/                            # all rules
muninn -e events.json -r rules/windows/process_creation/   # Windows process creation
muninn -e events.json -r rules/linux/                      # Linux only
muninn -e events.json -r rules/cloud/                      # cloud only
```

<details>
<summary><b>Supported SIGMA modifiers</b></summary>

| Modifier | Example | Description |
|----------|---------|-------------|
| `contains` | `CommandLine\|contains: 'whoami'` | Substring match |
| `startswith` | `Image\|startswith: 'C:\Windows'` | Prefix match |
| `endswith` | `Image\|endswith: '\cmd.exe'` | Suffix match |
| `re` | `CommandLine\|re: '.*-enc\s+'` | Regular expression |
| `all` | `CommandLine\|contains\|all:` | All values must match |
| `base64` | `CommandLine\|base64: 'whoami'` | Base64-encoded value |
| `base64offset` | `CommandLine\|base64offset: 'admin'` | Base64 with offset variants |
| `windash` | `CommandLine\|windash\|contains: '-enc'` | Dash variants (`-`, `/`, `--`) |
| `cidr` | `SourceIp\|cidr: '10.0.0.0/8'` | IP range |
| `gt/gte/lt/lte` | `EventID\|gte: 4624` | Numeric comparisons |
</details>

Rules licensed under [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License) by SigmaHQ.

## CLI Reference

```
muninn [OPTIONS] -e <LOG_PATH>

  -e, --events <PATH>       Log file or directory (recursive)
  -r, --rules <PATH>        SIGMA rules (file or directory)
  -k, --keyword <TEXT>       Full-text keyword search
  -f, --field <FIELD=PAT>    Field search (LIKE: %, _)
      --regex <FIELD=RE>     Regex search
      --sql <QUERY>          Raw SQL query
      --stats                Field statistics
      --distinct <FIELD>     Unique field values
  -s, --select <GLOB>        Only matching files
  -a, --avoid <GLOB>         Exclude matching files
      --min-level <LEVEL>    Minimum severity [default: low]
  -o, --output <FILE>        JSON output file
      --dbfile <FILE>        Export SQLite database
      --no-report            Disable auto-report
  -q, --quiet                Suppress output
```

## Using as a Library

```toml
[dependencies]
muninn = { git = "https://github.com/corax-security/muninn" }
```

```rust
use muninn::{parsers, search::SearchEngine, sigma};

let result = parsers::parse_file("events.json")?;
let mut engine = SearchEngine::new()?;
engine.load_events(&result.events)?;

let rules = sigma::load_rules("rules/windows/")?;
for rule in &rules {
    let sql = sigma::compile(rule)?;
    let result = engine.query_sql(&sql)?;
    if result.count > 0 {
        println!("[{}] {} — {} matches", rule.level, rule.title, result.count);
    }
}

let hits = engine.search_keyword("mimikatz")?;
engine.export_db("evidence.db")?;
```

## Building from Source

```bash
cargo build --release --features "all-parsers,cli"   # release build (~5 MB)
cargo test --features "all-parsers"                   # run tests
```

<details>
<summary><b>Feature flags, Docker, cross-compilation</b></summary>

| Feature | Description |
|---------|-------------|
| `all-parsers` | All format parsers (default) |
| `cli` | CLI binary |
| `parser-evtx` | Windows EVTX |
| `parser-syslog` | Syslog RFC 3164/5424 |
| `parser-cef` | Common Event Format |
| `parser-leef` | Log Event Extended Format |
| `parser-zeek` | Zeek/Bro TSV |
| `parser-w3c` | W3C Extended Log |
| `python` | Python bindings (PyO3) |

```bash
# Docker
docker build -t muninn .
docker run -v ./evidence:/data muninn /data/events.json -r /app/rules/ --stats

# Cross-compile for Windows
rustup target add x86_64-pc-windows-msvc
cargo build --release --features "all-parsers,cli" --target x86_64-pc-windows-msvc
```
</details>

## Public Log Datasets

| Dataset | Format | Link |
|---------|--------|------|
| EVTX-ATTACK-SAMPLES | EVTX | [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) |
| Hayabusa Sample EVTX | EVTX | [Yamato-Security/hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) |
| EVTX-to-MITRE-Attack | EVTX | [mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) |
| SecRepo auth.log | Syslog | [secrepo.com](https://www.secrepo.com/auth.log/) |
| SecRepo Zeek DNS/HTTP | Zeek TSV | [secrepo.com](https://www.secrepo.com/maccdc2012/) |
| Mordor / Security Datasets | JSON | [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) |

```bash
git clone --depth=1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
muninn -e EVTX-ATTACK-SAMPLES/ -r rules/windows/ -o detections.json
```

## Performance

| Metric | Value |
|--------|-------|
| Parsing | ~250K events/sec (JSON Lines) |
| SQLite load | 100K events < 5 sec |
| Binary size | ~5 MB (release, stripped, LTO) |
| Memory | SQLite-backed, handles millions of events |

## License

**AGPL-3.0** — see [LICENSE](LICENSE).

SIGMA rules in `rules/` licensed under [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License) by SigmaHQ.

---

<a id="russian"></a>

## Обзор

Muninn — автономный инструмент для анализа логов и обнаружения угроз. Один бинарник, 15+ форматов логов, 3100+ SIGMA-правил, ноль внешних зависимостей. SIEM не требуется.

Передайте директорию с логами — EVTX, JSON, Syslog, Zeek, CSV, XML, CEF, LEEF, Auditd, W3C — Muninn автоматически определит формат, загрузит всё в SQLite и применит SIGMA-правила или ваши запросы.

### Что можно анализировать

| Источник | Примеры |
|---|---|
| **Windows Event Logs** | Security (4624/4625/4688/4720), Sysmon (1/3/11/13/22), PowerShell (4104), System (7045), файлы `.evtx` |
| **Linux / Unix** | auth.log, syslog, auditd, экспорт journald |
| **Сетевые сенсоры** | Zeek/Bro (dns, http, conn, ssl), Suricata EVE JSON, Snort |
| **Межсетевые экраны** | iptables, Palo Alto, Fortinet, Check Point — CSV/Syslog/CEF/LEEF |
| **Облако** | AWS CloudTrail, Azure Activity, GCP Audit, M365, Okta — JSON |
| **Веб-серверы** | IIS (W3C), Apache/Nginx, прокси-серверы |
| **EDR / XDR** | Любая телеметрия в JSON, CSV или Syslog |

### Как получить данные

- Скопировать `.evtx` из `C:\Windows\System32\winevt\Logs\`
- Экспортировать из SIEM (Splunk, Elastic, QRadar) в JSON/CSV
- Собрать логи Zeek из `/opt/zeek/logs/`
- Скачать CloudTrail: `aws s3 sync s3://bucket/AWSLogs/ ./cloudtrail/`
- Экспортировать auditd: `ausearch --start today --format text > audit.log`

### Скачать и запустить

Готовые бинарники: [Releases](https://github.com/corax-security/muninn/releases)

**Linux:**
```bash
curl -sL https://github.com/corax-security/muninn/releases/latest/download/muninn-linux-amd64 -o muninn
chmod +x muninn
./muninn -e /path/to/logs/ -r rules/ --stats
```

**Windows:**
```powershell
Invoke-WebRequest -Uri "https://github.com/corax-security/muninn/releases/latest/download/muninn-windows-amd64.exe" -OutFile muninn.exe
.\muninn.exe -e C:\Logs\ -r rules\windows\ --stats
```

### Быстрый старт

```bash
muninn -e ./evidence/ -r rules/ --stats              # SIGMA-обнаружение
muninn -e ./evidence/ -k "mimikatz"                   # поиск по ключевому слову
muninn -e ./evidence/ -f "EventID=4624"               # поиск по полю
muninn -e ./evidence/ --distinct EventID              # уникальные значения
muninn -e ./evidence/ --dbfile evidence.db            # экспорт в SQLite
```

### Возможности

| | |
|---|---|
| **15+ форматов** | EVTX, JSON, CSV, XML, Syslog, CEF, LEEF, Zeek, W3C, Auditd, macOS — автоопределение |
| **3100+ SIGMA-правил** | Полный набор [SigmaHQ](https://github.com/SigmaHQ/sigma) |
| **Компилятор SIGMA** | YAML → SQL с модификаторами: `contains`, `endswith`, `startswith`, `re`, `base64`, `base64offset`, `windash`, `cidr`, `all`, `gt/gte/lt/lte` |
| **Поисковый движок** | На базе SQLite: ключевые слова, поля, регулярные выражения, SQL |
| **~5 МБ бинарник** | Статический, без внешних зависимостей |
| **Кроссплатформенный** | Linux x86_64, Windows x86_64 |
| **Авто-отчёт** | JSON-отчёт с меткой времени создаётся автоматически |
| **Библиотека + CLI** | Rust-крейт, CLI-утилита или Python-модуль |

### Сборка из исходников

```bash
cargo build --release --features "all-parsers,cli"
cargo test --features "all-parsers"
```

### Лицензия

**AGPL-3.0** — см. [LICENSE](LICENSE).

SIGMA-правила в `rules/` — [DRL 1.1](https://github.com/SigmaHQ/Detection-Rule-License) от SigmaHQ.
