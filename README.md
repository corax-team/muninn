# Muninn

**Memory of Corax. One binary. 15+ log formats. 3100+ SIGMA rules. Zero external dependencies.**

**Память Corax. Один бинарник. 15+ форматов логов. 3100+ SIGMA-правил. Ноль внешних зависимостей.**

**Muninn works standalone.** No SIEM required. Accepts any log files — manual copy, SIEM export, Zeek sensor, CloudTrail S3 dump, or any archive with logs.

**Muninn работает автономно.** SIEM не нужен. Принимает любые лог-файлы — ручное копирование, экспорт из SIEM, сенсор Zeek, дамп CloudTrail S3 или любой архив с логами.

---

## Features / Возможности

- **15+ log formats** — auto-detected, no flags needed / **15+ форматов логов** — автоматическое определение, без флагов
- **3100+ built-in SIGMA rules** from [SigmaHQ](https://github.com/SigmaHQ/sigma) / **3100+ встроенных SIGMA-правил** из [SigmaHQ](https://github.com/SigmaHQ/sigma)
- **SIGMA YAML → SQL compiler** with full modifier support (`contains`, `endswith`, `startswith`, `re`, `base64`, `base64offset`, `windash`, `cidr`, `all`, `gt/gte/lt/lte`) / **Компилятор SIGMA YAML → SQL** с полной поддержкой модификаторов
- **SQLite-backed search engine** — keyword, field, regex, raw SQL / **Поисковый движок на SQLite** — ключевые слова, поля, регулярные выражения, SQL-запросы
- **~5 MB** static binary, no runtime dependencies / **~5 МБ** статический бинарник, без зависимостей в рантайме
- **Cross-platform** — Linux x86_64, Windows x86_64 / **Кроссплатформенный** — Linux x86_64, Windows x86_64
- **Library + CLI + Python bindings** — use as a crate, command-line tool, or from Python / **Библиотека + CLI + Python-привязки** — используйте как крейт, утилиту командной строки или из Python

---

## Quick Start / Быстрый старт

```bash
# Build / Сборка
cargo build --release --features "all-parsers,cli"

# Parse + detect with built-in SIGMA rules / Парсинг + детект встроенными SIGMA-правилами
./target/release/muninn -e events.json -r rules/windows/

# Keyword search / Поиск по ключевому слову
./target/release/muninn -e events.json -k "mimikatz"

# Field search / Поиск по полю
./target/release/muninn -e events.json -f "EventID=4624"

# Regex search / Поиск по регулярному выражению
./target/release/muninn -e events.json --regex "CommandLine=.*-enc\s+[A-Za-z0-9+/=]+"

# SQL query / SQL-запрос
./target/release/muninn -e events.json --sql "SELECT * FROM events WHERE \"CommandLine\" LIKE '%whoami%'"

# Stats & exploration / Статистика и исследование
./target/release/muninn -e events.json --stats
./target/release/muninn -e events.json --distinct EventID

# Export to SQLite for further analysis / Экспорт в SQLite для дальнейшего анализа
./target/release/muninn -e events.json --dbfile evidence.db
sqlite3 evidence.db "SELECT * FROM events WHERE \"EventID\" = '4688'"

# JSON output / Вывод в JSON
./target/release/muninn -e events.json -r rules/ -o detections.json
```

---

## Search Examples / Примеры поиска

### Incident Response: lateral movement / Реагирование на инциденты: латеральное перемещение

```bash
# Find all remote logons (LogonType 3 = network, 10 = RDP)
# Найти все удалённые входы (LogonType 3 = сетевой, 10 = RDP)
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '4624' AND \"LogonType\" IN ('3','10')"

# Find PsExec usage / Найти использование PsExec
muninn -e evidence/ -k "psexec"

# Find pass-the-hash (NTLM logon)
# Найти pass-the-hash (NTLM-аутентификация)
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '4624' AND \"LogonType\" = '3' AND \"AuthenticationPackageName\" = 'NTLM'"
```

### Threat Hunting: suspicious processes / Охота за угрозами: подозрительные процессы

```bash
# Encoded PowerShell commands / Закодированные PowerShell-команды
muninn -e evidence/ --regex "CommandLine=.*-[eE]nc[oO]?d?e?d?C?o?m?m?a?n?d?\s+[A-Za-z0-9+/=]{20,}"

# LOLBins downloading files / LOLBins, скачивающие файлы
muninn -e evidence/ --sql "SELECT \"Image\",\"CommandLine\" FROM events WHERE \"CommandLine\" LIKE '%http%' AND (\"Image\" LIKE '%certutil%' OR \"Image\" LIKE '%mshta%' OR \"Image\" LIKE '%regsvr32%')"

# Processes spawned by Office / Процессы, запущенные из Office
muninn -e evidence/ --sql "SELECT \"Image\",\"CommandLine\",\"ParentImage\" FROM events WHERE \"ParentImage\" LIKE '%WINWORD%' OR \"ParentImage\" LIKE '%EXCEL%' OR \"ParentImage\" LIKE '%OUTLOOK%'"

# Reconnaissance / Разведка (whoami, net, ipconfig, systeminfo, nltest)
muninn -e evidence/ --sql "SELECT \"CommandLine\",\"User\" FROM events WHERE \"Image\" LIKE '%whoami%' OR \"Image\" LIKE '%net.exe' OR \"Image\" LIKE '%ipconfig%' OR \"Image\" LIKE '%systeminfo%' OR \"Image\" LIKE '%nltest%'"
```

### Persistence / Закрепление

```bash
# New scheduled tasks / Новые запланированные задачи
muninn -e evidence/ --sql "SELECT \"CommandLine\" FROM events WHERE \"EventID\" = '1' AND \"CommandLine\" LIKE '%schtasks%create%'"

# New services installed / Новые установленные службы
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '7045'"

# Registry run keys modified / Изменённые ключи автозапуска реестра
muninn -e evidence/ --sql "SELECT * FROM events WHERE \"EventID\" = '13' AND \"TargetObject\" LIKE '%\\Run\\%'"
```

### Credential Access / Доступ к учётным данным

```bash
# LSASS access / Доступ к LSASS
muninn -e evidence/ --sql "SELECT \"SourceImage\",\"GrantedAccess\" FROM events WHERE \"EventID\" = '10' AND \"TargetImage\" LIKE '%lsass.exe'"

# Kerberoasting (TGS requests for SPNs) / Kerberoasting (запросы TGS для SPN)
muninn -e evidence/ --sql "SELECT \"TargetUserName\",\"ServiceName\",\"TicketEncryptionType\" FROM events WHERE \"EventID\" = '4769' AND \"TicketEncryptionType\" = '0x17'"

# SSH brute force (syslog) / Брутфорс SSH (syslog)
muninn -e auth.log -k "Invalid user" --stats
muninn -e auth.log --sql "SELECT \"message\" FROM events WHERE \"message\" LIKE '%Invalid user%' LIMIT 20"
```

### Network: external IPs & domains / Сеть: внешние IP и домены

```bash
# All unique destination IPs / Все уникальные IP-адреса назначения
muninn -e evidence/ --distinct DestinationIp

# Find external IPs (exclude RFC1918 private ranges)
# Найти внешние IP (исключить приватные диапазоны RFC1918)
muninn -e evidence/ --sql "
  SELECT DISTINCT \"DestinationIp\" FROM events
  WHERE \"DestinationIp\" IS NOT NULL
    AND \"DestinationIp\" != ''
    AND \"DestinationIp\" NOT LIKE '10.%'
    AND \"DestinationIp\" NOT LIKE '172.16.%' AND \"DestinationIp\" NOT LIKE '172.17.%'
    AND \"DestinationIp\" NOT LIKE '172.18.%' AND \"DestinationIp\" NOT LIKE '172.19.%'
    AND \"DestinationIp\" NOT LIKE '172.2_.%' AND \"DestinationIp\" NOT LIKE '172.30.%'
    AND \"DestinationIp\" NOT LIKE '172.31.%'
    AND \"DestinationIp\" NOT LIKE '192.168.%'
    AND \"DestinationIp\" NOT LIKE '127.%'
"

# Find connections to known bad ports (C2 typical)
# Найти подключения к подозрительным портам (типичные для C2)
muninn -e evidence/ --sql "
  SELECT \"DestinationIp\",\"DestinationPort\",\"Image\" FROM events
  WHERE \"DestinationPort\" IN ('4444','5555','8080','8443','1337','9001','9090')
"

# Find all DNS queries (Sysmon EventID 22)
# Найти все DNS-запросы (Sysmon EventID 22)
muninn -e evidence/ --sql "SELECT \"QueryName\",\"Image\" FROM events WHERE \"EventID\" = '22'"

# Find all unique queried domains / Найти все уникальные запрошенные домены
muninn -e evidence/ --distinct QueryName

# Find suspicious TLDs / Найти подозрительные TLD
muninn -e evidence/ --sql "
  SELECT \"QueryName\",\"Image\" FROM events
  WHERE \"EventID\" = '22'
    AND (\"QueryName\" LIKE '%.xyz' OR \"QueryName\" LIKE '%.top' OR \"QueryName\" LIKE '%.tk'
      OR \"QueryName\" LIKE '%.pw' OR \"QueryName\" LIKE '%.cc' OR \"QueryName\" LIKE '%.onion')
"

# Find domains in URLs (proxy/web logs) / Найти домены в URL (прокси/веб-логи)
muninn -e evidence/ --regex "request=https?://[a-zA-Z0-9.-]+\.(xyz|top|tk|pw|onion)"

# Find connections to IPs in specific CIDR range
# Найти подключения к IP в определённом CIDR-диапазоне (через SIGMA-правила)
# Example SIGMA rule with cidr modifier:
#   DestinationIp|cidr: '185.220.0.0/16'
muninn -e evidence/ --sql "
  SELECT \"DestinationIp\",\"DestinationPort\",\"Image\" FROM events
  WHERE \"DestinationIp\" LIKE '185.220.%'
"

# Zeek DNS logs — find all queried domains / Zeek DNS — все запрошенные домены
muninn -e conn.log --distinct query

# Zeek HTTP logs — all visited hosts / Zeek HTTP — все посещённые хосты
muninn -e http.log --distinct host
```

### Data exploration / Исследование данных

```bash
# What Event IDs are present? / Какие EventID присутствуют?
muninn -e evidence/ --distinct EventID

# All unique process names / Все уникальные имена процессов
muninn -e evidence/ --distinct Image

# All unique source IPs / Все уникальные IP-адреса источников
muninn -e firewall.csv --distinct SourceIP

# Field statistics / Статистика полей
muninn -e evidence/ --stats

# Export to SQLite for advanced queries / Экспорт в SQLite для сложных запросов
muninn -e evidence/ --dbfile case.db
sqlite3 case.db "
  SELECT \"Image\", COUNT(*) as cnt
  FROM events
  WHERE \"EventID\" = '1'
  GROUP BY \"Image\"
  ORDER BY cnt DESC
  LIMIT 20
"
```

### Multi-format directory scan / Сканирование директории с разными форматами

```bash
# Auto-detect all formats / Автоопределение всех форматов
muninn -e ./case42/ -r rules/ -o detections.json --stats

# Only JSON files / Только JSON-файлы
muninn -e ./case42/ -s "*.json" -r rules/windows/

# Exclude pcap files / Исключить pcap-файлы
muninn -e ./case42/ -a "*.pcap" -r rules/
```

---

## Example Output / Пример вывода

```
$ muninn -e ./evidence/ -r ./rules/windows/

  muninn — memory of Corax

  > 847293 events from 42 files in 3.2s (312450 EVTX, 52441 Syslog, 482402 JSON Lines)
  > Loaded 2384 SIGMA rule(s)
  > 12 rule(s) matched

  ══════════════════════════════════════════════════════════════════════
  ●     CRITICAL  Mimikatz Command Line — 14 matches (8ms)
  ●         HIGH  Suspicious Encoded PowerShell — 23 matches (12ms)
  ●         HIGH  Remote Thread in LSASS — 3 matches (15ms)
  ●       MEDIUM  WhoAmi Execution — 47 matches (6ms)
  ●       MEDIUM  Scheduled Task Created via CLI — 8 matches (5ms)
  ●          LOW  Sysmon Configuration Change — 2 matches (3ms)
  ...
  ══════════════════════════════════════════════════════════════════════
  12 rules matched, 116 total events flagged
```

---

## Supported Log Formats / Поддерживаемые форматы логов

All auto-detected by magic bytes, headers, and content heuristics. / Все форматы определяются автоматически по magic bytes, заголовкам и эвристикам содержимого.

| Format / Формат | Detected by / Определяется по | Typical use case / Типичное применение |
|--------|------------|------------------|
| **EVTX** | `ElfFile` magic bytes | Windows Event Logs / Журналы событий Windows |
| **JSON Lines** | First char `{` | Sysmon JSON, AWS CloudTrail, Azure, GCP, M365, Okta |
| **CSV / TSV** | Extension + header heuristic / Расширение + эвристика | Firewall exports, EDR telemetry / Экспорт фаервола, телеметрия EDR |
| **XML** | `<?xml` / `<Event>` | Windows XML exports, Sysmon for Linux / XML-экспорт Windows |
| **Auditd** | `type=` prefix / Префикс `type=` | Linux audit logs / Логи аудита Linux |
| **Syslog** | RFC 3164/5424 PRI or BSD format | auth.log, sshd, sudo, cron |
| **CEF** | `CEF:0\|` prefix / Префикс `CEF:0\|` | ArcSight, firewalls, IDS/IPS / Файрволы, IDS/IPS |
| **LEEF** | `LEEF:1.0\|` / `LEEF:2.0\|` | IBM QRadar events / События IBM QRadar |
| **W3C Extended** | `#Fields:` header / Заголовок `#Fields:` | IIS, web proxies / Веб-прокси |
| **Zeek TSV** | `#separator` header / Заголовок `#separator` | Zeek/Bro IDS (dns, http, conn, etc.) |
| **macOS Unified** | `log show` output pattern | macOS system logs / Системные логи macOS |
| **Plain text** | Fallback / Запасной вариант | Application logs / Логи приложений |

---

## SIGMA Rules / SIGMA-правила

Muninn ships with **3100+ SIGMA rules** from [SigmaHQ](https://github.com/SigmaHQ/sigma) in the `rules/` directory.

Muninn включает **3100+ SIGMA-правил** из [SigmaHQ](https://github.com/SigmaHQ/sigma) в директории `rules/`.

| Category / Категория | Rules / Правил |
|----------|-------|
| Windows | 2384 |
| Cloud (AWS, Azure, GCP, M365) | 226 |
| Linux | 207 |
| Application / Приложения | 92 |
| macOS | 69 |
| Network / Сеть | 52 |
| Web | 45 |
| Identity / Идентификация | 24 |
| Category / Категория | 7 |

```bash
# Run all rules / Запустить все правила
muninn -e events.json -r rules/

# Only Windows process creation rules / Только правила создания процессов Windows
muninn -e events.json -r rules/windows/process_creation/

# Only Linux rules / Только Linux-правила
muninn -e events.json -r rules/linux/

# Only cloud rules / Только облачные правила
muninn -e events.json -r rules/cloud/
```

Rules are licensed under [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License) by SigmaHQ.

Правила лицензированы под [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License) от SigmaHQ.

### SIGMA Modifier Support / Поддержка модификаторов SIGMA

| Modifier / Модификатор | Example / Пример | Description / Описание |
|----------|---------|-------------|
| `contains` | `CommandLine\|contains: 'whoami'` | Substring match / Поиск подстроки |
| `startswith` | `Image\|startswith: 'C:\Windows'` | Prefix match / Совпадение по началу |
| `endswith` | `Image\|endswith: '\cmd.exe'` | Suffix match / Совпадение по окончанию |
| `re` | `CommandLine\|re: '.*-enc\s+'` | Regular expression / Регулярное выражение |
| `all` | `CommandLine\|contains\|all:` | All values must match / Все значения должны совпасть |
| `base64` | `CommandLine\|base64: 'whoami'` | Base64-encoded value / Значение в Base64 |
| `base64offset` | `CommandLine\|base64offset: 'admin'` | Base64 with offset variants / Base64 со сдвигом |
| `windash` | `CommandLine\|windash\|contains: '-enc'` | Windows dash variants (`-`, `/`, `--`) / Варианты дефиса Windows |
| `cidr` | `SourceIp\|cidr: '10.0.0.0/8'` | IP range (CIDR) / Диапазон IP (CIDR) |
| `gt/gte/lt/lte` | `EventID\|gte: 4624` | Numeric comparisons / Числовые сравнения |

---

## CLI Reference / Справка по CLI

```
muninn [OPTIONS] -e <LOG_PATH>

Arguments / Аргументы:
  -e, --events <LOG_PATH>     Log file or directory (recursive) / Лог-файл или директория (рекурсивно)

Log input / Входные логи:
  -s, --select <PATTERN>      Only files matching glob pattern / Только файлы по маске
  -a, --avoid <PATTERN>       Exclude files matching glob pattern / Исключить файлы по маске

Detection / Детектирование:
  -r, --rules <PATH>          SIGMA YAML rules (file or directory) / SIGMA YAML правила (файл или директория)
      --min-level <LEVEL>     Minimum severity [default: low] / Минимальный уровень [по умолчанию: low]

Search / Поиск:
      --sql <QUERY>           Raw SQL query against events table / SQL-запрос к таблице events
  -k, --keyword <TEXT>        Full-text keyword search / Полнотекстовый поиск по ключевому слову
  -f, --field <FIELD=PAT>     Field search (LIKE: %, _) / Поиск по полю (LIKE: %, _)
      --regex <FIELD=RE>      Regex search on a field / Поиск по регулярному выражению

Exploration / Исследование:
      --stats                 Show field statistics / Показать статистику полей
      --distinct <FIELD>      Show unique values of a field / Показать уникальные значения поля

Output / Вывод:
  -o, --output <FILE>         Write results as JSON / Записать результаты в JSON
      --dbfile <FILE>         Export SQLite database / Экспортировать в SQLite базу данных
  -q, --quiet                 Suppress terminal output / Подавить вывод в терминал
```

---

## Using as a Library / Использование как библиотеки

Add to your `Cargo.toml` / Добавьте в ваш `Cargo.toml`:

```toml
[dependencies]
muninn = { git = "https://github.com/corax-security/muninn" }
```

```rust
use muninn::{parsers, search::SearchEngine, sigma};

// Parse log files / Парсинг лог-файлов
let result = parsers::parse_file("events.json")?;

// Load into search engine / Загрузка в поисковый движок
let mut engine = SearchEngine::new()?;
engine.load_events(&result.events)?;

// Run SIGMA rules / Запуск SIGMA-правил
let rules = sigma::load_rules("rules/windows/")?;
for rule in &rules {
    let sql = sigma::compile(rule)?;
    let result = engine.query_sql(&sql)?;
    if result.count > 0 {
        println!("[{}] {} — {} matches", rule.level, rule.title, result.count);
    }
}

// Search / Поиск
let hits = engine.search_keyword("mimikatz")?;
let hits = engine.search_field("EventID", "4624")?;
let hits = engine.search_regex("CommandLine", r".*-enc\s+")?;

// Export / Экспорт
engine.export_db("evidence.db")?;
```

---

## Building / Сборка

```bash
# Debug build / Сборка для отладки
cargo build --features "all-parsers,cli"

# Release build (~5 MB binary) / Релизная сборка (~5 МБ)
cargo build --release --features "all-parsers,cli"

# Run tests / Запуск тестов
cargo test --features "all-parsers"

# Build with specific parsers only / Сборка только с нужными парсерами
cargo build --release --features "parser-syslog,parser-cef,cli"
```

### Feature Flags / Флаги возможностей

| Feature / Флаг | Description / Описание |
|---------|-------------|
| `all-parsers` | Enable all format parsers (default) / Все парсеры форматов (по умолчанию) |
| `cli` | Build command-line binary / Сборка CLI-бинарника |
| `parser-evtx` | Windows EVTX binary format / Бинарный формат Windows EVTX |
| `parser-syslog` | Syslog (RFC 3164/5424) |
| `parser-cef` | Common Event Format |
| `parser-leef` | Log Event Extended Format |
| `parser-zeek` | Zeek/Bro TSV logs / Логи Zeek/Bro TSV |
| `parser-w3c` | W3C Extended Log Format |
| `python` | Python bindings via PyO3 / Python-привязки через PyO3 |

### Docker

```bash
docker build -t muninn .
docker run -v ./evidence:/data muninn /data/events.json -r /app/rules/ --stats
```

### Cross-compilation / Кросс-компиляция

```bash
# Windows target from Linux / Windows-цель из Linux
rustup target add x86_64-pc-windows-msvc
cargo build --release --features "all-parsers,cli" --target x86_64-pc-windows-msvc
```

---

## Examples / Примеры

### Included sample files / Включённые примеры

The `examples/` directory contains ready-to-use sample data. / Директория `examples/` содержит готовые данные для тестирования.

**Log files / Лог-файлы** (`examples/logs/`):

| File / Файл | Format / Формат | Description / Описание |
|------|--------|-------------|
| [`sysmon_events.json`](examples/logs/sysmon_events.json) | JSON Lines | Sysmon EventID 1,3 — process creation, network connections (whoami, encoded PowerShell, certutil, net /domain) / Создание процессов, сетевые подключения |
| [`windows_security.json`](examples/logs/windows_security.json) | JSON Lines | Windows Security — logon (4624), failed logon (4625), process creation (4688), user creation (4720), group change (4732) / Вход, неудачный вход, создание процесса, создание пользователя |
| [`firewall.csv`](examples/logs/firewall.csv) | CSV | Firewall logs — ALLOW/DENY, ports 22/53/443/445/3389/4444 / Логи фаервола |
| [`auth.log`](examples/logs/auth.log) | Syslog | Linux auth — SSH login, sudo, brute force / SSH-вход, sudo, брутфорс |
| [`web_access.log`](examples/logs/web_access.log) | CEF | Web proxy + IDS — HTTP requests, SQL injection alert / Веб-прокси + IDS, алерт SQL-инъекции |
| [`windows_events.xml`](examples/logs/windows_events.xml) | XML | Windows Event XML — logon, failed logon, process creation / XML-события Windows |

**SIGMA rules / SIGMA-правила** (`examples/rules/`):

| File / Файл | MITRE ATT&CK | Description / Описание |
|------|--------------|-------------|
| [`whoami_execution.yml`](examples/rules/whoami_execution.yml) | T1033 Discovery | Detects whoami command / Обнаружение команды whoami |
| [`encoded_powershell.yml`](examples/rules/encoded_powershell.yml) | T1059.001 Execution | Encoded PowerShell (`-enc`) / Закодированный PowerShell |
| [`certutil_download.yml`](examples/rules/certutil_download.yml) | T1105 C2 | Certutil LOLBin file download / Загрузка файлов через certutil |
| [`account_creation.yml`](examples/rules/account_creation.yml) | T1136.001 Persistence | New user account (EventID 4720) / Создание нового пользователя |
| [`ssh_brute_force.yml`](examples/rules/ssh_brute_force.yml) | T1110.001 Credential Access | SSH brute force attempts / Попытки брутфорса SSH |

**Quickstart script / Скрипт быстрого запуска**: [`examples/quickstart.sh`](examples/quickstart.sh)

```bash
# Run the quickstart demo / Запуск демо
./examples/quickstart.sh

# Or test manually / Или тест вручную
muninn -e examples/logs/sysmon_events.json -r examples/rules/ --stats
muninn -e examples/logs/auth.log -k "Invalid user"
muninn -e examples/logs/windows_security.json -r rules/windows/ -o detections.json
```

### Public log datasets for testing / Публичные датасеты логов для тестирования

| Dataset / Датасет | Format / Формат | Size / Размер | Link / Ссылка |
|---------|--------|------|------|
| EVTX-ATTACK-SAMPLES | EVTX | 278 files, 50 MB | [sbousseaden/EVTX-ATTACK-SAMPLES](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES) |
| Hayabusa Sample EVTX | EVTX | Large collection / Большая коллекция | [Yamato-Security/hayabusa-sample-evtx](https://github.com/Yamato-Security/hayabusa-sample-evtx) |
| EVTX-to-MITRE-Attack | EVTX | 270+ samples / 270+ образцов | [mdecrevoisier/EVTX-to-MITRE-Attack](https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack) |
| SecRepo auth.log | Syslog | 86K lines SSH attacks / 86K строк SSH-атак | [secrepo.com/auth.log](https://www.secrepo.com/auth.log/) |
| SecRepo Zeek DNS | Zeek TSV | 428K records / 428K записей | [secrepo.com/maccdc2012](https://www.secrepo.com/maccdc2012/) |
| SecRepo Zeek HTTP | Zeek TSV | 1.3 GB / 1.3 ГБ | [secrepo.com/maccdc2012](https://www.secrepo.com/maccdc2012/) |
| Splunk Attack Data | JSON/Sysmon | Per-technique / По технике | [splunk/attack_data](https://github.com/splunk/attack_data) |
| Mordor / Security Datasets | JSON | MITRE ATT&CK mapped / Привязка к MITRE ATT&CK | [OTRF/Security-Datasets](https://github.com/OTRF/Security-Datasets) |

```bash
# Download and scan EVTX attack samples / Скачать и просканировать EVTX-атаки
git clone --depth=1 https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES.git
muninn -e EVTX-ATTACK-SAMPLES/ -r rules/windows/ -o detections.json

# Download and scan SecRepo auth.log / Скачать и просканировать SecRepo auth.log
curl -sL https://www.secrepo.com/auth.log/auth.log.gz | gunzip > auth.log
muninn -e auth.log -k "Invalid user" --stats
```

---

## Architecture / Архитектура

```
muninn/
├── src/
│   ├── lib.rs              # Library root / Корень библиотеки
│   ├── bin/muninn.rs        # CLI binary / CLI-бинарник
│   ├── model/mod.rs         # Event, ParseResult, SourceFormat
│   ├── parsers/             # 15+ format parsers / 15+ парсеров форматов
│   │   ├── mod.rs           # Auto-detection & dispatch / Автоопределение и диспетчеризация
│   │   ├── json.rs          # JSON Lines parser / Парсер JSON Lines
│   │   ├── csv_tsv.rs       # CSV/TSV parser / Парсер CSV/TSV
│   │   ├── xml.rs           # XML parser (streaming) / Потоковый парсер XML
│   │   ├── syslog.rs        # Syslog RFC 3164/5424
│   │   ├── cef.rs           # Common Event Format
│   │   ├── leef.rs          # Log Event Extended Format
│   │   ├── zeek.rs          # Zeek/Bro TSV
│   │   ├── w3c.rs           # W3C Extended Log
│   │   ├── evtx.rs          # Windows EVTX binary / Бинарный формат EVTX
│   │   ├── auditd.rs        # Linux Audit / Аудит Linux
│   │   ├── macos.rs         # macOS Unified Log
│   │   ├── flatten.rs       # Windows Event JSON flattener / Развёртка JSON Windows Events
│   │   └── text.rs          # Plain text fallback / Запасной парсер текста
│   ├── search/mod.rs        # SQLite-backed search engine / Поисковый движок на SQLite
│   └── sigma/               # SIGMA rule engine / Движок SIGMA-правил
│       ├── mod.rs            # Public API / Публичный API
│       ├── parser.rs         # YAML rule parser / Парсер YAML-правил
│       └── compiler.rs       # SIGMA → SQL compiler / Компилятор SIGMA → SQL
├── rules/                   # 3100+ SigmaHQ rules / 3100+ правил SigmaHQ
├── tests/                   # Integration tests / Интеграционные тесты
├── examples/                # Sample logs, rules, quickstart / Примеры логов, правил
├── scripts/                 # Build & ruleset scripts / Скрипты сборки
└── Cargo.toml
```

---

## Performance / Производительность

- **Parsing / Парсинг**: ~250K events/sec / ~250К событий/сек (JSON Lines)
- **Loading / Загрузка**: 100K events into SQLite in <5 seconds / 100К событий в SQLite за <5 секунд
- **Binary size / Размер бинарника**: ~5 MB / ~5 МБ (release, stripped, LTO)
- **Memory / Память**: SQLite-backed, handles millions of events / На основе SQLite, обрабатывает миллионы событий

---

## License / Лицензия

This project is licensed under **AGPL-3.0** — see [LICENSE](LICENSE) for details.

Проект лицензирован под **AGPL-3.0** — см. [LICENSE](LICENSE).

SIGMA rules in `rules/` are licensed under [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License) by SigmaHQ.

SIGMA-правила в `rules/` лицензированы под [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License) от SigmaHQ.
