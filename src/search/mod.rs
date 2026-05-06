use anyhow::{Context, Result};
use log::{debug, info};
use rusqlite::{params, Connection};
use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::model::Event;

const TABLE: &str = "events";

/// Reject field/index names that contain SQL-injection characters.
fn validate_identifier(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '-' | '.' | '@' | '#' | ' '))
    {
        anyhow::bail!("Invalid identifier: {:?}", name);
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct SearchResult {
    pub rows: Vec<HashMap<String, String>>,
    pub count: usize,
    pub query: String,
    pub duration_ms: u64,
}

pub struct SearchEngine {
    conn: Connection,
    columns: Vec<String>,
    event_count: usize,
}

fn register_regexp(conn: &Connection) -> Result<()> {
    conn.create_scalar_function(
        "REGEXP",
        2,
        rusqlite::functions::FunctionFlags::SQLITE_UTF8
            | rusqlite::functions::FunctionFlags::SQLITE_DETERMINISTIC,
        |ctx| {
            let pattern: String = ctx.get(0)?;
            let text: String = ctx.get::<String>(1).unwrap_or_default();
            let re = regex::Regex::new(&pattern)
                .map_err(|e| rusqlite::Error::UserFunctionError(Box::new(e)))?;
            Ok(re.is_match(&text))
        },
    )?;
    Ok(())
}

impl SearchEngine {
    pub fn new() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA journal_mode = OFF;
             PRAGMA synchronous = OFF;
             PRAGMA cache_size = -262144;
             PRAGMA temp_store = MEMORY;
             PRAGMA mmap_size = 536870912;
             PRAGMA page_size = 32768;
             PRAGMA locking_mode = EXCLUSIVE;",
        )?;

        register_regexp(&conn)?;

        Ok(SearchEngine {
            conn,
            columns: Vec::new(),
            event_count: 0,
        })
    }

    /// Create a lightweight in-memory engine for temporary per-file SIGMA evaluation.
    /// Uses minimal cache (16 MB) since events are loaded, queried, then discarded.
    pub fn new_lightweight() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        conn.execute_batch(
            "PRAGMA journal_mode = OFF;
             PRAGMA synchronous = OFF;
             PRAGMA cache_size = -16384;
             PRAGMA temp_store = MEMORY;
             PRAGMA mmap_size = 0;
             PRAGMA page_size = 4096;
             PRAGMA locking_mode = EXCLUSIVE;",
        )?;

        register_regexp(&conn)?;

        Ok(SearchEngine {
            conn,
            columns: Vec::new(),
            event_count: 0,
        })
    }

    /// Create a disk-backed temporary engine for per-file SIGMA evaluation of large files.
    /// Data goes to disk instead of RAM, keeping RSS low. The caller should delete the
    /// temp file after dropping the engine.
    pub fn new_temp_disk(path: &Path) -> Result<Self> {
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = OFF;
             PRAGMA synchronous = OFF;
             PRAGMA cache_size = -16384;
             PRAGMA temp_store = FILE;
             PRAGMA mmap_size = 0;
             PRAGMA page_size = 4096;
             PRAGMA locking_mode = EXCLUSIVE;",
        )?;

        register_regexp(&conn)?;

        Ok(SearchEngine {
            conn,
            columns: Vec::new(),
            event_count: 0,
        })
    }

    /// Create a new engine backed by an on-disk SQLite file.
    /// Events are written directly to disk — no RAM limit.
    pub fn new_on_disk(path: &Path) -> Result<Self> {
        // Remove existing file to start fresh
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -262144;
             PRAGMA temp_store = MEMORY;
             PRAGMA mmap_size = 536870912;
             PRAGMA page_size = 32768;
             PRAGMA locking_mode = EXCLUSIVE;",
        )?;

        register_regexp(&conn)?;

        Ok(SearchEngine {
            conn,
            columns: Vec::new(),
            event_count: 0,
        })
    }

    pub fn from_file(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        register_regexp(&conn)?;

        let columns: Vec<String> = {
            let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{}\")", TABLE))?;
            let result: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(1))?
                .filter_map(|r| r.ok())
                .collect();
            result
        };
        let event_count = conn
            .query_row(&format!("SELECT COUNT(*) FROM \"{}\"", TABLE), [], |row| {
                row.get::<_, usize>(0)
            })
            .unwrap_or(0);

        Ok(SearchEngine {
            conn,
            columns,
            event_count,
        })
    }

    pub fn load_events(&mut self, events: &[Event]) -> Result<usize> {
        if events.is_empty() {
            return Ok(0);
        }

        // Deduplicate columns case-insensitively (SQLite column names are case-insensitive)
        // Skip columns with names > 128 chars (certificate extensions, deeply nested XML)
        let mut seen_lower: HashSet<String> =
            self.columns.iter().map(|c| c.to_lowercase()).collect();
        let mut col_set: Vec<String> = self.columns.clone();
        for ev in events {
            for k in ev.fields.keys() {
                if k.len() > 128 {
                    continue; // Skip excessively long column names
                }
                let lower = k.to_lowercase();
                if seen_lower.insert(lower) {
                    col_set.push(k.clone());
                }
            }
        }

        let new_columns = col_set;

        if self.columns.is_empty() {
            let col_defs: Vec<String> = new_columns
                .iter()
                .map(|c| format!("\"{}\" TEXT", c))
                .collect();
            let sql = format!(
                "CREATE TABLE IF NOT EXISTS \"{}\" ({})",
                TABLE,
                col_defs.join(", ")
            );
            self.conn.execute(&sql, [])?;
            self.columns = new_columns;
        } else {
            // Case-insensitive existence check — SQLite treats column names that
            // way internally, and a previous batch may have added "FthEnabled..."
            // while this batch saw "FTHEnabled...". Without this, a duplicate
            // ALTER fires, fails, but self.columns still grows — and the next
            // INSERT references a column SQLite doesn't have under that case.
            for col in &new_columns {
                if self.columns.iter().any(|c| c.eq_ignore_ascii_case(col)) {
                    continue;
                }
                let sql = format!("ALTER TABLE \"{}\" ADD COLUMN \"{}\" TEXT", TABLE, col);
                match self.conn.execute(&sql, []) {
                    Ok(_) => self.columns.push(col.clone()),
                    Err(e) => {
                        // Don't push on failure — anything in self.columns must
                        // actually exist in the schema, otherwise the next
                        // prepare_cached() blows up with "no such column".
                        debug!("ALTER TABLE ADD COLUMN '{}' failed: {}", col, e);
                    }
                }
            }
        }

        // Defensive sync: fetch the live schema from SQLite and rebuild
        // self.columns from it. This costs one PRAGMA per load_events call but
        // guarantees that what we list in INSERT actually exists in the table.
        // Catches any prior drift (case-insensitive duplicates, failed ALTERs
        // still leaving stale entries in self.columns, etc.) before the
        // prepare_cached call below would have errored out hard.
        let actual_columns: Vec<String> = {
            let mut stmt = self
                .conn
                .prepare(&format!("PRAGMA table_info(\"{}\")", TABLE))?;
            let result: Vec<String> = stmt
                .query_map([], |row| row.get::<_, String>(1))?
                .filter_map(|r| r.ok())
                .collect();
            result
        };
        if !actual_columns.is_empty() {
            self.columns = actual_columns;
        }

        let tx = self.conn.transaction()?;
        let col_names: Vec<String> = self.columns.iter().map(|c| format!("\"{}\"", c)).collect();
        let placeholders: Vec<String> = self.columns.iter().map(|_| "?".into()).collect();
        let insert_sql = format!(
            "INSERT INTO \"{}\" ({}) VALUES ({})",
            TABLE,
            col_names.join(", "),
            placeholders.join(", ")
        );

        let mut stmt = tx.prepare_cached(&insert_sql)?;
        let mut loaded = 0;
        let empty = String::new();

        // Pre-compute the lowercase-keyed column list so per-event lookups can
        // fall back case-insensitively. SQLite resolves column names case-
        // insensitively, but our `Event::fields` HashMap keeps original case;
        // without this fallback, an event with `fthEnabledProcessStartup`
        // silently drops its value when self.columns has the column under
        // `FthEnabledProcessStartup`.
        let columns_lower: Vec<String> = self.columns.iter().map(|c| c.to_lowercase()).collect();

        for ev in events {
            // Build a lower→value index once per event. Cheap (events have
            // ~30-100 fields) and unblocks case-mismatched lookups.
            let lower_index: HashMap<String, &String> = ev
                .fields
                .iter()
                .map(|(k, v)| (k.to_lowercase(), v))
                .collect();

            let params: Vec<&dyn rusqlite::types::ToSql> = self
                .columns
                .iter()
                .enumerate()
                .map(|(i, col)| -> &dyn rusqlite::types::ToSql {
                    if let Some(v) = ev.fields.get(col) {
                        v
                    } else if let Some(v) = lower_index.get(&columns_lower[i]) {
                        *v
                    } else {
                        &empty
                    }
                })
                .collect();
            match stmt.execute(params.as_slice()) {
                Ok(_) => loaded += 1,
                Err(e) => log::debug!("Failed to insert event: {}", e),
            }
        }

        drop(stmt);
        tx.commit()?;
        self.event_count += loaded;

        info!("Loaded {} events (total: {})", loaded, self.event_count);
        Ok(loaded)
    }

    pub fn create_indexes(&self) -> Result<()> {
        if self.columns.is_empty() {
            return Ok(()); // No table created yet (0 events loaded)
        }
        let index_fields = [
            // ── Windows EVTX core ──
            "EventID",
            "Channel",
            "Provider_Name",
            "Computer",
            "Level",
            "Keywords",
            "TimeCreated",
            "SystemTime",
            // ── Process (Sysmon EID 1, Security 4688) ──
            "Image",
            "ParentImage",
            "CommandLine",
            "ParentCommandLine",
            "ProcessId",
            "ParentProcessId",
            "OriginalFileName",
            "IntegrityLevel",
            // ── File / Registry (Sysmon EID 11/12/13/14) ──
            "TargetFilename",
            "TargetObject",
            "ObjectName",
            // ── Network (Sysmon EID 3, Firewall) ──
            "SourceIp",
            "DestinationIp",
            "DestinationPort",
            "SourcePort",
            // ── Auth (Security 4624/4625/4648/4672) ──
            "User",
            "TargetUserName",
            "SubjectUserName",
            "LogonType",
            "IpAddress",
            "WorkstationName",
            // ── Service / Task / Pipe (7045, Sysmon 17/18) ──
            "ServiceName",
            "TaskName",
            "PipeName",
            // ── Sysmon extended ──
            "Hashes",
            "ImageLoaded",
            "SourceImage",
            "TargetImage",
            "QueryName",
            "CallTrace",
            // ── Windows Defender ──
            "ThreatName",
            "DetectionSource",
            "ActionName",
            // ── Syslog / Linux ──
            "hostname",
            "app_name",
            "procid",
            "facility",
            "severity",
            "message",
            "timestamp",
            "level",
            // ── Linux auditd ──
            "type",
            "exe",
            "comm",
            "syscall",
            "uid",
            "pid",
            "ppid",
            // ── CEF / LEEF (firewalls, IDS) ──
            "DeviceVendor",
            "DeviceProduct",
            "DeviceEventClassID",
            "Name",
            "Severity",
            "src",
            "dst",
            "shost",
            "dhost",
            "sport",
            "dport",
            "act",
            "proto",
            // ── Zeek ──
            "_zeek_log_type",
            "id_orig_h",
            "id_resp_h",
            "id_orig_p",
            "id_resp_p",
            "uid",
            "proto",
            "service",
            "query",
            "conn_state",
            // ── W3C / IIS / Apache / Nginx ──
            "c-ip",
            "s-ip",
            "cs-method",
            "cs-uri-stem",
            "sc-status",
            "sc-bytes",
            "cs-username",
            "cs-version",
            // ── macOS unified log ──
            "processImagePath",
            "subsystem",
            "category",
            "eventType",
            "eventSource",
            // ── Generic ──
            "Operation",
            "src_ip",
            "dst_ip",
            "@timestamp",
        ];
        for field in &index_fields {
            if self.columns.iter().any(|c| c == *field) {
                let sql = format!(
                    "CREATE INDEX IF NOT EXISTS \"idx_{}\" ON \"{}\" (\"{}\")",
                    field, TABLE, field
                );
                let _ = self.conn.execute(&sql, []);
            }
        }
        Ok(())
    }

    pub fn query_sql(&self, sql: &str) -> Result<SearchResult> {
        let start = std::time::Instant::now();
        let rows = self.execute_query(sql)?;
        let count = rows.len();
        Ok(SearchResult {
            rows,
            count,
            query: sql.to_string(),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    pub fn search_field(&self, field: &str, pattern: &str) -> Result<SearchResult> {
        validate_identifier(field)?;
        let sql = format!(
            "SELECT * FROM \"{}\" WHERE \"{}\" LIKE ? ESCAPE '\\'",
            TABLE, field
        );
        let start = std::time::Instant::now();

        let mut stmt = self.conn.prepare(&sql)?;
        let col_names: Vec<String> = stmt.column_names().iter().map(|n| n.to_string()).collect();

        let rows: Vec<HashMap<String, String>> = stmt
            .query_map(params![pattern], |row| {
                let mut map = HashMap::new();
                for (i, col) in col_names.iter().enumerate() {
                    if col == "_raw" {
                        continue;
                    }
                    if let Ok(v) = row.get::<_, String>(i) {
                        if !v.is_empty() {
                            map.insert(col.clone(), v);
                        }
                    }
                }
                Ok(map)
            })?
            .filter_map(|r| r.ok())
            .collect();

        let count = rows.len();
        Ok(SearchResult {
            rows,
            count,
            query: format!("{} LIKE '{}'", field, pattern),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    pub fn search_keyword(&self, keyword: &str) -> Result<SearchResult> {
        let sql = format!(
            "SELECT * FROM \"{}\" WHERE \"_raw\" LIKE ? ESCAPE '\\'",
            TABLE
        );
        let pattern = format!("%{}%", keyword.replace('%', "\\%").replace('_', "\\_"));
        let start = std::time::Instant::now();

        let mut stmt = self.conn.prepare(&sql)?;
        let col_names: Vec<String> = stmt.column_names().iter().map(|n| n.to_string()).collect();

        let rows: Vec<HashMap<String, String>> = stmt
            .query_map(params![pattern], |row| {
                let mut map = HashMap::new();
                for (i, col) in col_names.iter().enumerate() {
                    if col == "_raw" {
                        continue;
                    }
                    if let Ok(v) = row.get::<_, String>(i) {
                        if !v.is_empty() {
                            map.insert(col.clone(), v);
                        }
                    }
                }
                Ok(map)
            })?
            .filter_map(|r| r.ok())
            .collect();

        let count = rows.len();
        Ok(SearchResult {
            rows,
            count,
            query: format!("keyword: {}", keyword),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    pub fn search_regex(&self, field: &str, pattern: &str) -> Result<SearchResult> {
        let sql = format!("SELECT * FROM \"{}\" WHERE \"{}\" REGEXP ?", TABLE, field);
        let start = std::time::Instant::now();

        let mut stmt = self.conn.prepare(&sql)?;
        let col_names: Vec<String> = stmt.column_names().iter().map(|n| n.to_string()).collect();

        let rows: Vec<HashMap<String, String>> = stmt
            .query_map(params![pattern], |row| {
                let mut map = HashMap::new();
                for (i, col) in col_names.iter().enumerate() {
                    if col == "_raw" {
                        continue;
                    }
                    if let Ok(v) = row.get::<_, String>(i) {
                        if !v.is_empty() {
                            map.insert(col.clone(), v);
                        }
                    }
                }
                Ok(map)
            })?
            .filter_map(|r| r.ok())
            .collect();

        let count = rows.len();
        Ok(SearchResult {
            rows,
            count,
            query: format!("{} REGEXP '{}'", field, pattern),
            duration_ms: start.elapsed().as_millis() as u64,
        })
    }

    pub fn run_queries(&self, queries: &[(&str, &str)]) -> Vec<(String, SearchResult)> {
        queries
            .iter()
            .filter_map(|(label, sql)| match self.query_sql(sql) {
                Ok(result) if result.count > 0 => Some((label.to_string(), result)),
                Ok(_) => None,
                Err(e) => {
                    debug!("Query '{}' failed: {}", label, e);
                    None
                }
            })
            .collect()
    }

    pub fn distinct_values(&self, field: &str) -> Result<Vec<String>> {
        validate_identifier(field)?;
        let sql = format!(
            "SELECT DISTINCT \"{}\" FROM \"{}\" WHERE \"{}\" IS NOT NULL AND \"{}\" != '' ORDER BY \"{}\"",
            field, TABLE, field, field, field
        );
        let mut stmt = self.conn.prepare(&sql)?;
        let values: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(0))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(values)
    }

    pub fn fields(&self) -> &[String] {
        &self.columns
    }

    pub fn event_count(&self) -> usize {
        self.event_count
    }

    pub fn query_sql_with_limit(&self, sql: &str, limit: usize) -> Result<SearchResult> {
        let trimmed = sql.trim().trim_end_matches(';');
        let limited = format!("{} LIMIT {}", trimmed, limit);
        self.query_sql(&limited)
    }

    pub fn apply_time_filter(
        &self,
        time_field: &str,
        after: Option<&str>,
        before: Option<&str>,
    ) -> Result<usize> {
        let mut conditions = Vec::new();
        if let Some(a) = after {
            conditions.push(format!("\"{}\" < '{}'", time_field, a));
        }
        if let Some(b) = before {
            conditions.push(format!("\"{}\" > '{}'", time_field, b));
        }
        if conditions.is_empty() {
            return Ok(0);
        }
        let sql = format!(
            "DELETE FROM \"{}\" WHERE {}",
            TABLE,
            conditions.join(" OR ")
        );
        let deleted = self.conn.execute(&sql, [])?;
        Ok(deleted)
    }

    pub fn detect_time_field(&self) -> Option<String> {
        const CANDIDATES: &[&str] = &[
            "SystemTime",
            "timestamp",
            "@timestamp",
            "TimeCreated",
            "date",
            "_time",
            "time",
            "datetime",
            "EventTime",
            "UtcTime",
        ];
        for field in CANDIDATES {
            if self.columns.iter().any(|c| c == *field) {
                let sql = format!(
                    "SELECT COUNT(*) FROM \"{}\" WHERE \"{}\" IS NOT NULL AND \"{}\" != ''",
                    TABLE, field, field
                );
                if let Ok(count) = self.conn.query_row(&sql, [], |row| row.get::<_, usize>(0)) {
                    if count > 0 {
                        return Some(field.to_string());
                    }
                }
            }
        }
        None
    }

    pub fn create_index_on(&self, field: &str) -> Result<()> {
        validate_identifier(field)?;
        let sql = format!(
            "CREATE INDEX IF NOT EXISTS \"idx_custom_{}\" ON \"{}\" (\"{}\")",
            field, TABLE, field
        );
        self.conn.execute(&sql, [])?;
        Ok(())
    }

    pub fn drop_index(&self, index_name: &str) -> Result<()> {
        validate_identifier(index_name)?;
        let sql = format!("DROP INDEX IF EXISTS \"{}\"", index_name);
        self.conn.execute(&sql, [])?;
        Ok(())
    }

    pub fn list_indexes(&self) -> Result<Vec<String>> {
        let sql = format!("PRAGMA index_list(\"{}\")", TABLE);
        let mut stmt = self.conn.prepare(&sql)?;
        let indexes: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))?
            .filter_map(|r| r.ok())
            .collect();
        Ok(indexes)
    }

    pub fn export_jsonl(&self, path: &Path) -> Result<usize> {
        let sql = format!("SELECT * FROM \"{}\"", TABLE);
        let mut stmt = self.conn.prepare(&sql)?;
        let col_names: Vec<String> = stmt.column_names().iter().map(|n| n.to_string()).collect();

        let mut file = std::io::BufWriter::new(std::fs::File::create(path)?);
        let mut count = 0;

        let rows = stmt.query_map([], |row| {
            let mut map = serde_json::Map::new();
            for (i, col) in col_names.iter().enumerate() {
                if col == "_raw" {
                    continue;
                }
                if let Ok(v) = row.get::<_, String>(i) {
                    if !v.is_empty() {
                        map.insert(col.clone(), serde_json::Value::String(v));
                    }
                }
            }
            Ok(map)
        })?;

        use std::io::Write;
        for map in rows.flatten() {
            let json = serde_json::Value::Object(map);
            writeln!(file, "{}", json)?;
            count += 1;
        }

        Ok(count)
    }

    /// Switch to bulk load mode: minimal cache, no mmap, no fsync.
    /// Use before streaming large amounts of data into an on-disk engine.
    pub fn set_bulk_load_mode(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA cache_size = -32768;
             PRAGMA mmap_size = 0;
             PRAGMA synchronous = OFF;",
        )?;
        Ok(())
    }

    /// Switch to query mode: full cache and mmap for fast reads.
    /// Call after bulk loading is complete.
    pub fn set_query_mode(&self) -> Result<()> {
        self.conn.execute_batch(
            "PRAGMA cache_size = -262144;
             PRAGMA mmap_size = 536870912;
             PRAGMA synchronous = NORMAL;",
        )?;
        self.checkpoint_wal();
        Ok(())
    }

    /// Run a passive WAL checkpoint to consolidate writes and free memory.
    pub fn checkpoint_wal(&self) {
        let _ = self.conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE)");
    }

    pub fn export_db(&self, path: &Path) -> Result<()> {
        let mut dest = Connection::open(path)?;
        let backup = rusqlite::backup::Backup::new(&self.conn, &mut dest)?;
        backup.run_to_completion(100, std::time::Duration::from_millis(10), None)?;
        info!("Database exported to {:?}", path);
        Ok(())
    }

    pub fn stats(&self) -> Result<EngineStats> {
        let field_count = self.columns.len();
        let non_empty: HashMap<String, usize> = self
            .columns
            .iter()
            .filter_map(|col| {
                let sql = format!(
                    "SELECT COUNT(*) FROM \"{}\" WHERE \"{}\" IS NOT NULL AND \"{}\" != ''",
                    TABLE, col, col
                );
                self.conn
                    .query_row(&sql, [], |row| row.get::<_, usize>(0))
                    .ok()
                    .map(|c| (col.clone(), c))
            })
            .filter(|(_, c)| *c > 0)
            .collect();

        Ok(EngineStats {
            total_events: self.event_count,
            total_fields: field_count,
            populated_fields: non_empty,
        })
    }

    fn execute_query(&self, sql: &str) -> Result<Vec<HashMap<String, String>>> {
        let mut stmt = self.conn.prepare(sql).context("Failed to prepare SQL")?;
        let col_names: Vec<String> = stmt.column_names().iter().map(|n| n.to_string()).collect();

        let rows: Vec<HashMap<String, String>> = stmt
            .query_map([], |row| {
                let mut map = HashMap::new();
                for (i, col) in col_names.iter().enumerate() {
                    if col == "_raw" {
                        continue;
                    }
                    if let Ok(v) = row.get::<_, String>(i) {
                        if !v.is_empty() {
                            map.insert(col.clone(), v);
                        }
                    }
                }
                Ok(map)
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(rows)
    }
}

#[derive(Debug, serde::Serialize)]
pub struct EngineStats {
    pub total_events: usize,
    pub total_fields: usize,
    pub populated_fields: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Event, SourceFormat};

    fn make_event(fields: &[(&str, &str)]) -> Event {
        let mut ev = Event::new("test.evtx", SourceFormat::Evtx);
        for (k, v) in fields {
            ev.set(*k, *v);
        }
        ev
    }

    /// Regression: a column added in batch 1 under one case spelling must not
    /// crash the next batch when an event in that batch references the same
    /// field under a different case spelling. SQLite resolves columns
    /// case-insensitively; our code must keep self.columns in sync with the
    /// real schema and tolerate case-mismatched field keys at INSERT time.
    #[test]
    fn case_insensitive_column_handling_across_batches() {
        let mut eng = SearchEngine::new().unwrap();

        // Batch 1: introduces "FthEnabledProcessStartup" (canonical case)
        let batch1 = vec![make_event(&[
            ("EventID", "5379"),
            ("FthEnabledProcessStartup", "True"),
        ])];
        eng.load_events(&batch1).unwrap();

        // Batch 2: same field, different case spelling. Used to crash with
        // "table events has no column named FthEnabledProcessStartup" because
        // the ALTER TABLE for the new spelling failed (SQLite's case-insensitive
        // collision) but self.columns still grew, leaving the next INSERT's
        // column list referencing a non-existent column.
        let batch2 = vec![make_event(&[
            ("EventID", "5380"),
            ("fthEnabledProcessStartup", "False"),
        ])];
        eng.load_events(&batch2).unwrap();

        // Both events made it through and the value from batch 2 lands in the
        // single canonical column (case-insensitive lookup at INSERT time).
        let r = eng
            .query_sql("SELECT \"FthEnabledProcessStartup\" FROM \"events\" ORDER BY \"EventID\"")
            .unwrap();
        assert_eq!(r.rows.len(), 2);
        assert_eq!(
            r.rows[0]
                .get("FthEnabledProcessStartup")
                .map(|s| s.as_str()),
            Some("True")
        );
        assert_eq!(
            r.rows[1]
                .get("FthEnabledProcessStartup")
                .map(|s| s.as_str()),
            Some("False")
        );
    }

    /// Regression: a self.columns list that drifted out of sync with the actual
    /// SQLite schema (e.g. from a failed ALTER) must self-heal on the next
    /// load_events call via the PRAGMA table_info sync, not blow up at
    /// prepare_cached time.
    #[test]
    fn pragma_sync_self_heals_drifted_column_list() {
        let mut eng = SearchEngine::new().unwrap();
        eng.load_events(&[make_event(&[("EventID", "1")])]).unwrap();
        // Simulate drift: add a phantom column to self.columns that doesn't
        // actually exist in the SQLite schema.
        eng.columns.push("PhantomColumn".to_string());
        // Next load_events must NOT panic when prepare_cached parses the
        // INSERT — the PRAGMA sync at the top should drop "PhantomColumn"
        // before the INSERT statement is built.
        let result = eng.load_events(&[make_event(&[("EventID", "2")])]);
        assert!(result.is_ok(), "load_events must self-heal: {:?}", result);
    }
}
