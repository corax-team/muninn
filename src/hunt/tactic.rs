use crate::hunt::{set_hunt_finding, HuntSeverity};
use crate::model::Event;
use crate::transforms::Transform;

// ── Lateral Movement Indicator ─────────────────────────────────────

const LATERAL_PATTERNS: &[(&str, &str)] = &[
    ("psexec", "PsExec"),
    ("paexec", "PaExec"),
    ("psexesvc", "PsExecSvc"),
    ("wmic /node:", "WMI_Remote"),
    ("invoke-wmimethod", "WMI_PS"),
    ("enter-pssession", "PSRemoting"),
    ("invoke-command -computername", "PSRemoting"),
    ("new-pssession", "PSRemoting"),
    ("winrs -r:", "WinRS"),
    ("net use \\\\", "SMB_Net_Use"),
    ("schtasks /s ", "Remote_ScheduledTask"),
    ("schtasks /create /s ", "Remote_ScheduledTask"),
    ("mstsc /v:", "RDP"),
];

pub struct LateralMovementIndicator;

impl Transform for LateralMovementIndicator {
    fn name(&self) -> &str {
        "lateral_movement_indicator"
    }

    fn apply(&self, event: &mut Event) {
        let cmd = match event.fields.get("CommandLine") {
            Some(v) if v.len() > 5 => v.clone(),
            _ => return,
        };

        let cmd_lower = cmd.to_lowercase();

        for (pattern, label) in LATERAL_PATTERNS {
            if cmd_lower.contains(pattern) {
                event.fields.insert("hunt_lateral".into(), "true".into());
                event
                    .fields
                    .insert("hunt_lateral_method".into(), label.to_string());
                set_hunt_finding(
                    &mut event.fields,
                    "LateralMovement",
                    HuntSeverity::High,
                    &format!("Lateral movement: {}", label),
                );
                return;
            }
        }
    }
}

// ── Persistence Classifier ─────────────────────────────────────────

const PERSISTENCE_PATTERNS: &[(&str, &str)] = &[
    ("schtasks /create", "scheduled_task"),
    ("register-scheduledjob", "scheduled_task_ps"),
    ("new-scheduledtask", "scheduled_task_ps"),
    ("sc create", "service_creation"),
    ("new-service", "service_creation_ps"),
    ("reg add", "registry_run"),
    ("set-itemproperty", "registry_run_ps"),
    ("new-itemproperty", "registry_run_ps"),
    ("__eventfilter", "wmi_subscription"),
    ("__eventconsumer", "wmi_subscription"),
    ("register-wmievent", "wmi_subscription_ps"),
    ("crontab", "cron_linux"),
    ("systemctl enable", "systemd_linux"),
];

pub struct PersistenceClassifier;

impl Transform for PersistenceClassifier {
    fn name(&self) -> &str {
        "persistence_classifier"
    }

    fn apply(&self, event: &mut Event) {
        let cmd = match event.fields.get("CommandLine") {
            Some(v) if v.len() > 5 => v.clone(),
            _ => return,
        };

        let cmd_lower = cmd.to_lowercase();

        for (pattern, label) in PERSISTENCE_PATTERNS {
            if cmd_lower.contains(pattern) {
                event
                    .fields
                    .insert("hunt_persistence".into(), "true".into());
                event
                    .fields
                    .insert("hunt_persistence_type".into(), label.to_string());
                set_hunt_finding(
                    &mut event.fields,
                    "PersistenceClassifier",
                    HuntSeverity::Medium,
                    &format!("Persistence mechanism: {}", label),
                );
                return;
            }
        }
    }
}

// ── Recon Indicator ────────────────────────────────────────────────

const RECON_COMMANDS: &[&str] = &[
    "systeminfo",
    "hostname",
    "whoami",
    "ipconfig",
    "ifconfig",
    "netstat",
    "arp -a",
    "route print",
    "nslookup",
    "net user",
    "net group",
    "net localgroup",
    "net share",
    "net view",
    "nltest",
    "dsquery",
    "adfind",
    "ldapsearch",
    "tasklist",
    "qprocess",
    "wmic process",
    "netsh firewall",
    "netsh advfirewall",
];

pub struct ReconIndicator;

impl Transform for ReconIndicator {
    fn name(&self) -> &str {
        "recon_indicator"
    }

    fn apply(&self, event: &mut Event) {
        let cmd = match event.fields.get("CommandLine") {
            Some(v) if v.len() > 3 => v.clone(),
            _ => return,
        };

        let cmd_lower = cmd.to_lowercase();
        let mut found = Vec::new();

        for recon_cmd in RECON_COMMANDS {
            if cmd_lower.contains(&recon_cmd.to_lowercase()) {
                found.push(*recon_cmd);
            }
        }

        if found.is_empty() {
            return;
        }

        let severity = if found.len() >= 3 {
            HuntSeverity::Medium
        } else {
            HuntSeverity::Low
        };

        event.fields.insert("hunt_recon".into(), "true".into());
        event
            .fields
            .insert("hunt_recon_commands".into(), found.join(", "));
        set_hunt_finding(
            &mut event.fields,
            "ReconIndicator",
            severity,
            &format!("Reconnaissance: {}", found.join(", ")),
        );
    }
}

// ── Data Staging Detector ──────────────────────────────────────────

const STAGING_PATTERNS: &[(&str, &str)] = &[
    ("rar a", "archive_rar"),
    ("7z a", "archive_7z"),
    ("7za a", "archive_7z"),
    ("zip -r", "archive_zip"),
    ("tar czf", "archive_tar"),
    ("tar -czf", "archive_tar"),
    ("makecab", "archive_cab"),
    ("compact /c", "compress_ntfs"),
    ("sqlcmd", "db_dump_mssql"),
    ("mysqldump", "db_dump_mysql"),
    ("pg_dump", "db_dump_postgres"),
    ("mongodump", "db_dump_mongo"),
    ("robocopy", "bulk_copy"),
    ("xcopy /s", "bulk_copy"),
    ("findstr /s /i password", "sensitive_file_hunt"),
    ("findstr /s /i credential", "sensitive_file_hunt"),
];

pub struct DataStagingDetector;

impl Transform for DataStagingDetector {
    fn name(&self) -> &str {
        "data_staging_detector"
    }

    fn apply(&self, event: &mut Event) {
        let cmd = match event.fields.get("CommandLine") {
            Some(v) if v.len() > 5 => v.clone(),
            _ => return,
        };

        let cmd_lower = cmd.to_lowercase();

        for (pattern, label) in STAGING_PATTERNS {
            if cmd_lower.contains(pattern) {
                event
                    .fields
                    .insert("hunt_data_staging".into(), "true".into());
                event
                    .fields
                    .insert("hunt_staging_type".into(), label.to_string());
                set_hunt_finding(
                    &mut event.fields,
                    "DataStaging",
                    HuntSeverity::Medium,
                    &format!("Data staging activity: {}", label),
                );
                return;
            }
        }
    }
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
    fn test_lateral_psexec() {
        let mut event = make_event(&[("CommandLine", r"psexec \\DC01 cmd")]);
        LateralMovementIndicator.apply(&mut event);
        assert_eq!(event.get("hunt_lateral_method"), Some("PsExec"));
    }

    #[test]
    fn test_persistence_schtasks() {
        let mut event = make_event(&[(
            "CommandLine",
            r"schtasks /create /tn Evil /tr C:\Temp\evil.exe /sc daily",
        )]);
        PersistenceClassifier.apply(&mut event);
        assert_eq!(event.get("hunt_persistence_type"), Some("scheduled_task"));
    }

    #[test]
    fn test_recon_multi() {
        let mut event = make_event(&[(
            "CommandLine",
            "systeminfo && whoami && ipconfig && net user",
        )]);
        ReconIndicator.apply(&mut event);
        assert_eq!(event.get("hunt_recon"), Some("true"));
    }

    #[test]
    fn test_data_staging() {
        let mut event = make_event(&[(
            "CommandLine",
            r"7z a C:\Perflogs\data.7z C:\Users\admin\Documents\*",
        )]);
        DataStagingDetector.apply(&mut event);
        assert_eq!(event.get("hunt_staging_type"), Some("archive_7z"));
    }
}
