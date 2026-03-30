use crate::hunt::{set_hunt_finding, HuntSeverity};
use crate::model::Event;
use crate::transforms::Transform;

const SENSITIVE_PATTERNS: &[(&str, &str, HuntSeverity)] = &[
    // Windows credential stores
    (
        "\\config\\sam",
        "CREDENTIAL_HIVE_SAM",
        HuntSeverity::Critical,
    ),
    (
        "\\config\\system",
        "CREDENTIAL_HIVE_SYSTEM",
        HuntSeverity::Critical,
    ),
    (
        "\\config\\security",
        "CREDENTIAL_HIVE_SECURITY",
        HuntSeverity::Critical,
    ),
    ("ntds.dit", "AD_DATABASE", HuntSeverity::Critical),
    ("lsass.dmp", "LSASS_DUMP", HuntSeverity::Critical),
    ("lsass.zip", "LSASS_DUMP", HuntSeverity::Critical),
    ("procdump", "PROCDUMP_TOOL", HuntSeverity::High),
    // Linux credential stores
    ("/etc/shadow", "LINUX_SHADOW", HuntSeverity::Critical),
    ("/etc/passwd", "LINUX_PASSWD", HuntSeverity::Medium),
    // SSH keys
    ("id_rsa", "SSH_PRIVATE_KEY", HuntSeverity::High),
    ("id_ed25519", "SSH_PRIVATE_KEY", HuntSeverity::High),
    ("id_ecdsa", "SSH_PRIVATE_KEY", HuntSeverity::High),
    (
        "authorized_keys",
        "SSH_AUTHORIZED_KEYS",
        HuntSeverity::Medium,
    ),
    // Browser credentials
    ("login data", "BROWSER_CREDS", HuntSeverity::High),
    ("cookies", "BROWSER_COOKIES", HuntSeverity::Medium),
    ("key3.db", "FIREFOX_KEY_DB", HuntSeverity::High),
    ("key4.db", "FIREFOX_KEY_DB", HuntSeverity::High),
    ("logins.json", "FIREFOX_LOGINS", HuntSeverity::High),
    // Password managers
    (".kdbx", "KEEPASS_DB", HuntSeverity::High),
    (".kdb", "KEEPASS_DB", HuntSeverity::High),
    // Certificates and keys
    (".pfx", "CERTIFICATE_PFX", HuntSeverity::High),
    (".p12", "CERTIFICATE_P12", HuntSeverity::High),
    (".pem", "PRIVATE_KEY_PEM", HuntSeverity::Medium),
    (".key", "PRIVATE_KEY", HuntSeverity::Medium),
    // Config files with secrets
    (".env", "DOTENV_FILE", HuntSeverity::Medium),
    ("web.config", "WEB_CONFIG", HuntSeverity::Medium),
    ("wp-config.php", "WORDPRESS_CONFIG", HuntSeverity::Medium),
    (".git-credentials", "GIT_CREDENTIALS", HuntSeverity::High),
    (".aws/credentials", "AWS_CREDENTIALS", HuntSeverity::High),
];

pub struct SensitiveFileAccess;

impl Transform for SensitiveFileAccess {
    fn name(&self) -> &str {
        "sensitive_file_access"
    }

    fn apply(&self, event: &mut Event) {
        for field_name in &["TargetFilename", "ObjectName", "CommandLine"] {
            let val = match event.fields.get(*field_name) {
                Some(v) if !v.is_empty() => v.clone(),
                _ => continue,
            };

            let val_lower = val.to_lowercase();

            for (pattern, label, severity) in SENSITIVE_PATTERNS {
                if val_lower.contains(pattern) {
                    event
                        .fields
                        .insert("hunt_sensitive_file".into(), label.to_string());
                    set_hunt_finding(
                        &mut event.fields,
                        "SensitiveFileAccess",
                        *severity,
                        &format!("Access to sensitive file: {}", label),
                    );
                    return;
                }
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
    fn test_sam_hive() {
        let mut event = make_event(&[("TargetFilename", r"C:\Windows\System32\config\SAM")]);
        SensitiveFileAccess.apply(&mut event);
        assert_eq!(
            event.get("hunt_sensitive_file"),
            Some("CREDENTIAL_HIVE_SAM")
        );
    }

    #[test]
    fn test_ssh_key() {
        let mut event = make_event(&[("CommandLine", "cat /home/user/.ssh/id_rsa")]);
        SensitiveFileAccess.apply(&mut event);
        assert_eq!(event.get("hunt_sensitive_file"), Some("SSH_PRIVATE_KEY"));
    }

    #[test]
    fn test_ntds_dit() {
        let mut event = make_event(&[("TargetFilename", r"C:\Windows\NTDS\ntds.dit")]);
        SensitiveFileAccess.apply(&mut event);
        assert_eq!(event.get("hunt_sensitive_file"), Some("AD_DATABASE"));
    }
}
