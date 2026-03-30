use crate::hunt::{levenshtein, set_hunt_finding, HuntSeverity};
use crate::model::Event;
use crate::transforms::Transform;
use std::sync::OnceLock;

// ── Process Typosquatting ──────────────────────────────────────────

const CRITICAL_PROCESSES: &[&str] = &[
    "svchost.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "spoolsv.exe",
    "conhost.exe",
    "dllhost.exe",
    "taskhost.exe",
    "taskhostw.exe",
    "RuntimeBroker.exe",
    "explorer.exe",
    "dwm.exe",
];

// Known legitimate executables that look similar but are NOT typosquatting
const TYPOSQUAT_WHITELIST: &[&str] = &[
    "svchost.exe",
    "svchostctl.exe",
    "svchost_2.exe",
    "lsass.exe",
    "csrss.exe",
    "smss.exe",
    "conhost.exe",
    "dllhost.exe",
    "explorer.exe",
    "iexplore.exe",
    "dllhst3g.exe",
    "taskhost.exe",
    "taskhostw.exe",
    "taskhostex.exe",
    "RuntimeBroker.exe",
    "wmiprvse.exe",
    "WmiPrvSE.exe",
    "consent.exe",
    "smartscreen.exe",
];

pub struct ProcessTyposquatting;

impl Transform for ProcessTyposquatting {
    fn name(&self) -> &str {
        "process_typosquatting"
    }

    fn apply(&self, event: &mut Event) {
        let image = match event.fields.get("Image") {
            Some(v) if !v.is_empty() => v.clone(),
            _ => return,
        };

        let exe_name = extract_filename(&image);
        if exe_name.is_empty() {
            return;
        }

        let exe_lower = exe_name.to_lowercase();

        // Skip if it's an exact match to a critical process
        if CRITICAL_PROCESSES
            .iter()
            .any(|p| p.to_lowercase() == exe_lower)
        {
            return;
        }

        // Skip if whitelisted
        if TYPOSQUAT_WHITELIST
            .iter()
            .any(|w| w.to_lowercase() == exe_lower)
        {
            return;
        }

        for target in CRITICAL_PROCESSES {
            let target_lower = target.to_lowercase();

            // Quick length check: skip if length difference > 2
            if exe_lower.len().abs_diff(target_lower.len()) > 2 {
                continue;
            }

            let dist = levenshtein(&exe_lower, &target_lower);
            let max_dist = if target_lower.len() <= 7 { 1 } else { 2 };

            if dist > 0 && dist <= max_dist {
                event
                    .fields
                    .insert("hunt_typosquat_match".into(), target.to_string());
                event
                    .fields
                    .insert("hunt_typosquat_distance".into(), dist.to_string());
                set_hunt_finding(
                    &mut event.fields,
                    "ProcessTyposquatting",
                    HuntSeverity::High,
                    &format!(
                        "{} is Levenshtein distance {} from {}",
                        exe_name, dist, target
                    ),
                );
                return;
            }

            // Homoglyph check: 0→o, 1→l, rn→m, vv→w
            let homoglyph_normalized = exe_lower
                .replace('0', "o")
                .replace('1', "l")
                .replace("rn", "m")
                .replace("vv", "w");
            if homoglyph_normalized == target_lower && homoglyph_normalized != exe_lower {
                event
                    .fields
                    .insert("hunt_typosquat_match".into(), target.to_string());
                event
                    .fields
                    .insert("hunt_typosquat_distance".into(), "0-homoglyph".into());
                set_hunt_finding(
                    &mut event.fields,
                    "ProcessTyposquatting",
                    HuntSeverity::High,
                    &format!("{} is homoglyph of {}", exe_name, target),
                );
                return;
            }
        }
    }
}

// ── Process Masquerade ─────────────────────────────────────────────

const EXPECTED_PATHS: &[(&str, &[&str])] = &[
    (
        "svchost.exe",
        &["\\windows\\system32\\", "\\windows\\syswow64\\"],
    ),
    ("lsass.exe", &["\\windows\\system32\\"]),
    ("csrss.exe", &["\\windows\\system32\\"]),
    ("smss.exe", &["\\windows\\system32\\"]),
    ("wininit.exe", &["\\windows\\system32\\"]),
    ("winlogon.exe", &["\\windows\\system32\\"]),
    ("services.exe", &["\\windows\\system32\\"]),
    ("spoolsv.exe", &["\\windows\\system32\\"]),
    ("explorer.exe", &["\\windows\\", "\\windows\\syswow64\\"]),
    (
        "dllhost.exe",
        &["\\windows\\system32\\", "\\windows\\syswow64\\"],
    ),
    ("conhost.exe", &["\\windows\\system32\\"]),
    ("dwm.exe", &["\\windows\\system32\\"]),
    ("taskhostw.exe", &["\\windows\\system32\\"]),
];

pub struct ProcessMasquerade;

impl Transform for ProcessMasquerade {
    fn name(&self) -> &str {
        "process_masquerade"
    }

    fn apply(&self, event: &mut Event) {
        let image = match event.fields.get("Image") {
            Some(v) if !v.is_empty() => v.clone(),
            _ => return,
        };

        let image_lower = image.to_lowercase().replace('/', "\\");
        let exe_name = extract_filename(&image_lower);

        for (expected_exe, expected_dirs) in EXPECTED_PATHS {
            if exe_name == *expected_exe {
                let in_expected_dir = expected_dirs.iter().any(|dir| image_lower.contains(dir));
                if !in_expected_dir {
                    event
                        .fields
                        .insert("hunt_masquerade_exe".into(), expected_exe.to_string());
                    event
                        .fields
                        .insert("hunt_masquerade_actual_path".into(), image.clone());
                    set_hunt_finding(
                        &mut event.fields,
                        "ProcessMasquerade",
                        HuntSeverity::Critical,
                        &format!("{} running from unexpected path: {}", expected_exe, image),
                    );
                }
                return;
            }
        }
    }
}

// ── Process Path Anomaly ───────────────────────────────────────────

const SUSPICIOUS_DIRS: &[(&str, &str)] = &[
    // More specific paths first to avoid early match
    ("\\appdata\\local\\temp\\", "USER_TEMP"),
    ("\\windows\\temp\\", "WINDOWS_TEMP"),
    ("\\$recycle.bin\\", "RECYCLE_BIN"),
    ("\\perflogs\\", "PERFLOGS"),
    ("\\users\\public\\", "PUBLIC_PROFILE"),
    ("\\downloads\\", "DOWNLOADS"),
    ("\\temp\\", "TEMP_DIR"),
    ("/dev/shm/", "DEV_SHM"),
    ("/var/tmp/", "VAR_TMP"),
    ("/tmp/", "LINUX_TMP"),
];

pub struct ProcessPathAnomaly;

impl Transform for ProcessPathAnomaly {
    fn name(&self) -> &str {
        "process_path_anomaly"
    }

    fn apply(&self, event: &mut Event) {
        let image = match event.fields.get("Image") {
            Some(v) if !v.is_empty() => v.clone(),
            _ => return,
        };

        let image_lower = image.to_lowercase();

        for (pattern, label) in SUSPICIOUS_DIRS {
            if image_lower.contains(pattern) {
                event
                    .fields
                    .insert("hunt_suspicious_path".into(), label.to_string());
                set_hunt_finding(
                    &mut event.fields,
                    "ProcessPathAnomaly",
                    HuntSeverity::Medium,
                    &format!("Executable in suspicious directory: {}", label),
                );
                return;
            }
        }
    }
}

// ── Double Extension ───────────────────────────────────────────────

pub struct DoubleExtension;

impl DoubleExtension {
    fn regex() -> &'static regex::Regex {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        RE.get_or_init(|| {
            regex::Regex::new(
                r"(?i)\.(doc|docx|pdf|txt|jpg|jpeg|png|gif|bmp|xls|xlsx|ppt|pptx|csv|rtf|odt)\.(exe|scr|bat|cmd|com|pif|vbs|vbe|js|jse|wsh|wsf|ps1|msi|dll|hta|cpl)$"
            ).unwrap()
        })
    }
}

impl Transform for DoubleExtension {
    fn name(&self) -> &str {
        "double_extension"
    }

    fn apply(&self, event: &mut Event) {
        for field_name in &["TargetFilename", "Image"] {
            let val = match event.fields.get(*field_name) {
                Some(v) => v.clone(),
                None => continue,
            };
            if let Some(m) = Self::regex().find(&val) {
                let matched = m.as_str().to_string();
                event
                    .fields
                    .insert("hunt_double_ext".into(), matched.clone());
                set_hunt_finding(
                    &mut event.fields,
                    "DoubleExtension",
                    HuntSeverity::High,
                    &format!("Double extension detected: {}", matched),
                );
                return;
            }
        }
    }
}

// ── Helper ─────────────────────────────────────────────────────────

fn extract_filename(path: &str) -> String {
    let normalized = path.replace('/', "\\");
    normalized.rsplit('\\').next().unwrap_or("").to_lowercase()
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
    fn test_typosquatting_svch0st() {
        let mut event = make_event(&[("Image", r"C:\Users\admin\svch0st.exe")]);
        ProcessTyposquatting.apply(&mut event);
        assert_eq!(event.get("hunt_typosquat_match"), Some("svchost.exe"));
    }

    #[test]
    fn test_typosquatting_exact_match_no_alert() {
        let mut event = make_event(&[("Image", r"C:\Windows\System32\svchost.exe")]);
        ProcessTyposquatting.apply(&mut event);
        assert!(event.get("hunt_typosquat_match").is_none());
    }

    #[test]
    fn test_masquerade_svchost_wrong_dir() {
        let mut event = make_event(&[("Image", r"C:\Temp\svchost.exe")]);
        ProcessMasquerade.apply(&mut event);
        assert_eq!(event.get("hunt_masquerade_exe"), Some("svchost.exe"));
    }

    #[test]
    fn test_masquerade_svchost_correct_dir() {
        let mut event = make_event(&[("Image", r"C:\Windows\System32\svchost.exe")]);
        ProcessMasquerade.apply(&mut event);
        assert!(event.get("hunt_masquerade_exe").is_none());
    }

    #[test]
    fn test_path_anomaly_temp() {
        let mut event = make_event(&[("Image", r"C:\Users\admin\AppData\Local\Temp\malware.exe")]);
        ProcessPathAnomaly.apply(&mut event);
        assert_eq!(event.get("hunt_suspicious_path"), Some("USER_TEMP"));
    }

    #[test]
    fn test_double_extension() {
        let mut event = make_event(&[("TargetFilename", r"C:\Users\admin\invoice.pdf.exe")]);
        DoubleExtension.apply(&mut event);
        assert!(event.get("hunt_double_ext").is_some());
    }

    #[test]
    fn test_double_extension_legitimate() {
        let mut event = make_event(&[("TargetFilename", r"C:\archive.tar.gz")]);
        DoubleExtension.apply(&mut event);
        assert!(event.get("hunt_double_ext").is_none());
    }
}
