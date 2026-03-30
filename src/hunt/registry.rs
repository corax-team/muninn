use crate::hunt::{set_hunt_finding, HuntSeverity};
use crate::model::Event;
use crate::transforms::Transform;

const SUSPICIOUS_REGISTRY_PATHS: &[(&str, &str, HuntSeverity)] = &[
    ("\\currentversion\\run\\", "RUN_KEY", HuntSeverity::Medium),
    (
        "\\currentversion\\runonce\\",
        "RUNONCE_KEY",
        HuntSeverity::Medium,
    ),
    (
        "\\currentversion\\runservices\\",
        "RUNSERVICES_KEY",
        HuntSeverity::Medium,
    ),
    (
        "\\image file execution options\\",
        "IFEO",
        HuntSeverity::High,
    ),
    ("\\appinit_dlls", "APPINIT_DLLS", HuntSeverity::High),
    ("\\inprocserver32", "COM_HIJACK", HuntSeverity::Medium),
    ("\\winlogon\\shell", "WINLOGON_SHELL", HuntSeverity::High),
    (
        "\\winlogon\\userinit",
        "WINLOGON_USERINIT",
        HuntSeverity::High,
    ),
    (
        "\\policies\\explorer\\run",
        "POLICY_RUN",
        HuntSeverity::Medium,
    ),
    (
        "\\policies\\system\\",
        "SECURITY_POLICY",
        HuntSeverity::Medium,
    ),
    ("\\silentprocessexit\\", "SILENT_EXIT", HuntSeverity::High),
    ("\\globalflag", "GLOBAL_FLAG", HuntSeverity::High),
    (
        "\\environment\\userinitmprlogonscript",
        "LOGON_SCRIPT",
        HuntSeverity::High,
    ),
    (
        "\\currentversion\\explorer\\shell folders",
        "SHELL_FOLDERS",
        HuntSeverity::Medium,
    ),
];

pub struct SuspiciousRegistryPath;

impl Transform for SuspiciousRegistryPath {
    fn name(&self) -> &str {
        "suspicious_registry_path"
    }

    fn apply(&self, event: &mut Event) {
        let target = match event
            .fields
            .get("TargetObject")
            .or_else(|| event.fields.get("ObjectName"))
        {
            Some(v) if !v.is_empty() => v.clone(),
            _ => return,
        };

        let target_lower = target.to_lowercase();

        for (pattern, label, severity) in SUSPICIOUS_REGISTRY_PATHS {
            if target_lower.contains(pattern) {
                event
                    .fields
                    .insert("hunt_reg_suspicious".into(), label.to_string());
                set_hunt_finding(
                    &mut event.fields,
                    "SuspiciousRegistryPath",
                    *severity,
                    &format!("Suspicious registry path: {}", label),
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
    fn test_run_key() {
        let mut event = make_event(&[(
            "TargetObject",
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Malware",
        )]);
        SuspiciousRegistryPath.apply(&mut event);
        assert_eq!(event.get("hunt_reg_suspicious"), Some("RUN_KEY"));
    }

    #[test]
    fn test_ifeo() {
        let mut event = make_event(&[(
            "TargetObject",
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe\Debugger",
        )]);
        SuspiciousRegistryPath.apply(&mut event);
        assert_eq!(event.get("hunt_reg_suspicious"), Some("IFEO"));
    }
}
