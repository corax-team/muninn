use crate::hunt::{set_hunt_finding, HuntSeverity};
use crate::model::Event;
use crate::transforms::Transform;

const OFFICE_PROCESSES: &[&str] = &[
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "msaccess.exe",
    "onenote.exe",
    "mspub.exe",
    "visio.exe",
];

const BROWSER_PROCESSES: &[&str] = &[
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "iexplore.exe",
    "brave.exe",
    "opera.exe",
];

const PDF_PROCESSES: &[&str] = &[
    "acrobat.exe",
    "acrord32.exe",
    "foxitreader.exe",
    "foxitphantom.exe",
    "sumatrapdf.exe",
];

const SUSPICIOUS_CHILDREN: &[&str] = &[
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
    "bitsadmin.exe",
];

pub struct ParentProcessAnomaly;

impl Transform for ParentProcessAnomaly {
    fn name(&self) -> &str {
        "parent_process_anomaly"
    }

    fn apply(&self, event: &mut Event) {
        let parent = match event.fields.get("ParentImage") {
            Some(v) if !v.is_empty() => v.clone(),
            _ => return,
        };
        let child = match event.fields.get("Image") {
            Some(v) if !v.is_empty() => v.clone(),
            _ => return,
        };

        let parent_lower = parent.to_lowercase();
        let child_lower = child.to_lowercase();

        let parent_exe = parent_lower.rsplit('\\').next().unwrap_or("");
        let child_exe = child_lower.rsplit('\\').next().unwrap_or("");

        // Check if child is a suspicious scripting engine
        if !SUSPICIOUS_CHILDREN.contains(&child_exe) {
            return;
        }

        let anomaly_type = if OFFICE_PROCESSES.contains(&parent_exe) {
            "OFFICE_SPAWN"
        } else if BROWSER_PROCESSES.contains(&parent_exe) {
            "BROWSER_SPAWN"
        } else if PDF_PROCESSES.contains(&parent_exe) {
            "PDF_SPAWN"
        } else if parent_exe == "java.exe" || parent_exe == "javaw.exe" {
            "JAVA_SPAWN"
        } else if parent_exe == "wmiprvse.exe" {
            "WMI_SPAWN"
        } else {
            return;
        };

        event
            .fields
            .insert("hunt_parent_anomaly".into(), anomaly_type.into());
        set_hunt_finding(
            &mut event.fields,
            "ParentProcessAnomaly",
            HuntSeverity::High,
            &format!("{}: {} spawned {}", anomaly_type, parent_exe, child_exe),
        );
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
    fn test_office_spawn() {
        let mut event = make_event(&[
            (
                "ParentImage",
                r"C:\Program Files\Microsoft Office\WINWORD.EXE",
            ),
            ("Image", r"C:\Windows\System32\cmd.exe"),
        ]);
        ParentProcessAnomaly.apply(&mut event);
        assert_eq!(event.get("hunt_parent_anomaly"), Some("OFFICE_SPAWN"));
    }

    #[test]
    fn test_browser_spawn() {
        let mut event = make_event(&[
            ("ParentImage", r"C:\Program Files\Google\Chrome\chrome.exe"),
            ("Image", r"C:\Windows\System32\powershell.exe"),
        ]);
        ParentProcessAnomaly.apply(&mut event);
        assert_eq!(event.get("hunt_parent_anomaly"), Some("BROWSER_SPAWN"));
    }

    #[test]
    fn test_normal_parent_no_alert() {
        let mut event = make_event(&[
            ("ParentImage", r"C:\Windows\explorer.exe"),
            ("Image", r"C:\Windows\System32\cmd.exe"),
        ]);
        ParentProcessAnomaly.apply(&mut event);
        assert!(event.get("hunt_parent_anomaly").is_none());
    }
}
