use serde::Serialize;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize)]
pub struct Technique {
    pub id: String,
    pub name: String,
    pub tactic: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MitreRef {
    pub technique_id: Option<String>,
    pub tactic: Option<String>,
}

pub const TACTIC_ORDER: &[&str] = &[
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
];

pub const TACTIC_DISPLAY: &[(&str, &str)] = &[
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
];

pub struct MitreMapper {
    techniques: HashMap<String, Technique>,
}

impl Default for MitreMapper {
    fn default() -> Self {
        Self::new()
    }
}

impl MitreMapper {
    pub fn new() -> Self {
        let mut techniques = HashMap::new();
        let entries: &[(&str, &str, &str)] = &[
            // ── Reconnaissance ──────────────────────────────────────
            ("T1595", "Active Scanning", "reconnaissance"),
            ("T1595.001", "Scanning IP Blocks", "reconnaissance"),
            ("T1595.002", "Vulnerability Scanning", "reconnaissance"),
            ("T1595.003", "Wordlist Scanning", "reconnaissance"),
            (
                "T1589",
                "Gather Victim Identity Information",
                "reconnaissance",
            ),
            ("T1589.001", "Credentials", "reconnaissance"),
            ("T1589.002", "Email Addresses", "reconnaissance"),
            ("T1589.003", "Employee Names", "reconnaissance"),
            (
                "T1590",
                "Gather Victim Network Information",
                "reconnaissance",
            ),
            ("T1590.001", "Domain Properties", "reconnaissance"),
            ("T1590.002", "DNS", "reconnaissance"),
            ("T1590.004", "Network Topology", "reconnaissance"),
            ("T1590.005", "IP Addresses", "reconnaissance"),
            ("T1590.006", "Network Security Appliances", "reconnaissance"),
            ("T1592", "Gather Victim Host Information", "reconnaissance"),
            ("T1592.001", "Hardware", "reconnaissance"),
            ("T1592.002", "Software", "reconnaissance"),
            ("T1592.004", "Client Configurations", "reconnaissance"),
            ("T1598", "Phishing for Information", "reconnaissance"),
            ("T1598.001", "Spearphishing Service", "reconnaissance"),
            ("T1598.002", "Spearphishing Attachment", "reconnaissance"),
            ("T1598.003", "Spearphishing Link", "reconnaissance"),
            ("T1593", "Search Open Websites/Domains", "reconnaissance"),
            ("T1594", "Search Victim-Owned Websites", "reconnaissance"),
            ("T1596", "Search Open Technical Databases", "reconnaissance"),
            ("T1597", "Search Closed Sources", "reconnaissance"),
            // ── Resource Development ────────────────────────────────
            ("T1583", "Acquire Infrastructure", "resource-development"),
            ("T1583.001", "Domains", "resource-development"),
            (
                "T1583.003",
                "Virtual Private Server",
                "resource-development",
            ),
            ("T1583.006", "Web Services", "resource-development"),
            ("T1584", "Compromise Infrastructure", "resource-development"),
            ("T1585", "Establish Accounts", "resource-development"),
            ("T1585.001", "Social Media Accounts", "resource-development"),
            ("T1585.002", "Email Accounts", "resource-development"),
            ("T1586", "Compromise Accounts", "resource-development"),
            ("T1587", "Develop Capabilities", "resource-development"),
            ("T1587.001", "Malware", "resource-development"),
            ("T1587.003", "Digital Certificates", "resource-development"),
            ("T1587.004", "Exploits", "resource-development"),
            ("T1588", "Obtain Capabilities", "resource-development"),
            ("T1588.001", "Malware", "resource-development"),
            ("T1588.002", "Tool", "resource-development"),
            (
                "T1588.003",
                "Code Signing Certificates",
                "resource-development",
            ),
            ("T1588.005", "Exploits", "resource-development"),
            ("T1588.006", "Vulnerabilities", "resource-development"),
            ("T1608", "Stage Capabilities", "resource-development"),
            ("T1608.001", "Upload Malware", "resource-development"),
            ("T1608.002", "Upload Tool", "resource-development"),
            (
                "T1608.003",
                "Install Digital Certificate",
                "resource-development",
            ),
            ("T1608.005", "Link Target", "resource-development"),
            // ── Initial Access ──────────────────────────────────────
            (
                "T1190",
                "Exploit Public-Facing Application",
                "initial-access",
            ),
            ("T1133", "External Remote Services", "initial-access"),
            ("T1566", "Phishing", "initial-access"),
            ("T1566.001", "Spearphishing Attachment", "initial-access"),
            ("T1566.002", "Spearphishing Link", "initial-access"),
            ("T1566.003", "Spearphishing via Service", "initial-access"),
            ("T1078", "Valid Accounts", "initial-access"),
            ("T1078.001", "Default Accounts", "initial-access"),
            ("T1078.002", "Domain Accounts", "initial-access"),
            ("T1078.003", "Local Accounts", "initial-access"),
            ("T1078.004", "Cloud Accounts", "initial-access"),
            ("T1195", "Supply Chain Compromise", "initial-access"),
            (
                "T1195.001",
                "Compromise Software Dependencies and Development Tools",
                "initial-access",
            ),
            (
                "T1195.002",
                "Compromise Software Supply Chain",
                "initial-access",
            ),
            ("T1199", "Trusted Relationship", "initial-access"),
            (
                "T1091",
                "Replication Through Removable Media",
                "initial-access",
            ),
            ("T1189", "Drive-by Compromise", "initial-access"),
            ("T1200", "Hardware Additions", "initial-access"),
            // ── Execution ───────────────────────────────────────────
            ("T1059", "Command and Scripting Interpreter", "execution"),
            ("T1059.001", "PowerShell", "execution"),
            ("T1059.002", "AppleScript", "execution"),
            ("T1059.003", "Windows Command Shell", "execution"),
            ("T1059.004", "Unix Shell", "execution"),
            ("T1059.005", "Visual Basic", "execution"),
            ("T1059.006", "Python", "execution"),
            ("T1059.007", "JavaScript", "execution"),
            ("T1059.008", "Network Device CLI", "execution"),
            ("T1047", "Windows Management Instrumentation", "execution"),
            ("T1053", "Scheduled Task/Job", "execution"),
            ("T1053.002", "At", "execution"),
            ("T1053.003", "Cron", "execution"),
            ("T1053.005", "Scheduled Task", "execution"),
            ("T1569", "System Services", "execution"),
            ("T1569.001", "Launchctl", "execution"),
            ("T1569.002", "Service Execution", "execution"),
            ("T1204", "User Execution", "execution"),
            ("T1204.001", "Malicious Link", "execution"),
            ("T1204.002", "Malicious File", "execution"),
            ("T1106", "Native API", "execution"),
            ("T1129", "Shared Modules", "execution"),
            ("T1203", "Exploitation for Client Execution", "execution"),
            ("T1559", "Inter-Process Communication", "execution"),
            ("T1559.001", "Component Object Model", "execution"),
            ("T1559.002", "Dynamic Data Exchange", "execution"),
            // ── Persistence ─────────────────────────────────────────
            ("T1547", "Boot or Logon Autostart Execution", "persistence"),
            (
                "T1547.001",
                "Registry Run Keys / Startup Folder",
                "persistence",
            ),
            ("T1547.002", "Authentication Package", "persistence"),
            ("T1547.004", "Winlogon Helper DLL", "persistence"),
            ("T1547.005", "Security Support Provider", "persistence"),
            ("T1547.009", "Shortcut Modification", "persistence"),
            ("T1547.010", "Port Monitors", "persistence"),
            ("T1547.012", "Print Processors", "persistence"),
            ("T1547.014", "Active Setup", "persistence"),
            ("T1543", "Create or Modify System Process", "persistence"),
            ("T1543.002", "Systemd Service", "persistence"),
            ("T1543.003", "Windows Service", "persistence"),
            ("T1136", "Create Account", "persistence"),
            ("T1136.001", "Local Account", "persistence"),
            ("T1136.002", "Domain Account", "persistence"),
            ("T1136.003", "Cloud Account", "persistence"),
            ("T1098", "Account Manipulation", "persistence"),
            ("T1098.001", "Additional Cloud Credentials", "persistence"),
            (
                "T1098.002",
                "Additional Email Delegate Permissions",
                "persistence",
            ),
            ("T1098.004", "SSH Authorized Keys", "persistence"),
            ("T1197", "BITS Jobs", "persistence"),
            ("T1546", "Event Triggered Execution", "persistence"),
            (
                "T1546.001",
                "Change Default File Association",
                "persistence",
            ),
            ("T1546.002", "Screensaver", "persistence"),
            ("T1546.003", "WMI Event Subscription", "persistence"),
            ("T1546.008", "Accessibility Features", "persistence"),
            ("T1546.010", "AppInit DLLs", "persistence"),
            ("T1546.011", "Application Shimming", "persistence"),
            (
                "T1546.012",
                "Image File Execution Options Injection",
                "persistence",
            ),
            ("T1546.013", "PowerShell Profile", "persistence"),
            (
                "T1546.015",
                "Component Object Model Hijacking",
                "persistence",
            ),
            ("T1574", "Hijack Execution Flow", "persistence"),
            ("T1574.001", "DLL Search Order Hijacking", "persistence"),
            ("T1574.002", "DLL Side-Loading", "persistence"),
            ("T1574.006", "Dynamic Linker Hijacking", "persistence"),
            (
                "T1574.008",
                "Path Interception by Search Order Hijacking",
                "persistence",
            ),
            (
                "T1574.009",
                "Path Interception by Unquoted Path",
                "persistence",
            ),
            (
                "T1574.011",
                "Services Registry Permissions Weakness",
                "persistence",
            ),
            ("T1574.012", "COR_PROFILER", "persistence"),
            ("T1505", "Server Software Component", "persistence"),
            ("T1505.003", "Web Shell", "persistence"),
            ("T1505.004", "IIS Components", "persistence"),
            ("T1133", "External Remote Services", "persistence"),
            ("T1137", "Office Application Startup", "persistence"),
            ("T1137.001", "Office Template Macros", "persistence"),
            ("T1542", "Pre-OS Boot", "persistence"),
            ("T1542.003", "Bootkit", "persistence"),
            ("T1053.005", "Scheduled Task", "persistence"),
            ("T1176", "Browser Extensions", "persistence"),
            // ── Privilege Escalation ────────────────────────────────
            (
                "T1548",
                "Abuse Elevation Control Mechanism",
                "privilege-escalation",
            ),
            ("T1548.001", "Setuid and Setgid", "privilege-escalation"),
            (
                "T1548.002",
                "Bypass User Account Control",
                "privilege-escalation",
            ),
            ("T1548.003", "Sudo and Sudo Caching", "privilege-escalation"),
            (
                "T1548.004",
                "Elevated Execution with Prompt",
                "privilege-escalation",
            ),
            ("T1134", "Access Token Manipulation", "privilege-escalation"),
            (
                "T1134.001",
                "Token Impersonation/Theft",
                "privilege-escalation",
            ),
            (
                "T1134.002",
                "Create Process with Token",
                "privilege-escalation",
            ),
            (
                "T1134.003",
                "Make and Impersonate Token",
                "privilege-escalation",
            ),
            ("T1134.004", "Parent PID Spoofing", "privilege-escalation"),
            (
                "T1068",
                "Exploitation for Privilege Escalation",
                "privilege-escalation",
            ),
            ("T1055", "Process Injection", "privilege-escalation"),
            (
                "T1055.001",
                "Dynamic-link Library Injection",
                "privilege-escalation",
            ),
            (
                "T1055.002",
                "Portable Executable Injection",
                "privilege-escalation",
            ),
            (
                "T1055.003",
                "Thread Execution Hijacking",
                "privilege-escalation",
            ),
            (
                "T1055.004",
                "Asynchronous Procedure Call",
                "privilege-escalation",
            ),
            ("T1055.008", "Ptrace System Calls", "privilege-escalation"),
            ("T1055.012", "Process Hollowing", "privilege-escalation"),
            // ── Defense Evasion ─────────────────────────────────────
            (
                "T1027",
                "Obfuscated Files or Information",
                "defense-evasion",
            ),
            ("T1027.001", "Binary Padding", "defense-evasion"),
            ("T1027.002", "Software Packing", "defense-evasion"),
            ("T1027.003", "Steganography", "defense-evasion"),
            ("T1027.004", "Compile After Delivery", "defense-evasion"),
            (
                "T1027.005",
                "Indicator Removal from Tools",
                "defense-evasion",
            ),
            ("T1027.006", "HTML Smuggling", "defense-evasion"),
            ("T1027.010", "Command Obfuscation", "defense-evasion"),
            ("T1027.011", "Fileless Storage", "defense-evasion"),
            ("T1036", "Masquerading", "defense-evasion"),
            ("T1036.001", "Invalid Code Signature", "defense-evasion"),
            ("T1036.003", "Rename System Utilities", "defense-evasion"),
            ("T1036.004", "Masquerade Task or Service", "defense-evasion"),
            (
                "T1036.005",
                "Match Legitimate Name or Location",
                "defense-evasion",
            ),
            ("T1036.006", "Space after Filename", "defense-evasion"),
            ("T1036.007", "Double File Extension", "defense-evasion"),
            ("T1036.008", "Masquerade File Type", "defense-evasion"),
            ("T1070", "Indicator Removal", "defense-evasion"),
            ("T1070.001", "Clear Windows Event Logs", "defense-evasion"),
            (
                "T1070.002",
                "Clear Linux or Mac System Logs",
                "defense-evasion",
            ),
            ("T1070.003", "Clear Command History", "defense-evasion"),
            ("T1070.004", "File Deletion", "defense-evasion"),
            (
                "T1070.005",
                "Network Share Connection Removal",
                "defense-evasion",
            ),
            ("T1070.006", "Timestomp", "defense-evasion"),
            ("T1070.009", "Clear Persistence", "defense-evasion"),
            ("T1112", "Modify Registry", "defense-evasion"),
            (
                "T1140",
                "Deobfuscate/Decode Files or Information",
                "defense-evasion",
            ),
            ("T1218", "System Binary Proxy Execution", "defense-evasion"),
            ("T1218.001", "Compiled HTML File", "defense-evasion"),
            ("T1218.002", "Control Panel", "defense-evasion"),
            ("T1218.003", "CMSTP", "defense-evasion"),
            ("T1218.004", "InstallUtil", "defense-evasion"),
            ("T1218.005", "Mshta", "defense-evasion"),
            ("T1218.007", "Msiexec", "defense-evasion"),
            ("T1218.008", "Odbcconf", "defense-evasion"),
            ("T1218.009", "Regsvcs/Regasm", "defense-evasion"),
            ("T1218.010", "Regsvr32", "defense-evasion"),
            ("T1218.011", "Rundll32", "defense-evasion"),
            ("T1218.012", "Verclsid", "defense-evasion"),
            ("T1218.013", "Mavinject", "defense-evasion"),
            ("T1218.014", "MMC", "defense-evasion"),
            ("T1055", "Process Injection", "defense-evasion"),
            (
                "T1055.001",
                "Dynamic-link Library Injection",
                "defense-evasion",
            ),
            (
                "T1055.002",
                "Portable Executable Injection",
                "defense-evasion",
            ),
            ("T1055.003", "Thread Execution Hijacking", "defense-evasion"),
            ("T1055.012", "Process Hollowing", "defense-evasion"),
            ("T1562", "Impair Defenses", "defense-evasion"),
            ("T1562.001", "Disable or Modify Tools", "defense-evasion"),
            (
                "T1562.002",
                "Disable Windows Event Logging",
                "defense-evasion",
            ),
            (
                "T1562.003",
                "Impair Command History Logging",
                "defense-evasion",
            ),
            (
                "T1562.004",
                "Disable or Modify System Firewall",
                "defense-evasion",
            ),
            ("T1562.006", "Indicator Blocking", "defense-evasion"),
            (
                "T1562.007",
                "Disable or Modify Cloud Firewall",
                "defense-evasion",
            ),
            (
                "T1562.008",
                "Disable or Modify Cloud Logs",
                "defense-evasion",
            ),
            ("T1564", "Hide Artifacts", "defense-evasion"),
            (
                "T1564.001",
                "Hidden Files and Directories",
                "defense-evasion",
            ),
            ("T1564.002", "Hidden Users", "defense-evasion"),
            ("T1564.003", "Hidden Window", "defense-evasion"),
            ("T1564.004", "NTFS File Attributes", "defense-evasion"),
            ("T1564.006", "Run Virtual Instance", "defense-evasion"),
            ("T1564.010", "Process Argument Spoofing", "defense-evasion"),
            ("T1497", "Virtualization/Sandbox Evasion", "defense-evasion"),
            ("T1497.001", "System Checks", "defense-evasion"),
            ("T1497.003", "Time Based Evasion", "defense-evasion"),
            ("T1480", "Execution Guardrails", "defense-evasion"),
            ("T1480.001", "Environmental Keying", "defense-evasion"),
            ("T1202", "Indirect Command Execution", "defense-evasion"),
            ("T1220", "XSL Script Processing", "defense-evasion"),
            ("T1221", "Template Injection", "defense-evasion"),
            ("T1553", "Subvert Trust Controls", "defense-evasion"),
            ("T1553.001", "Gatekeeper Bypass", "defense-evasion"),
            ("T1553.002", "Code Signing", "defense-evasion"),
            ("T1553.004", "Install Root Certificate", "defense-evasion"),
            ("T1553.005", "Mark-of-the-Web Bypass", "defense-evasion"),
            (
                "T1553.006",
                "Code Signing Policy Modification",
                "defense-evasion",
            ),
            ("T1006", "Direct Volume Access", "defense-evasion"),
            ("T1014", "Rootkit", "defense-evasion"),
            (
                "T1127",
                "Trusted Developer Utilities Proxy Execution",
                "defense-evasion",
            ),
            ("T1127.001", "MSBuild", "defense-evasion"),
            ("T1197", "BITS Jobs", "defense-evasion"),
            ("T1207", "Rogue Domain Controller", "defense-evasion"),
            (
                "T1222",
                "File and Directory Permissions Modification",
                "defense-evasion",
            ),
            (
                "T1222.001",
                "Windows File and Directory Permissions Modification",
                "defense-evasion",
            ),
            (
                "T1222.002",
                "Linux and Mac File and Directory Permissions Modification",
                "defense-evasion",
            ),
            (
                "T1550",
                "Use Alternate Authentication Material",
                "defense-evasion",
            ),
            ("T1550.001", "Application Access Token", "defense-evasion"),
            ("T1550.002", "Pass the Hash", "defense-evasion"),
            ("T1550.003", "Pass the Ticket", "defense-evasion"),
            ("T1556", "Modify Authentication Process", "defense-evasion"),
            (
                "T1556.001",
                "Domain Controller Authentication",
                "defense-evasion",
            ),
            (
                "T1578",
                "Modify Cloud Compute Infrastructure",
                "defense-evasion",
            ),
            ("T1600", "Weaken Encryption", "defense-evasion"),
            ("T1601", "Modify System Image", "defense-evasion"),
            ("T1620", "Reflective Code Loading", "defense-evasion"),
            // ── Credential Access ───────────────────────────────────
            ("T1003", "OS Credential Dumping", "credential-access"),
            ("T1003.001", "LSASS Memory", "credential-access"),
            ("T1003.002", "Security Account Manager", "credential-access"),
            ("T1003.003", "NTDS", "credential-access"),
            ("T1003.004", "LSA Secrets", "credential-access"),
            (
                "T1003.005",
                "Cached Domain Credentials",
                "credential-access",
            ),
            ("T1003.006", "DCSync", "credential-access"),
            ("T1003.007", "Proc Filesystem", "credential-access"),
            (
                "T1003.008",
                "/etc/passwd and /etc/shadow",
                "credential-access",
            ),
            ("T1110", "Brute Force", "credential-access"),
            ("T1110.001", "Password Guessing", "credential-access"),
            ("T1110.002", "Password Cracking", "credential-access"),
            ("T1110.003", "Password Spraying", "credential-access"),
            ("T1110.004", "Credential Stuffing", "credential-access"),
            (
                "T1558",
                "Steal or Forge Kerberos Tickets",
                "credential-access",
            ),
            ("T1558.001", "Golden Ticket", "credential-access"),
            ("T1558.002", "Silver Ticket", "credential-access"),
            ("T1558.003", "Kerberoasting", "credential-access"),
            ("T1558.004", "AS-REP Roasting", "credential-access"),
            ("T1552", "Unsecured Credentials", "credential-access"),
            ("T1552.001", "Credentials In Files", "credential-access"),
            ("T1552.002", "Credentials in Registry", "credential-access"),
            ("T1552.003", "Bash History", "credential-access"),
            ("T1552.004", "Private Keys", "credential-access"),
            ("T1552.006", "Group Policy Preferences", "credential-access"),
            (
                "T1555",
                "Credentials from Password Stores",
                "credential-access",
            ),
            ("T1555.001", "Keychain", "credential-access"),
            (
                "T1555.003",
                "Credentials from Web Browsers",
                "credential-access",
            ),
            (
                "T1555.004",
                "Windows Credential Manager",
                "credential-access",
            ),
            ("T1555.005", "Password Managers", "credential-access"),
            (
                "T1556",
                "Modify Authentication Process",
                "credential-access",
            ),
            (
                "T1556.001",
                "Domain Controller Authentication",
                "credential-access",
            ),
            ("T1556.002", "Password Filter DLL", "credential-access"),
            (
                "T1556.003",
                "Pluggable Authentication Modules",
                "credential-access",
            ),
            ("T1557", "Adversary-in-the-Middle", "credential-access"),
            (
                "T1557.001",
                "LLMNR/NBT-NS Poisoning and SMB Relay",
                "credential-access",
            ),
            ("T1557.002", "ARP Cache Poisoning", "credential-access"),
            ("T1539", "Steal Web Session Cookie", "credential-access"),
            (
                "T1528",
                "Steal Application Access Token",
                "credential-access",
            ),
            (
                "T1649",
                "Steal or Forge Authentication Certificates",
                "credential-access",
            ),
            ("T1187", "Forced Authentication", "credential-access"),
            ("T1056", "Input Capture", "credential-access"),
            ("T1056.001", "Keylogging", "credential-access"),
            ("T1056.002", "GUI Input Capture", "credential-access"),
            ("T1056.004", "Credential API Hooking", "credential-access"),
            ("T1040", "Network Sniffing", "credential-access"),
            (
                "T1621",
                "Multi-Factor Authentication Request Generation",
                "credential-access",
            ),
            (
                "T1111",
                "Multi-Factor Authentication Interception",
                "credential-access",
            ),
            // ── Discovery ───────────────────────────────────────────
            ("T1087", "Account Discovery", "discovery"),
            ("T1087.001", "Local Account", "discovery"),
            ("T1087.002", "Domain Account", "discovery"),
            ("T1087.003", "Email Account", "discovery"),
            ("T1087.004", "Cloud Account", "discovery"),
            ("T1482", "Domain Trust Discovery", "discovery"),
            ("T1083", "File and Directory Discovery", "discovery"),
            ("T1135", "Network Share Discovery", "discovery"),
            ("T1069", "Permission Groups Discovery", "discovery"),
            ("T1069.001", "Local Groups", "discovery"),
            ("T1069.002", "Domain Groups", "discovery"),
            ("T1069.003", "Cloud Groups", "discovery"),
            ("T1057", "Process Discovery", "discovery"),
            ("T1012", "Query Registry", "discovery"),
            ("T1018", "Remote System Discovery", "discovery"),
            ("T1518", "Software Discovery", "discovery"),
            ("T1518.001", "Security Software Discovery", "discovery"),
            ("T1082", "System Information Discovery", "discovery"),
            (
                "T1016",
                "System Network Configuration Discovery",
                "discovery",
            ),
            ("T1016.001", "Internet Connection Discovery", "discovery"),
            ("T1049", "System Network Connections Discovery", "discovery"),
            ("T1033", "System Owner/User Discovery", "discovery"),
            ("T1007", "System Service Discovery", "discovery"),
            ("T1124", "System Time Discovery", "discovery"),
            ("T1497", "Virtualization/Sandbox Evasion", "discovery"),
            ("T1497.001", "System Checks", "discovery"),
            ("T1010", "Application Window Discovery", "discovery"),
            ("T1046", "Network Service Discovery", "discovery"),
            ("T1201", "Password Policy Discovery", "discovery"),
            ("T1120", "Peripheral Device Discovery", "discovery"),
            ("T1580", "Cloud Infrastructure Discovery", "discovery"),
            ("T1538", "Cloud Service Dashboard", "discovery"),
            ("T1526", "Cloud Service Discovery", "discovery"),
            // ── Lateral Movement ────────────────────────────────────
            ("T1021", "Remote Services", "lateral-movement"),
            ("T1021.001", "Remote Desktop Protocol", "lateral-movement"),
            ("T1021.002", "SMB/Windows Admin Shares", "lateral-movement"),
            (
                "T1021.003",
                "Distributed Component Object Model",
                "lateral-movement",
            ),
            ("T1021.004", "SSH", "lateral-movement"),
            ("T1021.005", "VNC", "lateral-movement"),
            ("T1021.006", "Windows Remote Management", "lateral-movement"),
            ("T1570", "Lateral Tool Transfer", "lateral-movement"),
            (
                "T1550",
                "Use Alternate Authentication Material",
                "lateral-movement",
            ),
            ("T1550.002", "Pass the Hash", "lateral-movement"),
            ("T1550.003", "Pass the Ticket", "lateral-movement"),
            (
                "T1563",
                "Remote Service Session Hijacking",
                "lateral-movement",
            ),
            ("T1563.001", "SSH Hijacking", "lateral-movement"),
            ("T1563.002", "RDP Hijacking", "lateral-movement"),
            ("T1080", "Taint Shared Content", "lateral-movement"),
            ("T1534", "Internal Spearphishing", "lateral-movement"),
            (
                "T1210",
                "Exploitation of Remote Services",
                "lateral-movement",
            ),
            // ── Collection ──────────────────────────────────────────
            ("T1560", "Archive Collected Data", "collection"),
            ("T1560.001", "Archive via Utility", "collection"),
            ("T1560.002", "Archive via Library", "collection"),
            ("T1560.003", "Archive via Custom Method", "collection"),
            ("T1005", "Data from Local System", "collection"),
            ("T1039", "Data from Network Shared Drive", "collection"),
            ("T1074", "Data Staged", "collection"),
            ("T1074.001", "Local Data Staging", "collection"),
            ("T1074.002", "Remote Data Staging", "collection"),
            ("T1114", "Email Collection", "collection"),
            ("T1114.001", "Local Email Collection", "collection"),
            ("T1114.002", "Remote Email Collection", "collection"),
            ("T1114.003", "Email Forwarding Rule", "collection"),
            ("T1213", "Data from Information Repositories", "collection"),
            ("T1213.001", "Confluence", "collection"),
            ("T1213.002", "Sharepoint", "collection"),
            ("T1119", "Automated Collection", "collection"),
            ("T1115", "Clipboard Data", "collection"),
            ("T1056", "Input Capture", "collection"),
            ("T1056.001", "Keylogging", "collection"),
            ("T1113", "Screen Capture", "collection"),
            ("T1125", "Video Capture", "collection"),
            ("T1123", "Audio Capture", "collection"),
            ("T1557", "Adversary-in-the-Middle", "collection"),
            // ── Command and Control ─────────────────────────────────
            ("T1071", "Application Layer Protocol", "command-and-control"),
            ("T1071.001", "Web Protocols", "command-and-control"),
            (
                "T1071.002",
                "File Transfer Protocols",
                "command-and-control",
            ),
            ("T1071.003", "Mail Protocols", "command-and-control"),
            ("T1071.004", "DNS", "command-and-control"),
            ("T1105", "Ingress Tool Transfer", "command-and-control"),
            ("T1090", "Proxy", "command-and-control"),
            ("T1090.001", "Internal Proxy", "command-and-control"),
            ("T1090.002", "External Proxy", "command-and-control"),
            ("T1090.003", "Multi-hop Proxy", "command-and-control"),
            ("T1090.004", "Domain Fronting", "command-and-control"),
            (
                "T1095",
                "Non-Application Layer Protocol",
                "command-and-control",
            ),
            ("T1572", "Protocol Tunneling", "command-and-control"),
            ("T1573", "Encrypted Channel", "command-and-control"),
            ("T1573.001", "Symmetric Cryptography", "command-and-control"),
            (
                "T1573.002",
                "Asymmetric Cryptography",
                "command-and-control",
            ),
            ("T1219", "Remote Access Software", "command-and-control"),
            ("T1102", "Web Service", "command-and-control"),
            ("T1102.001", "Dead Drop Resolver", "command-and-control"),
            (
                "T1102.002",
                "Bidirectional Communication",
                "command-and-control",
            ),
            ("T1568", "Dynamic Resolution", "command-and-control"),
            ("T1568.001", "Fast Flux DNS", "command-and-control"),
            (
                "T1568.002",
                "Domain Generation Algorithms",
                "command-and-control",
            ),
            ("T1132", "Data Encoding", "command-and-control"),
            ("T1132.001", "Standard Encoding", "command-and-control"),
            ("T1132.002", "Non-Standard Encoding", "command-and-control"),
            ("T1001", "Data Obfuscation", "command-and-control"),
            ("T1001.001", "Junk Data", "command-and-control"),
            ("T1001.002", "Steganography", "command-and-control"),
            ("T1001.003", "Protocol Impersonation", "command-and-control"),
            ("T1104", "Multi-Stage Channels", "command-and-control"),
            ("T1571", "Non-Standard Port", "command-and-control"),
            ("T1008", "Fallback Channels", "command-and-control"),
            ("T1659", "Content Injection", "command-and-control"),
            // ── Exfiltration ────────────────────────────────────────
            ("T1041", "Exfiltration Over C2 Channel", "exfiltration"),
            (
                "T1048",
                "Exfiltration Over Alternative Protocol",
                "exfiltration",
            ),
            (
                "T1048.001",
                "Exfiltration Over Symmetric Encrypted Non-C2 Protocol",
                "exfiltration",
            ),
            (
                "T1048.002",
                "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol",
                "exfiltration",
            ),
            (
                "T1048.003",
                "Exfiltration Over Unencrypted Non-C2 Protocol",
                "exfiltration",
            ),
            ("T1567", "Exfiltration Over Web Service", "exfiltration"),
            (
                "T1567.001",
                "Exfiltration to Code Repository",
                "exfiltration",
            ),
            ("T1567.002", "Exfiltration to Cloud Storage", "exfiltration"),
            ("T1029", "Scheduled Transfer", "exfiltration"),
            ("T1537", "Transfer Data to Cloud Account", "exfiltration"),
            (
                "T1011",
                "Exfiltration Over Other Network Medium",
                "exfiltration",
            ),
            ("T1020", "Automated Exfiltration", "exfiltration"),
            ("T1030", "Data Transfer Size Limits", "exfiltration"),
            ("T1052", "Exfiltration Over Physical Medium", "exfiltration"),
            // ── Impact ──────────────────────────────────────────────
            ("T1486", "Data Encrypted for Impact", "impact"),
            ("T1490", "Inhibit System Recovery", "impact"),
            ("T1489", "Service Stop", "impact"),
            ("T1485", "Data Destruction", "impact"),
            ("T1491", "Defacement", "impact"),
            ("T1491.001", "Internal Defacement", "impact"),
            ("T1491.002", "External Defacement", "impact"),
            ("T1529", "System Shutdown/Reboot", "impact"),
            ("T1561", "Disk Wipe", "impact"),
            ("T1561.001", "Disk Content Wipe", "impact"),
            ("T1561.002", "Disk Structure Wipe", "impact"),
            ("T1496", "Resource Hijacking", "impact"),
            ("T1531", "Account Access Removal", "impact"),
            ("T1499", "Endpoint Denial of Service", "impact"),
            ("T1499.001", "OS Exhaustion Flood", "impact"),
            ("T1499.002", "Service Exhaustion Flood", "impact"),
            ("T1498", "Network Denial of Service", "impact"),
            ("T1495", "Firmware Corruption", "impact"),
            ("T1565", "Data Manipulation", "impact"),
            ("T1565.001", "Stored Data Manipulation", "impact"),
        ];

        for (id, name, tactic) in entries {
            techniques.insert(
                id.to_lowercase(),
                Technique {
                    id: id.to_string(),
                    name: name.to_string(),
                    tactic: tactic.to_string(),
                },
            );
        }

        MitreMapper { techniques }
    }

    pub fn parse_tags(tags: &[String]) -> Vec<MitreRef> {
        let mut refs = Vec::new();
        for tag in tags {
            let lower = tag.to_lowercase();
            if lower.starts_with("attack.t") {
                let id = lower.strip_prefix("attack.").unwrap_or(&lower);
                refs.push(MitreRef {
                    technique_id: Some(id.to_uppercase()),
                    tactic: None,
                });
            } else if lower.starts_with("attack.") {
                let tactic = lower.strip_prefix("attack.").unwrap_or(&lower);
                // Convert underscore to hyphen for tactic matching
                let tactic = tactic.replace('_', "-");
                refs.push(MitreRef {
                    technique_id: None,
                    tactic: Some(tactic),
                });
            }
        }
        refs
    }

    pub fn resolve(&self, id: &str) -> Option<&Technique> {
        self.techniques.get(&id.to_lowercase())
    }

    pub fn resolve_refs(&self, refs: &[MitreRef]) -> Vec<Technique> {
        let mut result = Vec::new();
        for r in refs {
            if let Some(ref id) = r.technique_id {
                if let Some(tech) = self.resolve(id) {
                    result.push(tech.clone());
                }
            }
        }
        result
    }
}

pub fn tactic_display_name(tactic: &str) -> &str {
    for (key, display) in TACTIC_DISPLAY {
        if *key == tactic {
            return display;
        }
    }
    tactic
}

/// Generate ATT&CK Navigator layer JSON
pub fn export_navigator_layer(
    detections: &[(Vec<MitreRef>, String, usize)], // (refs, level, count)
    mapper: &MitreMapper,
) -> serde_json::Value {
    let mut tech_scores: HashMap<String, (usize, String)> = HashMap::new();

    for (refs, level, count) in detections {
        for r in refs {
            if let Some(ref id) = r.technique_id {
                let entry = tech_scores.entry(id.clone()).or_insert((0, String::new()));
                entry.0 += count;
                if entry.1.is_empty() {
                    entry.1 = level.clone();
                }
            }
        }
    }

    let techniques: Vec<serde_json::Value> = tech_scores
        .iter()
        .map(|(id, (score, level))| {
            let color = match level.as_str() {
                "critical" => "#ff0000",
                "high" => "#ff6666",
                "medium" => "#ffcc00",
                "low" => "#66ccff",
                _ => "#99ccff",
            };
            let name = mapper
                .resolve(id)
                .map(|t| t.name.as_str())
                .unwrap_or("Unknown");
            serde_json::json!({
                "techniqueID": id,
                "score": score,
                "color": color,
                "comment": format!("{} ({} events)", name, score),
                "enabled": true,
            })
        })
        .collect();

    serde_json::json!({
        "name": "Muninn Detection Coverage",
        "versions": {
            "attack": "14",
            "navigator": "4.9",
            "layer": "4.5"
        },
        "domain": "enterprise-attack",
        "description": "Generated by Muninn",
        "techniques": techniques,
        "gradient": {
            "colors": ["#66ccff", "#ffcc00", "#ff0000"],
            "minValue": 0,
            "maxValue": tech_scores.values().map(|v| v.0).max().unwrap_or(10)
        },
        "legendItems": [],
        "showTacticRowBackground": true,
        "tacticRowBackground": "#dddddd",
    })
}

/// Render kill chain ASCII view
pub fn render_killchain(
    detections: &[(String, Vec<MitreRef>, String, usize)], // (title, refs, level, count)
    mapper: &MitreMapper,
) -> String {
    let mut tactic_detections: HashMap<String, Vec<(String, String, usize)>> = HashMap::new();

    for (title, refs, level, count) in detections {
        let mut tactics_for_detection = std::collections::HashSet::new();
        // Resolve techniques to tactics
        for r in refs {
            if let Some(ref id) = r.technique_id {
                if let Some(tech) = mapper.resolve(id) {
                    tactics_for_detection.insert(tech.tactic.clone());
                }
            }
            if let Some(ref tactic) = r.tactic {
                tactics_for_detection.insert(tactic.clone());
            }
        }
        for tactic in tactics_for_detection {
            tactic_detections.entry(tactic).or_default().push((
                title.clone(),
                level.clone(),
                *count,
            ));
        }
    }

    let mut output = String::new();
    output.push_str("\n  Kill Chain View\n");
    output.push_str(&format!("  {}\n", "─".repeat(70)));

    for tactic_key in TACTIC_ORDER {
        if let Some(dets) = tactic_detections.get(*tactic_key) {
            let display = tactic_display_name(tactic_key);
            let items: Vec<String> = dets
                .iter()
                .map(|(title, _level, count)| format!("{} ({})", title, count))
                .collect();
            let max_severity = dets
                .iter()
                .map(|(_, l, _)| match l.as_str() {
                    "critical" => 4,
                    "high" => 3,
                    "medium" => 2,
                    _ => 1,
                })
                .max()
                .unwrap_or(0);
            let marker = match max_severity {
                4 => "■",
                3 => "■",
                2 => "■",
                _ => "□",
            };
            output.push_str(&format!(
                "  {} {:<22} {} {}\n",
                marker,
                display,
                "───",
                items.join(", ")
            ));
        }
    }

    output.push_str(&format!("  {}\n", "─".repeat(70)));
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tags() {
        let tags = vec![
            "attack.execution".to_string(),
            "attack.t1059.001".to_string(),
            "attack.defense_evasion".to_string(),
        ];
        let refs = MitreMapper::parse_tags(&tags);
        assert_eq!(refs.len(), 3);
        assert_eq!(refs[0].tactic, Some("execution".into()));
        assert_eq!(refs[1].technique_id, Some("T1059.001".into()));
        assert_eq!(refs[2].tactic, Some("defense-evasion".into()));
    }

    #[test]
    fn test_resolve() {
        let mapper = MitreMapper::new();
        let tech = mapper.resolve("T1059.001").unwrap();
        assert_eq!(tech.name, "PowerShell");
        assert_eq!(tech.tactic, "execution");
    }

    #[test]
    fn test_resolve_case_insensitive() {
        let mapper = MitreMapper::new();
        assert!(mapper.resolve("t1059.001").is_some());
        assert!(mapper.resolve("T1059.001").is_some());
    }

    #[test]
    fn test_unknown_technique() {
        let mapper = MitreMapper::new();
        assert!(mapper.resolve("T9999").is_none());
    }

    #[test]
    fn test_navigator_export() {
        let mapper = MitreMapper::new();
        let refs = vec![MitreRef {
            technique_id: Some("T1059.001".into()),
            tactic: None,
        }];
        let detections = vec![(refs, "high".to_string(), 5)];
        let layer = export_navigator_layer(&detections, &mapper);
        assert!(layer["techniques"].as_array().unwrap().len() > 0);
        assert_eq!(layer["domain"], "enterprise-attack");
    }

    #[test]
    fn test_killchain_render() {
        let mapper = MitreMapper::new();
        let refs1 = vec![MitreRef {
            technique_id: Some("T1059.001".into()),
            tactic: None,
        }];
        let refs2 = vec![MitreRef {
            technique_id: Some("T1003.001".into()),
            tactic: None,
        }];
        let detections = vec![
            ("Encoded PowerShell".into(), refs1, "high".into(), 5),
            ("LSASS Dump".into(), refs2, "critical".into(), 2),
        ];
        let output = render_killchain(&detections, &mapper);
        assert!(output.contains("Execution"));
        assert!(output.contains("Credential Access"));
        assert!(output.contains("Encoded PowerShell"));
    }
}
