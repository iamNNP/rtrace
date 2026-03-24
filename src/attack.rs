use regex::Regex;
use serde::Serialize;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AttackMapping {
    pub tactic_ids: Vec<String>,
    pub tactics: Vec<String>,
    pub technique_id: String,
    pub technique: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RuleCatalogEntry {
    pub rule: String,
    pub class: String,
    pub source_file: String,
    pub mitre_attack: Vec<AttackMapping>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleInfo {
    pub name: String,
    pub class: String,
    pub source_file: PathBuf,
}

pub fn load_runtime_rule_catalog(rules_dir: &Path) -> io::Result<Vec<RuleCatalogEntry>> {
    let mut out: Vec<RuleCatalogEntry> = load_active_rules(rules_dir)?
        .into_iter()
        .map(|rule| RuleCatalogEntry {
            mitre_attack: classify_rule(&rule.name, &rule.class),
            rule: rule.name,
            class: rule.class,
            source_file: normalize_path(&rule.source_file),
        })
        .collect();
    out.sort_by(|a, b| a.rule.cmp(&b.rule));
    Ok(out)
}

pub fn load_active_rules(rules_dir: &Path) -> io::Result<Vec<RuleInfo>> {
    let files = collect_active_rule_files(rules_dir)?;
    let mut out = Vec::new();
    let mut seen_names = HashSet::new();

    for file in files {
        let contents = fs::read_to_string(&file)?;
        let stripped = strip_block_comments(&contents);
        let class = rule_class_for_file(rules_dir, &file);
        for name in extract_rule_names(&stripped) {
            if !seen_names.insert(name.clone()) {
                continue;
            }
            out.push(RuleInfo {
                name,
                class: class.clone(),
                source_file: file.clone(),
            });
        }
    }

    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

pub fn classify_rule(rule_name: &str, class: &str) -> Vec<AttackMapping> {
    match class {
        "antidebug_antivm" => classify_antidebug_rule(rule_name),
        "capabilities" => classify_capability_rule(rule_name),
        "crypto" => classify_crypto_rule(rule_name),
        _ => vec![attack(
            &["TA0005"],
            &["Defense Evasion"],
            "T1027",
            "Obfuscated Files or Information",
        )],
    }
}

fn classify_antidebug_rule(rule_name: &str) -> Vec<AttackMapping> {
    let upper = rule_name.to_ascii_uppercase();

    if upper == "LINUX_VM_CHECKS" {
        return vec![attack(
            &["TA0005"],
            &["Defense Evasion"],
            "T1497.001",
            "System Checks",
        )];
    }

    if upper == "LINUX_DEBUGGER_CHECKS" {
        return vec![attack(
            &["TA0005"],
            &["Defense Evasion"],
            "T1622",
            "Debugger Evasion",
        )];
    }

    if upper == "DISABLE_UAX" {
        return vec![attack(
            &["TA0004", "TA0005"],
            &["Privilege Escalation", "Defense Evasion"],
            "T1548.002",
            "Bypass User Account Control",
        )];
    }

    if upper.starts_with("DISABLE_") {
        return vec![attack(
            &["TA0005"],
            &["Defense Evasion"],
            "T1562.001",
            "Impair Defenses",
        )];
    }

    if upper == "WIN_HOOK" {
        return vec![attack(
            &["TA0006", "TA0009"],
            &["Credential Access", "Collection"],
            "T1056",
            "Input Capture",
        )];
    }

    if upper.contains("TIMING") {
        return vec![attack(
            &["TA0005"],
            &["Defense Evasion"],
            "T1497.003",
            "Time Based Evasion",
        )];
    }

    if contains_any(
        &upper,
        &[
            "QEMU",
            "VBOX",
            "VMWARE",
            "VMTOOLS",
            "WINE",
            "VMDETECT",
            "SANDBOX",
            "WMI_VM",
            "BIOS",
            "DEVICEMAP",
            "DESCRIPTION",
            "FILEPATHS",
            "USERNAMES",
            "DRIVESIZE",
            "PATCHLEVEL",
            "DLLS",
            "GUEST_ADDITIONS",
            "VIDEODRIVERS",
            "MISC",
        ],
    ) {
        return vec![attack(
            &["TA0005"],
            &["Defense Evasion"],
            "T1497.001",
            "System Checks",
        )];
    }

    if contains_any(
        &upper,
        &[
            "DEBUGGER",
            "ANTI_DBG",
            "CHECK_DEBUGGER",
            "SEH",
            "THREADCONTROL",
            "OUTPUTDEBUGSTRING",
            "UNHANDLEDEXCEPTION",
            "RAISEEXCEPTION",
            "FINDWINDOW",
            "DRWATSON",
        ],
    ) {
        return vec![attack(
            &["TA0005"],
            &["Defense Evasion"],
            "T1622",
            "Debugger Evasion",
        )];
    }

    vec![attack(
        &["TA0005"],
        &["Defense Evasion"],
        "T1497.001",
        "System Checks",
    )]
}

fn classify_capability_rule(rule_name: &str) -> Vec<AttackMapping> {
    match rule_name {
        "linux_http_beacon" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1071.001",
            "Web Protocols",
        )],
        "linux_host_discovery" => vec![
            attack(
                &["TA0007"],
                &["Discovery"],
                "T1082",
                "System Information Discovery",
            ),
            attack(
                &["TA0007"],
                &["Discovery"],
                "T1016",
                "System Network Configuration Discovery",
            ),
        ],
        "linux_persistence_paths" => vec![
            attack(
                &["TA0003"],
                &["Persistence"],
                "T1543.002",
                "Create or Modify System Process: Systemd Service",
            ),
            attack(
                &["TA0003"],
                &["Persistence"],
                "T1053.003",
                "Scheduled Task/Job: Cron",
            ),
            attack(
                &["TA0005"],
                &["Defense Evasion"],
                "T1574.006",
                "Dynamic Linker Hijacking",
            ),
        ],
        "linux_secret_paths" => vec![
            attack(
                &["TA0006"],
                &["Credential Access"],
                "T1552.001",
                "Credentials In Files",
            ),
            attack(
                &["TA0009"],
                &["Collection"],
                "T1005",
                "Data from Local System",
            ),
        ],
        "linux_runtime_second_stage" => vec![
            attack(
                &["TA0011"],
                &["Command and Control"],
                "T1105",
                "Ingress Tool Transfer",
            ),
            attack(
                &["TA0002"],
                &["Execution"],
                "T1059.004",
                "Command and Scripting Interpreter: Unix Shell",
            ),
        ],
        "inject_thread" => vec![attack(
            &["TA0005", "TA0004"],
            &["Defense Evasion", "Privilege Escalation"],
            "T1055",
            "Process Injection",
        )],
        "hijack_network" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1090",
            "Proxy",
        )],
        "create_service" => vec![attack(
            &["TA0003", "TA0004"],
            &["Persistence", "Privilege Escalation"],
            "T1543.003",
            "Create or Modify System Process: Windows Service",
        )],
        "create_com_service" => vec![attack(
            &["TA0003", "TA0004"],
            &["Persistence", "Privilege Escalation"],
            "T1546.015",
            "Component Object Model Hijacking",
        )],
        "network_udp_sock" | "network_tcp_listen" | "network_tcp_socket"
        | "network_p2p_win" | "Str_Win32_Winsock2_Library" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1095",
            "Non-Application Layer Protocol",
        )],
        "network_dyndns" | "dyndns" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1568",
            "Dynamic Resolution",
        )],
        "network_toredo" | "network_tor" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1090",
            "Proxy",
        )],
        "network_smtp_dotNet" | "network_smtp_raw" | "network_smtp_vb" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1071.003",
            "Mail Protocols",
        )],
        "network_irc" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1071",
            "Application Layer Protocol",
        )],
        "network_http"
        | "Str_Win32_Wininet_Library"
        | "Str_Win32_Internet_API"
        | "Str_Win32_Http_API" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1071.001",
            "Web Protocols",
        )],
        "network_dropper" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1105",
            "Ingress Tool Transfer",
        )],
        "network_ftp" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1071.002",
            "File Transfer Protocols",
        )],
        "network_dns" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1071.004",
            "DNS",
        )],
        "network_ssl" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1573",
            "Encrypted Channel",
        )],
        "certificate" => vec![attack(
            &["TA0005"],
            &["Defense Evasion"],
            "T1553.004",
            "Install Root Certificate",
        )],
        "network_dga" => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1568.002",
            "Domain Generation Algorithms",
        )],
        "bitcoin" => vec![attack(
            &["TA0040"],
            &["Impact"],
            "T1496",
            "Resource Hijacking",
        )],
        "escalate_priv" | "win_token" => vec![attack(
            &["TA0004"],
            &["Privilege Escalation"],
            "T1134",
            "Access Token Manipulation",
        )],
        "screenshot" => vec![attack(
            &["TA0009"],
            &["Collection"],
            "T1113",
            "Screen Capture",
        )],
        "lookupip" => vec![attack(
            &["TA0007"],
            &["Discovery"],
            "T1016",
            "System Network Configuration Discovery",
        )],
        "lookupgeo" => vec![attack(
            &["TA0007"],
            &["Discovery"],
            "T1614",
            "System Location Discovery",
        )],
        "keylogger" => vec![attack(
            &["TA0006", "TA0009"],
            &["Credential Access", "Collection"],
            "T1056.001",
            "Keylogging",
        )],
        "cred_local" => vec![
            attack(
                &["TA0006"],
                &["Credential Access"],
                "T1003",
                "OS Credential Dumping",
            ),
            attack(
                &["TA0006"],
                &["Credential Access"],
                "T1555",
                "Credentials from Password Stores",
            ),
        ],
        "sniff_audio" => vec![attack(
            &["TA0009"],
            &["Collection"],
            "T1123",
            "Audio Capture",
        )],
        "cred_ff" | "cred_ie7" => vec![attack(
            &["TA0006"],
            &["Credential Access"],
            "T1555.003",
            "Credentials from Web Browsers",
        )],
        "cred_vnc" => vec![attack(
            &["TA0006"],
            &["Credential Access"],
            "T1552.001",
            "Credentials In Files",
        )],
        "sniff_lan" => vec![attack(
            &["TA0009"],
            &["Collection"],
            "T1040",
            "Network Sniffing",
        )],
        "migrate_apc" => vec![attack(
            &["TA0005", "TA0004"],
            &["Defense Evasion", "Privilege Escalation"],
            "T1055.004",
            "Asynchronous Procedure Call",
        )],
        "spreading_file" => vec![attack(
            &["TA0008"],
            &["Lateral Movement"],
            "T1570",
            "Lateral Tool Transfer",
        )],
        "spreading_share" => vec![attack(
            &["TA0007"],
            &["Discovery"],
            "T1135",
            "Network Share Discovery",
        )],
        "rat_vnc" => vec![attack(
            &["TA0008"],
            &["Lateral Movement"],
            "T1021.005",
            "VNC",
        )],
        "rat_rdp" => vec![attack(
            &["TA0008"],
            &["Lateral Movement"],
            "T1021.001",
            "Remote Desktop Protocol",
        )],
        "rat_telnet" => vec![attack(
            &["TA0008"],
            &["Lateral Movement"],
            "T1021",
            "Remote Services",
        )],
        "rat_webcam" => vec![attack(
            &["TA0009"],
            &["Collection"],
            "T1125",
            "Video Capture",
        )],
        "win_mutex" => vec![attack(
            &["TA0005"],
            &["Defense Evasion"],
            "T1480",
            "Execution Guardrails",
        )],
        "win_registry" => vec![attack(
            &["TA0005", "TA0003"],
            &["Defense Evasion", "Persistence"],
            "T1112",
            "Modify Registry",
        )],
        "win_private_profile" | "win_files_operation" => vec![attack(
            &["TA0009"],
            &["Collection"],
            "T1005",
            "Data from Local System",
        )],
        "ldpreload" => vec![attack(
            &["TA0003", "TA0005"],
            &["Persistence", "Defense Evasion"],
            "T1574.006",
            "Dynamic Linker Hijacking",
        )],
        "mysql_database_presence" => vec![attack(
            &["TA0009"],
            &["Collection"],
            "T1213",
            "Data from Information Repositories",
        )],
        _ => vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1071",
            "Application Layer Protocol",
        )],
    }
}

fn classify_crypto_rule(rule_name: &str) -> Vec<AttackMapping> {
    let upper = rule_name.to_ascii_uppercase();

    if upper == "BASE64_TABLE" {
        return vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1132.001",
            "Standard Encoding",
        )];
    }

    if contains_any(
        &upper,
        &[
            "RSA",
            "DSA",
            "OPENSSL_DSA",
            "CRYPTOPP_RSA",
            "CRYPTOPP_INTEGER",
            "RSAREF",
            "RSAEURO",
            "ECC_",
            "ECADD",
            "ECPOINT",
            "ECELGAMAL",
            "X509",
            "PKCS8",
            "CERT",
            "BIGDIG",
            "MIRACL",
            "FGINT",
            "OPENSSL_BN",
        ],
    ) {
        return vec![attack(
            &["TA0011"],
            &["Command and Control"],
            "T1573.002",
            "Asymmetric Cryptography",
        )];
    }

    if contains_any(
        &upper,
        &[
            "CRC",
            "MD5",
            "SHA",
            "RIPEMD",
            "WHIRLPOOL",
            "ELF_HASH",
            "UNKNOWN_RANDOM",
            "VC6_RANDOM",
            "VC8_RANDOM",
            "DELPHI_RANDOM",
            "DELPHI_COMPARECALL",
            "DELPHI_COPY",
            "DELPHI_INTTOSTR",
            "DELPHI_STRTOINT",
            "DELPHI_DECODEDATE",
        ],
    ) {
        return vec![attack(
            &["TA0005"],
            &["Defense Evasion"],
            "T1027",
            "Obfuscated Files or Information",
        )];
    }

    vec![attack(
        &["TA0011"],
        &["Command and Control"],
        "T1573.001",
        "Symmetric Cryptography",
    )]
}

fn collect_active_rule_files(rules_dir: &Path) -> io::Result<Vec<PathBuf>> {
    if let Some(index_file) = pick_index_file(rules_dir) {
        let mut seen = HashSet::new();
        let mut files = Vec::new();
        visit_rule_file(&index_file, &mut seen, &mut files)?;
        if !files.is_empty() {
            files.sort();
            return Ok(files);
        }
    }

    let mut out = Vec::new();
    collect_all_rule_files(rules_dir, &mut out)?;
    out.sort();
    Ok(out)
}

fn visit_rule_file(path: &Path, seen: &mut HashSet<PathBuf>, out: &mut Vec<PathBuf>) -> io::Result<()> {
    let canonical = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    if !seen.insert(canonical) {
        return Ok(());
    }

    let contents = fs::read_to_string(path)?;
    let stripped = strip_block_comments(&contents);
    let parent = path.parent().unwrap_or_else(|| Path::new("."));

    let includes = extract_includes(&stripped)
        .into_iter()
        .map(|include| normalize_include_path(parent, &include))
        .filter(|include_path| include_path.is_file())
        .collect::<Vec<_>>();

    let has_rules = !extract_rule_names(&stripped).is_empty();
    if has_rules {
        out.push(path.to_path_buf());
    }

    for include in includes {
        visit_rule_file(&include, seen, out)?;
    }

    Ok(())
}

fn collect_all_rule_files(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            collect_all_rule_files(&path, out)?;
            continue;
        }
        if is_yara_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn pick_index_file(dir: &Path) -> Option<PathBuf> {
    let candidates = [
        "runtime_index.yar",
        "runtime_index.yara",
        "index.yar",
        "index.yara",
        "all.yar",
        "all.yara",
    ];
    for name in &candidates {
        let path = dir.join(name);
        if path.is_file() {
            return Some(path);
        }
    }
    None
}

fn extract_rule_names(contents: &str) -> Vec<String> {
    let rule_re = Regex::new(r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+([A-Za-z0-9_]+)")
        .expect("regex should compile");
    rule_re
        .captures_iter(contents)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

fn extract_includes(contents: &str) -> Vec<String> {
    let include_re = Regex::new(r#"(?m)^\s*include\s+"([^"]+)""#).expect("regex should compile");
    include_re
        .captures_iter(contents)
        .filter_map(|cap| cap.get(1).map(|m| m.as_str().to_string()))
        .collect()
}

fn strip_block_comments(contents: &str) -> String {
    let bytes = contents.as_bytes();
    let mut out = String::with_capacity(contents.len());
    let mut i = 0;
    let mut in_block = false;

    while i < bytes.len() {
        if in_block {
            if i + 1 < bytes.len() && bytes[i] == b'*' && bytes[i + 1] == b'/' {
                in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }

        if i + 1 < bytes.len() && bytes[i] == b'/' && bytes[i + 1] == b'*' {
            in_block = true;
            i += 2;
            continue;
        }

        out.push(bytes[i] as char);
        i += 1;
    }

    out
}

fn normalize_include_path(base_dir: &Path, include: &str) -> PathBuf {
    let candidate = base_dir.join(include);
    fs::canonicalize(&candidate).unwrap_or(candidate)
}

fn normalize_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn rule_class_for_file(rules_dir: &Path, file: &Path) -> String {
    let relative = file.strip_prefix(rules_dir).unwrap_or(file);
    let class_path = relative.parent();
    let class = match class_path {
        Some(path) if !path.as_os_str().is_empty() => path.to_string_lossy().to_string(),
        _ => "root".to_string(),
    };
    class.replace('\\', "/")
}

fn is_yara_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()),
        Some("yar") | Some("yara")
    )
}

fn attack(
    tactic_ids: &[&str],
    tactics: &[&str],
    technique_id: &str,
    technique: &str,
) -> AttackMapping {
    AttackMapping {
        tactic_ids: tactic_ids.iter().map(|v| (*v).to_string()).collect(),
        tactics: tactics.iter().map(|v| (*v).to_string()).collect(),
        technique_id: technique_id.to_string(),
        technique: technique.to_string(),
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn classify_capability_rules_returns_expected_mappings() {
        let inject = classify_rule("inject_thread", "capabilities");
        assert_eq!(inject[0].technique_id, "T1055");

        let keylogger = classify_rule("keylogger", "capabilities");
        assert_eq!(keylogger[0].technique_id, "T1056.001");

        let ldpreload = classify_rule("ldpreload", "capabilities");
        assert_eq!(ldpreload[0].technique_id, "T1574.006");

        let linux_http = classify_rule("linux_http_beacon", "capabilities");
        assert_eq!(linux_http[0].technique_id, "T1071.001");

        let linux_stage = classify_rule("linux_runtime_second_stage", "capabilities");
        assert_eq!(linux_stage[0].technique_id, "T1105");
    }

    #[test]
    fn classify_antidebug_and_crypto_rules_returns_expected_mappings() {
        let anti_dbg = classify_rule("anti_dbg", "antidebug_antivm");
        assert_eq!(anti_dbg[0].technique_id, "T1622");

        let antivm = classify_rule("antivm_vmware", "antidebug_antivm");
        assert_eq!(antivm[0].technique_id, "T1497.001");

        let linux_dbg = classify_rule("linux_debugger_checks", "antidebug_antivm");
        assert_eq!(linux_dbg[0].technique_id, "T1622");

        let chacha = classify_rule("Chacha_256_constant", "crypto");
        assert_eq!(chacha[0].technique_id, "T1573.001");

        let rsa = classify_rule("FGint_RSAEncrypt", "crypto");
        assert_eq!(rsa[0].technique_id, "T1573.002");
    }

    #[test]
    fn load_active_rules_ignores_block_commented_rules_and_follows_includes() {
        let tmp = tempdir().expect("temp dir");
        let rules_dir = tmp.path().join("rules");
        let nested_dir = rules_dir.join("capabilities");
        fs::create_dir_all(&nested_dir).expect("mkdir");

        fs::write(
            rules_dir.join("runtime_index.yar"),
            "include \"./capabilities/capabilities.yar\"\n",
        )
        .expect("write index");
        fs::write(
            nested_dir.join("capabilities.yar"),
            "/*\nrule ignored_rule { condition: true }\n*/\nrule active_rule { condition: true }\n",
        )
        .expect("write rules");

        let catalog = load_active_rules(&rules_dir).expect("catalog");
        assert_eq!(catalog.len(), 1);
        assert_eq!(catalog[0].name, "active_rule");
        assert_eq!(catalog[0].class, "capabilities");
    }
}
