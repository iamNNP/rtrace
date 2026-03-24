use crate::attack::{classify_rule, load_active_rules, AttackMapping};
use crate::detectors::{DetectedPattern, PatternType, Severity};
use std::path::Path;

#[cfg(feature = "yara")]
use log::{info, warn};
#[cfg(feature = "yara")]
use std::collections::HashMap;
#[cfg(feature = "yara")]
use std::path::PathBuf;
#[cfg(feature = "yara")]
use std::sync::Arc;

#[cfg(feature = "yara")]
const YARA_TIMEOUT_SECS: i32 = 5;
#[cfg(feature = "yara")]
const MATCH_PREVIEW_MAX_BYTES: usize = 48;

#[cfg(feature = "yara")]
use yara::{Compiler, Yara};

#[cfg(feature = "yara")]
pub struct YaraScanner {
    _yara: Yara,
    rules: Arc<yara::Rules>,
    default_severity: Severity,
    rule_meta: HashMap<String, RuleMetadata>,
}

#[cfg(feature = "yara")]
struct MatchEvidence {
    string_id: String,
    offset: u64,
    bytes: Vec<u8>,
}

#[cfg(feature = "yara")]
#[derive(Clone)]
struct RuleMetadata {
    class: String,
    mitre_attack: Vec<AttackMapping>,
}

#[cfg(not(feature = "yara"))]
pub struct YaraScanner;

#[cfg(feature = "yara")]
impl YaraScanner {
    pub fn load_from_dir<P: AsRef<Path>>(rules_dir: P) -> Option<Self> {
        let rules_dir = rules_dir.as_ref();
        if !rules_dir.is_dir() {
            return None;
        }

        let rule_meta = match build_rule_metadata(rules_dir) {
            Ok(value) => value,
            Err(err) => {
                warn!("Failed to build YARA metadata {:?}: {}", rules_dir, err);
                return None;
            }
        };

        if rule_meta.is_empty() {
            return None;
        }

        let yara = match Yara::new() {
            Ok(value) => value,
            Err(err) => {
                warn!("Failed to initialize YARA: {}", err);
                return None;
            }
        };

        let mut compiler = match Compiler::new() {
            Ok(value) => value,
            Err(err) => {
                warn!("Failed to create YARA compiler: {}", err);
                return None;
            }
        };

        if let Some(index_file) = pick_index_file(rules_dir) {
            info!("Loading YARA index {:?}", index_file);
            compiler = match compiler.add_rules_file(&index_file) {
                Ok(value) => value,
                Err(err) => {
                    warn!("Failed to load YARA index {:?}: {}", index_file, err);
                    return None;
                }
            };
        } else {
            let mut rule_files: Vec<PathBuf> = match load_active_rules(rules_dir) {
                Ok(value) => value.into_iter().map(|rule| rule.source_file).collect(),
                Err(err) => {
                    warn!("Failed to enumerate YARA rule files {:?}: {}", rules_dir, err);
                    return None;
                }
            };
            rule_files.sort();
            rule_files.dedup();
            info!("Loading {} YARA rule files from {:?}", rule_files.len(), rules_dir);
            for file in rule_files {
                compiler = match compiler.add_rules_file(&file) {
                    Ok(value) => value,
                    Err(err) => {
                        warn!("Failed to load YARA rule {:?}: {}", file, err);
                        return None;
                    }
                };
            }
        }

        let rules = match compiler.compile_rules() {
            Ok(value) => value,
            Err(err) => {
                warn!("Failed to compile YARA rules: {}", err);
                return None;
            }
        };

        info!("YARA rules loaded from {:?}", rules_dir);

        Some(Self {
            _yara: yara,
            rules: Arc::new(rules),
            default_severity: Severity::Medium,
            rule_meta,
        })
    }

    pub fn scan_bytes(
        &self,
        bytes: &[u8],
        register: &str,
        address: Option<u64>,
        syscall_name: Option<&str>,
    ) -> Vec<DetectedPattern> {
        if bytes.is_empty() {
            return Vec::new();
        }

        let matches = match self.rules.scan_mem(bytes, YARA_TIMEOUT_SECS) {
            Ok(value) => value,
            Err(err) => {
                warn!("YARA scan failed: {}", err);
                return Vec::new();
            }
        };

        let mut out = Vec::new();
        let syscall_name = syscall_name.map(|s| s.to_string());

        for hit in matches {
            let severity = self.default_severity;
            let metadata = self.rule_meta.get(hit.identifier);
            let source = metadata
                .map(|value| value.class.clone())
                .unwrap_or_else(|| "unknown".to_string());
            let note = build_match_note(&hit.tags, &hit.namespace);
            let evidence = extract_match_evidence(&hit);
            let mut resolved_address = address;
            let mut match_string = None;
            let mut match_offset = None;
            let mut matched_bytes_hex = None;
            let mut matched_bytes_ascii = None;

            if let Some(evidence) = evidence {
                resolved_address = address.map(|base| base.saturating_add(evidence.offset));
                match_string = Some(evidence.string_id);
                match_offset = Some(evidence.offset);
                let (hex, ascii) = encode_match_bytes(&evidence.bytes);
                matched_bytes_hex = Some(hex);
                matched_bytes_ascii = Some(ascii);
            }

            out.push(DetectedPattern {
                pattern_type: PatternType::YaraRule,
                value: hit.identifier.to_string(),
                register: register.to_string(),
                cpu_register: None,
                address: resolved_address,
                match_string,
                match_offset,
                matched_bytes_hex,
                matched_bytes_ascii,
                syscall_name: syscall_name.clone(),
                source: Some(source),
                note,
                mitre_attack: metadata
                    .map(|value| value.mitre_attack.clone())
                    .unwrap_or_default(),
                severity,
            });
        }

        out
    }

    pub fn scan_file(&self, path: &Path, register: &str) -> Vec<DetectedPattern> {
        let bytes = match std::fs::read(path) {
            Ok(value) => value,
            Err(err) => {
                warn!("Failed to read file {:?} for YARA scan: {}", path, err);
                return Vec::new();
            }
        };

        let mut hits = self.scan_bytes(&bytes, register, None, None);
        if hits.is_empty() {
            return hits;
        }

        let file_note = format!("file: {}", path.to_string_lossy());
        for hit in &mut hits {
            hit.note = merge_note(hit.note.take(), &file_note);
        }
        hits
    }
}

#[cfg(not(feature = "yara"))]
impl YaraScanner {
    pub fn load_from_dir<P: AsRef<Path>>(_rules_dir: P) -> Option<Self> {
        None
    }

    pub fn scan_bytes(
        &self,
        _bytes: &[u8],
        _register: &str,
        _address: Option<u64>,
        _syscall_name: Option<&str>,
    ) -> Vec<DetectedPattern> {
        Vec::new()
    }

    pub fn scan_file(&self, _path: &Path, _register: &str) -> Vec<DetectedPattern> {
        Vec::new()
    }
}

#[cfg(feature = "yara")]
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

#[cfg(feature = "yara")]
fn build_rule_metadata(rules_dir: &Path) -> std::io::Result<HashMap<String, RuleMetadata>> {
    let mut out = HashMap::new();
    for rule in load_active_rules(rules_dir)? {
        if out.contains_key(&rule.name) {
            warn!("Duplicate YARA rule name '{}'", rule.name);
            continue;
        }
        out.insert(
            rule.name.clone(),
            RuleMetadata {
                class: rule.class.clone(),
                mitre_attack: classify_rule(&rule.name, &rule.class),
            },
        );
    }
    Ok(out)
}

#[cfg(feature = "yara")]
fn build_match_note(tags: &[&str], namespace: &str) -> Option<String> {
    let mut parts = Vec::new();
    if !namespace.is_empty() && namespace != "default" {
        parts.push(format!("namespace: {}", namespace));
    }
    if !tags.is_empty() {
        parts.push(format!("tags: {}", tags.join(", ")));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("; "))
    }
}

#[cfg(feature = "yara")]
fn merge_note(existing: Option<String>, extra: &str) -> Option<String> {
    if extra.is_empty() {
        return existing;
    }
    match existing {
        Some(current) if !current.is_empty() => Some(format!("{}; {}", current, extra)),
        _ => Some(extra.to_string()),
    }
}

#[cfg(feature = "yara")]
fn extract_match_evidence(rule: &yara::Rule<'_>) -> Option<MatchEvidence> {
    let mut best: Option<MatchEvidence> = None;

    for string in &rule.strings {
        for m in &string.matches {
            let candidate = MatchEvidence {
                string_id: string.identifier.to_string(),
                offset: m.offset as u64,
                bytes: m.data.clone(),
            };
            let take = best
                .as_ref()
                .map(|current| candidate.offset < current.offset)
                .unwrap_or(true);
            if take {
                best = Some(candidate);
            }
        }
    }

    best
}

#[cfg(feature = "yara")]
fn encode_match_bytes(bytes: &[u8]) -> (String, String) {
    let n = bytes.len().min(MATCH_PREVIEW_MAX_BYTES);
    let preview = &bytes[..n];

    let mut hex = preview
        .iter()
        .map(|byte| format!("{:02X}", byte))
        .collect::<Vec<_>>()
        .join(" ");

    let mut ascii = preview
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            }
        })
        .collect::<String>();

    if bytes.len() > n {
        hex.push_str(" ...");
        ascii.push_str("...");
    }

    (hex, ascii)
}
