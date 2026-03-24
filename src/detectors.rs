use crate::attack::AttackMapping;
use std::path::Path;
use std::sync::{Arc, Once};

use log::warn;

use crate::yara::YaraScanner;

#[derive(Debug, Clone)]
pub struct DetectedPattern {
    pub pattern_type: PatternType,
    pub value: String,
    pub register: String,
    pub cpu_register: Option<String>,
    pub address: Option<u64>,
    pub match_string: Option<String>,
    pub match_offset: Option<u64>,
    pub matched_bytes_hex: Option<String>,
    pub matched_bytes_ascii: Option<String>,
    pub syscall_name: Option<String>,
    pub source: Option<String>,
    pub note: Option<String>,
    pub mitre_attack: Vec<AttackMapping>,
    pub severity: Severity,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PatternType {
    IpAddress,
    SuspiciousString,
    ByteSequence,
    Regex,
    YaraRule,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn rank(&self) -> u8 {
        match self {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
        }
    }

    pub fn is_above(&self, other: Severity) -> bool {
        self.rank() > other.rank()
    }
}

pub struct PatternDetector {
    yara: Option<Arc<YaraScanner>>,
}

const RULES_DIR_PRIMARY: &str = "rules";
const RULES_ENV: &str = "RTRACE_RULES_DIR";

lazy_static::lazy_static! {
    static ref YARA_SCANNER: Option<Arc<YaraScanner>> = {
        let dir = std::env::var(RULES_ENV)
            .unwrap_or_else(|_| default_rules_dir().to_string());
        YaraScanner::load_from_dir(dir).map(Arc::new)
    };
}

static WARN_ONCE: Once = Once::new();

impl PatternDetector {
    pub fn new() -> Self {
        let yara = YARA_SCANNER.clone();
        if yara.is_none() {
            WARN_ONCE.call_once(|| {
                warn!("YARA rules are not loaded. Set RTRACE_RULES_DIR or place rules in ./rules.");
            });
        }
        Self { yara }
    }

    pub fn is_enabled(&self) -> bool {
        self.yara.is_some()
    }

    pub fn has_byte_rules(&self) -> bool {
        self.is_enabled()
    }

    pub fn should_scan_register_bytes(&self) -> bool {
        false
    }

    pub fn detect_patterns(
        &self,
        text: &str,
        register: &str,
        address: Option<u64>,
        syscall_name: Option<&str>,
    ) -> Vec<DetectedPattern> {
        if let Some(scanner) = &self.yara {
            return scanner.scan_bytes(text.as_bytes(), register, address, syscall_name);
        }
        Vec::new()
    }

    pub fn detect_byte_patterns(
        &self,
        bytes: &[u8],
        register: &str,
        address: Option<u64>,
        syscall_name: Option<&str>,
    ) -> Vec<DetectedPattern> {
        if let Some(scanner) = &self.yara {
            return scanner.scan_bytes(bytes, register, address, syscall_name);
        }
        Vec::new()
    }

    pub fn scan_file(&self, path: &Path, register: &str) -> Vec<DetectedPattern> {
        if let Some(scanner) = &self.yara {
            return scanner.scan_file(path, register);
        }
        Vec::new()
    }
}

impl Default for PatternDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn default_rules_dir() -> &'static str {
    RULES_DIR_PRIMARY
}
