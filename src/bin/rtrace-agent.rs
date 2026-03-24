use clap::Parser;
use log::{info, warn};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rtrace::attack::AttackMapping;
use rtrace::yara::YaraScanner;

const REGISTER_SCAN_MAX_BYTES: usize = 256;

#[derive(Parser, Debug)]
#[command(
    name = "rtrace-agent",
    about = "Guest agent for rtrace sandbox",
    after_help = "Examples:\n  /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --scan-interval-ms 500 --verbose\n  /samples/rtrace-agent --rules-dir /rules --pid 4242 --artifacts-dir /artifacts --stop-on-hit\n  /samples/rtrace-agent --rules-dir /rules --artifacts-dir /artifacts --scan-interval-ms 500 --stop-on-hit\n  /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --once"
)]
struct Cli {
    #[arg(long, default_value = "/rules")]
    rules_dir: PathBuf,

    #[arg(long)]
    samples_dir: Option<PathBuf>,

    #[arg(long, value_name = "PID")]
    pid: Vec<u32>,

    #[arg(long, default_value = "/artifacts")]
    artifacts_dir: PathBuf,

    #[arg(long, default_value_t = 1000)]
    scan_interval_ms: u64,

    #[arg(long, default_value_t = 128)]
    max_region_bytes: usize,

    #[arg(long, default_value_t = 1024 * 1024)]
    max_total_bytes: usize,

    #[arg(long)]
    save_maps: bool,

    #[arg(long)]
    dump_regions: bool,

    #[arg(long)]
    once: bool,

    #[arg(long)]
    stop_on_hit: bool,

    #[arg(short, long)]
    verbose: bool,
}

#[derive(Debug, Clone)]
struct ProcessInfo {
    pid: u32,
    ppid: u32,
    uid: u32,
    start_time_ticks: u64,
    exe: PathBuf,
    comm: String,
    cmdline_args: Vec<String>,
    cmdline: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ProcessKey {
    pid: u32,
    start_time_ticks: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct HitKey {
    process: ProcessKey,
    rule: String,
    channel: String,
    cpu_register: Option<String>,
}

#[derive(Debug, Clone)]
struct MemoryRegion {
    start: u64,
    end: u64,
    perms: String,
}

#[derive(Serialize)]
struct SnapshotMeta {
    timestamp_ms: u128,
    pid: u32,
    ppid: u32,
    uid: u32,
    process_start_time_ticks: u64,
    exe: String,
    comm: String,
    cmdline: String,
    hits: Vec<HitMeta>,
    regions: Vec<RegionMeta>,
}

impl ProcessInfo {
    fn key(&self) -> ProcessKey {
        ProcessKey {
            pid: self.pid,
            start_time_ticks: self.start_time_ticks,
        }
    }
}

#[derive(Serialize)]
struct HitMeta {
    rule: String,
    class: String,
    note: Option<String>,
    channel: String,
    mitre_attack: Vec<AttackMapping>,
    cpu_register: Option<String>,
    address: Option<u64>,
    match_string: Option<String>,
    match_offset: Option<u64>,
    matched_bytes_hex: Option<String>,
    matched_bytes_ascii: Option<String>,
}

#[derive(Serialize)]
struct RegionMeta {
    start: u64,
    len: usize,
    file: String,
}

#[derive(Debug, Clone)]
enum TargetScope {
    Samples(PathBuf),
    Pids(HashSet<u32>),
    AllNonSystem,
}

fn main() {
    let args = Cli::parse();

    if args.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    let scanner = match YaraScanner::load_from_dir(&args.rules_dir) {
        Some(scanner) => scanner,
        None => {
            eprintln!("Failed to load YARA rules from {:?}.", args.rules_dir);
            return;
        }
    };

    fs::create_dir_all(&args.artifacts_dir).ok();

    let target_scope = resolve_target_scope(&args);
    info!("Target scope: {}", describe_target_scope(&target_scope));

    let mut last_scan: HashMap<ProcessKey, Instant> = HashMap::new();
    let mut seen_hits: HashSet<HitKey> = HashSet::new();
    let mut seen_static: HashSet<(ProcessKey, PathBuf)> = HashSet::new();
    let mut terminated: HashSet<ProcessKey> = HashSet::new();

    loop {
        let processes = match read_processes() {
            Ok(value) => value,
            Err(err) => {
                warn!("Failed to read /proc: {}", err);
                thread::sleep(Duration::from_millis(args.scan_interval_ms));
                continue;
            }
        };

        let roots = find_root_processes(&processes, &target_scope);
        let tracked = match &target_scope {
            TargetScope::AllNonSystem => roots,
            _ => expand_children(&processes, &roots),
        };
        let tracked_keys: HashSet<ProcessKey> = tracked
            .iter()
            .filter_map(|pid| processes.get(pid).map(ProcessInfo::key))
            .collect();

        last_scan.retain(|key, _| tracked_keys.contains(key));
        seen_hits.retain(|hit| tracked_keys.contains(&hit.process));
        seen_static.retain(|(key, _)| tracked_keys.contains(key));
        terminated.retain(|key| tracked_keys.contains(key));

        for pid in tracked.iter().copied() {
            if let Some(info) = processes.get(&pid) {
                let key = info.key();
                for static_target in static_scan_targets(info, &target_scope) {
                    if !seen_static.insert((key, static_target.clone())) {
                        continue;
                    }

                    let hits = scanner.scan_file(&static_target, "FILE");
                    if !hits.is_empty() {
                        write_snapshot(
                            info,
                            &hits,
                            &[],
                            &args.artifacts_dir,
                            "static",
                            args.save_maps,
                            args.dump_regions,
                        );
                        let mut has_new_hit = false;
                        for hit in hits {
                            if seen_hits.insert(HitKey {
                                process: key,
                                rule: hit.value,
                                channel: hit.register,
                                cpu_register: hit.cpu_register,
                            }) {
                                has_new_hit = true;
                            }
                        }
                        if args.stop_on_hit && has_new_hit && !terminated.contains(&key) {
                            if terminate_process(info.pid) {
                                terminated.insert(key);
                                info!(
                                    "Stopped pid {} after static hit(s) (--stop-on-hit)",
                                    info.pid
                                );
                            }
                        }
                    }
                }
            }
        }

        for pid in tracked.iter().copied() {
            let info = match processes.get(&pid) {
                Some(value) => value,
                None => continue,
            };

            let now = Instant::now();
            let process_key = info.key();
            if let Some(last) = last_scan.get(&process_key) {
                if now.duration_since(*last).as_millis() < args.scan_interval_ms as u128 {
                    continue;
                }
            }
            last_scan.insert(process_key, now);

            match scan_process(
                info,
                process_key,
                &scanner,
                &args.artifacts_dir,
                args.max_region_bytes,
                args.max_total_bytes,
                args.save_maps,
                args.dump_regions,
                &mut seen_hits,
            ) {
                Ok(has_new_hits) => {
                    if args.stop_on_hit && has_new_hits && !terminated.contains(&process_key) {
                        if terminate_process(info.pid) {
                            terminated.insert(process_key);
                            info!(
                                "Stopped pid {} after memory/register hit(s) (--stop-on-hit)",
                                info.pid
                            );
                        }
                    }
                }
                Err(err) => {
                    warn!("Scan failed for pid {}: {}", pid, err);
                }
            }
        }

        if args.once {
            break;
        }
        thread::sleep(Duration::from_millis(args.scan_interval_ms));
    }
}

fn scan_process(
    info: &ProcessInfo,
    process_key: ProcessKey,
    scanner: &YaraScanner,
    artifacts_dir: &Path,
    max_region_bytes: usize,
    max_total_bytes: usize,
    save_maps: bool,
    dump_regions: bool,
    seen_hits: &mut HashSet<HitKey>,
) -> std::io::Result<bool> {
    let maps_path = format!("/proc/{}/maps", info.pid);
    let maps_text = fs::read_to_string(&maps_path)?;
    let regions = parse_maps(&maps_text);

    let mem_path = format!("/proc/{}/mem", info.pid);
    let mem = match File::open(&mem_path) {
        Ok(file) => file,
        Err(err) => {
            return Err(err);
        }
    };

    let mut total_read = 0usize;
    let mut region_dumps = Vec::new();
    let mut hits_all = Vec::new();
    let syscall_registers = read_syscall_registers(info.pid).unwrap_or_default();
    hits_all.extend(scan_register_pointer_hits(&mem, scanner, &syscall_registers));

    for region in regions {
        if !region.perms.starts_with('r') {
            continue;
        }
        if total_read >= max_total_bytes {
            break;
        }
        let region_len = (region.end - region.start) as usize;
        let read_len = region_len
            .min(max_region_bytes)
            .min(max_total_bytes.saturating_sub(total_read));
        if read_len == 0 {
            continue;
        }

        let mut buf = vec![0u8; read_len];
        let read = match mem.read_at(&mut buf, region.start) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if read == 0 {
            continue;
        }
        buf.truncate(read);
        total_read += read;

        let mut hits = scanner.scan_bytes(&buf, "MEM", Some(region.start), None);
        annotate_hits_with_registers(&mut hits, &syscall_registers);
        if hits.is_empty() {
            continue;
        }

        hits_all.extend(hits.clone());
        if dump_regions {
            region_dumps.push((region.start, buf));
        }
    }

    let new_hits: Vec<_> = hits_all
        .into_iter()
        .filter(|hit| {
            seen_hits.insert(HitKey {
                process: process_key,
                rule: hit.value.clone(),
                channel: hit.register.clone(),
                cpu_register: hit.cpu_register.clone(),
            })
        })
        .collect();

    if new_hits.is_empty() {
        return Ok(false);
    }

    write_snapshot(
        info,
        &new_hits,
        &region_dumps,
        artifacts_dir,
        "memory",
        save_maps,
        dump_regions,
    );

    Ok(true)
}

fn terminate_process(pid: u32) -> bool {
    let proc_path = format!("/proc/{}", pid);
    if !Path::new(&proc_path).exists() {
        return true;
    }

    let status = Command::new("kill")
        .arg("-KILL")
        .arg(pid.to_string())
        .status();

    match status {
        Ok(value) if value.success() => true,
        Ok(value) => {
            if !Path::new(&proc_path).exists() {
                return true;
            }
            warn!("Failed to stop pid {} with kill -KILL (status: {})", pid, value);
            false
        }
        Err(err) => {
            if !Path::new(&proc_path).exists() {
                return true;
            }
            warn!("Failed to execute kill for pid {}: {}", pid, err);
            false
        }
    }
}

fn write_snapshot(
    info: &ProcessInfo,
    hits: &[rtrace::detectors::DetectedPattern],
    region_dumps: &[(u64, Vec<u8>)],
    artifacts_dir: &Path,
    tag: &str,
    save_maps: bool,
    dump_regions: bool,
) {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_millis();

    let snapshot_dir = artifacts_dir.join(format!("{}_pid{}_{}", timestamp, info.pid, tag));
    if let Err(err) = fs::create_dir_all(&snapshot_dir) {
        warn!("Failed to create snapshot dir {:?}: {}", snapshot_dir, err);
        return;
    }

    let mut region_meta = Vec::new();
    if dump_regions {
        for (start, data) in region_dumps {
            let file_name = format!("region_{:x}_{}.bin", start, data.len());
            let path = snapshot_dir.join(&file_name);
            if let Err(err) = fs::write(&path, data) {
                warn!("Failed to write region dump {:?}: {}", path, err);
                continue;
            }
            region_meta.push(RegionMeta {
                start: *start,
                len: data.len(),
                file: file_name,
            });
        }
    }

    let meta = SnapshotMeta {
        timestamp_ms: timestamp,
        pid: info.pid,
        ppid: info.ppid,
        uid: info.uid,
        process_start_time_ticks: info.start_time_ticks,
        exe: info.exe.to_string_lossy().to_string(),
        comm: info.comm.clone(),
        cmdline: info.cmdline.clone(),
        hits: hits.iter().map(hit_to_meta).collect(),
        regions: region_meta,
    };

    let meta_path = snapshot_dir.join("meta.json");
    if let Ok(json) = serde_json::to_string_pretty(&meta) {
        let _ = fs::write(meta_path, json);
    }

    if save_maps {
        let maps_path = format!("/proc/{}/maps", info.pid);
        if let Ok(maps) = fs::read_to_string(maps_path) {
            let _ = fs::write(snapshot_dir.join("maps.txt"), maps);
        }
    }

    info!(
        "Snapshot created for pid {} with {} hits at {:?}",
        info.pid,
        hits.len(),
        snapshot_dir
    );
}

fn hit_to_meta(hit: &rtrace::detectors::DetectedPattern) -> HitMeta {
    HitMeta {
        rule: hit.value.clone(),
        class: hit.source.clone().unwrap_or_else(|| "unknown".to_string()),
        note: hit.note.clone(),
        channel: hit.register.clone(),
        mitre_attack: hit.mitre_attack.clone(),
        cpu_register: hit.cpu_register.clone(),
        address: hit.address,
        match_string: hit.match_string.clone(),
        match_offset: hit.match_offset,
        matched_bytes_hex: hit.matched_bytes_hex.clone(),
        matched_bytes_ascii: hit.matched_bytes_ascii.clone(),
    }
}

fn read_processes() -> std::io::Result<HashMap<u32, ProcessInfo>> {
    let mut out = HashMap::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let pid = match file_name.to_string_lossy().parse::<u32>() {
            Ok(value) => value,
            Err(_) => continue,
        };

        let exe = match fs::read_link(format!("/proc/{}/exe", pid)) {
            Ok(path) => path,
            Err(_) => continue,
        };
        let comm = fs::read_to_string(format!("/proc/{}/comm", pid))
            .unwrap_or_else(|_| String::from("unknown"))
            .trim()
            .to_string();
        let (cmdline_args, cmdline) = read_cmdline(pid);
        let (ppid, start_time_ticks) = read_proc_stat(pid).unwrap_or((0, 0));
        let uid = read_proc_uid(pid).unwrap_or(0);

        out.insert(
            pid,
            ProcessInfo {
                pid,
                ppid,
                uid,
                start_time_ticks,
                exe,
                comm,
                cmdline_args,
                cmdline,
            },
        );
    }
    Ok(out)
}

fn read_cmdline(pid: u32) -> (Vec<String>, String) {
    let path = format!("/proc/{}/cmdline", pid);
    match fs::read(path) {
        Ok(data) => {
            let args: Vec<String> = data
                .split(|b| *b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect();
            let cmdline = args.join(" ");
            (args, cmdline)
        }
        Err(_) => (Vec::new(), String::new()),
    }
}

fn read_proc_stat(pid: u32) -> Option<(u32, u64)> {
    let stat = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    parse_proc_stat(&stat)
}

fn read_proc_uid(pid: u32) -> Option<u32> {
    let status = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in status.lines() {
        if !line.starts_with("Uid:") {
            continue;
        }
        let mut parts = line.split_whitespace();
        parts.next()?;
        return parts.next()?.parse::<u32>().ok();
    }
    None
}

fn parse_proc_stat(stat: &str) -> Option<(u32, u64)> {
    let end = stat.rfind(')')?;
    let after = stat.get(end + 2..)?;
    let mut parts = after.split_whitespace();
    parts.next()?;
    let ppid: u32 = parts.next()?.parse().ok()?;
    let start_time_ticks: u64 = parts.nth(17)?.parse().ok()?;
    Some((ppid, start_time_ticks))
}

fn read_syscall_registers(pid: u32) -> std::io::Result<HashMap<String, u64>> {
    let path = format!("/proc/{}/syscall", pid);
    let text = fs::read_to_string(path)?;
    Ok(parse_syscall_registers(&text))
}

fn parse_syscall_registers(text: &str) -> HashMap<String, u64> {
    let mut out = HashMap::new();
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed == "running" {
        return out;
    }

    let tokens: Vec<&str> = trimmed.split_whitespace().collect();
    if tokens.len() < 10 {
        return out;
    }

    let names = ["RIP", "RSP", "RAX", "RDI", "RSI", "RDX", "R10", "R8", "R9"];
    for (idx, name) in names.iter().enumerate() {
        if let Some(value) = parse_u64_auto(tokens[idx + 1]) {
            out.insert((*name).to_string(), value);
        }
    }

    out
}

fn parse_u64_auto(token: &str) -> Option<u64> {
    if let Some(hex) = token.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    token.parse::<u64>().ok()
}

fn annotate_hits_with_registers(
    hits: &mut [rtrace::detectors::DetectedPattern],
    registers: &HashMap<String, u64>,
) {
    for hit in hits {
        let address = match hit.address {
            Some(value) => value,
            None => continue,
        };

        let mut exact_match: Option<String> = None;
        let mut closest_ptr: Option<(String, u64)> = None;
        for (name, value) in registers {
            if *value == address {
                exact_match = Some(name.clone());
                break;
            }

            if *value < address {
                let delta = address - *value;
                if delta <= 256 {
                    if let Some((_, best_delta)) = &closest_ptr {
                        if delta < *best_delta {
                            closest_ptr = Some((name.clone(), delta));
                        }
                    } else {
                        closest_ptr = Some((name.clone(), delta));
                    }
                }
            }
        }

        if let Some(reg) = exact_match {
            hit.cpu_register = Some(reg);
            continue;
        }

        if let Some((reg, delta)) = closest_ptr {
            if delta == 0 {
                hit.cpu_register = Some(reg);
            } else {
                hit.cpu_register = Some(format!("{}+{}", reg, delta));
            }
        }
    }
}

fn scan_register_pointer_hits(
    mem: &File,
    scanner: &YaraScanner,
    registers: &HashMap<String, u64>,
) -> Vec<rtrace::detectors::DetectedPattern> {
    let mut out = Vec::new();
    for (reg, addr) in registers {
        if *addr == 0 {
            continue;
        }

        let mut buf = vec![0u8; REGISTER_SCAN_MAX_BYTES];
        let read = match mem.read_at(&mut buf, *addr) {
            Ok(value) => value,
            Err(_) => continue,
        };
        if read == 0 {
            continue;
        }
        buf.truncate(read);

        let mut hits = scanner.scan_bytes(&buf, "REG", Some(*addr), None);
        if hits.is_empty() {
            continue;
        }
        for hit in &mut hits {
            hit.cpu_register = Some(reg.clone());
        }
        out.extend(hits);
    }
    out
}

fn resolve_target_scope(args: &Cli) -> TargetScope {
    if !args.pid.is_empty() {
        let pids: HashSet<u32> = args.pid.iter().copied().collect();
        return TargetScope::Pids(pids);
    }

    if let Some(samples_dir) = &args.samples_dir {
        return TargetScope::Samples(samples_dir.clone());
    }

    TargetScope::AllNonSystem
}

fn describe_target_scope(scope: &TargetScope) -> String {
    match scope {
        TargetScope::Samples(path) => format!("samples-dir ({})", path.to_string_lossy()),
        TargetScope::Pids(pids) => {
            let mut list: Vec<u32> = pids.iter().copied().collect();
            list.sort_unstable();
            format!("pid ({:?})", list)
        }
        TargetScope::AllNonSystem => "all-non-system".to_string(),
    }
}

fn is_sample_path(path: &Path, samples_dir: &Path) -> bool {
    path.is_absolute() && path.starts_with(samples_dir)
}

fn is_sample_target_path(path: &Path, samples_dir: &Path) -> bool {
    if !is_sample_path(path, samples_dir) {
        return false;
    }
    match fs::metadata(path) {
        Ok(meta) => !meta.is_dir(),
        Err(_) => true,
    }
}

fn is_agent_binary_path(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == "rtrace-agent")
        .unwrap_or(false)
}

fn process_references_samples(info: &ProcessInfo, samples_dir: &Path) -> bool {
    if is_sample_path(&info.exe, samples_dir) && !is_agent_binary_path(&info.exe) {
        return true;
    }

    info.cmdline_args
        .iter()
        .map(Path::new)
        .any(|path| is_sample_target_path(path, samples_dir) && !is_agent_binary_path(path))
}

fn is_agent_process(info: &ProcessInfo) -> bool {
    if info.comm == "rtrace-agent" {
        return true;
    }

    let exe_name_is_agent = info
        .exe
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name == "rtrace-agent")
        .unwrap_or(false);
    if exe_name_is_agent {
        return true;
    }

    info.cmdline_args
        .first()
        .and_then(|arg0| Path::new(arg0).file_name())
        .and_then(|name| name.to_str())
        .map(|name| name == "rtrace-agent")
        .unwrap_or(false)
}

fn static_scan_targets_for_samples(info: &ProcessInfo, samples_dir: &Path) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    if is_sample_path(&info.exe, samples_dir) && !is_agent_binary_path(&info.exe) {
        targets.push(info.exe.clone());
    }

    for arg in &info.cmdline_args {
        let path = PathBuf::from(arg);
        if !is_sample_target_path(&path, samples_dir) || is_agent_binary_path(&path) {
            continue;
        }
        if targets.iter().any(|target| target == &path) {
            continue;
        }
        targets.push(path);
    }
    targets
}

fn static_scan_targets_for_process(info: &ProcessInfo) -> Vec<PathBuf> {
    if is_agent_binary_path(&info.exe) {
        return Vec::new();
    }
    match fs::metadata(&info.exe) {
        Ok(meta) if meta.is_file() => vec![info.exe.clone()],
        _ => Vec::new(),
    }
}

fn static_scan_targets(info: &ProcessInfo, scope: &TargetScope) -> Vec<PathBuf> {
    match scope {
        TargetScope::Samples(samples_dir) => static_scan_targets_for_samples(info, samples_dir),
        TargetScope::Pids(_) => static_scan_targets_for_process(info),
        TargetScope::AllNonSystem => {
            let exe = info.exe.to_string_lossy();
            if is_non_system_root_path(&exe) {
                static_scan_targets_for_process(info)
            } else {
                Vec::new()
            }
        }
    }
}

fn find_root_processes(processes: &HashMap<u32, ProcessInfo>, scope: &TargetScope) -> HashSet<u32> {
    match scope {
        TargetScope::Samples(samples_dir) => find_sample_processes(processes, samples_dir),
        TargetScope::Pids(pids) => pids
            .iter()
            .copied()
            .filter(|pid| processes.contains_key(pid))
            .collect(),
        TargetScope::AllNonSystem => find_non_system_processes(processes),
    }
}

fn find_sample_processes(processes: &HashMap<u32, ProcessInfo>, samples_dir: &Path) -> HashSet<u32> {
    processes
        .iter()
        .filter_map(|(pid, info)| {
            if is_agent_process(info) {
                return None;
            }
            if process_references_samples(info, samples_dir) {
                return Some(*pid);
            }
            None
        })
        .collect()
}

fn find_non_system_processes(processes: &HashMap<u32, ProcessInfo>) -> HashSet<u32> {
    processes
        .iter()
        .filter_map(|(pid, info)| {
            if is_likely_system_process(info) {
                None
            } else {
                Some(*pid)
            }
        })
        .collect()
}

fn is_likely_system_process(info: &ProcessInfo) -> bool {
    if is_agent_process(info) {
        return true;
    }

    if info.pid <= 2 {
        return true;
    }

    if is_known_system_comm(&info.comm) {
        return true;
    }

    if info.uid >= 1000 {
        return false;
    }

    let exe = info.exe.to_string_lossy();
    if is_non_system_root_path(&exe) {
        return false;
    }

    exe.starts_with("/usr/")
        || exe.starts_with("/bin/")
        || exe.starts_with("/sbin/")
        || exe.starts_with("/lib/")
        || exe.starts_with("/lib64/")
        || exe.starts_with("/snap/")
        || info.ppid == 1
}

fn is_non_system_root_path(exe: &str) -> bool {
    exe.starts_with("/samples/")
        || exe.starts_with("/home/")
        || exe.starts_with("/root/")
        || exe.starts_with("/tmp/")
        || exe.starts_with("/var/tmp/")
        || exe.starts_with("/dev/shm/")
        || exe.starts_with("/mnt/")
}

fn is_known_system_comm(comm: &str) -> bool {
    matches!(
        comm,
        "systemd"
            | "systemd-journal"
            | "systemd-udevd"
            | "dbus-daemon"
            | "cron"
            | "sshd"
            | "agetty"
            | "rsyslogd"
            | "snapd"
            | "polkitd"
            | "udisksd"
            | "ModemManager"
            | "whoopsie"
            | "NetworkManager"
            | "systemd-logind"
            | "systemd-resolve"
            | "systemd-timesyn"
            | "unattended-upgr"
            | "containerd"
            | "dockerd"
    )
}

fn expand_children(processes: &HashMap<u32, ProcessInfo>, roots: &HashSet<u32>) -> HashSet<u32> {
    let mut tracked = roots.clone();
    loop {
        let mut added = false;
        for (pid, info) in processes {
            if tracked.contains(pid) {
                continue;
            }
            if tracked.contains(&info.ppid) {
                tracked.insert(*pid);
                added = true;
            }
        }
        if !added {
            break;
        }
    }
    tracked
}

fn parse_maps(contents: &str) -> Vec<MemoryRegion> {
    let mut regions = Vec::new();
    for line in contents.lines() {
        let mut parts = line.split_whitespace();
        let range = match parts.next() {
            Some(value) => value,
            None => continue,
        };
        let perms = match parts.next() {
            Some(value) => value.to_string(),
            None => continue,
        };

        let mut range_it = range.split('-');
        let start = match range_it
            .next()
            .and_then(|v| u64::from_str_radix(v, 16).ok())
        {
            Some(value) => value,
            None => continue,
        };
        let end = match range_it
            .next()
            .and_then(|v| u64::from_str_radix(v, 16).ok())
        {
            Some(value) => value,
            None => continue,
        };

        regions.push(MemoryRegion { start, end, perms });
    }
    regions
}

#[cfg(test)]
mod tests {
    use super::*;
    use rtrace::detectors::{DetectedPattern, PatternType, Severity};
    use tempfile::tempdir;

    #[test]
    fn parse_proc_stat_extracts_ppid_and_start_time() {
        let stat = "1234 (bash) S 42 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 999 24 25";
        let parsed = parse_proc_stat(stat).expect("stat should parse");
        assert_eq!(parsed.0, 42);
        assert_eq!(parsed.1, 999);
    }

    #[test]
    fn parse_maps_skips_invalid_lines() {
        let maps = "\
00400000-00452000 r-xp 00000000 08:02 12345 /bin/cat
broken line
7ffc12345000-7ffc12367000 rw-p 00000000 00:00 0 [stack]
";
        let regions = parse_maps(maps);
        assert_eq!(regions.len(), 2);
        assert_eq!(regions[0].start, 0x0040_0000);
        assert_eq!(regions[0].end, 0x0045_2000);
        assert_eq!(regions[0].perms, "r-xp");
        assert_eq!(regions[1].start, 0x7ffc_1234_5000);
        assert_eq!(regions[1].end, 0x7ffc_1236_7000);
        assert_eq!(regions[1].perms, "rw-p");
    }

    #[test]
    fn find_sample_processes_matches_cmdline_script() {
        let tmp = tempdir().expect("temp dir");
        let samples_dir = tmp.path().join("samples");
        fs::create_dir_all(&samples_dir).expect("samples dir");
        let script_path = samples_dir.join("payload.sh");
        fs::write(&script_path, "#!/usr/bin/env bash\necho test\n").expect("script");

        let mut processes = HashMap::new();
        processes.insert(
            100,
            ProcessInfo {
                pid: 100,
                ppid: 1,
                uid: 1000,
                start_time_ticks: 11,
                exe: PathBuf::from("/usr/bin/bash"),
                comm: "bash".to_string(),
                cmdline_args: vec![
                    "/usr/bin/bash".to_string(),
                    script_path.to_string_lossy().to_string(),
                ],
                cmdline: format!("/usr/bin/bash {}", script_path.to_string_lossy()),
            },
        );

        let roots = find_sample_processes(&processes, &samples_dir);
        assert!(roots.contains(&100));

        let info = processes.get(&100).expect("process exists");
        let scope = TargetScope::Samples(samples_dir.clone());
        let targets = static_scan_targets(info, &scope);
        assert_eq!(targets, vec![script_path]);
    }

    #[test]
    fn find_sample_processes_ignores_samples_directory_argument() {
        let tmp = tempdir().expect("temp dir");
        let samples_dir = tmp.path().join("samples");
        fs::create_dir_all(&samples_dir).expect("samples dir");

        let mut processes = HashMap::new();
        processes.insert(
            200,
            ProcessInfo {
                pid: 200,
                ppid: 1,
                uid: 0,
                start_time_ticks: 22,
                exe: PathBuf::from("/opt/rtrace-agent"),
                comm: "rtrace-agent".to_string(),
                cmdline_args: vec![
                    "/opt/rtrace-agent".to_string(),
                    "--samples-dir".to_string(),
                    samples_dir.to_string_lossy().to_string(),
                ],
                cmdline: format!(
                    "/opt/rtrace-agent --samples-dir {}",
                    samples_dir.to_string_lossy()
                ),
            },
        );

        let roots = find_sample_processes(&processes, &samples_dir);
        assert!(!roots.contains(&200));
    }

    #[test]
    fn find_sample_processes_ignores_agent_binary_in_samples() {
        let tmp = tempdir().expect("temp dir");
        let samples_dir = tmp.path().join("samples");
        fs::create_dir_all(&samples_dir).expect("samples dir");
        let agent_path = samples_dir.join("rtrace-agent");
        fs::write(&agent_path, "stub").expect("agent file");

        let mut processes = HashMap::new();
        processes.insert(
            300,
            ProcessInfo {
                pid: 300,
                ppid: 1,
                uid: 0,
                start_time_ticks: 33,
                exe: agent_path.clone(),
                comm: "rtrace-agent".to_string(),
                cmdline_args: vec![
                    agent_path.to_string_lossy().to_string(),
                    "--samples-dir".to_string(),
                    samples_dir.to_string_lossy().to_string(),
                ],
                cmdline: format!(
                    "{} --samples-dir {}",
                    agent_path.to_string_lossy(),
                    samples_dir.to_string_lossy()
                ),
            },
        );

        let roots = find_sample_processes(&processes, &samples_dir);
        assert!(!roots.contains(&300));
    }

    #[test]
    fn find_sample_processes_ignores_wrapper_pointing_to_agent_binary() {
        let tmp = tempdir().expect("temp dir");
        let samples_dir = tmp.path().join("samples");
        fs::create_dir_all(&samples_dir).expect("samples dir");
        let agent_path = samples_dir.join("rtrace-agent");
        fs::write(&agent_path, "stub").expect("agent file");

        let mut processes = HashMap::new();
        processes.insert(
            400,
            ProcessInfo {
                pid: 400,
                ppid: 1,
                uid: 1000,
                start_time_ticks: 44,
                exe: PathBuf::from("/usr/bin/timeout"),
                comm: "timeout".to_string(),
                cmdline_args: vec![
                    "/usr/bin/timeout".to_string(),
                    "8".to_string(),
                    agent_path.to_string_lossy().to_string(),
                ],
                cmdline: format!("/usr/bin/timeout 8 {}", agent_path.to_string_lossy()),
            },
        );

        let roots = find_sample_processes(&processes, &samples_dir);
        assert!(!roots.contains(&400));
    }

    #[test]
    fn find_non_system_processes_keeps_user_and_suspicious_root_paths() {
        let mut processes = HashMap::new();
        processes.insert(
            10,
            ProcessInfo {
                pid: 10,
                ppid: 1,
                uid: 0,
                start_time_ticks: 10,
                exe: PathBuf::from("/usr/sbin/sshd"),
                comm: "sshd".to_string(),
                cmdline_args: vec!["/usr/sbin/sshd".to_string()],
                cmdline: "/usr/sbin/sshd".to_string(),
            },
        );
        processes.insert(
            500,
            ProcessInfo {
                pid: 500,
                ppid: 1,
                uid: 1000,
                start_time_ticks: 20,
                exe: PathBuf::from("/usr/bin/python3"),
                comm: "python3".to_string(),
                cmdline_args: vec!["/usr/bin/python3".to_string(), "script.py".to_string()],
                cmdline: "/usr/bin/python3 script.py".to_string(),
            },
        );
        processes.insert(
            501,
            ProcessInfo {
                pid: 501,
                ppid: 1,
                uid: 0,
                start_time_ticks: 21,
                exe: PathBuf::from("/tmp/dropper"),
                comm: "dropper".to_string(),
                cmdline_args: vec!["/tmp/dropper".to_string()],
                cmdline: "/tmp/dropper".to_string(),
            },
        );

        let roots = find_non_system_processes(&processes);
        assert!(!roots.contains(&10));
        assert!(roots.contains(&500));
        assert!(roots.contains(&501));
    }

    #[test]
    fn static_scan_targets_in_all_mode_skip_standard_system_paths() {
        let info_usr = ProcessInfo {
            pid: 600,
            ppid: 1,
            uid: 1000,
            start_time_ticks: 1,
            exe: PathBuf::from("/usr/bin/bash"),
            comm: "bash".to_string(),
            cmdline_args: vec!["/usr/bin/bash".to_string()],
            cmdline: "/usr/bin/bash".to_string(),
        };
        let scope = TargetScope::AllNonSystem;
        assert!(static_scan_targets(&info_usr, &scope).is_empty());

        let tmp_base = std::env::temp_dir();
        let sample = tmp_base.join("rtrace_test_dropper_static_scan");
        fs::write(&sample, "stub").expect("sample file");
        let info_tmp = ProcessInfo {
            pid: 601,
            ppid: 1,
            uid: 0,
            start_time_ticks: 2,
            exe: sample.clone(),
            comm: "dropper".to_string(),
            cmdline_args: vec!["/tmp/dropper".to_string()],
            cmdline: "/tmp/dropper".to_string(),
        };
        let targets = static_scan_targets(&info_tmp, &scope);
        assert_eq!(targets, vec![sample.clone()]);
        fs::remove_file(sample).ok();
    }

    #[test]
    fn parse_syscall_registers_reads_expected_x86_64_fields() {
        let line = "1 0x400123 0x7fff0000 0x0 0x1111 0x2222 0x3333 0x4444 0x5555 0x6666";
        let regs = parse_syscall_registers(line);
        assert_eq!(regs.get("RIP").copied(), Some(0x400123));
        assert_eq!(regs.get("RSP").copied(), Some(0x7fff0000));
        assert_eq!(regs.get("RDI").copied(), Some(0x1111));
        assert_eq!(regs.get("RSI").copied(), Some(0x2222));
        assert_eq!(regs.get("RDX").copied(), Some(0x3333));
        assert_eq!(regs.get("R10").copied(), Some(0x4444));
        assert_eq!(regs.get("R8").copied(), Some(0x5555));
        assert_eq!(regs.get("R9").copied(), Some(0x6666));
    }

    #[test]
    fn annotate_hits_with_registers_sets_exact_or_offset_register() {
        let mut regs = HashMap::new();
        regs.insert("RDI".to_string(), 0x1000);
        regs.insert("RSI".to_string(), 0x2000);

        let mut hits = vec![
            DetectedPattern {
                pattern_type: PatternType::YaraRule,
                value: "t1".to_string(),
                register: "MEM".to_string(),
                cpu_register: None,
                address: Some(0x1000),
                match_string: None,
                match_offset: None,
                matched_bytes_hex: None,
                matched_bytes_ascii: None,
                syscall_name: None,
                source: None,
                note: None,
                mitre_attack: Vec::new(),
                severity: Severity::Medium,
            },
            DetectedPattern {
                pattern_type: PatternType::YaraRule,
                value: "t2".to_string(),
                register: "MEM".to_string(),
                cpu_register: None,
                address: Some(0x2010),
                match_string: None,
                match_offset: None,
                matched_bytes_hex: None,
                matched_bytes_ascii: None,
                syscall_name: None,
                source: None,
                note: None,
                mitre_attack: Vec::new(),
                severity: Severity::Medium,
            },
        ];

        annotate_hits_with_registers(&mut hits, &regs);
        assert_eq!(hits[0].cpu_register.as_deref(), Some("RDI"));
        assert_eq!(hits[1].cpu_register.as_deref(), Some("RSI+16"));
    }
}
