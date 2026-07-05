use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempfile;

const DEFAULT_FSCK_TIMEOUT_SECS: u64 = 30;
const DEFAULT_MAX_OUTPUT_BYTES: usize = 1024 * 1024;

/// Limits applied to a single fsck.erofs execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecLimits {
    pub timeout: Duration,
    pub max_output_bytes: usize,
    pub kill_process_group: bool,
    pub rss_limit_mb: Option<u64>,
}

impl Default for ExecLimits {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_FSCK_TIMEOUT_SECS),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            kill_process_group: true,
            rss_limit_mb: None,
        }
    }
}

/// Result of invoking fsck.erofs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FsckResult {
    pub exit_code: i32,
    pub signal: Option<i32>,
    pub timed_out: bool,
    pub killed_process_group: bool,
    pub rss_limit_mb: Option<u64>,
    pub peak_rss_kb: Option<u64>,
    pub cgroup_v2: bool,
    pub cgroup_oom_delta: Option<u64>,
    pub cgroup_oom_kill_delta: Option<u64>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub classification: String,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct CgroupMemoryEvents {
    oom: u64,
    oom_kill: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ProcessUsage {
    peak_rss_kb: Option<u64>,
}

/// Run fsck.erofs against an image.
pub fn run_fsck<A: AsRef<Path>, B: AsRef<Path>>(
    fsck_path: A,
    image_path: B,
    extra_args: &[String],
) -> Result<FsckResult> {
    run_fsck_with_limits(fsck_path, image_path, extra_args, ExecLimits::default())
}

/// Run fsck.erofs against an image with an explicit timeout.
pub fn run_fsck_with_timeout<A: AsRef<Path>, B: AsRef<Path>>(
    fsck_path: A,
    image_path: B,
    extra_args: &[String],
    timeout: Duration,
) -> Result<FsckResult> {
    run_fsck_with_limits(
        fsck_path,
        image_path,
        extra_args,
        ExecLimits {
            timeout,
            ..ExecLimits::default()
        },
    )
}

/// Run fsck.erofs against an image with explicit execution limits.
pub fn run_fsck_with_limits<A: AsRef<Path>, B: AsRef<Path>>(
    fsck_path: A,
    image_path: B,
    extra_args: &[String],
    limits: ExecLimits,
) -> Result<FsckResult> {
    let mut stdout_file = tempfile().context("failed to create fsck stdout tempfile")?;
    let mut stderr_file = tempfile().context("failed to create fsck stderr tempfile")?;
    let child_stdout = stdout_file
        .try_clone()
        .context("failed to clone fsck stdout tempfile")?;
    let child_stderr = stderr_file
        .try_clone()
        .context("failed to clone fsck stderr tempfile")?;

    let mut cmd = Command::new(fsck_path.as_ref());
    cmd.args(extra_args)
        .arg(image_path.as_ref())
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::from(child_stderr));
    configure_process_group(&mut cmd, limits.kill_process_group);
    configure_memory_limit(&mut cmd, limits.rss_limit_mb)?;

    let cgroup_before = read_cgroup_v2_memory_events();
    let mut child = cmd.spawn().with_context(|| {
        format!(
            "failed to execute fsck.erofs ({})",
            fsck_path.as_ref().display()
        )
    })?;

    let (status, timed_out, killed_process_group, usage) = wait_for_child(
        &mut child,
        limits.timeout,
        limits.kill_process_group,
        fsck_path.as_ref(),
    )
    .with_context(|| {
        format!(
            "failed to collect fsck.erofs status for {}",
            image_path.as_ref().display()
        )
    })?;
    let cgroup_after = read_cgroup_v2_memory_events();
    let cgroup_delta = cgroup_event_delta(cgroup_before, cgroup_after);

    let (stdout, stdout_truncated) = read_limited_output(
        &mut stdout_file,
        limits.max_output_bytes,
        "stdout",
        image_path.as_ref(),
    )?;
    let (stderr, stderr_truncated) = read_limited_output(
        &mut stderr_file,
        limits.max_output_bytes,
        "stderr",
        image_path.as_ref(),
    )?;
    let signal = if timed_out {
        None
    } else {
        exit_signal(&status)
    };
    let exit_code = if timed_out {
        124
    } else {
        status
            .code()
            .or_else(|| signal.map(|signal| 128 + signal))
            .unwrap_or(-1)
    };

    let (classification, reason) = classify_fsck_execution(
        exit_code,
        signal,
        timed_out,
        limits.rss_limit_mb,
        cgroup_delta,
        &stderr,
        &stdout,
    );

    Ok(FsckResult {
        exit_code,
        signal,
        timed_out,
        killed_process_group,
        rss_limit_mb: limits.rss_limit_mb,
        peak_rss_kb: usage.peak_rss_kb,
        cgroup_v2: cgroup_before.is_some() && cgroup_after.is_some(),
        cgroup_oom_delta: cgroup_delta.map(|events| events.oom),
        cgroup_oom_kill_delta: cgroup_delta.map(|events| events.oom_kill),
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        classification: classification.to_string(),
        reason: reason.to_string(),
    })
}

fn read_limited_output(
    file: &mut File,
    max_output_bytes: usize,
    stream: &str,
    image_path: &Path,
) -> Result<(String, bool)> {
    file.seek(SeekFrom::Start(0)).with_context(|| {
        format!(
            "failed to seek fsck {stream} tempfile for {}",
            image_path.display()
        )
    })?;
    let read_limit = u64::try_from(max_output_bytes)
        .unwrap_or(u64::MAX - 1)
        .saturating_add(1);
    let mut data = Vec::new();
    file.take(read_limit)
        .read_to_end(&mut data)
        .with_context(|| {
            format!(
                "failed to read fsck {stream} tempfile for {}",
                image_path.display()
            )
        })?;

    let truncated = data.len() > max_output_bytes;
    if truncated {
        data.truncate(max_output_bytes);
    }
    let mut text = String::from_utf8_lossy(&data).to_string();
    if truncated {
        text.push_str(&format!(
            "\n[erofs-rs: fsck {stream} truncated to {max_output_bytes} bytes]\n"
        ));
    }
    Ok((text, truncated))
}

fn wait_for_child(
    child: &mut Child,
    timeout: Duration,
    kill_process_group: bool,
    fsck_path: &Path,
) -> Result<(ExitStatus, bool, bool, ProcessUsage)> {
    let start = Instant::now();
    let mut timed_out = false;
    let mut killed_process_group = false;
    loop {
        if let Some((status, usage)) = try_wait_with_usage(child)? {
            return Ok((status, timed_out, killed_process_group, usage));
        }
        if start.elapsed() >= timeout {
            timed_out = true;
            killed_process_group = kill_timed_out_child(child, kill_process_group);
            let (status, usage) = wait_with_usage(child, fsck_path)?;
            return Ok((status, timed_out, killed_process_group, usage));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(unix)]
fn try_wait_with_usage(child: &mut Child) -> Result<Option<(ExitStatus, ProcessUsage)>> {
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::unix::process::ExitStatusExt;

    let pid = libc::pid_t::try_from(child.id())
        .map_err(|_| anyhow::anyhow!("child pid {} does not fit pid_t", child.id()))?;
    loop {
        let mut status = 0;
        let mut usage = MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: wait4 is called for the child PID we spawned, with valid
        // pointers to status and rusage storage for libc to initialize.
        let rc = unsafe { libc::wait4(pid, &mut status, libc::WNOHANG, usage.as_mut_ptr()) };
        if rc == 0 {
            return Ok(None);
        }
        if rc == pid {
            // SAFETY: wait4 returned this child PID, so rusage has been
            // initialized by the kernel before we read it.
            let usage = unsafe { usage.assume_init() };
            return Ok(Some((
                ExitStatus::from_raw(status),
                process_usage_from_rusage(&usage),
            )));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error).context("failed to wait4 child process");
    }
}

#[cfg(unix)]
fn wait_with_usage(child: &mut Child, _fsck_path: &Path) -> Result<(ExitStatus, ProcessUsage)> {
    use std::io;
    use std::mem::MaybeUninit;
    use std::os::unix::process::ExitStatusExt;

    let pid = libc::pid_t::try_from(child.id())
        .map_err(|_| anyhow::anyhow!("child pid {} does not fit pid_t", child.id()))?;
    loop {
        let mut status = 0;
        let mut usage = MaybeUninit::<libc::rusage>::uninit();
        // SAFETY: wait4 is called for the child PID we spawned, with valid
        // pointers to status and rusage storage for libc to initialize.
        let rc = unsafe { libc::wait4(pid, &mut status, 0, usage.as_mut_ptr()) };
        if rc == pid {
            // SAFETY: wait4 returned this child PID, so rusage has been
            // initialized by the kernel before we read it.
            let usage = unsafe { usage.assume_init() };
            return Ok((
                ExitStatus::from_raw(status),
                process_usage_from_rusage(&usage),
            ));
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(error).context("failed to wait4 child process");
    }
}

#[cfg(unix)]
fn process_usage_from_rusage(usage: &libc::rusage) -> ProcessUsage {
    ProcessUsage {
        peak_rss_kb: u64::try_from(usage.ru_maxrss).ok(),
    }
}

#[cfg(not(unix))]
fn try_wait_with_usage(child: &mut Child) -> Result<Option<(ExitStatus, ProcessUsage)>> {
    Ok(child
        .try_wait()?
        .map(|status| (status, ProcessUsage { peak_rss_kb: None })))
}

#[cfg(not(unix))]
fn wait_with_usage(child: &mut Child, fsck_path: &Path) -> Result<(ExitStatus, ProcessUsage)> {
    let status = child
        .wait()
        .with_context(|| format!("failed to wait for fsck.erofs ({})", fsck_path.display()))?;
    Ok((status, ProcessUsage { peak_rss_kb: None }))
}

#[cfg(unix)]
fn exit_signal(status: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;

    status.signal()
}

#[cfg(not(unix))]
fn exit_signal(_status: &ExitStatus) -> Option<i32> {
    None
}

#[cfg(unix)]
fn configure_process_group(cmd: &mut Command, enabled: bool) {
    if enabled {
        use std::os::unix::process::CommandExt;

        cmd.process_group(0);
    }
}

#[cfg(not(unix))]
fn configure_process_group(_cmd: &mut Command, _enabled: bool) {}

#[cfg(unix)]
fn configure_memory_limit(cmd: &mut Command, rss_limit_mb: Option<u64>) -> Result<()> {
    let Some(rss_limit_mb) = rss_limit_mb else {
        return Ok(());
    };
    use std::io;
    use std::os::unix::process::CommandExt;

    let bytes = rss_limit_mb
        .checked_mul(1024 * 1024)
        .ok_or_else(|| anyhow::anyhow!("rss limit {rss_limit_mb} MiB overflows"))?;
    let limit = libc::rlim_t::try_from(bytes)
        .map_err(|_| anyhow::anyhow!("rss limit {rss_limit_mb} MiB does not fit rlim_t"))?;
    // pre_exec runs in the child after fork and before exec. Keep the closure
    // async-signal-safe and only call setrlimit with copied integer values.
    unsafe {
        cmd.pre_exec(move || {
            let rlimit = libc::rlimit {
                rlim_cur: limit,
                rlim_max: limit,
            };
            if libc::setrlimit(libc::RLIMIT_AS, &rlimit) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn configure_memory_limit(_cmd: &mut Command, _rss_limit_mb: Option<u64>) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn kill_timed_out_child(child: &mut Child, kill_process_group: bool) -> bool {
    if !kill_process_group {
        let _ = child.kill();
        return false;
    }

    let Ok(process_group) = libc::pid_t::try_from(child.id()) else {
        let _ = child.kill();
        return false;
    };
    // The child was spawned with process_group(0), so its pid is also the
    // process-group id. Kill the whole group to avoid orphaned descendants.
    let killed_group = unsafe { libc::killpg(process_group, libc::SIGKILL) == 0 };
    if !killed_group {
        let _ = child.kill();
    }
    killed_group
}

#[cfg(not(unix))]
fn kill_timed_out_child(child: &mut Child, _kill_process_group: bool) -> bool {
    let _ = child.kill();
    false
}

#[cfg(target_os = "linux")]
fn read_cgroup_v2_memory_events() -> Option<CgroupMemoryEvents> {
    let cgroup_rel = current_cgroup_v2_relative_path()?;
    let mount = cgroup_v2_mountpoint()?;
    let events = if cgroup_rel == "/" {
        mount.join("memory.events")
    } else {
        mount
            .join(cgroup_rel.trim_start_matches('/'))
            .join("memory.events")
    };
    parse_cgroup_v2_memory_events(&std::fs::read_to_string(events).ok()?)
}

#[cfg(not(target_os = "linux"))]
fn read_cgroup_v2_memory_events() -> Option<CgroupMemoryEvents> {
    None
}

#[cfg(target_os = "linux")]
fn current_cgroup_v2_relative_path() -> Option<String> {
    let content = std::fs::read_to_string("/proc/self/cgroup").ok()?;
    content.lines().find_map(|line| {
        let mut fields = line.splitn(3, ':');
        let _hierarchy = fields.next()?;
        let controllers = fields.next()?;
        let path = fields.next()?;
        controllers.is_empty().then_some(path.to_string())
    })
}

#[cfg(target_os = "linux")]
fn cgroup_v2_mountpoint() -> Option<std::path::PathBuf> {
    let content = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    content.lines().find_map(|line| {
        let (pre, post) = line.split_once(" - ")?;
        let mut post_fields = post.split_whitespace();
        let fs_type = post_fields.next()?;
        if fs_type != "cgroup2" {
            return None;
        }
        let mountpoint = pre.split_whitespace().nth(4)?;
        Some(std::path::PathBuf::from(mountpoint.replace("\\040", " ")))
    })
}

#[cfg(target_os = "linux")]
fn parse_cgroup_v2_memory_events(content: &str) -> Option<CgroupMemoryEvents> {
    let mut events = CgroupMemoryEvents::default();
    let mut saw_event = false;
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let Some(name) = fields.next() else {
            continue;
        };
        let Some(value) = fields.next().and_then(|value| value.parse::<u64>().ok()) else {
            continue;
        };
        match name {
            "oom" => {
                events.oom = value;
                saw_event = true;
            }
            "oom_kill" => {
                events.oom_kill = value;
                saw_event = true;
            }
            _ => {}
        }
    }
    saw_event.then_some(events)
}

fn cgroup_event_delta(
    before: Option<CgroupMemoryEvents>,
    after: Option<CgroupMemoryEvents>,
) -> Option<CgroupMemoryEvents> {
    let before = before?;
    let after = after?;
    Some(CgroupMemoryEvents {
        oom: after.oom.saturating_sub(before.oom),
        oom_kill: after.oom_kill.saturating_sub(before.oom_kill),
    })
}

/// Classify fsck.erofs output into consistent categories.
///
/// fsck.erofs often exits 0 even when errors were printed, so stderr is
/// inspected first.
pub fn classify_fsck_result(
    exit_code: i32,
    stderr: &str,
    stdout: &str,
) -> (&'static str, &'static str) {
    classify_fsck_execution(
        exit_code,
        None,
        exit_code == 124,
        None,
        None,
        stderr,
        stdout,
    )
}

fn classify_fsck_execution(
    exit_code: i32,
    signal: Option<i32>,
    timed_out: bool,
    rss_limit_mb: Option<u64>,
    cgroup_delta: Option<CgroupMemoryEvents>,
    stderr: &str,
    stdout: &str,
) -> (&'static str, &'static str) {
    let err = stderr.to_lowercase();
    let out = stdout.to_lowercase();
    let combined = format!("{err}\n{out}");
    let effective_signal = signal.or_else(|| exit_code_to_signal(exit_code));

    if timed_out || exit_code == 124 || err.contains("timed out") {
        return ("rejected_timeout", "fsck timed out");
    }

    let failed_or_signaled = exit_code != 0 || signal.is_some();
    if failed_or_signaled && cgroup_delta.is_some_and(|events| events.oom_kill > 0) {
        return ("rejected_oom", "cgroup v2 memory.oom_kill increased");
    }

    if failed_or_signaled && cgroup_delta.is_some_and(|events| events.oom > 0) {
        return ("rejected_oom", "cgroup v2 memory.oom increased");
    }

    if combined.contains("out of memory") || combined.contains("cannot allocate memory") {
        return ("rejected_oom", "fsck hit a memory allocation failure");
    }

    if effective_signal == Some(libc_signal("SIGKILL"))
        && (rss_limit_mb.is_some() || combined.contains("oom") || combined.contains("killed"))
    {
        return ("rejected_oom", "fsck was killed while memory-limited");
    }

    if let Some(reason) = fatal_signal_name(effective_signal, exit_code) {
        return ("rejected_crash", reason);
    }

    if let Some(reason) = signal_name(effective_signal, exit_code) {
        return ("rejected_signal", reason);
    }

    if contains_sanitizer_diagnostic(&combined) {
        return ("sanitizer_crash", "sanitizer diagnostic detected");
    }

    let has_error_keyword = [
        "error",
        "failed",
        "invalid",
        "corruption",
        "bogus",
        "not supported",
    ]
    .iter()
    .any(|k| combined.contains(k));

    if exit_code == 0 && !has_error_keyword {
        return ("accepted", "fsck accepted the image");
    }

    if err.contains("failed to verify superblock checksum") || err.contains("invalid checksum") {
        return (
            "rejected_checksum",
            "superblock checksum verification failed",
        );
    }

    if err.contains("i/o error") || err.contains("failed to read") {
        return ("rejected_io_error", "I/O error during read");
    }

    if err.contains("found some filesystem corruption")
        || err.contains("bogus")
        || err.contains("corruption")
    {
        return ("rejected_corruption", "fsck detected corruption");
    }

    if err.contains("not supported") || err.contains("invalid") {
        return ("rejected_invalid", "fsck rejected as invalid");
    }

    if exit_code != 0 {
        return ("rejected_other", "fsck rejected");
    }

    ("accepted_with_errors", "fsck exited 0 but printed errors")
}

fn fatal_signal_name(signal: Option<i32>, exit_code: i32) -> Option<&'static str> {
    match signal.or_else(|| exit_code_to_signal(exit_code)) {
        Some(signal) if signal == libc_signal("SIGABRT") => Some("fsck terminated with SIGABRT"),
        Some(signal) if signal == libc_signal("SIGBUS") => Some("fsck terminated with SIGBUS"),
        Some(signal) if signal == libc_signal("SIGFPE") => Some("fsck terminated with SIGFPE"),
        Some(signal) if signal == libc_signal("SIGILL") => Some("fsck terminated with SIGILL"),
        Some(signal) if signal == libc_signal("SIGSEGV") => Some("fsck terminated with SIGSEGV"),
        _ => None,
    }
}

fn signal_name(signal: Option<i32>, exit_code: i32) -> Option<&'static str> {
    match signal.or_else(|| exit_code_to_signal(exit_code)) {
        Some(signal) if signal == libc_signal("SIGKILL") => Some("fsck terminated with SIGKILL"),
        Some(signal) if signal == libc_signal("SIGTERM") => Some("fsck terminated with SIGTERM"),
        Some(signal) if signal == libc_signal("SIGXCPU") => Some("fsck terminated with SIGXCPU"),
        Some(signal) if signal == libc_signal("SIGXFSZ") => Some("fsck terminated with SIGXFSZ"),
        _ => None,
    }
}

fn exit_code_to_signal(exit_code: i32) -> Option<i32> {
    (exit_code > 128).then_some(exit_code - 128)
}

fn libc_signal(name: &str) -> i32 {
    match name {
        "SIGABRT" => libc::SIGABRT,
        "SIGBUS" => libc::SIGBUS,
        "SIGFPE" => libc::SIGFPE,
        "SIGILL" => libc::SIGILL,
        "SIGKILL" => libc::SIGKILL,
        "SIGSEGV" => libc::SIGSEGV,
        "SIGTERM" => libc::SIGTERM,
        "SIGXCPU" => libc::SIGXCPU,
        "SIGXFSZ" => libc::SIGXFSZ,
        _ => 0,
    }
}

fn contains_sanitizer_diagnostic(text: &str) -> bool {
    [
        "addresssanitizer",
        "undefinedbehaviorsanitizer",
        "memorysanitizer",
        "threadsanitizer",
        "leaksanitizer",
        "runtime error:",
    ]
    .iter()
    .any(|needle| text.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::{CgroupMemoryEvents, classify_fsck_execution, classify_fsck_result};

    #[test]
    fn classifies_common_fatal_signals() {
        assert_eq!(
            classify_fsck_result(134, "", ""),
            ("rejected_crash", "fsck terminated with SIGABRT")
        );
        assert_eq!(
            classify_fsck_result(135, "", ""),
            ("rejected_crash", "fsck terminated with SIGBUS")
        );
        assert_eq!(
            classify_fsck_result(136, "", ""),
            ("rejected_crash", "fsck terminated with SIGFPE")
        );
        assert_eq!(
            classify_fsck_result(139, "", ""),
            ("rejected_crash", "fsck terminated with SIGSEGV")
        );
    }

    #[test]
    fn classifies_oom_and_nonfatal_signals() {
        assert_eq!(
            classify_fsck_result(137, "Killed", ""),
            ("rejected_oom", "fsck was killed while memory-limited")
        );
        assert_eq!(
            classify_fsck_result(143, "", ""),
            ("rejected_signal", "fsck terminated with SIGTERM")
        );
        assert_eq!(
            classify_fsck_result(1, "cannot allocate memory", ""),
            ("rejected_oom", "fsck hit a memory allocation failure")
        );
    }

    #[test]
    fn classifies_cgroup_oom_delta() {
        assert_eq!(
            classify_fsck_execution(
                9,
                Some(libc::SIGKILL),
                false,
                None,
                Some(CgroupMemoryEvents {
                    oom: 1,
                    oom_kill: 0,
                }),
                "",
                "",
            ),
            ("rejected_oom", "cgroup v2 memory.oom increased")
        );
        assert_eq!(
            classify_fsck_execution(
                9,
                Some(libc::SIGKILL),
                false,
                None,
                Some(CgroupMemoryEvents {
                    oom: 1,
                    oom_kill: 1,
                }),
                "",
                "",
            ),
            ("rejected_oom", "cgroup v2 memory.oom_kill increased")
        );
    }

    #[test]
    fn ignores_cgroup_oom_delta_for_successful_fsck() {
        assert_eq!(
            classify_fsck_execution(
                0,
                None,
                false,
                None,
                Some(CgroupMemoryEvents {
                    oom: 1,
                    oom_kill: 1,
                }),
                "",
                "",
            ),
            ("accepted", "fsck accepted the image")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_cgroup_v2_memory_events() {
        assert_eq!(
            super::parse_cgroup_v2_memory_events(
                "low 0\nhigh 0\nmax 0\noom 2\noom_kill 1\noom_group_kill 0\n"
            ),
            Some(CgroupMemoryEvents {
                oom: 2,
                oom_kill: 1,
            })
        );
    }

    #[test]
    fn classifies_sanitizer_diagnostics() {
        assert_eq!(
            classify_fsck_result(1, "==1==ERROR: AddressSanitizer: heap-buffer-overflow", ""),
            ("sanitizer_crash", "sanitizer diagnostic detected")
        );
        assert_eq!(
            classify_fsck_result(1, "", "runtime error: load of misaligned address"),
            ("sanitizer_crash", "sanitizer diagnostic detected")
        );
    }
}
