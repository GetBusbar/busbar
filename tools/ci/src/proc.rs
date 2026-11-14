//! Supervised host commands, signal interruption and the few libc calls needed.
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

pub type Result<T> = std::result::Result<T, String>;

pub fn require(ok: bool, message: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(message.to_owned()) }
}

mod ffi {
    unsafe extern "C" {
        pub fn geteuid() -> u32;
        pub fn kill(pid: i32, signal: i32) -> i32;
        pub fn signal(signal: i32, handler: usize) -> usize;
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    #[repr(C)]
    pub struct StatVfs {
        pub f_bsize: u64,
        pub f_frsize: u64,
        pub f_blocks: u64,
        pub f_bfree: u64,
        pub f_bavail: u64,
        pub f_files: u64,
        pub f_ffree: u64,
        pub f_favail: u64,
        pub f_fsid: u64,
        pub f_flag: u64,
        pub f_namemax: u64,
        pub spare: [i32; 6],
    }
    #[cfg(all(target_os = "linux", target_pointer_width = "64"))]
    unsafe extern "C" {
        pub fn statvfs(path: *const std::ffi::c_char, out: *mut StatVfs) -> i32;
    }
}

pub const O_NOFOLLOW: i32 = if cfg!(target_os = "linux") {
    0o400000
} else {
    0x0100
};
pub const SIGINT: i32 = 2;
pub const SIGKILL: i32 = 9;
pub const SIGTERM: i32 = 15;

pub fn euid() -> u32 {
    unsafe { ffi::geteuid() }
}

pub fn signal_process(pid: i32, signal: i32) {
    unsafe {
        ffi::kill(pid, signal);
    }
}

/// Filesystem capacity: (capacity bytes, available bytes, inodes, available inodes).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Capacity {
    pub capacity_bytes: u64,
    pub available_bytes: u64,
    pub capacity_inodes: u64,
    pub available_inodes: u64,
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub fn statvfs(path: &std::path::Path) -> Result<Capacity> {
    use std::os::unix::ffi::OsStrExt;
    let raw = std::ffi::CString::new(path.as_os_str().as_bytes()).map_err(|e| e.to_string())?;
    let mut out = std::mem::MaybeUninit::<ffi::StatVfs>::uninit();
    if unsafe { ffi::statvfs(raw.as_ptr(), out.as_mut_ptr()) } != 0 {
        return Err(format!(
            "statvfs {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let v = unsafe { out.assume_init() };
    Ok(Capacity {
        capacity_bytes: v.f_blocks * v.f_frsize,
        available_bytes: v.f_bavail * v.f_frsize,
        capacity_inodes: v.f_files,
        available_inodes: v.f_favail,
    })
}

#[cfg(not(all(target_os = "linux", target_pointer_width = "64")))]
pub fn statvfs(_: &std::path::Path) -> Result<Capacity> {
    Err("statvfs is only implemented for the Linux native worker".into())
}

static INTERRUPTED: AtomicI32 = AtomicI32::new(0);

extern "C" fn record(signal: i32) {
    let _ = INTERRUPTED.compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
}

/// Route SIGTERM/SIGINT into a flag observed by every supervised wait, so
/// cleanup runs on cancellation exactly as on failure.
pub fn install_signal_handlers() {
    let handler = record as extern "C" fn(i32) as usize;
    unsafe {
        ffi::signal(SIGTERM, handler);
        ffi::signal(SIGINT, handler);
    }
}

/// Restore default SIGTERM/SIGINT dispositions after a supervised phase.
pub fn restore_default_signals() {
    unsafe {
        ffi::signal(SIGTERM, 0);
        ffi::signal(SIGINT, 0);
    }
}

pub fn interrupted() -> Option<i32> {
    match INTERRUPTED.load(Ordering::SeqCst) {
        0 => None,
        signal => Some(signal),
    }
}

pub fn check_interrupted() -> Result<()> {
    match interrupted() {
        Some(signal) => Err(format!(
            "protected controller interrupted by signal {signal}"
        )),
        None => Ok(()),
    }
}

pub const HOST_PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";

/// Exact host executable from the fixed host PATH (`shutil.which`).
pub fn host_program(name: &str) -> Result<String> {
    use std::os::unix::fs::PermissionsExt;
    for directory in HOST_PATH.split(':') {
        let path = std::path::Path::new(directory).join(name);
        if let Ok(metadata) = std::fs::metadata(&path)
            && metadata.is_file()
            && metadata.permissions().mode() & 0o111 != 0
        {
            return Ok(path.to_string_lossy().into_owned());
        }
    }
    Err(format!("required host tool is absent: {name}"))
}

#[derive(Default)]
pub struct Options {
    pub env: Vec<(String, String)>,
    pub stdin: Option<Vec<u8>>,
    pub capture: bool,
    pub timeout: Option<Duration>,
    pub cwd: Option<std::path::PathBuf>,
    /// Workload commands stop when the controller is interrupted; cleanup
    /// commands (the default) still run to completion within their timeouts.
    pub interruptible: bool,
    /// On interruption: SIGTERM, then SIGKILL after this grace. Default: SIGKILL.
    pub grace: Option<Duration>,
    /// Cancellation in addition to SIGTERM/SIGINT (same semantics).
    pub cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

pub fn command(argv: &[String], options: &Options) -> Result<Command> {
    let (program, args) = argv.split_first().ok_or("empty command")?;
    let mut command = Command::new(program);
    command
        .args(args)
        .env_clear()
        .envs(options.env.iter().map(|(k, v)| (k, v)));
    if let Some(cwd) = &options.cwd {
        command.current_dir(cwd);
    }
    command.process_group(0);
    Ok(command)
}

/// Wait for a child, killing its process group on timeout or interruption.
pub fn supervise(child: &mut Child, options: &Options, name: &str) -> Result<ExitStatus> {
    let started = Instant::now();
    let group = child.id() as i32;
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            return Ok(status);
        }
        let timed_out = options.timeout.is_some_and(|t| started.elapsed() >= t);
        let cancelled = interrupted().is_some()
            || options
                .cancel
                .as_ref()
                .is_some_and(|c| c.load(Ordering::SeqCst));
        if timed_out || (options.interruptible && cancelled) {
            if let (Some(grace), false) = (options.grace, timed_out) {
                signal_process(-group, SIGTERM);
                let deadline = Instant::now() + grace;
                while Instant::now() < deadline {
                    if child.try_wait().map_err(|e| e.to_string())?.is_some() {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
            signal_process(-group, SIGKILL);
            let _ = child.wait();
            return Err(if timed_out {
                format!("{name} timed out")
            } else {
                format!("{name} interrupted")
            });
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Run a host command; output is captured (bounded to 64 MiB) when requested.
pub fn run(argv: &[String], options: &Options) -> Result<Output> {
    let name = argv.first().cloned().unwrap_or_default();
    let mut command = command(argv, options)?;
    command.stdin(if options.stdin.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    if options.capture {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let mut child = command.spawn().map_err(|e| format!("{name}: {e}"))?;
    let writer = options.stdin.clone().map(|data| {
        let mut input = child.stdin.take().unwrap();
        std::thread::spawn(move || {
            use std::io::Write;
            let _ = input.write_all(&data);
        })
    });
    let readers = if options.capture {
        let reader = |stream: Box<dyn Read + Send>| {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                let _ = stream.take(64 << 20).read_to_end(&mut out);
                out
            })
        };
        Some((
            reader(Box::new(child.stdout.take().unwrap())),
            reader(Box::new(child.stderr.take().unwrap())),
        ))
    } else {
        None
    };
    let status = supervise(&mut child, options, &name);
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let (stdout, stderr) = match readers {
        Some((out, err)) => (
            out.join().unwrap_or_default(),
            err.join().unwrap_or_default(),
        ),
        None => (Vec::new(), Vec::new()),
    };
    Ok(Output {
        status: status?,
        stdout,
        stderr,
    })
}

/// `subprocess.run(..., check=True)`.
pub fn checked(argv: &[String], options: &Options) -> Result<Output> {
    let output = run(argv, options)?;
    require(
        output.status.success(),
        &format!(
            "{} failed ({})",
            argv.first().map(String::as_str).unwrap_or(""),
            output.status
        ),
    )?;
    Ok(output)
}

pub fn strings(argv: &[&str]) -> Vec<String> {
    argv.iter().map(|v| (*v).to_owned()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supervised_commands_are_bounded_and_environment_is_exact() {
        let options = Options {
            env: vec![("ONLY".into(), "1".into())],
            capture: true,
            stdin: Some(b"input".to_vec()),
            ..Default::default()
        };
        let output = checked(&strings(&["/bin/sh", "-c", "cat; env"]), &options).unwrap();
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(text.starts_with("input"));
        assert!(text.contains("ONLY=1"));
        assert!(!text.contains("HOME="));
        let slow = Options {
            timeout: Some(Duration::from_millis(200)),
            ..Default::default()
        };
        let started = Instant::now();
        let error = run(&strings(&["/bin/sleep", "30"]), &slow).unwrap_err();
        assert!(error.contains("timed out"));
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(checked(&strings(&["/bin/sh", "-c", "exit 3"]), &Options::default()).is_err());
    }

    #[test]
    fn interruption_stops_workload_but_never_cleanup() {
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let workload = Options {
            interruptible: true,
            grace: Some(Duration::from_millis(100)),
            cancel: Some(cancel.clone()),
            ..Default::default()
        };
        let started = Instant::now();
        assert!(
            run(&strings(&["/bin/sleep", "30"]), &workload)
                .unwrap_err()
                .contains("interrupted")
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        let cleanup = Options {
            cancel: Some(cancel),
            capture: true,
            ..Default::default()
        };
        let output = checked(
            &strings(&["/bin/sh", "-c", "sleep 0.2; echo disposed"]),
            &cleanup,
        )
        .unwrap();
        assert_eq!(String::from_utf8(output.stdout).unwrap(), "disposed\n");
    }
}
