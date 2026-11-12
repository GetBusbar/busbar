//! Python semantics the native step runner depends on: exception classes and
//! their `str()`, the deferred SIGTERM/SIGINT model of the former
//! `Interruptions`, `subprocess.run`/`Popen` behaviour, `os` path helpers and
//! the few libc calls std does not expose.
use crate::json::Value;
use crate::py;
use std::fmt;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// The Python exception class a failure would have had; it selects the
/// handlers that catch it (`except (Violation, OSError, ValueError, KeyError)`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Violation,
    Value,
    Runtime,
    Os,
    Key,
    Type,
    Called,
    Timeout,
    Interrupted,
}

#[derive(Clone, Debug)]
pub struct Error {
    pub kind: Kind,
    /// `str(error)`, exactly as the former controller recorded it.
    pub message: String,
    pub signal: i32,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error {
    pub fn new(kind: Kind, message: impl Into<String>) -> Error {
        Error {
            kind,
            message: message.into(),
            signal: 0,
        }
    }
    /// `except (Violation, OSError, ValueError, KeyError)`.
    pub fn is_ordinary(&self) -> bool {
        matches!(
            self.kind,
            Kind::Violation | Kind::Value | Kind::Os | Kind::Key
        )
    }
}

pub type R<T> = Result<T, Error>;

pub fn violation(message: impl Into<String>) -> Error {
    Error::new(Kind::Violation, message)
}
pub fn value_error(message: impl Into<String>) -> Error {
    Error::new(Kind::Value, message)
}
pub fn runtime(message: impl Into<String>) -> Error {
    Error::new(Kind::Runtime, message)
}
/// `KeyError(key)`: `str()` is the key's repr.
pub fn key_error(key: &str) -> Error {
    Error::new(Kind::Key, py::repr_str(key))
}
pub fn interrupted(signal: i32) -> Error {
    Error {
        kind: Kind::Interrupted,
        message: format!("native qualification interrupted by signal {signal}"),
        signal,
    }
}

/// `if not value: raise Violation(message)`.
pub fn need(ok: bool, message: &str) -> R<()> {
    if ok { Ok(()) } else { Err(violation(message)) }
}
/// `require` of the modules that raise `ValueError`.
pub fn need_value(ok: bool, message: &str) -> R<()> {
    if ok {
        Ok(())
    } else {
        Err(value_error(message))
    }
}

/// Errors from the shared bootstrap helpers (`proc::Result`) are ValueErrors there.
pub fn from_text(message: String) -> Error {
    value_error(message)
}

/// `str(OSError)`: `[Errno N] strerror: 'filename'`.
pub fn os_error(error: &std::io::Error, filename: Option<&Path>) -> Error {
    let message = match error.raw_os_error() {
        Some(code) => {
            let text = std::io::Error::from_raw_os_error(code).to_string();
            let text = text
                .strip_suffix(&format!(" (os error {code})"))
                .unwrap_or(&text)
                .to_owned();
            match filename {
                Some(path) => format!(
                    "[Errno {code}] {text}: {}",
                    py::repr_str(&path.to_string_lossy())
                ),
                None => format!("[Errno {code}] {text}"),
            }
        }
        None => error.to_string(),
    };
    Error::new(Kind::Os, message)
}

/// Attach a path to an `io::Result`, as Python's OSError carries `filename`.
pub trait Io<T> {
    fn at(self, path: &Path) -> R<T>;
}
impl<T> Io<T> for std::io::Result<T> {
    fn at(self, path: &Path) -> R<T> {
        self.map_err(|e| os_error(&e, Some(path)))
    }
}

/// JSON documents written by trusted tools or the engine; malformed input is a ValueError.
pub fn loads(data: &[u8]) -> R<Value> {
    py::loads(data).map_err(|e| Error::new(e_kind(&e), e.message.clone()))
}
fn e_kind(error: &py::PyErr) -> Kind {
    if error.is_value_error() {
        Kind::Value
    } else {
        Kind::Type
    }
}

/// `dict[key]` on JSON.
pub fn at<'a>(value: &'a Value, key: &str) -> R<&'a Value> {
    value.get(key).ok_or_else(|| key_error(key))
}
pub fn at_str<'a>(value: &'a Value, key: &str) -> R<&'a str> {
    at(value, key)?
        .as_str()
        .ok_or_else(|| Error::new(Kind::Type, format!("{key} is not a string")))
}

// ---------------------------------------------------------------------------
// Interruptions: the first SIGTERM/SIGINT is recorded and further ones are
// ignored so command, service and receipt cleanup cannot be interrupted. The
// signal is raised (once) at the next interruptible wait outside a deferred
// region, and again at every outermost deferred region's normal exit.

struct State {
    pending: AtomicI32,
    raised: AtomicBool,
    deferred: AtomicUsize,
}

impl State {
    const fn new() -> State {
        State {
            pending: AtomicI32::new(0),
            raised: AtomicBool::new(false),
            deferred: AtomicUsize::new(0),
        }
    }
}

/// One process-wide state; the step runner's main thread alone defers.
#[cfg(not(test))]
fn state() -> &'static State {
    static STATE: State = State::new();
    &STATE
}

/// Unit tests run concurrently, so each test thread has its own state.
#[cfg(test)]
fn state() -> &'static State {
    thread_local! {
        static STATE: &'static State = Box::leak(Box::new(State::new()));
    }
    STATE.with(|s| *s)
}

mod ffi {
    unsafe extern "C" {
        pub fn signal(signal: i32, handler: usize) -> usize;
        pub fn kill(pid: i32, signal: i32) -> i32;
        pub fn setsid() -> i32;
        pub fn openat(dirfd: i32, path: *const std::ffi::c_char, flags: i32, ...) -> i32;
        pub fn close(fd: i32) -> i32;
    }
}

const SIG_IGN: usize = 1;
const SIG_DFL: usize = 0;

extern "C" fn handle(signal: i32) {
    let _ = state()
        .pending
        .compare_exchange(0, signal, Ordering::SeqCst, Ordering::SeqCst);
    unsafe {
        ffi::signal(crate::proc::SIGTERM, SIG_IGN);
        ffi::signal(crate::proc::SIGINT, SIG_IGN);
    }
}

pub fn install_interruptions() {
    let handler = handle as extern "C" fn(i32) as usize;
    unsafe {
        ffi::signal(crate::proc::SIGTERM, handler);
        ffi::signal(crate::proc::SIGINT, handler);
    }
}

pub fn restore_interruptions() {
    unsafe {
        ffi::signal(crate::proc::SIGTERM, SIG_DFL);
        ffi::signal(crate::proc::SIGINT, SIG_DFL);
    }
}

pub fn pending() -> Option<i32> {
    match state().pending.load(Ordering::SeqCst) {
        0 => None,
        signal => Some(signal),
    }
}

/// The signal handler's immediate raise, observed at interruptible waits.
pub fn poll_interrupt() -> R<()> {
    if let Some(signal) = pending()
        && state().deferred.load(Ordering::SeqCst) == 0
        && !state().raised.swap(true, Ordering::SeqCst)
    {
        return Err(interrupted(signal));
    }
    Ok(())
}

/// `with deferred_interruptions(): body`.
pub fn deferred<T>(body: impl FnOnce() -> R<T>) -> R<T> {
    state().deferred.fetch_add(1, Ordering::SeqCst);
    let result = body();
    let outer = state().deferred.fetch_sub(1, Ordering::SeqCst) == 1;
    let value = result?;
    if outer && let Some(signal) = pending() {
        state().raised.store(true, Ordering::SeqCst);
        return Err(interrupted(signal));
    }
    Ok(value)
}

#[cfg(test)]
pub fn simulate_signal_for_test(signal: i32) {
    state().pending.store(signal, Ordering::SeqCst);
}

// ---------------------------------------------------------------------------
// Subprocesses.

pub enum Input {
    Inherit,
    Null,
    Bytes(Vec<u8>),
    Pipe(std::process::ChildStdout),
}

pub enum Output {
    Inherit,
    Null,
    Capture,
    File(File),
}

/// `subprocess.run(argv, env=..., cwd=..., stdin/stdout/stderr=..., timeout=...)`.
pub struct Spec {
    pub argv: Vec<String>,
    /// `None` inherits the controller environment (`os.environ`).
    pub env: Option<Vec<(String, String)>>,
    pub cwd: Option<PathBuf>,
    pub stdin: Input,
    pub stdout: Output,
    pub stderr: Output,
    /// Seconds, and their Python text for `TimeoutExpired`.
    pub timeout: Option<(f64, String)>,
    pub new_session: bool,
}

impl Spec {
    pub fn new(argv: Vec<String>) -> Spec {
        Spec {
            argv,
            env: None,
            cwd: None,
            stdin: Input::Inherit,
            stdout: Output::Inherit,
            stderr: Output::Inherit,
            timeout: None,
            new_session: false,
        }
    }
    pub fn env(mut self, env: &[(String, String)]) -> Spec {
        self.env = Some(env.to_vec());
        self
    }
    pub fn cwd(mut self, cwd: &Path) -> Spec {
        self.cwd = Some(cwd.to_owned());
        self
    }
    pub fn capture(mut self) -> Spec {
        self.stdout = Output::Capture;
        self.stderr = Output::Capture;
        self
    }
    pub fn quiet(mut self) -> Spec {
        self.stdout = Output::Null;
        self.stderr = Output::Null;
        self
    }
    pub fn timeout(mut self, seconds: u64) -> Spec {
        self.timeout = Some((seconds as f64, seconds.to_string()));
        self
    }
    pub fn input(mut self, data: Vec<u8>) -> Spec {
        self.stdin = Input::Bytes(data);
        self
    }
}

#[derive(Debug)]
pub struct Done {
    pub argv: Vec<String>,
    /// `Popen.returncode`: negative signal number when killed.
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Done {
    /// `check=True`.
    pub fn checked(self) -> R<Done> {
        if self.code != 0 {
            return Err(called_error(&self.argv, self.code));
        }
        Ok(self)
    }
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
}

/// `repr(list_of_str)`.
pub fn repr_list(argv: &[String]) -> String {
    format!(
        "[{}]",
        argv.iter()
            .map(|a| py::repr_str(a))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

const SIGNAL_NAMES: [&str; 32] = [
    "",
    "SIGHUP",
    "SIGINT",
    "SIGQUIT",
    "SIGILL",
    "SIGTRAP",
    "SIGABRT",
    "SIGBUS",
    "SIGFPE",
    "SIGKILL",
    "SIGUSR1",
    "SIGSEGV",
    "SIGUSR2",
    "SIGPIPE",
    "SIGALRM",
    "SIGTERM",
    "SIGSTKFLT",
    "SIGCHLD",
    "SIGCONT",
    "SIGSTOP",
    "SIGTSTP",
    "SIGTTIN",
    "SIGTTOU",
    "SIGURG",
    "SIGXCPU",
    "SIGXFSZ",
    "SIGVTALRM",
    "SIGPROF",
    "SIGWINCH",
    "SIGIO",
    "SIGPWR",
    "SIGSYS",
];

/// `str(CalledProcessError(code, argv))`.
pub fn called_error(argv: &[String], code: i32) -> Error {
    let command = repr_list(argv);
    let message = if code < 0 {
        let number = -code;
        match SIGNAL_NAMES.get(number as usize).filter(|n| !n.is_empty()) {
            Some(name) => format!("Command '{command}' died with <Signals.{name}: {number}>."),
            None => format!("Command '{command}' died with unknown signal {number}."),
        }
    } else {
        format!("Command '{command}' returned non-zero exit status {code}.")
    };
    Error::new(Kind::Called, message)
}

pub fn timeout_error(argv: &[String], timeout: &str) -> Error {
    Error::new(
        Kind::Timeout,
        format!(
            "Command '{}' timed out after {timeout} seconds",
            repr_list(argv)
        ),
    )
}

/// Spawn with Python's `Popen` file handling; `start_new_session` is `setsid`.
pub fn spawn(spec: &mut Spec) -> R<Child> {
    let (program, args) = spec
        .argv
        .split_first()
        .ok_or_else(|| value_error("empty command"))?;
    let mut command = Command::new(program);
    command.args(args);
    if let Some(env) = &spec.env {
        command.env_clear().envs(env.iter().map(|(k, v)| (k, v)));
    }
    if let Some(cwd) = &spec.cwd {
        command.current_dir(cwd);
    }
    command.stdin(match std::mem::replace(&mut spec.stdin, Input::Inherit) {
        Input::Inherit => Stdio::inherit(),
        Input::Null => Stdio::null(),
        Input::Bytes(data) => {
            spec.stdin = Input::Bytes(data);
            Stdio::piped()
        }
        Input::Pipe(stdout) => Stdio::from(stdout),
    });
    for (slot, out) in [(0, &mut spec.stdout), (1, &mut spec.stderr)] {
        let stdio = match std::mem::replace(out, Output::Inherit) {
            Output::Inherit => Stdio::inherit(),
            Output::Null => {
                *out = Output::Null;
                Stdio::null()
            }
            Output::Capture => {
                *out = Output::Capture;
                Stdio::piped()
            }
            Output::File(file) => Stdio::from(file),
        };
        if slot == 0 {
            command.stdout(stdio);
        } else {
            command.stderr(stdio);
        }
    }
    if spec.new_session {
        unsafe {
            command.pre_exec(|| {
                ffi::setsid();
                Ok(())
            });
        }
    }
    let path = Path::new(program);
    command.spawn().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound || path.is_absolute() {
            os_error(&e, Some(path))
        } else {
            os_error(&e, None)
        }
    })
}

pub fn returncode(status: std::process::ExitStatus) -> i32 {
    match status.code() {
        Some(code) => code,
        None => -status.signal().unwrap_or(0),
    }
}

/// `subprocess.run`: on timeout or interruption the child is killed (SIGKILL,
/// not its group), reaped, and the exception is raised.
pub fn run(mut spec: Spec) -> R<Done> {
    let mut child = spawn(&mut spec)?;
    let writer = match std::mem::replace(&mut spec.stdin, Input::Null) {
        Input::Bytes(data) => {
            let mut stdin = child.stdin.take();
            Some(std::thread::spawn(move || {
                if let Some(stream) = stdin.as_mut() {
                    let _ = stream.write_all(&data);
                }
                drop(stdin);
            }))
        }
        _ => None,
    };
    let reader = |stream: Option<Box<dyn Read + Send>>| {
        stream.map(|mut s| {
            std::thread::spawn(move || {
                let mut out = Vec::new();
                let _ = s.read_to_end(&mut out);
                out
            })
        })
    };
    let out = reader(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let err = reader(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let started = Instant::now();
    let outcome = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Ok(returncode(status)),
            Ok(None) => {}
            Err(e) => break Err(os_error(&e, None)),
        }
        if let Some((seconds, text)) = &spec.timeout
            && started.elapsed().as_secs_f64() >= *seconds
        {
            let _ = child.kill();
            let _ = child.wait();
            break Err(timeout_error(&spec.argv, text));
        }
        if let Err(error) = poll_interrupt() {
            let _ = child.kill();
            let _ = child.wait();
            break Err(error);
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    if let Some(writer) = writer {
        let _ = writer.join();
    }
    let stdout = out
        .map(|t| t.join().unwrap_or_default())
        .unwrap_or_default();
    let stderr = err
        .map(|t| t.join().unwrap_or_default())
        .unwrap_or_default();
    Ok(Done {
        argv: spec.argv,
        code: outcome?,
        stdout,
        stderr,
    })
}

/// `subprocess.check_output(argv, ...)`: stdout captured, stderr inherited.
pub fn check_output(mut spec: Spec) -> R<Vec<u8>> {
    spec.stdout = Output::Capture;
    Ok(run(spec)?.checked()?.stdout)
}

/// `subprocess.run(argv, check=True)` with inherited streams.
pub fn check_call(spec: Spec) -> R<()> {
    run(spec)?.checked().map(|_| ())
}

pub fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_owned()).collect()
}

/// `os.killpg`; `false` is ProcessLookupError.
pub fn killpg(pid: u32, signal: i32) -> bool {
    unsafe { ffi::kill(-(pid as i32), signal) == 0 }
}

/// `stop_process_group(process, grace=10)`: TERM the session, wait for it to
/// empty, KILL on the deadline, then reap the leader within one second.
pub fn stop_process_group(child: &mut Child, grace: Duration) -> R<i32> {
    deferred(|| {
        if !killpg(child.id(), crate::proc::SIGTERM) {
            let status = child.wait().map_err(|e| os_error(&e, None))?;
            return Ok(returncode(status));
        }
        let deadline = Instant::now() + grace;
        loop {
            let _ = child.try_wait();
            if !killpg(child.id(), 0) {
                break;
            }
            let now = Instant::now();
            if now >= deadline {
                killpg(child.id(), crate::proc::SIGKILL);
                break;
            }
            std::thread::sleep((deadline - now).min(Duration::from_millis(50)));
        }
        let started = Instant::now();
        loop {
            if let Some(status) = child.try_wait().map_err(|e| os_error(&e, None))? {
                return Ok(returncode(status));
            }
            if started.elapsed() >= Duration::from_secs(1) {
                return Err(Error::new(Kind::Timeout, "process group did not exit"));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })
}

// ---------------------------------------------------------------------------
// Paths with pathlib semantics.

/// `Path(value).resolve()`: realpath of the existing prefix, lexical rest.
pub fn resolve(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut resolved = PathBuf::from("/");
    let mut missing = false;
    for component in absolute.components() {
        match component {
            Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            Component::ParentDir => {
                resolved.pop();
            }
            Component::Normal(name) => {
                resolved.push(name);
                if !missing {
                    match std::fs::canonicalize(&resolved) {
                        Ok(real) => resolved = real,
                        Err(_) => missing = true,
                    }
                }
            }
        }
    }
    resolved
}

/// `os.path.abspath`: lexical normalization only.
pub fn abspath(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut out = PathBuf::from("/");
    for component in absolute.components() {
        match component {
            Component::Normal(name) => out.push(name),
            Component::ParentDir => {
                out.pop();
            }
            _ => {}
        }
    }
    out
}

pub fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// `str(path)`.
pub fn text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `Path.parents` plus the path itself, nearest first.
pub fn self_and_parents(path: &Path) -> Vec<PathBuf> {
    let mut out = vec![path.to_owned()];
    let mut current = path;
    while let Some(parent) = current.parent() {
        out.push(parent.to_owned());
        current = parent;
    }
    out
}

/// `PurePosixPath.as_uri()`.
pub fn as_uri(path: &Path) -> String {
    let mut out = String::from("file://");
    for byte in text(path).bytes() {
        if byte.is_ascii_alphanumeric() || b"_.-~/".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `path.mkdir(mode=mode)` (umask applies, like `os.mkdir`).
pub fn mkdir(path: &Path, mode: u32, exist_ok: bool) -> R<()> {
    use std::os::unix::fs::DirBuilderExt;
    match std::fs::DirBuilder::new().mode(mode).create(path) {
        Ok(()) => Ok(()),
        Err(e) if exist_ok && e.kind() == std::io::ErrorKind::AlreadyExists && path.is_dir() => {
            Ok(())
        }
        Err(e) => Err(os_error(&e, Some(path))),
    }
}

/// `path.mkdir(parents=True, exist_ok=...)`.
pub fn mkdirs(path: &Path, exist_ok: bool) -> R<()> {
    if path.is_dir() {
        return if exist_ok {
            Ok(())
        } else {
            Err(os_error(&std::io::Error::from_raw_os_error(17), Some(path)))
        };
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.is_dir()
    {
        mkdirs(parent, true)?;
    }
    mkdir(path, 0o777, exist_ok)
}

pub fn chmod(path: &Path, mode: u32) -> R<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).at(path)
}

pub fn read(path: &Path) -> R<Vec<u8>> {
    std::fs::read(path).at(path)
}
pub fn read_text(path: &Path) -> R<String> {
    let data = read(path)?;
    String::from_utf8(data).map_err(|_| value_error("'utf-8' codec can't decode bytes"))
}
pub fn write(path: &Path, data: impl AsRef<[u8]>) -> R<()> {
    std::fs::write(path, data).at(path)
}
pub fn read_json(path: &Path) -> R<Value> {
    loads(&read(path)?)
}

/// `open(path, 'xb')`.
pub fn create_new(path: &Path) -> R<File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .at(path)
}

/// `shutil.rmtree` without following links.
pub fn rmtree(path: &Path) -> R<()> {
    std::fs::remove_dir_all(path).at(path)
}

/// `shutil.copytree(source, destination)` of controller-made regular trees.
pub fn copytree(source: &Path, destination: &Path) -> R<()> {
    std::fs::create_dir(destination).at(destination)?;
    let mut entries: Vec<_> = std::fs::read_dir(source)
        .at(source)?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());
    for entry in entries {
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let kind = std::fs::symlink_metadata(&from).at(&from)?.file_type();
        if kind.is_symlink() {
            let target = std::fs::read_link(&from).at(&from)?;
            std::os::unix::fs::symlink(target, &to).at(&to)?;
        } else if kind.is_dir() {
            copytree(&from, &to)?;
        } else {
            std::fs::copy(&from, &to).at(&from)?;
        }
    }
    let mode = std::fs::metadata(source).at(source)?.permissions();
    std::fs::set_permissions(destination, mode).at(destination)
}

/// `path.rglob('*')` (directories are entered without following links),
/// in directory order sorted by name for determinism.
pub fn rglob(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn walk(directory: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(directory) else {
            return;
        };
        let mut names: Vec<_> = entries.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        names.sort();
        for path in names {
            out.push(path.clone());
            if std::fs::symlink_metadata(&path).is_ok_and(|m| m.is_dir()) {
                walk(&path, out);
            }
        }
    }
    walk(root, &mut out);
    out
}

/// `sorted(paths)`: pathlib orders by component lists, not by text.
pub fn sort_paths(paths: &mut [PathBuf]) {
    paths.sort_by(|a, b| {
        let left: Vec<_> = a.components().map(|c| c.as_os_str().to_owned()).collect();
        let right: Vec<_> = b.components().map(|c| c.as_os_str().to_owned()).collect();
        left.cmp(&right)
    });
}

/// `fnmatch` of one pathlib glob component (case-sensitive; `*`, `?`, `[...]`).
pub fn fnmatch(name: &str, pattern: &str) -> bool {
    fn go(n: &[char], p: &[char]) -> bool {
        match p.first() {
            None => n.is_empty(),
            Some('*') => (0..=n.len()).any(|i| go(&n[i..], &p[1..])),
            Some('?') => !n.is_empty() && go(&n[1..], &p[1..]),
            Some('[') => {
                let Some(end) = p.iter().skip(1).position(|c| *c == ']').map(|i| i + 1) else {
                    return n.first() == Some(&'[') && go(&n[1..], &p[1..]);
                };
                let Some(c) = n.first() else { return false };
                let mut set = &p[1..end];
                let negate = matches!(set.first(), Some('!'));
                if negate {
                    set = &set[1..];
                }
                let mut hit = false;
                let mut i = 0;
                while i < set.len() {
                    if i + 2 < set.len() && set[i + 1] == '-' {
                        hit |= set[i] <= *c && *c <= set[i + 2];
                        i += 3;
                    } else {
                        hit |= set[i] == *c;
                        i += 1;
                    }
                }
                hit != negate && go(&n[1..], &p[end + 1..])
            }
            Some(c) => n.first() == Some(c) && go(&n[1..], &p[1..]),
        }
    }
    let n: Vec<char> = name.chars().collect();
    let p: Vec<char> = pattern.chars().collect();
    go(&n, &p)
}

/// `root.glob(pattern)` for patterns of literal and wildcard components.
pub fn glob(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut current = vec![root.to_owned()];
    let parts: Vec<&str> = pattern.split('/').collect();
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        let mut next = Vec::new();
        for base in &current {
            if !part.contains(['*', '?', '[']) {
                let path = base.join(part);
                if (last && (path.exists() || is_symlink(&path))) || (!last && path.is_dir()) {
                    next.push(path);
                }
                continue;
            }
            let Ok(entries) = std::fs::read_dir(base) else {
                continue;
            };
            for entry in entries.filter_map(|e| e.ok()) {
                let name = entry.file_name().to_string_lossy().into_owned();
                let path = entry.path();
                if fnmatch(&name, part) && (last || path.is_dir()) {
                    next.push(path);
                }
            }
        }
        current = next;
    }
    current
}

// ---------------------------------------------------------------------------
// Descriptor-anchored opens (`os.open(..., dir_fd=...)`).

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub mod flags {
    pub const O_DIRECTORY: i32 = 0o200000;
    pub const O_NOFOLLOW: i32 = 0o400000;
}
#[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
pub mod flags {
    pub const O_DIRECTORY: i32 = 0o40000;
    pub const O_NOFOLLOW: i32 = 0o100000;
}
#[cfg(target_os = "macos")]
pub mod flags {
    pub const O_DIRECTORY: i32 = 0x100000;
    pub const O_NOFOLLOW: i32 = 0x100;
}
#[cfg(target_os = "linux")]
pub const O_NONBLOCK: i32 = 0o4000;
#[cfg(target_os = "macos")]
pub const O_NONBLOCK: i32 = 0x4;
#[cfg(target_os = "linux")]
pub const O_CLOEXEC: i32 = 0o2000000;
#[cfg(target_os = "macos")]
pub const O_CLOEXEC: i32 = 0x1000000;
pub const AT_FDCWD: i32 = if cfg!(target_os = "macos") { -2 } else { -100 };

/// `os.open(name, flags, dir_fd=fd)`; the error names `name` like CPython.
pub fn openat(dirfd: i32, name: &std::ffi::OsStr, flags: i32) -> R<i32> {
    use std::os::unix::ffi::OsStrExt;
    let path =
        std::ffi::CString::new(name.as_bytes()).map_err(|_| value_error("embedded null byte"))?;
    let fd = unsafe { ffi::openat(dirfd, path.as_ptr(), flags | O_CLOEXEC) };
    if fd < 0 {
        return Err(os_error(
            &std::io::Error::last_os_error(),
            Some(Path::new(name)),
        ));
    }
    Ok(fd)
}

pub fn close(fd: i32) {
    unsafe {
        ffi::close(fd);
    }
}

// ---------------------------------------------------------------------------
// Small Python value helpers.

/// `round(x, digits)` then `repr` as a JSON number.
pub fn round_float(value: f64, digits: usize) -> Value {
    let text = format!("{value:.digits$}");
    Value::Number(py::float_repr(text.parse().unwrap_or(0.0)))
}

/// `int(text)` for base-10 text, with its ValueError message.
pub fn py_int(text: &str) -> R<i128> {
    let trimmed = text.trim();
    let digits = trimmed.strip_prefix(['+', '-']).unwrap_or(trimmed);
    let valid = !digits.is_empty()
        && !digits.starts_with('_')
        && !digits.ends_with('_')
        && !digits.contains("__")
        && digits.chars().all(|c| c.is_ascii_digit() || c == '_');
    let cleaned: String = trimmed.chars().filter(|c| *c != '_').collect();
    match (valid, cleaned.parse::<i128>()) {
        (true, Ok(number)) => Ok(number),
        _ => Err(value_error(format!(
            "invalid literal for int() with base 10: {}",
            py::repr_str(text)
        ))),
    }
}

/// `uuid.uuid4().hex`.
pub fn uuid_hex() -> String {
    let mut bytes = [0u8; 16];
    if let Ok(mut source) = File::open("/dev/urandom") {
        let _ = source.read_exact(&mut bytes);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// An insertion-ordered `dict[str, str]` (`os.environ`-shaped mappings).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Dict(pub Vec<(String, String)>);

impl Dict {
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        let value = value.into();
        match self.0.iter_mut().find(|(k, _)| k == key) {
            Some(row) => row.1 = value,
            None => self.0.push((key.to_owned(), value)),
        }
    }
    pub fn contains(&self, key: &str) -> bool {
        self.get(key).is_some()
    }
    pub fn update(&mut self, other: &Dict) {
        for (k, v) in &other.0 {
            self.set(k, v.clone());
        }
    }
    /// The process environment as `os.environ` sees it.
    pub fn environ() -> Dict {
        Dict(
            std::env::vars_os()
                .map(|(k, v)| {
                    (
                        k.to_string_lossy().into_owned(),
                        v.to_string_lossy().into_owned(),
                    )
                })
                .collect(),
        )
    }
    pub fn pairs(&self) -> Vec<(String, String)> {
        self.0.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn python_error_text_matches_the_former_receipts() {
        let argv = strings(&["git", "-C", "/x", "fetch"]);
        assert_eq!(
            called_error(&argv, 128).message,
            "Command '['git', '-C', '/x', 'fetch']' returned non-zero exit status 128."
        );
        assert_eq!(
            called_error(&argv, -9).message,
            "Command '['git', '-C', '/x', 'fetch']' died with <Signals.SIGKILL: 9>."
        );
        assert_eq!(
            timeout_error(&argv, "3600").message,
            "Command '['git', '-C', '/x', 'fetch']' timed out after 3600 seconds"
        );
        assert_eq!(key_error("NetworkMode").message, "'NetworkMode'");
        let missing = std::io::Error::from_raw_os_error(2);
        assert_eq!(
            os_error(&missing, Some(Path::new("/a/b"))).message,
            "[Errno 2] No such file or directory: '/a/b'"
        );
        assert_eq!(
            interrupted(15).message,
            "native qualification interrupted by signal 15"
        );
        assert_eq!(py_int(" 12 ").unwrap(), 12);
        assert_eq!(py_int("1_0").unwrap(), 10);
        assert_eq!(
            py_int("x").unwrap_err().message,
            "invalid literal for int() with base 10: 'x'"
        );
    }

    #[test]
    fn interruptions_are_deferred_raised_once_and_again_at_region_exits() {
        simulate_signal_for_test(15);
        // A signal during a deferred region surfaces at its exit, not inside.
        let inside = deferred(|| {
            assert!(poll_interrupt().is_ok());
            deferred(|| Ok(()))
        });
        let error = inside.unwrap_err();
        assert_eq!((error.kind, error.signal), (Kind::Interrupted, 15));
        // Once raised, ordinary waits no longer raise; cleanup proceeds...
        assert!(poll_interrupt().is_ok());
        assert!(run(Spec::new(strings(&["/bin/sh", "-c", "exit 0"]))).is_ok());
        // ...but every outermost deferred region still re-raises on exit.
        assert_eq!(deferred(|| Ok(())).unwrap_err().kind, Kind::Interrupted);
        assert_eq!(
            deferred(|| -> R<()> { Err(violation("x")) })
                .unwrap_err()
                .message,
            "x"
        );
    }

    #[test]
    fn a_pending_signal_stops_a_supervised_wait() {
        simulate_signal_for_test(2);
        let started = Instant::now();
        let error = run(Spec::new(strings(&["/bin/sleep", "5"]))).unwrap_err();
        assert_eq!(
            error.message,
            "native qualification interrupted by signal 2"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn process_groups_are_stopped_with_grace_then_killed() {
        let marker = std::env::temp_dir().join(format!("busbar-ci-trap-{}", uuid_hex()));
        let script = format!("trap '' TERM; sleep 30 & touch {}; wait", marker.display());
        let mut spec = Spec::new(strings(&["/bin/sh", "-c", &script]));
        spec.new_session = true;
        let mut child = spawn(&mut spec).unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        while !marker.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = std::fs::remove_file(&marker);
        let started = Instant::now();
        let code = stop_process_group(&mut child, Duration::from_millis(300)).unwrap();
        assert_eq!(code, -9);
        assert!(started.elapsed() < Duration::from_secs(3));
        let mut polite = Spec::new(strings(&["/bin/sleep", "30"]));
        polite.new_session = true;
        let mut child = spawn(&mut polite).unwrap();
        assert_eq!(
            stop_process_group(&mut child, Duration::from_secs(5)).unwrap(),
            -15
        );
    }

    #[test]
    fn floats_round_like_python() {
        assert_eq!(crate::json::dumps(&round_float(1.23456, 3), false), "1.235");
        assert_eq!(crate::json::dumps(&round_float(2.0, 3), false), "2.0");
        assert_eq!(crate::json::dumps(&round_float(0.0004, 3), false), "0.0");
        assert_eq!(crate::json::dumps(&round_float(301.04, 1), false), "301.0");
    }

    #[test]
    fn subprocess_semantics() {
        let done =
            run(Spec::new(strings(&["/bin/sh", "-c", "echo hi; exit 3"])).capture()).unwrap();
        assert_eq!((done.code, done.text().as_str()), (3, "hi\n"));
        assert!(
            done.checked()
                .unwrap_err()
                .message
                .contains("exit status 3")
        );
        let slow = Spec {
            timeout: Some((0.2, "0.2".into())),
            ..Spec::new(strings(&["/bin/sleep", "5"]))
        };
        let error = run(slow).unwrap_err();
        assert_eq!(error.kind, Kind::Timeout);
        assert!(error.message.ends_with("timed out after 0.2 seconds"));
        let fed = run(Spec::new(strings(&["/bin/cat"]))
            .input(b"abc".to_vec())
            .capture())
        .unwrap();
        assert_eq!(fed.stdout, b"abc");
        assert_eq!(
            run(Spec::new(strings(&["/nonexistent-tool"])))
                .unwrap_err()
                .message,
            "[Errno 2] No such file or directory: '/nonexistent-tool'"
        );
    }

    #[test]
    fn globbing_and_ordering_follow_pathlib() {
        assert!(fnmatch("a-samples.json", "*-samples.json"));
        assert!(fnmatch(".hidden.xml", "*.xml"));
        assert!(!fnmatch("a.json", "*.xml"));
        assert!(fnmatch("b", "[a-c]"));
        let mut paths = vec![PathBuf::from("/r/a-b/x"), PathBuf::from("/r/a/x")];
        sort_paths(&mut paths);
        assert_eq!(paths[0], PathBuf::from("/r/a/x"));
        assert_eq!(as_uri(Path::new("/a b/c%")), "file:///a%20b/c%25");
    }
}
