// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY PLUGIN'S OWN LOG FILE — the host end of plugin logging (decision #85, and
//! `BUSBAR-1.6.0.md` THE DESIGN, §11.2).
//!
//! A plugin reports; the host writes. Whatever a plugin logged during a call reaches the host as
//! log diagnostics on the call's reply, already bounded by the dispatcher ([`super::plugin`]), and
//! [`PluginLogSink`] writes each one as ONE line of the plugin instance's own file:
//!
//! ```text
//! 2026-09-28T12:00:00Z DEBUG my-instance <kind> h2::client: binding client connection
//! ```
//!
//! — the time, the level, the instance, the kind, then the text. The file is
//! `<dir>/<instance>.log`, the instance name with every byte outside `[A-Za-z0-9._-]` written as
//! `_`. Lines under the instance's configured level are not written. A declared diagnostic is a
//! line too, its id before its text. The records one reply could not carry are one line saying how
//! many. Every control character in a text is escaped, so a record is one line and nothing raw
//! reaches a terminal: a line break is `\n`, a carriage return `\r`, any other `\u{..}`.
//!
//! BUSBAR'S OWN LOG keeps a copy of every WARN and ERROR record, written when the record is handed
//! over, so it lands among the host's own lines in the order 1.5.5 printed it ([`mirror`]); those
//! are the rare lines, and the host's subscriber decides how it writes them.
//!
//! OFF THE DISPATCH WORKER (§11.2: no blocking on the hot path; §11.11 R4: the bounded disk lane is
//! the SQLite store's and the file export sink's alone, so plugin logging may not claim it). The
//! sink is fed inside the crossing, where the reply's records are still plugin memory, so there it
//! only checks the level, copies the record and hands it to its file's writer thread with a send
//! that never waits. The writer opens, rotates and writes the file. Its queue holds
//! [`LOG_QUEUE_LINES`]; a line handed over while it is full is counted, not written, and the lines
//! one full queue lost are one line saying how many, written once the writer has caught up.
//!
//! ROTATION follows the host's one file rule (the host-effect `rotate`): once the file holds the
//! configured size, it is renamed to `<file>.1` (older archives shift up, `keep` of them kept) and a
//! new file begins. No size configured: never rotated. A file has ONE state in the process (its
//! descriptor, its size, its rotation), whichever sinks write it: two live sinks of one instance
//! rotate it once and never write an archive. A rotation that fails is one line in the file, once,
//! and is tried again only after another `rotate` bytes.
//!
//! A CONFIG APPLY reaches every live sink ([`PluginLogConfig::reconfigure`], THE DESIGN §11.2): the
//! level at once, the directory and rotation at the next line.
//!
//! THE DIRECTORY is the host's too: a sink is OPENED when its plugin instance is bound, and opening
//! creates `dir` (and any missing parent) if it is not there yet, through the loader's one durable
//! owner, and opens the file. Create-or-reuse, idempotent. A directory that cannot be used (a file
//! where it should be, no permission) refuses the open with `plugins.logs.dir <dir>: <error>`. The
//! plugin never names a path, opens a file or holds a descriptor, so the compiled-in and the
//! dropped-in build of one plugin write the same bytes.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock, Weak};

use busbar_contract::abi::mechanism::call::{
    DIAG_LOG, SEVERITY_DEBUG, SEVERITY_ERROR, SEVERITY_INFO, SEVERITY_TRACE, SEVERITY_WARN,
};
use busbar_contract::abi::mechanism::KindCode;

use super::plugin::{Diagnostic, Dropped, EnvelopeSink, Metric};

/// A plugin log level. Ordered by verbosity: a line is written when its level is at or below the
/// instance's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    /// Nothing is written.
    Off,
    /// Errors.
    Error,
    /// Warnings and above.
    Warn,
    /// Information and above.
    Info,
    /// Debug and above.
    Debug,
    /// Everything.
    Trace,
}

impl LogLevel {
    pub fn parse(word: &str) -> Option<Self> {
        Some(match word {
            "off" => Self::Off,
            "error" => Self::Error,
            "warn" => Self::Warn,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => return None,
        })
    }

    fn of_severity(severity: u8) -> Self {
        match severity {
            SEVERITY_ERROR => Self::Error,
            SEVERITY_WARN => Self::Warn,
            SEVERITY_INFO => Self::Info,
            SEVERITY_DEBUG => Self::Debug,
            SEVERITY_TRACE => Self::Trace,
            _ => Self::Info,
        }
    }

    fn of_u8(n: u8) -> Self {
        match n {
            0 => Self::Off,
            1 => Self::Error,
            2 => Self::Warn,
            3 => Self::Info,
            4 => Self::Debug,
            _ => Self::Trace,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Off => "OFF  ",
            Self::Error => "ERROR",
            Self::Warn => "WARN ",
            Self::Info => "INFO ",
            Self::Debug => "DEBUG",
            Self::Trace => "TRACE",
        }
    }
}

/// Where plugin logs go, and how much of them: the host's `plugins.logs` configuration.
///
/// Every clone shares ONE live setting: [`PluginLogConfig::reconfigure`] on any of them (the
/// root's config apply) moves every sink opened from any of them onto the new words at its next
/// line. Two configurations are equal when their words are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginLogConfig {
    /// The directory every plugin instance's file lives in.
    pub dir: PathBuf,
    /// The level of an instance `levels` does not name.
    pub level: LogLevel,
    /// Per-instance levels, by instance name.
    pub levels: BTreeMap<String, LogLevel>,
    /// Rotate a file once it holds this many bytes; `None` never rotates.
    pub rotate_bytes: Option<u64>,
    /// How many rotated archives to keep.
    pub keep: u32,
    /// The operator NAMED the directory (`plugins.logs.dir`): each sink opens its file when it is
    /// bound, so an unusable directory refuses the boot. Under the default directory a file is
    /// created at its first line, so a deployment whose plugins log nothing persists nothing (a
    /// configuration without a data directory writes no file, as 1.5.5 wrote none).
    pub named_dir: bool,
    /// The live words every sink opened from this configuration (or a clone) follows.
    live: Live,
}

pub const DEFAULT_DIR: &str = "logs/plugins";

pub const DEFAULT_KEEP: u32 = 5;

impl PluginLogConfig {
    pub fn from_words(
        dir: Option<&str>,
        level: Option<&str>,
        levels: &BTreeMap<String, String>,
        rotate_mb: Option<u64>,
        keep: Option<u32>,
    ) -> Result<Self, String> {
        let word = |key: String, w: &str| {
            LogLevel::parse(w).ok_or_else(|| {
                format!("{key}: '{w}' is not a level (off, error, warn, info, debug, trace)")
            })
        };
        let level = level.map_or(Ok(LogLevel::Info), |w| word("plugins.logs.level".into(), w))?;
        let levels = levels
            .iter()
            .map(|(k, w)| Ok((k.clone(), word(format!("plugins.logs.levels['{k}']"), w)?)))
            .collect::<Result<_, String>>()?;
        if rotate_mb == Some(0) {
            return Err("plugins.logs.rotate_mb: must be at least 1".into());
        }
        Ok(Self {
            dir: PathBuf::from(dir.unwrap_or(DEFAULT_DIR)),
            named_dir: dir.is_some(),
            level,
            levels,
            rotate_bytes: rotate_mb.map(|mb| mb.saturating_mul(1024 * 1024)),
            keep: keep.unwrap_or(DEFAULT_KEEP),
            live: Live::default(),
        })
    }

    pub fn level_for(&self, instance: &str) -> LogLevel {
        self.current().level_for(instance)
    }

    pub fn path_for(&self, instance: &str, kind: KindCode) -> PathBuf {
        self.current().dir.join(file_name(instance, kind))
    }

    fn words(&self) -> Words {
        Words {
            dir: self.dir.clone(),
            level: self.level,
            levels: self.levels.clone(),
            rotate_bytes: self.rotate_bytes,
            keep: self.keep,
            named_dir: self.named_dir,
        }
    }

    fn current(&self) -> Arc<Words> {
        self.live
            .0
            .now
            .words()
            .unwrap_or_else(|| Arc::new(self.words()))
    }

    pub fn reconfigure(&self, next: &PluginLogConfig) {
        let words = Arc::new(next.words());
        if *self.current() == *words {
            return;
        }
        if next.named_dir {
            if let Err(e) = crate::durable::create_dir_all(&words.dir) {
                tracing::warn!(
                    error = %format!("plugins.logs.dir {}: {e}", words.dir.display()),
                    "the applied plugin log directory cannot be used"
                );
            }
        }
        let cell = &self.live.0;
        let mut sinks = cell.sinks.lock().unwrap_or_else(|p| p.into_inner());
        *cell.now.words.write().unwrap_or_else(|p| p.into_inner()) = Some(Arc::clone(&words));
        cell.now.generation.fetch_add(1, Ordering::AcqRel);
        sinks.retain(|s| {
            s.upgrade().is_some_and(|s| {
                s.level
                    .store(words.level_for(&s.instance) as u8, Ordering::Release);
                true
            })
        });
    }

    pub fn sink(
        &self,
        instance: &str,
        kind: KindCode,
        metrics: Arc<dyn EnvelopeSink>,
    ) -> Result<PluginLogSink, String> {
        let cell = &self.live.0;
        let (admit, words) = {
            let mut sinks = cell.sinks.lock().unwrap_or_else(|p| p.into_inner());
            let words = self.current();
            let admit = Arc::new(Admit {
                instance: instance.to_string(),
                level: AtomicU8::new(words.level_for(instance) as u8),
            });
            sinks.retain(|s| s.strong_count() > 0);
            sinks.push(Arc::downgrade(&admit));
            (admit, words)
        };
        let name = file_name(instance, kind);
        let path = words.dir.join(&name);
        let tag = Arc::new(Tag {
            instance: instance.to_string(),
            kind: format!("{kind:?}").to_ascii_lowercase(),
        });
        if words.named_dir {
            FileSlot::of(&path)
                .and_then(|slot| slot.open())
                .map_err(|e| refusal(&path, &e))?;
        }
        let lane = {
            let mut lanes = cell.lanes.lock().unwrap_or_else(|p| p.into_inner());
            match lanes.get(&name).and_then(Weak::upgrade) {
                Some(lane) => lane,
                None => {
                    let lane = Lane::start(&name, &cell.now, words, &tag).map_err(|e| {
                        format!("plugins.logs: the log writer of {instance} could not start: {e}")
                    })?;
                    lanes.retain(|_, l| l.strong_count() > 0);
                    lanes.insert(name, Arc::downgrade(&lane));
                    lane
                }
            }
        };
        Ok(PluginLogSink {
            tag,
            admit,
            #[cfg(test)]
            path,
            metrics,
            clock: wall_secs,
            lane,
        })
    }
}

fn file_name(instance: &str, kind: KindCode) -> String {
    let qualified = match crate::boot::kind_of(kind).root_key() {
        Some(section)
            if !instance
                .strip_prefix(section)
                .is_some_and(|rest| rest.starts_with('.')) =>
        {
            format!("{section}.{instance}")
        }
        _ => instance.to_string(),
    };
    let stem: String = qualified
        .bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
                b as char
            } else {
                '_'
            }
        })
        .collect();

    let stem = if stem.bytes().all(|b| b == b'.') {
        stem.replace('.', "_")
    } else {
        stem
    };
    format!("{stem}.log")
}

fn refusal(path: &Path, e: &std::io::Error) -> String {
    let dir = path.parent().unwrap_or(path);
    format!("plugins.logs.dir {}: {e}", dir.display())
}

/// The words of `plugins.logs` a sink and its writer follow.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Words {
    dir: PathBuf,
    level: LogLevel,
    levels: BTreeMap<String, LogLevel>,
    rotate_bytes: Option<u64>,
    keep: u32,
    named_dir: bool,
}

impl Words {
    fn level_for(&self, instance: &str) -> LogLevel {
        self.levels.get(instance).copied().unwrap_or(self.level)
    }
}

/// ONE live setting, shared by every clone of a [`PluginLogConfig`].
#[derive(Clone, Default)]
struct Live(Arc<Cell>);

impl PartialEq for Live {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for Live {}

impl std::fmt::Debug for Live {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Live")
    }
}

#[derive(Default)]
struct Cell {
    /// The words, shared with every writer.
    now: Arc<Now>,
    /// Each file's writer, by file name: every sink of one file shares it.
    lanes: Mutex<HashMap<String, Weak<Lane>>>,
    /// Every open sink's level, set anew by each reconfigure.
    sinks: Mutex<Vec<Weak<Admit>>>,
}

/// The words a writer follows, and how many times they changed.
#[derive(Default)]
struct Now {
    generation: AtomicU64,
    words: RwLock<Option<Arc<Words>>>,
}

impl Now {
    fn words(&self) -> Option<Arc<Words>> {
        self.words.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

struct Admit {
    instance: String,
    level: AtomicU8,
}

struct Tag {
    instance: String,
    kind: String,
}

fn wall_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub const LOG_QUEUE_LINES: usize = 1024;

pub struct PluginLogSink {
    tag: Arc<Tag>,
    admit: Arc<Admit>,

    #[cfg(test)]
    path: PathBuf,
    metrics: Arc<dyn EnvelopeSink>,
    clock: fn() -> u64,

    lane: Arc<Lane>,
}

struct Lane {
    queue: SyncSender<Job>,
    over: Arc<Over>,
}

/// The lines a full queue refused, not yet reported, and the time of the last of them.
#[derive(Default)]
struct Over {
    lines: AtomicU64,
    at: AtomicU64,
}

enum Job {
    Line {
        tag: Arc<Tag>,
        at: u64,
        level: LogLevel,
        text: Vec<u8>,
    },

    Tally,

    #[cfg(test)]
    Flush(SyncSender<()>),
}

impl std::fmt::Debug for PluginLogSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginLogSink")
            .field("instance", &self.tag.instance)
            .field("kind", &self.tag.kind)
            .field(
                "level",
                &LogLevel::of_u8(self.admit.level.load(Ordering::Relaxed)),
            )
            .finish_non_exhaustive()
    }
}

impl PluginLogSink {
    #[cfg(test)]
    #[must_use]
    pub fn with_clock(self, clock: fn() -> u64) -> Self {
        Self { clock, ..self }
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    pub fn flush(&self) {
        let (done, wait) = sync_channel(1);
        if self.lane.queue.send(Job::Flush(done)).is_ok() {
            let _ = wait.recv();
        }
    }

    fn line(&self, level: LogLevel, text: Vec<u8>) {
        if level == LogLevel::Off
            || level > LogLevel::of_u8(self.admit.level.load(Ordering::Acquire))
        {
            return;
        }
        let at = (self.clock)();
        let over = &self.lane.over;
        if over.lines.load(Ordering::Acquire) > 0 {
            let _ = self.lane.queue.try_send(Job::Tally);
        }
        let job = Job::Line {
            tag: Arc::clone(&self.tag),
            at,
            level,
            text,
        };
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.lane.queue.try_send(job)
        {
            over.at.store(at, Ordering::Release);
            over.lines.fetch_add(1, Ordering::AcqRel);

            let _ = self.lane.queue.try_send(Job::Tally);
        }
    }
}

impl Lane {
    fn start(
        name: &str,
        now: &Arc<Now>,
        words: Arc<Words>,
        first: &Arc<Tag>,
    ) -> std::io::Result<Arc<Self>> {
        let (queue, jobs) = sync_channel(LOG_QUEUE_LINES);
        let over = Arc::new(Over::default());
        let writer = Writer {
            name: name.to_string(),
            now: Arc::clone(now),

            seen: u64::MAX,
            path: words.dir.join(name),
            words,
            slot: None,
            over: Arc::clone(&over),
            last: Arc::clone(first),
        };
        std::thread::Builder::new()
            .name("busbar-plugin-log".into())
            .spawn(move || writer.drain(&jobs))?;
        Ok(Arc::new(Self { queue, over }))
    }
}

struct Writer {
    name: String,
    now: Arc<Now>,

    seen: u64,
    words: Arc<Words>,
    path: PathBuf,

    slot: Option<Arc<FileSlot>>,
    over: Arc<Over>,

    last: Arc<Tag>,
}

impl Writer {
    fn drain(mut self, jobs: &Receiver<Job>) {
        while let Ok(job) = jobs.recv() {
            self.run(job);
            while let Ok(job) = jobs.try_recv() {
                self.run(job);
            }
            self.tally();
        }
    }

    fn run(&mut self, job: Job) {
        match job {
            Job::Line {
                tag,
                at,
                level,
                text,
            } => {
                self.line(&tag, at, level, &text);
                self.last = tag;
            }
            Job::Tally => self.tally(),
            #[cfg(test)]
            Job::Flush(done) => {
                self.tally();
                let _ = done.send(());
            }
        }
    }

    fn tally(&mut self) {
        let n = self.over.lines.swap(0, Ordering::AcqRel);
        if n == 0 {
            return;
        }
        let tag = Arc::clone(&self.last);
        let at = self.over.at.load(Ordering::Acquire);
        let text = format!("busbar: {n} log lines were dropped: the log writer was behind");
        self.line(&tag, at, LogLevel::Warn, text.as_bytes());
    }

    fn follow(&mut self) {
        let generation = self.now.generation.load(Ordering::Acquire);
        if generation == self.seen {
            return;
        }
        self.seen = generation;
        if let Some(words) = self.now.words() {
            let path = words.dir.join(&self.name);
            if path != self.path {
                self.path = path;
                self.slot = None;
            }
            self.words = words;
        }
    }

    fn line(&mut self, tag: &Tag, at: u64, level: LogLevel, text: &[u8]) {
        self.follow();
        let line = render(tag, at, level, text);
        let slot = match self.slot.clone() {
            Some(slot) => slot,
            None => match FileSlot::of(&self.path) {
                Ok(slot) => {
                    self.slot = Some(Arc::clone(&slot));
                    slot
                }
                Err(e) => return self.lost(tag, &e),
            },
        };
        match slot.append(line.as_bytes(), self.words.rotate_bytes, self.words.keep) {
            Ok(None) => {}
            Ok(Some(report)) => {
                tracing::warn!(
                    plugin = %tag.instance,
                    file = %slot.path.display(),
                    failed = ?report.failed,
                    "a plugin log file could not be rotated"
                );
                let text = report.line(self.words.rotate_bytes.unwrap_or(0));
                let line = render(tag, at, LogLevel::Warn, text.as_bytes());
                if let Err(e) = slot.append(line.as_bytes(), None, self.words.keep) {
                    self.lost(tag, &e);
                }
            }
            Err(e) => self.lost(tag, &e),
        }
    }

    fn lost(&self, tag: &Tag, e: &std::io::Error) {
        tracing::warn!(
            plugin = %tag.instance,
            error = %refusal(&self.path, e),
            "a plugin log line could not be written"
        );
    }
}

fn render(tag: &Tag, at: u64, level: LogLevel, text: &[u8]) -> String {
    let mut line = format!(
        "{} {} {} {} ",
        busbar_contract::civil::rfc3339_from_secs(at),
        level.label(),
        tag.instance,
        tag.kind
    );
    escape_into(&mut line, text);
    line.push('\n');
    line
}

fn escape_into(line: &mut String, text: &[u8]) {
    use std::fmt::Write as _;
    for c in String::from_utf8_lossy(text).chars() {
        match c {
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            c if c.is_control() => {
                let _ = write!(line, "\\u{{{:x}}}", u32::from(c));
            }
            c => line.push(c),
        }
    }
}

fn mirror(level: LogLevel, text: &[u8]) {
    if !matches!(level, LogLevel::Error | LogLevel::Warn) {
        return;
    }
    let text = String::from_utf8_lossy(text);
    let said_raw = text
        .split_once(": ")
        .map_or(text.as_ref(), |(_, rest)| rest);
    let mut said = String::new();
    escape_into(&mut said, without_diag_field(said_raw).as_bytes());
    match level {
        LogLevel::Error => tracing::error!(target: MIRROR_TARGET, "{said}"),
        _ => tracing::warn!(target: MIRROR_TARGET, "{said}"),
    }
}

fn without_diag_field(text: &str) -> std::borrow::Cow<'_, str> {
    const FIELD: &str = " diag=";
    let Some(at) = text.find(FIELD) else {
        return std::borrow::Cow::Borrowed(text);
    };
    let rest = &text[at + FIELD.len()..];
    let end = rest.find(' ').map_or(text.len(), |i| at + FIELD.len() + i);
    std::borrow::Cow::Owned([&text[..at], &text[end..]].concat())
}

pub const MIRROR_TARGET: &str = "busbar::plugin";

static FILES: Mutex<Option<HashMap<PathBuf, Weak<FileSlot>>>> = Mutex::new(None);

struct FileSlot {
    path: PathBuf,
    state: Mutex<FileState>,
}

#[derive(Default)]
struct FileState {
    /// The open file, and the bytes it holds.
    file: Option<(File, u64)>,
    /// After a rotation that failed, the size the next attempt waits for.
    retry_at: u64,
    /// A failed rotation was reported and none has succeeded since.
    failing: bool,
}

struct RotationReport {
    failed: Vec<crate::host::FailedStep>,
}

impl RotationReport {
    fn line(&self, limit: u64) -> String {
        format!(
            "busbar: this log file could not be rotated ({}); it is tried again once it holds another {limit} bytes",
            self.failed.join(", ")
        )
    }
}

impl FileSlot {
    fn of(path: &Path) -> std::io::Result<Arc<Self>> {
        let (dir, name) = match (path.parent(), path.file_name()) {
            (Some(dir), Some(name)) => (dir, name),
            _ => return Err(std::io::Error::other("no file name")),
        };
        let key = if dir.as_os_str().is_empty() {
            std::env::current_dir()?.join(name)
        } else {
            crate::durable::create_dir_all(dir)?;
            std::fs::canonicalize(dir)?.join(name)
        };
        let mut files = FILES.lock().unwrap_or_else(|p| p.into_inner());
        let files = files.get_or_insert_with(HashMap::new);
        if let Some(slot) = files.get(&key).and_then(Weak::upgrade) {
            return Ok(slot);
        }
        files.retain(|_, s| s.strong_count() > 0);
        let slot = Arc::new(Self {
            path: key.clone(),
            state: Mutex::new(FileState::default()),
        });
        files.insert(key, Arc::downgrade(&slot));
        Ok(slot)
    }

    fn open(&self) -> std::io::Result<()> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if st.file.is_none() {
            st.file = Some(self.opened()?);
        }
        Ok(())
    }

    fn opened(&self) -> std::io::Result<(File, u64)> {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let held = f.metadata().map_or(0, |m| m.len());
        Ok((f, held))
    }

    fn append(
        &self,
        bytes: &[u8],
        rotate: Option<u64>,
        keep: u32,
    ) -> std::io::Result<Option<RotationReport>> {
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let held = match &st.file {
            Some((_, held)) => *held,
            None => std::fs::metadata(&self.path).map_or(0, |m| m.len()),
        };
        let mut report = None;
        if let Some(limit) = rotate.filter(|&limit| held >= limit && held >= st.retry_at) {
            st.file = None;
            let (renamed, failed) = crate::host::rotate(&self.path, keep);
            st.retry_at = if renamed {
                0
            } else {
                held.saturating_add(limit)
            };
            if renamed && failed.is_empty() {
                st.failing = false;
            } else {
                if !st.failing {
                    report = Some(RotationReport { failed });
                }
                st.failing = true;
            }
        }
        if st.file.is_none() {
            st.file = Some(self.opened()?);
        }
        let Some((f, held)) = st.file.as_mut() else {
            return Ok(report);
        };
        f.write_all(bytes)?;
        *held += bytes.len() as u64;
        Ok(report)
    }
}

impl EnvelopeSink for PluginLogSink {
    fn metric(&self, m: Metric<'_>) {
        self.metrics.metric(m);
    }

    fn diag(&self, d: Diagnostic<'_>) {
        let level = LogLevel::of_severity(d.severity);
        if d.id == DIAG_LOG {
            mirror(level, d.text);
            return self.line(level, d.text.to_vec());
        }
        let mut text = Vec::with_capacity(d.name.len() + 2 + d.text.len());
        text.extend_from_slice(d.name);
        text.extend_from_slice(b": ");
        text.extend_from_slice(d.text);
        self.line(level, text);
    }

    fn dropped(&self, why: Dropped) {
        if let Dropped::Logs(n) = why {
            self.line(
                LogLevel::Warn,
                format!("busbar: {n} log records of one reply were dropped over the bound")
                    .into_bytes(),
            );
        }
        self.metrics.dropped(why);
    }
}

#[cfg(test)]
#[path = "../../tests/fixtures/log_witness_plugin.rs"]
mod log_witness_plugin;

#[cfg(test)]
#[path = "../tests/plugin_log_tests.rs"]
pub(crate) mod tests;
