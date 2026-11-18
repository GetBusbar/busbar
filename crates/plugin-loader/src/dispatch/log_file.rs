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
//! `<dir>/<section>.<instance>.log` (the section is omitted when the instance already carries it),
//! the instance name with every byte outside `[A-Za-z0-9._-]` written as
//! `_`. Lines under the instance's configured level are not written. A declared diagnostic is a
//! line too, its id before its text. The records one reply could not carry are one line saying how
//! many. Every control character in a text, and every line separator or bidirectional
//! control (U+2028, U+2029, U+200E, U+200F, U+202A-U+202E, U+2066-U+2069), is escaped, so a record is
//! one line and nothing raw reaches a terminal: a line break is `\n`, a carriage return `\r`, any
//! other `\u{..}`.
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

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, RwLock, Weak};

use busbar_contract::abi::mechanism::call::{
    DIAG_LOG, SEVERITY_DEBUG, SEVERITY_ERROR, SEVERITY_INFO, SEVERITY_TRACE, SEVERITY_WARN,
};

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
    pub(crate) live: Live,
}

pub const DEFAULT_DIR: &str = "logs/plugins";

pub const DEFAULT_KEEP: u32 = 5;

pub(crate) fn refusal(path: &Path, e: &std::io::Error) -> String {
    let dir = path.parent().unwrap_or(path);
    crate::cold::dispatch::load::dir_refusal(dir, e)
}

/// The words of `plugins.logs` a sink and its writer follow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Words {
    pub(crate) dir: PathBuf,
    pub(crate) level: LogLevel,
    pub(crate) levels: BTreeMap<String, LogLevel>,
    pub(crate) rotate_bytes: Option<u64>,
    pub(crate) keep: u32,
    pub(crate) named_dir: bool,
}

impl Words {
    pub(crate) fn level_for(&self, instance: &str) -> LogLevel {
        self.levels.get(instance).copied().unwrap_or(self.level)
    }
}

/// ONE live setting, shared by every clone of a [`PluginLogConfig`].
#[derive(Clone, Default)]
pub(crate) struct Live(pub(crate) Arc<Cell>);

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
pub(crate) struct Cell {
    /// The words, shared with every writer.
    pub(crate) now: Arc<Now>,
    /// Each file's writer, by file name: every sink of one file shares it.
    pub(crate) lanes: Mutex<foldhash::HashMap<String, Weak<Lane>>>,
    /// Every open sink's level, set anew by each reconfigure.
    pub(crate) sinks: Mutex<Vec<Weak<Admit>>>,
}

/// The words a writer follows, and how many times they changed.
#[derive(Default)]
pub(crate) struct Now {
    pub(crate) generation: AtomicU64,
    pub(crate) words: RwLock<Option<Arc<Words>>>,
}

impl Now {
    pub(crate) fn words(&self) -> Option<Arc<Words>> {
        self.words.read().unwrap_or_else(|p| p.into_inner()).clone()
    }
}

pub(crate) struct Admit {
    pub(crate) instance: String,
    pub(crate) level: AtomicU8,
}

pub(crate) struct Tag {
    pub(crate) instance: String,
    pub(crate) kind: String,
}

pub(crate) fn wall_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

pub const LOG_QUEUE_LINES: usize = 1024;

pub struct PluginLogSink {
    pub(crate) tag: Arc<Tag>,
    pub(crate) admit: Arc<Admit>,

    #[cfg(test)]
    pub(crate) path: PathBuf,
    pub(crate) metrics: Arc<dyn EnvelopeSink>,
    pub(crate) clock: fn() -> u64,

    pub(crate) lane: Arc<Lane>,
}

pub(crate) struct Lane {
    pub(crate) queue: SyncSender<Job>,
    pub(crate) over: Arc<Over>,
}

/// The lines a full queue refused, not yet reported, and the time of the last of them.
#[derive(Default)]
pub(crate) struct Over {
    lines: AtomicU64,
    at: AtomicU64,
    /// The writer is gone and the host has been told so.
    gone: AtomicBool,
    /// Line buffers the writer has written and handed back, cleared, for the sinks to copy the
    /// next records into: a record's copy reuses one instead of allocating.
    spare: Mutex<Vec<Vec<u8>>>,
}

/// The most written line buffers a lane keeps for reuse: one full queue's worth.
const SPARE_LINES: usize = LOG_QUEUE_LINES;

impl Over {
    /// A cleared line buffer: one the writer handed back, or a new one when none is spare.
    fn buffer(&self) -> Vec<u8> {
        self.spare
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .pop()
            .unwrap_or_default()
    }

    /// Hand a written line buffer back for reuse, cleared; dropped once enough are spare.
    fn recycle(&self, mut text: Vec<u8>) {
        text.clear();
        let mut spare = self
            .spare
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if spare.len() < SPARE_LINES {
            spare.push(text);
        }
    }
}

pub(crate) enum Job {
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
    #[must_use]
    fn with_lane(self, lane: Arc<Lane>) -> Self {
        Self { lane, ..self }
    }

    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    pub fn flush(&self) {
        let (done, wait) = std::sync::mpsc::sync_channel(1);
        if self.lane.queue.send(Job::Flush(done)).is_ok() {
            let _ = wait.recv();
        }
    }

    /// Whether a line at `level` is written: it is not `Off` and at or under the instance's level.
    fn admits(&self, level: LogLevel) -> bool {
        level != LogLevel::Off && level <= LogLevel::of_u8(self.admit.level.load(Ordering::Acquire))
    }

    fn line(&self, level: LogLevel, text: Vec<u8>) {
        if !self.admits(level) {
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
        if let Err(e) = self.lane.queue.try_send(job) {
            if matches!(e, TrySendError::Disconnected(_)) && !over.gone.swap(true, Ordering::AcqRel)
            {
                tracing::warn!(
                    plugin = %self.tag.instance,
                    "the plugin log writer is gone; this plugin's log lines are lost"
                );
            }
            over.at.store(at, Ordering::Release);
            over.lines.fetch_add(1, Ordering::AcqRel);

            let _ = self.lane.queue.try_send(Job::Tally);
        }
    }
}

pub(crate) struct Writer {
    pub(crate) name: String,
    /// The line being written, reused for every line this writer renders.
    pub(crate) rendered: String,
    pub(crate) now: Arc<Now>,

    pub(crate) seen: u64,
    pub(crate) words: Arc<Words>,
    pub(crate) path: PathBuf,

    pub(crate) slot: Option<Arc<FileSlot>>,
    pub(crate) over: Arc<Over>,

    pub(crate) last: Arc<Tag>,
}

impl Writer {
    pub(crate) fn drain(mut self, jobs: &Receiver<Job>) {
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
                self.over.recycle(text);
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
        let mut text = self.over.buffer();
        let _ = write!(
            text,
            "busbar: {n} log lines were dropped: the log writer was behind"
        );
        self.line(&tag, at, LogLevel::Warn, &text);
        self.over.recycle(text);
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
        let mut line = std::mem::take(&mut self.rendered);
        render(&mut line, tag, at, level, text);
        self.write_line(tag, at, &line);
        self.rendered = line;
    }

    fn write_line(&mut self, tag: &Tag, at: u64, line: &str) {
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
                let mut line = std::mem::take(&mut self.rendered);
                render(&mut line, tag, at, LogLevel::Warn, text.as_bytes());
                let appended = slot.append(line.as_bytes(), None, self.words.keep);
                self.rendered = line;
                if let Err(e) = appended {
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

/// Render one line of a plugin's file into `line` (cleared first): the time, the level, the
/// instance, the kind, then the escaped text.
fn render(line: &mut String, tag: &Tag, at: u64, level: LogLevel, text: &[u8]) {
    use std::fmt::Write as _;
    line.clear();
    let _ = write!(
        line,
        "{} {} {} {} {}",
        busbar_contract::civil::rfc3339_from_secs(at),
        level.label(),
        tag.instance,
        tag.kind,
        Escaped(&String::from_utf8_lossy(text)),
    );
    line.push('\n');
}

/// A text written with every control character, line separator and bidirectional control
/// escaped, so it is one line and nothing raw reaches a terminal.
struct Escaped<'a>(&'a str);

impl std::fmt::Display for Escaped<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use std::fmt::Write as _;
        for c in self.0.chars() {
            match c {
                '\n' => f.write_str("\\n")?,
                '\r' => f.write_str("\\r")?,
                c if c.is_control()
                    || matches!(
                        c,
                        '\u{2028}' | '\u{2029}' | '\u{200E}' | '\u{200F}'
                            | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
                    ) =>
                {
                    write!(f, "\\u{{{:x}}}", u32::from(c))?;
                }
                c => f.write_char(c)?,
            }
        }
        Ok(())
    }
}

fn mirror(level: LogLevel, text: &[u8]) {
    if !matches!(level, LogLevel::Error | LogLevel::Warn) {
        return;
    }
    let text = String::from_utf8_lossy(text);
    let said_raw = text
        .split_once(": ")
        .map_or_else(|| text.as_ref(), |(_, rest)| rest);
    let (before, after) = diag_field_split(said_raw);
    let (before, after) = (Escaped(before), Escaped(after));
    match level {
        LogLevel::Error => tracing::error!(target: MIRROR_TARGET, "{before}{after}"),
        _ => tracing::warn!(target: MIRROR_TARGET, "{before}{after}"),
    }
}

/// `text` around its ` diag=<id>` field: the text before the field and the text after it (empty
/// when it names none).
fn diag_field_split(text: &str) -> (&str, &str) {
    const FIELD: &str = " diag=";
    let Some(at) = text.find(FIELD) else {
        return (text, "");
    };
    let rest = &text[at + FIELD.len()..];
    let end = rest.find(' ').map_or(text.len(), |i| at + FIELD.len() + i);
    (&text[..at], &text[end..])
}

#[cfg(test)]
fn without_diag_field(text: &str) -> std::borrow::Cow<'_, str> {
    match diag_field_split(text) {
        (before, "") => std::borrow::Cow::Borrowed(before),
        (before, after) => std::borrow::Cow::Owned([before, after].concat()),
    }
}

pub const MIRROR_TARGET: &str = "busbar::plugin";

static FILES: Mutex<Option<foldhash::HashMap<PathBuf, Weak<FileSlot>>>> = Mutex::new(None);

pub(crate) struct FileSlot {
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
        crate::cold::dispatch::load::rotation_failed(&self.failed, limit)
    }
}

impl FileSlot {
    pub(crate) fn of(path: &Path) -> std::io::Result<Arc<Self>> {
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
        let files = files.get_or_insert_with(Default::default);
        if let Some(slot) = files.get(&key).and_then(Weak::upgrade) {
            return Ok(slot);
        }
        crate::cold::dispatch::load::prune_weak_map(&mut *files);
        let slot = Arc::new(Self {
            path: key.clone(),
            state: Mutex::new(FileState::default()),
        });
        files.insert(key, Arc::downgrade(&slot));
        Ok(slot)
    }

    pub(crate) fn open(&self) -> std::io::Result<()> {
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
            match self.opened() {
                Ok(file) => st.file = Some(file),
                Err(e) => {
                    if report.is_some() {
                        // The report dies with this error: let a later append build it again.
                        st.failing = false;
                        st.retry_at = 0;
                    }
                    return Err(e);
                }
            }
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
        }
        if !self.admits(level) {
            return;
        }
        // The record is still plugin memory: copy it into a line buffer the writer handed back.
        let mut text = self.lane.over.buffer();
        if d.id != DIAG_LOG {
            text.extend_from_slice(d.name);
            text.extend_from_slice(b": ");
        }
        text.extend_from_slice(d.text);
        self.line(level, text);
    }

    fn dropped(&self, why: Dropped) {
        if let Dropped::Logs(n) = why {
            if self.admits(LogLevel::Warn) {
                let mut text = self.lane.over.buffer();
                let _ = write!(
                    text,
                    "busbar: {n} log records of one reply were dropped over the bound"
                );
                self.line(LogLevel::Warn, text);
            }
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
