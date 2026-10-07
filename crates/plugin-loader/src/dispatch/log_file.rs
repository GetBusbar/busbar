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
//! many.
//!
//! OFF THE DISPATCH WORKER (§11.2: no blocking on the hot path; §11.11 R4: the bounded disk lane is
//! the SQLite store's and the file export sink's alone, so plugin logging may not claim it). The
//! sink is fed inside the crossing, where the reply's records are still plugin memory, so there it
//! only checks the level, copies the record and hands it to the instance's own writer thread with
//! a send that never waits. The writer opens, rotates and writes the file. Its queue holds
//! [`LOG_QUEUE_LINES`]; a line handed over while it is full is counted, not written, and the lines
//! one full queue lost are one line saying how many, written once the writer has caught up.
//!
//! ROTATION follows the host's one file rule (the host-effect `rotate`): once the file holds the
//! configured size, it is renamed to `<file>.1` (older archives shift up, `keep` of them kept) and a
//! new file begins. No size configured: never rotated.
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
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;

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
    /// The level a config word names: `off`, `error`, `warn`, `info`, `debug` or `trace`.
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

    /// The level a reply's severity carries.
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

    /// The level as a line shows it, five wide.
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
}

/// `plugins.logs.dir` when unset.
pub const DEFAULT_DIR: &str = "logs/plugins";
/// `plugins.logs.keep` when unset.
pub const DEFAULT_KEEP: u32 = 5;

impl PluginLogConfig {
    /// Resolve the `plugins.logs` block: `dir` (default [`DEFAULT_DIR`]), `level` (default `info`),
    /// per-instance `levels`, `rotate_mb` (unset: never rotate) and `keep` (default
    /// [`DEFAULT_KEEP`]). A level word that names no level, or a zero `rotate_mb`, is an error
    /// naming its key.
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
        })
    }

    /// The level `instance` logs at.
    pub fn level_for(&self, instance: &str) -> LogLevel {
        self.levels.get(instance).copied().unwrap_or(self.level)
    }

    /// The file `instance` logs to.
    pub fn path_for(&self, instance: &str) -> PathBuf {
        let stem: String = instance
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
                    b as char
                } else {
                    '_'
                }
            })
            .collect();
        // A name of dots only would name the directory itself or its parent.
        let stem = if stem.bytes().all(|b| b == b'.') {
            stem.replace('.', "_")
        } else {
            stem
        };
        self.dir.join(format!("{stem}.log"))
    }

    /// OPEN the sink a plugin instance is bound with: its log records and declared diagnostics go
    /// to its own file, its metrics (and every drop) go on to `metrics`. Under a named directory it
    /// creates the directory if it is missing and opens the file, and an unusable directory is
    /// refused as `plugins.logs.dir <dir>: <error>`; under the default one the file is created at
    /// its first line ([`PluginLogConfig::named_dir`]).
    pub fn sink(
        &self,
        instance: &str,
        kind: KindCode,
        metrics: Arc<dyn EnvelopeSink>,
    ) -> Result<PluginLogSink, String> {
        let writer = Writer {
            instance: instance.to_string(),
            kind: format!("{kind:?}").to_ascii_lowercase(),
            path: self.path_for(instance),
            rotate_bytes: self.rotate_bytes,
            keep: self.keep,
            over: Arc::default(),
            file: None,
        };
        let file = if self.named_dir {
            Some(writer.open().map_err(|e| writer.refusal(&e))?)
        } else {
            None
        };
        PluginLogSink::start(Writer { file, ..writer }, self.level_for(instance), metrics)
    }
}

/// Seconds since the epoch, on the wall clock.
fn wall_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The most lines one instance's writer holds unwritten. A line handed over while it is full is
/// not written: it is counted, and the count is ONE line once the writer has caught up.
pub const LOG_QUEUE_LINES: usize = 1024;

/// ONE plugin instance's log file, as an [`EnvelopeSink`]. It formats nothing and touches no file:
/// each admitted record is copied, stamped and handed to the instance's own writer thread without
/// waiting ([`LOG_QUEUE_LINES`]).
pub struct PluginLogSink {
    instance: String,
    kind: String,
    level: LogLevel,
    path: PathBuf,
    metrics: Arc<dyn EnvelopeSink>,
    clock: fn() -> u64,
    /// The writer's queue; never waited on from [`EnvelopeSink`].
    lane: SyncSender<Job>,
    /// The lines the queue had no room for, shared with the writer that reports them.
    over: Arc<Over>,
}

/// The lines a full queue refused, not yet reported, and the time of the last of them.
#[derive(Default)]
struct Over {
    lines: AtomicU64,
    at: AtomicU64,
}

/// What the writer thread is handed.
enum Job {
    /// One record: its time, its level and its text as the plugin sent it.
    Line {
        at: u64,
        level: LogLevel,
        text: Vec<u8>,
    },
    /// Report the lines a full queue refused, here in the file's order.
    Tally,
    /// Answer once every line handed over before this one is written.
    Flush(SyncSender<()>),
}

impl std::fmt::Debug for PluginLogSink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginLogSink")
            .field("instance", &self.instance)
            .field("kind", &self.kind)
            .field("level", &self.level)
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl PluginLogSink {
    /// The sink of `writer`'s instance, its writer thread started (its file already open under a
    /// named directory).
    fn start(
        writer: Writer,
        level: LogLevel,
        metrics: Arc<dyn EnvelopeSink>,
    ) -> Result<Self, String> {
        let (lane, queue) = sync_channel(LOG_QUEUE_LINES);
        let sink = Self {
            instance: writer.instance.clone(),
            kind: writer.kind.clone(),
            level,
            path: writer.path.clone(),
            metrics,
            clock: wall_secs,
            lane,
            over: writer.over.clone(),
        };
        std::thread::Builder::new()
            .name("busbar-plugin-log".into())
            .spawn(move || writer.drain(&queue))
            .map_err(|e| {
                format!(
                    "plugins.logs: the log writer of {} could not start: {e}",
                    sink.instance
                )
            })?;
        Ok(sink)
    }

    /// The same sink with its time read from `clock` (seconds since the epoch).
    #[must_use]
    pub fn with_clock(self, clock: fn() -> u64) -> Self {
        Self { clock, ..self }
    }

    /// The file this sink writes.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Wait until every line handed over before this call is in the file (or was reported lost).
    /// It waits on the writer: never call it on a dispatch worker.
    pub fn flush(&self) {
        let (done, wait) = sync_channel(1);
        if self.lane.send(Job::Flush(done)).is_ok() {
            let _ = wait.recv();
        }
    }

    /// Hand one line at `level` to the writer, if the instance's level admits it. Never waits: a
    /// full queue counts the line instead, and the count is written once the writer catches up.
    fn line(&self, level: LogLevel, text: Vec<u8>) {
        if level == LogLevel::Off || level > self.level {
            return;
        }
        let at = (self.clock)();
        if self.over.lines.load(Ordering::Acquire) > 0 {
            // The lines lost so far are reported before this one, in the file's order.
            let _ = self.lane.try_send(Job::Tally);
        }
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.lane.try_send(Job::Line { at, level, text })
        {
            self.over.at.store(at, Ordering::Release);
            self.over.lines.fetch_add(1, Ordering::AcqRel);
            // The writer may have emptied the queue since: then this Tally reports the count; if
            // the queue is still full, the writer reports it when it has drained what it holds.
            let _ = self.lane.try_send(Job::Tally);
        }
    }
}

/// THE WRITER: one instance's file, owned by its own thread. Every open, rotation and write of the
/// file happens here, never on the thread that crossed into the plugin.
struct Writer {
    instance: String,
    kind: String,
    path: PathBuf,
    rotate_bytes: Option<u64>,
    keep: u32,
    over: Arc<Over>,
    /// The open file, and the bytes it holds.
    file: Option<(File, u64)>,
}

impl Writer {
    /// Write every job until the sink is gone; whenever the queue runs empty, report what a full
    /// queue refused.
    fn drain(mut self, queue: &Receiver<Job>) {
        while let Ok(job) = queue.recv() {
            self.run(job);
            while let Ok(job) = queue.try_recv() {
                self.run(job);
            }
            self.tally();
        }
    }

    fn run(&mut self, job: Job) {
        match job {
            Job::Line { at, level, text } => self.line(at, level, &text),
            Job::Tally => self.tally(),
            Job::Flush(done) => {
                self.tally();
                let _ = done.send(());
            }
        }
    }

    /// The lines a full queue refused, as ONE line saying how many.
    fn tally(&mut self) {
        let n = self.over.lines.swap(0, Ordering::AcqRel);
        if n > 0 {
            let at = self.over.at.load(Ordering::Acquire);
            let text = format!("busbar: {n} log lines were dropped: the log writer was behind");
            self.line(at, LogLevel::Warn, text.as_bytes());
        }
    }

    /// Create the directory if it is missing (create-or-reuse), then open the file for append.
    fn open(&self) -> std::io::Result<(File, u64)> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            crate::durable::create_dir_all(dir)?;
        }
        let f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        let held = f.metadata().map_or(0, |m| m.len());
        Ok((f, held))
    }

    /// The refusal an unusable directory earns, naming the key and the directory.
    fn refusal(&self, e: &std::io::Error) -> String {
        let dir = self.path.parent().unwrap_or(&self.path);
        format!("plugins.logs.dir {}: {e}", dir.display())
    }

    /// Write one line. A failure to write is reported on the host's own log and the line is lost;
    /// it never reaches the plugin.
    fn line(&mut self, at: u64, level: LogLevel, text: &[u8]) {
        let mut line = format!(
            "{} {} {} {} ",
            busbar_contract::civil::rfc3339_from_secs(at),
            level.label(),
            self.instance,
            self.kind
        );
        // One record is one line: a line break inside the text is written as `\n`.
        for c in String::from_utf8_lossy(text).chars() {
            match c {
                '\n' => line.push_str("\\n"),
                '\r' => line.push_str("\\r"),
                c => line.push(c),
            }
        }
        line.push('\n');
        if let Err(e) = self.append(line.as_bytes()) {
            tracing::warn!(
                plugin = %self.instance,
                error = %self.refusal(&e),
                "a plugin log line could not be written"
            );
        }
    }

    fn append(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let due = match (&self.file, self.rotate_bytes) {
            (Some((_, held)), Some(limit)) => *held >= limit,
            (None, Some(limit)) => std::fs::metadata(&self.path).is_ok_and(|m| m.len() >= limit),
            _ => false,
        };
        if due {
            self.file = None;
            crate::host::rotate(&self.path.to_string_lossy(), self.keep);
        }
        if self.file.is_none() {
            self.file = Some(self.open()?);
        }
        let Some((f, held)) = self.file.as_mut() else {
            return Ok(());
        };
        f.write_all(bytes)?;
        *held += bytes.len() as u64;
        Ok(())
    }
}

impl EnvelopeSink for PluginLogSink {
    fn metric(&self, m: Metric<'_>) {
        self.metrics.metric(m);
    }

    fn diag(&self, d: Diagnostic<'_>) {
        let level = LogLevel::of_severity(d.severity);
        if d.id == DIAG_LOG {
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

/// The plugin-logging witness, compiled in: the LINKED door of the tests below (the same source is
/// the `log_witness_door` example `cdylib`, the DROPPED door).
#[cfg(test)]
#[path = "../../tests/fixtures/log_witness_plugin.rs"]
mod log_witness_plugin;

#[cfg(test)]
#[path = "../tests/plugin_log_tests.rs"]
mod tests;
