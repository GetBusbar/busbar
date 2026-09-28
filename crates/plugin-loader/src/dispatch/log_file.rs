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
use std::sync::{Arc, Mutex};

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
    /// to its own file, its metrics (and every drop) go on to `metrics`. Creates the directory if
    /// it is missing and opens the file; an unusable directory is refused as
    /// `plugins.logs.dir <dir>: <error>`.
    pub fn sink(
        &self,
        instance: &str,
        kind: KindCode,
        metrics: Arc<dyn EnvelopeSink>,
    ) -> Result<PluginLogSink, String> {
        let sink = PluginLogSink {
            instance: instance.to_string(),
            kind: format!("{kind:?}").to_ascii_lowercase(),
            level: self.level_for(instance),
            path: self.path_for(instance),
            rotate_bytes: self.rotate_bytes,
            keep: self.keep,
            metrics,
            clock: wall_secs,
            file: Mutex::new(None),
        };
        let opened = sink.open().map_err(|e| sink.refusal(&e))?;
        *sink.file.lock().unwrap_or_else(|p| p.into_inner()) = Some(opened);
        Ok(sink)
    }
}

/// Seconds since the epoch, on the wall clock.
fn wall_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// ONE plugin instance's log file, as an [`EnvelopeSink`].
pub struct PluginLogSink {
    instance: String,
    kind: String,
    level: LogLevel,
    path: PathBuf,
    rotate_bytes: Option<u64>,
    keep: u32,
    metrics: Arc<dyn EnvelopeSink>,
    clock: fn() -> u64,
    /// The open file, and the bytes it holds; every line is written under this lock.
    file: Mutex<Option<(File, u64)>>,
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
    /// The same sink with its time read from `clock` (seconds since the epoch).
    #[must_use]
    pub fn with_clock(self, clock: fn() -> u64) -> Self {
        Self { clock, ..self }
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

    /// The file this sink writes.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Write one line at `level`, if the instance's level admits it. A failure to write is reported
    /// on the host's own log and the line is lost; it never reaches the plugin.
    fn line(&self, level: LogLevel, text: &[u8]) {
        if level == LogLevel::Off || level > self.level {
            return;
        }
        let mut line = format!(
            "{} {} {} {} ",
            busbar_contract::civil::rfc3339_from_secs((self.clock)()),
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

    fn append(&self, bytes: &[u8]) -> std::io::Result<()> {
        let mut file = self.file.lock().unwrap_or_else(|p| p.into_inner());
        let due = match (&*file, self.rotate_bytes) {
            (Some((_, held)), Some(limit)) => *held >= limit,
            (None, Some(limit)) => std::fs::metadata(&self.path).is_ok_and(|m| m.len() >= limit),
            _ => false,
        };
        if due {
            *file = None;
            crate::host::rotate(&self.path.to_string_lossy(), self.keep);
        }
        if file.is_none() {
            *file = Some(self.open()?);
        }
        let Some((f, held)) = file.as_mut() else {
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
            return self.line(level, d.text);
        }
        let mut text = d.name.to_vec();
        text.extend_from_slice(b": ");
        text.extend_from_slice(d.text);
        self.line(level, &text);
    }

    fn dropped(&self, why: Dropped) {
        if let Dropped::Logs(n) = why {
            self.line(
                LogLevel::Warn,
                format!("busbar: {n} log records of one reply were dropped over the bound")
                    .as_bytes(),
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
