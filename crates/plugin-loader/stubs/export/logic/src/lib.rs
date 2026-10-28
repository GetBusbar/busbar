// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The **request-log FILE sink** (`module: request-log-file`, PUSH): each request-log batch the host
//! builds for this instance is appended to a JSONL file.
//!
//! A `kind: export` plugin on the export kind's memory ABI (`busbar_contract::abi::export`, THE
//! DESIGN §11): ONE door ([`door`], `plugin_door!`), linked into the binary as a compiled-in row or
//! exported by the sibling `busbar-export-file-plugin` cdylib as its one symbol. Its manifest still
//! carries [`DECLARES`] (`busbar-plugin-pack --declares-file declares.json`): its one series (1.5.5's
//! shed counter), the five catalogue codes and the one destination.
//!
//! **The sink never opens a path.** Its manifest declares `path` a DESTINATION: the host binds the
//! operator's configured path, and every append and every rotation is a host act on the host's
//! bounded disk lane (THE DESIGN §11.11 R4, the `disk.append` service of §11.12): a delivery hands
//! the batch, unchanged, to `disk.append` under the key `path`, and the host appends it whole —
//! rotating the file by rename first when it already holds `rotate_mb` MiB. What the host reports
//! back is raised in the words the sink always raised: an append the host could not make drops the
//! batch with the open-failed ([`OPEN_FAILED`]) or append-failed ([`APPEND_FAILED`]) line, and each
//! failed step of a rotation with its own declared code.
//!
//! Settings are validated by the sink itself while the host validates the configuration, with the
//! same serde shape ([`config::FileSettings`]) and so the same words.

#![forbid(unsafe_code)]

pub mod config;

use std::mem::size_of;
use std::sync::{PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::export::{
    self, CheckIn, CheckOut, DeliverIn, ExportStream, ScrapeIn, ScrapeOut, ServeIn, ServeOut,
    StatusOut, Tail,
};
use busbar_contract::abi::host::service::{
    DiskWritten, DISK_OPEN_FAILED, DISK_RENAME_FAILED, DISK_RETENTION_FAILED, DISK_ROTATED,
    DISK_SHIFT_FAILED,
};
use busbar_contract::abi::mechanism::call::{AbiStr, InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Rewrite, Statement, REWRITE_ALIAS};
use busbar_contract::abi::sdk::conn::{ConnFailure, DiskFailure, Host};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use config::FileSettings;

/// The plugin's canonical name.
pub const NAME: &str = "busbar-stub-export";

/// The `module:` an operator writes — the frozen 1.5.x module name.
pub const ALIAS: &str = "request-log-file";

/// What this sink DECLARES to the host (the manifest's `declares` section): its one series, its
/// five catalogue codes and its one destination. The packer embeds it (`--declares-file`).
pub const DECLARES: &str = include_str!("../declares.json");

/// How many rotated archives ONE sink keeps (`<path>.1` .. `<path>.{ROTATE_ARCHIVE_LIMIT}`) before the
/// oldest is dropped to make room for a new rotation: the retention the host's disk lane applies to
/// this sink's destination, the host's own constant. A RETENTION policy, not a truncation one.
pub const ROTATE_ARCHIVE_LIMIT: u32 = busbar_contract::services::DISK_KEEP;

/// The most appends one instance holds in flight (1.5.5's `MAX_INFLIGHT_FILE_APPENDS`); past it the
/// host sheds the line and counts the declared shed counter.
pub const MAX_INFLIGHT: u32 = 64;

/// The declared destination: the settings key naming the file.
pub const DESTINATION: &str = "path";

/// The catalogue code a dropped line is raised under: writing the opened file failed.
pub const APPEND_FAILED: &str = "BUSBAR-7073";
/// The catalogue code a dropped line is raised under: the file could not be opened for the append.
pub const OPEN_FAILED: &str = "BUSBAR-7074";
/// The catalogue code a rotation raises when dropping the oldest archive failed.
pub const RETENTION_FAILED: &str = "BUSBAR-7075";
/// The catalogue code a rotation raises when shifting an archive up one slot failed.
pub const SHIFT_FAILED: &str = "BUSBAR-7076";
/// The catalogue code a rotation raises when renaming the live file to its first archive failed.
pub const ROTATE_RENAME_FAILED: &str = "BUSBAR-7077";

/// The streams this sink carries: the request log.
const STREAMS: &[u8] = &[ExportStream::Logs as u8];

/// The export kind's Statement tail: `logs`, and no route (a push-only sink).
const TAIL: Tail = Tail {
    head: KindTailHead {
        size: size_of::<Tail>() as u32,
        _reserved: 0,
    },
    streams: STREAMS.as_ptr(),
    streams_len: STREAMS.len(),
    routes: std::ptr::null(),
    routes_len: 0,
};

/// The module name an operator writes, as the alias the registry holds beside [`NAME`].
const REWRITES: &[Rewrite] = &[Rewrite {
    class: REWRITE_ALIAS,
    _reserved: 0,
    from: abi_str(ALIAS),
    to: AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    },
}];

/// This plugin's Statement: its name, version, in-flight bound, alias and stream.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    ..statement(NAME, env!("CARGO_PKG_VERSION"), MAX_INFLIGHT)
};

/// The settings, parsed as the configuration grammar parses them (empty is `{}`).
fn parse(settings: &[u8]) -> Result<FileSettings, Refusal> {
    let bytes = if settings.is_empty() { b"{}" } else { settings };
    serde_json::from_slice::<serde_json::Value>(bytes)
        .and_then(serde_json::from_value)
        .map_err(|e| Refusal::failed(format!("settings: {e}")))
}

/// One opened instance.
#[derive(Debug)]
pub struct FileSink {
    /// The instance's settings; `None` when they do not parse (validation already refused them, so
    /// an instance that got this far is never configured that way — it simply writes nothing).
    settings: RwLock<Option<FileSettings>>,
}

impl Life for FileSink {
    const CANCEL: u32 = export::cancel::ABORTED;

    /// The settings' shape, in the configuration grammar's own serde words.
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        parse(settings).map(|_| ())
    }

    /// Never refuses: the settings were validated with the configuration, and an instance whose
    /// settings do not parse writes nothing.
    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            settings: RwLock::new(parse(settings).ok()),
        })
    }

    /// A reload's settings replace the instance's.
    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        *self
            .settings
            .write()
            .unwrap_or_else(PoisonError::into_inner) = parse(settings).ok();
        Ok(Refreshed::default())
    }
}

impl FileSink {
    /// The configured path; `None` when the settings did not parse (the instance writes nothing).
    pub fn path(&self) -> Option<String> {
        self.settings
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|s| s.path.clone())
    }

    /// Have the host append `batch` (JSON lines, unchanged) to the destination on `host`'s disk
    /// lane, under the op running on `ticket`: what [`Connector::disk_append`] answered. An instance
    /// whose settings did not parse, or an empty batch, appends nothing and answers at once.
    ///
    /// [`Connector::disk_append`]: busbar_contract::abi::sdk::conn::Connector::disk_append
    pub fn append(
        &self,
        host: Option<&Host>,
        ticket: busbar_contract::abi::mechanism::ticket::Ticket,
        batch: &[u8],
    ) -> Poll<Option<Result<DiskWritten, DiskFailure>>> {
        if batch.is_empty() || self.path().is_none() {
            return Poll::Ready(None);
        }
        let Some(host) = host else {
            return Poll::Ready(Some(Err(DiskFailure {
                step: 0,
                rotation: no_rotation(),
                why: ConnFailure::Unarmed,
            })));
        };
        host.connector(ticket)
            .disk_append(DESTINATION, batch)
            .map(Some)
    }

    /// Raise what the host reported for one append, in the order it happened: each failed step of
    /// the rotation that ran before it, the rotation itself, then — when the batch did not land —
    /// the line that says it was dropped.
    pub fn settle(&self, answer: &Result<DiskWritten, DiskFailure>) {
        self.settle_at(&self.path().unwrap_or_default(), answer);
    }

    /// [`FileSink::settle`] naming `path`: the file the append was issued against, which a reload
    /// that landed while the append was pending may have replaced in the settings.
    pub fn settle_at(&self, path: &str, answer: &Result<DiskWritten, DiskFailure>) {
        let rotation = match answer {
            Ok(w) => *w,
            Err(f) => f.rotation,
        };
        if rotation.faults & DISK_RETENTION_FAILED != 0 {
            tracing::warn!(
                diag = %RETENTION_FAILED,
                archive = %format!("{path}.{ROTATE_ARCHIVE_LIMIT}"),
                "request-log archive retention cleanup failed; the archive series may exceed ROTATE_ARCHIVE_LIMIT"
            );
        }
        if rotation.faults & DISK_SHIFT_FAILED != 0 {
            tracing::warn!(
                diag = %SHIFT_FAILED,
                path = %path,
                "request-log archive shift failed; older archive left in place rather than lost"
            );
        }
        if rotation.faults & DISK_RENAME_FAILED != 0 {
            tracing::warn!(
                diag = %ROTATE_RENAME_FAILED,
                path = %path,
                "request-log file rotation rename failed; continuing to APPEND to the current file \
                 rather than truncate it, so no recorded data is lost — the file will exceed rotate_mb \
                 until this is resolved"
            );
        }
        if rotation.rotated == DISK_ROTATED {
            tracing::info!(path = %path, archive = %format!("{path}.1"), "request-log file rotated by rename");
        }
        match answer {
            Ok(_) => {}
            // The host could not open the file for the append: the file it could not open, a
            // destination it never opened (one this sink was not granted), or its disk lane full.
            Err(f) if f.step == DISK_OPEN_FAILED => {
                tracing::warn!(diag = %OPEN_FAILED, path = %path, error = %f.why, "request-log file open failed; this log was dropped");
            }
            // Every other append that did not land is the append-failed line, in the host's words:
            // the write itself failed, or the append was never run (no ticket, no disk service, a
            // fault), which is no file-open problem, so not BUSBAR-7074 and its disk remedy. A
            // plugin speaks only over the ABI (Part 2 #2): every dropped batch carries a declared code.
            Err(f) => {
                tracing::warn!(diag = %APPEND_FAILED, path = %path, error = %f.why, "request-log file append failed; this log was dropped");
            }
        }
    }
}

/// A report of no rotation.
const fn no_rotation() -> DiskWritten {
    DiskWritten {
        size: 0,
        rotated: 0,
        faults: 0,
        _reserved: [0; 2],
        written: 0,
    }
}

/// The instance state every slot reads.
type State = Held<FileSink>;

/// `deliver`: the batch appended through the host's disk lane ([`FileSink::append`]), pending
/// while the host appends; fire-and-forget, so READY whatever became of the line once the host
/// answered ([`FileSink::settle`] raises what it reported).
pub struct Deliver;

impl SafeSlot for Deliver {
    type In = DeliverIn;
    type Out = OutHead;
    type State = State;
    fn call(
        instance: Instance<'_, State>,
        input: Lent<'_, DeliverIn>,
        _: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Refused;
        };
        // A resumed delivery re-issues the append it parked (the host answers its stored result);
        // a fresh one appends the batch it was lent.
        // The batch is the lent `in`, which a resume re-presents from continuation-owned memory
        // (spec A.5), so it is never copied. What is parked is the path the append was issued
        // against, so the lines a late answer raises name that file, not a reload's new one.
        let issued_at: String = instance
            .resume::<String>()
            .map(|p| *p)
            .unwrap_or_else(|| h.life().path().unwrap_or_default());
        let batch: &[u8] = input.field(|i| &i.batch).bytes();
        match h.life().append(h.host(), instance.ticket(), batch) {
            Poll::Pending => {
                instance.park(issued_at);
                Outcome::Pending
            }
            Poll::Ready(Some(answer)) => {
                h.life().settle_at(&issued_at, &answer);
                Outcome::Ready
            }
            Poll::Ready(None) => Outcome::Ready,
        }
    }
}

/// `scrape`: a push sink renders no exposition.
pub struct Scrape;

impl SafeSlot for Scrape {
    type In = ScrapeIn;
    type Out = ScrapeOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, ScrapeIn>, _: Out<'_, ScrapeOut>) -> Outcome {
        Outcome::Ready
    }
}

/// `status`: nothing to report.
pub struct Status;

impl SafeSlot for Status {
    type In = InHead;
    type Out = StatusOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, InHead>, _: Out<'_, StatusOut>) -> Outcome {
        Outcome::Ready
    }
}

/// `check`: no check across instances; each instance's settings are `validate`'s.
pub struct Check;

impl SafeSlot for Check {
    type In = CheckIn;
    type Out = CheckOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, CheckIn>, _: Out<'_, CheckOut>) -> Outcome {
        Outcome::Ready
    }
}

/// `serve`: no route, so any request is `404`.
pub struct Serve;

impl SafeSlot for Serve {
    type In = ServeIn;
    type Out = ServeOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, ServeIn>, mut out: Out<'_, ServeOut>) -> Outcome {
        out.set(|o| &o.status_code, 404_u16);
        Outcome::Ready
    }
}

mod table {
    use super::{Check, Deliver, FileSink, Safe, Scrape, Serve, Status};

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: super::STATEMENT,
        lifecycle: life(FileSink),
        kind_ops: {
            deliver: Safe<Deliver>, scrape: Safe<Scrape>, status: Safe<Status>,
            check: Safe<Check>, serve: Safe<Serve>,
        },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::door;
