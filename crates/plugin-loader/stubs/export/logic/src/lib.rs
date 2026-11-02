// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

pub const NAME: &str = "busbar-stub-export";

pub const ALIAS: &str = "request-log-file";

pub const DECLARES: &str = include_str!("../declares.json");

pub const ROTATE_ARCHIVE_LIMIT: u32 = busbar_contract::services::DISK_KEEP;

pub const MAX_INFLIGHT: u32 = 64;

pub const DESTINATION: &str = "path";

pub const APPEND_FAILED: &str = "BUSBAR-7073";

pub const OPEN_FAILED: &str = "BUSBAR-7074";

pub const RETENTION_FAILED: &str = "BUSBAR-7075";

pub const SHIFT_FAILED: &str = "BUSBAR-7076";

pub const ROTATE_RENAME_FAILED: &str = "BUSBAR-7077";

const STREAMS: &[u8] = &[ExportStream::Logs as u8, ExportStream::Events as u8];

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

const REWRITES: &[Rewrite] = &[Rewrite {
    class: REWRITE_ALIAS,
    _reserved: 0,
    from: abi_str(ALIAS),
    to: AbiStr {
        ptr: std::ptr::null(),
        len: 0,
    },
}];

pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    ..statement(NAME, env!("CARGO_PKG_VERSION"), MAX_INFLIGHT)
};

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

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        parse(settings).map(|_| ())
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            settings: RwLock::new(parse(settings).ok()),
        })
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let settings = parse(settings)?;
        *self
            .settings
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(settings);
        Ok(Refreshed::default())
    }
}

impl FileSink {
    pub fn path(&self) -> Option<String> {
        self.settings
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|s| s.path.clone())
    }

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

    pub fn settle(&self, answer: &Result<DiskWritten, DiskFailure>) {
        self.settle_at(&self.path().unwrap_or_default(), answer);
    }

    pub fn settle_at(&self, path: &str, answer: &Result<DiskWritten, DiskFailure>) {
        let rotation = match answer {
            Ok(w) => *w,
            Err(f) => f.rotation,
        };
        if rotation.faults & DISK_RETENTION_FAILED != 0 {
            tracing::warn!(
                diag = %RETENTION_FAILED,
                path = %path,
                "request-log archive retention cleanup failed; the archive series may exceed configured retention"
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

            Err(f) if f.step == DISK_OPEN_FAILED => {
                tracing::warn!(diag = %OPEN_FAILED, path = %path, error = %f.why, "request-log file open failed; this log was dropped");
            }

            Err(f) => {
                tracing::warn!(diag = %APPEND_FAILED, path = %path, error = %f.why, "request-log file append failed; this log was dropped");
            }
        }
    }
}

const fn no_rotation() -> DiskWritten {
    DiskWritten {
        size: 0,
        rotated: 0,
        faults: 0,
        _reserved: [0; 2],
        written: 0,
    }
}

type State = Held<FileSink>;

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

pub struct Scrape;

impl SafeSlot for Scrape {
    type In = ScrapeIn;
    type Out = ScrapeOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, ScrapeIn>, _: Out<'_, ScrapeOut>) -> Outcome {
        Outcome::Ready
    }
}

pub struct Status;

impl SafeSlot for Status {
    type In = InHead;
    type Out = StatusOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, InHead>, _: Out<'_, StatusOut>) -> Outcome {
        Outcome::Ready
    }
}

pub struct Check;

impl SafeSlot for Check {
    type In = CheckIn;
    type Out = CheckOut;
    type State = State;
    fn call(_: Instance<'_, State>, _: Lent<'_, CheckIn>, _: Out<'_, CheckOut>) -> Outcome {
        Outcome::Ready
    }
}

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

pub use table::door;
