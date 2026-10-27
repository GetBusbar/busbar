// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the prometheus sink on the export kind's table (`busbar_contract::abi::export`), its
//! lifecycle the SDK's generic one over [`Prometheus`] (`abi::sdk::life`), every kind op a
//! [`SafeSlot`].
//!
//! * `validate` — [`crate::validate`]: the configuration's words, the zero-retention refusal included.
//! * `open` / `refresh` — nothing to hold but the size the last snapshot took (the buffer the next
//!   read starts with).
//! * `serve` — THE SINK'S OWN ROUTES (`BUSBAR-1.6.0.md` Appendix A B.5, l.3829: "`/metrics` and
//!   `/metrics/hooks` are the scrape sink's own listener needs: declared in its `routes` list,
//!   served on the data listener behind the data key, and answered by its `serve`"; §5
//!   l.626-628). The Statement declares `GET /metrics` and `GET /metrics/hooks` behind the data
//!   key; `serve` reads the host's families through the host snapshot service (`snapshot.read`,
//!   scope WHOLE or HOOKS) and answers 1.5.5's bytes: `200` with the exposition
//!   ([`crate::render`]) under `text/plain; version=0.0.4`, or the hook exposition
//!   ([`crate::render_hooks`]) under `text/plain; version=0.0.4; charset=utf-8`; NOT READY (the
//!   host's recorder is not installed yet) is `503` with `Retry-After: 1` and no body. A read the
//!   host declines is FAILED (the host answers `502`); any other path is REFUSED.
//! * `scrape` — a snapshot the host hands in, rendered ([`crate::render`]) into the host's buffer; a
//!   buffer too small is FAILED with the bytes `needed`, nothing written, and the host calls again
//!   once. With `SCRAPE_FLAG_HOOK_FAMILIES` on the head the families are the host's hook families
//!   and render as 1.5.5's `/metrics/hooks` ([`crate::render_hooks`]).
//! * `deliver` — READY, nothing kept: the host pulls `metrics`, it never pushes them.
//! * `status` — READY with nothing to report. `check` — at the limits phase, 1.5.5's refusal of
//!   every instance after the first ([`crate::check_limits`]): the sink states the `one_instance`
//!   mark, so the host asks it while the configuration is resolved; READY with nothing otherwise.
//!
//! No `unsafe` here: the snapshot and the buffer `scrape` is lent are read and written through the
//! SDK's safe lend (`families()`, `samples()`, `labels()`, `buf()`).

use std::sync::atomic::{AtomicUsize, Ordering};

use busbar_contract::abi::export::{
    cancel, CheckIn, CheckOut, DeliverIn, ExportStream, Route, ScrapeIn, ScrapeOut, ServeIn,
    ServeOut, StatusOut, Tail, CHECK_PHASE_LIMITS, ROUTE_AUTH_KEY, SCRAPE_FLAG_HOOK_FAMILIES,
};
use busbar_contract::abi::host::service::{SNAPSHOT_SCOPE_HOOKS, SNAPSHOT_SCOPE_WHOLE};
use busbar_contract::abi::mechanism::call::{
    AbiStr, InHead, OutHead, Outcome, BLOB_JSON, BLOB_OCTETS,
};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement, MARK_ONE_INSTANCE};
use busbar_contract::abi::mechanism::ticket::{CompletionHandle, Ticket};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{
    Instance, Lent, MetricFamily, MetricSample, Out, Safe, SafeSlot, ServiceError, Services,
};

use crate::NAME;

/// The one stream the sink carries.
const STREAMS: &[u8] = &[ExportStream::Metrics as u8];

/// A `'static` string as the ABI names it.
const fn abi(s: &'static str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

/// The well-known exposition path.
const METRICS: &str = "/metrics";
/// The well-known hook exposition path.
const METRICS_HOOKS: &str = "/metrics/hooks";

/// `GET path` behind the data plane's key.
const fn get(path: &'static str) -> Route {
    Route {
        path: abi(path),
        method: abi("GET"),
        auth: ROUTE_AUTH_KEY,
        _reserved: 0,
    }
}

/// The sink's own routes: the two well-known expositions, 1.5.5's paths behind the data key.
const ROUTES: &[Route] = &[get(METRICS), get(METRICS_HOOKS)];

const TAIL: Tail = Tail {
    head: KindTailHead {
        size: std::mem::size_of::<Tail>() as u32,
        _reserved: 0,
    },
    streams: STREAMS.as_ptr(),
    streams_len: STREAMS.len(),
    routes: ROUTES.as_ptr(),
    routes_len: ROUTES.len(),
};

/// This plugin's Statement: its name and version, the `metrics` stream and its two routes.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    // One scrape sink renders the ONE well-known `/metrics`: at most one instance.
    marks: MARK_ONE_INSTANCE,
    ..statement(NAME, env!("CARGO_PKG_VERSION"), 64)
};

/// The buffer the first snapshot read starts with.
const FIRST_READ: usize = 64 * 1024;

/// One opened instance: it holds only the size the last snapshot took, the buffer the next read
/// starts with.
#[derive(Debug)]
pub struct Prometheus {
    read_hint: AtomicUsize,
}

impl Prometheus {
    /// The host's families of `scope` through the host snapshot service, into a buffer of the last
    /// read's size; a short buffer earns the one re-call, with headroom (a ticket-less re-call reads
    /// the snapshot again, which may have grown). `None` = not ready.
    fn read(
        &self,
        services: &Services,
        scope: u32,
    ) -> Result<Option<Vec<MetricFamily>>, ServiceError> {
        let none = CompletionHandle {
            ticket: Ticket::NONE,
            seq: 0,
            _reserved: 0,
        };
        let mut buf = vec![0u64; self.read_hint.load(Ordering::Relaxed).div_ceil(8)];
        let read = match services.snapshot_read(none, scope, &mut buf) {
            Err(ServiceError::Short { bytes, .. }) => {
                let want = usize::try_from(bytes).unwrap_or(usize::MAX / 2);
                let want = want.saturating_add(want / 4);
                self.read_hint.store(want, Ordering::Relaxed);
                buf = vec![0u64; want.div_ceil(8)];
                services.snapshot_read(none, scope, &mut buf)
            }
            other => other,
        };
        read.map(|families| families.map(|f| f.into_iter().map(lift).collect()))
    }
}

/// One host family, as the renderer reads it.
fn lift(f: busbar_contract::export_calls::Family) -> MetricFamily {
    MetricFamily {
        kind: busbar_contract::export_calls::type_word(f.kind)
            .unwrap_or("untyped")
            .to_string(),
        name: f.name,
        help: f.help,
        samples: f
            .samples
            .into_iter()
            .map(|s| MetricSample {
                name: s.name,
                labels: s.labels,
                value: s.value,
            })
            .collect(),
    }
}

impl Life for Prometheus {
    const CANCEL: u32 = cancel::ABORTED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        crate::validate(settings).map_err(Refusal::failed)
    }

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            read_hint: AtomicUsize::new(FIRST_READ),
        })
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

/// The text `s` names, through the SDK's safe lend; `None` when it is absent (a NULL string).
fn text(s: Lent<'_, AbiStr>) -> Option<String> {
    (!s.ptr.is_null()).then(|| String::from_utf8_lossy(s.bytes()).into_owned())
}

/// The snapshot `input` lends, in the order the host gave it, read through the SDK's accessors.
fn families(input: Lent<'_, ScrapeIn>) -> Vec<MetricFamily> {
    input
        .families()
        .iter()
        .map(|f| MetricFamily {
            name: text(f.field(|f| &f.name)).unwrap_or_default(),
            kind: busbar_contract::export_calls::type_word(f.kind)
                .unwrap_or("untyped")
                .to_string(),
            help: text(f.field(|f| &f.help)),
            samples: f
                .samples()
                .iter()
                .map(|s| MetricSample {
                    name: text(s.field(|s| &s.name)).unwrap_or_default(),
                    labels: s
                        .labels()
                        .iter()
                        .map(|l| {
                            (
                                text(l.field(|l| &l.key)).unwrap_or_default(),
                                text(l.field(|l| &l.value)).unwrap_or_default(),
                            )
                        })
                        .collect(),
                    value: text(s.field(|s| &s.value)).unwrap_or_default(),
                })
                .collect(),
        })
        .collect()
}

/// `scrape`: the snapshot rendered into the host's buffer.
pub struct Scrape;

impl SafeSlot for Scrape {
    type In = ScrapeIn;
    type Out = ScrapeOut;
    type State = Held<Prometheus>;
    fn call(
        _: Instance<'_, Held<Prometheus>>,
        input: Lent<'_, ScrapeIn>,
        mut out: Out<'_, ScrapeOut>,
    ) -> Outcome {
        let families = families(input);
        let body = if input.head.flags & SCRAPE_FLAG_HOOK_FAMILIES != 0 {
            crate::render_hooks(&families)
        } else {
            crate::render(&families)
        };
        let mut buf = input.buf();
        // The export ABI: a `cap` too small means the plugin writes nothing and sets `needed`.
        if body.len() > buf.cap() {
            out.set(|o| &o.needed, body.len());
            return Outcome::Failed;
        }
        buf.extend(body.as_bytes());
        out.set(|o| &o.written, buf.written());
        Outcome::Ready
    }
}

/// `deliver`: nothing kept — the host pulls `metrics`.
pub struct Deliver;

impl SafeSlot for Deliver {
    type In = DeliverIn;
    type Out = OutHead;
    type State = Held<Prometheus>;
    fn call(
        _: Instance<'_, Held<Prometheus>>,
        _: Lent<'_, DeliverIn>,
        _: Out<'_, OutHead>,
    ) -> Outcome {
        Outcome::Ready
    }
}

/// `status`: nothing to report.
pub struct Status;

impl SafeSlot for Status {
    type In = InHead;
    type Out = StatusOut;
    type State = Held<Prometheus>;
    fn call(
        _: Instance<'_, Held<Prometheus>>,
        _: Lent<'_, InHead>,
        _: Out<'_, StatusOut>,
    ) -> Outcome {
        Outcome::Ready
    }
}

/// `check`: at the limits phase, a second instance refused in 1.5.5's words.
pub struct Check;

impl SafeSlot for Check {
    type In = CheckIn;
    type Out = CheckOut;
    type State = Held<Prometheus>;
    fn call(
        instance: Instance<'_, Held<Prometheus>>,
        input: Lent<'_, CheckIn>,
        mut out: Out<'_, CheckOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Refused;
        };
        if input.phase != CHECK_PHASE_LIMITS {
            return Outcome::Ready;
        }
        let names: Vec<String> = input
            .instances()
            .iter()
            .map(|c| text(c.field(|c| &c.name)).unwrap_or_default())
            .collect();
        let lines = crate::check_limits(&names);
        if !lines.is_empty() {
            let json = serde_json::to_vec(&lines).unwrap_or_default();
            out.lease(|o| &o.findings, h.leases(), json, BLOB_JSON);
        }
        Outcome::Ready
    }
}

/// `/metrics`' response headers: 1.5.5's content type (oracle cell `ops.scrape__metrics__key`).
const METRICS_HEADERS: &[AbiStr] = &[abi("content-type"), abi("text/plain; version=0.0.4")];
/// `/metrics/hooks`' response headers: 1.5.5's content type, which carried a charset (oracle cell
/// `ops.scrape__metricshooks__key`).
const HOOKS_HEADERS: &[AbiStr] = &[
    abi("content-type"),
    abi("text/plain; version=0.0.4; charset=utf-8"),
];
/// The not-ready answer's headers: retry in a second.
const NOT_READY_HEADERS: &[AbiStr] = &[abi("retry-after"), abi("1")];

/// What one route answers from: the snapshot scope it reads, its response headers and its
/// renderer.
type Exposition = (u32, &'static [AbiStr], fn(&[MetricFamily]) -> String);

/// `serve`: the sink's own two routes, over the host snapshot service.
pub struct Serve;

impl SafeSlot for Serve {
    type In = ServeIn;
    type Out = ServeOut;
    type State = Held<Prometheus>;
    fn call(
        instance: Instance<'_, Held<Prometheus>>,
        input: Lent<'_, ServeIn>,
        mut out: Out<'_, ServeOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Refused;
        };
        let (scope, headers, render): Exposition = match input.field(|i| &i.path).as_str() {
            Ok(METRICS) => (SNAPSHOT_SCOPE_WHOLE, METRICS_HEADERS, crate::render),
            Ok(METRICS_HOOKS) => (SNAPSHOT_SCOPE_HOOKS, HOOKS_HEADERS, crate::render_hooks),
            _ => return Outcome::Refused,
        };
        let Some(services) = h.host().and_then(|host| host.services()) else {
            return Outcome::Failed;
        };
        let (status, headers, body) = match h.life().read(&services, scope) {
            Ok(Some(families)) => (200u16, headers, render(&families).into_bytes()),
            Ok(None) => (503u16, NOT_READY_HEADERS, Vec::new()),
            Err(_) => return Outcome::Failed,
        };
        out.set(|o| &o.status_code, status);
        // The header list is program memory; the answer names material, so it names a lease (the
        // body's, or one kept for the list alone).
        out.list(|o| &o.headers_out, |o| &o.headers_out_len, headers);
        if body.is_empty() {
            out.keep(h.leases(), ());
        } else {
            out.lease(|o| &o.body, h.leases(), body, BLOB_OCTETS);
        }
        Outcome::Ready
    }
}

mod table {
    use super::{Check, Deliver, Prometheus, Safe, Scrape, Serve, Status};

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: super::STATEMENT,
        lifecycle: life(Prometheus),
        kind_ops: {
            deliver: Safe<Deliver>, scrape: Safe<Scrape>, status: Safe<Status>,
            check: Safe<Check>, serve: Safe<Serve>,
        },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::door;
