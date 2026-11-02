// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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

const STREAMS: &[u8] = &[ExportStream::Metrics as u8];

const fn abi(s: &'static str) -> AbiStr {
    AbiStr {
        ptr: s.as_ptr(),
        len: s.len(),
    }
}

const METRICS: &str = "/metrics";

const METRICS_HOOKS: &str = "/metrics/hooks";

const fn get(path: &'static str) -> Route {
    Route {
        path: abi(path),
        method: abi("GET"),
        auth: ROUTE_AUTH_KEY,
        _reserved: 0,
    }
}

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

busbar_contract::statement_extensions!(LISTENER_POLICY: [
    ("listener.public_routes", br#"["/metrics","/metrics/hooks"]"#),
    ("listener.persistent_routes", br#"["/metrics/hooks"]"#),
]);

pub const STATEMENT: Statement = Statement {
    extensions: LISTENER_POLICY,
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),

    marks: MARK_ONE_INSTANCE,
    ..statement(NAME, env!("CARGO_PKG_VERSION"), 64)
};

const FIRST_READ: usize = 64 * 1024;

/// One opened instance: it holds only the size the last snapshot took, the buffer the next read
/// starts with.
#[derive(Debug)]
pub struct Prometheus {
    read_hint: AtomicUsize,
}

impl Prometheus {
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

fn lift(mut f: busbar_contract::export_calls::Family) -> MetricFamily {
    MetricFamily {
        kind: busbar_contract::export_calls::type_word(f.kind)
            .unwrap_or("untyped")
            .to_string(),
        name: std::mem::take(&mut f.name),
        help: f.help.take(),
        samples: std::mem::take(&mut f.samples)
            .into_iter()
            .map(|mut s| MetricSample {
                name: std::mem::take(&mut s.name),
                labels: std::mem::take(&mut s.labels),
                value: std::mem::take(&mut s.value),
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

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        crate::validate(settings).map_err(Refusal::failed)?;
        Ok(Refreshed::default())
    }
}

fn text(s: Lent<'_, AbiStr>) -> Option<String> {
    (!s.ptr.is_null()).then(|| String::from_utf8_lossy(s.bytes()).into_owned())
}

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

        if body.len() > buf.cap() {
            out.set(|o| &o.needed, body.len());
            return Outcome::Failed;
        }
        buf.extend(body.as_bytes());
        out.set(|o| &o.written, buf.written());
        Outcome::Ready
    }
}

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

const METRICS_HEADERS: &[AbiStr] = &[abi("content-type"), abi("text/plain; version=0.0.4")];

const HOOKS_HEADERS: &[AbiStr] = &[
    abi("content-type"),
    abi("text/plain; version=0.0.4; charset=utf-8"),
];

const NOT_READY_HEADERS: &[AbiStr] = &[abi("retry-after"), abi("1")];

type Exposition = (u32, &'static [AbiStr], fn(&[MetricFamily]) -> String);

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

pub use table::door;
