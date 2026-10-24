// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR: the OTLP sink on the export kind's table (`busbar_contract::abi::export`), its
//! lifecycle the SDK's generic one over [`Otlp`] (`abi::sdk::life`), every kind op a [`SafeSlot`].
//!
//! * `validate` — the settings parse as [`OtlpSettings`], refusing in serde's words.
//! * `open` / `refresh` — the settings become the endpoint (userinfo split into a Basic header).
//!   Settings that do not parse still open, taking nothing: the configuration refused them.
//! * `deliver` — the batch's spans as one OTLP request, sent by `exchange()` over the declared need,
//!   PENDING while the host carries it; READY whatever became of it (a dropped export is logged at
//!   debug). The host's first answer settles the run: carried, `OTLP tracing enabled`; refused by
//!   the connector, `…; disabling OTLP trace export`, and no later batch is sent.
//! * `scrape` and `serve` — REFUSED: the sink carries no metrics and serves no route.
//! * `status` and `check` — READY with nothing to report.

use std::sync::{Mutex, PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::export::{
    cancel, CheckIn, CheckOut, DeliverIn, ExportStream, ScrapeIn, ScrapeOut, ServeIn, ServeOut,
    StatusOut, Tail, CHECK_PHASE_LIMITS,
};
use busbar_contract::abi::host::conn::connector::{
    Need, DIRECTION_OUTBOUND, EGRESS_LOOPBACK_ALLOWED, KEEP_NAMED,
};
use busbar_contract::abi::mechanism::call::{Blob, InHead, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement, MARK_ONE_INSTANCE};
use busbar_contract::abi::sdk::conn::ConnFailure;
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::{exchange, Exchange, ExchangeResponse, Request};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};

use crate::{
    mask_userinfo, proto, request_target, split_credentials, OtlpSettings, CONTENT_TYPE,
    EXPORT_TIMEOUT_MS, NAME,
};

/// The one need's index in [`STATEMENT`]'s needs.
pub const NEED: u32 = 0;

/// The collector, reached through the host: framed `http`, under the `loopback-allowed` egress class
/// 1.5.5's exporter held its endpoint to, its target the `url` setting (THE DESIGN §5, PB-100): the
/// host declares the need pinned to the operator's collector, its userinfo left out, and refuses a
/// dial to any other host. Each export names the same collector ([`Endpoint::collector`], the URL
/// with its userinfo stripped), so no credential is ever part of what the host dials; the userinfo
/// travels only as the request's `Authorization`.
pub(crate) const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_LOOPBACK_ALLOWED,
    transport: abi_str("http"),
    auth: abi_str(""),
    target_from: abi_str("settings.url"),
    trust_from: abi_str(""),
    details: Blob::ABSENT,
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: EXPORT_TIMEOUT_MS,
    // The collector's response head is not read: the named (empty) list, nothing denied beyond it.
    keep_mode: KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}];

/// The one stream the sink carries.
const STREAMS: &[u8] = &[ExportStream::Traces as u8];

const TAIL: Tail = Tail {
    head: KindTailHead {
        size: std::mem::size_of::<Tail>() as u32,
        _reserved: 0,
    },
    streams: STREAMS.as_ptr(),
    streams_len: STREAMS.len(),
    routes: std::ptr::null(),
    routes_len: 0,
};

/// This plugin's Statement: its name and version, the `traces` stream, and the collector need.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    // OTLP installs the ONE process-global tracer subscriber: at most one instance.
    marks: MARK_ONE_INSTANCE,
    ..statement(NAME, env!("CARGO_PKG_VERSION"), 64)
};

/// Where each export goes, as one instance's settings name it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Endpoint {
    /// The settings' URL, userinfo masked: what every line names.
    pub shown: String,
    /// The collector the host dials — the settings' URL without its userinfo; `None` when the
    /// settings did not parse.
    pub collector: Option<String>,
    /// The request target (path and query) and the `Authorization` the userinfo became; `None`
    /// when the settings did not parse.
    pub target: Option<(String, Option<String>)>,
}

impl Endpoint {
    /// The endpoint `settings` name.
    #[must_use]
    pub fn of(settings: &[u8]) -> Self {
        match OtlpSettings::parse(settings) {
            Ok(s) => {
                let (clean, authorization) = split_credentials(&s.url);
                Self {
                    shown: mask_userinfo(&s.url),
                    target: Some((request_target(&clean), authorization)),
                    collector: Some(clean),
                }
            }
            Err(_) => Self::default(),
        }
    }

    /// The request carrying `body` to this endpoint; `None` when it names none.
    #[must_use]
    pub fn request(&self, body: Vec<u8>) -> Option<Request> {
        let (target, authorization) = self.target.as_ref()?;
        let mut fields = vec![(b"content-type".to_vec(), CONTENT_TYPE.as_bytes().to_vec())];
        if let Some(value) = authorization {
            fields.push((b"authorization".to_vec(), value.as_bytes().to_vec()));
        }
        Some(Request {
            method: b"POST".to_vec(),
            target: target.as_bytes().to_vec(),
            fields,
            body,
            timeout_ms: EXPORT_TIMEOUT_MS,
        })
    }
}

/// One opened instance.
#[derive(Debug)]
pub struct Otlp {
    endpoint: RwLock<Endpoint>,
    /// Whether this run takes spans, once the host's first answer settled it.
    admitted: Mutex<Option<bool>>,
}

impl Otlp {
    /// The endpoint this instance sends to.
    #[must_use]
    pub fn endpoint(&self) -> Endpoint {
        self.endpoint
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether the host refused this run's exports: its connector refused the first one (the
    /// egress class's verdict on the target, or no connector at all).
    fn refused(&self) -> bool {
        *self.admitted.lock().unwrap_or_else(PoisonError::into_inner) == Some(false)
    }

    /// What became of one export: the first answer the host gives settles whether this run takes
    /// spans (the line a rollout check greps for, or the refusal and that export is disabled); a
    /// non-2xx or failed export drops that batch, logged at debug.
    fn settle(&self, shown: &str, result: &Result<ExchangeResponse, ConnFailure>) {
        {
            let mut admitted = self.admitted.lock().unwrap_or_else(PoisonError::into_inner);
            match (result, *admitted) {
                (Err(e @ (ConnFailure::Refused(_) | ConnFailure::Unarmed)), None) => {
                    tracing::error!("{e}; disabling OTLP trace export");
                    *admitted = Some(false);
                    return;
                }
                (Ok(_), None) => {
                    tracing::info!(endpoint = %shown, "OTLP tracing enabled");
                    *admitted = Some(true);
                }
                _ => {}
            }
        }
        match result {
            Ok(reply) if (200..300).contains(&reply.status) => {}
            Ok(reply) => tracing::debug!(
                endpoint = %shown,
                status = reply.status,
                "OTLP span export returned a non-2xx status; this span was dropped"
            ),
            Err(e) => dropped(shown, e),
        }
    }
}

impl Life for Otlp {
    const CANCEL: u32 = cancel::ABORTED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        OtlpSettings::parse(settings)
            .map(|_| ())
            .map_err(|e| Refusal::failed(format!("settings: {e}")))
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            endpoint: RwLock::new(Endpoint::of(settings)),
            admitted: Mutex::new(None),
        })
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        *self
            .endpoint
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Endpoint::of(settings);
        *self.admitted.lock().unwrap_or_else(PoisonError::into_inner) = None;
        Ok(Refreshed::default())
    }
}

/// The OTLP request a JSON-lines batch makes, each record that is no span logged and skipped.
fn batch_body(batch: &[u8]) -> Option<Vec<u8>> {
    let records: Vec<serde_json::Value> = batch
        .split(|b| *b == b'\n')
        .filter(|line| !line.iter().all(u8::is_ascii_whitespace))
        .map(|line| serde_json::from_slice(line).unwrap_or_default())
        .collect();
    for _ in records.iter().filter(|r| !proto::is_span(r)) {
        tracing::debug!("OTLP span export skipped a record with no span identity");
    }
    proto::export_request(&records)
}

/// `deliver`: the batch as one OTLP request, exchanged over the need.
pub struct Deliver;

impl SafeSlot for Deliver {
    type In = DeliverIn;
    type Out = OutHead;
    type State = Held<Otlp>;
    fn call(
        instance: Instance<'_, Held<Otlp>>,
        input: Lent<'_, DeliverIn>,
        _: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        let endpoint = held.life().endpoint();
        let mut state = match instance.resume::<Exchange>() {
            Some(parked) => *parked,
            None => {
                if held.life().refused() {
                    return Outcome::Ready;
                }
                let Some(body) = batch_body(input.field(|i| &i.batch).bytes()) else {
                    return Outcome::Ready;
                };
                let Some(request) = endpoint.request(body) else {
                    return Outcome::Ready;
                };
                match Exchange::request(request) {
                    Ok(state) => state,
                    Err(e) => {
                        dropped(&endpoint.shown, &e);
                        return Outcome::Ready;
                    }
                }
            }
        };
        let answer = match held.host() {
            Some(host) => exchange(
                &mut host.connector(instance.ticket()),
                &mut state,
                NEED,
                endpoint.collector.as_deref(),
            ),
            None => Poll::Ready(Err(ConnFailure::Unarmed)),
        };
        match answer {
            Poll::Pending => {
                instance.park(state);
                Outcome::Pending
            }
            Poll::Ready(result) => {
                held.life().settle(&endpoint.shown, &result);
                Outcome::Ready
            }
        }
    }
}

/// The line an export that did not reach the collector writes.
fn dropped(shown: &str, error: &ConnFailure) {
    tracing::debug!(
        endpoint = %shown,
        error = %error,
        "OTLP span export failed; this span was dropped"
    );
}

/// `scrape`: REFUSED — the sink carries no metrics.
pub struct Scrape;

impl SafeSlot for Scrape {
    type In = ScrapeIn;
    type Out = ScrapeOut;
    type State = Held<Otlp>;
    fn call(_: Instance<'_, Held<Otlp>>, _: Lent<'_, ScrapeIn>, _: Out<'_, ScrapeOut>) -> Outcome {
        Outcome::Refused
    }
}

/// `status`: nothing to report.
pub struct Status;

impl SafeSlot for Status {
    type In = InHead;
    type Out = StatusOut;
    type State = Held<Otlp>;
    fn call(_: Instance<'_, Held<Otlp>>, _: Lent<'_, InHead>, _: Out<'_, StatusOut>) -> Outcome {
        Outcome::Ready
    }
}

/// `check`: at the limits phase, 1.5.5's refusal of every instance after the first
/// ([`crate::check_limits`]) — the sink states the `one_instance` mark, so the host asks it while
/// the configuration is resolved; READY with nothing otherwise.
pub struct Check;

impl SafeSlot for Check {
    type In = CheckIn;
    type Out = CheckOut;
    type State = Held<Otlp>;
    fn call(
        instance: Instance<'_, Held<Otlp>>,
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
            .map(|c| String::from_utf8_lossy(c.field(|c| &c.name).bytes()).into_owned())
            .collect();
        let lines = crate::check_limits(&names);
        if !lines.is_empty() {
            let json = serde_json::to_vec(&lines).unwrap_or_default();
            out.lease(|o| &o.findings, h.leases(), json, BLOB_JSON);
        }
        Outcome::Ready
    }
}

/// `serve`: REFUSED — the sink serves no route.
pub struct Serve;

impl SafeSlot for Serve {
    type In = ServeIn;
    type Out = ServeOut;
    type State = Held<Otlp>;
    fn call(_: Instance<'_, Held<Otlp>>, _: Lent<'_, ServeIn>, _: Out<'_, ServeOut>) -> Outcome {
        Outcome::Refused
    }
}

mod table {
    use super::{Check, Deliver, Otlp, Safe, Scrape, Serve, Status};

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: super::STATEMENT,
        lifecycle: life(Otlp),
        kind_ops: {
            deliver: Safe<Deliver>, scrape: Safe<Scrape>, status: Safe<Status>,
            check: Safe<Check>, serve: Safe<Serve>,
        },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::door;
