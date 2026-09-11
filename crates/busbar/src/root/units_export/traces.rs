// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SPAN PRODUCER — root composition, and the half of the OTLP export that is not a sink.
//!
//! Every other push sink of this kind is called from the request-finish fan-out beside this module:
//! the engine finishes a request, the root builds one payload per projection and hands each sink a
//! record. SPANS HAVE NO SUCH CALL SITE and cannot be given one. They do not arrive at a call —
//! they arrive at a `tracing_subscriber::Layer` through the global dispatcher, because every
//! `#[instrument]` and every `info_span!` in this tree enters and exits through it. Nothing in the
//! engine and nothing in the composition root is on a stack that could call `receive` per span, and
//! adding one would mean re-implementing span capture on top of a subscriber that already does it.
//!
//! So the producer is a LAYER, and a layer on this process's subscriber is composition by
//! definition — a property of THIS process, exactly as the fan-out is a property of this process's
//! request-finish path. That is why it is here and not in a crate of kind `export`: a sink may name
//! no subscriber, no registry, no clock and no runtime, and this file names all four.
//!
//! WHAT THIS REPLACES, and it is the reason this is a redesign and not a move.
//! `crates/busbar/src/root/logging.rs` used to build an `opentelemetry_sdk` tracer provider with a
//! BATCH exporter behind `tracing_opentelemetry::layer()`. That processor carried its own queue,
//! its own flush cadence, its own drop-on-full rule and its own shutdown, none of which this process
//! could see or stop — a SECOND shed for one stream, behind the root's own gate, and the one that
//! actually dropped spans was the one nobody declared. Here there is ONE queue, ONE
//! [`AdmissionGate`] against the bound the sink declares, and ONE maintenance tick — the same
//! decision the metrics fold runs on — on the same shutdown broadcast as every other background
//! task, so the last spans before a stop are EXPORTED rather than lost and this process can say
//! whether that happened.
//!
//! WHAT IS STILL THE ENGINE'S. The socket and the credential. A connection pool on the open-web
//! posture is this deployment's egress posture, and it leaves when that client leaves; the userinfo
//! split that moves an operator's credential out of the URL and into a header travels WITH the
//! socket, because it is auth-header construction and not an SSRF predicate. The SSRF verdict
//! itself already belongs to the egress unit and is still asked with this process's own resolver.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use busbar_contract::{Delivery, Export, ExportHost, ExportItem};
use busbar_export_otlp::{
    AttrValue, OtlpSink, SpanKind, SpanRecord, SpanStatus, GATE, MAX_ATTRIBUTES_PER_SPAN,
    MAX_SPANS_PER_DELIVERY, STREAM,
};
use busbar_unit_egress::sink_guard::{mask_userinfo, percent_decode, validate_otlp_endpoint};
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

use super::admission::AdmissionGate;
use super::reports::EngineOtlpReport;
// THROUGH THE PARENT, deliberately, exactly as `reports` takes its counters. The `legacy-reach`
// ratchet counts DISTINCT symbols the root spells through a retiring crate's prefix and may only go
// down, so the two modules the engine still owns are named ONCE for this whole directory — in
// `mod.rs` — and every file under it reaches them from there.
use super::{config, export, ExportDeliverySend};

/// The HTTP Basic auth scheme prefix (RFC 7617). Includes the trailing space so callers can write
/// `format!("{AUTH_SCHEME}{token}")` without hard-coding the space.
const AUTH_SCHEME: &str = "Basic ";

/// The header an OTLP credential rides on once it is off the URL.
const AUTH_HEADER: &str = "authorization";

/// HOW OFTEN THE QUEUE IS DRAINED. One export request per interval, which is what makes the
/// interval the in-flight bound on exchanges: there is never a second export on the wire because
/// there is never a second drain. Five seconds is the cadence the retired batch processor's own
/// scheduled delay used, so an operator's collector sees the same arrival pattern it did.
const FLUSH_INTERVAL: Duration = Duration::from_secs(5);

/// How long any ONE export request may take, end to end. The collector is a background,
/// seconds-cadence push like every other telemetry delivery this process makes, and this is the
/// deadline the retired exporter's client applied.
const DELIVERY_TIMEOUT: Duration = Duration::from_secs(10);

/// How many characters of one attribute value may cross. The BOUND is the composer's, because the
/// composer is the only party that can apply one before the bytes exist; the sink states how many
/// attributes ([`MAX_ATTRIBUTES_PER_SPAN`]) and this states how big each may be.
const MAX_ATTRIBUTE_CHARS: usize = 1024;

/// The `tracing` field names this process reads as STATEMENTS ABOUT THE SPAN rather than as
/// attributes of it — the same three `tracing-opentelemetry` read, spelled the same way, so a
/// callsite that already sets them keeps meaning what it meant.
const FIELD_KIND: &str = "otel.kind";
const FIELD_STATUS_CODE: &str = "otel.status_code";
const FIELD_STATUS_MESSAGE: &str = "otel.status_message";

/// The composed OTLP export: the sink, the ONE gate it is shed against, the ONE queue, and the wire.
///
/// Held behind an `Arc` and shared by the layer (which fills the queue) and the tick (which drains
/// it). Every field is a thing the COMPOSER owns; the sink holds none of them and could not name
/// their types.
struct Traces {
    /// The sink, as a `dyn Export`. After construction this module cannot tell which sink it holds.
    sink: Arc<dyn Export>,
    /// The outcome half, bound at composition to the one point the sink's crate is named.
    outcome: Arc<dyn Fn(Result<u16, String>) + Send + Sync>,
    /// THE ONE SHED. `MAX_SPANS_PER_DELIVERY` slots, the bound the SINK declares; a span that
    /// cannot take one is dropped and counted on `busbar_admission_denied_total{gate="otlp"}`,
    /// uniformly with every other gate in this process. There is no second counter, because the
    /// party that drops a span is the party that declared it may.
    gate: AdmissionGate,
    /// The spans waiting for the next drain, each holding the slot it was admitted under.
    queue: Mutex<Vec<(SpanRecord, tokio::sync::OwnedSemaphorePermit)>>,
    /// The wire, shared with every other push sink this process composed.
    send: ExportDeliverySend,
}

impl Traces {
    /// Take one finished span, or shed it. Called from the layer, on whatever thread closed the
    /// span, and never blocks: a full gate is a `None` and a `None` is a drop.
    fn offer(&self, record: SpanRecord) {
        let Some(permit) = self.gate.try_enter() else {
            return;
        };
        self.queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((record, permit));
    }

    /// Drain everything queued into ONE export request, and return how many spans went into it.
    ///
    /// The permits ride along in `hold` and are released when the exchange ends, so the bound stays
    /// a bound on spans that have not yet been PUT ON A WIRE rather than on spans that have not yet
    /// been queued.
    fn drain(&self) -> usize {
        let drained: Vec<(SpanRecord, tokio::sync::OwnedSemaphorePermit)> =
            std::mem::take(&mut *self.queue.lock().unwrap_or_else(|e| e.into_inner()));
        if drained.is_empty() {
            return 0;
        }
        let (records, permits): (Vec<SpanRecord>, Vec<_>) = drained.into_iter().unzip();
        let Ok(bytes) = serde_json::to_vec(&records) else {
            // Structurally unreachable: every field of a span record serializes. Answered rather
            // than panicked, because a telemetry drain must never be the thing that stops serving.
            return 0;
        };
        let loan = WireLoan {
            send: self.send.clone(),
            hold: Mutex::new(Some(Box::new(permits))),
            outcome: self.outcome.clone(),
        };
        // The record goes over the face; the sink frames the export request and puts it on the wire
        // THIS loan lends it. The ack is real here — there is no queue behind it any more — but
        // what this process does about one is counted by the gate, not re-decided here.
        let _ack = self.sink.receive(
            ExportItem {
                stream: STREAM,
                bytes: &bytes,
            },
            &loan,
        );
        records.len()
    }
}

/// WHAT THIS PROCESS LENDS ONE SPAN EXPORT: the egress wire, for the length of ONE `receive`, with
/// the whole drained batch's slots riding along so they are returned when the exchange ends and not
/// when the call does.
struct WireLoan {
    send: ExportDeliverySend,
    /// Taken out exactly once by the single `send` a `receive` makes.
    hold: Mutex<Option<Box<dyn Send>>>,
    outcome: Arc<dyn Fn(Result<u16, String>) + Send + Sync>,
}

impl ExportHost for WireLoan {
    fn send(&self, delivery: Delivery) -> bool {
        let Some(hold) = self.hold.lock().unwrap_or_else(|e| e.into_inner()).take() else {
            // One drained batch is one exchange; a second send inside one `receive` would put an
            // export on the wire nobody sheds for.
            return false;
        };
        let outcome = self.outcome.clone();
        (self.send)(
            delivery.target,
            delivery.headers,
            delivery.body,
            DELIVERY_TIMEOUT,
            hold,
            Box::new(move |result| outcome(result)),
        );
        true
    }

    fn read(&self, _stream: &str) -> Option<String> {
        None
    }
}

/// The composed export, so the shutdown path can drain it one last time. Unset ⇒ [`install`] found
/// no `otlp` instance and composed nothing at all.
static TRACES: OnceLock<Arc<Traces>> = OnceLock::new();

/// Compose the OTLP export the operator configured and hand back the subscriber layer that feeds
/// it. Called ONCE at boot, BEFORE the subscriber is installed — a layer cannot be added to a
/// subscriber that already exists.
///
/// `None` ⇒ no `otlp` instance, or an endpoint the SSRF guard refused. In either case nothing is
/// composed, no client is built and no span is ever observed: the zero-config default pays nothing.
pub fn install(cfg: Option<&config::OtlpSettings>) -> Option<TraceLayer> {
    let endpoint = cfg.map(|o| o.url.as_str());
    // SSRF-VALIDATE BEFORE ANYTHING IS BUILT, so a config pointing at cloud metadata or an internal
    // service is refused and the export left off — span data carries key ids, pool names and
    // governance decisions, so this sink must be as SSRF-safe as the request-log webhook (loopback
    // collectors are allowed). THE RESOLUTION IS THIS SIDE'S; the verdict is the unit's, because a
    // unit does no I/O. A lookup that errors yields no addresses, which refuses nothing.
    let resolve = |host: &str, port: u16| -> Vec<std::net::IpAddr> {
        use std::net::ToSocketAddrs as _;
        (host, port)
            .to_socket_addrs()
            .map(|it| it.map(|sa| sa.ip()).collect())
            .unwrap_or_default()
    };
    let validated = match validate_otlp_endpoint(endpoint, &resolve) {
        Ok(v) => v?,
        Err(msg) => {
            eprintln!("busbar: {msg}; disabling OTLP trace export");
            return None;
        }
    };
    let traces = Arc::new(compose(&validated, export::export_delivery_send()));
    let _ = TRACES.set(traces.clone());
    // The endpoint is logged MASKED. The subscriber is not up yet at this point, so this line
    // arrives with the rest of boot rather than before it.
    let shown = mask_userinfo(&validated);
    Some(TraceLayer { traces, shown })
}

/// [`install`] over an already-validated endpoint and an explicit wire — the whole of the
/// composition, split from the config read and the client build in front of it so a test can drive
/// it over a send of its own and see the bytes that would have left the process.
fn compose(endpoint: &str, send: ExportDeliverySend) -> Traces {
    let (target, headers) = split_credentials(endpoint);
    let built = Arc::new(OtlpSink::new(
        target,
        headers,
        resource(),
        Arc::new(EngineOtlpReport),
    ));
    let judge = built.clone();
    Traces {
        sink: built,
        outcome: Arc::new(move |result| judge.observe(result)),
        gate: AdmissionGate::new(MAX_SPANS_PER_DELIVERY, GATE),
        queue: Mutex::new(Vec::new()),
        send,
    }
}

/// WHAT THIS PROCESS CALLS ITSELF on the wire. A sink does not know what binary it was linked into,
/// so the composer says it.
fn resource() -> Vec<(String, String)> {
    vec![
        ("service.name".to_string(), "busbar".to_string()),
        (
            "service.version".to_string(),
            env!("CARGO_PKG_VERSION").to_string(),
        ),
    ]
}

/// Split any embedded userinfo (`scheme://user:pass@host/...`) OUT of a validated endpoint,
/// returning the credential-free target and the headers the credential travels in instead.
///
/// It is here, with the socket, and not in the sink: it is auth-header construction. The point is
/// that the endpoint STRING the sink holds — and therefore the one any report could ever name —
/// never carries the operator's secret, so the crate that frames the export has nothing to leak.
///
/// A URL with no userinfo, or a string that does not parse as a URL, yields the endpoint unchanged
/// and no header: a credential-free endpoint must not be mangled, and validation already accepted
/// it. Pure, so it is unit-testable without process-wide state.
fn split_credentials(endpoint: &str) -> (String, Vec<(String, String)>) {
    let Ok(mut parsed) = url::Url::parse(endpoint) else {
        return (endpoint.to_string(), Vec::new());
    };
    let username = parsed.username().to_string();
    let password = parsed.password().map(str::to_string);
    if username.is_empty() && password.is_none() {
        return (endpoint.to_string(), Vec::new());
    }
    // Per RFC 7617 the Basic credential is `base64(user-id ":" password)`, with an empty password
    // when none was supplied. The userinfo arrives percent-encoded in the URL; decode it so the
    // wire credential matches what the operator configured.
    let user = percent_decode(&username);
    let pass = percent_decode(password.as_deref().unwrap_or(""));
    let token = base64_encode(format!("{user}:{pass}").as_bytes());
    // Strip the userinfo so the target is credential-free. Both setters return `Err(())` only for a
    // cannot-be-a-base URL, which a URL that parsed WITH userinfo is not; on the unexpected error we
    // still must not leak, so fall back to a host-only rebuild.
    let clean = if parsed.set_username("").is_err() || parsed.set_password(None).is_err() {
        let host = parsed.host_str().unwrap_or("");
        match parsed.port() {
            Some(p) => format!("{}://{host}:{p}", parsed.scheme()),
            None => format!("{}://{host}", parsed.scheme()),
        }
    } else {
        parsed.into()
    };
    (
        clean,
        vec![(AUTH_HEADER.to_string(), format!("{AUTH_SCHEME}{token}"))],
    )
}

/// Standard base64 (RFC 4648 §4, with `=` padding) of arbitrary bytes. Used only to build the
/// `Authorization: Basic <base64(user:pass)>` header value above; hand-rolled rather than pulling a
/// `base64` crate into the direct dependency set (a dozen lines, run once, at startup, off the
/// request path). Pure, so it is unit-testable.
fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        // Pack up to three input bytes into a 24-bit big-endian buffer; absent bytes are 0.
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[((n >> 18) & 0x3f) as usize] as char);
        out.push(ALPHABET[((n >> 12) & 0x3f) as usize] as char);
        // The 3rd/4th sextets become `=` padding when the input chunk was short.
        out.push(if chunk.len() > 1 {
            ALPHABET[((n >> 6) & 0x3f) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[(n & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}

// ── the identifiers ──────────────────────────────────────────────────────────────────────────

/// The per-process seed the span/trace ids are derived from, taken once from the standard library's
/// own randomly-keyed hasher and the boot wall clock. It is not a cryptographic source and does not
/// need to be: a trace id has to be UNIQUE across the deployment and unguessable enough that a
/// third party cannot forge a correlation, which is the same bar `tracing-opentelemetry`'s default
/// generator meets. Taking it from the standard library is what keeps a random-number crate out of
/// the composition root for a telemetry id.
static SEED: OnceLock<u64> = OnceLock::new();

/// Monotonic per-process counter, mixed with the seed so two ids minted in the same nanosecond on
/// two threads still differ.
static MINTED: AtomicU64 = AtomicU64::new(0);

/// One well-distributed 64-bit value. SplitMix64 over `seed ^ counter`: the counter guarantees
/// uniqueness and the mix makes the sequence unguessable from one observed id.
fn next_u64() -> u64 {
    let seed = *SEED.get_or_init(|| {
        use std::hash::{BuildHasher as _, Hasher as _};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u64(now_unix_nanos());
        h.finish()
    });
    let mut z = seed.wrapping_add(
        MINTED
            .fetch_add(1, Ordering::Relaxed)
            .wrapping_mul(0x9e37_79b9_7f4a_7c15),
    );
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A fresh W3C trace id. Never all-zero: the specification says an all-zero id is INVALID, and a
/// collector is entitled to discard a trace carrying one.
fn new_trace_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&next_u64().to_be_bytes());
    id[8..].copy_from_slice(&next_u64().to_be_bytes());
    if id == [0u8; 16] {
        id[15] = 1;
    }
    id
}

/// A fresh W3C span id, never all-zero for the same reason.
fn new_span_id() -> [u8; 8] {
    let id = next_u64().to_be_bytes();
    if id == [0u8; 8] {
        return 1u64.to_be_bytes();
    }
    id
}

/// This process's wall clock, as the OTLP schema wants it. A span's window is a fact about WHEN,
/// which only the process that observed it can state.
fn now_unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

// ── the layer ────────────────────────────────────────────────────────────────────────────────

/// What this process observed about ONE open span, kept in the registry's own per-span extensions —
/// which is where a span's state belongs, because the registry already owns the span's lifetime and
/// a side table keyed by id would be a second one to leak.
struct Observed {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    start_unix_nanos: u64,
    fields: Fields,
}

/// The attributes and the three STATEMENTS a callsite can make about its span, collected as the
/// span is created and as `record` adds to it. BOUNDED HERE: a sink states how many attributes it
/// will take and the composer is the only party that can apply that before the bytes exist.
#[derive(Default)]
struct Fields {
    attributes: Vec<(String, AttrValue)>,
    dropped: u32,
    kind: Option<SpanKind>,
    status_code: Option<String>,
    status_message: Option<String>,
}

impl Fields {
    /// Take one field. The three `otel.*` names are statements ABOUT the span and never attributes
    /// OF it; everything else is an attribute, admitted while there is room and counted once there
    /// is not.
    fn put(&mut self, name: &str, value: AttrValue) {
        match name {
            FIELD_KIND => {
                if let AttrValue::Str(s) = &value {
                    self.kind = Some(match s.as_str() {
                        "server" | "SERVER" => SpanKind::Server,
                        "client" | "CLIENT" => SpanKind::Client,
                        "producer" | "PRODUCER" => SpanKind::Producer,
                        "consumer" | "CONSUMER" => SpanKind::Consumer,
                        _ => SpanKind::Internal,
                    });
                }
            }
            FIELD_STATUS_CODE => {
                if let AttrValue::Str(s) = &value {
                    self.status_code = Some(s.clone());
                }
            }
            FIELD_STATUS_MESSAGE => {
                if let AttrValue::Str(s) = &value {
                    self.status_message = Some(s.clone());
                }
            }
            _ if self.attributes.len() < MAX_ATTRIBUTES_PER_SPAN => {
                self.attributes.push((name.to_string(), value));
            }
            _ => self.dropped = self.dropped.saturating_add(1),
        }
    }

    /// What the callsite said about the outcome. `Unset` is a different fact from `Ok` and is
    /// carried as one.
    fn status(&self) -> SpanStatus {
        match self.status_code.as_deref() {
            Some("OK") | Some("ok") => SpanStatus::Ok,
            Some("ERROR") | Some("error") => SpanStatus::Error {
                message: self.status_message.clone().unwrap_or_default(),
            },
            _ => SpanStatus::Unset,
        }
    }
}

/// One string attribute, truncated to the composer's bound. Truncation is on CHARACTER boundaries,
/// so a multi-byte value can never be cut into invalid UTF-8.
fn bounded(value: &str) -> AttrValue {
    AttrValue::Str(match value.char_indices().nth(MAX_ATTRIBUTE_CHARS) {
        Some((at, _)) => value[..at].to_string(),
        None => value.to_string(),
    })
}

impl tracing::field::Visit for Fields {
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.put(field.name(), bounded(value));
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.put(field.name(), AttrValue::Int(value));
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.put(
            field.name(),
            AttrValue::Int(i64::try_from(value).unwrap_or(i64::MAX)),
        );
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.put(field.name(), AttrValue::Bool(value));
    }
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        self.put(field.name(), bounded(&format!("{value:?}")));
    }
}

/// THE PRODUCER. A `tracing_subscriber::Layer` that turns every span this process closes into one
/// [`SpanRecord`] on the `traces` stream.
///
/// It is the piece `tracing-opentelemetry` used to be, and the only NEW code in this landing: trace
/// id minting, parent linking off the registry's span extensions, and the attribute projection all
/// have to be written where that crate wrote them. What is NOT written here is a queue, a flush, a
/// provider or an exporter — those were the parts that made the SDK's pipeline a second, undeclared
/// shed, and they are deleted rather than re-implemented.
pub struct TraceLayer {
    traces: Arc<Traces>,
    /// The MASKED endpoint, for the one boot line that names it.
    shown: String,
}

impl TraceLayer {
    /// The masked endpoint, so the caller can say OTLP is on without ever holding the raw one.
    pub fn endpoint(&self) -> &str {
        &self.shown
    }
}

impl<S> tracing_subscriber::Layer<S> for TraceLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        // THE PARENT IS THE REGISTRY'S ANSWER, not a guess: an explicit `parent:` wins, a
        // contextual span takes whatever is currently entered, and a span declared `parent: None`
        // is a root even inside an entered one. A parent this layer never observed (it was created
        // before the layer, or filtered out) starts a NEW trace rather than inheriting a trace id
        // that does not exist.
        let parent = attrs.parent().and_then(|p| ctx.span(p)).or_else(|| {
            attrs
                .is_contextual()
                .then(|| ctx.lookup_current())
                .flatten()
        });
        let (trace_id, parent_span_id) = match parent.as_ref().map(|p| p.extensions()) {
            Some(ext) => match ext.get::<Observed>() {
                Some(o) => (o.trace_id, Some(o.span_id)),
                None => (new_trace_id(), None),
            },
            None => (new_trace_id(), None),
        };
        let mut fields = Fields::default();
        attrs.record(&mut fields);
        span.extensions_mut().insert(Observed {
            trace_id,
            span_id: new_span_id(),
            parent_span_id,
            start_unix_nanos: now_unix_nanos(),
            fields,
        });
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        let Some(span) = ctx.span(id) else {
            return;
        };
        let mut ext = span.extensions_mut();
        if let Some(observed) = ext.get_mut::<Observed>() {
            values.record(&mut observed.fields);
        }
    }

    fn on_close(&self, id: tracing::span::Id, ctx: Context<'_, S>) {
        let Some(span) = ctx.span(&id) else {
            return;
        };
        let Some(observed) = span.extensions_mut().remove::<Observed>() else {
            return;
        };
        self.traces.offer(SpanRecord {
            trace_id: observed.trace_id,
            span_id: observed.span_id,
            parent_span_id: observed.parent_span_id,
            name: span.metadata().name().to_string(),
            kind: observed.fields.kind.unwrap_or(SpanKind::Internal),
            start_unix_nanos: observed.start_unix_nanos,
            end_unix_nanos: now_unix_nanos(),
            status: observed.fields.status(),
            attributes: observed.fields.attributes,
            dropped_attributes: observed.fields.dropped,
        });
    }
}

// ── the tick ─────────────────────────────────────────────────────────────────────────────────

/// Run the span drain until the shutdown broadcast fires, then drain one last time.
///
/// Returns immediately when nothing was composed. The loop is the process's own maintenance tick —
/// the same one the metrics fold runs on — so the stop is a first-class arm of the wait and the
/// LAST interval of spans before a shutdown is exported instead of dropped. The retired pipeline
/// could not do that: its flush was the SDK's, and this process could not see whether it finished.
pub async fn run(shutdown: tokio::sync::broadcast::Receiver<()>) -> u64 {
    let Some(traces) = TRACES.get() else {
        return 0;
    };
    let traces = traces.clone();
    crate::root::metrics_drain::run(FLUSH_INTERVAL, shutdown, move || {
        let _ = traces.drain();
    })
    .await
}

/// Drain whatever is queued, right now, on the calling thread. The one serve mode whose exit does
/// not go through the shutdown broadcast — the stdio one, which `std::process::exit`s — calls this
/// so its final spans leave too. A no-op when nothing was composed.
pub fn flush() {
    if let Some(traces) = TRACES.get() {
        let _ = traces.drain();
    }
}

#[cfg(test)]
#[path = "../tests/traces.rs"]
mod tests;
