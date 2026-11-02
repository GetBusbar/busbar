// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#![deny(unsafe_code)]

use std::mem::size_of;
use std::sync::{Mutex, PoisonError, RwLock};
use std::task::Poll;

use busbar_contract::abi::export::{
    self, CheckIn, CheckOut, CheckPhase, DeliverIn, ExportStream, ScrapeIn, ScrapeOut, ServeIn,
    ServeOut, StatusOut, Tail, CHECK_PHASE_LIMITS,
};
use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, EGRESS_OPEN_WEB};
use busbar_contract::abi::mechanism::call::{AbiStr, Blob, InHead, OutHead, Outcome, BLOB_JSON};
use busbar_contract::abi::mechanism::door::{KindTailHead, Rewrite, Statement, REWRITE_ALIAS};
use busbar_contract::abi::mechanism::lifecycle::RefreshIn;
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::{exchange, Exchange, ExchangeResponse, Request};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};

pub const NAME: &str = "busbar-stub-export-carried";

pub const ALIAS: &str = "request-log-webhook";

pub const DECLARES: &str = include_str!("../declares.json");

const MAX_PERMITS: usize = usize::MAX >> 3;

const MAX_DURATION_SECS: u64 = 30 * 365 * 86_400;

const DISABLED: &str = "BUSBAR-7070";
const NON_2XX: &str = "BUSBAR-7071";
const TRANSPORT_ERROR: &str = "BUSBAR-7072";

const TARGET_FROM: &str = "settings.url";

const MAX_INFLIGHT: u32 = u32::MAX;

const NEED: u32 = 0;

mod config;
use config::DEFAULT_MAX_INFLIGHT;
pub use config::{ExportAuthHeader, WebhookSettings};

pub type Settings = WebhookSettings;

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_OUTBOUND,
    egress_class: EGRESS_OPEN_WEB,
    transport: abi_str("http"),
    auth: NONE,
    target_from: abi_str(TARGET_FROM),
    trust_from: NONE,
    details: Blob::ABSENT,
    keep_response_headers: std::ptr::null(),
    keep_response_headers_len: 0,
    timeout_ms: 0,

    keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}];

const STREAMS: &[u8] = &[ExportStream::Logs as u8];

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
    to: NONE,
}];

pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    ..statement(NAME, env!("CARGO_PKG_VERSION"), MAX_INFLIGHT)
};

fn parse(settings: &[u8]) -> Result<Settings, Refusal> {
    let bytes = if settings.is_empty() { b"{}" } else { settings };
    serde_json::from_slice::<serde_json::Value>(bytes)
        .and_then(serde_json::from_value)
        .map_err(|e| Refusal::failed(format!("settings: {e}")))
}

/// One opened instance.
#[derive(Debug)]
pub struct Webhook {
    /// Its settings, when they parse (the host refused the configuration otherwise; a sink opened
    /// only to validate or check settings still opens).
    settings: RwLock<Option<Settings>>,
    /// The host's verdict on the target: `None` until the first delivery asks.
    live: Mutex<Option<bool>>,
}

impl Life for Webhook {
    const CANCEL: u32 = export::cancel::ABORTED;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        parse(settings).map(|_| ())
    }

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            settings: RwLock::new(parse(settings).ok()),
            live: Mutex::new(None),
        })
    }

    fn ready(
        &self,
        host: &Host,
        _: busbar_contract::abi::mechanism::ticket::Ticket,
    ) -> Poll<Result<(), Refusal>> {
        if self.settings().is_some() {
            let _ = self.admitted(Some(host));
        }
        Poll::Ready(Ok(()))
    }

    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        let settings = parse(settings)?;
        *self
            .settings
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(settings);
        *self.live.lock().unwrap_or_else(PoisonError::into_inner) = None;
        Ok(Refreshed::default())
    }
}

impl Webhook {
    pub fn settings(&self) -> Option<Settings> {
        self.settings
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn admitted(&self, host: Option<&Host>) -> bool {
        let mut live = self.live.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(v) = *live {
            return v;
        }
        let verdict = host.map_or(Err(ConnFailure::Unarmed), |h| {
            h.connector(busbar_contract::abi::mechanism::ticket::Ticket::NONE)
                .admit(NEED)
        });
        let ok = match verdict {
            Ok(()) => true,
            Err(e) => {
                let url = self.settings().map(|s| s.url);
                let words = refusal_words(url.as_deref(), &e);
                tracing::error!(diag = %DISABLED, "{words}; disabling this webhook exporter");
                false
            }
        };
        *live = Some(ok);
        ok
    }
}

pub fn request(s: &Settings, line: &[u8]) -> Request {
    let mut fields = Vec::new();
    if let Some(basic) = basic_authorization(&s.url) {
        append(&mut fields, b"authorization", &basic);
    }
    append(&mut fields, b"content-type", b"application/json");
    if let Some(h) = &s.auth_header {
        append(&mut fields, h.name.as_bytes(), h.value.as_bytes());
    }
    let target = match url::Url::parse(&s.url) {
        Ok(u) => match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_string(),
        },
        Err(_) => "/".to_string(),
    };
    Request {
        method: b"POST".to_vec(),
        target: target.into_bytes(),
        fields,
        body: line.to_vec(),
        timeout_ms: s.delivery_timeout_secs.saturating_mul(1000),
    }
}

fn append(fields: &mut Vec<(Vec<u8>, Vec<u8>)>, name: &[u8], value: &[u8]) {
    let field = (name.to_vec(), value.to_vec());
    match fields
        .iter()
        .rposition(|(n, _)| n.eq_ignore_ascii_case(name))
    {
        Some(i) => fields.insert(i + 1, field),
        None => fields.push(field),
    }
}

pub fn basic_authorization(url: &str) -> Option<Vec<u8>> {
    let u = url::Url::parse(url).ok()?;
    if !u.has_authority() {
        return None;
    }
    let username = String::from_utf8(percent_decode(u.username().as_bytes())).ok()?;
    let password = u
        .password()
        .and_then(|p| String::from_utf8(percent_decode(p.as_bytes())).ok());
    if username.is_empty() && password.is_none() {
        return None;
    }
    let mut credentials = format!("{username}:").into_bytes();
    if let Some(p) = password {
        credentials.extend_from_slice(p.as_bytes());
    }
    let mut value = b"Basic ".to_vec();
    value.extend_from_slice(base64(&credentials).as_bytes());
    Some(value)
}

fn percent_decode(s: &[u8]) -> Vec<u8> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            let pair = s
                .get(i + 1)
                .copied()
                .and_then(hex)
                .zip(s.get(i + 2).copied().and_then(hex));
            if let Some((high, low)) = pair {
                out.push((high << 4) | low);
                i += 3;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        let sextets = [
            a >> 2,
            ((a & 0x03) << 4) | (b >> 4),
            ((b & 0x0f) << 2) | (c >> 6),
            c & 0x3f,
        ];
        for (i, sextet) in sextets.into_iter().enumerate() {
            out.push(if i <= chunk.len() {
                char::from(ALPHABET[usize::from(sextet)])
            } else {
                '='
            });
        }
    }
    out
}

pub fn refusal_words(url: Option<&str>, refused: &ConnFailure) -> String {
    match (url, refused) {
        (Some(u), ConnFailure::Refused(_)) if !is_https(u) => format!(
            "observability.request_log_webhook_url must be an https:// URL (got '{}')",
            mask_userinfo(u)
        ),
        _ => refused.to_string(),
    }
}

fn is_https(url: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
}

pub fn report(url: &str, answered: Result<ExchangeResponse, ConnFailure>) {
    match answered {
        Ok(r) if (200..300).contains(&r.status) => {}
        Ok(r) => tracing::warn!(
            diag = %NON_2XX,
            webhook_url = ?mask_userinfo(url),
            status = %r.status,
            "request-log webhook delivery returned a non-2xx status; this log was dropped"
        ),
        Err(e) => tracing::warn!(
            diag = %TRANSPORT_ERROR,
            webhook_url = ?mask_userinfo(url),
            error_kind = %e,
            "request-log webhook delivery failed (transport error); this log was dropped"
        ),
    }
}

pub fn check(phase: CheckPhase, instances: &[(String, serde_json::Value)]) -> Vec<String> {
    let parsed: Vec<Settings> = instances
        .iter()
        .filter_map(|(_, s)| serde_json::from_value(s.clone()).ok())
        .collect();
    let mut errors = Vec::new();
    if phase == CheckPhase::Instances {
        instance_checks(&parsed, &mut errors);
        return errors;
    }
    let bound = parsed
        .iter()
        .map(|w| w.max_inflight_deliveries)
        .max()
        .unwrap_or(DEFAULT_MAX_INFLIGHT);
    if bound < 1 {
        errors.push(
            "export.request-log-webhook.settings.max_inflight_deliveries must be >= 1 (a 0-permit \
             semaphore admits nothing, silently dropping every webhook delivery)"
                .to_string(),
        );
    }
    if bound > MAX_PERMITS {
        errors.push(format!(
            "export.request-log-webhook.settings.max_inflight_deliveries must be <= \
             {MAX_PERMITS} (tokio::sync::Semaphore's hard permit ceiling — a value above \
             it panics at build time instead of failing validation)"
        ));
    }
    errors
}

fn instance_checks(parsed: &[Settings], errors: &mut Vec<String>) {
    for (i, w) in parsed.iter().enumerate() {
        if w.delivery_timeout_secs > MAX_DURATION_SECS {
            errors.push(format!(
                "the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.delivery_timeout_secs: {}, above the {MAX_DURATION_SECS}-second (30-year) \
                 ceiling every duration is bounded by — a delivery deadline that far out overflows \
                 the clock",
                mask_userinfo(&w.url),
                w.delivery_timeout_secs
            ));
        }
        if w.delivery_timeout_secs < 1 {
            errors.push(format!(
                "the `module: request-log-webhook` export instance targeting '{}' (#{i}) sets \
                 settings.delivery_timeout_secs: 0, which would abort every delivery — it must be \
                 >= 1",
                mask_userinfo(&w.url)
            ));
        }
    }
}

pub fn mask_userinfo(url: &str) -> String {
    let Ok(mut parsed) = url::Url::parse(url) else {
        return mask_unparsed(url);
    };
    if parsed.username().is_empty() && parsed.password().is_none() {
        return url.to_string();
    }
    if parsed.set_password(None).is_err() || parsed.set_username("***").is_err() {
        let host = parsed.host_str().unwrap_or("");
        return match parsed.port() {
            Some(p) => format!("{}://***@{host}:{p}", parsed.scheme()),
            None => format!("{}://***@{host}", parsed.scheme()),
        };
    }
    parsed.into()
}

fn mask_unparsed(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    match rest[..end].rfind('@') {
        Some(at) => format!("{scheme}://***{}", &rest[at..]),
        None => url.to_string(),
    }
}

#[allow(unsafe_code)]
fn instances(input: Lent<'_, CheckIn>) -> Vec<(String, serde_json::Value)> {
    /// `len` bytes at `p`, or none.
    ///
    /// # Safety
    /// A non-NULL `p` points at `len` readable bytes, valid for the call.
    unsafe fn lent<'a>(p: *const u8, len: usize) -> &'a [u8] {
        if p.is_null() || len == 0 {
            return &[];
        }
        // SAFETY: the caller's contract.
        unsafe { std::slice::from_raw_parts(p, len) }
    }
    let i = input.get();
    if i.instances.is_null() || i.instances_len == 0 {
        return Vec::new();
    }
    // SAFETY: the host lends `instances_len` `CheckInstance`s at `instances`, and every string and
    // blob they name, for the call (`abi::export::CheckIn`); `input` is lent for the call.
    let list = unsafe { std::slice::from_raw_parts(i.instances, i.instances_len) };
    list.iter()
        .map(|c| {
            // SAFETY: as above.
            let (name, settings) = unsafe {
                (
                    lent(c.name.ptr, c.name.len),
                    lent(c.settings.ptr, c.settings.len),
                )
            };
            (
                String::from_utf8_lossy(name).into_owned(),
                serde_json::from_slice(settings).unwrap_or(serde_json::Value::Null),
            )
        })
        .collect()
}

type State = Held<Webhook>;

struct Refreshing {
    settings: Settings,
    probe: usize,
    issued: u32,
    exchange: Option<Exchange>,
}

pub struct Refresh;

const PENDING_REFRESH_PATH_MARKER: &str = "/pending-refresh";
const REFUSED_REFRESH_PATH_MARKER: &str = "pending-refresh-refuse";
const REFRESH_PROBE_FIELD: &str = "refresh_probe";
const CANDIDATE_EXCHANGES: usize = 2;

impl SafeSlot for Refresh {
    type In = RefreshIn;
    type Out = OutHead;
    type State = State;

    fn call(
        instance: Instance<'_, State>,
        input: Lent<'_, RefreshIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Refused;
        };
        let settings = match parse(input.field(|i| &i.settings).bytes()) {
            Ok(settings) => settings,
            Err(error) => return out.fail(error),
        };
        if !settings.url.contains(PENDING_REFRESH_PATH_MARKER) {
            return <busbar_contract::abi::sdk::life::Refresh<Webhook> as SafeSlot>::call(
                instance, input, out,
            );
        }
        let mut pending = instance.resume::<Refreshing>().map_or_else(
            || Refreshing {
                settings,
                probe: 0,
                issued: 0,
                exchange: None,
            },
            |pending| *pending,
        );
        let Some(host) = h.host() else {
            return Outcome::Refused;
        };
        while pending.probe < CANDIDATE_EXCHANGES {
            let mut connector = host.connector_from(instance.ticket(), pending.issued);
            let mut exchange = match pending.exchange.take() {
                Some(exchange) => exchange,
                None => match Exchange::request(request(
                    &pending.settings,
                    format!("{{\"{REFRESH_PROBE_FIELD}\":{}}}", pending.probe).as_bytes(),
                )) {
                    Ok(exchange) => exchange,
                    Err(error) => return out.fail(Refusal::failed(error.to_string())),
                },
            };
            match busbar_contract::abi::sdk::exchange::exchange(
                &mut connector,
                &mut exchange,
                NEED,
                None,
            ) {
                Poll::Pending => {
                    pending.exchange = Some(exchange);
                    instance.park(pending);
                    return Outcome::Pending;
                }
                Poll::Ready(Ok(_)) => {
                    pending.issued = connector.issued();
                    pending.probe += 1;
                }
                Poll::Ready(Err(error)) => return out.fail(Refusal::failed(error.to_string())),
            }
        }
        if pending.settings.url.contains(REFUSED_REFRESH_PATH_MARKER) {
            return out.fail(Refusal::refused(
                "the neutral fixture refused its checked candidate",
            ));
        }
        *h.life()
            .settings
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(pending.settings);
        *h.life().live.lock().unwrap_or_else(PoisonError::into_inner) = None;
        Outcome::Ready
    }
}

struct Posting {
    settings: Settings,
    line: usize,
    issued: u32,
    exchange: Option<Exchange>,
}

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
        let hook = h.life();
        let mut at = match instance.resume::<Posting>() {
            Some(posting) => *posting,
            None => {
                let Some(settings) = hook.settings() else {
                    return Outcome::Ready;
                };
                if !hook.admitted(h.host()) {
                    return Outcome::Ready;
                }
                Posting {
                    settings,
                    line: 0,
                    issued: 0,
                    exchange: None,
                }
            }
        };
        let lines: Vec<&[u8]> = input
            .field(|i| &i.batch)
            .bytes()
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        while let Some(line) = lines.get(at.line) {
            let answered = match h.host() {
                None => Err(ConnFailure::Unarmed),
                Some(host) => {
                    let mut c = host.connector_from(instance.ticket(), at.issued);
                    let started = match at.exchange.take() {
                        Some(ex) => Ok(ex),
                        None => Exchange::request(request(&at.settings, line)),
                    };
                    match started {
                        Err(e) => Err(e),
                        Ok(mut ex) => match exchange(&mut c, &mut ex, NEED, None) {
                            Poll::Pending => {
                                at.exchange = Some(ex);
                                instance.park(at);
                                return Outcome::Pending;
                            }
                            Poll::Ready(r) => {
                                at.issued = c.issued();
                                r
                            }
                        },
                    }
                }
            };
            report(&at.settings.url, answered);
            at.line += 1;
        }
        Outcome::Ready
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
    fn call(
        instance: Instance<'_, State>,
        input: Lent<'_, CheckIn>,
        mut out: Out<'_, CheckOut>,
    ) -> Outcome {
        let Some(h) = instance.get() else {
            return Outcome::Refused;
        };
        let phase = match input.phase {
            CHECK_PHASE_LIMITS => CheckPhase::Limits,
            _ => CheckPhase::Instances,
        };
        let lines = check(phase, &instances(input));
        if !lines.is_empty() {
            let json = serde_json::to_vec(&lines).unwrap_or_default();
            out.lease(|o| &o.findings, h.leases(), json, BLOB_JSON);
        }
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
    use super::{Check, Deliver, Refresh, Safe, Scrape, Serve, Status, Webhook};
    use busbar_contract::abi::sdk::life;

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: super::STATEMENT,
        lifecycle: {
            validate: Safe<life::Validate<Webhook>>, open: Safe<life::Open<Webhook>>,
            refresh: Safe<Refresh>, retire: Safe<life::Retire<Webhook>>,
            tick: Safe<life::Tick<Webhook>>, drive: Safe<life::Drive<Webhook>>,
            cancel: Safe<life::Cancel<Webhook>>, release: Safe<life::Release<Webhook>>,
            close: Safe<life::Close<Webhook>>,
        },
        ready: Safe<life::Ready<Webhook>>,
        kind_ops: {
            deliver: Safe<Deliver>, scrape: Safe<Scrape>, status: Safe<Status>,
            check: Safe<Check>, serve: Safe<Serve>,
        },
    }
}

pub use table::door;
