// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`busbar-export-webhook`** — the request-log WEBHOOK sink as a `kind: export` plugin on the
//! export kind's memory ABI (`busbar_contract::abi::export`, THE DESIGN §11):
//! `export.<name>.module: request-log-webhook`. ONE door ([`door`], `plugin_door!`), linked into
//! the binary as a compiled-in row or exported by the sibling `busbar-export-webhook-plugin` cdylib
//! as its one symbol; its manifest still carries [`DECLARES`] (the shed counter and the three
//! catalogue codes it raises).
//!
//! Each request-log line of a delivered batch is POSTed, as the compact JSON line it is, with
//! `content-type: application/json`, the instance's optional `auth_header`, and the
//! `authorization: Basic …` a userinfo in the URL becomes (as 1.5.5's reqwest made it), to the
//! instance's `https://` target — through the HOST's connector: the Statement declares ONE outbound
//! need whose target is the `url` setting (the host drops its userinfo), under the open-web egress
//! class (public destinations over a secure connection only), and the request rides the SDK's
//! framed `exchange` under the instance's `delivery_timeout_secs`. The sink never dials. A delivery
//! is fire-and-forget and never retried: a non-2xx answer or a transport failure drops that one line
//! and raises BUSBAR-7071 / BUSBAR-7072 at WARN, as 1.5.5 warned them.
//!
//! **Admission.** The door states `ready`, so the host's verdict on the target (the need's admission
//! at bind) is asked at boot, before the instance serves; a refused target raises BUSBAR-7070 (`…; disabling this webhook exporter`,
//! in 1.5.5's words when the refusal is the `https://` scheme rule)
//! once and the instance takes no delivery until a reload — its siblings keep delivering.
//!
//! **Settings** are checked in two phases, as they always were: their SHAPE while the configuration
//! is resolved (`validate`), and the delivery deadline and in-flight bound while it is validated
//! (`check`, after the limits). Every line the sink raises is logged with the catalogue's `diag`
//! banner field; the door's call capture carries it to the instance's plugin log (THE DESIGN §11.2).
//!
//! `deny`, not `forbid`: the export kind's SDK lends no safe reader of `check`'s instance list, so
//! [`instances`] reads it — the one reviewed `unsafe` here.

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
use busbar_contract::abi::sdk::conn::{ConnFailure, Host};
use busbar_contract::abi::sdk::door::{abi_str, statement};
use busbar_contract::abi::sdk::exchange::{exchange, Exchange, ExchangeResponse, Request};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};

/// The plugin's canonical name.
pub const NAME: &str = "busbar-stub-export-carried";
/// The module name an `export:` instance names it by.
pub const ALIAS: &str = "request-log-webhook";
/// The manifest `declares` section (`--declares-file` for the signed tarball).
pub const DECLARES: &str = include_str!("../declares.json");

/// The in-flight ceiling: the host's semaphore holds at most `usize::MAX >> 3` permits, and a
/// larger bound panics where the gate is built rather than failing validation.
const MAX_PERMITS: usize = usize::MAX >> 3;
/// The ceiling every duration in a busbar configuration is bounded by (30 years, in seconds).
const MAX_DURATION_SECS: u64 = 30 * 365 * 86_400;

const DISABLED: &str = "BUSBAR-7070";
const NON_2XX: &str = "BUSBAR-7071";
const TRANSPORT_ERROR: &str = "BUSBAR-7072";

/// The config path the target comes from: the `url` setting (`settings.<key>`, the path the host's
/// connection-table fill resolves). A bare key resolves to nothing, and the host's connector
/// refuses a need whose target resolved to nothing.
const TARGET_FROM: &str = "settings.url";

/// The in-flight ceiling this sink declares: no bound of its own. The bound is the operator's
/// `max_inflight_deliveries` (1.5.5's, 64 when unset), which the host applies per instance; `check`
/// refuses one past [`MAX_PERMITS`] or below 1.
const MAX_INFLIGHT: u32 = u32::MAX;
/// The one need's index in the Statement.
const NEED: u32 = 0;

mod config;
use config::DEFAULT_MAX_INFLIGHT;
pub use config::{ExportAuthHeader, WebhookSettings};

/// This sink's settings (the configuration's `WebhookSettings`).
pub type Settings = WebhookSettings;

const NONE: AbiStr = AbiStr {
    ptr: std::ptr::null(),
    len: 0,
};

/// The one need: outbound over a secure connection to the `url` setting's target, public
/// destinations only (1.5.5's https-only policy refusing loopback, link-local, private, CGNAT and
/// cloud-metadata targets). It is framed by the `http` transport — the scheme its claim names; an
/// `https://` target is secured by the host's connector, and the open-web egress class refuses any
/// target that is not secure before a byte leaves.
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
    // The receiver's response head is not read: the named (empty) list, nothing denied beyond it.
    keep_mode: busbar_contract::abi::host::conn::connector::KEEP_NAMED,
    _reserved: 0,
    deny_response_headers: std::ptr::null(),
    deny_response_headers_len: 0,
}];

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
    to: NONE,
}];

/// This plugin's Statement: its name, version, its in-flight ceiling, alias, stream and need.
pub const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    rewrites: REWRITES.as_ptr(),
    rewrites_len: REWRITES.len(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    ..statement(NAME, env!("CARGO_PKG_VERSION"), MAX_INFLIGHT)
};

/// The settings, parsed as the configuration grammar parses them (empty is `{}`).
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

    /// The settings' shape, in the configuration grammar's own serde words.
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        parse(settings).map(|_| ())
    }

    /// Never refuses: settings that do not parse are the configuration's refusal, reported by
    /// `validate` — a sink opened only to answer that must open.
    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self {
            settings: RwLock::new(parse(settings).ok()),
            live: Mutex::new(None),
        })
    }

    /// DISCOVERY AT BOOT (the mechanism's `ready`, awaited after `open` before the instance serves):
    /// the host's verdict on the target is asked here, once, so a refused target raises BUSBAR-7070
    /// at boot, as 1.5.5 refused it when the sink was configured. It never refuses the boot: the
    /// instance is disabled and its siblings serve, as in 1.5.5. Settings that did not parse are the
    /// configuration's refusal, not this one's.
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

    /// A reload's settings replace the instance's, and its target is asked about afresh.
    fn refresh(&self, settings: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        *self
            .settings
            .write()
            .unwrap_or_else(PoisonError::into_inner) = parse(settings).ok();
        *self.live.lock().unwrap_or_else(PoisonError::into_inner) = None;
        Ok(Refreshed::default())
    }
}

impl Webhook {
    /// The instance's settings, when they parsed.
    pub fn settings(&self) -> Option<Settings> {
        self.settings
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Whether the host admitted the target, asked once: a refusal (or no host to ask) raises
    /// BUSBAR-7070 in the host's words and disables the instance.
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

/// The request one line is POSTed as: compact JSON to the target's path and query, under the
/// instance's deadline, with the fields 1.5.5's reqwest request held, in its order: the
/// `authorization: Basic …` the URL's userinfo became ([`basic_authorization`]), then
/// `content-type: application/json`, then the auth header — each appended as an `http::HeaderMap`
/// appends, so a configured auth header named `Authorization` is sent too, after the userinfo's,
/// as 1.5.5 sent both.
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

/// One field appended as an `http::HeaderMap` appends it, the map 1.5.5's request held its fields
/// in and wrote them from: after the last field of the same name (names compared without case),
/// or last when there is none.
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

/// THE USERINFO AS 1.5.5 SENT IT: the `authorization` value a target URL's userinfo became, `None`
/// when it carries none. 1.5.5 POSTed through reqwest 0.12, whose `RequestBuilder::new`
/// (`extract_authority`) took the parsed URL's username and password off the URL, each
/// percent-decoded and kept only when that is UTF-8 (a username that is not leaves no field at
/// all; a password that is not is left out), and, when either was set, wrote `basic_auth`:
/// `Basic ` and the padded standard base64 of `{username}:` followed by the password, if any. The
/// host's connector drops the userinfo from the target the `url` setting gives the need.
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

/// `%XX` (two hex digits, either case) decoded to its byte; any other byte, a `%` not followed by
/// two hex digits included, kept as it is (percent-encoding's `percent_decode`).
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

/// The standard base64 alphabet, padded (RFC 4648 §4; base64's `STANDARD` engine).
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

/// BUSBAR-7070's words for a refused target. When the host refused it and the target is not an
/// `https://` URL, the refusal is the scheme rule, and it is said in 1.5.5's words byte for byte
/// (v1.5.5 `crates/busbar/src/observability.rs` `validate_webhook_url`; the scheme read without
/// case, as there). Any other refusal is said in the host's words.
pub fn refusal_words(url: Option<&str>, refused: &ConnFailure) -> String {
    match (url, refused) {
        (Some(u), ConnFailure::Refused(_)) if !is_https(u) => format!(
            "observability.request_log_webhook_url must be an https:// URL (got '{}')",
            mask_userinfo(u)
        ),
        _ => refused.to_string(),
    }
}

/// `url` names the `https` scheme, read without case (RFC 3986; 1.5.5's `scheme_is`).
fn is_https(url: &str) -> bool {
    url.split_once("://")
        .is_some_and(|(scheme, _)| scheme.eq_ignore_ascii_case("https"))
}

/// What became of one line: nothing to say for a 2xx; BUSBAR-7071 for any other status,
/// BUSBAR-7072 for a transport failure — each at WARN, as 1.5.5 warned them
/// (`warn_webhook_delivery_failed`), the target's userinfo masked.
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

/// The checks the configuration's VALIDATION runs across every webhook instance, each at the point
/// of the validation it has always run at: AMONG the operational limits' checks
/// ([`CheckPhase::Limits`]) the in-flight bound — one bound over the instances, the largest
/// configured (64 with none), so a generous instance is never refused for a stingy sibling; AFTER
/// them ([`CheckPhase::Instances`]) each instance's delivery deadline, numbered by its position.
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

/// Each instance's delivery deadline, numbered by its position among the instances.
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

/// `url` with any userinfo (`scheme://user:pass@host/…`) replaced by `***`, safe for a log line;
/// a URL with none, or a string that is not a URL, unchanged.
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

/// The mask for a string `url::Url` refuses (an empty host, say) yet that still carries
/// `scheme://userinfo@…`: everything between `://` and the last `@` of the authority becomes `***`.
/// A string with no such authority is returned unchanged.
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

/// `check`'s instances, `(name, settings)` in configuration order (settings that are not JSON read
/// as `null`, which no check parses).
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

/// The instance state every slot reads.
type State = Held<Webhook>;

/// What a delivery parks across PENDING: the line it is on, the handles issued before that line's
/// exchange, and the exchange.
struct Posting {
    line: usize,
    issued: u32,
    exchange: Option<Exchange>,
}

/// `deliver`: each line of the batch POSTed in order, one exchange after another; fire-and-forget,
/// so READY whatever became of the lines, PENDING while an exchange runs.
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
        let Some(s) = hook.settings() else {
            return Outcome::Ready;
        };
        if !hook.admitted(h.host()) {
            return Outcome::Ready;
        }
        let lines: Vec<&[u8]> = input
            .field(|i| &i.batch)
            .bytes()
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty())
            .collect();
        let mut at = instance.resume::<Posting>().map_or(
            Posting {
                line: 0,
                issued: 0,
                exchange: None,
            },
            |p| *p,
        );
        while let Some(line) = lines.get(at.line) {
            let answered = match h.host() {
                None => Err(ConnFailure::Unarmed),
                Some(host) => {
                    let mut c = host.connector_from(instance.ticket(), at.issued);
                    let started = match at.exchange.take() {
                        Some(ex) => Ok(ex),
                        None => Exchange::request(request(&s, line)),
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
            report(&s.url, answered);
            at.line += 1;
        }
        Outcome::Ready
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

/// `check`: [`check`] at the phase asked, its lines as a JSON array under a lease.
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
    use super::{Check, Deliver, Safe, Scrape, Serve, Status, Webhook};

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: super::STATEMENT,
        lifecycle: life(Webhook, ready),
        kind_ops: {
            deliver: Safe<Deliver>, scrape: Safe<Scrape>, status: Safe<Status>,
            check: Safe<Check>, serve: Safe<Serve>,
        },
    }
}

/// This plugin's door: the one a compiled-in build links and the dropped-in image exports.
pub use table::door;
