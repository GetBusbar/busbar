// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SELF-MINTING STYLES' SHARED MACHINERY: `jwt-bearer` (RFC 7523) and `oauth-client-credentials`
//! (RFC 6749 §4.4) each obtain a short-lived bearer from a token endpoint and present it as
//! `authorization: Bearer <token>`. They differ ONLY in the token request ([`jwt_bearer`],
//! [`oauth_client_credentials`]). This module owns everything else: the cached token, the
//! per-request read, and the refresh ahead of expiry.
//!
//! MOVED from the kernel's `egress_auth/bearer_token.rs` and the two mint bodies (KERNEL<>PLUGINS
//! step 22). The cached token, the header built once at mint, the empty-token-is-a-failure rule, the
//! refresh schedule ([`next_refresh_secs`]) and every failure text are verbatim. What changed is the
//! DRIVER, as BUSBAR-1.6.0.md THE DESIGN, §6.5 requires: the old background tokio task becomes a state machine
//! advanced on `tick` ([`Minted::tick`]), and the old engine client becomes the plugin's own need
//! ([`Wire`], the host's connection table). Nothing here blocks: a read with nothing ready answers
//! pending and the next `tick` reads again.
//!
//! THE EXPIRED-TOKEN RULE (BUSBAR-1.6.0.md THE DESIGN, §6.5, Q-EXPIRED): when the cached token has expired AND its
//! refresh has failed, the per-request call answers not-ready ([`Read::Wait`]) and the ticket is
//! woken when a mint lands; the host bounds the wait by the attempt's deadline.

pub(crate) mod host_wire;
pub(crate) mod jwt_bearer;
pub(crate) mod oauth_client_credentials;
pub(crate) mod token_exchange;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use busbar_contract::conn::{ConnError, ConnId, PieceKind};
use busbar_contract::redacted::Redacted;

use crate::token_response::{
    default_expires_in, deserialize_expires_in, deserialize_redacted, json_err,
};
use busbar_contract::header::{is_legal_header_value, token_value};

/// Refresh this many seconds BEFORE the token's stated expiry, so a request never races an expired
/// token across the refresh boundary.
const REFRESH_SKEW_SECS: u64 = 300;
/// Floor on the refresh sleep so a short-lived / already-near-expiry token can't spin the loop hot,
/// and the retry delay after a mint failure.
pub(crate) const MIN_SLEEP_SECS: u64 = 30;
/// The whole-mint deadline — send plus capped body read under ONE absolute instant, the
/// client-level 30s total the retired reqwest builder carried.
pub(crate) const MINT_DEADLINE_SECS: u64 = 30;
/// The cap on a token response body when the kernel states none: 1.5.5's
/// `limits.upstream_error_body_max_bytes` default (256 KiB). The kernel passes the operator's value
/// in the binding's settings (`max_response_bytes`).
pub(crate) const DEFAULT_MAX_RESPONSE_BYTES: usize = 256 * 1024;
/// How long `tick` waits before reading an in-flight exchange again.
pub(crate) const IN_FLIGHT_POLL_NS: u64 = 5_000_000;

/// Nanoseconds in a second, on the tick clock.
pub(crate) const NS: u64 = 1_000_000_000;

/// Wall-clock seconds since the epoch (1970-01-01 UTC) — the clock a token's `expires_in` and a JWT's `iat` are
/// read against, as in 1.5.5.
pub(crate) fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// THE PLUGIN'S OWN NEEDS, by their index in the Statement (`crate::NEEDS`): the token endpoint
/// each style POSTs to, its target the binding's own setting (egress class `loopback-allowed`: https
/// or loopback plaintext, as 1.5.5 validated a mint endpoint; ARCHITECT ruling, SEAM-4f).
pub(crate) mod need {
    /// `oauth-client-credentials`: `settings.token_url`.
    pub const TOKEN_URL: u32 = 0;
    /// `jwt-bearer`: `settings.token_uri`.
    pub const TOKEN_URI: u32 = 1;
}

/// One token request: POST `body` (a form) to `target`, over the need `need`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TokenRequest {
    /// The need it goes out on ([`need`]).
    pub need: u32,
    /// The token endpoint.
    pub target: String,
    /// The head fields, in order.
    pub fields: Vec<(&'static str, &'static str)>,
    /// The form body.
    pub body: Redacted<String>,
}

impl TokenRequest {
    /// A form POST of `body` to `target`, over the need `need`. Its fields are 1.5.5's, in 1.5.5's
    /// order: the form's `content-type`, then reqwest's client-default `accept: */*`, which the
    /// request carries itself (the http door writes no field the caller did not: transport
    /// neutrality, SEAM-4i).
    pub(crate) fn form(need: u32, target: String, body: String) -> Self {
        Self {
            need,
            target,
            fields: vec![
                ("content-type", "application/x-www-form-urlencoded"),
                ("accept", "*/*"),
            ],
            body: Redacted::new(body),
        }
    }
}

/// A style that mints: how it builds its token request.
pub(crate) enum Minter {
    /// RFC 7523.
    JwtBearer(Box<jwt_bearer::Signer>),
    /// RFC 6749 §4.4.
    ClientCredentials(oauth_client_credentials::ClientCreds),
    /// RFC 8693, for one scope: minted ON DEMAND (a request that finds no usable token starts the
    /// exchange), never refreshed ahead of a request.
    TokenExchange(token_exchange::Scoped),
}

impl Minter {
    fn request(&self, now: u64) -> Result<TokenRequest, String> {
        match self {
            Minter::JwtBearer(s) => s.request(now),
            Minter::ClientCredentials(c) => c.request(),
            Minter::TokenExchange(x) => x.request(),
        }
    }
}

/// A minted access token and the wall-clock epoch second it expires at.
pub(crate) struct CachedToken {
    /// The minted bearer, held redacted so it never leaks via `Debug`/logs and zeroizes on drop.
    pub(crate) token: Redacted<String>,
    pub(crate) expires_at: u64,
    /// The `Bearer <token>` value, pre-built ONCE here (at mint time) rather than on every request.
    /// `None` when `token` is empty (the pre-first-mint sentinel) or contains bytes invalid for an
    /// header value — both cases mean "emit no auth header".
    header: Option<Redacted<String>>,
}

impl std::fmt::Debug for CachedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedToken")
            .field("token", &self.token)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl CachedToken {
    /// Construct a `CachedToken`, building its header once here. The second value is whether the
    /// token was omitted for bytes invalid in a header value (the caller reports it). The token
    /// arrives already [`Redacted`] (the minters decode it straight into one); the header build
    /// below is its one exposure.
    pub(crate) fn new(token: Redacted<String>, expires_at: u64) -> (Self, bool) {
        let (header, invalid) = if token.expose_secret().is_empty() {
            (None, false)
        } else {
            let v = token_value(token.expose_secret());
            if is_legal_header_value(&v) {
                (Some(Redacted::new(v)), false)
            } else {
                (None, true)
            }
        };
        (
            Self {
                token,
                expires_at,
                header,
            },
            invalid,
        )
    }

    /// The header value, when there is one to present.
    pub(crate) fn header(&self) -> Option<&str> {
        self.header.as_ref().map(|h| h.expose_secret().as_str())
    }
}

/// Seconds to sleep before the next re-mint, given a token that expires at `expires_at` (epoch secs).
///
/// Refresh `REFRESH_SKEW_SECS` BEFORE expiry for a normally-lived token so a request never races the
/// expiry boundary. But that skew cannot be honored for a SHORT-TTL token: the old
/// `(ttl - SKEW).max(MIN_SLEEP)` floored the sleep back up to `MIN_SLEEP_SECS` (30s) even for a token
/// that expired in, say, 10s — so `headers_for` served an EXPIRED bearer for ~20s and the upstream 401'd.
/// Instead:
///   - `ttl == 0` (already expired / garbage `expires_in ≈ 0`): back off `MIN_SLEEP_SECS` so the mint
///     loop cannot spin hot — nothing useful to serve, fail safe.
///   - `ttl <= REFRESH_SKEW_SECS` (too short to refresh a full skew early): re-mint at ~half the
///     remaining life, so the refresh always lands BEFORE expiry (never past `ttl`), and never below 1s.
///   - otherwise: the normal `ttl - REFRESH_SKEW_SECS`, with `MIN_SLEEP_SECS` as a hot-loop floor near
///     the skew boundary.
///
/// Guarantees: for any `ttl > 0` the next mint is scheduled strictly before expiry (no expired token is
/// served); for `ttl == 0` the loop is rate-limited to `MIN_SLEEP_SECS`.
pub(crate) fn next_refresh_secs(expires_at: u64, now: u64) -> u64 {
    let ttl = expires_at.saturating_sub(now);
    if ttl == 0 {
        MIN_SLEEP_SECS
    } else if ttl <= REFRESH_SKEW_SECS {
        (ttl / 2).max(1)
    } else {
        (ttl - REFRESH_SKEW_SECS).max(MIN_SLEEP_SECS)
    }
}

/// An OAuth token endpoint's success body (RFC 6749 section 5.1), as far as a minter reads it.
/// Deserialize-only, and `access_token` is decoded straight into [`Redacted`] (secret-hygiene #53).
#[derive(serde::Deserialize)]
struct TokenResponse {
    #[serde(deserialize_with = "deserialize_redacted")]
    access_token: Redacted<String>,
    #[serde(
        default = "default_expires_in",
        deserialize_with = "deserialize_expires_in"
    )]
    expires_in: u64,
}

/// Parse a finished token response: a non-2xx status is the endpoint's refusal, named with a short
/// snippet of its body; otherwise the JSON token. Verbatim from the two mint bodies.
pub(crate) fn parse_response(
    status: u16,
    body: &[u8],
    now: u64,
) -> Result<(CachedToken, bool), String> {
    let body = String::from_utf8_lossy(body);
    if !(200..300).contains(&status) {
        // Never log the request/assertion wholesale (may echo claims or the client secret); status +
        // a short snippet only. Diagnostic-only: the request has already failed on `status`.
        let status = http::StatusCode::from_u16(status)
            .map(|s| s.to_string())
            .unwrap_or_else(|_| status.to_string());
        return Err(format!(
            "token endpoint returned {status}: {}",
            body.chars().take(200).collect::<String>()
        ));
    }
    // A decode failure is described without the decoder's text, which can quote the token.
    let tok: TokenResponse =
        serde_json::from_str(&body).map_err(json_err("token response JSON invalid"))?;
    Ok(CachedToken::new(
        tok.access_token,
        // saturating_add: `expires_in` is attacker-influenced (comes off the token endpoint), so a
        // huge value must clamp to u64::MAX rather than wrap/panic.
        now.saturating_add(tok.expires_in),
    ))
}

/// One piece a need's connection delivered, as the exchange reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Got {
    /// What the piece carries.
    pub kind: PieceKind,
    /// How many bytes of the buffer it filled.
    pub len: usize,
    /// It ends its frame.
    pub end: bool,
    /// The status number, where the wire reports one.
    pub status: Option<u32>,
}

/// The plugin's own need, as the exchange uses it: the host's connection table
/// (`busbar_contract::abi::host::conn::HostConns`), or a test's double.
pub(crate) trait Wire: Send + Sync {
    /// Open a connection for the need, sending the request's head and body.
    fn open(&self, req: &TokenRequest, timeout_ms: u64) -> Result<ConnId, ConnError>;
    /// Read one piece into `buf`; [`ConnError::Pending`] when nothing is ready.
    fn read(&self, conn: ConnId, buf: &mut [u8]) -> Result<Got, ConnError>;
    /// Close the connection.
    fn close(&self, conn: ConnId);
}

/// Where one binding's exchange stands.
enum Exchange {
    /// No exchange; the next is due at `due_ns` on the tick clock.
    Idle { due_ns: u64 },
    /// An exchange is in flight on `conn`.
    InFlight {
        conn: ConnId,
        started_ns: u64,
        status: Option<u32>,
        body: Vec<u8>,
    },
}

/// What a finished tick of one cell reports for the envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Report {
    /// A mint failed; it will retry (`EGRESS_OAUTH_MINT_FAILED`).
    MintFailed(String),
    /// The endpoint answered 200 with an empty token (`EGRESS_OAUTH_EMPTY_TOKEN`).
    EmptyToken,
    /// The minted token holds bytes invalid in a header value (`EGRESS_OAUTH_TOKEN_INVALID_BYTES`).
    TokenInvalidBytes,
    /// A token landed.
    Minted,
}

/// The answer the per-request call reads.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Read<'a> {
    /// Present this header value (`Bearer <token>`).
    Header(&'a str),
    /// No header (an un-encodable token): the upstream answers 401.
    Nothing,
    /// Not ready: nothing has minted yet (THE DESIGN §11: Ready | Pending, PENDING until the first
    /// mint lands), or the token has expired and its refresh failed.
    Wait,
}

/// ONE BINDING'S TOKEN: keyed by (style, credential, settings) in the instance's cache, so it
/// survives `refresh` and re-opening (abi/auth: the outbound token cache outlives a handle).
pub(crate) struct Minted {
    minter: Minter,
    max_response_bytes: usize,
    token: RwLock<Arc<CachedToken>>,
    exchange: Mutex<Exchange>,
    refresh_failed: AtomicBool,
    /// Minted on demand ([`Minter::TokenExchange`]): no refresh ahead of a request, no retry on a
    /// schedule; a request that finds no usable token arms the next exchange.
    on_demand: bool,
    /// An on-demand cell's token is presented until this wall-clock epoch second: the instant a
    /// scheduled style would refresh it ([`next_refresh_secs`] from its mint).
    usable_until: AtomicU64,
}

impl Minted {
    /// A cell that has minted nothing yet; its first exchange is due on the first `tick`.
    pub(crate) fn new(minter: Minter, max_response_bytes: usize) -> Self {
        Self {
            on_demand: matches!(minter, Minter::TokenExchange(_)),
            minter,
            max_response_bytes,
            token: RwLock::new(Arc::new(CachedToken::new(String::new().into(), 0).0)),
            exchange: Mutex::new(Exchange::Idle { due_ns: 0 }),
            refresh_failed: AtomicBool::new(false),
            usable_until: AtomicU64::new(0),
        }
    }

    /// Minted on demand (the token-exchange style's per-scope cell).
    pub(crate) fn on_demand(&self) -> bool {
        self.on_demand
    }

    /// No exchange is in flight.
    pub(crate) fn idle(&self) -> bool {
        matches!(
            *self
                .exchange
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            Exchange::Idle { .. }
        )
    }

    /// An on-demand cell holds a token it presents at wall-clock `now`.
    pub(crate) fn usable(&self, now: u64) -> bool {
        self.is_ready() && now < self.usable_until.load(Ordering::Acquire)
    }

    fn current(&self) -> Arc<CachedToken> {
        self.token
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Ready once the first mint has populated a non-empty token (the `ready` fact).
    pub(crate) fn is_ready(&self) -> bool {
        !self.current().token.expose_secret().is_empty()
    }

    /// Present the cached token for a request at wall-clock `now` (epoch seconds), through `f`
    /// (so the borrow of the cached value never escapes the read).
    pub(crate) fn read<T>(&self, now: u64, f: impl FnOnce(Read<'_>) -> T) -> T {
        let tok = self.current();
        // ON DEMAND: a token past its use is not presented; the request arms the next exchange
        // (due at once, when none is in flight) and waits for it.
        if self.on_demand && !self.usable(now) {
            if let Exchange::Idle { due_ns } = &mut *self
                .exchange
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                *due_ns = 0;
            }
            return f(Read::Wait);
        }
        if tok.token.expose_secret().is_empty() {
            return f(Read::Wait);
        }
        if now >= tok.expires_at && self.refresh_failed.load(Ordering::Acquire) {
            return f(Read::Wait);
        }
        match tok.header() {
            Some(h) => f(Read::Header(h)),
            None => f(Read::Nothing),
        }
    }

    /// Advance the exchange at tick-clock `now_ns`: start one when due, read what arrived, finish it.
    /// Answers when the cell next wants a tick, and what happened.
    pub(crate) fn tick(&self, now_ns: u64, wire: Option<&dyn Wire>) -> (u64, Option<Report>) {
        let mut ex = self
            .exchange
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Exchange::Idle { due_ns } = *ex {
            if now_ns < due_ns {
                return (due_ns, None);
            }
            let Some(wire) = wire else {
                // No need was granted: nothing can mint. Say so once per retry period.
                *ex = Exchange::Idle {
                    due_ns: now_ns + MIN_SLEEP_SECS * NS,
                };
                return self.failed(
                    &mut ex,
                    now_ns,
                    "token endpoint request failed: no connection was granted for the token endpoint"
                        .to_string(),
                );
            };
            let req = match self.minter.request(now_epoch()) {
                Ok(r) => r,
                Err(e) => return self.failed(&mut ex, now_ns, e),
            };
            match wire.open(&req, MINT_DEADLINE_SECS * 1000) {
                Ok(conn) => {
                    *ex = Exchange::InFlight {
                        conn,
                        started_ns: now_ns,
                        status: None,
                        body: Vec::new(),
                    }
                }
                Err(e) => {
                    return self.failed(
                        &mut ex,
                        now_ns,
                        format!("token endpoint request failed: {}", conn_cause(e)),
                    )
                }
            }
        }
        let Some(wire) = wire else {
            return (now_ns + IN_FLIGHT_POLL_NS, None);
        };
        let Exchange::InFlight {
            conn,
            started_ns,
            status,
            body,
        } = &mut *ex
        else {
            return (now_ns + IN_FLIGHT_POLL_NS, None);
        };
        let conn = *conn;
        let mut buf = [0_u8; 16 * 1024];
        let finished = loop {
            if now_ns.saturating_sub(*started_ns) >= MINT_DEADLINE_SECS * NS {
                break Err(
                    "token endpoint response was not read before the mint deadline; refusing to \
                     parse a partial token response"
                        .to_string(),
                );
            }
            match wire.read(conn, &mut buf) {
                Ok(got) => {
                    if got.status.is_some() {
                        *status = got.status;
                    }
                    if got.kind == PieceKind::Body {
                        body.extend_from_slice(&buf[..got.len]);
                        if body.len() > self.max_response_bytes {
                            break Err(format!(
                                "token endpoint response exceeded the {}-byte cap; refusing to \
                                 parse a truncated token response",
                                self.max_response_bytes
                            ));
                        }
                    }
                    if got.kind == PieceKind::Completion || (got.kind == PieceKind::Body && got.end)
                    {
                        break Ok((status.unwrap_or(0), std::mem::take(body)));
                    }
                }
                Err(ConnError::Pending) => return (now_ns + IN_FLIGHT_POLL_NS, None),
                Err(ConnError::Closed) if status.is_some() && !body.is_empty() => {
                    break Ok((status.unwrap_or(0), std::mem::take(body)))
                }
                Err(ConnError::Closed) => {
                    break Err(
                        "token endpoint connection failed mid-response; refusing to parse \
                               a partial token response"
                            .to_string(),
                    )
                }
                Err(e) => break Err(format!("token endpoint request failed: {}", conn_cause(e))),
            }
        };
        wire.close(conn);
        match finished.and_then(|(status, body)| parse_response(status as u16, &body, now_epoch()))
        {
            // A 200 with an EMPTY access_token must be treated as a (retryable) failure, not stored:
            // an empty token collides with the pre-first-mint sentinel, so `ready` would stay false
            // forever AND the per-request call would emit no auth header — a permanent wedge with no
            // self-healing. Retry at MIN_SLEEP instead, exactly like a mint error.
            Ok((fresh, _)) if fresh.token.expose_secret().is_empty() => {
                self.refresh_failed.store(true, Ordering::Release);
                let due = if self.on_demand {
                    u64::MAX
                } else {
                    now_ns + MIN_SLEEP_SECS * NS
                };
                *ex = Exchange::Idle { due_ns: due };
                (due, Some(Report::EmptyToken))
            }
            Ok((fresh, invalid)) => {
                let now = now_epoch();
                let ahead = next_refresh_secs(fresh.expires_at, now);
                // An on-demand token is presented until a scheduled style would refresh it, and no
                // exchange is due until a request finds it past that.
                let due = if self.on_demand {
                    u64::MAX
                } else {
                    now_ns + ahead * NS
                };
                *self
                    .token
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Arc::new(fresh);
                if self.on_demand {
                    self.usable_until
                        .store(now.saturating_add(ahead), Ordering::Release);
                }
                self.refresh_failed.store(false, Ordering::Release);
                *ex = Exchange::Idle { due_ns: due };
                (
                    due,
                    Some(if invalid {
                        Report::TokenInvalidBytes
                    } else {
                        Report::Minted
                    }),
                )
            }
            Err(e) => self.failed(&mut ex, now_ns, e),
        }
    }

    /// A failed mint: keep serving whatever token is current, and retry at `MIN_SLEEP_SECS` (an
    /// on-demand cell retries when a request next arms it).
    fn failed(&self, ex: &mut Exchange, now_ns: u64, e: String) -> (u64, Option<Report>) {
        self.refresh_failed.store(true, Ordering::Release);
        let due = if self.on_demand {
            u64::MAX
        } else {
            now_ns + MIN_SLEEP_SECS * NS
        };
        *ex = Exchange::Idle { due_ns: due };
        (due, Some(Report::MintFailed(e)))
    }
}

/// The cause a connection refusal names — never the URL (it can carry query/secret material).
fn conn_cause(e: ConnError) -> &'static str {
    match e {
        ConnError::Pending => "not ready",
        ConnError::Timeout => "timed out",
        ConnError::Closed => "connection closed",
        ConnError::NotOwner => "connection not owned",
        ConnError::UndeclaredNeed => "no need declared for the token endpoint",
        ConnError::Refused => "refused",
        ConnError::Fault => "fault",
        ConnError::Unarmed => "not armed",
        ConnError::CredentialUnavailable => "credential unavailable",
    }
}

#[cfg(test)]
#[path = "../tests/mint_tests.rs"]
pub(crate) mod tests;
