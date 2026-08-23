// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The EGRESS family of the plane host-vtable, wired over busbar-core's REAL guarded transport.
//!
//! The host OWNS every outbound byte. A plane never holds a client, a socket, a resolver, or a
//! credential in plaintext; it holds an opaque [`EgressId`] and asks the host to open, pump, write
//! and close. That is the whole point of routing egress through this seam: the SSRF resolve-then-pin
//! ([`crate::net_guard`]), the SPKI observation, the mTLS client-identity, the breaker and the meter
//! are all ONE chokepoint the host controls, applied identically whatever the plane is dispatching.
//!
//! ## What is wired here, and what is a faithful Phase-2 note
//!
//! * [`EgressKind::Http`] — FULLY wired for the request/READ round trip: the outbound request is
//!   built from the [`EgressDesc`] outbound tail (the `verb`, the packed header set, and the one-shot
//!   request `body`), the credential is INJECTED host-side (the resolved credential the plane named by
//!   ref, never plaintext the plane held — see [`inject_credential`]), then resolve-then-pin over
//!   [`crate::net_guard::resolve_and_pin_async`], a per-hop PINNED client (the a2a lesson — a pooled
//!   client re-resolves and reopens the DNS-rebind window, so a governed hop pins the address and
//!   refuses a second lookup), the post-connect observed peer identity handed back in the
//!   [`EgressHead`], a background streaming task that pumps `resp.chunk().await` into a bounded
//!   channel, and an arena [`Closer`](super::scope::DispatchScope::register_egress) that tears the
//!   whole thing down on close / dispatch-drop / cancellation.
//! * [`EgressKind::Http`] STREAMED request-body duplex ([`egress_write`]) — a Phase-2 note. The
//!   one-shot request body rides [`EgressDesc::body_ptr`] at open; a CLIENT-STREAMED (chunk-by-chunk)
//!   request body still needs HTTP/2 `Body::wrap_stream`, so `egress_write` stays `Unsupported` for
//!   the HTTP kind.
//! * [`EgressKind::RawConn`] / [`EgressKind::Subprocess`] — faithful Phase-2 notes (see
//!   [`egress_open`]). The governance path is identical; only the channel SHAPE differs (a pinned raw
//!   socket, a governed `tokio::process`), and each is a large wiring of its own.
//!
//! ## The streaming poll seam maps onto the a2a `chunk().await` model
//!
//! The design's poll seam (`Chunk | Pending | End | Cancelled | Err`) is the INVERSION of
//! `a2a::transport::post_stream`'s `on_chunk -> Continue/Stop` callback: instead of the host calling
//! back per chunk, the plane calls [`egress_poll`] per chunk. The background task's "emit this chunk"
//! is a bounded-channel `send` (backpressure = the a2a `Continue`); a closed channel or a `Stop`
//! notify is the a2a `Stop`. Mapped onto the ABI's [`StatusClass`]:
//!
//! | design       | ABI                                   |
//! |---|---|
//! | `Chunk(n)`   | `Ok`, `out_written = n > 0`           |
//! | `End` (EOF)  | `Ok`, `out_written = 0`               |
//! | `Cancelled`  | `Gone` (id closed / reclaimed)        |
//! | `Err`        | `Fault`                               |
//!
//! `Pending` collapses into a BLOCKING per-chunk `recv`: each [`egress_poll`] returns the next
//! network chunk or EOF, so a crossing happens per NETWORK CHUNK — never per token.

use super::scope::EgressFaultDetail;
use super::{recover, HostState};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::pod::EgressFault;
use busbar_plugin::hot::pod::POD_VERSION;
use busbar_plugin::hot::{
    EgressDesc, EgressFailClass, EgressHead, EgressId, EgressKind, EgressOpen, PipeId, StatusClass,
};
use busbar_plugin::read_sized_field;
use std::collections::HashMap;
use std::collections::VecDeque;
use std::mem::MaybeUninit;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, LazyLock, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// One governed hop's end-to-end ceiling. Bounds `send()` so a wedged upstream cannot pin the
/// streaming task forever. Phase 2 derives this from the App's resolved upstream limits
/// ([`crate::state::UpstreamClientSettings`]); the scaffold uses a fixed, conservative ceiling.
const EGRESS_TIMEOUT: Duration = Duration::from_secs(30);

/// How many network chunks the streaming task may run ahead of the plane's polling. Bounded so a
/// fast upstream and a slow plane apply real backpressure (the send parks) rather than buffering an
/// upstream-chosen amount of memory — the channel analogue of the a2a `on_chunk` cadence.
const CHUNK_CHANNEL_DEPTH: usize = 16;

// ── The host's allowlist-scope stance, read off `EgressDesc::allowlist_scope`. ──────────────────
// `allowlist_scope` is "the host-defined allowlist scope this egress is checked against" — so the
// host, not the plane, decides whether a scope may reach a private/loopback or plaintext endpoint.
// These convention bits are read directly; resolving the scope id against operator config is not yet
// wired. The guard stays FAIL-CLOSED by default: a scope of 0 reaches neither.

/// This allowlist scope permits private / loopback / CGNAT addresses (cloud-metadata stays refused —
/// that is the guard, not a policy the scope can speak for; see [`crate::net_guard`]).
const SCOPE_ALLOW_PRIVATE: u32 = 1 << 0;
/// This allowlist scope permits a plaintext `http://` endpoint.
const SCOPE_ALLOW_PLAINTEXT: u32 = 1 << 1;

/// A message the background streaming task sends the plane's poller, one per network event.
enum ChunkMsg {
    /// One network chunk of response body.
    Data(Vec<u8>),
    /// The stream ended cleanly (`resp.chunk()` returned `None`).
    End,
    /// The stream failed mid-body; carries the flattened cause for the log.
    Err(String),
}

/// The connect outcome the streaming task reports back to [`egress_open`] BEFORE any body is pumped.
enum HeadMsg {
    /// Connected: the observed status, the observed peer identity (empty on a plaintext hop), and the
    /// packed response headers the plane classifies on (content-type + Location).
    Ok {
        status: u16,
        spki: Vec<u8>,
        resp_headers: Vec<u8>,
    },
    /// The resolve-then-pin guard refused the hop (SSRF / scheme / metadata).
    Refused(String),
    /// The transport failed before a response head arrived. Carries the neutral CLASS (connect vs io
    /// vs host-fault) and the flattened cause, so the plane reproduces its own failover taxonomy.
    Fault {
        class: EgressFailClass,
        cause: String,
    },
}

/// One open governed HTTP egress the host owns end to end. The plane holds only its [`EgressId`].
struct HttpEgress {
    /// The receiver end of the bounded chunk channel; `None` once closed. Behind a `Mutex` because
    /// [`egress_poll`] holds only a shared `&HttpEgress` (via the registry) yet must `recv`.
    chunks: Mutex<Option<Receiver<ChunkMsg>>>,
    /// Bytes from a network chunk larger than the caller's buffer, served across subsequent polls so
    /// a crossing is bounded by the caller's `buf_cap` without dropping a byte.
    pending: Mutex<VecDeque<u8>>,
    /// Set once the stream has reached EOF / erred, so a poll after the end reads `Ok(0)` rather than
    /// blocking on a dead channel.
    ended: Mutex<bool>,
    /// The teardown signal: notified on close so a task parked in `chunk().await` unblocks promptly.
    stop: Arc<tokio::sync::Notify>,
    /// The streaming task's thread handle, joined on close; `None` once joined (idempotent).
    join: Mutex<Option<JoinHandle<()>>>,
    /// The observed peer identity bytes, kept alive HERE so the [`EgressHead::observed_spki_ptr`]
    /// handed back at open stays valid for as long as the egress is open (the plane may read it after
    /// `egress_open` returns). Empty on a plaintext hop.
    observed_spki: Vec<u8>,
    /// The packed response-header records (content-type + Location) the plane classifies on, kept alive
    /// HERE for the same reason `observed_spki` is: the [`EgressHead::resp_headers_ptr`] handed back at
    /// open borrows these and the plane reads them after `egress_open` returns.
    resp_headers: Vec<u8>,
}

impl HttpEgress {
    /// Serve up to `cap` bytes into `buf`, draining `pending` first and then one network chunk.
    /// Blocks for the next chunk (the `Pending`-collapse), returns `Ok(0)` at EOF.
    ///
    /// # Safety
    /// `buf`/`cap` must describe a live writable range for the call (ABI discipline).
    unsafe fn poll(&self, buf: *mut u8, cap: usize) -> (StatusClass, usize) {
        if buf.is_null() || cap == 0 {
            return (StatusClass::Refused, 0);
        }
        // Serve any buffered remainder first — never block while bytes are already in hand.
        {
            let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
            if !pending.is_empty() {
                return (StatusClass::Ok, drain_into(&mut pending, buf, cap));
            }
        }
        if *self.ended.lock().unwrap_or_else(|e| e.into_inner()) {
            return (StatusClass::Ok, 0); // EOF: clean end of stream.
        }
        // Block for the next network chunk. The receiver is taken under the lock only long enough to
        // recv on it, so close (which takes the `Option`) races cleanly to `Gone`.
        let msg = {
            let guard = self.chunks.lock().unwrap_or_else(|e| e.into_inner());
            let Some(rx) = guard.as_ref() else {
                return (StatusClass::Gone, 0); // closed / reclaimed underneath us.
            };
            rx.recv()
        };
        match msg {
            Ok(ChunkMsg::Data(bytes)) => {
                let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
                pending.extend(bytes);
                (StatusClass::Ok, drain_into(&mut pending, buf, cap))
            }
            Ok(ChunkMsg::End) | Err(_) => {
                *self.ended.lock().unwrap_or_else(|e| e.into_inner()) = true;
                (StatusClass::Ok, 0)
            }
            Ok(ChunkMsg::Err(reason)) => {
                tracing::debug!(target: "busbar::plane_host::egress", %reason, "egress stream failed mid-body");
                *self.ended.lock().unwrap_or_else(|e| e.into_inner()) = true;
                (StatusClass::Fault, 0)
            }
        }
    }

    /// Tear the egress down: signal the task, drop the receiver (unblocks a task parked on a full
    /// send), and join the thread. Idempotent — a second call finds the handle already taken.
    fn close(&self) {
        self.stop.notify_one();
        // Dropping the receiver makes a task blocked on a full channel `send` observe a disconnect
        // and break, complementing the `stop` notify that unblocks a task parked in `chunk().await`.
        let _ = self.chunks.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(handle) = self.join.lock().unwrap_or_else(|e| e.into_inner()).take() {
            let _ = handle.join();
        }
    }
}

/// Copy `min(cap, pending.len())` bytes off the FRONT of `pending` into `buf`, returning the count.
///
/// # Safety
/// `buf`/`cap` must describe a live writable range for the call.
unsafe fn drain_into(pending: &mut VecDeque<u8>, buf: *mut u8, cap: usize) -> usize {
    let n = cap.min(pending.len());
    // SAFETY: caller's contract — `buf` is writable for `cap` bytes; we write only `n <= cap`.
    let out = unsafe { std::slice::from_raw_parts_mut(buf, n) };
    for slot in out.iter_mut() {
        *slot = pending.pop_front().expect("n <= pending.len()");
    }
    n
}

/// The PROCESS-WIDE registry of open egresses, keyed by a GLOBALLY unique id.
///
/// Global (not per-[`DispatchScope`](super::scope::DispatchScope)) because two concurrent dispatches
/// each allocate arena-local ids from `1`, which would collide in one map — so the id the plane holds
/// is minted from a process atomic and the backend lives here. The arena still owns RECLAIM: a
/// `Closer` registered per open removes+closes this entry when the dispatch ends, so a dropped
/// dispatch cannot leak a socket or a streaming thread.
static REGISTRY: LazyLock<Mutex<HashMap<u64, Arc<HttpEgress>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// The next globally-unique egress id. `0` is the reserved [`EgressId::NONE`] sentinel, so ids
/// start at `1`.
static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn registry() -> std::sync::MutexGuard<'static, HashMap<u64, Arc<HttpEgress>>> {
    REGISTRY.lock().unwrap_or_else(|e| e.into_inner())
}

/// Remove an egress from the registry and close it. Idempotent: the map remove elects exactly one
/// closer (the explicit [`egress_close`] or the arena `Closer`); the loser finds nothing.
fn close_and_remove(id: u64) -> bool {
    let entry = registry().remove(&id);
    match entry {
        Some(egress) => {
            egress.close();
            true
        }
        None => false,
    }
}

/// Classify a transport error into the neutral [`EgressFailClass`] the plane fails over on: a connect/
/// TLS/redirect-follow failure is `Connect` (the "unreachable" class), anything else that reached the
/// wire is `Io`. The plane maps this onto its own taxonomy (the mcp `Unreachable` vs `Io` split).
fn classify_transport_error(err: &reqwest::Error) -> EgressFailClass {
    if err.is_connect() {
        EgressFailClass::Connect
    } else {
        EgressFailClass::Io
    }
}

/// The observed peer identity: the SubjectPublicKeyInfo PIN of the leaf certificate the
/// (already-verified) TLS handshake produced, in the ONE canonical spelling
/// (`sha256/<base64>` — [`super::spki::pin`]). Empty on a plaintext hop (nothing was proved) and
/// empty where the certificate cannot be walked — reported honestly as absent rather than softened
/// into a pass, exactly as `a2a::transport::peer_spki_of` reports `None`.
///
/// This is the SAME pin the plane would compute itself: the host and the plane share one DER walk
/// (lifted to [`super::spki`]), so a governed hop hands back the string the plane's own spelling
/// yields, byte for byte — and it survives a certificate renewal because it pins the KEY, not the
/// leaf bytes.
fn observed_identity(resp: &reqwest::Response) -> Vec<u8> {
    let Some(info) = resp.extensions().get::<reqwest::tls::TlsInfo>() else {
        return Vec::new();
    };
    let Some(der) = info.peer_certificate() else {
        return Vec::new();
    };
    match super::spki::pin(der) {
        Ok(pin) => pin.into_bytes(),
        Err(_) => Vec::new(), // an unwalkable certificate proves no pin — honestly absent.
    }
}

/// Build the [`crate::net_guard::GuardPolicy`] for a hop from the host's allowlist-scope stance. Only
/// the private/plaintext arms are the scope's to relax; the cloud-metadata and obfuscated-encoding
/// refusals are the guard and no scope can speak for them.
fn guard_policy(scope: u32) -> crate::net_guard::GuardPolicy {
    crate::net_guard::GuardPolicy {
        allow_private: scope & SCOPE_ALLOW_PRIVATE != 0,
        allow_plaintext: scope & SCOPE_ALLOW_PLAINTEXT != 0,
        // Unused by the resolve-then-pin path (it judges names and addresses); the streaming read is
        // bounded by `stop` + the client timeout, not a fixed body cap.
        max_redirects: 0,
        max_body_bytes: usize::MAX,
        timeout: EGRESS_TIMEOUT,
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The outbound-request spec built from the EgressDesc DATA tail (verb / headers / body), plus the
// host-side credential INJECTION. The plane sends only neutral data + an opaque credential ref; the
// host resolves the ref to the plaintext it owns and places it — the secret is read here, never off
// a plane POD.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A fully-built outbound request: the method, the forwarded header set (the injected credential
/// header, if any, is already among these), and the one-shot request body.
struct ReqSpec {
    /// The request method/verb (defaults to `GET` when the plane sent none).
    method: reqwest::Method,
    /// The header set the host forwards verbatim, plus the injected credential header (if any).
    headers: Vec<(String, String)>,
    /// The one-shot request body (empty ⇒ a bodyless request).
    body: Vec<u8>,
}

/// Build the [`ReqSpec`] from the [`EgressDesc`] outbound tail, reading each tail field only behind
/// the sized-struct guard (a sender that predates the tail yields a bodyless `GET`).
fn build_req_spec(d: &EgressDesc) -> ReqSpec {
    let method = read_sized_field!(d, EgressDesc, verb_ptr)
        .zip(read_sized_field!(d, EgressDesc, verb_len))
        .and_then(|(ptr, len)| method_of(ptr, len))
        .unwrap_or(reqwest::Method::GET);
    let headers = match (
        read_sized_field!(d, EgressDesc, headers_ptr),
        read_sized_field!(d, EgressDesc, headers_len),
    ) {
        // SAFETY: a non-null `(headers_ptr, headers_len)` is a live borrowed range for the call (ABI).
        (Some(ptr), Some(len)) => unsafe { parse_headers(ptr, len) },
        _ => Vec::new(),
    };
    let body = match (
        read_sized_field!(d, EgressDesc, body_ptr),
        read_sized_field!(d, EgressDesc, body_len),
    ) {
        // SAFETY: a non-null `(body_ptr, body_len)` is a live borrowed range for the call (ABI).
        (Some(ptr), Some(len)) if !ptr.is_null() && len != 0 => {
            unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
        }
        _ => Vec::new(),
    };
    ReqSpec {
        method,
        headers,
        body,
    }
}

/// Pack the RESPONSE headers the plane classifies on into the neutral name/value record format (`u32
/// name_len` LE, name, `u32 value_len` LE, value) — the SAME packing the request header set uses, so
/// the plane decodes both with one parser. `content-type` is surfaced whenever present (the plane keys
/// SSE-vs-JSON on it); `Location` is surfaced whenever present (a redirect the plane refuses). Values
/// are surfaced VERBATIM — the host lower-cases and interprets nothing; that stays plane-side.
fn pack_response_headers(resp: &reqwest::Response) -> Vec<u8> {
    let mut pairs: Vec<(&str, String)> = Vec::new();
    for (name, header) in [
        ("content-type", reqwest::header::CONTENT_TYPE),
        ("location", reqwest::header::LOCATION),
    ] {
        if let Some(value) = resp.headers().get(&header).and_then(|v| v.to_str().ok()) {
            pairs.push((name, value.to_string()));
        }
    }
    pack_header_records(&pairs)
}

/// Pack `(name, value)` header pairs into length-prefixed records: `u32 name_len` (LE), name bytes,
/// `u32 value_len` (LE), value bytes — the inverse of [`parse_headers`].
fn pack_header_records(pairs: &[(&str, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in pairs {
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// Parse the request VERB bytes into a [`reqwest::Method`], or `None` (⇒ default `GET`) when absent or
/// malformed.
fn method_of(ptr: *const u8, len: usize) -> Option<reqwest::Method> {
    if ptr.is_null() || len == 0 {
        return None;
    }
    // SAFETY: `(ptr, len)` is a live borrowed range for the call (ABI borrow discipline).
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    reqwest::Method::from_bytes(bytes).ok()
}

/// Parse the packed header set: a sequence of records, each `u32 name_len` (LE), `name_len` name
/// bytes, `u32 value_len` (LE), `value_len` value bytes. Malformed / truncated input stops parsing
/// and returns what was read so far — fail-safe (a bad header record is dropped, never guessed).
///
/// # Safety
/// `(ptr, len)` MUST describe a live, initialized byte range for the call.
unsafe fn parse_headers(ptr: *const u8, len: usize) -> Vec<(String, String)> {
    if ptr.is_null() || len == 0 {
        return Vec::new();
    }
    // SAFETY: caller's contract — `(ptr, len)` is a live borrowed range.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let mut out = Vec::new();
    let mut i = 0usize;
    while let Some(name_len) = read_u32(bytes, &mut i) {
        let Some(name) = read_str(bytes, &mut i, name_len) else {
            break;
        };
        let Some(value_len) = read_u32(bytes, &mut i) else {
            break;
        };
        let Some(value) = read_str(bytes, &mut i, value_len) else {
            break;
        };
        out.push((name, value));
    }
    out
}

/// Read a little-endian `u32` at `*i`, advancing `*i` by 4; `None` when fewer than 4 bytes remain.
fn read_u32(bytes: &[u8], i: &mut usize) -> Option<usize> {
    let end = i.checked_add(4)?;
    let word = bytes.get(*i..end)?;
    *i = end;
    Some(u32::from_le_bytes(word.try_into().ok()?) as usize)
}

/// Read `n` bytes at `*i` as a lossy UTF-8 string, advancing `*i` by `n`; `None` when fewer than `n`
/// bytes remain.
fn read_str(bytes: &[u8], i: &mut usize, n: usize) -> Option<String> {
    let end = i.checked_add(n)?;
    let slice = bytes.get(*i..end)?;
    *i = end;
    Some(String::from_utf8_lossy(slice).into_owned())
}

/// INJECT the resolved credential into `spec.headers`, host-side. The plane named the credential by an
/// opaque `credential_ref` and its PLACEMENT (header name + auth-scheme prefix) as neutral data; the
/// host resolves the ref to the plaintext it OWNS (see [`super::creds`]) and appends
/// `{header_name}: {scheme}{secret}`. Nothing happens when the plane named no credential, no header,
/// or the ref is unknown/expired (fail-closed — a stale ref injects nothing rather than a wrong token).
/// The plaintext is read HERE and never crosses back to the plane.
fn inject_credential(d: &EgressDesc, spec: &mut ReqSpec) {
    if d.credential_ref == 0 {
        return;
    }
    let header_name = match (
        read_sized_field!(d, EgressDesc, cred_header_ptr),
        read_sized_field!(d, EgressDesc, cred_header_len),
    ) {
        // SAFETY: a non-null `(cred_header_ptr, cred_header_len)` is a live borrowed range (ABI).
        (Some(ptr), Some(len)) if !ptr.is_null() && len != 0 => unsafe {
            borrowed_string(ptr, len)
        },
        _ => return, // no placement header → nothing to inject the credential into.
    };
    let scheme = match (
        read_sized_field!(d, EgressDesc, cred_scheme_ptr),
        read_sized_field!(d, EgressDesc, cred_scheme_len),
    ) {
        // SAFETY: a non-null `(cred_scheme_ptr, cred_scheme_len)` is a live borrowed range (ABI).
        (Some(ptr), Some(len)) if !ptr.is_null() && len != 0 => unsafe {
            borrowed_string(ptr, len)
        },
        _ => String::new(),
    };
    let now = crate::store::now_ms() / 1_000;
    let Some(secret) = super::creds::resolve(d.credential_ref, now) else {
        return; // unknown / expired ref → inject nothing (fail-closed).
    };
    let value = format!("{scheme}{}", String::from_utf8_lossy(&secret));
    spec.headers.push((header_name, value));
}

/// Read a borrowed `(ptr, len)` byte range into an owned lossy-UTF-8 `String`.
///
/// # Safety
/// `(ptr, len)` MUST describe a live, initialized byte range for the call.
unsafe fn borrowed_string(ptr: *const u8, len: usize) -> String {
    // SAFETY: caller's contract — `(ptr, len)` is a live borrowed range.
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    String::from_utf8_lossy(bytes).into_owned()
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// The four vtable slots. Each recovers the HostState FIRST, runs inside a MANDATORY catch_unwind,
// and FAILS CLOSED (`Fault` / `Gone` / `Refused`) on a caught panic — never a permissive value.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Open a governed egress. On `Ok` writes an [`EgressOpen`]; on any refusal/fault the out-param is
/// left untouched (init-only-on-Ok).
pub(crate) fn egress_open(
    host: HostCtx,
    desc: *const EgressDesc,
    out: *mut MaybeUninit<EgressOpen>,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let state: &HostState = unsafe { recover(host) };
        if desc.is_null() || out.is_null() {
            return StatusClass::Refused;
        }
        // SAFETY: a non-null `desc` is a live, initialized `EgressDesc` for the call (ABI).
        let d = unsafe { &*desc };

        match d.kind {
            EgressKind::Http => open_http(state, d, out),
            // Phase 2: a governed RAW duplex byte channel. It SHARES the subprocess pipe shape
            // (`pipe_read`/`pipe_write` keyed by a `PipeId`); only the channel differs — a pinned
            // socket rather than a child's stdio. The governance path is identical (resolve-then-pin,
            // SPKI, mTLS, breaker, meter); joining it is append-only (no ABI change). Refused honestly.
            EgressKind::RawConn => StatusClass::Unsupported,
            // A governed child process, its stdin/stdout the duplex `PipeId` — spawned under the HOST
            // command allowlist. See [`super::pipe`]; the plane frames on top of the raw byte channel.
            EgressKind::Subprocess => super::pipe::open_subprocess(state, d, out),
        }
    }))
    .unwrap_or(StatusClass::Fault)
}

/// The HTTP open: resolve-then-pin, connect over a pinned per-hop client, observe the peer identity,
/// spawn the streaming task, register the arena closer, and hand back the [`EgressOpen`].
fn open_http(state: &HostState, d: &EgressDesc, out: *mut MaybeUninit<EgressOpen>) -> StatusClass {
    // The borrowed target URL bytes.
    if d.target_ptr.is_null() || d.target_len == 0 {
        return StatusClass::Refused;
    }
    // SAFETY: `(target_ptr, target_len)` is a live borrowed range for the call (ABI discipline).
    let url_bytes = unsafe { std::slice::from_raw_parts(d.target_ptr, d.target_len) };
    let Ok(url) = std::str::from_utf8(url_bytes) else {
        return StatusClass::Refused;
    };
    let url = url.to_string();
    // Kept for the fault surface: the streaming thread MOVES `url`, so a separate copy stays here to be
    // surfaced (separately from the cause) if the hop fails.
    let fault_url = url.clone();

    let policy = guard_policy(d.allowlist_scope);

    // Strict-recognise the URL and judge its scheme up front, so a malformed / non-http(s) /
    // inadmissible-plaintext target fails fast without spawning a thread.
    let (https, host_name, port, _path) = match crate::net_guard::split_url(&url) {
        Ok(parts) => parts,
        Err(refusal) => {
            stash_fault(
                state,
                EgressFailClass::Refused,
                0,
                refusal.to_string(),
                &fault_url,
            );
            return StatusClass::Refused;
        }
    };
    if let Err(refusal) = crate::net_guard::judge_scheme(&url, https, policy) {
        stash_fault(
            state,
            EgressFailClass::Refused,
            0,
            refusal.to_string(),
            &fault_url,
        );
        return StatusClass::Refused;
    }

    // THE mTLS CLIENT IDENTITY, resolved host-side from the opaque ref the plane named — the plane
    // never sees a key. An unknown/zero ref resolves to `None`, which is the honest mTLS outcome: the
    // hop presents no certificate and an mTLS peer closes the handshake itself rather than the host
    // forging one (the a2a `presenting`/no-identity posture, restated at the seam). See
    // [`super::identity`].
    let identity = super::identity::resolve(d.client_identity_ref);
    // BUSBAR'S OWN END OF THE HANDSHAKE, decided HERE — before the streaming thread MOVES `identity`.
    // `1` when a client certificate is carried into the handshake (offered if the peer asks), `0`
    // when none was resolved. A fact about the connection this hop opens, handed back on the head.
    let client_identity_offered = u8::from(identity.is_some());

    // Build the outbound request from the neutral DATA tail (verb / packed headers / body), then
    // INJECT the credential the plane named by ref — the host resolves the ref to the plaintext it
    // owns (see `super::creds`) and places it under the plane-supplied header/scheme, so the secret
    // is read HERE, never off a plane POD. The sized-struct guard means a sender that predates the
    // tail leaves these null → a bodyless GET with no injected credential (the pre-enrichment shape).
    let mut spec = build_req_spec(d);
    inject_credential(d, &mut spec);

    let (head_tx, head_rx) = sync_channel::<HeadMsg>(1);
    let (chunk_tx, chunk_rx) = sync_channel::<ChunkMsg>(CHUNK_CHANNEL_DEPTH);
    let stop = Arc::new(tokio::sync::Notify::new());
    let stop_task = Arc::clone(&stop);

    // The streaming task owns its own current-thread runtime and the response for its whole life —
    // the response and the runtime NEVER cross a thread. It reports the connect head once, then
    // pumps chunks until EOF, error, or the `stop` notify.
    let join = std::thread::Builder::new()
        .name("busbar-egress".into())
        .spawn(move || {
            run_http_stream(
                &url, &host_name, port, https, policy, &spec, identity, &head_tx, &chunk_tx,
                &stop_task,
            );
        });
    let Ok(join) = join else {
        // Could not even spawn the streaming thread: a host-side fault, no cause from the wire.
        stash_fault(
            state,
            EgressFailClass::Fault,
            0,
            "governed egress could not start its streaming task".to_string(),
            &fault_url,
        );
        return StatusClass::Fault;
    };

    // Block for the connect head (or a bounded timeout so a wedged connect cannot pin the caller).
    let head = match head_rx.recv_timeout(EGRESS_TIMEOUT.saturating_add(Duration::from_secs(5))) {
        Ok(head) => head,
        Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {
            stop.notify_one();
            let _ = join.join();
            stash_fault(
                state,
                EgressFailClass::Io,
                0,
                "governed egress timed out waiting for the connect head".to_string(),
                &fault_url,
            );
            return StatusClass::Fault;
        }
    };
    let (status, spki, resp_headers) = match head {
        HeadMsg::Ok {
            status,
            spki,
            resp_headers,
        } => (status, spki, resp_headers),
        HeadMsg::Refused(reason) => {
            tracing::debug!(target: "busbar::plane_host::egress", %reason, "governed egress refused");
            let _ = join.join();
            // The guard refused the hop before a socket — surface the class + the guard's own reason
            // (the plane composes its refusal string over the neutral cause).
            stash_fault(state, EgressFailClass::Refused, 0, reason, &fault_url);
            return StatusClass::Refused;
        }
        HeadMsg::Fault { class, cause } => {
            tracing::debug!(target: "busbar::plane_host::egress", %cause, "governed egress faulted");
            let _ = join.join();
            stash_fault(state, class, 0, cause, &fault_url);
            return StatusClass::Fault;
        }
    };

    let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let egress = Arc::new(HttpEgress {
        chunks: Mutex::new(Some(chunk_rx)),
        pending: Mutex::new(VecDeque::new()),
        ended: Mutex::new(false),
        stop,
        join: Mutex::new(Some(join)),
        observed_spki: spki,
        resp_headers,
    });

    // The EgressHead borrows the backend's own SPKI + response-header bytes, which live until close — so
    // the pointers handed back stay valid while the plane holds the EgressOpen.
    let (spki_ptr, spki_len) = if egress.observed_spki.is_empty() {
        (std::ptr::null(), 0)
    } else {
        (egress.observed_spki.as_ptr(), egress.observed_spki.len())
    };
    let (rh_ptr, rh_len) = if egress.resp_headers.is_empty() {
        (std::ptr::null(), 0)
    } else {
        (egress.resp_headers.as_ptr(), egress.resp_headers.len())
    };
    let open = EgressOpen {
        size: std::mem::size_of::<EgressOpen>() as u32,
        version: POD_VERSION,
        _reserved: 0,
        id: EgressId(id),
        pipe: PipeId::NONE, // HTTP is not a duplex byte channel.
        head: EgressHead {
            size: std::mem::size_of::<EgressHead>() as u32,
            version: POD_VERSION,
            status_code: status,
            observed_spki_ptr: spki_ptr,
            observed_spki_len: spki_len,
            resp_headers_ptr: rh_ptr,
            resp_headers_len: rh_len,
            client_identity_offered,
            _reserved4: [0; 7],
        },
    };

    // Publish the backend, THEN register the arena closer, THEN write the out-param — so a plane that
    // reads the id can immediately find the backend, and the dispatch arena reclaims it on drop.
    registry().insert(id, Arc::clone(&egress));
    // The arena returns its own id; we ignore it and hand the plane the global id (see `REGISTRY`).
    let _ = state.scope.register_egress(Box::new(move || {
        close_and_remove(id);
    }));

    // SAFETY: `out` is non-null (checked) and writable for one `EgressOpen`; written only on Ok.
    unsafe {
        (*out).write(open);
    }
    StatusClass::Ok
}

/// The body of the streaming thread: resolve-then-pin, connect, report the head, pump chunks.
#[allow(clippy::too_many_arguments)]
fn run_http_stream(
    url: &str,
    host_name: &str,
    port: u16,
    https: bool,
    policy: crate::net_guard::GuardPolicy,
    spec: &ReqSpec,
    identity: Option<reqwest::Identity>,
    head_tx: &SyncSender<HeadMsg>,
    chunk_tx: &SyncSender<ChunkMsg>,
    stop: &tokio::sync::Notify,
) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = head_tx.send(HeadMsg::Fault {
                class: EgressFailClass::Fault,
                cause: format!("egress runtime: {e}"),
            });
            return;
        }
    };
    rt.block_on(async move {
        // THE GUARD: exactly one resolution, every answered address judged, the survivor pinned.
        let pin =
            match crate::net_guard::resolve_and_pin_async(host_name, port, https, policy).await {
                Ok(pin) => pin,
                Err(refusal) => {
                    let _ = head_tx.send(HeadMsg::Refused(refusal.to_string()));
                    return;
                }
            };
        // THE PINNED CLIENT, from the ONE shared core builder ([`crate::egress::build_pinned_client`]):
        // connects to the judged address, refuses a second lookup, follows no redirect (a 3xx is an
        // unguarded URL), reads the peer certificate off the verified handshake, and now carries the
        // canonical connection knobs (tcp_nodelay / connect_timeout / pool_idle_timeout) this path had
        // lacked. The mutual-TLS identity is resolved host-side from the plane's opaque ref — offering
        // it ASKS FOR NOTHING (presented only when the peer's `CertificateRequest` asks), and there is
        // no knob anywhere that turns verification off. The total deadline rides the REQUEST below, not
        // the client.
        let client = match crate::egress::build_pinned_client(
            host_name,
            pin.socket_addr(),
            Arc::new(crate::egress::RefuseSecondLookup),
            identity,
            &[],
        ) {
            Ok(client) => client,
            Err(e) => {
                let _ = head_tx.send(HeadMsg::Fault {
                    class: EgressFailClass::Fault,
                    cause: format!("egress client: {e}"),
                });
                return;
            }
        };
        // The outbound request: the plane's verb (default GET), its forwarded headers, and its
        // one-shot body. The credential header (if any) is already in `spec.headers` — injected
        // host-side from the resolved ref, so no plane-held plaintext reaches this builder. The total
        // deadline is applied here because the shared client carries none.
        let mut builder = client
            .request(spec.method.clone(), url)
            .timeout(EGRESS_TIMEOUT);
        for (name, value) in &spec.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if !spec.body.is_empty() {
            builder = builder.body(spec.body.clone());
        }
        let mut resp = match builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                // The real transport failure: classify it (connect vs io) FIRST (the connect verdict is
                // read off the original error), then strip the url and flatten the cause chain so the
                // cause is URL-FREE — the url is surfaced SEPARATELY, so a plane includes or strips it
                // as it chooses (mcp uses the url-free cause directly; a2a re-inserts the url). This is
                // exactly the `without_url()`-then-flatten the mcp transport does today.
                let class = classify_transport_error(&e);
                let e = e.without_url();
                let _ = head_tx.send(HeadMsg::Fault {
                    class,
                    cause: crate::egress::with_cause(&e),
                });
                return;
            }
        };
        let status = resp.status().as_u16();
        // READ THE CERTIFICATE BEFORE THE BODY — it belongs to THIS connection.
        let spki = observed_identity(&resp);
        // The RESPONSE HEADERS the plane classifies on, surfaced as neutral records — the host formats
        // none of them. `content-type` (SSE vs JSON) is surfaced always; `Location` only when present
        // (a redirect), so the plane can refuse the 3xx with the unguarded target's own location.
        let resp_headers = pack_response_headers(&resp);
        if head_tx
            .send(HeadMsg::Ok {
                status,
                spki,
                resp_headers,
            })
            .is_err()
        {
            return; // the opener went away before we connected; nothing to stream to.
        }

        // PUMP THE BODY, one network chunk per loop. `stop` (close / cancel) wins the race so a task
        // parked in `chunk().await` unblocks promptly rather than after the next byte.
        loop {
            tokio::select! {
                biased;
                () = stop.notified() => break,
                chunk = resp.chunk() => match chunk {
                    Ok(Some(bytes)) => {
                        // A blocking send on a full channel is the backpressure seam (the a2a
                        // `Continue` cadence); a disconnect means the plane closed — stop.
                        if chunk_tx.send(ChunkMsg::Data(bytes.to_vec())).is_err() {
                            break;
                        }
                    }
                    Ok(None) => {
                        let _ = chunk_tx.send(ChunkMsg::End);
                        break;
                    }
                    Err(e) => {
                        let _ = chunk_tx.send(ChunkMsg::Err(e.to_string()));
                        break;
                    }
                }
            }
        }
    });
}

/// Stash a neutral fault into the dispatch scope so a following `egress_fault` hands it to the plane.
fn stash_fault(state: &HostState, class: EgressFailClass, status: u16, cause: String, url: &str) {
    state.scope.stash_egress_fault(EgressFaultDetail {
        class,
        status,
        cause,
        url: url.to_string(),
    });
}

/// Copy `min(cap, bytes.len())` of `bytes` into `buf` (tolerating a null/zero slot), returning the
/// count copied.
///
/// # Safety
/// `buf`, when non-null, is a writable range of at least `cap` bytes for the call.
unsafe fn copy_capped(buf: *mut u8, cap: usize, bytes: &[u8]) -> usize {
    if buf.is_null() || cap == 0 {
        return 0;
    }
    let n = bytes.len().min(cap);
    // SAFETY: `bytes[..n]` is initialized and `buf[..n]` is writable (n ≤ cap, caller ABI).
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf, n) };
    n
}

/// Retrieve the neutral FAILURE detail of the last failed `egress_open` in this dispatch scope. Writes
/// an [`EgressFault`] header (class + status + the FULL cause/url lengths) and copies the flattened
/// cause bytes and the target url bytes into SEPARATE caller buffers. `Gone` when no fault is pending.
///
/// The cause and url are kept SEPARATE so a plane composes its own operator string — one keeps the url,
/// another strips it. The header carries the FULL lengths even when a buffer was too small, and in that
/// case the fault is LEFT stashed so the plane can re-call with a larger buffer (the read is not
/// destructive until it fits); a read that fit consumes it.
pub(crate) fn egress_fault(
    host: HostCtx,
    out: *mut MaybeUninit<EgressFault>,
    cause_buf: *mut u8,
    cause_cap: usize,
    url_buf: *mut u8,
    url_cap: usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let state: &HostState = unsafe { recover(host) };
        let Some(detail) = state.scope.take_egress_fault() else {
            return StatusClass::Gone; // no fault pending.
        };
        let cause_bytes = detail.cause.as_bytes();
        let url_bytes = detail.url.as_bytes();
        // SAFETY: caller's `(cause_buf, cause_cap)` / `(url_buf, url_cap)` are writable ranges (ABI).
        let cause_written = unsafe { copy_capped(cause_buf, cause_cap, cause_bytes) };
        let url_written = unsafe { copy_capped(url_buf, url_cap, url_bytes) };
        // If either did not fit, LEAVE the fault stashed so the plane can re-call with bigger buffers.
        let truncated = cause_written < cause_bytes.len() || url_written < url_bytes.len();
        if truncated {
            state.scope.stash_egress_fault(detail.clone());
        }
        let fault = EgressFault {
            size: std::mem::size_of::<EgressFault>() as u32,
            version: POD_VERSION,
            fail_class: detail.class,
            _reserved: 0,
            status_code: detail.status,
            _reserved2: 0,
            // The FULL lengths (not the capped written counts), so a plane detects truncation and
            // re-calls with a buffer sized to the header it just read.
            cause_len: cause_bytes.len() as u32,
            url_len: url_bytes.len() as u32,
        };
        // SAFETY: `out`, when non-null, is a writable/aligned `MaybeUninit<EgressFault>` for the call.
        unsafe { busbar_plugin::write_out(out, fault) };
        StatusClass::Ok
    }))
    .unwrap_or(StatusClass::Fault)
}

/// Pump readable bytes from a governed egress into the caller's buffer. Blocks for the next network
/// chunk; `Ok` with `out_written = 0` is a clean end of stream.
pub(crate) fn egress_poll(
    host: HostCtx,
    egress: EgressId,
    buf: *mut u8,
    buf_cap: usize,
    out_written: *mut usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state: &HostState = unsafe { recover(host) };
        if out_written.is_null() {
            return StatusClass::Refused;
        }
        let Some(handle) = registry().get(&egress.0).map(Arc::clone) else {
            return StatusClass::Gone; // unknown / already closed / reclaimed.
        };
        // SAFETY: caller's `buf`/`buf_cap` describe a live writable range (ABI discipline).
        let (class, written) = unsafe { handle.poll(buf, buf_cap) };
        if class == StatusClass::Ok {
            // SAFETY: `out_written` is non-null (checked) and writable for one `usize`.
            unsafe {
                *out_written = written;
            }
        }
        class
    }))
    .unwrap_or(StatusClass::Fault)
}

/// Write a request-body / duplex chunk to a governed egress.
///
/// Phase 2 for [`EgressKind::Http`]: the shipped hop is a bodyless streaming REQUEST, so there is no
/// client-streamed body to write — a duplex request body needs HTTP/2 `Body::wrap_stream` and a
/// method/body field on [`EgressDesc`] that the ABI does not yet carry. A known egress is answered
/// `Unsupported` (the capability is real but not wired for this kind); an unknown one is `Gone`.
pub(crate) fn egress_write(
    host: HostCtx,
    egress: EgressId,
    buf: *const u8,
    len: usize,
) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state: &HostState = unsafe { recover(host) };
        let _ = (buf, len);
        if registry().contains_key(&egress.0) {
            StatusClass::Unsupported
        } else {
            StatusClass::Gone
        }
    }))
    .unwrap_or(StatusClass::Fault)
}

/// Close a governed egress and reclaim it. Idempotent; also run by the arena `Closer` on
/// dispatch-drop / cancellation. `Ok` when this call closed it, `Gone` when it was already gone.
pub(crate) fn egress_close(host: HostCtx, egress: EgressId) -> StatusClass {
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: recovery invariant (see `super::recover`).
        let _state: &HostState = unsafe { recover(host) };
        if close_and_remove(egress.0) {
            StatusClass::Ok
        } else {
            StatusClass::Gone
        }
    }))
    .unwrap_or(StatusClass::Fault)
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// SAFE DRIVER WRAPPERS for the neutral fetch adapter (`crate::egress::seam`).
//
// busbar-core denies `unsafe` everywhere EXCEPT this audited `plane_host` FFI module. The fetch
// adapter that re-expresses `egress_poll` as the planes' existing buffered/streamed return types
// lives in `crate::egress` (a `#![deny(unsafe_code)]` module) and drives the egress slots through
// these wrappers — each does the raw out-param read / borrowed-bytes decode HERE and hands back only
// OWNED, fully-decoded values, so no raw pointer ever escapes to the seam. This keeps ALL egress-slot
// `unsafe` in the one sanctioned module while the neutral adapter (and the `Response`/`StreamHead`
// projection) stays plane-blind in `crate::egress`.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Map two host allowlist-scope bools onto the [`EgressDesc::allowlist_scope`] bit convention this
/// module reads. Exposed so the seam builds a desc without duplicating the bit values.
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn scope_bits(allow_private: bool, allow_plaintext: bool) -> u32 {
    let mut scope = 0u32;
    if allow_private {
        scope |= SCOPE_ALLOW_PRIVATE;
    }
    if allow_plaintext {
        scope |= SCOPE_ALLOW_PLAINTEXT;
    }
    scope
}

/// The fully-decoded connect head of a governed egress the seam adopts — every field OWNED, no
/// borrowed host pointer. The `peer_spki` / `location` / `content_type` strings are decoded HERE from
/// the borrowed head bytes; the plane composes its own return types over them.
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct OpenedHead {
    /// The opaque egress handle the seam polls the body off and closes.
    pub id: EgressId,
    /// The observed status/response code.
    pub status: u16,
    /// The observed peer SPKI pin (`sha256/…`), or `None` on a plaintext hop / an unwalkable cert.
    /// Decoded from the SAME bytes `crate::plane_host::spki::pin` produced, so it is byte-identical to
    /// the pin a plane's own `peer_spki_of` would compute (they share that one function).
    pub peer_spki: Option<String>,
    /// The response `Location`, verbatim, when the head surfaced one (a redirect).
    pub location: Option<String>,
    /// The response `content-type`, verbatim, when the head surfaced one.
    pub content_type: Option<String>,
    /// Busbar's own end of the handshake: whether a client identity was carried into the TLS
    /// handshake (offered if the peer asked). See [`EgressHead::client_identity_offered`].
    pub client_identity_offered: bool,
}

/// A fully-decoded egress fault the seam composes its own operator string over — the class, the status,
/// and the flattened CAUSE and TARGET-url kept SEPARATE (one plane keeps the url, another strips it),
/// exactly as [`egress_fault`] hands them across the ABI.
// Read by the plane fetch converters (sub-commits 3/4) that compose an operator string over the
// neutral fault; unread until then, so allow it unconditionally on this scaffold.
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
#[allow(dead_code)]
#[derive(Debug)]
pub(crate) struct EgressFaultInfo {
    pub class: EgressFailClass,
    pub status: u16,
    pub cause: String,
    pub url: String,
}

/// The outcome of driving [`egress_open`] over a host: the adopted head, or the neutral fault detail.
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum OpenOutcome {
    Opened(OpenedHead),
    Fault(EgressFaultInfo),
}

/// Decode the host's packed response-header records (`u32 name_len | name | u32 val_len | val`, LE)
/// and pull out `content-type` and `location` (the two the host surfaces). The names are packed
/// lower-case by the host; matched case-insensitively for robustness.
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
fn decode_head_headers(bytes: &[u8]) -> (Option<String>, Option<String>) {
    let mut content_type = None;
    let mut location = None;
    let mut i = 0usize;
    while let Some(name) = read_u32(bytes, &mut i)
        .and_then(|nl| read_str(bytes, &mut i, nl))
        .and_then(|name| {
            let vl = read_u32(bytes, &mut i)?;
            let value = read_str(bytes, &mut i, vl)?;
            Some((name, value))
        })
    {
        let (n, v) = name;
        if n.eq_ignore_ascii_case("content-type") {
            content_type = Some(v);
        } else if n.eq_ignore_ascii_case("location") {
            location = Some(v);
        }
    }
    (content_type, location)
}

/// Drive [`egress_open`] over `host` for `desc`, returning a fully-decoded [`OpenOutcome`]. All raw
/// out-param reads and borrowed-head-byte decodes happen here; the caller receives only owned values.
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn drive_open(host: HostCtx, desc: &EgressDesc) -> OpenOutcome {
    let mut out = MaybeUninit::<EgressOpen>::uninit();
    let status = egress_open(host, desc as *const EgressDesc, &mut out);
    if status != StatusClass::Ok {
        return OpenOutcome::Fault(drive_fault(host));
    }
    // SAFETY: `egress_open` returned `Ok`, so it initialized the out-param (init-only-on-Ok).
    let open = unsafe { out.assume_init() };
    let head = open.head;
    let peer_spki = if head.observed_spki_ptr.is_null() || head.observed_spki_len == 0 {
        None
    } else {
        // SAFETY: on `Ok`, the head's SPKI pointer borrows host-owned bytes live while the egress is
        // open. We copy them into an owned String immediately, before any close.
        let bytes =
            unsafe { std::slice::from_raw_parts(head.observed_spki_ptr, head.observed_spki_len) };
        Some(String::from_utf8_lossy(bytes).into_owned())
    };
    let (content_type, location) = if head.resp_headers_ptr.is_null() || head.resp_headers_len == 0
    {
        (None, None)
    } else {
        // SAFETY: as above — the head's response-header pointer borrows host-owned bytes live while
        // the egress is open; decoded into owned Strings here.
        let bytes =
            unsafe { std::slice::from_raw_parts(head.resp_headers_ptr, head.resp_headers_len) };
        decode_head_headers(bytes)
    };
    OpenOutcome::Opened(OpenedHead {
        id: open.id,
        status: head.status_code,
        peer_spki,
        location,
        content_type,
        client_identity_offered: head.client_identity_offered != 0,
    })
}

/// Read the neutral fault detail of the last failed [`egress_open`] in this dispatch scope through
/// [`egress_fault`], with generous buffers. Returns a host-fault fallback when none is pending (which
/// should not happen after a non-`Ok` open, but keeps the seam total).
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
fn drive_fault(host: HostCtx) -> EgressFaultInfo {
    // A first read with fixed buffers; if the header reports a longer cause/url, re-read once with
    // exact buffers (the read is non-destructive until it fits — see `egress_fault`).
    fn read_once(
        host: HostCtx,
        cause_cap: usize,
        url_cap: usize,
    ) -> Option<(EgressFault, String, String)> {
        let mut out = MaybeUninit::<EgressFault>::uninit();
        let mut cause = vec![0u8; cause_cap];
        let mut url = vec![0u8; url_cap];
        let status = egress_fault(
            host,
            &mut out,
            cause.as_mut_ptr(),
            cause.len(),
            url.as_mut_ptr(),
            url.len(),
        );
        if status != StatusClass::Ok {
            return None;
        }
        // SAFETY: `Ok` ⇒ the out-param is initialized.
        let fault = unsafe { out.assume_init() };
        let c = String::from_utf8_lossy(&cause[..(fault.cause_len as usize).min(cause.len())])
            .into_owned();
        let u =
            String::from_utf8_lossy(&url[..(fault.url_len as usize).min(url.len())]).into_owned();
        Some((fault, c, u))
    }

    let first = read_once(host, 4096, 4096);
    let Some((fault, cause, url)) = first else {
        return EgressFaultInfo {
            class: EgressFailClass::Fault,
            status: 0,
            cause: String::new(),
            url: String::new(),
        };
    };
    // Re-read with exact buffers if the fixed ones truncated (the header carries the FULL lengths).
    let (fault, cause, url) = if fault.cause_len as usize > cause.len().max(4096)
        || fault.url_len as usize > url.len().max(4096)
        || cause.len() < fault.cause_len as usize
        || url.len() < fault.url_len as usize
    {
        read_once(
            host,
            (fault.cause_len as usize).max(1),
            (fault.url_len as usize).max(1),
        )
        .unwrap_or((fault, cause, url))
    } else {
        (fault, cause, url)
    };
    EgressFaultInfo {
        class: fault.fail_class,
        status: fault.status_code,
        cause,
        url,
    }
}

/// Poll up to `buf.len()` readable bytes off a governed egress into `buf`. Returns the status class
/// and the count written. A safe wrapper around [`egress_poll`]: the raw buffer pointer read stays
/// HERE. `Ok`+`0` is EOF; `Fault` is a mid-body transport failure; `Gone` is a reclaimed id.
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn drive_poll(host: HostCtx, id: EgressId, buf: &mut [u8]) -> (StatusClass, usize) {
    let mut written: usize = 0;
    let class = egress_poll(host, id, buf.as_mut_ptr(), buf.len(), &mut written);
    (class, written)
}

/// Close and reclaim a governed egress — the seam's teardown once the body is read or the stream ends.
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn drive_close(host: HostCtx, id: EgressId) -> StatusClass {
    egress_close(host, id)
}

#[cfg(test)]
#[path = "egress_tests.rs"]
mod tests;
