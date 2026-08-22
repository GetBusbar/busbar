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

use super::{recover, HostState};
use busbar_plugin::hot::host::HostCtx;
use busbar_plugin::hot::pod::POD_VERSION;
use busbar_plugin::hot::{EgressDesc, EgressHead, EgressId, EgressKind, EgressOpen, PipeId, StatusClass};
use busbar_plugin::read_sized_field;
use sha2::{Digest, Sha256};
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
// The scaffold reads these convention bits directly; Phase 2 resolves the scope id against operator
// config. The guard stays FAIL-CLOSED by default: a scope of 0 reaches neither.

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
    /// Connected: the observed status and the observed peer identity (empty on a plaintext hop).
    Ok { status: u16, spki: Vec<u8> },
    /// The resolve-then-pin guard refused the hop (SSRF / scheme / metadata).
    Refused(String),
    /// The transport failed before a response head arrived (connect / TLS / send).
    Fault(String),
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
        let _ = self
            .chunks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
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

/// A resolver the pinned client is handed that REFUSES every lookup. The `.resolve()` host override
/// below means the client never needs a second lookup; installing a refusing resolver makes the
/// difference between "never needs to" and "cannot" — if the pin is ever dropped the hop fails loudly
/// instead of quietly re-resolving the name (the a2a `NoSecondLookup` discipline, restated).
struct RefuseSecondLookup;

impl reqwest::dns::Resolve for RefuseSecondLookup {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let name = name.as_str().to_string();
        Box::pin(std::future::ready(Err(Box::<
            dyn std::error::Error + Send + Sync,
        >::from(format!(
            "governed egress pins the resolved address before connecting; a second lookup of \
             `{name}` is the DNS-rebind window the pin exists to close and must not happen"
        )))))
    }
}

/// The observed peer identity: the SHA-256 of the leaf certificate the (already-verified) TLS
/// handshake produced. Empty on a plaintext hop (nothing was proved) — reported honestly as absent
/// rather than softened into a pass, exactly as `a2a::transport::peer_spki_of` reports `None`.
///
/// Phase 2 narrows this to the certificate's SubjectPublicKeyInfo sub-field (the `a2a::spki` DER
/// walk, once that leaf is de-feature-gated) so the pin survives a certificate renewal.
fn observed_identity(resp: &reqwest::Response) -> Vec<u8> {
    let Some(info) = resp.extensions().get::<reqwest::tls::TlsInfo>() else {
        return Vec::new();
    };
    let Some(der) = info.peer_certificate() else {
        return Vec::new();
    };
    let mut hasher = Sha256::new();
    hasher.update(der);
    hasher.finalize().to_vec()
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
    ReqSpec { method, headers, body }
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
        let Some(name) = read_str(bytes, &mut i, name_len) else { break };
        let Some(value_len) = read_u32(bytes, &mut i) else { break };
        let Some(value) = read_str(bytes, &mut i, value_len) else { break };
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
        (Some(ptr), Some(len)) if !ptr.is_null() && len != 0 => unsafe { borrowed_string(ptr, len) },
        _ => return, // no placement header → nothing to inject the credential into.
    };
    let scheme = match (
        read_sized_field!(d, EgressDesc, cred_scheme_ptr),
        read_sized_field!(d, EgressDesc, cred_scheme_len),
    ) {
        // SAFETY: a non-null `(cred_scheme_ptr, cred_scheme_len)` is a live borrowed range (ABI).
        (Some(ptr), Some(len)) if !ptr.is_null() && len != 0 => unsafe { borrowed_string(ptr, len) },
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
fn open_http(
    state: &HostState,
    d: &EgressDesc,
    out: *mut MaybeUninit<EgressOpen>,
) -> StatusClass {
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

    let policy = guard_policy(d.allowlist_scope);

    // Strict-recognise the URL and judge its scheme up front, so a malformed / non-http(s) /
    // inadmissible-plaintext target fails fast without spawning a thread.
    let (https, host_name, port, _path) = match crate::net_guard::split_url(&url) {
        Ok(parts) => parts,
        Err(_) => return StatusClass::Refused,
    };
    if crate::net_guard::judge_scheme(&url, https, policy).is_err() {
        return StatusClass::Refused;
    }

    // NOTE (Phase 2): `client_identity_ref` (mTLS) is accepted here as an opaque REF the HOST
    // resolves — the plane never sees a key. Wiring it needs the boot-time client-identity map plumbed
    // onto `HostState`; the ref is honored structurally (the chokepoint is here).
    let _client_identity_ref = d.client_identity_ref;

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
            run_http_stream(&url, &host_name, port, https, policy, &spec, &head_tx, &chunk_tx, &stop_task);
        });
    let Ok(join) = join else {
        return StatusClass::Fault; // could not spawn the streaming thread.
    };

    // Block for the connect head (or a bounded timeout so a wedged connect cannot pin the caller).
    let head = match head_rx.recv_timeout(EGRESS_TIMEOUT.saturating_add(Duration::from_secs(5))) {
        Ok(head) => head,
        Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => {
            stop.notify_one();
            let _ = join.join();
            return StatusClass::Fault;
        }
    };
    let (status, spki) = match head {
        HeadMsg::Ok { status, spki } => (status, spki),
        HeadMsg::Refused(reason) => {
            tracing::debug!(target: "busbar::plane_host::egress", %reason, "governed egress refused");
            let _ = join.join();
            return StatusClass::Refused;
        }
        HeadMsg::Fault(reason) => {
            tracing::debug!(target: "busbar::plane_host::egress", %reason, "governed egress faulted");
            let _ = join.join();
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
    });

    // The EgressHead borrows the backend's own SPKI bytes, which live until close — so the pointer
    // handed back stays valid while the plane holds the EgressOpen.
    let (spki_ptr, spki_len) = if egress.observed_spki.is_empty() {
        (std::ptr::null(), 0)
    } else {
        (egress.observed_spki.as_ptr(), egress.observed_spki.len())
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
        },
    };

    // Publish the backend, THEN register the arena closer, THEN write the out-param — so a plane that
    // reads the id can immediately find the backend, and the dispatch arena reclaims it on drop.
    registry().insert(id, Arc::clone(&egress));
    // The arena returns its own id; we ignore it and hand the plane the global id (see `REGISTRY`).
    let _ = state
        .scope
        .register_egress(Box::new(move || {
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
            let _ = head_tx.send(HeadMsg::Fault(format!("egress runtime: {e}")));
            return;
        }
    };
    rt.block_on(async move {
        // THE GUARD: exactly one resolution, every answered address judged, the survivor pinned.
        let pin = match crate::net_guard::resolve_and_pin_async(host_name, port, https, policy).await
        {
            Ok(pin) => pin,
            Err(refusal) => {
                let _ = head_tx.send(HeadMsg::Refused(refusal.to_string()));
                return;
            }
        };
        // THE PINNED CLIENT: connects to the judged address, refuses a second lookup, follows no
        // redirect (a 3xx is an unguarded URL), and reads the peer certificate off the verified
        // handshake.
        let client = match reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .tls_info(true)
            .timeout(EGRESS_TIMEOUT)
            .dns_resolver(Arc::new(RefuseSecondLookup))
            .resolve(host_name, pin.socket_addr())
            .build()
        {
            Ok(client) => client,
            Err(e) => {
                let _ = head_tx.send(HeadMsg::Fault(format!("egress client: {e}")));
                return;
            }
        };
        // The outbound request: the plane's verb (default GET), its forwarded headers, and its
        // one-shot body. The credential header (if any) is already in `spec.headers` — injected
        // host-side from the resolved ref, so no plane-held plaintext reaches this builder.
        let mut builder = client.request(spec.method.clone(), url);
        for (name, value) in &spec.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }
        if !spec.body.is_empty() {
            builder = builder.body(spec.body.clone());
        }
        let mut resp = match builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                let _ = head_tx.send(HeadMsg::Fault(e.to_string()));
                return;
            }
        };
        let status = resp.status().as_u16();
        // READ THE CERTIFICATE BEFORE THE BODY — it belongs to THIS connection.
        let spki = observed_identity(&resp);
        if head_tx.send(HeadMsg::Ok { status, spki }).is_err() {
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

#[cfg(test)]
#[path = "egress_tests.rs"]
mod tests;
