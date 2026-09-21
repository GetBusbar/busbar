// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL FETCH ADAPTER: re-express a host-owned governed egress (`egress_open` + `egress_poll`
//! + `egress_fault`) as the buffered / streamed return shapes the protocol planes already consume, so
//! an extracted plane never holds a concrete `reqwest::Response`.
//!
//! ## Why this exists and what it does NOT change
//!
//! A protocol plane owns a small amount of logic on top of one outbound hop: a redirect loop, a
//! body-cap decision, a streaming frame parse. NONE of that moves here. What moves is the hop itself —
//! the socket, the pinned client, the peer certificate, the streamed body — which the host already owns
//! behind the egress vtable. This module is the thin translation between the host's poll seam and a
//! plane's existing [`Response`](super::Response) / [`StreamHead`](super::StreamHead) vocabulary, so
//! those callers read unchanged.
//!
//! ## Byte-identity, by construction
//!
//! The wire bytes are the host's `build_pinned_client` reqwest codec — the SAME one a plane's own
//! transport used — so status/body/headers/ALPN are unchanged by moving the hop host-side. The peer
//! SPKI pin is decoded from the same observed-identity bytes the neutral
//! `busbar_kernel::plane_host::spki` pin walk produces, which a plane's own transport calls to
//! compute its pin, so the pin string is byte-identical. The body cap / `ReadEnd` classification is
//! re-expressed over the poll seam to match
//! [`crate::proxy::read_capped`] exactly (Ok-0 = Complete, Fault = TransportError, an over-cap probe =
//! Truncated). A byte-identity CONFORMANCE test drives this adapter and a direct reqwest hop against
//! the same fixture and asserts the two agree.
//!
//! ## No `unsafe` here
//!
//! busbar-core denies `unsafe` outside `plane_host`. Every raw out-param read and borrowed-head decode
//! is done by the SAFE driver wrappers in [`crate::plane_host::egress`] (`drive_open`, `drive_poll`,
//! `drive_close`); this adapter is pure safe glue that owns only the cap loop and the projection.

#![cfg_attr(not(test), allow(dead_code))]

use busbar_plugin::hot::{EgressDesc, EgressKind, StatusClass, POD_VERSION};

use crate::plane_host::egress::{
    drive_close, drive_open, drive_poll, scope_bits, OpenOutcome, OpenedHead,
};
use crate::plane_host::scope::DispatchScope;
use crate::proxy::ReadEnd;

// The neutral buffered/fault RETURN shapes and the [`HostlessEgress`] driver trait relocated to
// `busbar_kernel::egress::seam` (field-neutral `std` data + the plugin `EgressFailClass`), so a
// plane crate reads them without naming core. Re-exported here so every in-core `Buffered` /
// `EgressFaultInfo` reach — `buffered`/`stream_head` below and the `crate::egress::seam::*` call
// sites — is unchanged, and so `CoreHostlessEgress` below can implement the trait.

/// Mint a throw-away dispatch scope and run `f` over it — the HOSTLESS entry the extracted in-core
/// planes drive this seam through (they hold no `HostCtx`). The scope lives for the whole closure, so a
/// STREAMING caller runs its `stream_head` + `pump` (+ fault read-back) under ONE scope — the arena
/// closer registered at open fires only when `f` returns, not between the two calls. Mirrors
/// [`crate::plane_host::journal::journal_append_scoped_full_hostless`]: an in-core twin of the FFI
/// path, funnelling into the exact same governed-hop bodies, for a site that has no host to open.
pub fn with_hostless<R>(f: impl FnOnce(&DispatchScope) -> R) -> R {
    let scope = DispatchScope::new();
    f(&scope)
}

// The neutral hop description this adapter consumes relocated to `busbar_kernel::egress::seam`
// (pure `std` data — borrowed slices, allowlist flags, opaque host refs, a deadline and an
// already-judged pinned address) so a plane crate builds a hop spec without reaching into core.
// Re-exported here so every in-core `HopSpec` reach — `build_desc`/`buffered`/`stream_head` below,
// and `crate::egress::seam::HopSpec` from the plane transports — is unchanged.

/// Pack `(name, value)` header pairs into the ABI's length-prefixed record form (`u32 name_len` LE,
/// name, `u32 value_len` LE, value) — the form [`EgressDesc::headers_ptr`] carries.
fn pack_headers(headers: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (name, value) in headers {
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&(value.len() as u32).to_le_bytes());
        out.extend_from_slice(value.as_bytes());
    }
    out
}

/// Build the borrowed [`EgressDesc`] for a hop, borrowing `spec`'s bytes and the packed header buffer.
/// The returned desc's pointers are live for as long as `spec`, `packed_headers` and the derived
/// buffers here are — the caller keeps them on the stack across the `drive_open` call (the host copies
/// everything it needs at open, so the borrow need only span that call).
fn build_desc<'a>(spec: &'a HopSpec<'a>, packed_headers: &'a [u8]) -> EgressDesc {
    let (headers_ptr, headers_len) = if packed_headers.is_empty() {
        (std::ptr::null(), 0)
    } else {
        (packed_headers.as_ptr(), packed_headers.len())
    };
    let (verb_ptr, verb_len) = if spec.verb.is_empty() {
        (std::ptr::null(), 0)
    } else {
        (spec.verb.as_ptr(), spec.verb.len())
    };
    let (body_ptr, body_len) = if spec.body.is_empty() {
        (std::ptr::null(), 0)
    } else {
        (spec.body.as_ptr(), spec.body.len())
    };
    // Encode the plane's already-judged pinned address (Design A) into the 16-byte slot + kind: a v4
    // address fills the first 4 bytes (kind 4), a v6 address fills all 16 (kind 6). `None` ⇒ kind 0,
    // the host resolves the URL host itself (the pre-enrichment behaviour).
    let (resolved_addr, resolved_addr_kind) = match spec.resolved_addr {
        Some(std::net::IpAddr::V4(v4)) => {
            let mut bytes = [0u8; 16];
            bytes[..4].copy_from_slice(&v4.octets());
            (bytes, 4u8)
        }
        Some(std::net::IpAddr::V6(v6)) => (v6.octets(), 6u8),
        None => ([0u8; 16], 0u8),
    };
    EgressDesc {
        size: std::mem::size_of::<EgressDesc>() as u32,
        version: POD_VERSION,
        kind: busbar_plugin::hot::RawEgressKind::of(EgressKind::OneShot),
        _reserved: 0,
        allowlist_scope: scope_bits(spec.allow_private, spec.allow_plaintext),
        _reserved2: 0,
        target_ptr: spec.url.as_ptr(),
        target_len: spec.url.len(),
        client_identity_ref: spec.client_identity_ref,
        credential_ref: 0,
        verb_ptr,
        verb_len,
        headers_ptr,
        headers_len,
        body_ptr,
        body_len,
        cred_header_ptr: std::ptr::null(),
        cred_header_len: 0,
        cred_scheme_ptr: std::ptr::null(),
        cred_scheme_len: 0,
        env_ptr: std::ptr::null(),
        env_len: 0,
        cwd_ptr: std::ptr::null(),
        cwd_len: 0,
        stderr_inherit: 0,
        _reserved3: [0; 7],
        trust_anchor_ref: spec.trust_anchor_ref,
        timeout_ms: spec.timeout.as_millis().min(u64::MAX as u128) as u64,
        resolved_addr,
        resolved_addr_kind,
        _reserved4: [0; 7],
    }
}

/// How many body bytes the adapter reads per poll — bounded, and always clamped to the remaining cap
/// so the accumulated body never overruns `cap` (matching [`crate::proxy::read_capped`]).
const READ_CHUNK: usize = 64 * 1024;

/// Read a governed egress body into an owned buffer, applying `cap` EXACTLY as
/// [`crate::proxy::read_capped`] does: accumulate up to `cap` bytes, and once `cap` is reached probe
/// one more byte to tell a body that ended at the cap (`Complete`) from one that overran it
/// (`Truncated`). A mid-body [`StatusClass::Fault`] is [`ReadEnd::TransportError`]. The returned buffer
/// holds at most `cap` bytes, byte-identical to `read_capped`'s prefix.
fn read_capped_over(
    scope: &DispatchScope,
    id: busbar_plugin::hot::EgressId,
    cap: usize,
) -> (Vec<u8>, ReadEnd) {
    let mut body: Vec<u8> = Vec::new();
    let mut scratch = vec![0u8; READ_CHUNK];
    loop {
        let remaining = cap.saturating_sub(body.len());
        if remaining == 0 {
            // Cap reached: one probe byte decides Truncated (more existed) vs Complete (clean EOF).
            let mut one = [0u8; 1];
            let (class, n) = drive_poll(scope, id, &mut one);
            return match class {
                StatusClass::Ok if n == 0 => (body, ReadEnd::Complete),
                StatusClass::Ok => (body, ReadEnd::Truncated),
                _ => (body, ReadEnd::TransportError),
            };
        }
        let take = remaining.min(scratch.len());
        let (class, n) = drive_poll(scope, id, &mut scratch[..take]);
        match class {
            StatusClass::Ok if n == 0 => return (body, ReadEnd::Complete),
            StatusClass::Ok => body.extend_from_slice(&scratch[..n]),
            _ => return (body, ReadEnd::TransportError),
        }
    }
}

/// Open a governed hop and read its body to `cap`, returning the neutral [`Buffered`] projection — the
/// buffered round trip a protocol plane builds its own return type over. On an open refusal/fault,
/// `Err` carries the neutral [`EgressFaultInfo`] the plane composes
/// its operator string over (the cause and url are kept SEPARATE). The egress is closed before return.
pub fn buffered(
    scope: &DispatchScope,
    spec: &HopSpec<'_>,
    cap: usize,
) -> Result<Buffered, EgressFaultInfo> {
    let packed = pack_headers(spec.headers);
    let desc = build_desc(spec, &packed);
    let head = match drive_open(scope, &desc) {
        OpenOutcome::Opened(h) => h,
        OpenOutcome::Fault(f) => return Err(f),
    };
    let OpenedHead {
        id,
        status,
        peer_spki,
        location,
        content_type,
        client_identity_offered,
    } = head;
    let (body, end) = read_capped_over(scope, id, cap);
    drive_close(id);
    Ok(Buffered {
        status,
        location,
        content_type,
        peer_spki,
        client_identity_offered,
        body,
        end,
    })
}

// ── The STREAMING relay adapter. ─────────────────────────────────────────────────────────────────
//
// A streaming plane relay reads the head, then either buffers a non-stream reply whole (a non-2xx or a
// non-`text/event-stream` answer is NOT a stream) or drives the body chunk-by-chunk into the caller's
// sink. This adapter splits that into `stream_head` (the head + the buffer-or-stream decision, the
// non-stream body already read) and `pump` (drive the live stream). The caller calls `stream_head`
// and, on a live stream, `pump`, then returns the head — the same StreamHead the relay driver reads.

/// The outcome of opening a stream relay hop: a non-stream reply buffered whole, or a live event-stream
/// to [`pump`]. Gated on the neutral `egress-stream` capability marker, enabled only by whichever plane
/// feature's relay is its one consumer.
#[cfg(feature = "egress-stream")]
pub enum StreamOutcome {
    /// A non-2xx or non-event-stream reply, read whole to the cap. The [`StreamHead`](super::StreamHead)
    /// carries the body; there is nothing to pump.
    Buffered(super::StreamHead),
    /// A live `text/event-stream`: the head (empty body — the bytes go to the sink) and the egress id
    /// the caller [`pump`]s.
    Streaming {
        head: super::StreamHead,
        id: busbar_plugin::hot::EgressId,
    },
}

/// Open a stream relay hop and read its head. A non-2xx / non-`text/event-stream` reply is read whole
/// to `cap` (a [`StreamOutcome::Buffered`]); a real event-stream returns [`StreamOutcome::Streaming`]
/// with the egress left open for [`pump`]. `content_type` is lower-cased into the head exactly as a
/// plane's own relay does. On an open refusal/fault, `Err` carries the neutral fault.
#[cfg(feature = "egress-stream")]
pub fn stream_head(
    scope: &DispatchScope,
    spec: &HopSpec<'_>,
    cap: usize,
) -> Result<StreamOutcome, EgressFaultInfo> {
    let packed = pack_headers(spec.headers);
    let desc = build_desc(spec, &packed);
    let head = match drive_open(scope, &desc) {
        OpenOutcome::Opened(h) => h,
        OpenOutcome::Fault(f) => return Err(f),
    };
    // The relay lower-cases the content-type and treats an absent one as empty (`unwrap_or_default`).
    let content_type = head.content_type.unwrap_or_default().to_ascii_lowercase();
    let is_stream =
        (200..300).contains(&head.status) && content_type.starts_with("text/event-stream");
    if is_stream {
        Ok(StreamOutcome::Streaming {
            head: super::StreamHead {
                status: head.status,
                content_type,
                body: Vec::new(),
            },
            id: head.id,
        })
    } else {
        // A non-stream reply is read whole to the cap; a mid-body transport failure is surfaced to the
        // caller as the SAME neutral fault an open failure is, so the relay composes one message.
        let (body, end) = read_capped_over(scope, head.id, cap);
        drive_close(head.id);
        if matches!(end, ReadEnd::TransportError) {
            return Err(EgressFaultInfo {
                class: busbar_plugin::hot::EgressFailClass::Io,
                status: head.status,
                cause: "the connection failed mid-body".to_string(),
                url: spec.url.to_string(),
            });
        }
        Ok(StreamOutcome::Buffered(super::StreamHead {
            status: head.status,
            content_type,
            body,
        }))
    }
}

/// The outcome of pumping a live stream to a sink.
#[cfg(feature = "egress-stream")]
pub enum PumpEnd {
    /// The stream ended cleanly (EOF) or the sink asked to stop.
    Done,
    /// The stream failed mid-body; carries the neutral fault (the FLATTENED cause the host stashed on
    /// the poll — `with_cause(&e)` — so the relay reports the SAME operator line its own path did).
    // Read by [`CoreHostlessEgress::stream`] below, which maps a `Failed` pump into the `Err` its
    // caller composes a message from.
    Failed(#[allow(dead_code)] EgressFaultInfo),
}

/// Drive a live event-stream body to `on_chunk`, one host read per call, until EOF, the sink's
/// [`ChunkFlow::Stop`](super::ChunkFlow), or a transport failure. The egress is closed on return.
///
/// PER-CHUNK BOUNDARY NUANCE: the host delivers bytes in reads bounded by the buffer this pump offers,
/// which need not match the upstream's own chunk boundaries. The CONCATENATION of what `on_chunk` sees
/// is byte-identical to the upstream body; the individual boundaries may differ. SSE is boundary-free
/// at the byte level (the relay re-parses frames), so this is faithful — the pump offers a large buffer
/// so a whole upstream chunk usually arrives at once.
#[cfg(feature = "egress-stream")]
pub fn pump(
    scope: &DispatchScope,
    id: busbar_plugin::hot::EgressId,
    on_chunk: &mut (dyn FnMut(&[u8]) -> super::ChunkFlow + Send),
) -> PumpEnd {
    let mut scratch = vec![0u8; READ_CHUNK];
    let end = loop {
        let (class, n) = drive_poll(scope, id, &mut scratch);
        match class {
            StatusClass::Ok if n == 0 => break PumpEnd::Done,
            StatusClass::Ok => {
                if on_chunk(&scratch[..n]) == super::ChunkFlow::Stop {
                    break PumpEnd::Done;
                }
            }
            // A mid-body Fault stashed the real cause on `scope`; read it back so the relay reports the
            // SAME `with_cause(&e)` line it did directly. `Gone` yields the neutral fallback fault.
            _ => break PumpEnd::Failed(crate::plane_host::egress::drive_fault(scope)),
        }
    };
    drive_close(id);
    end
}

/// THE CORE-BACKED hostless-egress driver — the one production implementation of the neutral
/// [`HostlessEgress`] trait, installed at boot by the composition root. It funnels each hop into the
/// EXACT `with_hostless` + `buffered` / `stream_head` + `pump` bodies above (the `plane_host` FFI
/// egress vtable), so a plane that drives `hostless()` runs byte-identical to the in-core callers that
/// name these functions directly. A ZST unit struct, so `&CoreHostlessEgress` promotes to `'static`.
pub struct CoreHostlessEgress;

impl HostlessEgress for CoreHostlessEgress {
    fn buffered(&self, spec: &HopSpec<'_>, cap: usize) -> Result<Buffered, EgressFaultInfo> {
        with_hostless(|scope| buffered(scope, spec, cap))
    }

    #[cfg(feature = "egress-stream")]
    fn stream(
        &self,
        spec: &HopSpec<'_>,
        cap: usize,
        on_chunk: &mut (dyn FnMut(&[u8]) -> super::ChunkFlow + Send),
    ) -> Result<super::StreamHead, EgressFaultInfo> {
        // ONE hostless scope spans the head AND the pump, so the streaming egress stays open between
        // `stream_head` and `pump` — byte-identical to how a plane's own streaming transport drives it,
        // save that the neutral fault is surfaced whole (the caller maps it to its own message).
        with_hostless(|scope| match stream_head(scope, spec, cap)? {
            StreamOutcome::Buffered(head) => Ok(head),
            StreamOutcome::Streaming { head, id } => match pump(scope, id, on_chunk) {
                PumpEnd::Done => Ok(head),
                PumpEnd::Failed(f) => Err(f),
            },
        })
    }
}

// ==== merged from busbar-substrate (W4.b P2 engine drain) ====
/// The one hop the adapter opens, as neutral data. The plane composes protocol on top; this carries
/// only what an outbound request IS — verb, url, headers, body — plus the host's allowlist stance and
/// the opaque mTLS client-identity ref (never a key).
pub struct HopSpec<'a> {
    pub verb: &'a str,
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    /// The host allowlist stance for this hop (lowered from the plane's per-registration policy).
    pub allow_private: bool,
    pub allow_plaintext: bool,
    /// The opaque host-side client-identity ref (`0` = present none). Never a key.
    pub client_identity_ref: u64,
    /// The opaque host-side trust-anchor ref (`0` = no extra roots — trust only the platform roots).
    /// Never certificate bytes. Carries a private-CA registration (a `trusting_root` fixture).
    pub trust_anchor_ref: u64,
    /// The per-hop end-to-end deadline. [`Duration::ZERO`] ⇒ the host's default ceiling.
    pub timeout: std::time::Duration,
    /// The plane's ALREADY-JUDGED pinned address for this hop (Design A). `Some` ⇒ the host connects
    /// to THIS address and does NOT resolve the URL host (the plane resolved-then-pinned plane-side and
    /// hands the survivor over); `None` ⇒ the host resolves the URL host itself. The URL host is still
    /// used for SNI / cert-name / mTLS in either case.
    pub resolved_addr: Option<std::net::IpAddr>,
}

// ── THE NEUTRAL HOSTLESS-EGRESS SEAM ─────────────────────────────────────────────────────────────
//
// The buffered / streamed RETURN shapes a plane reads back from one governed hop, plus the neutral
// DRIVER trait an extracted plane calls to run that hop without naming core. The concrete driver
// stays core's (`busbar_kernel::egress::seam::CoreHostlessEgress`, over the `plane_host` FFI egress
// vtable) and is installed at boot; a plane holds only `&dyn HostlessEgress` off [`hostless`]. The
// shapes below are field-neutral (they name only `std` + the substrate `ReadEnd` and the plugin
// `EgressFailClass`), relocated from `busbar_kernel::egress::seam` / `busbar_kernel::plane_host::egress`
// so a plane crate reads them without reaching into core; core re-exports them so its own call sites
// resolve unchanged. Gated to the plane features, this seam's only consumers.

/// One buffered outbound round trip, reduced to what a caller reads back — the NEUTRAL projection every
/// plane maps from (the [`Response`](super::Response) shape carries a subset; a dispatch caller reads
/// status/body/content-type for its own `is_sse` / redirect refusal). `content_type` is surfaced
/// VERBATIM (the host lower-cases nothing); a caller applies its own casing.
#[cfg(any(feature = "dispatch", feature = "relay"))]
pub struct Buffered {
    pub status: u16,
    pub location: Option<String>,
    /// Read by the dispatch converter for its `is_sse` decision.
    #[cfg_attr(not(feature = "dispatch"), allow(dead_code))]
    pub content_type: Option<String>,
    pub peer_spki: Option<String>,
    pub client_identity_offered: bool,
    pub body: Vec<u8>,
    /// How the capped read ended — the poll-seam re-expression of [`crate::proxy::ReadEnd`].
    pub end: crate::proxy::ReadEnd,
}

/// A fully-decoded egress fault the seam composes its own operator string over — the class, the status,
/// and the flattened CAUSE and TARGET-url kept SEPARATE (one plane keeps the url, another strips it),
/// exactly as the host `egress_fault` hands them across the ABI.
#[cfg(any(feature = "dispatch", feature = "relay"))]
#[derive(Debug)]
pub struct EgressFaultInfo {
    pub class: busbar_plugin::hot::EgressFailClass,
    pub status: u16,
    pub cause: String,
    pub url: String,
}

/// THE NEUTRAL DRIVER an extracted plane runs a governed hop through — the trait `hostless()` hands
/// back, whose only production implementation is core's `CoreHostlessEgress` (over the `plane_host`
/// FFI egress vtable), installed once at boot. A plane names this trait, never the concrete driver, so
/// the unsafe FFI half stays core's alone.
///
/// [`stream`](HostlessEgress::stream) is `relay`-only: its one implementation drives the core
/// `stream_head` + `pump` streaming path, which is itself `relay`-gated, and its one caller is the
/// relay path. The buffered hop is shared by every plane (a dispatch caller and a buffered fetch).
#[cfg(any(feature = "dispatch", feature = "relay"))]
pub trait HostlessEgress: Send + Sync {
    /// One buffered outbound round trip: open a governed hop, read its body to `cap`, and hand back
    /// the neutral [`Buffered`] projection (or the neutral [`EgressFaultInfo`] on an open/read fault).
    fn buffered(&self, spec: &HopSpec<'_>, cap: usize) -> Result<Buffered, EgressFaultInfo>;

    /// Open a streaming hop: read the head, then either hand back a non-stream reply buffered whole or
    /// pump a live event-stream body into `on_chunk`. The relay path's one code path.
    #[cfg(feature = "relay")]
    fn stream(
        &self,
        spec: &HopSpec<'_>,
        cap: usize,
        on_chunk: &mut (dyn FnMut(&[u8]) -> super::ChunkFlow + Send),
    ) -> Result<super::StreamHead, EgressFaultInfo>;
}

/// THE PROCESS-WIDE hostless-egress driver, installed once by the composition root
/// ([`install_hostless_egress`]). A plane reads it back through [`hostless`] and gets `None` in a
/// build that installed none (a plane running without the core-backed driver behind it).
#[cfg(any(feature = "dispatch", feature = "relay"))]
static HOSTLESS: std::sync::OnceLock<&'static dyn HostlessEgress> = std::sync::OnceLock::new();

/// Install the process hostless-egress driver — the composition root's one write, at boot, before any
/// plane dispatches. Idempotent by `OnceLock`: a second install is a no-op (the first driver wins).
#[cfg(any(feature = "dispatch", feature = "relay"))]
pub fn install_hostless_egress(driver: &'static dyn HostlessEgress) {
    let _ = HOSTLESS.set(driver);
}

/// The installed hostless-egress driver, or `None` when none was installed. A plane that gets `None`
/// has no egress backend behind it and refuses the hop rather than inventing one.
#[cfg(any(feature = "dispatch", feature = "relay"))]
pub fn hostless() -> Option<&'static dyn HostlessEgress> {
    HOSTLESS.get().copied()
}

// ── SEND AN ALREADY-PINNED HOP ───────────────────────────────────────────────────────────────────
//
// The POST-PIN send skeleton every extracted plane shares: build the neutral [`HopSpec`] for a hop the
// plane has ALREADY resolved-then-pinned plane-side, run it on the installed hostless driver, and hand
// back the buffered projection (or the streamed head). It names no protocol and no plane — the plane
// keeps its own PRE-pin door (resolve/guard/pin, live-trust re-check, credential attach) and its own
// POST-return interpretation (`ReadEnd`, SSE, redirect refusal); ONLY the identical
// `HopSpec`-literal + `hostless()` null-check + `buffered`/`stream` call lives here now, so the "no
// second lookup" posture of an already-judged hop is expressed in exactly one place.

/// One ALREADY-PINNED outbound hop, as neutral data. The plane resolved-then-pinned and judged `addr`
/// plane-side, so the host re-judges nothing: the pinned address is handed straight through (Design A)
/// and the allowlist stances are moot. The generic input both planes build AFTER their own pin — it
/// carries only what an outbound request IS plus the opaque host-side refs, and names no protocol.
#[cfg(any(feature = "dispatch", feature = "relay"))]
pub struct PinnedHop<'a> {
    pub verb: &'a str,
    pub url: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    /// The opaque host-side client-identity ref (`0` = present none). Never a key.
    pub client_identity_ref: u64,
    /// The opaque host-side trust-anchor ref (`0` = platform roots only). Never certificate bytes.
    pub trust_anchor_ref: u64,
    /// The per-hop end-to-end deadline. [`Duration::ZERO`](std::time::Duration) ⇒ the host default.
    pub timeout: std::time::Duration,
    /// The plane's ALREADY-JUDGED pinned address (Design A): the host connects HERE and resolves
    /// nothing. The URL host is still used for SNI / cert-name / mTLS.
    pub addr: std::net::IpAddr,
}

#[cfg(any(feature = "dispatch", feature = "relay"))]
impl PinnedHop<'_> {
    /// Lower to the neutral [`HopSpec`] the driver consumes. The pin is expressed HERE, once: a
    /// supplied `resolved_addr` means the host re-judges nothing, so `allow_private`/`allow_plaintext`
    /// are moot and set open — the plane's own pre-pin guard already judged this hop.
    fn spec(&self) -> HopSpec<'_> {
        HopSpec {
            verb: self.verb,
            url: self.url,
            headers: self.headers,
            body: self.body,
            allow_private: true,
            allow_plaintext: true,
            client_identity_ref: self.client_identity_ref,
            trust_anchor_ref: self.trust_anchor_ref,
            timeout: self.timeout,
            resolved_addr: Some(self.addr),
        }
    }
}

/// The neutral fault a build with NO installed driver refuses a pinned hop with — the same
/// `Fault`-class, url-carrying shape the host's `egress_fault` produces, so a caller that keeps the
/// `cause` and a caller that classifies the `class` both read exactly what they read before.
#[cfg(any(feature = "dispatch", feature = "relay"))]
fn no_backend_fault(url: &str) -> EgressFaultInfo {
    EgressFaultInfo {
        class: busbar_plugin::hot::EgressFailClass::Fault,
        status: 0,
        cause: "no governed egress backend is installed for this build".to_string(),
        url: url.to_string(),
    }
}

/// SEND ONE ALREADY-PINNED HOP, BUFFERED. Builds the neutral [`HopSpec`] for a hop the plane already
/// pinned, runs it on the installed hostless driver, and hands back the [`Buffered`] projection (or the
/// neutral [`EgressFaultInfo`] — a build with no driver refuses here rather than inventing a client).
/// The caller keeps its own `ReadEnd` / SSE / redirect interpretation.
#[cfg(any(feature = "dispatch", feature = "relay"))]
pub fn send_pinned_buffered(hop: &PinnedHop<'_>, cap: usize) -> Result<Buffered, EgressFaultInfo> {
    hostless()
        .ok_or_else(|| no_backend_fault(hop.url))?
        .buffered(&hop.spec(), cap)
}

/// SEND ONE ALREADY-PINNED HOP, STREAMED. As [`send_pinned_buffered`], but drives the streaming path:
/// read the head, then either buffer a non-stream reply whole or pump a live event-stream body into
/// `on_chunk`. One hostless scope spans the head and the pump.
#[cfg(feature = "relay")]
pub fn send_pinned_stream(
    hop: &PinnedHop<'_>,
    cap: usize,
    on_chunk: &mut (dyn FnMut(&[u8]) -> super::ChunkFlow + Send),
) -> Result<super::StreamHead, EgressFaultInfo> {
    hostless()
        .ok_or_else(|| no_backend_fault(hop.url))?
        .stream(&hop.spec(), cap, on_chunk)
}
