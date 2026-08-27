// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL HOP SPECIFICATION — the pure-data description of one outbound governed hop a plane
//! hands the host-mediated fetch adapter.
//!
//! [`HopSpec`] names only `std` types (a couple of borrowed slices, two allowlist flags, two opaque
//! host-side refs, a deadline and an already-judged pinned address). The FETCH ADAPTER that consumes
//! it — the `buffered` / `stream_head` / `pump` drivers that reach the `plane_host` FFI egress vtable
//! — stays in `busbar_core::egress::seam`, because that half drives core-owned unsafe drivers. This
//! is only the neutral INPUT to that adapter, relocated so a plane crate builds a hop spec without
//! reaching into core; core re-exports it, so `busbar_core::egress::seam::HopSpec` still resolves.

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
    /// Never certificate bytes. Carries a private-CA registration (the a2a `trusting_root` fixture).
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
// stays core's (`busbar_core::egress::seam::CoreHostlessEgress`, over the `plane_host` FFI egress
// vtable) and is installed at boot; a plane holds only `&dyn HostlessEgress` off [`hostless`]. The
// shapes below are field-neutral (they name only `std` + the substrate `ReadEnd` and the plugin
// `EgressFailClass`), relocated from `busbar_core::egress::seam` / `busbar_core::plane_host::egress`
// so a plane crate reads them without reaching into core; core re-exports them so its own call sites
// resolve unchanged. Gated to the plane features, this seam's only consumers.

/// One buffered outbound round trip, reduced to what a caller reads back — the NEUTRAL projection both
/// planes map from (the A2A [`Response`](super::Response) carries a subset; the MCP dispatch reads
/// status/body/content-type for its own `is_sse` / redirect refusal). `content_type` is surfaced
/// VERBATIM (the host lower-cases nothing); a caller applies its own casing.
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
pub struct Buffered {
    pub status: u16,
    pub location: Option<String>,
    /// Read by the MCP dispatch converter for its `is_sse` decision.
    #[cfg_attr(not(feature = "plane-mcp"), allow(dead_code))]
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
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
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
/// [`stream`](HostlessEgress::stream) is `plane-a2a`-only: its one implementation drives the core
/// `stream_head` + `pump` streaming path, which is itself `plane-a2a`-gated, and its one caller is the
/// A2A relay. The buffered hop is shared by both planes (the MCP dispatch and the A2A card fetch).
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
pub trait HostlessEgress: Send + Sync {
    /// One buffered outbound round trip: open a governed hop, read its body to `cap`, and hand back
    /// the neutral [`Buffered`] projection (or the neutral [`EgressFaultInfo`] on an open/read fault).
    fn buffered(&self, spec: &HopSpec<'_>, cap: usize) -> Result<Buffered, EgressFaultInfo>;

    /// Open a streaming hop: read the head, then either hand back a non-stream reply buffered whole or
    /// pump a live event-stream body into `on_chunk`. The A2A relay's one code path.
    #[cfg(feature = "plane-a2a")]
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
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
static HOSTLESS: std::sync::OnceLock<&'static dyn HostlessEgress> = std::sync::OnceLock::new();

/// Install the process hostless-egress driver — the composition root's one write, at boot, before any
/// plane dispatches. Idempotent by `OnceLock`: a second install is a no-op (the first driver wins).
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
pub fn install_hostless_egress(driver: &'static dyn HostlessEgress) {
    let _ = HOSTLESS.set(driver);
}

/// The installed hostless-egress driver, or `None` when none was installed. A plane that gets `None`
/// has no egress backend behind it and refuses the hop rather than inventing one.
#[cfg(any(feature = "plane-mcp", feature = "plane-a2a"))]
pub fn hostless() -> Option<&'static dyn HostlessEgress> {
    HOSTLESS.get().copied()
}
