// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the egress unit does to an upstream exchange's bytes and headers: the operator
//! body caps, the network-failure labels a transient failure is recorded with, and the
//! client-header mechanics stripped from a request head before it goes upstream.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Historical default cap on a buffered upstream ERROR / verbatim-relay body (bytes) — 256 KiB, the
/// value read before any operator config is installed (unit tests, pre-boot). Owned HERE, in the
/// neutral substrate, and re-exported by core's `config` as `DEFAULT_UPSTREAM_ERROR_BODY_MAX_BYTES`
/// so the number has ONE definition.
pub const UPSTREAM_ERROR_BODY_MAX_BYTES_DEFAULT: usize = 256 * 1024;

/// Historical default egress translate-body cap (bytes) — 32 MiB, the value read before any operator
/// config is installed (unit tests, pre-boot). MUST equal core's `config::DEFAULT_REQUEST_BODY_MAX_BYTES`
/// (the one knob that drives both the inbound `DefaultBodyLimit` and this egress translate cap); the two
/// are pinned equal by construction and by core's `limits` tests. The one definition is the
/// contract's, which a plane reads.
pub use busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT;

/// Process-global egress translate-body cap (bytes). Seeded to the historical default so an
/// UNINSTALLED read (unit tests, pre-boot) is byte-identical to core's
/// `limits::translate_body_max_bytes()` fallback; core's `limits::install`/`InstallGuard` overwrite it
/// with the operator-resolved `LimitsResolved::request_body_max_bytes` on every apply and restore it on
/// a rejected apply, so the value here always tracks core's installed knob. Read PER translated body
/// (not per byte), so a `Relaxed` atomic is ample.
static TRANSLATE_BODY_MAX_BYTES: AtomicUsize = AtomicUsize::new(TRANSLATE_BODY_MAX_BYTES_DEFAULT);

/// Read the installed egress translate-body cap (bytes). The neutral twin of core's
/// `limits::translate_body_max_bytes()`: same process-global value, named from a plane crate without
/// reaching into `busbar-core`. Falls back to [`TRANSLATE_BODY_MAX_BYTES_DEFAULT`] until core installs
/// the resolved limits.
pub fn max_translate_body_bytes() -> usize {
    TRANSLATE_BODY_MAX_BYTES.load(Ordering::Relaxed)
}

/// Install the resolved egress translate-body cap process-wide. Called ONLY by core's `limits`
/// install/reload/rollback path with the value it also installs into its own `LimitsResolved` slot,
/// so the two never diverge; there is no other writer.
pub fn set_max_translate_body_bytes(bytes: usize) {
    TRANSLATE_BODY_MAX_BYTES.store(bytes, Ordering::Relaxed);
}

// ── Network-transient `err_type` values passed to `record_transient_in`. Distinct from the
//    protocol's error-KIND tokens: they label the *category* of network failure recorded in the
//    breaker store, not the protocol-level error kind surfaced to the caller.
/// `err_type` recorded when the upstream connection could not be opened.
pub const ERR_NET_CONNECT: &str = "connect";
/// `err_type` recorded when the upstream did not answer within the attempt's deadline.
pub const ERR_NET_TIMEOUT: &str = "timeout";

// CLIENT-HEADER FORWARDING — THE NEUTRAL MECHANISM.
//
// What a client sends goes out. On a same-dialect route a plane forwards EVERY client header; a
// translated route forwards none (the plane translates what maps and drops the rest, and no header
// maps). The headers that never pass are mechanics, not choices, and the mechanics are stated here
// ONCE, naming no dialect header:
//
//   * [`re_derived`] — the fields HTTP defines per connection (the contract's `hop_by_hop`, plus every
//     name a `connection` field nominates) and `host`/`content-length`, which the connection carrying
//     the upstream request derives for itself;
//   * the names the plane GOVERNS (its dialects' credential headers and tenant selectors, declared as
//     the plane's DATA and asked through a `governed` predicate): busbar's own
//     upstream credential and configuration replace them;
//   * busbar's own control headers: its `x-busbar-` namespace ([`CONTROL_PREFIX`]) and whatever
//     else the plane names as busbar's (a pool's affinity header) through the same predicate.
//
// A neutral build with no plane resident calls neither and forwards nothing.

/// The fields the upstream connection derives for itself, beyond HTTP's hop-by-hop set.
///
/// `accept-encoding` is here because busbar reads the answer to meter it and decodes no content
/// coding: a client's `gzip` would make the far end compress what busbar must read, and 1.5.5
/// sent none (pinned by `a_clients_accept_encoding_never_goes_upstream`).
pub const RE_DERIVED: &[&str] = &["host", "content-length", "accept-encoding"];

/// The content coding busbar asks a provider for. 1.6.0 has one choice, `Identity` (as 1.5.5):
/// busbar sends no `accept-encoding`, so it never spends CPU or latency decoding what it reads to
/// meter. A later config gate (gzip or br, with decompression limits) adds a variant here and its
/// decoding on the answer side; every caller already asks [`upstream_encoding`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UpstreamEncoding {
    /// No content coding: no `accept-encoding` is sent.
    Identity,
}

impl UpstreamEncoding {
    /// The `accept-encoding` value busbar sends for this choice, or `None` to send none.
    #[must_use]
    pub const fn accept_encoding(self) -> Option<&'static str> {
        match self {
            Self::Identity => None,
        }
    }
}

/// THE ONE PLACE the upstream encoding is chosen. There is no gate in 1.6.0.
#[must_use]
pub const fn upstream_encoding() -> UpstreamEncoding {
    UpstreamEncoding::Identity
}

/// Write busbar's own `accept-encoding` choice ([`upstream_encoding`]) onto an upstream head that
/// [`strip_re_derived`] already cleared of the client's. Identity writes nothing.
pub fn apply_upstream_encoding(fields: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    if let Some(value) = upstream_encoding().accept_encoding() {
        fields.push((b"accept-encoding".to_vec(), value.as_bytes().to_vec()));
    }
}

/// busbar's own header namespace: a client field under it is addressed to busbar, never upstream.
pub const CONTROL_PREFIX: &str = "x-busbar-";

/// Whether the client field `name` is a per-connection mechanic the upstream request re-derives: a
/// hop-by-hop field, a field a `connection` field `nominated`, or one of [`RE_DERIVED`].
#[must_use]
pub fn re_derived<'a>(name: &str, nominated: impl IntoIterator<Item = &'a [u8]>) -> bool {
    // A request's own header names are lower-case already; only a plane-spelled one pays the copy.
    let lower: std::borrow::Cow<'_, str> = if name.bytes().any(|b| b.is_ascii_uppercase()) {
        name.to_ascii_lowercase().into()
    } else {
        name.into()
    };
    RE_DERIVED.contains(&&*lower)
        || busbar_contract::abi::transport::fields::hop_by_hop(&lower, nominated)
}

/// Drop from the head a plane hands the kernel what the host drops from a client's:
/// the per-connection mechanics ([`re_derived`], a `connection` field's nominations included) and
/// busbar's own namespace ([`CONTROL_PREFIX`]). The connection re-derives the mechanics; the rest is
/// addressed to busbar, never upstream.
pub fn strip_re_derived(fields: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    let nominated: Vec<Vec<u8>> = fields
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(b"connection"))
        .map(|(_, v)| v.clone())
        .collect();
    fields.retain(|(n, _)| {
        !std::str::from_utf8(n).is_ok_and(|n| {
            re_derived(n, nominated.iter().map(Vec::as_slice))
                || n.to_ascii_lowercase().starts_with(CONTROL_PREFIX)
        })
    });
}

#[cfg(test)]
#[path = "tests/upstream_encoding_tests.rs"]
mod upstream_encoding_tests;
