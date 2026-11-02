// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the egress unit does to an upstream exchange's bytes and headers: the operator

use std::sync::atomic::{AtomicUsize, Ordering};

/// Historical default cap on a buffered upstream ERROR / verbatim-relay body (bytes) — 256 KiB, the
pub const UPSTREAM_ERROR_BODY_MAX_BYTES_DEFAULT: usize = 256 * 1024;

/// Historical default egress translate-body cap (bytes) — 32 MiB, the value read before any operator
pub use busbar_contract::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT;

/// Process-global egress translate-body cap (bytes). Seeded to the historical default so an
static TRANSLATE_BODY_MAX_BYTES: AtomicUsize = AtomicUsize::new(TRANSLATE_BODY_MAX_BYTES_DEFAULT);

/// Read the installed egress translate-body cap (bytes). The neutral twin of core's
pub fn max_translate_body_bytes() -> usize {
    TRANSLATE_BODY_MAX_BYTES.load(Ordering::Relaxed)
}

/// Install the resolved egress translate-body cap process-wide. Called ONLY by core's `limits`
pub fn set_max_translate_body_bytes(bytes: usize) {
    TRANSLATE_BODY_MAX_BYTES.store(bytes, Ordering::Relaxed);
}

/// `err_type` recorded when the upstream connection could not be opened.
pub const ERR_NET_CONNECT: &str = "connect";
/// `err_type` recorded when the upstream did not answer within the attempt's deadline.
pub const ERR_NET_TIMEOUT: &str = "timeout";

/// The fields the upstream connection derives for itself, beyond HTTP's hop-by-hop set.
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
pub fn apply_upstream_encoding(fields: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    if let Some(value) = upstream_encoding().accept_encoding() {
        fields.push((b"accept-encoding".to_vec(), value.as_bytes().to_vec()));
    }
}

/// busbar's own header namespace: a client field under it is addressed to busbar, never upstream.
pub const CONTROL_PREFIX: &str = "x-busbar-";

/// Whether the client field `name` is a per-connection mechanic the upstream request re-derives: a
#[must_use]
pub fn re_derived<'a>(name: &str, nominated: impl IntoIterator<Item = &'a [u8]>) -> bool {
    let lower: std::borrow::Cow<'_, str> = if name.bytes().any(|b| b.is_ascii_uppercase()) {
        name.to_ascii_lowercase().into()
    } else {
        name.into()
    };
    RE_DERIVED.contains(&&*lower)
        || busbar_contract::abi::transport::fields::hop_by_hop(&lower, nominated)
}

/// Drop from the head a plane hands the kernel what the host drops from a client's:
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
