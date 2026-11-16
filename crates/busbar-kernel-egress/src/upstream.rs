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

/// The fields the upstream connection derives for itself, lower-case: busbar's own (`host`,
/// `content-length`, `accept-encoding`), HTTP's hop-by-hop set (RFC 9110 §7.6.1 and the proxy
/// pair), and the framer's own protocol handshake lines (IF §13 round 23: `upgrade`, `connection`,
/// `sec-websocket-key`, `sec-websocket-version`, a closed list), which the framer writes after auth
/// `outbound`, so no auth style sees or signs them and the wire never carries two of one.
pub(crate) const RE_DERIVED: &[&str] = &[
    "host",
    "content-length",
    "accept-encoding",
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "sec-websocket-key",
    "sec-websocket-version",
];

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
        crate::cold::push_field(fields, b"accept-encoding", value.as_bytes());
    }
}

/// busbar's own header namespace: a client field under it is addressed to busbar, never upstream.
pub(crate) const CONTROL_PREFIX: &str = "x-busbar-";

/// Whether the client field `name` is a per-connection mechanic the upstream request re-derives: a
#[must_use]
pub fn re_derived<'a>(name: &str, nominated: impl IntoIterator<Item = &'a [u8]>) -> bool {
    // The list is lower-case, so a case-blind match is the lower-cased name's exact one; a name a
    // `connection` field nominates is hop-by-hop for this head too, compared case-blind.
    RE_DERIVED
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
        || nominated.into_iter().any(|list| {
            list.split(|b| *b == b',')
                .any(|n| n.trim_ascii().eq_ignore_ascii_case(name.as_bytes()))
        })
}

/// Drop from the head a plane hands the kernel what the host drops from a client's:
pub fn strip_re_derived(fields: &mut Vec<(Vec<u8>, Vec<u8>)>) {
    // Every `connection` field is itself hop-by-hop and goes; move them behind the rest, keeping
    // the rest in order, so their values can name what else goes while the rest is compacted.
    let mut kept = 0;
    for at in 0..fields.len() {
        if !fields[at].0.eq_ignore_ascii_case(b"connection") {
            fields.swap(kept, at);
            kept += 1;
        }
    }
    let (head, connection) = fields.split_at_mut(kept);
    let nominated = || connection.iter().map(|(_, v)| v.as_slice());
    let mut write = 0;
    for at in 0..head.len() {
        let dropped = std::str::from_utf8(&head[at].0).is_ok_and(|n| {
            re_derived(n, nominated())
                || n.as_bytes()
                    .get(..CONTROL_PREFIX.len())
                    .is_some_and(|p| p.eq_ignore_ascii_case(CONTROL_PREFIX.as_bytes()))
        });
        if !dropped {
            head.swap(write, at);
            write += 1;
        }
    }
    fields.truncate(write);
}

#[cfg(test)]
#[path = "tests/upstream_encoding_tests.rs"]
mod upstream_encoding_tests;
