// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOP'S BILLED-BYTES ACCOUNTING — split out of [`super::relay`] (structure-lint) so the
//! module that opens the socket stays under the file-size cap; the type re-exports through
//! `super::relay::HopBytes` unchanged, so every caller elsewhere in the crate (`receive.rs`,
//! `originate.rs`) that names `relay::HopBytes` is untouched by this file existing.

/// **THE PAYLOAD BYTES ONE HOP MOVED, BOTH WAYS** — the quantity A2A's one declared class, `bytes`,
/// ledgers (OWNER RULING §13/Q30c, recorded as Q35: *a billed A2A byte = payload bytes relayed BOTH
/// ways per hop, request + response*).
///
/// **A PAYLOAD BYTE is a BODY byte on the hop's wire, and nothing else:**
///
/// - SENT: the length of the request body busbar handed the transport for THIS hop — the framed
///   body (JSON-RPC envelope, REST document or gRPC length-prefixed message, whichever binding the
///   backend's card declares), after any identity translation or hook rewrite. Counted once the
///   transport has carried the exchange (it returned an answer, or a streamed chunk arrived).
/// - RECEIVED: the length of the response body the backend answered, as the transport delivered it
///   (content bytes, after the HTTP transfer coding is removed) — for a unary hop the whole body, for
///   a stream the SUM OF EVERY CHUNK received, whether or not busbar then relayed it (a caller that
///   hangs up mid-stream stops the hop; what had already arrived is counted).
/// - EXCLUDED: the request line, the status line and every header in both directions (transport
///   framing, not payload), TLS and TCP overhead, and anything busbar answers itself.
///
/// A hop refused before the socket — the guard, the live trust gate, the breaker, an unframable
/// method, an unleasable credential — never reaches the transport, so it counts ZERO by
/// construction: the counters below are only touched after the transport call.
///
/// Atomic rather than `Cell` because the streaming hop counts from inside the transport's chunk
/// sink, which is `Send`; the counts are read once, after the relay returns, on the same thread.
///
/// AND WHETHER THE HOP LEFT AT ALL: [`HopBytes::left`] is set by the relay at the one line past
/// which a hop is on its way to the backend (every pre-socket gate passed, the request framed and
/// built), so the charge is settled on the relay's own knowledge rather than inferred from which
/// refusal came back — an `Unframable` is raised both before the send and on reading the answer.
#[derive(Debug, Default)]
pub(crate) struct HopBytes {
    sent: std::sync::atomic::AtomicU64,
    received: std::sync::atomic::AtomicU64,
    left: std::sync::atomic::AtomicBool,
}

impl HopBytes {
    /// The hop is past every pre-socket gate and goes to the transport. Visible to
    /// [`super::relay`], whose preamble is the one place that line is.
    pub(super) fn mark_left(&self) {
        self.left.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// Whether the hop went to the transport: a hop that did is billed whatever the backend then
    /// answered; one that did not was refused before the socket and ledgers nothing.
    pub(crate) fn left(&self) -> bool {
        self.left.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Visible to [`super::relay`], which is the only caller: the transport-return sites where a
    /// hop's byte count is known are all in that module.
    pub(super) fn add_sent(&self, n: usize) {
        self.sent.fetch_add(
            u64::try_from(n).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    pub(super) fn add_received(&self, n: usize) {
        self.received.fetch_add(
            u64::try_from(n).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
    }

    /// The request body bytes this hop put on the wire.
    pub(crate) fn sent(&self) -> u64 {
        self.sent.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// The response body bytes this hop read off the wire.
    pub(crate) fn received(&self) -> u64 {
        self.received.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Both ways: the one figure the hop's `bytes` class ledgers. Saturating — a count is never a
    /// wrap.
    pub(crate) fn total(&self) -> u64 {
        self.sent().saturating_add(self.received())
    }
}
