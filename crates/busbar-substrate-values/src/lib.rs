// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The PURE half of the busbar neutral substrate — the value families a codec or a plane NAMES.
//!
//! `busbar-substrate` used to hold two different things behind one name: these value types, and the
//! egress engine that dials upstreams. Because a plane is a pure kind, its WHOLE transitive closure
//! is scanned, and one whole-workspace `cargo metadata` unifies features — so no feature gate could
//! keep the engine out of a codec's closure while the two shared a crate. Splitting the name is what
//! splits the closure.
//!
//! WHAT LIVES HERE: the protocol declaration registry (`proto`), the cross-plane IR (`ir`), the
//! breaker taxonomy and classifier (`breaker`), the protocol handler matrix (`handlers`), the
//! billing / media / json / wire / eventstream / sigv4 / lossless vocabularies, the neutral
//! transport axis (`transport`), the diagnostics catalog and its emit macros, and the pure half of
//! `proxy` (the caps, the kind tokens, the capped read, the client-header mechanics).
//!
//! WHAT DOES NOT: anything whose closure opens something. The egress engine, the net guard, the
//! runtime hosts, the async doors and the axum-shaped response builders stay in `busbar-substrate`,
//! which depends on this crate and RE-EXPORTS every module below at its historical path — so
//! `busbar_substrate::proto::…` and every other old spelling still resolve, unchanged, for the
//! composed binary.

// The neutral coded-diagnostic catalog and the cross-crate emit macros (`diag_warn!`/`diag_error!`/
// `diag_debug!`, hoisted to this crate's ROOT by `#[macro_export]`). `busbar-substrate` re-exports
// both the module and the three macros so `busbar_substrate::diagnostics::…` and
// `busbar_substrate::diag_warn!` resolve exactly as before.
pub mod diagnostics;

// The five neutral transport/crypto utility leaves: JSON canonicalization + the depth-guarded parser
// seam, the base64/media-type helper, the AWS EventStream framing codec, the source-scoped
// lossless-extras namespace, and the hand-rolled SigV4 signer.
pub mod eventstream;
pub mod json;
pub mod lossless;
pub mod media;
pub mod sigv4;

/// The three WIRE-FORMAT NAMES the transport axis and the plane declaration share. The CUT: the rest
/// of `plane` is the declaration/registry surface, which names the host seams and the route mount and
/// therefore stays with them in `busbar-substrate` — but [`transport::Transport::name`] reads these
/// three constants (that is the whole point of them: one spelling for the metric label, the plane's
/// wire-format list and the served card's `protocolBinding`), so they crossed with the axis.
/// `busbar-substrate`'s own `plane` re-exports all three, so `busbar_substrate::plane::WIRE_JSONRPC`
/// and its siblings resolve unchanged.
pub mod plane {
    /// THE WIRE FORMAT both mounted planes speak: JSON-RPC 2.0. Named once, here, because it is read
    /// twice as a `wire_format_names` entry and once more by the error-shaping boundary, which
    /// decides that a refusal on a mounted plane is a JSON-RPC error object rather than a vendor
    /// envelope. A literal spelled per site is how those two answers start to differ.
    pub const WIRE_JSONRPC: &str = "jsonrpc";

    /// THE SECOND WIRE FORMAT THE A2A PLANE SPEAKS: A2A's HTTP+JSON binding, where the REQUEST LINE
    /// names the operation rather than a body member. Named once, here, because it is read three ways
    /// and all three must agree — as a `wire_format_names` entry, as the
    /// `busbar_core::transport::Transport::HttpJson` label, and (upper-cased by
    /// `a2a::serve::servable_bindings`) as the `protocolBinding` a served agent card advertises. The
    /// card spelling is `HTTP+JSON`, so this is that string lower-cased and nothing else.
    pub const WIRE_HTTP_JSON: &str = "http+json";

    /// The A2A specification's gRPC binding, as a wire-format name. Lower-case here and upper-cased
    /// once, by `busbar_core::a2a::serve::servable_bindings`, into the `GRPC` an agent card advertises
    /// — so the card cannot claim a binding the plane does not list, which is the whole reason that
    /// function reads this list rather than writing one of its own.
    pub const WIRE_GRPC: &str = "grpc";
}

// The value families the money path is written in.
pub mod billing;
pub mod breaker;
pub mod handlers;
pub mod ir;
pub mod proto;
pub mod transport;
pub mod wire;

// The PURE half of `proxy`: the two process-global body caps, the capped upstream-body read, the
// content-type / error-kind / disposition / transparency-header vocabularies, the neutral error
// envelope and the client-header capture/fold mechanics, plus the SSE frame reader. The three items
// that reach I/O — the `tokio` task-local RTT slot, the egress-client shim over the engine, and the
// axum-`Response` ingress-error shaper — stayed in `busbar-substrate` with the engine they name;
// that crate's `proxy` re-exports everything here beside them.
pub mod proxy;

/// THE WALL CLOCK the shared store reads. The CUT: the rest of `store` names `tokio::sync` (the
/// lane-availability taxonomy's semaphore-permit arm, the `lane_semaphore` accessor), while these two
/// are a pure `SystemTime` read a dialect writer calls on the response path for an omitted `created`
/// timestamp. So the clock crossed and the semaphore-shaped remainder stayed in `busbar-substrate`,
/// which re-exports both names from its own `store`.
pub mod store {
    /// Get current time in seconds since epoch. The shared wall clock both core and the plane crates
    /// read (the plane via the `clock_now` host seam long-term; this is the single implementation).
    pub fn now() -> u64 {
        let _t = busbar_timing::timeit!("store_now");
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// The same wall clock in MILLISECONDS — for the two sub-second callers (an operator TTL and the
    /// A2A task poll). `u64`, matching [`now`]: a duration since the epoch, never negative.
    #[cfg_attr(not(any(feature = "dispatch", feature = "relay")), allow(dead_code))]
    pub fn now_ms() -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }
}

/// The PURE half of `egress_auth`: the static API-key header builder, which is a total function of
/// its two arguments. The CUT: every other credential mechanism in that module mints over the
/// network (the RFC 7523 / RFC 6749 §4.4 token-endpoint POSTs) or reads a service-account key off
/// disk, so the module's remainder stayed in `busbar-substrate`, which re-exports this name at its
/// historical `busbar_substrate::egress_auth::api_key_headers` path.
pub mod egress_auth {
    use http::{HeaderName, HeaderValue};

    /// A static API key sent in a fixed header (`x-api-key`, `x-goog-api-key`, …). Delegates to the
    /// one header-building implementation in [`crate::proto`] so the refusal behaviour on a key that
    /// is not a legal header value has exactly one definition.
    pub fn api_key_headers(header: &'static str, key: &str) -> Vec<(HeaderName, HeaderValue)> {
        crate::proto::api_key_auth_headers(header, key)
    }
}

// The neutral warn-capture tracing Layer a plane's tests assert coded diagnostics through. Revealed
// only under the test surface, exactly as in the parent crate; `busbar-substrate`'s `testkit`
// re-exports this module so `busbar_substrate::testkit::warn_capture::WarnCapture` resolves.
#[cfg(any(test, feature = "test-support"))]
pub mod testkit {
    pub mod warn_capture;
}

// This crate's OWN relocated framing tests reach `WarnCapture` at this historical `test_support`
// path (how it was carried in the parent crate). It is a RE-EXPORT of `testkit::warn_capture`, not
// a second copy: two independent copies each minted their OWN process-global capture gate, so a
// `test_support` capture and a `testkit` capture never actually serialized against each other under
// `cargo test -p busbar-substrate-values` (which links both) — contradicting the one-gate invariant
// both files' docs state. One module, one gate.
#[cfg(test)]
mod test_support {
    pub use crate::testkit::warn_capture;
}

#[cfg(test)]
mod warn_capture_gate_tests {
    /// `test_support::warn_capture` and `testkit::warn_capture` were two byte-identical COPIES of
    /// the same `WarnCapture` layer, each with its OWN process-global serialization gate (see
    /// either module's docs). Both compile into `cargo test -p busbar-substrate-values`, so a
    /// `test_support` capture and a `testkit` capture never actually serialize against each
    /// other — contradicting both files' stated one-gate invariant. Prove it: hold a `test_support`
    /// capture on this thread, spawn a thread that constructs a `testkit` capture, and assert it
    /// BLOCKS until the first drops (a single shared gate), rather than acquiring immediately (two
    /// independent gates).
    #[test]
    fn test_support_and_testkit_share_one_capture_gate() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let held = crate::test_support::warn_capture::WarnCapture::default();
        let acquired = Arc::new(AtomicBool::new(false));
        let acquired_writer = acquired.clone();

        let handle = std::thread::spawn(move || {
            let _other = crate::testkit::warn_capture::WarnCapture::default();
            acquired_writer.store(true, Ordering::SeqCst);
        });

        // Give the spawned thread every chance to (wrongly) acquire immediately.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert!(
            !acquired.load(Ordering::SeqCst),
            "a testkit::WarnCapture acquired while a test_support::WarnCapture is still held — \
             the two are not sharing one process-global gate"
        );

        drop(held);
        handle.join().unwrap();
        assert!(
            acquired.load(Ordering::SeqCst),
            "the testkit::WarnCapture must acquire once the test_support::WarnCapture drops"
        );
    }
}
