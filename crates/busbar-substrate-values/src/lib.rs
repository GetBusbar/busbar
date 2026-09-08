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

    /// HOW A PLANE'S MESSAGES ARE FRAMED — the DIALECT axis, and deliberately not the transport one.
    ///
    /// This is the half that used to be spelled as variants of `transport::Transport`, beside `Http`
    /// and `Stdio`, and the two do not belong in one closed set. A channel is what carries bytes; a
    /// framing is what the bytes are shaped as once they arrive. A2A makes the difference impossible
    /// to ignore: its JSON-RPC and HTTP+JSON bindings ride the SAME HTTP channel, over the same
    /// socket, at the same path, and differ only in whether a body member or the request line names
    /// the operation. One enum holding `Http` next to `JsonRpc` cannot say that, because it makes
    /// "which socket" and "which vocabulary" the same kind of word — which is the exact shape the
    /// owner ruling calls a plane-transport.
    ///
    /// It lives HERE, with the three wire-format names, because a framing is something a PLANE
    /// declares about itself. The three named framings are exactly the three names above, and
    /// [`WireFraming::Native`] is the honest fourth: the plane's own body, undeclared on this axis.
    /// Adding a framing is a change to this enum and touches no transport; adding a channel is a
    /// change to `transport::TransportFamily` and touches no framing.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub enum WireFraming {
        /// THE PLANE'S OWN BODY, undeclared on this axis. What rides an ordinary POST to a plane, a
        /// streamable-HTTP `/mcp` exchange, an MCP stdio pipe or an open duplex socket: the channel
        /// carries whatever the plane's codec wrote, and nothing here declares what that is.
        ///
        /// Not "no framing" — a framing this axis does not name. The distinction matters because the
        /// three below exist only where an outside instrument scores the framings of ONE channel as
        /// separate legs, and nothing scores a plane's own body that way.
        Native,
        /// A JSON-RPC 2.0 ENVELOPE — `{jsonrpc, id, method, params}`, where a BODY MEMBER names the
        /// operation. A2A's `JSONRPC` binding, and the leg its conformance instrument reports as
        /// `jsonrpc:`. Labelled [`WIRE_JSONRPC`].
        JsonRpc,
        /// A2A'S HTTP+JSON BINDING — the same exchange with THE REQUEST LINE naming the operation
        /// instead of a body member: `POST /message:send` rather than `{"method":"SendMessage"}`.
        /// A2A section 11.3 makes the REST body the JSON-RPC `params` verbatim and the REST success
        /// body the `result` verbatim, which is why arming it is re-framing and not translation.
        /// Labelled [`WIRE_HTTP_JSON`].
        HttpJson,
        /// A LENGTH-PREFIXED PROTOBUF FRAME, transcoded to and from the codec's JSON wire, and
        /// terminated with a `grpc-status` trailer rather than an HTTP status. Labelled
        /// [`WIRE_GRPC`] — the one place a framing name and a channel name coincide, which is a fact
        /// about the gRPC specification and not a reason to fuse the axes.
        Proto,
    }

    impl WireFraming {
        /// Every framing, so a site that must cover all of them cannot silently cover some.
        pub const ALL: &'static [WireFraming] = &[
            WireFraming::Native,
            WireFraming::JsonRpc,
            WireFraming::HttpJson,
            WireFraming::Proto,
        ];

        /// The wire-format name a plane declares this framing as, or `None` for the plane's own
        /// body — which has no name on this axis because the plane never declared one.
        ///
        /// Read from the three constants above rather than spelled again, so the metric label, the
        /// plane's `wire_format_names` list and the `protocolBinding` a served agent card advertises
        /// stay one vocabulary instead of three that happen to agree today.
        #[must_use]
        pub fn wire_format_name(self) -> Option<&'static str> {
            match self {
                WireFraming::Native => None,
                WireFraming::JsonRpc => Some(WIRE_JSONRPC),
                WireFraming::HttpJson => Some(WIRE_HTTP_JSON),
                WireFraming::Proto => Some(WIRE_GRPC),
            }
        }
    }
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
#[path = "tests/lib.rs"]
mod warn_capture_gate_tests;
