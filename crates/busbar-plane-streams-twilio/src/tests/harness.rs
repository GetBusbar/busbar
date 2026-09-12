//! The smallest thing that can call the plane this dialect belongs to.
//!
//! A COPY of that plane's own test harness, trimmed to what these cells use: an arena, a clock, a
//! configuration view, a transport view and a label set. It is copied rather than shared because
//! the alternative is the plane taking a dev-dependency on this crate — the plane naming a dialect,
//! which is the one edge the kind gate says can never exist. Nothing here is shipped.
use busbar_plane_streams::dialect::Dialect;

use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Labels, SlabBytes, Span};
use busbar_contract::ids::{SessionId, StreamId};
use busbar_contract::unit::{Clock, ConfigView, Ctx, SessionView, TransportView};
use busbar_contract::wire::{Direction, Frame, FrameMeta};
use std::sync::Arc;

/// An arena that never reuses a byte — fine for a short test process.
#[derive(Debug, Default)]
pub struct LeakArena;

impl Arena for LeakArena {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ArenaBytes<'a>, ArenaBudget> {
        Ok(ArenaBytes::new(Box::leak(src.to_vec().into_boxed_slice())))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ArenaBudget> {
        Ok(Box::leak(src.to_string().into_boxed_str()))
    }

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], ArenaBudget> {
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
    }

    fn remaining(&self) -> usize {
        usize::MAX
    }
}

/// A configuration block with nothing in it.
#[derive(Debug, Default)]
pub struct EmptyConfig;

impl ConfigView for EmptyConfig {
    fn get_str(&self, _key: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

/// A transport stack that publishes a request target as a fact — the same convention
/// `busbar-plane-llm`'s harness uses for its own `path` fact.
#[derive(Debug)]
pub struct WsStack {
    path: String,
}

impl WsStack {
    /// A stack that saw this request target.
    #[must_use]
    pub fn new(path: &str) -> Self {
        Self {
            path: path.to_string(),
        }
    }
}

impl TransportView for WsStack {
    fn key(&self) -> &'static str {
        "ws"
    }
    fn chain(&self) -> &[&'static str] {
        &["tcp", "tls", "http", "ws"]
    }
    fn fact(&self, key: &str) -> Option<&str> {
        if key == "path" {
            Some(&self.path)
        } else {
            None
        }
    }
}

/// A session that reports zero paired upstreams, for the calls that take one.
///
/// Not yet used by a test in this crate (every current test drives `decode_ingress`/`decode_response`
/// through a bare `Ctx` with no session), kept as shared harness for the session-bound tests a future
/// pass adds — the same reason `busbar-plane-llm`'s own harness carries fixtures its current test
/// file does not all exercise yet.
#[allow(dead_code)]
#[derive(Debug)]
pub struct FreshSession;

impl SessionView for FreshSession {
    fn id(&self) -> SessionId {
        SessionId(0)
    }
    fn is_bound(&self) -> bool {
        true
    }
    fn session_fact(&self, _key: &str) -> Option<&str> {
        None
    }
    fn transport_fact(&self, _key: &str) -> Option<&str> {
        None
    }
    fn upstream_count(&self) -> usize {
        0
    }
}

/// Build a context over the pieces above.
#[must_use]
pub fn ctx<'u>(
    arena: &'u LeakArena,
    config: &'u EmptyConfig,
    transport: &'u WsStack,
    labels: &'u Labels<'u>,
) -> Ctx<'u> {
    Ctx::new(
        Clock {
            unix_secs: 1_772_000_000,
            monotonic_nanos: 0,
        },
        config,
        None,
        transport,
        labels,
        arena,
    )
}

/// One inbound frame carrying a whole wire event.
#[must_use]
pub fn frame(bytes: &[u8]) -> Frame {
    Frame {
        direction: Direction::Inbound,
        stream: StreamId(0),
        bytes: SlabBytes::new(Arc::from(bytes.to_vec().into_boxed_slice())),
        meta: FrameMeta::default(),
    }
}

/// AN UPSTREAM DIALECT THAT IS NOT A SIBLING, declared here.
///
/// These cells route a carrier session at an upstream, and the upstream speaks SOME dialect; which
/// one is not what any of them is about. They used to name the GA realtime row, which was a
/// `&'static` the neutral plane declared — and the day that dialect got a crate of its own, naming
/// it would have made this crate depend on a SIBLING DIALECT, which is the plane fusion one level
/// down and is refused. A row declared in this crate's own tests says exactly as much and depends
/// on no one.
pub static AN_UPSTREAM_DIALECT: Dialect = Dialect {
    name: "an-upstream-dialect",
    duplex_upstream: true,
    authenticates_from_session: true,
    meters_own_uplink: false,
    envelope: None,
    locked_session_config: None,
    reader: None,
    writer: None,
    credential_at: None,
    // A fixture row: this wire is client-speaks-first, so it owes no opening frame.
    opening_event: None,
    // A fixture row: no client event on this wire is one a caller blocks on.
    request_terminal: None,
};
