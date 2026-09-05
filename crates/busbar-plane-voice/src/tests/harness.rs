//! The smallest thing that can call this plane.
//!
//! The same minimum-size harness `busbar-plane-llm`'s own (unused-so-far) test harness builds: an
//! arena, a clock, a configuration view, a transport view and a label set, plus the kernel-built
//! values (a unit, a verified destination) handed through a seal. Nothing here is shipped.

use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Ir, Labels, SlabBytes};
use busbar_contract::dest::{DestinationFacts, VerifiedDestination};
use busbar_contract::ids::{LaneId, OpClassId, SessionId, StreamId};
use busbar_contract::plugin::KernelSeal;
use busbar_contract::unit::{Clock, ConfigView, Ctx, Origin, SessionView, TransportView, Unit};
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

/// The marker the kernel-built constructors take. A test is not a plugin; what stops a plugin
/// fabricating one is the manifest allow-list, not the type system.
#[derive(Debug)]
pub struct TestSeal;

impl KernelSeal for TestSeal {
    fn seal_origin(&self) -> &'static str {
        "busbar-plane-voice tests"
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

/// A unit built the way the kernel builds one, over a decoded body.
#[must_use]
pub fn unit<'u>(op: OpClassId, body: Ir<'u>) -> Unit<'u> {
    Unit::new(
        &TestSeal,
        busbar_contract::UnitKey::new(1),
        Origin::Client,
        None,
        Some(StreamId(0)),
        Direction::Inbound,
        None,
        op,
        body,
        None,
    )
}

/// A destination sealed the way the trust unit seals one.
#[must_use]
pub fn destination(host: &'static str, lane: LaneId) -> VerifiedDestination {
    VerifiedDestination::seal(
        &TestSeal,
        DestinationFacts::Upstream {
            transport: "ws",
            host,
            lane,
        },
        "ws",
        None,
    )
}
