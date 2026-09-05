//! The smallest thing that can call a plane.
//!
//! The loop hands a plane an arena, a clock, a configuration view, a transport view and a label
//! set, and it hands the kernel-built values — a unit, a verified destination — through a seal. All
//! of that is here, at the minimum size that lets the plane be called for real. Nothing here is
//! shipped; it exists so the tests exercise the same entry points the kernel does rather than a
//! private back door.
//!
//! Each test binary includes this module and uses the part of it that it needs, so the unused-item
//! warning is turned off here rather than in each of them: an item unused by one test file is used
//! by another, and splitting the harness per file would mean maintaining several harnesses.

#![allow(dead_code)]

use busbar_contract::bounded::SlabBytes;
use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Ir, Labels};
use busbar_contract::dest::{DestinationFacts, VerifiedDestination};
use busbar_contract::ids::{LaneId, OpClassId, StreamId};
use busbar_contract::plugin::KernelSeal;
use busbar_contract::unit::{Clock, ConfigView, Ctx, Origin, TransportView, Unit};
use busbar_contract::wire::{Direction, Frame, FrameMeta};
use std::sync::Arc;

/// An arena that never reuses a byte.
///
/// The shipped arena is a bump allocator the kernel resets per unit; a test does not need the reset
/// and does need the borrow to outlive the call, so this one hands out memory it never reclaims.
/// A test process is short.
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

/// A configuration block with nothing in it, so every default is the declared one.
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

/// A transport stack that publishes a request target and a header set as facts.
#[derive(Debug)]
pub struct HttpStack {
    facts: Vec<(String, String)>,
}

impl HttpStack {
    /// A stack that saw this request target and these headers.
    #[must_use]
    pub fn new(path: &str, headers: &[(&str, &str)]) -> Self {
        let mut facts = vec![("path".to_string(), path.to_string())];
        for (name, value) in headers {
            facts.push(((*name).to_string(), (*value).to_string()));
        }
        Self { facts }
    }
}

impl TransportView for HttpStack {
    fn key(&self) -> &'static str {
        "http"
    }
    fn chain(&self) -> &[&'static str] {
        &["tcp", "tls", "http"]
    }
    fn fact(&self, key: &str) -> Option<&str> {
        self.facts
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// The marker the kernel-built constructors take.
///
/// A plugin cannot name the crate that provides the real one; a test is not a plugin, and it needs
/// a unit and a verified destination to hand the plane. The design says as much: what stops a
/// plugin fabricating one is the manifest allow-list, not the type system.
#[derive(Debug)]
pub struct TestSeal;

impl KernelSeal for TestSeal {
    fn seal_origin(&self) -> &'static str {
        "busbar-plane-llm tests"
    }
}

/// Build a context over the pieces above.
#[must_use]
pub fn ctx<'u>(
    arena: &'u LeakArena,
    config: &'u EmptyConfig,
    transport: &'u HttpStack,
    labels: &'u Labels<'u>,
) -> Ctx<'u> {
    Ctx::new(
        Clock {
            unix_secs: 1_752_000_000,
            monotonic_nanos: 0,
        },
        config,
        None,
        transport,
        labels,
        arena,
    )
}

/// One inbound frame carrying a whole body.
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
            transport: "http",
            host,
            lane,
        },
        "http",
        None,
    )
}

/// The request target that names each dialect on the detection ladder.
#[must_use]
pub fn path_for(dialect: &str) -> &'static str {
    match dialect {
        "anthropic" => "/v1/messages",
        "openai" => "/v1/chat/completions",
        "gemini" => "/v1beta/models/gemini-2.0-flash:generateContent",
        "bedrock" => "/model/claude/converse",
        "cohere" => "/v2/chat",
        "responses" => "/v1/responses",
        other => panic!("no request target is declared for the dialect {other}"),
    }
}
