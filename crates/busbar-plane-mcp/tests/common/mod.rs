//! The scaffolding one plane call needs, and nothing more.
//!
//! A plane is handed a context carrying one resource — the arena — and a handful of borrowed
//! read-only views. Everything below is the smallest honest stand-in for each: an arena that hands
//! out bytes, views that answer what they were told to answer, and a seal that lets a test build the
//! kernel-owned values the loop would otherwise build.
//!
//! The seal deserves a sentence. The contract's kernel-side values take a reference to a seal so a
//! plugin cannot fabricate its own evidence, and the contract says out loud that the trait is public
//! and that what really stops a plugin implementing it is the manifest allow-list rather than the
//! type system. A TEST implementing it is exactly the case that admission contemplates: nothing here
//! ships, and a test that could not build a unit could not call the methods that take one.

#![allow(dead_code)]

use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Labels, SlabBytes};
use busbar_contract::ids::{PrincipalId, SessionId};
use busbar_contract::plugin::KernelSeal;
use busbar_contract::unit::{Clock, ConfigView, Ctx, SessionView, TransportView};
use busbar_contract::wire::{Direction, Frame, FrameMeta};
use std::sync::atomic::{AtomicUsize, Ordering};

/// An arena that hands out bytes and counts what it handed out.
///
/// It leaks rather than reusing a buffer, which is the right trade for a test: the real arena
/// resets per unit, and a test that had to model the reset would be testing the arena rather than
/// the plane.
pub struct TestArena {
    used: AtomicUsize,
    ceiling: usize,
}

impl TestArena {
    /// An arena with the contract's own per-unit ceiling.
    pub fn new() -> Self {
        Self {
            used: AtomicUsize::new(0),
            ceiling: busbar_contract::bounded::ARENA_BYTES,
        }
    }

    /// An arena that runs out after a given number of bytes.
    pub fn with_ceiling(ceiling: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            ceiling,
        }
    }
}

impl Default for TestArena {
    fn default() -> Self {
        Self::new()
    }
}

impl Arena for TestArena {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ArenaBytes<'a>, ArenaBudget> {
        let remaining = self
            .ceiling
            .saturating_sub(self.used.load(Ordering::Relaxed));
        if src.len() > remaining {
            return Err(ArenaBudget {
                wanted: src.len(),
                remaining,
            });
        }
        self.used.fetch_add(src.len(), Ordering::Relaxed);
        let leaked: &'static [u8] = Box::leak(src.to_vec().into_boxed_slice());
        Ok(ArenaBytes::new(leaked))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, ArenaBudget> {
        let remaining = self
            .ceiling
            .saturating_sub(self.used.load(Ordering::Relaxed));
        if src.len() > remaining {
            return Err(ArenaBudget {
                wanted: src.len(),
                remaining,
            });
        }
        self.used.fetch_add(src.len(), Ordering::Relaxed);
        let leaked: &'static str = Box::leak(src.to_string().into_boxed_str());
        Ok(leaked)
    }

    fn remaining(&self) -> usize {
        self.ceiling
            .saturating_sub(self.used.load(Ordering::Relaxed))
    }
}

/// A configuration block with nothing in it.
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

/// A transport that answers with the key it was given.
pub struct TestTransport {
    pub key: &'static str,
    pub chain: Vec<&'static str>,
}

impl TestTransport {
    /// A transport stack of one named layer.
    pub fn new(key: &'static str) -> Self {
        Self {
            key,
            chain: vec![key],
        }
    }
}

impl TransportView for TestTransport {
    fn key(&self) -> &'static str {
        self.key
    }
    fn chain(&self) -> &[&'static str] {
        &self.chain
    }
    fn fact(&self, _key: &str) -> Option<&str> {
        None
    }
}

/// A session that answers what it was told to answer.
pub struct TestSession {
    pub id: SessionId,
    pub bound: bool,
    pub facts: Vec<(&'static str, String)>,
}

impl TestSession {
    /// An unbound session with no facts.
    pub fn new() -> Self {
        Self {
            id: SessionId(1),
            bound: false,
            facts: Vec::new(),
        }
    }

    /// The same session, bound.
    pub fn bound() -> Self {
        Self {
            bound: true,
            ..Self::new()
        }
    }
}

impl Default for TestSession {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionView for TestSession {
    fn id(&self) -> SessionId {
        self.id
    }
    fn is_bound(&self) -> bool {
        self.bound
    }
    fn session_fact(&self, key: &str) -> Option<&str> {
        self.facts
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }
    fn transport_fact(&self, _key: &str) -> Option<&str> {
        None
    }
    fn upstream_count(&self) -> usize {
        0
    }
}

/// The seal a test presents to build the values the kernel would build.
pub struct TestSeal;

impl KernelSeal for TestSeal {
    fn seal_origin(&self) -> &'static str {
        "test"
    }
}

/// A clock frozen at a readable instant, so nothing here varies with when it ran.
pub const CLOCK: Clock = Clock {
    unix_secs: 1_700_000_000,
    monotonic_nanos: 0,
};

/// One inbound frame carrying a document.
pub fn frame(bytes: &[u8]) -> Frame {
    Frame {
        direction: Direction::Inbound,
        stream: busbar_contract::ids::StreamId(0),
        bytes: SlabBytes::new(std::sync::Arc::from(bytes.to_vec().into_boxed_slice())),
        meta: FrameMeta {
            bytes: bytes.len() as u64,
            transport_units: None,
            status: None,
        },
    }
}

/// One outbound frame carrying a document.
pub fn response_frame(bytes: &[u8]) -> Frame {
    Frame {
        direction: Direction::Outbound,
        ..frame(bytes)
    }
}

/// Everything a context borrows, held together so a test can build one.
pub struct Scaffold {
    pub arena: TestArena,
    pub config: EmptyConfig,
    pub transport: TestTransport,
    pub session: TestSession,
    pub labels: Labels<'static>,
}

impl Scaffold {
    /// A scaffold over one named transport.
    pub fn new(transport: &'static str) -> Self {
        Self {
            arena: TestArena::new(),
            config: EmptyConfig,
            transport: TestTransport::new(transport),
            session: TestSession::new(),
            labels: Labels::new(),
        }
    }

    /// The context itself.
    pub fn ctx(&self) -> Ctx<'_> {
        Ctx::new(
            CLOCK,
            &self.config,
            Some(&self.session),
            &self.transport,
            &self.labels,
            &self.arena,
        )
    }

    /// A context with no session, as a one-shot transport hands one over.
    pub fn ctx_without_session(&self) -> Ctx<'_> {
        Ctx::new(
            CLOCK,
            &self.config,
            None,
            &self.transport,
            &self.labels,
            &self.arena,
        )
    }
}

/// A principal, for the units a test builds.
pub fn principal() -> PrincipalId {
    PrincipalId::new("test-principal")
}
