//! The scaffolding one plane call needs, and nothing more.
//!
//! Copied in shape from `busbar-plane-a2a`/`busbar-plane-mcp`'s own `tests/common/mod.rs`: a plane
//! is handed a context carrying one resource — the arena — and a handful of borrowed read-only
//! views. Everything below is the smallest honest stand-in for each: an arena that hands out bytes,
//! views that answer what they were told to answer, and a seal that lets a test build the
//! kernel-owned values the loop would otherwise build.
//!
//! The one addition this plane's scaffold needs over its siblings' is a transport that can publish
//! the `path` fact ([`busbar_contract::transport::facts::PATH`]): this plane's one-shot decode step
//! (`decode_one_shot`) reads it to pick which of the two one-shot dialects (`transcribe`, `tts`) a
//! request is, and a scaffold that always answered `None` could never reach that path at all.

#![allow(dead_code)]

use busbar_contract::bounded::{Arena, ArenaBudget, ArenaBytes, Labels, SlabBytes, Span};
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

    fn alloc_spans<'a>(
        &'a self,
        src: &[(&'a str, Span)],
    ) -> Result<&'a [(&'a str, Span)], ArenaBudget> {
        let wanted = std::mem::size_of_val(src);
        let remaining = self
            .ceiling
            .saturating_sub(self.used.load(Ordering::Relaxed));
        if wanted > remaining {
            return Err(ArenaBudget { wanted, remaining });
        }
        self.used.fetch_add(wanted, Ordering::Relaxed);
        Ok(Box::leak(src.to_vec().into_boxed_slice()))
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

/// A transport that answers with the key it was given, and optionally publishes a `path` fact.
///
/// The `path` fact is this plane's own dispatch key for a one-shot request (see
/// [`busbar_contract::transport::facts::PATH`], read by `decode_one_shot` in `src/plane.rs`); every
/// other fact answers `None`, exactly as the sibling planes' scaffolds do.
pub struct TestTransport {
    pub key: &'static str,
    pub chain: Vec<&'static str>,
    pub path: Option<&'static str>,
}

impl TestTransport {
    /// A transport stack of one named layer, publishing no facts.
    pub fn new(key: &'static str) -> Self {
        Self {
            key,
            chain: vec![key],
            path: None,
        }
    }

    /// The same transport, publishing a `path` fact — the shape a one-shot HTTP request arrives
    /// under.
    pub fn with_path(key: &'static str, path: &'static str) -> Self {
        Self {
            key,
            chain: vec![key],
            path: Some(path),
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
    fn fact(&self, key: &str) -> Option<&str> {
        if key == busbar_contract::transport::facts::PATH {
            self.path
        } else {
            None
        }
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
            status_code: None,
            retry_after_secs: None,
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
    /// A scaffold over one named transport, publishing no `path` fact.
    pub fn new(transport: &'static str) -> Self {
        Self {
            arena: TestArena::new(),
            config: EmptyConfig,
            transport: TestTransport::new(transport),
            session: TestSession::new(),
            labels: Labels::new(),
        }
    }

    /// A scaffold over one named transport, publishing the given `path` fact — the shape this
    /// plane's one-shot decode step dispatches on.
    pub fn with_path(transport: &'static str, path: &'static str) -> Self {
        Self {
            arena: TestArena::new(),
            config: EmptyConfig,
            transport: TestTransport::with_path(transport, path),
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

    /// The same context, with the wall-clock reading chosen by the caller.
    ///
    /// A test that asks whether an answer moves with the clock needs two readings to hand over;
    /// every other test wants the one frozen reading [`Self::ctx`] supplies.
    pub fn ctx_at(&self, unix_secs: u64) -> Ctx<'_> {
        Ctx::new(
            Clock {
                unix_secs,
                monotonic_nanos: CLOCK.monotonic_nanos,
            },
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
