//! The scaffolding one plane call needs, and nothing more.
//!
//! A plane is handed a context carrying one resource — the arena — and a handful of borrowed
//! read-only views. Everything below is the smallest honest stand-in for each, mirrored from
//! `busbar-plane-a2a`'s own `tests/common/mod.rs`: an arena that hands out bytes, views that answer
//! what they were told to answer, and a seal that lets a test build the kernel-owned values the
//! loop would otherwise build.

#![allow(dead_code)]

use busbar_contract::bounded::{
    Labels, PlaneAlloc, PlaneAllocBudget, ScratchBytes, SlabBytes, Span,
};
use busbar_contract::ids::{PrincipalId, SessionId};
use busbar_contract::unit::{Clock, ConfigView, Ctx, SessionView, TransportView};
use busbar_contract::wire::{Direction, Frame, FrameMeta};
use std::sync::atomic::{AtomicUsize, Ordering};

/// An arena that hands out bytes and counts what it handed out.
pub struct TestPlaneAlloc {
    used: AtomicUsize,
    ceiling: usize,
}

impl TestPlaneAlloc {
    pub fn new() -> Self {
        Self {
            used: AtomicUsize::new(0),
            ceiling: busbar_contract::bounded::SCRATCH_BASE_BYTES,
        }
    }
}

impl Default for TestPlaneAlloc {
    fn default() -> Self {
        Self::new()
    }
}

impl PlaneAlloc for TestPlaneAlloc {
    fn alloc_bytes<'a>(&'a self, src: &[u8]) -> Result<ScratchBytes<'a>, PlaneAllocBudget> {
        let remaining = self
            .ceiling
            .saturating_sub(self.used.load(Ordering::Relaxed));
        if src.len() > remaining {
            return Err(PlaneAllocBudget {
                wanted: src.len(),
                remaining,
            });
        }
        self.used.fetch_add(src.len(), Ordering::Relaxed);
        let leaked: &'static [u8] = Box::leak(src.to_vec().into_boxed_slice());
        Ok(ScratchBytes::new(leaked))
    }

    fn alloc_str<'a>(&'a self, src: &str) -> Result<&'a str, PlaneAllocBudget> {
        let remaining = self
            .ceiling
            .saturating_sub(self.used.load(Ordering::Relaxed));
        if src.len() > remaining {
            return Err(PlaneAllocBudget {
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
    ) -> Result<&'a [(&'a str, Span)], PlaneAllocBudget> {
        let wanted = std::mem::size_of_val(src);
        let remaining = self
            .ceiling
            .saturating_sub(self.used.load(Ordering::Relaxed));
        if wanted > remaining {
            return Err(PlaneAllocBudget { wanted, remaining });
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

/// A transport that answers with the path/verb it was given.
pub struct TestTransport {
    pub key: &'static str,
    pub chain: Vec<&'static str>,
    pub path: Option<String>,
    pub method: Option<String>,
}

impl TestTransport {
    pub fn new(key: &'static str) -> Self {
        Self {
            key,
            chain: vec![key],
            path: None,
            method: None,
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
            return self.path.as_deref();
        }
        if key == busbar_contract::transport::facts::METHOD {
            return self.method.as_deref();
        }
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
    pub fn new() -> Self {
        Self {
            id: SessionId(1),
            bound: false,
            facts: Vec::new(),
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

/// The blessed TEST seal (#65). `KernelSeal` is SEALED — no crate outside `busbar-contract` can
/// implement it — so a fixture names the contract's own `test-seal` type instead of forging one.
/// The type system stops a plugin now, not the manifest allow-list alone.
pub use busbar_contract::plugin::TestKernelSeal as TestSeal;

/// A clock frozen at a readable instant.
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
    pub arena: TestPlaneAlloc,
    pub config: EmptyConfig,
    pub transport: TestTransport,
    pub session: TestSession,
    pub labels: Labels<'static>,
}

impl Scaffold {
    pub fn new(transport: &'static str) -> Self {
        Self {
            arena: TestPlaneAlloc::new(),
            config: EmptyConfig,
            transport: TestTransport::new(transport),
            session: TestSession::new(),
            labels: Labels::new(),
        }
    }

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

    /// The same scaffold, over a stack that saw this request verb.
    #[must_use]
    pub fn with_method(mut self, method: &str) -> Self {
        self.transport.method = Some(method.to_string());
        self
    }

    /// The same scaffold, over a stack that saw this request target.
    #[must_use]
    pub fn on_path(mut self, path: &str) -> Self {
        self.transport.path = Some(path.to_string());
        self
    }
}

/// A principal, for the units a test builds.
pub fn principal() -> PrincipalId {
    PrincipalId::new("test-principal")
}

/// A sealed upstream destination, for the calls that take one.
pub fn sealed_destination() -> busbar_contract::dest::VerifiedDestination {
    let seal = TestSeal;
    busbar_contract::dest::VerifiedDestination::seal(
        &seal,
        busbar_contract::dest::DestinationFacts::Upstream {
            transport: "http",
            address: busbar_contract::UpstreamAddress::socket("api.typesafe.ai"),
            lane: busbar_contract::ids::LaneId::new("standard"),
        },
        "http",
        None,
    )
}
