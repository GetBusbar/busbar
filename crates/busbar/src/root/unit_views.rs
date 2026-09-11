// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VIEWS ONE UNIT IS RUN OVER, as the composition root fills them.
//!
//! The loop builds every unit's `Ctx` and it builds it from exactly this: the node's clock, the
//! configuration block a plugin may read, the session it belongs to, the transport stack under it,
//! its metric labels and the generation's key handle. None of those are the kernel's to know —
//! which configuration block belongs to which plane, which transports were composed under this
//! listener and which generation's material the stack was provisioned with are all facts the root
//! resolved at boot — so the kernel declares the bundle and the root fills it.
//!
//! **This is the one place a bundle is assembled.** Before it, the only `Ctx` in this tree was a
//! test's, built beside a leaking arena and a hand-written view per cell; there was no production
//! one because there was no production arena for it to be built around. There is now, so the
//! cells build theirs the way the node builds its own — same constructor, same views, same arena —
//! and a cell that drifted from the served path would have to change this file to do it.

use busbar_contract::{
    bounded::Labels,
    unit::{Clock, SessionView, TransportView},
    TransportKeyHandle,
};

/// The loop's own names, re-exported ONCE for the whole root.
///
/// A file that spelled the path itself would be one more place the root names the loop, and the
/// kind matrix counts exactly that. One spelling, here, beside the bundle they are used with.
pub use busbar_kernel::record::{UnitRecord, UnitViews};

/// The identity value the root fills and the loop is handed, re-exported for the cells that build
/// one by hand.
///
/// Test-only, because that is who needs the NAME: the four production sites that drive the loop
/// build one inline and already name the loop for other reasons, so a re-export they do not use
/// would be an unused import in the shipped binary rather than a convenience.
#[cfg(any(test, feature = "test-harness"))]
pub use busbar_kernel::teller::UnitCtx;

/// The transport stack under one unit, as the root composed it.
///
/// The key names the TOP transport — the one that decoded the arrival — and the chain is the
/// composed stack bottom layer first, which is the order the node built it in and the order an
/// audit record reads it back in. Both are static: a stack is composed at boot and a unit runs
/// under the one it arrived on.
#[derive(Debug)]
pub struct StackView {
    key: &'static str,
    chain: &'static [&'static str],
}

impl StackView {
    /// The stack a unit arrived on: its top transport and the layers under it.
    #[must_use]
    pub fn new(key: &'static str, chain: &'static [&'static str]) -> Self {
        StackView { key, chain }
    }
}

impl TransportView for StackView {
    fn key(&self) -> &'static str {
        self.key
    }

    fn chain(&self) -> &[&'static str] {
        self.chain
    }

    fn fact(&self, _key: &str) -> Option<&str> {
        // Transport facts are written at accept, dial, upgrade and handoff, into the session's own
        // kernel-owned map — which is what `SessionView::transport_fact` reads. A one-shot unit has
        // no session and therefore no map, and answering from anywhere else here would be this view
        // inventing a fact the transport never wrote.
        None
    }
}

/// THE CONFIGURATION BLOCK ONE PLANE MAY READ, as the root resolved it.
///
/// A plugin reads its own block and nothing else, and this is the whole of it: the pairs the
/// composition root put in. There is no path from here to another plugin's configuration, to
/// policy or to a secret, because there is nothing here BUT the pairs.
///
/// An EMPTY block is an answer and not a stand-in for one. A deployment that declared no block for
/// a plane has nothing to hand it, and every key answering `None` is exactly what "nothing was
/// declared" means — where a view that invented values would be a plane reading configuration
/// nobody wrote.
#[derive(Debug, Default)]
pub struct Block {
    entries: Vec<(String, Setting)>,
}

/// One resolved configuration value, in the three shapes the view answers in.
#[derive(Debug)]
pub enum Setting {
    /// A string value.
    Text(String),
    /// A whole-number value.
    Number(i64),
    /// A flag.
    Flag(bool),
}

impl Block {
    /// The block a deployment declared, as resolved pairs.
    #[must_use]
    pub fn new(entries: Vec<(String, Setting)>) -> Self {
        Block { entries }
    }

    fn get(&self, key: &str) -> Option<&Setting> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

impl busbar_contract::unit::ConfigView for Block {
    fn get_str(&self, key: &str) -> Option<&str> {
        match self.get(key) {
            Some(Setting::Text(s)) => Some(s),
            _ => None,
        }
    }

    fn get_int(&self, key: &str) -> Option<i64> {
        match self.get(key) {
            Some(Setting::Number(n)) => Some(*n),
            _ => None,
        }
    }

    fn get_bool(&self, key: &str) -> Option<bool> {
        match self.get(key) {
            Some(Setting::Flag(b)) => Some(*b),
            _ => None,
        }
    }
}

/// THE VIEWS ONE LISTENER'S UNITS ARE RUN OVER, assembled once and lent per unit.
///
/// Held by whatever drives the loop — one per listener, not one per unit — because every part of it
/// is a fact about the composition rather than about the request. What varies per unit is what
/// [`views`](UnitViewSet::views) takes: the clock reading, the session and the handle.
#[derive(Debug)]
pub struct UnitViewSet {
    config: Block,
    transport: StackView,
    labels: Labels<'static>,
    booted: std::time::Instant,
}

impl UnitViewSet {
    /// The bundle for one listener: what a plugin may read, and the stack it reads it under.
    #[must_use]
    pub fn new(config: Block, transport_key: &'static str, chain: &'static [&'static str]) -> Self {
        UnitViewSet {
            config,
            transport: StackView::new(transport_key, chain),
            labels: Labels::new(),
            booted: std::time::Instant::now(),
        }
    }

    /// THE NODE'S CLOCK, read once per unit, here.
    ///
    /// A plane is pure over its inputs and time is an input, so it arrives through the context
    /// rather than out of the machine — which is what `unit-no-wall-clock` holds every unit crate
    /// to. The rule stops at the composition root because somebody has to read the machine's clock,
    /// and this is the layer that does: once, at the top, into a value the steps read.
    #[must_use]
    pub fn clock(&self) -> Clock {
        Clock {
            unix_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |since| since.as_secs()),
            monotonic_nanos: self.booted.elapsed().as_nanos(),
        }
    }

    /// Lend the bundle to one unit.
    ///
    /// The key handle is offered, never snapshotted: the loop PINS it at Verify, from the
    /// generation the unit started on, so a unit finishes against the material it started with
    /// while a reload installs a replacement.
    #[must_use]
    pub fn views<'v>(
        &'v self,
        clock: Clock,
        session: Option<&'v dyn SessionView>,
        key_handle: Option<&'v TransportKeyHandle>,
    ) -> UnitViews<'v> {
        UnitViews {
            clock,
            config: &self.config,
            session,
            transport: &self.transport,
            labels: &self.labels,
            key_handle,
        }
    }
}
