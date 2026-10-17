// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE IMAGE'S WORD INTERNER: the one place a configured string becomes a `&'static str` key
//! ([`Registration`]), its ceiling ([`MAX_VOCABULARY`]) and its one-way freeze. It is the kernel's
//! because it is process state: `busbar-contract` holds no `static`, `OnceLock`, `LazyLock` or
//! `thread_local` outside tests (THE DESIGN A.8 "Statelessness", `BUSBAR-1.6.0.md` l.3701; gate
//! `contract-stateless`), and the contract's types it hands out ([`LaneId`], [`MeterClassId`])
//! are plain borrowed names.

use busbar_contract::{LaneId, MeterClassId};

/// How many distinct keys one image may ever intern.
///
/// The freeze below is what a composition root does. This is what holds where there is no
/// composition root to do it: a test binary, a bench or a fuzz target, which has no boot phase. In
/// each of those the freeze never happens, and this ceiling is the whole bound. (A plugin never
/// holds a vocabulary: its closure is `busbar-contract`, which holds no static — THE DESIGN A.8,
/// `BUSBAR-1.6.0.md` l.3701, gate `contract-stateless` — so the interner is the kernel's.)
///
/// Sized for configuration, not for traffic: it is every open-vocabulary category a plugin may
/// declare against, summed across every kind of plugin key, for a deployment far larger than any
/// that has been configured. A node that reaches it has a defect, not a big configuration.
pub const MAX_VOCABULARY: usize = 4096;

/// The image's one vocabulary, and whether it is still open.
///
/// A `static` rather than state on the registration value because the LEAKED STRINGS are the
/// resource and the resource is process-wide. Ownership of a registration value bounds nothing:
/// the value is constructible by anyone, so a bound that lives inside one instance is a bound per
/// instance, which is no bound at all against a caller that makes a fresh instance per request.
static VOCABULARY: std::sync::LazyLock<std::sync::Mutex<std::collections::HashSet<&'static str>>> =
    std::sync::LazyLock::new(|| std::sync::Mutex::new(std::collections::HashSet::new()));
static FROZEN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The one place a configured string becomes a declared key.
///
/// Every identifier on this surface is a borrowed static string, because the declarations that
/// carry them are associated constants and a constant cannot own a heap allocation. But lanes,
/// hosts, dialects and other plugin-declared identifiers are CONFIGURED: they are read at boot,
/// and a value read at boot is not static on its own. Something has to bridge those two facts, and
/// until now nothing named what — so every plane coped with a const table the composition root was
/// expected to seal somehow, and one transport leaked a fresh string on every dial, which is a leak
/// per request.
///
/// This is that bridge, and it is the composition root's. The root builds one of these at boot,
/// interns every config-derived open-vocabulary key through it, and hands the resulting static
/// names to the registrations that declare them. The set is finite because configuration is finite;
/// it is leaked ONCE because interning is idempotent; and its size is a fixed term of the node's
/// resident memory rather than a term that grows with traffic. Nothing outside registration may
/// intern: a key minted per unit would be exactly the leak this replaces.
///
/// ## How "nothing outside registration" is held
///
/// First by where it lives: the kernel, which no plugin can name (a plugin's closure is
/// `busbar-contract` alone, Part 2 #40(a)). Then, inside the host, not by who owns this value: it
/// is constructible by any host crate, and it has to be, for their own tests. What holds instead is
/// that the resource being spent — leaked `&'static str` — is process-wide, so the bound is
/// process-wide too. Every registration in one image reads and writes ONE vocabulary. The
/// composition root fills it at boot and calls [`freeze`](Self::freeze); after that, [`key`] is a
/// LOOKUP: a name the root registered still resolves, from anywhere, and a name it did not is
/// refused. A plane that holds a registration of its own and asks for a name it took off a request
/// gets `None`, having allocated nothing, no matter how many registrations it makes.
///
/// The refusal is returned as a value and never raised as a panic, because the name that reaches it
/// is client-supplied: a panic there is a way for a request to stop the node, which is a worse
/// failure than the leak being closed. And [`MAX_VOCABULARY`] bounds an image whose freeze never
/// happens at all, which is every image that has no composition root in it.
///
/// [`key`]: Self::key
#[derive(Debug, Default)]
pub struct Registration {
    interned: std::collections::HashSet<&'static str>,
}

impl Registration {
    /// A registration with nothing interned yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The static name for one configured key: interned if the vocabulary is open, resolved if it
    /// is already there, and refused otherwise.
    ///
    /// Idempotent: asking twice yields the same name and leaks once. `None` says the key is not in
    /// this image's vocabulary and cannot be added to it — because boot is over, or because the
    /// ceiling is reached — which is a refusal to route on that name, not an error to recover from.
    pub fn key(&mut self, value: &str) -> Option<&'static str> {
        let mut vocabulary = VOCABULARY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let found = if let Some(existing) = vocabulary.get(value) {
            *existing
        } else if FROZEN.load(std::sync::atomic::Ordering::Acquire)
            || vocabulary.len() >= MAX_VOCABULARY
        {
            return None;
        } else {
            let leaked: &'static str = Box::leak(value.to_owned().into_boxed_str());
            vocabulary.insert(leaked);
            leaked
        };
        drop(vocabulary);
        self.interned.insert(found);
        Some(found)
    }

    /// The [`LaneId`] for one configured lane name.
    ///
    /// The priced axis is declared as a borrowed static name and a configured lane's name is read
    /// at boot, so something has to bridge the two — and the bridge is this one, not a second id
    /// type that owns its string. An owned lane id would double the type every rate-card key, every
    /// verified destination and every locator comparison is written in, for one configured value;
    /// interning keeps the axis one `Copy` name and pays a fixed registration-time allocation for
    /// it. Refuses for the same reasons [`key`](Self::key) does: a lane nobody registered is not a
    /// lane this node routes to.
    pub fn lane(&mut self, name: &str) -> Option<LaneId> {
        self.key(name).map(LaneId::new)
    }

    /// The static name the vocabulary already holds for `value`, or `None`. A LOOKUP ONLY, open
    /// vocabulary or closed: it never interns, so it is the one form a per-unit path may call with a
    /// name the unit reported. Boot and config registration are what put a name here.
    #[must_use]
    pub fn resolve(value: &str) -> Option<&'static str> {
        VOCABULARY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(value)
            .copied()
    }

    /// [`Self::resolve`] as the [`MeterClassId`] a usage line carries: a class the vocabulary holds
    /// resolves, and a class nobody declared or configured does not.
    #[must_use]
    pub fn meter_class(value: &str) -> Option<MeterClassId> {
        Self::resolve(value).map(MeterClassId::new)
    }

    /// Close the image's vocabulary. The composition root's last registration-time act.
    ///
    /// Idempotent, and one-way: there is no thaw, because a vocabulary that can be reopened is a
    /// vocabulary a request path can reopen. Calling it before the root has finished registering
    /// costs the node its own configured names and fails the boot loudly — which is the right shape
    /// for a first-party ordering mistake, and is not something a request can cause.
    pub fn freeze() {
        FROZEN.store(true, std::sync::atomic::Ordering::Release);
    }

    /// Whether the vocabulary has been closed.
    #[must_use]
    pub fn is_frozen() -> bool {
        FROZEN.load(std::sync::atomic::Ordering::Acquire)
    }

    /// How many distinct keys this IMAGE has interned.
    ///
    /// The fixed resident-memory term is counted from here, so it is readable rather than inferred,
    /// and it is the process's count rather than one registration's because the leak is the
    /// process's.
    #[must_use]
    pub fn interned() -> usize {
        VOCABULARY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// How many distinct keys this registration has resolved.
    #[must_use]
    pub fn len(&self) -> usize {
        self.interned.len()
    }

    /// Whether this registration has resolved nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.interned.is_empty()
    }
}
