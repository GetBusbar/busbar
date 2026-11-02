// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::{LaneId, MeterClassId};

pub const MAX_VOCABULARY: usize = 4096;

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
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

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

    pub fn lane(&mut self, name: &str) -> Option<LaneId> {
        self.key(name).map(LaneId::new)
    }

    #[must_use]
    pub fn resolve(value: &str) -> Option<&'static str> {
        VOCABULARY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(value)
            .copied()
    }

    #[must_use]
    pub fn meter_class(value: &str) -> Option<MeterClassId> {
        Self::resolve(value).map(MeterClassId::new)
    }

    pub fn freeze() {
        FROZEN.store(true, std::sync::atomic::Ordering::Release);
    }

    #[must_use]
    pub fn is_frozen() -> bool {
        FROZEN.load(std::sync::atomic::Ordering::Acquire)
    }

    #[must_use]
    pub fn interned() -> usize {
        VOCABULARY
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.interned.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.interned.is_empty()
    }
}
