// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The leak-once interner, and the rule that makes "once" a property of the type.
//!
//! An id, name or other open-vocabulary key that is only known at config time — a lane, a pool, a
//! model, a provider host, a dialect name, a configured plugin's key — becomes a `&'static str`
//! exactly once, by the composition root, at registration. Never per connection, per dial or per
//! call. The resulting allocation is fixed at registration and is a countable term in the node's
//! resident-memory budget; a leak anywhere else is a defect rather than a variant of the rule.
//!
//! ## Why the interner is wrapped rather than used directly
//!
//! `busbar_contract::Registration` is already idempotent, which gets "exactly once" for a key that
//! is interned twice. What it does not carry is *when*: nothing in its shape stops a request path
//! calling `key()` on the thousandth connection and leaking a fresh string every time. That is the
//! failure the rule is actually about, and it is a failure of ordering, not of duplication.
//!
//! [`Vocabulary`] adds the ordering. It interns during boot, is sealed once configuration has been
//! read, and refuses afterwards — in EVERY build. A `key()` call after the seal is a programming
//! mistake in the root: no operator input can cause one and there is no recovery that would make
//! sense, so the answer is to stop rather than to continue leaking. Enforcing it only where
//! `debug_assertions` are on would have made the seal a property of how the binary was compiled,
//! and would have left it unenforced in the one build whose resident memory anybody budgets.
//!
//! ## What goes through it
//!
//! Everything in [`ConfigKeys`], and nothing else. The list is written out as a struct rather than
//! assembled ad hoc at a dozen call sites, because the one thing a reader wants to know about this
//! rule is *which* keys it covers, and a list spread across the boot path cannot answer that.
//!
//! Four of the entries are the easiest to miss, because they are not identifiers: the egress-auth
//! scheme's header, access-key-id, region and service names; the trust unit's caller-facing text
//! naming what was asked for; the transport-key unit's slot fingerprint; and the admission unit's
//! window name. Each is a `&'static str` a unit requires and a value configuration supplies, which
//! is the whole definition of what this interner is for.
//!
//! ## Where the values come from
//!
//! [`ConfigKeys`] is the root's own view of the parsed configuration, not a re-parse of it. The
//! 1.5.5 document parse stays where it is and hands these lists over; naming them here means the
//! root's inputs are one readable list rather than a set of field accesses scattered through boot.
//! The step that switches a plane onto the root is what fills it from the resolved config.

use busbar_contract::Registration;
use std::collections::BTreeMap;

/// Every config-derived open-vocabulary key the root interns, in one list.
///
/// Empty is a valid value throughout: a deployment that configures no pool has no lane names, and a
/// zero-config boot interns nothing at all. That matters, because the fixed memory term is supposed
/// to be zero on a deployment that declared nothing.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ConfigKeys {
    /// Every configured lane name.
    pub lanes: Vec<String>,
    /// Every configured pool name.
    pub pools: Vec<String>,
    /// Every configured model name.
    pub models: Vec<String>,
    /// Every configured provider host.
    pub hosts: Vec<String>,
    /// Every dialect name the configuration spells out.
    pub dialects: Vec<String>,
    /// Every configured agent the agent plane fronts.
    pub agents: Vec<String>,
    /// Every registered tool server.
    pub servers: Vec<String>,
    /// Every dynamically loaded plugin's key, leaked once at load.
    pub plugin_keys: Vec<String>,
    /// The four egress-auth scheme fields: header, access-key id, region, service.
    pub egress_auth_fields: Vec<String>,
    /// The trust unit's caller-facing text naming what was asked for, per configured entry.
    pub unpriced_messages: Vec<String>,
    /// One fingerprint per provisioned transport-key slot.
    pub slot_fingerprints: Vec<String>,
    /// Every configured group name a principal can charge through.
    ///
    /// The door works in `String`s, because a group name is configuration and nothing else. What
    /// needs the static one is the kernel's reading of what the node is running: a lease per
    /// capped-`concurrent` group, recorded on the unit's slot and held for the life of the unit, in
    /// a vocabulary that outlives every request. This is where the two meet.
    pub groups: Vec<String>,
    /// Every window name a configured group bucket is declared over.
    pub bucket_windows: Vec<String>,
    /// Every meter class a configured bucket declares a cap or a price over.
    ///
    /// A meter class is open vocabulary in the strictest sense: the four token classes are the
    /// previous release's whole set and a migrated plane's classes are whatever its own configuration
    /// names. The unit counts them under a `&'static str`, so a class discovered at a rate lookup
    /// would be a leak per priced line rather than per boot.
    pub meter_classes: Vec<String>,
    /// Every meter class sealed as one this deployment prices at zero.
    ///
    /// The migration's own list, and a separate field rather than a subset of the one above because
    /// it is separately sourced: the classes the previous release never priced are sealed at the
    /// opening, not read off a bucket. A class in both is one leak, which is what the interner is
    /// idempotent for.
    pub unpriced_classes: Vec<String>,
}

impl ConfigKeys {
    /// Every key, in a stable order, exactly as the interner will walk them.
    ///
    /// Order is fixed so that two boots on one configuration intern in the same sequence, which is
    /// what makes the count reproducible and the memory term comparable across restarts.
    pub fn all(&self) -> impl Iterator<Item = &str> {
        self.lanes
            .iter()
            .chain(&self.pools)
            .chain(&self.models)
            .chain(&self.hosts)
            .chain(&self.dialects)
            .chain(&self.agents)
            .chain(&self.servers)
            .chain(&self.plugin_keys)
            .chain(&self.egress_auth_fields)
            .chain(&self.unpriced_messages)
            .chain(&self.slot_fingerprints)
            .chain(&self.groups)
            .chain(&self.bucket_windows)
            .chain(&self.meter_classes)
            .chain(&self.unpriced_classes)
            .map(String::as_str)
    }
}

/// What a caller sees when it interns after the seal.
///
/// A named constant rather than a message written at the panic site, so the refusal has one spelling
/// an operator can search for, a test can assert on, and a later reader can find every producer of
/// a later reader can find its one producer by. There is exactly one, which is what makes the name
/// worth having.
pub const SEALED_VOCABULARY: &str =
    "root vocabulary sealed: a key was interned after boot, which is a per-call leak";

/// The node's vocabulary: one interner, filled at boot, sealed, and read-only after.
///
/// There is one of these per process. It is not `Clone` and it is not `Copy`, which is deliberate:
/// two vocabularies would be two leak budgets, and the whole point of counting the term is that
/// there is one of it.
#[derive(Debug)]
pub struct Vocabulary {
    registration: Registration,
    sealed: bool,
}

impl Default for Vocabulary {
    fn default() -> Self {
        Vocabulary::new()
    }
}

impl Vocabulary {
    /// An empty vocabulary, open for interning.
    #[must_use]
    pub fn new() -> Self {
        Vocabulary {
            registration: Registration::new(),
            sealed: false,
        }
    }

    /// Intern one key.
    ///
    /// # Panics
    ///
    /// If the vocabulary has been sealed. A key that is only discovered after configuration has been
    /// read is a key that will be discovered again on the next connection, and that is the per-dial
    /// leak the rule exists to forbid.
    ///
    /// The refusal is the same in every build, which is the correction: a debug-only assertion made
    /// the seal a property of how the binary was compiled rather than of the type, so the shipped
    /// binary — the only one whose resident memory anybody budgets — was the one build where the
    /// rule was not enforced. A leak that grows with connections is not a fault that gets smaller
    /// for being unobserved, and this module's own header says the vocabulary REFUSES afterwards.
    pub fn key(&mut self, value: &str) -> &'static str {
        assert!(!self.sealed, "{SEALED_VOCABULARY}: `{value}`");
        self.registration.key(value).unwrap_or_else(|| {
            panic!(
                "vocabulary: `{value}` could not be interned — the node's key set is past the \
                 frozen image's capacity, or the image was frozen before boot finished interning"
            )
        })
    }

    /// Intern every config-derived key, once.
    ///
    /// Returns the interned names in the same order [`ConfigKeys::all`] walks them, so a caller
    /// that needs the static name for a particular entry can take it by position rather than
    /// interning it again.
    pub fn intern_all(&mut self, keys: &ConfigKeys) -> Vec<&'static str> {
        keys.all().map(|value| self.key(value)).collect()
    }

    /// The interned name of every configured group, looked up by the name configuration wrote.
    ///
    /// The door works in configuration's own `String`s and the slot works in the node's static
    /// vocabulary, so something has to hold both halves of each pair. This is that value: built
    /// once at boot, handed to the projection that resolves the group table, and read nowhere on
    /// the request path. Interning is idempotent, so calling this after [`Vocabulary::intern_all`]
    /// leaks nothing a second time — it returns the names that boot already leaked.
    pub fn group_ids(&mut self, keys: &ConfigKeys) -> BTreeMap<String, &'static str> {
        keys.groups
            .iter()
            .map(|name| (name.clone(), self.key(name)))
            .collect()
    }

    /// Close the vocabulary. Nothing may intern after this.
    ///
    /// Called once configuration has resolved and every config-derived key has gone through, which
    /// is before anything registers a key and long before a listener is bound.
    pub fn seal(&mut self) {
        self.sealed = true;
    }

    /// Whether the vocabulary is closed.
    #[must_use]
    pub fn is_sealed(&self) -> bool {
        self.sealed
    }

    /// How many distinct keys were interned.
    ///
    /// This is the fixed resident-memory term, readable rather than inferred.
    #[must_use]
    pub fn len(&self) -> usize {
        self.registration.len()
    }

    /// Whether nothing was interned. True of a zero-config boot, which is the point.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.registration.is_empty()
    }
}

#[cfg(test)]
#[path = "tests/vocabulary.rs"]
mod tests;
