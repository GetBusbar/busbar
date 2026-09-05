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
//! read, and refuses afterwards. The refusal is a debug assertion rather than a runtime error
//! because a `key()` call after the seal is a programming mistake in the root — there is no
//! operator input that can cause one and no recovery that would make sense — so it should stop a
//! test and a debug binary loudly, and cost a release binary nothing.
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
    /// Every window name a configured group bucket is declared over.
    pub bucket_windows: Vec<String>,
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
            .chain(&self.bucket_windows)
            .map(String::as_str)
    }
}

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
    /// In a debug build, if the vocabulary has been sealed. A key that is only discovered after
    /// configuration has been read is a key that will be discovered again on the next connection,
    /// and that is the per-dial leak the rule exists to forbid.
    pub fn key(&mut self, value: &str) -> &'static str {
        debug_assert!(
            !self.sealed,
            "vocabulary sealed: `{value}` was interned after boot, which is a per-call leak"
        );
        self.registration.key(value)
    }

    /// Intern every config-derived key, once.
    ///
    /// Returns the interned names in the same order [`ConfigKeys::all`] walks them, so a caller
    /// that needs the static name for a particular entry can take it by position rather than
    /// interning it again.
    pub fn intern_all(&mut self, keys: &ConfigKeys) -> Vec<&'static str> {
        keys.all()
            .map(|value| self.registration.key(value))
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
mod tests {
    use super::*;

    fn a_configured_deployment() -> ConfigKeys {
        ConfigKeys {
            lanes: vec!["lane-primary".into(), "lane-standby".into()],
            pools: vec!["pool-main".into()],
            models: vec!["model-a".into(), "model-b".into()],
            hosts: vec!["upstream.example".into()],
            dialects: vec!["dialect-one".into()],
            agents: vec!["agent-alpha".into()],
            servers: vec!["server-one".into()],
            plugin_keys: vec!["store-memory".into()],
            egress_auth_fields: vec![
                "authorization".into(),
                "AKIAEXAMPLE".into(),
                "eu-west-1".into(),
                "service-name".into(),
            ],
            unpriced_messages: vec!["no configured rate for pool-main".into()],
            slot_fingerprints: vec!["fingerprint-0".into()],
            bucket_windows: vec!["60s".into()],
        }
    }

    /// The whole list goes through, and every key is distinct, so the interned count is the key
    /// count. This is the fixed memory term, and it is a number a reader can check.
    #[test]
    fn every_config_derived_key_is_interned_once() {
        let keys = a_configured_deployment();
        let mut vocabulary = Vocabulary::new();
        let interned = vocabulary.intern_all(&keys);

        assert_eq!(interned.len(), keys.all().count());
        assert_eq!(vocabulary.len(), 17);
        for (name, value) in interned.iter().zip(keys.all()) {
            assert_eq!(*name, value);
        }
    }

    /// The same configuration read twice — a reload that changes nothing — leaks nothing the second
    /// time. Idempotence is what makes a reload cost no memory.
    #[test]
    fn interning_the_same_configuration_twice_leaks_nothing_further() {
        let keys = a_configured_deployment();
        let mut vocabulary = Vocabulary::new();

        let first = vocabulary.intern_all(&keys);
        let after_first = vocabulary.len();
        let second = vocabulary.intern_all(&keys);

        assert_eq!(vocabulary.len(), after_first);
        for (a, b) in first.iter().zip(&second) {
            assert!(std::ptr::eq(*a, *b), "a repeated key was leaked twice");
        }
    }

    /// A deployment that declares nothing interns nothing. The fixed term is zero, which is what
    /// makes a zero-config boot indistinguishable from the previous release's.
    #[test]
    fn a_zero_config_boot_interns_nothing() {
        let mut vocabulary = Vocabulary::new();
        let interned = vocabulary.intern_all(&ConfigKeys::default());
        assert!(interned.is_empty());
        assert!(vocabulary.is_empty());
        assert_eq!(vocabulary.len(), 0);
    }

    /// The seal is the whole point of the wrapper: after it, a key is a defect, and a debug build
    /// says so rather than quietly leaking.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "vocabulary sealed")]
    fn interning_after_the_seal_is_a_defect() {
        let mut vocabulary = Vocabulary::new();
        vocabulary.intern_all(&a_configured_deployment());
        vocabulary.seal();
        let _ = vocabulary.key("a-lane-discovered-on-the-thousandth-connection");
    }

    /// And before the seal it is ordinary work: the assertion is about when, not about what.
    #[test]
    fn interning_before_the_seal_is_ordinary() {
        let mut vocabulary = Vocabulary::new();
        assert!(!vocabulary.is_sealed());
        let name = vocabulary.key("lane-late-but-still-at-boot");
        assert_eq!(name, "lane-late-but-still-at-boot");
        vocabulary.seal();
        assert!(vocabulary.is_sealed());
        assert_eq!(vocabulary.len(), 1);
    }

    /// The walk order is fixed, so two boots on one configuration intern in one sequence. Without
    /// that the count is reproducible but the ordering is not, and a memory comparison across
    /// restarts stops meaning anything.
    #[test]
    fn the_walk_order_is_stable() {
        let keys = a_configured_deployment();
        let first: Vec<&str> = keys.all().collect();
        let second: Vec<&str> = keys.all().collect();
        assert_eq!(first, second);
        assert_eq!(first[0], "lane-primary");
        assert_eq!(first[first.len() - 1], "60s");
    }

    /// A key that appears in two sections — a pool and a lane sharing a name, which configuration
    /// permits — is one leak, not two, and both sections get the same static name back.
    #[test]
    fn a_name_used_in_two_sections_is_leaked_once() {
        let keys = ConfigKeys {
            lanes: vec!["shared".into()],
            pools: vec!["shared".into()],
            ..ConfigKeys::default()
        };
        let mut vocabulary = Vocabulary::new();
        let interned = vocabulary.intern_all(&keys);

        assert_eq!(interned.len(), 2);
        assert!(std::ptr::eq(interned[0], interned[1]));
        assert_eq!(vocabulary.len(), 1);
    }
}
