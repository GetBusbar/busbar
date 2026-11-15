// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONFIG GRAMMAR OF ONE READ (SECRET-SHORTHAND-BOOT §3.1-3.3): the secret shorthand a
//! document may use, computed for that read from the modules its own effective `plugins:` block
//! admits, and passed explicitly to every reader. Core declares no word. A read never takes its
//! grammar from what the last generation left on the live secret axis.
//!
//! The composition root computes it (phase 1, [`grammar_for`]): the same scan and judgement the
//! registry build runs, pure, with no dlopen, no high-water write and no axis mutation.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_contract::secret_ref::Sugars;

use super::PluginsCfg;

/// Who declares a grammar item: its version, where it comes from (`linked`, or the archive's file
/// name) and its trust label. Reported in refusals and boot lines; never compared by the pin.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Owner {
    pub version: String,
    pub origin: String,
    pub trust: String,
}

/// The grammar one read parses under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grammar {
    /// The secret shorthand and roles the admissible secret modules declare.
    pub sugars: Sugars,
    /// Every admissible module by name.
    pub owners: BTreeMap<String, Owner>,
    /// What the read's scan did not admit, one capped line per file: appended to a refusal.
    report: Vec<String>,
}

impl Grammar {
    /// The grammar of a read that admits nothing: canonical `{ module, settings }` references only.
    /// Built by tests and by `--list-plugins`' report mode; no production reader falls back to it.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            sugars: Sugars::default(),
            owners: BTreeMap::new(),
            report: Vec::new(),
        }
    }

    #[must_use]
    pub fn new(sugars: Sugars, owners: BTreeMap<String, Owner>, report: Vec<String>) -> Self {
        Self {
            sugars,
            owners,
            report,
        }
    }

    /// One line per secret, plane or auth file the read's scan did not admit, capped.
    #[must_use]
    pub fn report(&self) -> &[String] {
        &self.report
    }

    /// `refusal`, then this grammar's report lines: a refused word, section or style names the
    /// file its module would have come from.
    #[must_use]
    pub fn with_report(&self, refusal: impl Into<String>) -> String {
        let mut refusal = refusal.into();
        for line in &self.report {
            refusal.push_str("\n  - ");
            refusal.push_str(line);
        }
        refusal
    }
}

/// Why a read has no grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrammarRefusal(pub String);

impl std::fmt::Display for GrammarRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<GrammarRefusal> for String {
    fn from(refusal: GrammarRefusal) -> Self {
        refusal.0
    }
}

const UNBOUND: &str = "this configuration was decoded without a grammar: read it through a reader \
                       that computes or is given its grammar (`deploy_from_deserializer`)";

/// The grammar a decoded configuration carries. `Unbound` (the default, which `#[serde(skip)]`
/// gives) refuses when read, so no configuration silently parses or validates under no grammar.
#[derive(Clone, Default)]
pub enum GrammarField {
    #[default]
    Unbound,
    Bound(Arc<Grammar>),
}

impl GrammarField {
    #[must_use]
    pub fn bound(grammar: Grammar) -> Self {
        Self::Bound(Arc::new(grammar))
    }

    pub fn get(&self) -> Result<&Grammar, GrammarRefusal> {
        match self {
            Self::Bound(grammar) => Ok(&**grammar),
            Self::Unbound => Err(GrammarRefusal(UNBOUND.to_owned())),
        }
    }
}

impl std::fmt::Debug for GrammarField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unbound => f.write_str("Unbound"),
            Self::Bound(grammar) => f
                .debug_tuple("Bound")
                .field(&grammar.owners.keys().collect::<Vec<_>>())
                .finish(),
        }
    }
}

/// Whether phase 1 may download `plugins.fetch` before it scans. Process start never fetches (the
/// fetch needs the booted connector, §3.14); only reload-class operations do, after their
/// authority pre-check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fetch {
    None,
    Reload,
}

/// What phase 1 judges one read against.
#[derive(Debug)]
pub struct PhaseOneIn<'a> {
    /// The read's effective `plugins:` block (after its normalization, env mode and patch).
    pub plugins: &'a PluginsCfg,
    /// The directory the read's admission will scan.
    pub dir: &'a std::path::Path,
    /// The overlay's `plugin_versions` pins, when the reader has an open Store; else empty.
    pub pins: &'a BTreeMap<String, String>,
    pub fetch: Fetch,
}

impl<'a> PhaseOneIn<'a> {
    /// The read of `plugins` alone: its own directory, no pins, no fetch.
    #[must_use]
    pub fn of(plugins: &'a PluginsCfg) -> Self {
        static NO_PINS: BTreeMap<String, String> = BTreeMap::new();
        Self {
            plugins,
            dir: std::path::Path::new(&plugins.dir),
            pins: &NO_PINS,
            fetch: Fetch::None,
        }
    }
}

/// The words the live secret axis declares, as a grammar: what the serving generation admitted.
/// For an admin request body decoded before its own read is computed (SECRET-SHORTHAND-BOOT MR-B3
/// moves admin bodies to their own phase 1), never for a configuration read.
#[must_use]
pub fn admitted() -> Grammar {
    Grammar::new(
        super::secret::admitted_sugars(),
        BTreeMap::new(),
        Vec::new(),
    )
}

/// The composition root's phase 1 ([`crate::preflight::RootInstall::grammar`]).
pub type GrammarFn = fn(&PhaseOneIn<'_>) -> Result<Grammar, GrammarRefusal>;

/// Phase 1 for one read: the grammar the modules `input` admits declare, through the root's
/// registry scan and judgement. A read that loads no plugin (`plugins.enabled: false`) in a binary
/// with no composition root admits nothing, so its grammar is empty; a read that would scan
/// `plugins.dir` with no root to scan it is refused.
pub fn grammar_for(input: &PhaseOneIn<'_>) -> Result<Grammar, GrammarRefusal> {
    match crate::preflight::root_rows().grammar {
        Some(phase_one) => phase_one(input),
        None if !input.plugins.enabled => Ok(Grammar::empty()),
        None => Err(GrammarRefusal(
            "no composition root installed the config grammar: plugins.enabled needs the root's \
             scan of plugins.dir to read this configuration"
                .to_owned(),
        )),
    }
}

#[cfg(test)]
#[path = "tests/grammar_tests.rs"]
mod tests;
