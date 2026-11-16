// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE CONFIG GRAMMAR OF ONE READ (SECRET-SHORTHAND-BOOT §3.1-3.3): the secret shorthand a
//! document may use, computed for that read from the modules its own effective `plugins:` block
//! admits, and passed explicitly to every reader. Core declares no word. A read never takes its
//! grammar from what the last generation left on the live secret axis.
//!
//! The composition root computes it (phase 1, [`grammar_for`]): the same scan and judgement the
//! registry build runs, pure, with no dlopen, no high-water write and no axis mutation.

use std::collections::{BTreeMap, BTreeSet};
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

/// The kind of a process-lifetime grammar item: its code is bound once, at process start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ItemKind {
    /// A top-level section a plane declares or owns.
    Section,
    /// An outbound auth style (a provider entry's `auth:`) an auth module declares.
    Style,
}

/// How one read judges a process-lifetime item against what this process registered at start
/// (SECRET-SHORTHAND-BOOT §3.6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// Admissible under the read and registered at start from the same image: it counts.
    Counts,
    /// Admissible and registered, but its file was replaced in place: it counts under the running
    /// image, and the new image takes effect at the next restart.
    Replaced,
    /// Admissible under the read, but this process did not register it at start.
    Unregistered,
    /// Registered at start, but the read does not admit it (the cause class).
    NotAdmitted(String),
}

/// One plane section or outbound auth style, as one read judges it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub kind: ItemKind,
    /// The section key, or the style word.
    pub name: String,
    /// The module that declares it.
    pub module: String,
    /// The image it is bound from: `linked`, or the archive's SHA-256.
    pub image: String,
    pub standing: Standing,
}

/// What one read used of its grammar, recorded by its parse (SECRET-SHORTHAND-BOOT §3.8): the
/// grammar pin compares exactly these items, and an unused item never refuses.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Used {
    /// Secret shorthand words in reference positions and settings bags, declared or not.
    pub words: BTreeSet<String>,
    /// Core grammar roles (`fill`) a template or plane fill uses.
    pub roles: BTreeSet<String>,
    /// Top-level plane sections the document writes.
    pub sections: BTreeSet<String>,
    /// Outbound auth styles the providers name.
    pub styles: BTreeSet<String>,
}

impl Used {
    /// Add what a recording parse used ([`busbar_contract::secret_ref::context::deserialize_recording`]).
    pub fn absorb(&mut self, words: busbar_contract::secret_ref::context::UsedWords) {
        let (words, roles) = words.into_parts();
        self.words.extend(words);
        self.roles.extend(roles);
    }

    /// Add everything `other` used.
    pub fn extend(&mut self, other: &Used) {
        self.words.extend(other.words.iter().cloned());
        self.roles.extend(other.roles.iter().cloned());
        self.sections.extend(other.sections.iter().cloned());
        self.styles.extend(other.styles.iter().cloned());
    }
}

/// The grammar one read parses under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grammar {
    /// The secret shorthand and roles the admissible secret modules declare.
    pub sugars: Sugars,
    /// Every admissible module by name.
    pub owners: BTreeMap<String, Owner>,
    /// The plane sections and outbound auth styles, judged against what start registered.
    pub items: Vec<Item>,
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
            items: Vec::new(),
            report: Vec::new(),
        }
    }

    #[must_use]
    pub fn new(sugars: Sugars, owners: BTreeMap<String, Owner>, report: Vec<String>) -> Self {
        Self {
            sugars,
            owners,
            items: Vec::new(),
            report,
        }
    }

    /// This grammar with its process-lifetime items (§3.6).
    #[must_use]
    pub fn with_items(mut self, items: Vec<Item>) -> Self {
        self.items = items;
        self
    }

    /// One line per secret, plane or auth file the read's scan did not admit, capped.
    #[must_use]
    pub fn report(&self) -> &[String] {
        &self.report
    }

    /// This grammar as an admin response may show it (SECRET-SHORTHAND-BOOT §3.9): a refusal names
    /// the item and its cause class, never a file, a trust setting or the inventory; the report
    /// is one pointer to the plugin listing, which a caller reads under its own authority.
    #[must_use]
    pub fn trimmed(mut self) -> Self {
        if !self.report.is_empty() {
            self.report = vec![ADMIN_REPORT.to_owned()];
        }
        self
    }

    /// Add one report line (the first-boot fetch limit, §3.9), within the cap.
    fn push_report(&mut self, line: String) {
        if self.report.len() < REPORT_LINES {
            self.report.push(line);
        }
    }

    /// The refusal for a document that writes `name` (a top-level section, or a provider's
    /// `auth:` style) when this read does not let it count (§3.6): an admissible module this
    /// process did not register at start (restart), or a registered one the read no longer admits.
    #[must_use]
    pub fn item_refusal(&self, kind: ItemKind, name: &str) -> Option<String> {
        let item = self
            .items
            .iter()
            .find(|item| item.kind == kind && item.name == name)?;
        let (what, first, remove) = match kind {
            ItemKind::Section => (
                format!("`{name}:` is the section of `{}`", item.module),
                format!("`{name}:`"),
                "the section",
            ),
            ItemKind::Style => (
                format!(
                    "outbound auth style `{name}` is the style of `{}`",
                    item.module
                ),
                format!("auth style `{name}`"),
                "the style",
            ),
        };
        match &item.standing {
            Standing::Counts | Standing::Replaced => None,
            Standing::Unregistered => Some(format!(
                "{what}, which this process did not load at start; a first {first} cannot take \
                 effect on a running process, so the change was refused and nothing was changed: \
                 write it in the config file and restart."
            )),
            Standing::NotAdmitted(cause) => Some(format!(
                "{what}, which this read's plugins: block does not admit ({cause}); the running \
                 process still serves the current generation; restore the block, or remove \
                 {remove}."
            )),
        }
    }

    /// The items this read counts under the running image while a replaced file waits for the
    /// next restart: what `reload_to_apply` lists.
    pub fn replaced(&self) -> impl Iterator<Item = &Item> {
        self.items
            .iter()
            .filter(|item| item.standing == Standing::Replaced)
    }

    /// Where `module`'s declaration comes from, for a refusal: its archive, or `linked`.
    fn origin_of(&self, module: &str) -> String {
        self.owners
            .get(module)
            .map_or_else(|| "linked".to_owned(), |owner| owner.origin.clone())
    }

    fn describe_word(&self, word: &str) -> String {
        match self.sugars.get(word) {
            None => "no admitted secret module".to_owned(),
            Some(sugar) => format!(
                "{} ({}) declaring setting `{}`",
                sugar.plugin,
                self.origin_of(&sugar.plugin),
                sugar.setting
            ),
        }
    }

    fn describe_role(&self, role: &str) -> Option<String> {
        self.sugars.with_role(role).map(|sugar| {
            format!(
                "{} ({}) `{}:`",
                sugar.plugin,
                self.origin_of(&sugar.plugin),
                sugar.word
            )
        })
    }

    fn describe_item(&self, kind: ItemKind, name: &str) -> Option<(String, String, &'static str)> {
        self.items
            .iter()
            .find(|item| item.kind == kind && item.name == name)
            .map(|item| {
                let class = match item.standing {
                    Standing::Counts | Standing::Replaced => "counts",
                    Standing::Unregistered => "restart required",
                    Standing::NotAdmitted(_) => "not admitted",
                };
                (item.module.clone(), item.image.clone(), class)
            })
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

/// What an admin response shows in place of a grammar's report (§3.9).
pub const ADMIN_REPORT: &str = "see GET /api/v1/admin/plugins for what plugins.dir admitted";

/// The most report lines a grammar carries; the scan's own cap leaves room for the fetch lines.
const REPORT_LINES: usize = 24;

/// Which two grammars a pin compares, and what its refusal tells the operator (BUSBAR-3170).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pin {
    /// The read's grammar against what admission admitted (bootstrap and every build).
    Admission,
    /// Boot: `config.yaml`'s own block (the start grammar) against the Store's pins and patch.
    Store,
    /// A write of a `/plugins` patch or a pin: what the next start reads from `config.yaml` alone
    /// against what the effective documents would read.
    NextBoot,
}

impl Pin {
    fn sides(self) -> (&'static str, &'static str, &'static str) {
        match self {
            Pin::Admission => (
                "was read as",
                "but admission now gives",
                "plugins.dir changed after the configuration was read. Reload (or restart) to \
                 read it again.",
            ),
            Pin::Store => (
                "is read from config.yaml's plugins: block as",
                "but the Store's plugin pins and document patch give",
                "make config.yaml's plugins: block admit the same module; or write the canonical \
                 `{ module: …, settings: … }` form; or start once with --ignore-overlay to boot \
                 without the Store's pins and patches, then remove the pin with plugins/rollback.",
            ),
            Pin::NextBoot => (
                "is read at the next start from config.yaml's plugins: block as",
                "but this change gives",
                "the next restart would refuse it, so the change was refused and nothing was \
                 changed. Write the change in config.yaml, or use the canonical `{ module: …, \
                 settings: … }` form.",
            ),
        }
    }
}

/// THE GRAMMAR PIN (BUSBAR-3170, SECRET-SHORTHAND-BOOT §3.8): every item `used` names declares the
/// same in `read` (the grammar the configuration was read under) and in `now` (the grammar the
/// other side gives). A word compares its whole declaration, never its owner's version or file
/// (those are reported); a section or style compares its module, image and standing. Present on
/// one side and absent on the other is a mismatch both ways. Unused items never refuse.
pub fn pin(read: &Grammar, now: &Grammar, used: &Used, pin: Pin) -> Result<(), String> {
    let (was, now_gives, remedy) = pin.sides();
    let changed = |what: String, before: String, after: String| {
        crate::diagnostics::coded(
            &crate::diagnostics::CONFIG_GRAMMAR_CHANGED,
            format!("{what} {was} {before}, {now_gives} {after}: {remedy}"),
        )
    };
    for word in &used.words {
        if read.sugars.get(word) != now.sugars.get(word) {
            return Err(changed(
                format!("`{{{word}: \u{2026}}}`"),
                read.describe_word(word),
                now.describe_word(word),
            ));
        }
    }
    for role in &used.roles {
        let (before, after) = (read.describe_role(role), now.describe_role(role));
        if before != after {
            let none = || "no admitted secret module".to_owned();
            return Err(changed(
                format!("the `{role}` role"),
                before.unwrap_or_else(none),
                after.unwrap_or_else(none),
            ));
        }
    }
    // Sections and styles compare only between two judged grammars (each lists what start
    // registered); a grammar judged before start registered anything lists none.
    let judged = !read.items.is_empty() && !now.items.is_empty();
    for (kind, names) in [
        (ItemKind::Section, &used.sections),
        (ItemKind::Style, &used.styles),
    ]
    .into_iter()
    .filter(|_| judged)
    {
        for name in names {
            let (before, after) = (
                read.describe_item(kind, name),
                now.describe_item(kind, name),
            );
            if before != after {
                let shown = |side: Option<(String, String, &str)>| {
                    side.map_or_else(
                        || "no registered module".to_owned(),
                        |(module, image, class)| format!("{module} ({image}, {class})"),
                    )
                };
                let what = match kind {
                    ItemKind::Section => format!("`{name}:`"),
                    ItemKind::Style => format!("auth style `{name}`"),
                };
                return Err(changed(what, shown(before), shown(after)));
            }
        }
    }
    Ok(())
}

/// One line per `plugins.fetch` file not yet in `dir` (SECRET-SHORTHAND-BOOT §3.9, option a): a
/// read that does not fetch cannot see a module that only the fetch delivers. Busbar cannot know
/// which module an unfetched file holds, so the line names the file only.
#[must_use]
pub fn pending_fetch_lines(plugins: &PluginsCfg, dir: &std::path::Path) -> Vec<String> {
    if !plugins.enabled {
        return Vec::new();
    }
    plugins
        .fetch
        .iter()
        .filter_map(|entry| super::fetch_target_from(entry).ok())
        .filter(|target| !dir.join(&target.filename).exists())
        .map(|target| {
            let file: String = target
                .filename
                .escape_debug()
                .to_string()
                .chars()
                .take(96)
                .collect();
            format!(
                "plugins.fetch lists \"{file}\", not yet in plugins.dir: the boot fetch runs after \
                 the configuration is read. Pre-seed plugins.dir with the pinned artifact, or write \
                 the canonical form for the first start."
            )
        })
        .collect()
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

/// The read a decoded configuration carries: the grammar it was read under and what its parse used
/// of it ([`Used`], held beside the grammar, never on it). `Unbound` (the default, which
/// `#[serde(skip)]` gives) refuses when read, so no configuration silently parses or validates
/// under no grammar.
#[derive(Clone, Default)]
pub enum GrammarField {
    #[default]
    Unbound,
    Bound(Arc<Grammar>, Arc<Used>),
}

impl GrammarField {
    #[must_use]
    pub fn bound(grammar: Grammar) -> Self {
        Self::Bound(Arc::new(grammar), Arc::default())
    }

    /// The read of a document under `grammar` whose parse used `used`.
    #[must_use]
    pub fn bound_used(grammar: Grammar, used: Used) -> Self {
        Self::Bound(Arc::new(grammar), Arc::new(used))
    }

    pub fn get(&self) -> Result<&Grammar, GrammarRefusal> {
        match self {
            Self::Bound(grammar, _) => Ok(&**grammar),
            Self::Unbound => Err(GrammarRefusal(UNBOUND.to_owned())),
        }
    }

    /// What the read used of its grammar: what the grammar pin compares.
    pub fn used(&self) -> Result<&Used, GrammarRefusal> {
        match self {
            Self::Bound(_, used) => Ok(&**used),
            Self::Unbound => Err(GrammarRefusal(UNBOUND.to_owned())),
        }
    }

    /// Add what a later parse of the same read used (its providers catalog, a stored definition
    /// typed under its grammar). An unbound read records nothing; reading it refuses anyway.
    pub fn record(&mut self, more: &Used) {
        if let Self::Bound(_, used) = self {
            Arc::make_mut(used).extend(more);
        }
    }
}

impl std::fmt::Debug for GrammarField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unbound => f.write_str("Unbound"),
            Self::Bound(grammar, _) => f
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

/// Compute one read's grammar through its explicitly owned root context.
pub fn grammar_for(
    input: &PhaseOneIn<'_>,
    rules: &dyn crate::appbuild::RootRules,
) -> Result<Grammar, GrammarRefusal> {
    let mut grammar = rules.grammar(input)?;
    // A read that does not fetch cannot see a module only the fetch delivers (§3.14): a refusal
    // names each pending file.
    if input.fetch == Fetch::None {
        for line in pending_fetch_lines(input.plugins, input.dir) {
            grammar.push_report(line);
        }
    }
    Ok(grammar)
}

#[cfg(test)]
#[path = "tests/grammar_tests.rs"]
mod tests;
