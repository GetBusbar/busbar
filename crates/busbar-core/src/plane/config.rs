// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PARSE-TIME RULES A PLANE SECTION IS READ BY, owned once: how the section MAP is split, and
//! whether a hook reference stays inside its plane.
//!
//! ## Why the whole rule lives here and not on a plane
//!
//! It was written twice — `a2a/config.rs` and `mcp/config.rs` each carried a
//! `refuse_cross_plane_reference` and a `validate_section_hooks`, and the two were byte-identical
//! down to the sentence an operator reads. Two of them included the same HARDCODED section list,
//! `["pools", "tools", "agents", "export", "identity-providers"]`, in two protocol-local files that
//! no compiler links. Nothing made them agree; they agreed because one was copied from the other.
//!
//! That list is the part that rots. It is a fact about the top-level config grammar, and the config
//! grammar is declared in two tables that already exist: [`Plane::ALL`] names the plane sections and
//! [`NamedMapSection::ALL`] names the 1.5.3 named-definition maps. A plane or a section added to
//! either table used to leave both copies of the literal behind, and a section missing from the
//! literal is not a loud failure — it is `agents.planner` being accepted as a bare hook name,
//! resolving to nothing, and an operator believing a control is attached that is not.
//!
//! So the list is DERIVED ([`config_sections`]) and passed in as a PARAMETER rather than written.
//! The judgement takes the sections it is judging against, which is also what lets a plane busbar
//! does not have be validated by this code with nothing written for it (see
//! `plane/tests/config_tests.rs`).
//!
//! **What core owns:** the trim, the empty-name refusal, the section-prefix scan, the bare-name
//! requirement, and every SENTENCE. **What a caller owns:** its own WORDING for WHERE the refusal
//! happened — `at` is "`agents.planner`" or "`tools.hooks`", and those are different sentences to an
//! operator diagnosing a boot failure. A caller keeps its refusal vocabulary, not its decision.
//!
//! The sentences survive the move through a TOTAL `From<Refusal<'_>> for String`. Totality is the
//! point: a refusal added to [`HookRefError`] later has to be given a sentence of its own rather
//! than being folded silently into a nearby arm, which is how two refusals become one wording that
//! is wrong for one of them.
//!
//! ## THIS IS NOT THE OTHER CROSS-PLANE REFUSAL, and the two must not be merged
//!
//! [`super::PlaneSections::resolve`] also refuses a cross-plane reference, with
//! [`super::RefError::CrossPlane`]. It is a SECOND, STRUCTURAL check and not a duplicate of this
//! one. They answer different questions at different moments:
//!
//!   * THIS one runs at PARSE time, on a STRING, before anything is known to exist. It refuses
//!     `agents.planner` written where a bare name belongs — a SHAPE that names a plane, whether or
//!     not any `planner` exists anywhere.
//!   * [`super::PlaneSections::resolve`] runs at RESOLVE time, on a name that EXISTS. It refuses a
//!     bare `planner` that resolves on a sibling plane — a name whose shape is legal and whose
//!     BINDING crosses the boundary.
//!
//! Neither subsumes the other: this one fires on a name nothing defines, and that one fires on a
//! name with no dot in it. Collapsing them would not deduplicate a check, it would delete one.
//!
//! ## THE SECTION SPLIT, and why it is here rather than three times
//!
//! `pools:`, `tools:` and `agents:` are SIBLINGS OF ONE SHAPE — that is the sentence every one of
//! the three section modules opens with — and the shape is: a map whose keys are registrations,
//! except for the two words reserved at the section level on EVERY plane
//! ([`RESERVED_SECTION_KEYS`]), which are lifted out first as the all-plane `hooks:` attach (a LIST,
//! so ADDITIVE) and the all-plane `upstream_credentials:` default (a SCALAR, so OVERRIDE).
//!
//! That shape was READ THREE TIMES — `config/mod.rs`'s `PoolsCfg`, `mcp/config.rs`'s `ToolsCfg` and
//! `a2a/config.rs`'s `AgentsCfg` each carried its own `Deserialize` doing the same six steps in the
//! same order: refuse a reserved key holding a MAPPING before the typed lifts (so the operator reads
//! "that name is reserved" instead of "expected a sequence"), lift `hooks`, lift
//! `upstream_credentials`, then walk the remainder refusing a reserved NAME, parse each value and
//! run the plane's value rules. Three copies of a parse ORDER is the shape this repo's plane ledger
//! calls DEBT, and it is the dangerous kind: the pre-lift refusal is the step a fourth plane would
//! be likeliest to omit, and omitting it does not fail — it produces a confusing type error on a
//! config that should have been named.
//!
//! So [`split_section`] owns the ORDER and every SENTENCE, and a plane supplies the only three
//! things that genuinely differ: WHICH plane it is (the section word and the noun an operator reads
//! back both come off [`Plane`], so there is no second vocabulary to keep in step), the TYPE one
//! registration parses into, and its own VALUE RULES. Everything a plane keeps after that is a rule
//! about ITS OWN values — which is why `mcp/config.rs` and `a2a/config.rs` share a filename and
//! nothing else.

use serde::Deserialize;

use crate::config::named_map::NamedMapSection;

use super::Plane;

/// A PLANE'S CONFIG SECTION, ASKED FOR ITS OWN SECRETS — so core enumerates a plane's credential
/// references without naming that plane's credential-bearing types.
///
/// Implemented by the type a plane's top-level config section deserializes into (`tools:` →
/// [`crate::mcp::config::ToolsCfg`], `agents:` → [`crate::a2a::config::AgentsCfg`]). The composition
/// walk in `config_validate::secret_refs` gathers every plane's references by LOOPING this trait over
/// the configured plane sections, rather than destructuring each plane's own config types itself: the
/// section that owns a credential is the section that knows it is one.
///
/// [`Self::secret_refs`] destructures its plane's config types EXHAUSTIVELY (no `..`), so the
/// anti-omission force that used to live in `config_validate::secret_refs` — adding a credential
/// field to a plane fails to compile until someone decides, in the impl, whether it is a secret —
/// travels with the plane instead of staying behind in core.
pub(crate) trait PlaneCfg: std::any::Any + Send + Sync {
    /// EVERY secret reference this plane's config section carries, as `(config-path, &SecretRef)`,
    /// where the path is the operator-facing dotted location `--validate` prints in an error. The
    /// path is fully qualified from the top-level section down (`tools.<name>.env.<var>`), so a
    /// caller can concatenate the planes' answers with no per-plane prefixing of its own.
    fn secret_refs(&self) -> Vec<(String, &crate::config::SecretRef)>;
}

/// THE TWO WORDS RESERVED AT EVERY PLANE SECTION'S TOP LEVEL, under the name the shared reader uses.
///
/// One declaration, re-exported rather than restated: the whole point of the rule is that the
/// reserved word space does not vary per plane, and a second `&["hooks", "upstream_credentials"]`
/// literal is how a word comes to be reserved on one plane and free on another.
pub(crate) use crate::config::RESERVED_POOLS_SECTION_KEYS as RESERVED_SECTION_KEYS;

/// EVERY TOP-LEVEL CONFIG SECTION a bare hook reference could be reaching onto, DERIVED from the two
/// tables that declare the config grammar rather than written as a literal.
///
/// [`super::registry::PlaneDecl::config_section`] over [`super::registry::plane_decls`] gives the
/// plane sections (`pools:`, `tools:`, `agents:`, and any registered plane's own section);
/// [`NamedMapSection::key`] over [`NamedMapSection::ALL`] gives the 1.5.3 named-definition maps
/// (`identity-providers:`, `export:`, and the two plane sections again, which is why this
/// de-duplicates). Both tables state that their variant set is the only thing a new section adds —
/// this function is what makes that true for the hook-reference rule too.
///
/// Order is deterministic (plane tables first, in layering order) so a refusal naming a section
/// names the same one on every run. A nondeterministic diagnostic makes a boot failure
/// unreproducible.
pub(crate) fn config_sections() -> Vec<&'static str> {
    config_sections_from(super::registry::plane_decls())
}

/// THE SECTION FOLD, over a GIVEN plane declaration list rather than the process one — so a test can
/// pass a plane busbar does not have and watch its section reach this grammar with nothing written
/// for it in core (see `plane/tests/registry_tests.rs`). [`config_sections`] passes the process
/// [`super::registry::plane_decls`]; the plane sections come off each decl's
/// [`super::registry::PlaneDecl::config_section`] rather than an enum `match`, which is what lets a
/// registered plane's section into the hook-reference grammar.
pub(crate) fn config_sections_from(
    decls: &[&'static super::registry::PlaneDecl],
) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for section in decls
        .iter()
        .map(|decl| decl.config_section)
        .chain(NamedMapSection::ALL.iter().map(|s| s.key()))
    {
        if !out.contains(&section) {
            out.push(section);
        }
    }
    out
}

/// WHY a hook reference was refused. Three arms, and each one is a different thing for an operator
/// to do about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HookRefError {
    /// The name is empty or whitespace. Nothing to look up, and nothing to diagnose.
    Empty,
    /// The name is prefixed with a config SECTION, so it reaches onto another plane.
    CrossPlane {
        /// The reference exactly as the operator wrote it (trimmed).
        hook: String,
        /// The section it reaches onto.
        section: &'static str,
        /// What is left after the section prefix — the bare name they probably meant.
        rest: String,
    },
    /// The name is dotted but names no section busbar knows. Still not a bare name.
    NotBare {
        /// The reference exactly as the operator wrote it (trimmed).
        hook: String,
    },
}

/// A [`HookRefError`] plus the CALLER'S WORDING for where it happened — the one thing a plane keeps.
pub(crate) struct Refusal<'a> {
    /// The caller's own label for the site: "`agents.planner`", "`tools.hooks`".
    pub(crate) at: &'a str,
    /// The decision core made.
    pub(crate) err: HookRefError,
}

// EVERY SENTENCE AN OPERATOR READS FOR THIS RULE, written once. The match is TOTAL on purpose: a
// fourth [`HookRefError`] arm will not compile until somebody writes the sentence it is owed,
// which is the alternative to it quietly inheriting a neighbour's wording.
impl From<Refusal<'_>> for String {
    fn from(r: Refusal<'_>) -> String {
        let at = r.at;
        match r.err {
            HookRefError::Empty => format!("{at}: `hooks:` contains an empty name"),
            HookRefError::CrossPlane {
                hook,
                section,
                rest,
            } => format!(
                "{at}: `hooks:` may only name hooks from the top-level `hooks:` map, by bare name. \
                 `{hook}` reaches onto the `{section}:` plane, and no entry on one plane may \
                 reference an entry on another. Did you mean the hook `{rest}`?"
            ),
            HookRefError::NotBare { hook } => format!(
                "{at}: `hooks:` may only name hooks from the top-level `hooks:` map, by bare name. \
                 `{hook}` is not a bare name."
            ),
        }
    }
}

/// THE DECISION, and the only copy of it: is `hook` a legal bare reference into the one top-level
/// `hooks:` map, judged against `sections`?
///
/// `sections` is a PARAMETER rather than a literal so the set of sections this rule knows about is
/// the set the config grammar declares — see [`config_sections`]. Production passes that; a test
/// passes a plane busbar does not have and gets the same judgement with nothing written for it.
///
/// No I/O, no globals, no config types: a string and a list of section names in, a verdict out.
pub(crate) fn judge_hook_ref(hook: &str, sections: &[&'static str]) -> Result<(), HookRefError> {
    let hook = hook.trim();
    if hook.is_empty() {
        return Err(HookRefError::Empty);
    }
    // A dotted name is the tell: bare names into `hooks:` never contain a plane prefix.
    for section in sections {
        if let Some(rest) = hook.strip_prefix(&format!("{section}.")) {
            return Err(HookRefError::CrossPlane {
                hook: hook.to_string(),
                section,
                rest: rest.to_string(),
            });
        }
    }
    if hook.contains('.') {
        return Err(HookRefError::NotBare {
            hook: hook.to_string(),
        });
    }
    Ok(())
}

/// REFUSE, rather than ignore, a reference that reaches onto another plane.
///
/// A hook reference is a bare name into the one top-level `hooks:` map. Somebody who writes
/// `pools.fast` or `agents.planner` there means something, and the something is not available: no
/// entry on one plane may reference an entry on another. Dropping it silently would leave an
/// operator believing a control is attached that is not, which is worse than the typo.
///
/// `at` is the CALLER'S vocabulary for the site; the verdict and the sentence are core's.
pub(crate) fn refuse_cross_plane_reference(
    at: &str,
    hook: &str,
    sections: &[&'static str],
) -> Result<(), String> {
    judge_hook_ref(hook, sections).map_err(|err| Refusal { at, err }.into())
}

/// A whole attach list, judged by the same rule one entry is — the SECTION-level `hooks:` list has
/// no per-entry parse to hang off, and a looser rule there would be a hole in exactly the place an
/// operator attaches a control to everything.
pub(crate) fn validate_section_hooks(
    at: &str,
    hooks: &[String],
    sections: &[&'static str],
) -> Result<(), String> {
    for hook in hooks {
        refuse_cross_plane_reference(at, hook, sections)?;
    }
    Ok(())
}

/// ONE PLANE SECTION, split: the two reserved section knobs lifted out, and every other key parsed
/// as one registration.
///
/// Insertion-ordered, because catalogue construction and every operator-facing listing read it and a
/// hash-ordered listing is a listing that changes between runs for no reason. A plane that wants
/// another container converts once, at the end, where the conversion is visible.
pub(crate) struct Section<T> {
    /// The reserved `<section>.hooks:` all-plane attach list. LIST ⇒ ADDITIVE.
    pub(crate) hooks: Vec<String>,
    /// The reserved `<section>.upstream_credentials:` all-plane default. SCALAR ⇒ OVERRIDE.
    pub(crate) upstream_credentials: Option<crate::auth::UpstreamCreds>,
    /// The registrations — every key that is not one of [`RESERVED_SECTION_KEYS`].
    pub(crate) entries: indexmap::IndexMap<String, T>,
}

/// THE SECTION-MAP SPLIT, and the only copy of it: read one plane's top-level section into its two
/// reserved knobs and its registrations, in the one order all three planes are read in.
///
/// `plane` supplies the WORDS (`Plane::config_section` and [`Plane::subject_noun`]) so no caller
/// carries a second vocabulary for its own section; `validate` is the plane's VALUE RULES, run on
/// each entry as it is parsed, so the file and the admin write path refuse the same definitions —
/// the ONE GRAMMAR, TWO PATHS rule. A plane with no value rules passes `|_, _| Ok(())`.
///
/// The REFUSAL ORDER is the load-bearing part. A reserved key holding a MAPPING is somebody trying
/// to define a registration by that name, and it is refused BEFORE the typed lifts so the operator
/// reads "that name is reserved" rather than "expected a sequence" — the diagnosis is different, and
/// the confusing one costs an operator an afternoon.
pub(crate) fn split_section<'de, D, T>(
    deserializer: D,
    plane: Plane,
    validate: impl Fn(&str, &T) -> Result<(), String>,
) -> Result<Section<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    use serde::de::Error as _;

    let section = plane.config_section();
    let noun = plane.subject_noun();

    let mut raw: indexmap::IndexMap<String, serde_yaml::Value> =
        indexmap::IndexMap::deserialize(deserializer)?;

    // BEFORE the typed lifts, for the reason in the doc above.
    for reserved in RESERVED_SECTION_KEYS {
        if raw
            .get(*reserved)
            .is_some_and(|v| matches!(v, serde_yaml::Value::Mapping(_)))
        {
            return Err(D::Error::custom(reserved_name_refusal(
                section, noun, reserved,
            )));
        }
    }

    let hooks: Vec<String> = match raw.shift_remove("hooks") {
        None => Vec::new(),
        Some(v) => Vec::<String>::deserialize(v).map_err(|e| {
            D::Error::custom(format!(
                "the reserved `{section}.hooks:` all-{section} attach must be a list of hook \
                 names: {e}"
            ))
        })?,
    };
    let upstream_credentials = match raw.shift_remove("upstream_credentials") {
        None => None,
        Some(v) => Some(crate::auth::UpstreamCreds::deserialize(v).map_err(|e| {
            D::Error::custom(format!(
                "the reserved `{section}.upstream_credentials:` all-{section} default must be a \
                 credential mode (`own` or `passthrough`): {e}"
            ))
        })?),
    };

    let mut entries = indexmap::IndexMap::new();
    for (name, value) in raw {
        // The well-typed spellings are gone; this catches the map-valued "I meant a registration"
        // one with a precise message instead of a type error.
        if RESERVED_SECTION_KEYS.contains(&name.as_str()) {
            return Err(D::Error::custom(reserved_name_refusal(
                section, noun, &name,
            )));
        }
        let def: T = T::deserialize(value).map_err(D::Error::custom)?;
        validate(&name, &def).map_err(D::Error::custom)?;
        entries.insert(name, def);
    }

    Ok(Section {
        hooks,
        upstream_credentials,
        entries,
    })
}

/// THE SENTENCE an operator reads when they name a registration with a reserved section word,
/// written once for all three planes and for both spellings that reach it.
///
/// It names the section, what the two words ARE, and that the rule holds on every plane — because
/// the surprise the reservation exists to prevent is precisely learning the word space once and
/// discovering it differs somewhere else.
fn reserved_name_refusal(section: &str, noun: &str, name: &str) -> String {
    format!(
        "`{name}` may not be used as a name in `{section}:`: that key is RESERVED at the \
         `{section}:` section level (the all-{section} `hooks:` attach list and \
         `upstream_credentials:` default), on every plane. Rename the {noun}."
    )
}

#[cfg(test)]
#[path = "tests/config_tests.rs"]
mod config_tests;
