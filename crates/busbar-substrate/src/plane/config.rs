// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NEUTRAL CONFIG-SEAM CONTRACTS a plane's config section is read THROUGH — relocated to the
//! neutral substrate so a plane crate names them without reaching into `busbar_core::plane::config`.
//!
//! These are the pure CONTRACTS: [`PlaneCfg`] (a plane section asked for its own secrets / registry
//! queries), [`PlaneEndpointCfg`] (its endpoint twin), [`ContainerGateInputs`] (a section's hook-gate
//! inputs, a POD), and [`refuse_cross_plane_reference`] (the parse-time bare-hook-reference rule, a
//! pure string judgement). They name only `busbar_api::SecretRef` + `serde_json`/`std::any`, so they
//! live here; core re-exports them, so `crate::plane::config::{PlaneCfg, PlaneEndpointCfg,
//! ContainerGateInputs, refuse_cross_plane_reference}` still resolves there.
//!
//! The SECTION-MAP SPLIT — [`split_section`], its [`Section`] carrier, the reserved-key literal
//! ([`RESERVED_SECTION_KEYS`]) and the reserved-name refusal — is here too: it is pure `serde` +
//! `indexmap` + `busbar_api::UpstreamCreds` once its ONE registry coupling (the `PlaneDecl` lookup
//! that turned a plane key into the section/noun WORDS) is lifted out into a param pair the caller
//! supplies, so an extracted plane reads its own section without naming core. Core keeps only a thin
//! `split_section` WRAPPER that supplies those words from `busbar_core::plane::registry` for its own
//! callers, and `config_sections`, which reaches that registry. So this module is now the whole config
//! reader a plane needs; the registry-coupled `config_sections` singleton stays core.

/// A PLANE'S CONFIG SECTION, ASKED FOR ITS OWN SECRETS — so core enumerates a plane's credential
/// references without naming that plane's credential-bearing types.
///
/// Implemented by the type a plane's top-level config section deserializes into (`tools:` →
/// `busbar_mcp`'s `ToolsCfg`, `agents:` → `busbar_core::a2a::config::AgentsCfg`). The composition
/// walk in `config_validate::secret_refs` gathers every plane's references by LOOPING this trait over
/// the configured plane sections, rather than destructuring each plane's own config types itself: the
/// section that owns a credential is the section that knows it is one.
///
/// [`Self::secret_refs`] destructures its plane's config types EXHAUSTIVELY (no `..`), so the
/// anti-omission force that used to live in `config_validate::secret_refs` — adding a credential
/// field to a plane fails to compile until someone decides, in the impl, whether it is a secret —
/// travels with the plane instead of staying behind in core.
pub trait PlaneCfg: std::any::Any + Send + Sync + std::fmt::Debug {
    /// EVERY secret reference this plane's config section carries, as `(config-path, &SecretRef)`,
    /// where the path is the operator-facing dotted location `--validate` prints in an error. The
    /// path is fully qualified from the top-level section down (`tools.<name>.env.<var>`), so a
    /// caller can concatenate the planes' answers with no per-plane prefixing of its own.
    fn secret_refs(&self) -> Vec<(String, &busbar_api::SecretRef)>;

    /// Is `name` a REGISTRATION in this section (a `tools:` server / an `agents:` agent)? The
    /// membership check the config resolver and the admin write path consult without naming the
    /// plane's registry type.
    fn contains_def(&self, name: &str) -> bool;

    /// Every registration NAME in this section, in registry order — the enumeration the unified
    /// pool-name validator folds into its global-uniqueness sets without naming the plane's registry
    /// type. Borrowed from the section, so a caller collects them into a `&str` set for free.
    fn def_names(&self) -> Vec<&str>;

    /// This section's CURRENT entry for `name`, projected back to a raw definition document, or
    /// `None` when there is no such entry — the base half of the overlay's per-entry merge, so the
    /// generic named-map path round-trips an entry without naming the plane's entry type.
    fn entry_document(&self, name: &str) -> Option<serde_json::Value>;

    /// Parse a raw definition document into this section's typed entry and insert it under `name`,
    /// returning the SAME error string boot produces on a malformed entry — so the admin write path
    /// installs a `tools:`/`agents:` entry without core naming the entry type.
    fn insert_def(&mut self, name: &str, def: &serde_json::Value) -> Result<(), String>;

    /// This section's HOOK-GATE INPUTS — the reserved section-level attach list and each
    /// registration's own hook list, in registry order — so `appbuild` resolves the per-registration
    /// gates without naming the plane's registry type. See [`ContainerGateInputs`].
    fn container_gates(&self) -> ContainerGateInputs;

    /// The plane's own SECTION-WIDE registry rules, run at resolve — today the MCP plane's
    /// published-name uniqueness, which is the one rule that is not about a single registration. A
    /// section with no cross-registration rule returns `Ok(())`.
    fn validate_registry(&self) -> Result<(), String>;

    /// True when the operator actually wrote CONTENT for this section (a non-empty registry). Read by
    /// the config deletion-gate leg to refuse a present section that names a compiled-out plane — so it
    /// is called ONLY in a build where at least one plane is off; with both planes compiled in every
    /// section names a plane this build serves and no leg reads it.
    #[cfg_attr(all(feature = "dispatch", feature = "relay"), allow(dead_code))]
    fn is_present(&self) -> bool;

    /// This section as `&dyn Any`, so a plane's own module can downcast it back to its concrete
    /// config type across the type-erased seam.
    fn as_any(&self) -> &dyn std::any::Any;

    /// A boxed clone — the trait-object `Clone` `RootCfg`/`DeployCfg` need since `Box<dyn PlaneCfg>`
    /// is not `Clone` on its own.
    fn clone_box(&self) -> Box<dyn PlaneCfg>;

    /// A clone erased into `Arc<dyn Any>` around the CONCRETE section type — the carrier `App`'s
    /// type-erased config slot holds, so a plane's own module downcasts it back to its concrete type.
    fn clone_arc_any(&self) -> std::sync::Arc<dyn std::any::Any + Send + Sync>;
}

/// A PLANE SECTION'S HOOK-GATE INPUTS, in the neutral shape `appbuild::resolve_container_gates`
/// reads — the reserved section-level `hooks:` attach list, and each registration's `(name, hooks)`
/// in registry order. Neutral so a plane hands its gate inputs across the seam without core naming
/// the plane's registry type.
pub struct ContainerGateInputs {
    /// The reserved `<section>.hooks:` all-section attach list (`ToolsCfg::all_server_hooks` /
    /// `AgentsCfg::all_agent_hooks`).
    pub section_hooks: Vec<String>,
    /// Each registration and its OWN `hooks:` list, in registry (insertion) order — the order the
    /// gate resolution and every operator-facing listing already read.
    pub containers: Vec<(String, Vec<String>)>,
}

/// A PLANE'S TOP-LEVEL ENDPOINT SECTION (the MCP plane's `mcp:` block — busbar's own resource-server
/// door), captured through the neutral seam so `DeployCfg` names no `busbar_mcp` endpoint type. The
/// twin of [`PlaneCfg`] for the one plane section that is an ENDPOINT rather than a registry.
pub trait PlaneEndpointCfg: std::any::Any + Send + Sync + std::fmt::Debug {
    /// True when the operator wrote CONTENT for this endpoint block — read by the config
    /// deletion-gate leg to refuse a present `mcp:` block that names a compiled-out plane.
    fn is_present(&self) -> bool;
    /// This endpoint as `&dyn Any`, so the plane's own module downcasts it back to its concrete
    /// endpoint config to LOWER it into the validated resource.
    fn as_any(&self) -> &dyn std::any::Any;
}

/// WHY a hook reference was refused. Three arms, and each one is a different thing for an operator
/// to do about it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HookRefError {
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
/// the set the config grammar declares — see `busbar_core::plane::config::config_sections`.
/// Production passes that; a test passes a plane busbar does not have and gets the same judgement
/// with nothing written for it.
///
/// No I/O, no globals, no config types: a string and a list of section names in, a verdict out.
///
/// `pub` (rather than the pre-move `pub(crate)`) so `busbar_core`'s `plane::config` tests can reach
/// it through the core re-export; its only production caller is [`refuse_cross_plane_reference`].
pub fn judge_hook_ref(hook: &str, sections: &[&'static str]) -> Result<(), HookRefError> {
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
pub fn refuse_cross_plane_reference(
    at: &str,
    hook: &str,
    sections: &[&'static str],
) -> Result<(), String> {
    judge_hook_ref(hook, sections).map_err(|err| Refusal { at, err }.into())
}

/// THE SECTION-LIST PROVIDER SEAM — the neutral read side of core's registry-coupled
/// [`config_sections`] singleton (which stays in `busbar_core::plane::config`, since it folds the
/// process plane registry this crate must not name).
///
/// A plane crate that refuses a cross-plane hook reference at parse time needs the WHOLE section
/// list — its own section plus every other plane's — to judge against, but must not reach into core
/// to fold it. So the composition root binds core's `config_sections` fn here once (before the CLI
/// flags read `--validate`), and a plane reads the same list back through [`plane_sections`] without
/// naming the registry. Before any bind, [`plane_sections`] yields the empty list — a section-less
/// judgement that still refuses malformed (dotted) references, only not the cross-plane ones, which
/// is why the bind is on the boot path ahead of config validation rather than lazy.
static PLANE_SECTIONS: std::sync::OnceLock<fn() -> Vec<&'static str>> = std::sync::OnceLock::new();

/// BIND the process section-list provider. Idempotent (first bind wins); the composition root calls
/// this once at startup with `busbar_core::plane::config::config_sections`.
pub fn install_plane_sections(provider: fn() -> Vec<&'static str>) {
    let _ = PLANE_SECTIONS.set(provider);
}

/// THE PROCESS SECTION LIST, read through the bound provider — or the empty list if none is bound
/// (the pre-bind / no-planes build), which still lets [`refuse_cross_plane_reference`] refuse a
/// dotted reference, just not attribute it to a plane.
pub fn plane_sections() -> Vec<&'static str> {
    PLANE_SECTIONS
        .get()
        .map(|provider| provider())
        .unwrap_or_default()
}

/// THE FROZEN 1.5.3 NAMED-DEFINITION-MAP SECTION KEYS, in route/mount order (additive-only since
/// 1.5.3, guarded by the config-stability gate). `identity-providers`/`export` are core-native;
/// `tools`/`agents` are the MCP/A2A plane sections, listed here too so a fold matches core's
/// `NamedMapSection::sections()` tail whether or not those planes are registered.
///
/// This is the STATIC NOUN SOURCE the deletion-gate and every `.key()` repoint read after the
/// `NamedMapSection::Tools`/`Agents` variants were folded into `Plane(&str)`: it does NOT go empty
/// when a plane is compiled out, so a `tools:`/`agents:` block written for an absent plane is still
/// recognised (and refused) rather than silently accepted. None is a plane KEY, so the
/// neutral-purity lint's token rules do not fire on them.
pub const NAMED_MAP_SECTIONS: [&str; 4] = ["identity-providers", "export", "tools", "agents"];

/// TEST-SUPPORT SEAM — the section-list PROVIDER a plane's `testkit` binds through
/// [`install_plane_sections`], so an extracted plane crate reaches the NEUTRAL ABI rather than back
/// into `busbar_core::plane::config::config_sections`. Byte-for-byte the same fold that singleton runs:
/// every registered plane's own `config_section` (from [`crate::plane::registry::test_registered_planes`],
/// in registration order) followed by the frozen 1.5.3 named-definition-map sections, deduped in that
/// order. `tools:`/`agents:` appear in BOTH halves — a plane declares them and they are also 1.5.3
/// named-map sections — so the trailing pair guarantees they are known even when their owning plane is
/// not registered in a given test binary, exactly as core's `NamedMapSection::sections()` tail does.
#[cfg(any(test, feature = "test-support"))]
pub fn default_plane_sections() -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for section in crate::plane::registry::test_registered_planes()
        .iter()
        .map(|d| d.config_section)
        .chain(NAMED_MAP_SECTIONS)
    {
        if !out.contains(&section) {
            out.push(section);
        }
    }
    out
}

/// THE ADDITIVE-LIST COMBINE RULE, stated once for every plane that has one.
///
/// A section-level attach (`pools.hooks:` / `tools.hooks:` / `agents.hooks:`) and an entry's own
/// `hooks:` are a LIST, and a LIST combines ADDITIVELY: section first, then the entry's own, deduped
/// by name so a hook named in both fires ONCE, at its first (section) position.
///
/// Lives on the neutral seam beside [`ContainerGateInputs`] (whose inputs it folds) rather than once
/// per plane because it is a rule of the CONFIG GRAMMAR, not of any plane — and because two copies of
/// it is exactly how the section list and an entry list come to dedupe differently on one plane and
/// not the other. Core re-exports it at `crate::hooks::attach_list`; the extracted plane crates reach
/// it here without naming `busbar_core::hooks`.
pub fn attach_list(section: &[String], own: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::with_capacity(section.len() + own.len());
    for h in section.iter().chain(own) {
        if !out.iter().any(|e| e == h) {
            out.push(h.clone());
        }
    }
    out
}

// ── THE SECTION-MAP SPLIT ────────────────────────────────────────────────────────────────────────
//
// The reserved-key refusals + the two typed lifts (`hooks:` / `upstream_credentials:`) a plane's
// top-level section is read into, plus the reserved-key literal and the operator refusal sentence.
// Relocated here from `busbar_core::plane::config` so an extracted plane crate reads its own section
// without naming core: the ONE registry coupling — the `PlaneDecl` lookup that turned a plane key
// into the section/noun WORDS — is lifted OUT into a param pair the caller supplies (a plane passes
// its own `PLANE_DECL.config_section` / `subject_noun` consts), so this half names only `serde` +
// `indexmap` + `busbar_api::UpstreamCreds` and no registry. Core wraps it with the lookup for its own
// callers (`config::split_section(deserializer, plane_key, validate)`), so those are unchanged.

/// THE TWO WORDS RESERVED AT EVERY PLANE SECTION'S TOP LEVEL: the all-plane `hooks:` attach list and
/// the `upstream_credentials:` default. Every other key is a registration.
///
/// THE ONE declaration of the pair, now that the split that reads it lives here: core re-exports it as
/// both `crate::plane::config::RESERVED_SECTION_KEYS` and `crate::config::RESERVED_POOLS_SECTION_KEYS`,
/// so there is still a single `&["hooks", "upstream_credentials"]` literal in the tree and a word
/// cannot come to be reserved on one plane and free on another.
pub const RESERVED_SECTION_KEYS: &[&str] = &["hooks", "upstream_credentials"];

/// One plane's top-level section, split into its two reserved knobs and its registrations.
///
/// Insertion-ordered, because catalogue construction and every operator-facing listing read it and a
/// hash-ordered listing is a listing that changes between runs for no reason. A plane that wants
/// another container converts once, at the end, where the conversion is visible.
pub struct Section<T> {
    /// The reserved `<section>.hooks:` all-plane attach list. LIST ⇒ ADDITIVE.
    pub hooks: Vec<String>,
    /// The reserved `<section>.upstream_credentials:` all-plane default. SCALAR ⇒ OVERRIDE.
    pub upstream_credentials: Option<busbar_api::UpstreamCreds>,
    /// The registrations — every key that is not one of [`RESERVED_SECTION_KEYS`].
    pub entries: indexmap::IndexMap<String, T>,
}

/// THE SECTION-MAP SPLIT, and the only copy of it: read one plane's top-level section into its two
/// reserved knobs and its registrations, in the one order all three planes are read in.
///
/// `section` / `noun` supply the WORDS for the operator sentences (a plane passes its own decl's
/// `config_section` and `subject_noun`), so no caller carries a second vocabulary for its own section
/// and the split names no plane registry; `validate` is the plane's VALUE RULES, run on each entry as
/// it is parsed, so the file and the admin write path refuse the same definitions — the ONE GRAMMAR,
/// TWO PATHS rule. A plane with no value rules passes `|_, _| Ok(())`.
///
/// The REFUSAL ORDER is the load-bearing part. A reserved key holding a MAPPING is somebody trying to
/// define a registration by that name, and it is refused BEFORE the typed lifts so the operator reads
/// "that name is reserved" rather than "expected a sequence" — the diagnosis is different, and the
/// confusing one costs an operator an afternoon.
pub fn split_section<'de, D, T>(
    deserializer: D,
    section: &'static str,
    noun: &'static str,
    validate: impl Fn(&str, &T) -> Result<(), String>,
) -> Result<Section<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    use serde::de::Error as _;
    use serde::Deserialize as _;

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
    // THE SENTENCE IS 1.5.5's, TO THE BYTE, with the section word substituted in — the same rule
    // the reserved-name refusal below is held to. `must be a credential mode (`own` or
    // `passthrough`)` says no more than `must be `own` or `passthrough`` and says it in different
    // bytes, and different bytes are what an operator's log alert notices.
    let upstream_credentials = match raw.shift_remove("upstream_credentials") {
        None => None,
        Some(v) => Some(busbar_api::UpstreamCreds::deserialize(v).map_err(|e| {
            D::Error::custom(format!(
                "the reserved `{section}.upstream_credentials:` all-{section} default must be \
                 `own` or `passthrough`: {e}"
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
/// IT IS 1.5.5's SENTENCE, TO THE BYTE, with `pools:`/`pool` substituted in — the wording an
/// operator's runbook, log alert and CI grep were written against. The generalisation to the other
/// planes is the section/noun substitution and NOTHING ELSE: a clause this refusal did not carry in
/// 1.5.5 (however true) changes the line a matcher matches, so it stays out. It names the section,
/// what the two words ARE, and what to do instead.
fn reserved_name_refusal(section: &str, noun: &str, name: &str) -> String {
    format!(
        "a {noun} may not be named `{name}`: that key is RESERVED at the \
         `{section}:` section level (the all-{section} `hooks:` attach list and \
         `upstream_credentials:` default). Rename the {noun}."
    )
}

// ── THE PLANE-SECTION CARRIERS AND THE DERIVED SECTION GRAMMAR ───────────────────────────────────
//
// Relocated from `busbar_core::plane::config`. These are the neutral CARRIERS a config document holds
// a plane's top-level section in (`tools:`, `agents:`, `streams:`, the `mcp:` endpoint door) plus the
// two rules derived from the plane registry — the section list a bare hook reference is judged against
// and the registry-lookup wrapper around [`split_section`]. They moved down with the registry's
// population half so the config layer can name them without an edge into core; nothing here spells a
// plane key or a dialect, because every plane-specific fact is read off a `PlaneDecl` the plane itself
// registered. Core re-exports each at its historical `crate::plane::config::…` spelling.

/// A PLANE'S TOP-LEVEL CONFIG SECTION, CAPTURED RAW — the neutral carrier the config document uses for
/// a plane's section in a build where the plane that would LOWER it is compiled out.
///
/// The MCP plane's `tools:`/`mcp:` sections and the A2A plane's `agents:` section deserialize into that
/// plane's own registry type — types that do not exist when their plane is compiled out. So in that
/// build the field holds a `RawPlaneSection` instead, which captures whatever the operator wrote
/// without naming a plane type. A section that carries CONTENT in such a build names a plane that is
/// not present; `resolve` REFUSES it (see the config deletion-gate leg), exactly as the protocol
/// registry refuses a config naming a deleted dialect.
///
/// This type lives OUTSIDE the config document's own directory on purpose: `cargo xtask gate
/// config-schema` fingerprints that directory, and the plane-gated twin field (declared LAST) is what
/// that fingerprint records — so the `tools:`/`mcp:`/`agents:` schema is unchanged by this capture. A
/// `RawPlaneSection` declared under `config/` would add a new fingerprinted type and drift the
/// committed snapshot; declared here it never enters the config surface.
///
/// Compiled UNCONDITIONALLY: besides the compiled-out-plane capture, it is the empty-section fallback
/// the neutral `*Section` newtypes take when a plane hook is absent, so it must exist in every feature
/// combination (including both planes on, where it is simply never constructed).
#[derive(Debug, Clone, Default)]
pub struct RawPlaneSection {
    /// The captured value, or `None` when the section was absent or explicitly null.
    raw: Option<serde_yaml::Value>,
}

impl<'de> serde::Deserialize<'de> for RawPlaneSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_yaml::Value::deserialize(deserializer)?;
        let raw = if value.is_null() { None } else { Some(value) };
        Ok(RawPlaneSection { raw })
    }
}

// A raw-captured section carries no ENUMERABLE secrets: it is unparsed, and a non-empty one is
// refused at resolve, so it never reaches a running deployment. Implementing the seam with an empty
// answer lets the validator's `secret_refs` loop the trait over the section bindings uniformly, the
// same way it does for the typed plane configs, without naming the compiled-out plane's types.
impl PlaneCfg for RawPlaneSection {
    fn secret_refs(&self) -> Vec<(String, &busbar_api::SecretRef)> {
        Vec::new()
    }
    // A raw-captured section holds no PARSED registry: it names a compiled-out plane and is refused at
    // resolve, so every registry query answers empty. These are reached only for the neutral carrier's
    // uniform loop; the deletion-gate refusal is what actually fires for a present raw section.
    fn contains_def(&self, _name: &str) -> bool {
        false
    }
    fn def_names(&self) -> Vec<&str> {
        Vec::new()
    }
    fn entry_document(&self, _name: &str) -> Option<serde_json::Value> {
        None
    }
    fn insert_def(&mut self, _name: &str, _def: &serde_json::Value) -> Result<(), String> {
        // Unreachable in practice: the named-map write path refuses a compiled-out plane's section
        // BEFORE install (see `NamedMapSection::parse_def`). Fail closed if a caller ever reaches it.
        Err("this build was compiled without the plane that owns this section".to_string())
    }
    fn container_gates(&self) -> ContainerGateInputs {
        ContainerGateInputs {
            section_hooks: Vec::new(),
            containers: Vec::new(),
        }
    }
    fn validate_registry(&self) -> Result<(), String> {
        Ok(())
    }
    fn is_present(&self) -> bool {
        RawPlaneSection::is_present(self)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn clone_box(&self) -> Box<dyn PlaneCfg> {
        Box::new(self.clone())
    }
    fn clone_arc_any(&self) -> std::sync::Arc<dyn std::any::Any + Send + Sync> {
        std::sync::Arc::new(self.clone())
    }
}

// The `mcp:` ENDPOINT carrier when the MCP plane is compiled out: a present `mcp:` block names a
// plane this build cannot serve, refused at resolve (the deletion-gate leg) exactly as a present
// `tools:` section is.
impl PlaneEndpointCfg for RawPlaneSection {
    fn is_present(&self) -> bool {
        RawPlaneSection::is_present(self)
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

impl RawPlaneSection {
    /// True when the operator actually wrote CONTENT for this section (a non-empty mapping or any
    /// non-null scalar/sequence). An absent, null, or empty-mapping section is not "present": it
    /// names no plane and is not refused.
    pub fn is_present(&self) -> bool {
        match &self.raw {
            None | Some(serde_yaml::Value::Null) => false,
            Some(serde_yaml::Value::Mapping(m)) => !m.is_empty(),
            Some(_) => true,
        }
    }
}

/// This plane's EMPTY registry section, via its `default_section` seam hook — the value a neutral
/// `*Section` newtype takes when its `#[serde(default)]` field is ABSENT. A plane compiled out has no
/// hook and falls back to an empty raw capture (never present, never refused). Byte-identical to the
/// pre-seam typed field's `Default`.
fn default_plane_section(config_section: &str) -> Box<dyn PlaneCfg> {
    match crate::plane::registry::plane_decl_for_config_section(config_section)
        .and_then(|d| d.default_section)
    {
        Some(f) => f(),
        None => Box::new(RawPlaneSection::default()),
    }
}

/// Deserialize this plane's top-level registry section through its `parse_section` seam hook, so the
/// neutral carrier names no plane registry type. A plane compiled out has no hook and captures the
/// section RAW (refused at `resolve` if present). The hook's `Err(String)` is surfaced through
/// `de::Error::custom`, so it rides the SAME `from_str::<DeployCfg>` channel a typed field's parse
/// error rode — the operator sees the plane's own sentence, byte-identical bar any `at line` suffix.
fn deserialize_plane_section<'de, D>(
    config_section: &str,
    deserializer: D,
) -> Result<Box<dyn PlaneCfg>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    let value = serde_yaml::Value::deserialize(deserializer)?;
    match crate::plane::registry::plane_decl_for_config_section(config_section)
        .and_then(|d| d.parse_section)
    {
        Some(parse) => parse(&value).map_err(serde::de::Error::custom),
        None => {
            let raw = if value.is_null() { None } else { Some(value) };
            Ok(Box::new(RawPlaneSection { raw }))
        }
    }
}

/// Deserialize this plane's top-level ENDPOINT block (the MCP plane's `mcp:` door) through its
/// `parse_endpoint` seam hook — the twin of [`deserialize_plane_section`] for the one plane section
/// that is an endpoint rather than a registry. Compiled out ⇒ raw capture, refused at `resolve`.
fn deserialize_plane_endpoint<'de, D>(
    config_section: &str,
    deserializer: D,
) -> Result<Option<Box<dyn PlaneEndpointCfg>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize as _;
    let value = serde_yaml::Value::deserialize(deserializer)?;
    if value.is_null() {
        return Ok(None);
    }
    match crate::plane::registry::plane_decl_for_config_section(config_section)
        .and_then(|d| d.parse_endpoint)
    {
        Some(parse) => parse(&value).map(Some).map_err(serde::de::Error::custom),
        None => Ok(Some(Box::new(RawPlaneSection { raw: Some(value) }))),
    }
}

/// THE `tools:` MCP SERVER REGISTRY as it lands in the config document, type-erased behind
/// [`PlaneCfg`] — the neutral seam the MCP plane's `ToolsCfg` deserializes through, so the document
/// names no plane type. Absent ⇒ the plane's `Default` (an empty registry).
#[derive(Debug)]
pub struct ToolsSection(pub Box<dyn PlaneCfg>);

impl Default for ToolsSection {
    fn default() -> Self {
        ToolsSection(default_plane_section(NAMED_MAP_SECTIONS[2]))
    }
}
impl<'de> serde::Deserialize<'de> for ToolsSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_plane_section(NAMED_MAP_SECTIONS[2], deserializer).map(ToolsSection)
    }
}

/// THE `agents:` A2A REGISTRY as it lands in the config document, type-erased behind [`PlaneCfg`] —
/// the neutral seam the A2A plane's `AgentsCfg` deserializes through. Absent ⇒ an empty registry.
#[derive(Debug)]
pub struct AgentsSection(pub Box<dyn PlaneCfg>);

impl Default for AgentsSection {
    fn default() -> Self {
        AgentsSection(default_plane_section(NAMED_MAP_SECTIONS[3]))
    }
}
impl<'de> serde::Deserialize<'de> for AgentsSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_plane_section(NAMED_MAP_SECTIONS[3], deserializer).map(AgentsSection)
    }
}

/// THE `streams:` SECTION as it lands in the config document, type-erased behind [`PlaneCfg`] — the
/// neutral seam the owning plane's `StreamsCfg` deserializes through, so the document names no plane
/// type. Absent ⇒ the plane's `Default` (the empty `streams:`).
///
/// `streams` is a SINGULAR typed section (one live posture per deployment), NOT a named-definition
/// map, so it is keyed by the bare `"streams"` config-section literal rather than a `NamedMapSection`
/// index — the generic seam resolves the owning decl by that config section. The plane compiled out
/// (the default build) captures it RAW and refuses a present section at `resolve`, exactly as
/// `tools:`/`agents:` are.
#[derive(Debug)]
pub struct StreamsSection(pub Box<dyn PlaneCfg>);

impl Default for StreamsSection {
    fn default() -> Self {
        StreamsSection(default_plane_section("streams"))
    }
}
impl<'de> serde::Deserialize<'de> for StreamsSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_plane_section("streams", deserializer).map(StreamsSection)
    }
}

/// THE `mcp:` ENDPOINT BLOCK as it lands in the config document, type-erased behind
/// [`PlaneEndpointCfg`] — the neutral seam the MCP plane's `McpCfg` deserializes through. Absent/null
/// ⇒ `None` (not an MCP server), byte-identical to the pre-seam `Option<McpCfg>::default()`.
#[derive(Debug, Default)]
pub struct McpEndpointSection(pub Option<Box<dyn PlaneEndpointCfg>>); // plane-purity: frozen-wire McpEndpointSection is recorded verbatim in config-schema.snapshot.json as the mcp: field type

// plane-purity: frozen-wire the impl below is for McpEndpointSection, the snapshot-recorded mcp: field type
impl<'de> serde::Deserialize<'de> for McpEndpointSection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserialize_plane_endpoint(
            // The endpoint door is owned by the `tools:` plane, so it is keyed by that CONFIG
            // SECTION — no plane key is named here.
            NAMED_MAP_SECTIONS[2],
            deserializer,
        )
        .map(McpEndpointSection) // plane-purity: frozen-wire the snapshot-recorded mcp: field type
    }
}

/// EVERY TOP-LEVEL CONFIG SECTION a bare hook reference could be reaching onto, DERIVED from the two
/// tables that declare the config grammar rather than written as a literal.
///
/// [`crate::plane::registry::PlaneDecl::config_section`] over
/// [`crate::plane::registry::plane_decls`] gives the plane sections (`pools:`, `tools:`, `agents:`,
/// and any registered plane's own section); [`NAMED_MAP_SECTIONS`] gives the 1.5.3 named-definition
/// maps (`identity-providers:`, `export:`, and the two plane sections again, which is why this
/// de-duplicates). Both tables state that their variant set is the only thing a new section adds —
/// this function is what makes that true for the hook-reference rule too.
///
/// Order is deterministic (plane tables first, in layering order) so a refusal naming a section
/// names the same one on every run. A nondeterministic diagnostic makes a boot failure
/// unreproducible.
pub fn config_sections() -> Vec<&'static str> {
    config_sections_from(crate::plane::registry::plane_decls())
}

/// THE SECTION FOLD, over a GIVEN plane declaration list rather than the process one — so a test can
/// pass a plane busbar does not have and watch its section reach this grammar with nothing written
/// for it. [`config_sections`] passes the process [`crate::plane::registry::plane_decls`]; the plane
/// sections come off each decl's [`crate::plane::registry::PlaneDecl::config_section`] rather than an
/// enum `match`, which is what lets a registered plane's section into the hook-reference grammar.
pub fn config_sections_from(
    decls: &[&'static crate::plane::registry::PlaneDecl],
) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = Vec::new();
    for section in decls
        .iter()
        .map(|decl| decl.config_section)
        .chain(NAMED_MAP_SECTIONS)
    {
        if !out.contains(&section) {
            out.push(section);
        }
    }
    out
}

/// A whole attach list, judged by the same rule one entry is — the SECTION-level `hooks:` list has
/// no per-entry parse to hang off, and a looser rule there would be a hole in exactly the place an
/// operator attaches a control to everything.
pub fn validate_section_hooks(
    at: &str,
    hooks: &[String],
    sections: &[&'static str],
) -> Result<(), String> {
    for hook in hooks {
        refuse_cross_plane_reference(at, hook, sections)?;
    }
    Ok(())
}

/// THE SECTION-MAP SPLIT FOR A CALLER THAT HOLDS A PLANE KEY: turn a plane KEY into the section/noun
/// WORDS via the plane registry, then hand off to the neutral [`split_section`].
///
/// `plane_key` supplies the WORDS (its decl's `config_section` and `subject_noun`) so no caller
/// carries a second vocabulary for its own section; `validate` is the plane's VALUE RULES, run on
/// each entry as it is parsed, so the file and the admin write path refuse the same definitions —
/// the ONE GRAMMAR, TWO PATHS rule. A plane with no value rules passes `|_, _| Ok(())`.
///
/// An extracted plane crate skips this wrapper and calls [`split_section`] directly with its OWN
/// `PLANE_DECL.config_section` / `subject_noun` consts — it holds no plane registry to look up.
pub fn split_section_for_plane<'de, D, T>(
    deserializer: D,
    plane_key: &'static str,
    validate: impl Fn(&str, &T) -> Result<(), String>,
) -> Result<Section<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::de::DeserializeOwned,
{
    let d = crate::plane::registry::plane_decl(plane_key);
    split_section(deserializer, d.config_section, d.subject_noun, validate)
}
