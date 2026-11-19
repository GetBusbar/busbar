// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S CALLS, AS THE HOST'S TWO HALVES SHARE THEM (`BUSBAR-1.6.0.md` Part 3, the plane

use std::sync::Arc;

/// A door's own `validate` over a whole section (its settings, JSON): `Ok`, or the door's words.
pub type SectionJudge = Arc<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>;

/// WHAT A DOOR FACES THE WORLD WITH for one generation, as its `open` published it: the paths it
/// answers on (each with the dialect word a refusal on it wears), the audience it binds, with its
/// protected-resource metadata document (`None` = it binds none), and the names it lists.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DoorFacing {
    /// Each claimed target, as stated (a pattern keeps its `{name}` segments), and its dialect word.
    pub claims: Vec<(String, &'static str)>,
    /// The audience it binds and its resource metadata document.
    pub admission: Option<(String, String)>,
    /// The names its snapshot lists (`PlaneSnapshot::listed`), in its order; empty = none.
    pub listed: Vec<String>,
}

/// A door's facing for a section, its other owned sections (one JSON object keyed by section name,
pub type FacingProbe = Arc<
    dyn Fn(&[u8], &[u8], Option<&str>, &[DialectFacts]) -> Result<DoorFacing, String> + Send + Sync,
>;

/// ONE PROVIDER'S DIALECT FACTS as a door plane is handed them at open (THE DESIGN section 4;
/// `PlaneOpenIn::providers`), owned: its name, its resolved `protocol` and its `error_map` as one
/// JSON object (`None` = it states none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DialectFacts {
    /// The provider's `providers:` key.
    pub name: String,
    /// Its resolved `protocol`.
    pub protocol: String,
    /// Its `error_map`, as JSON; `None` = none stated.
    pub error_map: Option<Vec<u8>>,
}

/// THE ONE BUILDER OF A DOOR PLANE'S OPEN-TIME PROVIDER LIST, for its served instance and its probe
pub fn dialect_facts(
    section: &crate::yaml::Value,
    lookup: impl Fn(&str) -> Option<(String, std::collections::BTreeMap<String, String>)>,
) -> Vec<DialectFacts> {
    use crate::section::{MODEL_PROVIDER_KEY, RESERVED_MODELS_KEY};
    use crate::yaml::{MappingExt as _, ValueExt as _};
    let mut out: Vec<DialectFacts> = Vec::new();
    let referenced = section
        .get(RESERVED_MODELS_KEY)
        .and_then(crate::yaml::ValueExt::as_mapping)
        .into_iter()
        .flat_map(|m| m.values())
        .filter_map(|entry| entry.get(MODEL_PROVIDER_KEY)?.as_str());
    for name in referenced {
        if out.iter().any(|f| f.name == name) {
            continue;
        }
        let Some((protocol, error_map)) = lookup(name) else {
            continue;
        };
        out.push(DialectFacts {
            name: name.to_string(),
            protocol,
            error_map: (!error_map.is_empty())
                .then(|| serde_json::to_vec(&error_map).ok())
                .flatten(),
        });
    }
    out
}

/// ONE ADMIN ROUTE a plane door states in its Statement tail (`PlaneTail::admin_routes`): the verb,
/// the target relative to the admin mount, its flags and the word it is audited under (empty =
/// never audited).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatedAdminRoute {
    /// The verb.
    pub verb: &'static str,
    /// The target, relative to the admin mount.
    pub target: &'static str,
    /// `ROUTE_PUBLIC` or `0`.
    pub flags: u32,
    /// The audit word; empty = never audited.
    pub audit_verb: &'static str,
}

/// Registry facts derived from a plane door's
/// Statement, never declared separately in the root.
/// The loader reads them off the Statement
/// (`sections`) and its plane tail, linked or dropped alike, and the kernel folds them into its
/// plane registry before the config prepass (`busbar_kernel::plane_driver::door::fold`). Every word
/// is kept for the process.
#[derive(Clone)]
pub struct PlaneRegistration {
    /// The plane's registry key: the door's Statement name.
    pub key: &'static str,
    /// The section the Statement declares (`SECTION_DECLARING`): the plane's config verb.
    pub section: &'static str,
    /// The other sections the Statement owns (neither declaring nor consumed): the plane's
    /// endpoint block beside its verb, handed to its `open` as `PlaneOpenIn::owned`.
    pub owns: Vec<&'static str>,
    /// The sections the Statement CONSUMES (`SECTION_CONSUMED`): sections another owner declares
    /// that the plane reads (a kind's root, such as the connections its members are reached over).
    /// A plane that consumes the transport kind's root restricts the members its section names
    /// there to the dialects it states.
    pub consumes: Vec<&'static str>,
    /// The sections the Statement marks REQUIRED (`SECTION_REQUIRED`), in Statement order: a
    /// document must carry each while the plane is linked (CONFIG-REQ, Law 7), and the kernel's
    /// config pre-pass refuses one that omits it with the frozen missing-field text.
    pub requires: Vec<&'static str>,
    /// The Statement's secret-reference paths (`Statement::secret_refs`): the settings paths whose
    /// values are secret references, each `settings.<key>...`, where `*` stands for every key of
    /// the map at that point (each registration, each entry). The kernel enumerates the references
    /// they name in its section, so `--validate` and boot resolve every one.
    pub secret_refs: Vec<&'static str>,
    /// The admin routes its tail states: the kernel's row mounts each on
    /// the admin router, served by the instance's `serve` op.
    pub admin_routes: Vec<StatedAdminRoute>,
    /// Their OpenAPI path fragment, each path relative to the admin mount (JSON); `None` = none.
    pub admin_openapi: Option<&'static [u8]>,
    /// Declared response media types requiring streamed delivery.
    pub streaming_content_types: Vec<&'static str>,
    /// The tail's label (`PlaneTail::label`).
    pub label: &'static str,
    /// The tail's subject noun.
    pub subject_noun: &'static str,
    /// The tail's admin noun.
    pub admin_noun: &'static str,
    /// The tail's audit kind.
    pub audit_kind: &'static str,
    /// The tail's signing domain and key-id prefix; `None` = it signs nothing.
    pub signing: Option<(&'static str, &'static str)>,
    /// The tail's dialects, in order (the plane's wire formats).
    pub dialects: Vec<&'static str>,
    /// Each dialect's `DIALECT_*` flags (its `dialect_auth` line's), parallel to
    /// [`Self::dialects`]: whether a provider's
    /// `protocol` may name it.
    pub dialect_flags: Vec<u32>,
    /// The tail's scope kinds.
    pub scope_kinds: Vec<&'static str>,
    /// The tail's billable classes, each with its unit family.
    pub billable_classes: Vec<(&'static str, &'static str)>,
    /// Validated generic class parent edges.
    pub class_parents: Vec<crate::plane::ClassParent>,
    /// The tail's fee units.
    pub fee_units: Vec<&'static str>,
    /// The tail's record kinds.
    pub record_kinds: Vec<&'static str>,
    /// The tail's kernel-owned trust keys.
    pub trust_keys: Vec<crate::plane::TrustKeyDecl>,
    /// The tail's sentence refusing a forwarded caller credential; `None` = it states none.
    pub caller_credential_refusal: Option<&'static str>,
    /// Whether the tail states `TAIL_FALLBACK`: the plane is the catch-all every unclaimed path
    /// falls through to, and its card is the flat one (at most one registered plane).
    pub fallback: bool,
    /// The provider-key descriptor its Statement states under
    /// [`crate::provider_keys::EXT_PROVIDER_KEYS`]: the `providers:` entry keys the
    /// plane owns, per form, in their frozen order and the neutral shape vocabulary; `None` = it
    /// states none. The kernel's door fold keeps it; nothing parses an entry from it yet.
    pub provider_keys: Option<crate::provider_keys::ProviderKeys>,
    /// The door's own `validate` over a whole section (its settings, JSON): `Ok`, or the door's
    /// words. The kernel runs it where the section is parsed and where an admin write lands.
    pub validate: SectionJudge,
    /// What the door faces the world with for a section, its owned sections and the deployment's
    /// public base URL: the kernel mounts its claims and binds its audience from it, per generation.
    pub facing: FacingProbe,
}

impl std::fmt::Debug for PlaneRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlaneRegistration")
            .field("key", &self.key)
            .field("section", &self.section)
            .finish_non_exhaustive()
    }
}

/// The trust facts a READY `arrive` stated, owned (a counterparty, and optionally an item and
/// the digest it is offered at): what the kernel's Approve judges.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArrivedTrust {
    /// The counterparty, a name among the instance's declared trust entries.
    pub counterparty: Vec<u8>,
    /// The item the unit uses there; `None` = the counterparty as a whole.
    pub item: Option<Vec<u8>>,
    /// The digest the item is offered at now; `None` = none observed.
    pub digest: Option<Vec<u8>>,
}
