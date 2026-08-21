// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SELECTION AND DISPATCH-TIME RE-VALIDATION: what invalidating a session collapses into once the
//! protocol has no sessions left to invalidate, plus the ordering that puts integrity validation
//! ahead of the audit append.
//!
//! ## Two steps, and the gap between them is the whole point
//!
//! 1. **Resolve** — a namespaced name is turned into a bound identity under the snapshot live at
//!    that moment, and the snapshot's GENERATION is recorded with it.
//! 2. **Re-validate at dispatch** — immediately before the call goes out, the LIVE generation is
//!    re-read and the bound identity is re-compared against the LIVE snapshot.
//!
//! Under a stateless protocol that second step is not a backstop to session invalidation — it IS the
//! defence, and it is the only one needed. A call whose candidate was resolved under generation *N*
//! is refused when the live generation is *N+1*, which is what stops an in-flight call outliving
//! the quarantine that was meant to stop it.
//!
//! ## Route on the KEY, never on the description
//!
//! Route ONLY on the bound identity — registered server, namespaced tool, schema/description digest
//! — and never on an upstream's free text. That rule is enforced here by construction and then
//! MACHINE-CHECKED. [`resolve`] takes a namespaced name and a snapshot; there is no argument through
//! which a description could arrive, and no line of this module's code reads `ToolDef::description`.
//! That second half is a test
//! (`tests/routing_key_tests.rs::dispatch_never_reads_a_tool_description`) that scans this module's
//! own source with prose stripped, because "no line reads it" is a claim that decays the moment
//! somebody adds a convenience.
//!
//! The honest limit stays honest: this protects busbar's ROUTING. It does not protect the
//! MODEL's tool-CHOICE. If two approved servers expose near-identical tools, which one the model
//! asks for is the model's decision, outside busbar's routing boundary.
//!
//! ## Order of refusals, and why it is that order
//!
//! Trust state, then grant, then digest, then generation. Each step's refusal message is one an
//! operator can act on, and putting the grant check before the digest check means a caller with no
//! grant learns nothing about the upstream's current schema — a refusal that leaks the thing it is
//! refusing access to is a refusal that has failed at half its job.

// ── NO PRODUCTION CALLER YET ────────────────────────────────────────────────────────────────────
//
// This is the CLIENT-side dispatch entry point, written when the client direction was the only
// half that existed. `tools/call` now enters through `mcp::upstream`, which composes the same
// parts under the SERVER plane's catalogue and trust gate, so this path is redundant on the hot
// path and kept only for the `connect`/refresh flow that has no verb yet.
//
// It is NOT deleted, because its tests are the ones that prove the bound-identity rule holds
// against a hostile tool description. Scoped to this module so anything else in `client/` losing
// its caller still breaks the build.
#![allow(dead_code)]

use super::argguard::{ArgRefusal, ArgScan};
use super::catalogue::{CatalogueCache, CatalogueSnapshot};
use super::egress::EgressDenied;
use super::identity::{BoundIdentity, NameError, ToolKey};
use super::ssrf::{SsrfPolicy, SsrfRefusal};
use crate::trust::TrustState;
use busbar_api::VirtualKey;

/// A resolved candidate, stamped with the generation it was resolved under.
///
/// The generation is on the VALUE rather than read again later from a variable, so a caller cannot
/// hold a bound identity and forget which snapshot produced it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Resolved {
    pub(crate) identity: BoundIdentity,
    pub(crate) generation: u64,
}

/// Why a dispatch was refused. Integrity is validated BEFORE anything is appended to the audit log,
/// and every arm here must then be AUDITED as a rejection rather than dropped: a call that was
/// stopped is exactly the call an investigator later needs a record of.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DispatchRefusal {
    /// The namespaced name did not parse into a `(server, tool)` pair.
    MalformedName(NameError),
    /// No such server in the live catalogue.
    UnknownServer(String),
    /// The server is not `Approved` — pending, quarantined, suspended or in error.
    ServerNotApproved { server: String, state: TrustState },
    /// The server is approved but does not currently offer this tool.
    UnknownTool(String),
    /// THE RUG-PULL REFUSAL: the tool is offered at a digest the operator did not approve.
    SchemaDrift {
        tool: String,
        approved_or_absent: String,
        observed: String,
    },
    /// THE LIFECYCLE-RACE REFUSAL: the catalogue moved between selection and dispatch.
    GenerationMoved { selected: u64, live: u64 },
    /// THE CONFUSED-DEPUTY REFUSAL: the inbound principal's grant does not cover this call.
    Egress(EgressDenied),
    /// The destination failed the dispatch-time SSRF check.
    Ssrf(SsrfRefusal),
    /// THE ARGUMENT REFUSAL: a URL or host carried INSIDE the per-request tool arguments failed the
    /// same check the destination does. The routing rule makes the destination immune to
    /// attacker-chosen text; it does not make the payload immune, and this is the arm that says so.
    ToolArgument(ArgRefusal),
}

impl std::fmt::Display for DispatchRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DispatchRefusal::MalformedName(e) => write!(f, "{e}"),
            DispatchRefusal::UnknownServer(s) => {
                write!(f, "no MCP server `{s}` is registered on this deployment")
            }
            DispatchRefusal::ServerNotApproved { server, state } => write!(
                f,
                "MCP server `{server}` is {state:?}, so it serves nothing; work its changes queue \
                 and re-approve it"
            ),
            DispatchRefusal::UnknownTool(t) => {
                write!(f, "MCP server does not currently offer tool `{t}`")
            }
            DispatchRefusal::SchemaDrift {
                tool,
                approved_or_absent,
                observed,
            } => write!(
                f,
                "tool `{tool}` is offered at digest {observed} but the approved digest is \
                 {approved_or_absent}; the definition changed under the cache and the call is \
                 refused until an operator re-approves it"
            ),
            DispatchRefusal::GenerationMoved { selected, live } => write!(
                f,
                "the MCP catalogue moved from generation {selected} to {live} between selection and \
                 dispatch; the call is refused rather than sent against a snapshot the operator has \
                 already replaced"
            ),
            DispatchRefusal::Egress(e) => write!(f, "{e}"),
            DispatchRefusal::Ssrf(e) => write!(f, "{e}"),
            DispatchRefusal::ToolArgument(e) => write!(f, "{e}"),
        }
    }
}

/// STEP 1 — resolve a namespaced name to a bound identity, under `snapshot`, for `caller`.
///
/// The only routing input is `namespaced`. See the module header for why there is no second one.
pub(crate) fn resolve(
    snapshot: &CatalogueSnapshot,
    namespaced: &str,
    caller: &VirtualKey,
) -> Result<Resolved, DispatchRefusal> {
    let key = ToolKey::parse(namespaced).map_err(DispatchRefusal::MalformedName)?;
    let server = snapshot
        .server(key.server())
        .ok_or_else(|| DispatchRefusal::UnknownServer(key.server().to_string()))?;
    let state = server.state();
    if state != TrustState::Approved {
        return Err(DispatchRefusal::ServerNotApproved {
            server: key.server().to_string(),
            state,
        });
    }
    // GRANT BEFORE DIGEST: an ungranted caller learns that it is ungranted and nothing else.
    super::egress::authorise_tool_egress(caller, &key).map_err(DispatchRefusal::Egress)?;
    let identity = server
        .bound_identity(key.tool())
        .ok_or_else(|| DispatchRefusal::UnknownTool(key.tool().to_string()))?;
    // THE HASH-PIN CHECK. `Approval::serves` is the SAME comparison the operator's changes queue is
    // rendered from, rather than a second opinion that could disagree with it at exactly the moment
    // a call races a quarantine.
    if !server.approval.serves(key.tool(), &identity.digest) {
        return Err(DispatchRefusal::SchemaDrift {
            tool: key.namespaced(),
            approved_or_absent: approved_digest_of(server, key.tool()),
            observed: identity.digest.clone(),
        });
    }
    Ok(Resolved {
        identity,
        generation: snapshot.generation(),
    })
}

/// The digest the operator approved for `tool`, or a marker when none was.
///
/// Rendered rather than returned as an `Option` because it goes straight into an operator-facing
/// refusal, and "approved digest: None" reads as a bug where "not approved" reads as a fact.
fn approved_digest_of(server: &super::catalogue::ServerCatalogue, tool: &str) -> String {
    // Recover it by asking the same gate: the approval's internals are deliberately private, and
    // reaching into them here would be a second reader of a structure that has one.
    if let Some(def) = server.observed.get(tool) {
        let observed = super::catalogue::tool_digest(def);
        if server.approval.serves(tool, &observed) {
            return observed;
        }
    }
    "<not approved at the observed digest>".to_string()
}

/// STEP 2 — re-validate `resolved` against the LIVE cache, immediately before the call goes out.
///
/// Re-reads the generation FIRST and refuses on any movement, without inspecting the new snapshot.
/// That is deliberate: deciding whether a particular change mattered means re-deriving the whole
/// selection, and a "did this specific change affect me" test is exactly the reasoning that lets a
/// revocation slip through. Movement is refusal; the caller retries and re-selects.
pub(crate) fn revalidate(
    cache: &CatalogueCache,
    resolved: &Resolved,
    caller: &VirtualKey,
) -> Result<(), DispatchRefusal> {
    let live = cache.generation();
    if live != resolved.generation {
        return Err(DispatchRefusal::GenerationMoved {
            selected: resolved.generation,
            live,
        });
    }
    // Belt AND braces, and they are not the same check: the generation catches a swap, this catches
    // the case where the snapshot is the one we selected under and the caller's own grant has since
    // been narrowed. A key revocation does not bump the catalogue generation, because the catalogue
    // did not change.
    let snapshot = cache.load();
    let re = resolve(&snapshot, &resolved.identity.key.namespaced(), caller)?;
    if re.identity != resolved.identity {
        return Err(DispatchRefusal::SchemaDrift {
            tool: resolved.identity.key.namespaced(),
            approved_or_absent: resolved.identity.digest.clone(),
            observed: re.identity.digest,
        });
    }
    Ok(())
}

/// STEP 3 — judge the per-request ARGUMENTS against the tool's PINNED input schema.
///
/// Separate from [`resolve`] because it answers a different question. Resolve decides WHERE the
/// call goes, on the bound identity alone; this decides whether the DATA the call carries is
/// admissible. An argument is attacker-influenced content travelling to an operator-chosen
/// destination, which the routing rule does not and cannot address.
///
/// THE SCHEMA IS RE-PINNED HERE. The definition is re-hashed and compared against the digest the
/// resolution carried, so the document the walk reads is the one the operator approved rather than
/// whatever the cache holds at the moment of the walk. A schema swapped underneath this call is
/// drift, and drift refuses.
///
/// Returns what the walk VISITED on success. A caller that wants to know the guard did work — and
/// the tests, which must — can read it, because a walker that visits nothing refuses nothing.
pub(crate) fn check_arguments(
    snapshot: &CatalogueSnapshot,
    resolved: &Resolved,
    arguments: &serde_json::Value,
    policy: SsrfPolicy,
) -> Result<ArgScan, DispatchRefusal> {
    let key = &resolved.identity.key;
    let server = snapshot
        .server(key.server())
        .ok_or_else(|| DispatchRefusal::UnknownServer(key.server().as_str().to_string()))?;
    let def = server
        .observed
        .get(key.tool())
        .ok_or_else(|| DispatchRefusal::UnknownTool(key.tool().to_string()))?;
    let observed = super::catalogue::tool_digest(def);
    if observed != resolved.identity.digest {
        return Err(DispatchRefusal::SchemaDrift {
            tool: key.namespaced(),
            approved_or_absent: resolved.identity.digest.clone(),
            observed,
        });
    }
    super::argguard::guard(&def.input_schema, arguments, policy)
        .map_err(DispatchRefusal::ToolArgument)
}

/// The catalogue one caller may SEE: every served tool the caller holds both grants for.
///
/// Separate from [`resolve`] because they answer different questions at different moments — this is
/// the catalogue filter (an authorisation decision per owner ruling 2), and `resolve` is the
/// credential-selection gate that binds an outbound call to the inbound caller's own grant. Both
/// consult the same `scope_allowed`; neither is the other's backstop.
pub(crate) fn visible_catalogue(
    snapshot: &CatalogueSnapshot,
    caller: &VirtualKey,
) -> Vec<BoundIdentity> {
    snapshot
        .served_tools()
        .into_iter()
        .filter(|bi| super::egress::authorise_tool_egress(caller, &bi.key).is_ok())
        .collect()
}

#[cfg(test)]
#[path = "tests/dispatch_tests.rs"]
mod dispatch_tests;

#[cfg(test)]
#[path = "tests/routing_key_tests.rs"]
mod routing_key_tests;

#[cfg(test)]
#[path = "tests/generation_recheck_tests.rs"]
mod generation_recheck_tests;
