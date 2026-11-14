// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE GENERIC NAMED-DEFINITION MAP CRUD — one handler set for every 1.5.3 named map.
//!
//! 1.5.3 froze the config grammar into ONE pattern: every plugin-instance kind is a top-level named
//! DEFINITION map (`name → {module, settings, …}`) referenced by bare name. This module is that
//! pattern on the ADMIN API, so the two mirror each other exactly:
//!
//! | route | scope | meaning |
//! |---|---|---|
//! | `GET    <section>`                  | `read-only` | list every definition |
//! | `GET    <section>/{name}`           | `read-only` | one definition |
//! | `PUT    <section>/{name}`           | `full`      | create-or-replace (upsert) |
//! | `PATCH  <section>/{name}/settings`  | `full`      | replace only the opaque settings bag |
//! | `DELETE <section>/{name}`           | `full`      | remove |
//!
//! `<section>` is `/identity-providers` or `/export` today. **Adding `tools:` (1.5.4 MCP) or
//! `agents:` (1.5.6 A2A) is ONE variant on [`NamedMapSection`]** — [`routes`] mounts from
//! `NamedMapSection::ALL`, `openapi_paths` emits from it, and the error taxonomy declares per route
//! SHAPE — so a new section is purely additive and BREAKS NOTHING already shipped.
//!
//! ## Why this rebuilds the whole `App` instead of patching the snapshot
//!
//! `resolve()` LOWERS these definition maps into runtime shapes — `identity-providers:` becomes the
//! data + admin auth chains, the hosted-login methods and the per-provider scope ceilings; `export:`
//! becomes the recorder, the request-log sinks and the tracer. There is no in-place edit of those
//! that is equivalent to the config path. So a mutation writes the definition into the config
//! OVERLAY and re-runs the boot pipeline (disk truth → overlay → resolve → build), exactly as
//! `PUT /config/settings` does. Same durability contract as every other config mutation:
//! PERSIST-then-SWAP, fail-closed, inside the one `config_transaction`.
//!
//! ## What a successful mutation CANNOT make live: a new plugin ROUTE
//!
//! Every plugin-route PATH is registered on the axum router ONCE, at process start, and a config
//! apply swaps only the `Arc<App>` snapshot — the router is never rebuilt. The two directions are
//! therefore not symmetric: REMOVING an `export:` instance takes effect immediately (the mounted
//! dispatcher resolves the owner from the CURRENT snapshot and 404s when it finds none), while ADDING
//! one that declares a path this process never mounted (a `prometheus` instance, hence `GET /metrics`,
//! where none existed at boot) is stored and live on the snapshot yet keeps 404ing until a RESTART.
//!
//! That used to be a silent 200. The mutation response now carries
//! `reload_to_apply` + `note` ([`MutatedDefView`]) naming exactly the paths this mutation declared and
//! the process cannot serve — the same restart-required contract `PUT /config/settings` has for its
//! boot-frozen fields. Both fields are omitted when nothing is pending, so a mutation that changes no
//! route (including every removal) is byte-identical to what it always answered.
//!
//! ## The `max_admin_scope` TRUST CEILING (identity-providers)
//!
//! `max_admin_scope:` is the ceiling on the admin authority obtainable THROUGH a provider — the
//! backstop that keeps an external IdP from ever minting `full` admins. Raising it over the API is
//! therefore a privilege-escalation lever, so **this API refuses to raise it at all** (409
//! `conflict`, `Cond::TrustCeilingRaise`): a ceiling may be LOWERED (tightening is always safe) or
//! left alone, and raising one is an operator FILE edit. That is strictly stronger than gating the
//! raise on `full` scope — every mutation here already requires `full` at the route matrix, so a
//! scope gate alone would permit exactly the operators this rule stops. It also mirrors the hooks
//! surface's existing rule that a GRANT can never widen in place. Every attempt, allowed or refused,
//! is audited.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch};
use axum::Router;

use super::{
    config_transaction, err_json, err_json_cond, if_match_version, respond, stale_if_match,
    with_config_etag, Outcome,
};
use crate::admin::audit;
use crate::admin::v1::contract::taxonomy::Cond;
use crate::admin::v1::contract::AdminError;
use crate::config::named_map::NamedMapSection;
use crate::state::{App, AppHandle};

/// Mount the five routes of EVERY named-map section. Driven by `NamedMapSection::ALL`, so a new
/// section's routes appear here the moment its variant exists — there is no per-section handler,
/// no per-section route literal, and nothing to forget.
pub(crate) fn routes() -> Router<Arc<AppHandle>> {
    let mut router = Router::new();
    for section in NamedMapSection::ALL {
        let s = *section;
        router = router
            .route(
                s.path_root(),
                get(move |state: State<Arc<AppHandle>>| list(state, s)),
            )
            .route(
                &format!("{}/{{name}}", s.path_root()),
                get(move |state: State<Arc<AppHandle>>, path: Path<String>| {
                    get_one(state, path, s)
                })
                .put(
                    move |state: State<Arc<AppHandle>>,
                          principal: axum::Extension<crate::auth::AuthPrincipal>,
                          path: Path<String>,
                          headers: axum::http::HeaderMap,
                          body: axum::body::Bytes| {
                        put(state, principal, path, headers, body, s)
                    },
                )
                .delete(
                    move |state: State<Arc<AppHandle>>,
                          principal: axum::Extension<crate::auth::AuthPrincipal>,
                          path: Path<String>,
                          headers: axum::http::HeaderMap| {
                        delete(state, principal, path, headers, s)
                    },
                ),
            )
            .route(
                &format!("{}/{{name}}/settings", s.path_root()),
                patch(
                    move |state: State<Arc<AppHandle>>,
                          principal: axum::Extension<crate::auth::AuthPrincipal>,
                          path: Path<String>,
                          headers: axum::http::HeaderMap,
                          body: axum::body::Bytes| {
                        patch_settings(state, principal, path, headers, body, s)
                    },
                ),
            );
    }
    router
}

/// `GET /api/v1/admin/<section>` — every definition in the section (+ the config-plane `ETag`, so a
/// caller chains straight into an `If-Match` mutation without a second read).
async fn list(State(handle): State<Arc<AppHandle>>, section: NamedMapSection) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(
            StatusCode::OK,
            super::service(&handle).list_named_defs(section).await,
        ),
        version,
    )
}

/// `GET /api/v1/admin/<section>/{name}` — one definition (404 if unknown; + the config-plane `ETag`).
async fn get_one(
    State(handle): State<Arc<AppHandle>>,
    Path(name): Path<String>,
    section: NamedMapSection,
) -> Response {
    let version = handle.load().config_version;
    with_config_etag(
        respond(
            StatusCode::OK,
            super::service(&handle).get_named_def(section, &name).await,
        ),
        version,
    )
}

/// What a mutation does to the section's overlay entry — the ONE axis the three write verbs differ
/// on. Everything else (guards, rebuild, persist, swap, audit, versioning) is shared below.
enum Mutation {
    /// `PUT` — the whole definition document, create-or-replace.
    Replace(serde_json::Value),
    /// `PATCH …/settings` — replace ONLY the `settings:` bag of an existing definition.
    Settings(serde_json::Map<String, serde_json::Value>),
    /// `DELETE` — remove the definition.
    Remove,
}

impl Mutation {
    /// The audit ACTION verb (`identity-provider.replace`, `export.delete`, …).
    fn verb(&self) -> &'static str {
        match self {
            Mutation::Replace(_) => "replace",
            Mutation::Settings(_) => "settings",
            Mutation::Remove => "delete",
        }
    }

    /// Does this verb require the name to already exist? `PUT` is an upsert; the other two are not.
    fn requires_existing(&self) -> bool {
        !matches!(self, Mutation::Replace(_))
    }
}

/// `PUT /api/v1/admin/<section>/{name}` — create-or-replace one definition, live after an atomic
/// swap. Body is the definition document exactly as `config.yaml` spells it
/// (`{"module": …, "settings": {…}, …}`), parsed into the section's `deny_unknown_fields` config
/// struct, so a typo is the same loud reject the file would give.
async fn put(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
    section: NamedMapSection,
) -> Response {
    let def: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            return err_json_cond(
                &AdminError::Validation(format!(
                    "malformed {} definition body: {e}",
                    section.singular()
                )),
                Cond::MalformedBody,
            )
        }
    };
    apply(
        handle,
        principal,
        section,
        name,
        headers,
        Mutation::Replace(def),
    )
    .await
}

/// `PATCH /api/v1/admin/<section>/{name}/settings` — replace ONLY the opaque `settings:` bag,
/// leaving every other field of the definition untouched. The narrow edit an operator reaches for
/// (retarget a webhook URL, retune a buffer) without restating the whole definition.
///
/// Unlike `PATCH /hooks/{name}/settings` there is no configure-ack round-trip: a hook is a LIVE
/// process that must acknowledge new settings, while these settings are consumed by re-resolving the
/// config, so the rebuild-and-swap IS the acknowledgement.
async fn patch_settings(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    body: axum::body::Bytes,
    section: NamedMapSection,
) -> Response {
    let req: NamedSettingsReq = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err_json_cond(
                &AdminError::Validation(format!("malformed settings body: {e}")),
                Cond::MalformedBody,
            )
        }
    };
    apply(
        handle,
        principal,
        section,
        name,
        headers,
        Mutation::Settings(req.settings),
    )
    .await
}

/// The `PATCH /api/v1/admin/<section>/{name}/settings` body: the whole replacement settings bag.
/// A sibling of the hooks surface's `PatchSettingsReq` (same shape, same semantics: `settings:` is
/// REPLACED, not deep-merged, so the stored bag is always exactly what the caller sent).
#[derive(serde::Deserialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct NamedSettingsReq {
    // settings-leak-lint: allow — INBOUND request body (`Deserialize` only). This is the operator
    // WRITING the bag; the matching READ projects `settings_keys` (see `NamedDefView`).
    pub(crate) settings: serde_json::Map<String, serde_json::Value>,
}

/// `DELETE /api/v1/admin/<section>/{name}` — remove one definition, live after an atomic swap.
/// `204 No Content` (carrying the new config-plane `ETag`).
///
/// REFUSED as a terminal `conflict` when another config site still references the name (see
/// `NamedMapSection::referents`) — removing an identity provider that `auth.chain:` still names
/// would otherwise take the whole config down at the next resolve.
async fn delete(
    State(handle): State<Arc<AppHandle>>,
    axum::Extension(principal): axum::Extension<crate::auth::AuthPrincipal>,
    Path(name): Path<String>,
    headers: axum::http::HeaderMap,
    section: NamedMapSection,
) -> Response {
    apply(handle, principal, section, name, headers, Mutation::Remove).await
}

/// A rejection that KNOWS its taxonomy condition. The transaction body returns these through the
/// SUCCESS channel (`Ok(Outcome::Value(Err(…)))`) rather than the error channel, purely so the
/// wire projection can name the `Cond` — the transaction's own `Err` channel carries only an
/// `AdminError`, and a 400 whose condition is anonymous is a 400 `openapi.json` cannot describe.
/// Returning through the success channel is behaviourally identical here: every one of these is
/// decided BEFORE anything is persisted or swapped, so nothing is committed either way.
type Rejection = (AdminError, Cond);

/// THE SHARED MUTATION PATH for every named-map write verb.
///
/// In order: parse the guard header → refuse a deployment that cannot durably record a config change
/// → 404 an unknown name (for the verbs that need one) → then, inside the ONE config transaction:
/// re-validate `If-Match` against a fresh post-lock snapshot, re-read BASE config from disk, refuse
/// to shadow a base-defined entry, apply the section-specific guards, rebuild a complete `App` from
/// (disk truth + the mutated overlay), and PERSIST-then-SWAP fail-closed. Audited and version-logged
/// on both outcomes.
async fn apply(
    handle: Arc<AppHandle>,
    principal: crate::auth::AuthPrincipal,
    section: NamedMapSection,
    name: String,
    headers: axum::http::HeaderMap,
    mutation: Mutation,
) -> Response {
    let actor = principal.actor_id().to_string();
    let action = format!("{}.{}", section.singular(), mutation.verb());
    let resource = format!("{}:{name}", section.singular());
    let reject = |e: &AdminError, cond: Cond, actor: &str| -> Response {
        audit::AUDIT.record_by(&action, &resource, audit::OUTCOME_REJECTED, actor);
        err_json_cond(e, cond)
    };

    let expected = match if_match_version(&headers) {
        Ok(v) => v,
        Err(resp) => {
            audit::AUDIT.record_by(&action, &resource, audit::OUTCOME_REJECTED, &actor);
            return resp;
        }
    };
    let current = handle.load();
    // NO DISK BASE: this rebuild re-reads `config.yaml` as the base truth the overlay layers onto.
    // An ephemeral busbar has none — the same 400 `config/reload` and `PUT /config/settings` give.
    let (Some(config_path), Some(providers_path)) =
        (current.config_path.clone(), current.providers_path.clone())
    else {
        return reject(
            &AdminError::Validation(format!(
                "this busbar was started without config files (ephemeral mode); a `{}` mutation has \
                 no disk base to merge onto",
                section.key()
            )),
            Cond::NoDiskBase,
            &actor,
        );
    };
    // LOCKED CONFIG: no writable overlay backend ⇒ runtime config mutation is refused by design
    // (1.5.3 boot invariant: `config.locked` XOR a writable overlay). Refused up front rather than
    // after a full rebuild we could never durably record.
    if current.overlay_path.is_none() {
        audit::AUDIT.record_by(&action, &resource, audit::OUTCOME_REJECTED, &actor);
        return err_json(&AdminError::Validation(
            crate::config::overlay::NO_WRITABLE_OVERLAY_MSG.to_string(),
        ));
    }
    // EXISTENCE before the concurrency guard — the same status precedence the hooks surface
    // establishes, so a stale guard on a nonexistent entry answers 404, never 409.
    if mutation.requires_existing() && !section_contains(&current, section, &name) {
        return reject(
            &AdminError::not_found(format!("{} `{name}`", section.singular())),
            Cond::UnknownResource,
            &actor,
        );
    }
    if let Mutation::Replace(def) = &mutation {
        if let Err(e) = validate_definition(section, &name, def) {
            return reject(&e, Cond::InvalidConfig, &actor);
        }
    }
    if let Mutation::Settings(settings) = &mutation {
        // Bound the settings map on EVERY write path (the same caps the hooks settings push uses):
        // it is persisted verbatim into the config overlay, so an unbounded map bloats durable state.
        if let Err(e) = crate::admin::v1::service::validate_hook_settings_size(settings) {
            return reject(&e, Cond::InvalidConfig, &actor);
        }
    }

    // Captured BEFORE the mutation moves into the transaction body: a removal answers `204`, an
    // upsert answers the stored definition.
    let removes = matches!(mutation, Mutation::Remove);
    let txn_section = section;
    let txn_name = name.clone();
    let out = config_transaction(&handle, move |txn| {
        let current = txn.app();
        if let Some(e) = stale_if_match(expected, current.config_version) {
            return Err(e);
        }
        let snapshot = current.clone();
        // Everything below reads config files + the overlay and re-runs the boot pipeline, so it is
        // queued onto `spawn_blocking` — under the mutation guard, off the reactor.
        Ok(txn.read_store(move || {
            let mut loaded = crate::load_config_from_disk(
                &config_path,
                Some(&providers_path),
                false,
                crate::config::EnvSubst::Strict,
            )
            .map_err(AdminError::Validation)?;
            // BASE-CONFIG PROTECTION: an entry declared in `config.yaml` is operator file config and
            // is never shadowed, retuned or subtracted through the API — the same posture the hooks
            // and groups surfaces take. Checked against the FRESHLY loaded, PRE-overlay deploy, which
            // is the only place base truth actually lives.
            if txn_section.contains(&loaded.deploy, &txn_name) {
                return Ok(Outcome::Value(Err((
                    AdminError::Conflict(format!(
                        "{} `{txn_name}` is defined in the base config file; edit config.yaml (the \
                         API cannot silently shadow operator file config)",
                        txn_section.singular()
                    )),
                    Cond::BaseDefined,
                ))));
            }
            let mut doc = loaded.overlay_doc.clone().unwrap_or_default();
            let entries = doc.named_maps.entry(txn_section.key().to_string()).or_default();
            let next_def: Option<serde_json::Value> = match &mutation {
                Mutation::Replace(def) => Some(def.clone()),
                Mutation::Settings(settings) => {
                    // The target is necessarily an OVERLAY entry (a base entry was refused above),
                    // so its raw definition document is in hand — patch just its `settings` key and
                    // leave every other field byte-identical.
                    let Some(existing) = entries.get(&txn_name) else {
                        return Ok(Outcome::Value(Err((
                            AdminError::not_found(format!(
                                "{} `{txn_name}`",
                                txn_section.singular()
                            )),
                            Cond::UnknownResource,
                        ))));
                    };
                    let mut def = existing.clone();
                    match def.as_object_mut() {
                        Some(obj) => {
                            obj.insert(
                                "settings".to_string(),
                                serde_json::Value::Object(settings.clone()),
                            );
                        }
                        None => {
                            return Ok(Outcome::Value(Err((
                                AdminError::Validation(format!(
                                    "the stored `{}` definition for `{txn_name}` is not an object",
                                    txn_section.key()
                                )),
                                Cond::InvalidConfig,
                            ))))
                        }
                    }
                    Some(def)
                }
                Mutation::Remove => {
                    // DANGLING-REFERENCE GUARD: refuse to remove a definition another config site
                    // still names, rather than letting the rebuild fail with a less actionable
                    // "references X, which is not defined" further down the pipeline.
                    let referents = txn_section.referents(&loaded.deploy, &txn_name);
                    if !referents.is_empty() {
                        return Ok(Outcome::Value(Err((
                            AdminError::Conflict(format!(
                                "cannot delete {} `{txn_name}`: still referenced by {} — remove the \
                                 reference first",
                                txn_section.singular(),
                                referents.join(", ")
                            )),
                            Cond::StillReferenced,
                        ))));
                    }
                    None
                }
            };
            // THE TYPED SCHEMA CHECK — the SAME `deny_unknown_fields` parse `config.yaml` gets, run
            // against the SAME structs (`NamedMapSection::validate_def` delegates to the one
            // `parse_def` the overlay applier uses). Without it the API's grammar and the file's
            // grammar were two different things: a typo'd key (`buffer:` for `buffer_size:`) passed
            // the structural check above, was persisted verbatim into the overlay, and was then
            // silently DROPPED at the next rebuild with only a `tracing::error!` — an accepted 200
            // for config that never took effect. Runs BEFORE anything is persisted or swapped, and
            // covers PATCH …/settings too (its composed document is the thing that must parse).
            if let Some(def) = next_def.as_ref() {
                if let Err(e) = txn_section.validate_def(&txn_name, def) {
                    return Ok(Outcome::Value(Err((
                        AdminError::Validation(e),
                        Cond::InvalidConfig,
                    ))));
                }
            }
            // TRUST CEILING (identity-providers): a `max_admin_scope` may be lowered or left alone,
            // never RAISED through the API. See this module's header for why refusing outright is
            // the right rule rather than gating the raise on a scope the caller necessarily holds.
            if let Some(def) = next_def.as_ref() {
                if let Err(e) = check_trust_ceiling(txn_section, &snapshot, &txn_name, def) {
                    return Ok(Outcome::Value(Err(e)));
                }
            }
            match &next_def {
                Some(def) => {
                    entries.insert(txn_name.clone(), def.clone());
                }
                None => {
                    entries.remove(&txn_name);
                }
            }
            if entries.is_empty() {
                doc.named_maps.remove(txn_section.key());
            }
            // Re-run the boot pipeline over (disk truth + the MUTATED overlay): the named maps and
            // the other pre-resolve sections apply to the `DeployCfg`, then resolve lowers them, then
            // the post-resolve hooks/groups overlay sections merge on — exactly the reload mechanism.
            loaded.overlay_doc = Some(doc.clone());
            let built = (|| {
                crate::config::overlay::apply_root_to_deploy(&mut loaded.deploy, &doc);
                let mut cfg = crate::config::resolve(&loaded.deploy, &loaded.defs)
                    .map_err(|errs| format!("config errors:\n  - {}", errs.join("\n  - ")))?;
                let base_hook_names: std::collections::HashSet<String> =
                    cfg.hooks.keys().cloned().collect();
                let base_group_names: std::collections::HashSet<String> =
                    cfg.groups.keys().cloned().collect();
                crate::config::overlay::merge_into(&mut cfg, doc);
                crate::build_app_from_config(
                    cfg,
                    loaded.deploy.plugins.clone(),
                    // Preserve the LIVE overlay path (not the env-derived one the disk load
                    // returns), exactly as the reset + config/settings rebuilds do.
                    snapshot.overlay_path.clone(),
                    base_hook_names,
                    base_group_names,
                    (Some(config_path), Some(providers_path)),
                    Some(&snapshot),
                )
            })();
            let (built, gov_rotate) = match built {
                Ok(v) => v,
                // The rebuild rejected the mutated config — NOTHING was persisted or swapped.
                Err(e) => {
                    return Ok(Outcome::Value(Err((
                        AdminError::Validation(e),
                        Cond::InvalidConfig,
                    ))))
                }
            };
            let installed = Arc::new(built);
            // RESTART-TO-APPLY, decided on the REBUILT snapshot while the
            // pre-mutation one is still in hand: a mutation that introduces a plugin-route PATH the
            // router never mounted at boot is stored and live on the snapshot, but the path itself
            // keeps 404ing until a restart. Carried out of the transaction so the response can SAY so.
            let awaiting_restart = crate::plugin_routes::paths_awaiting_restart(
                &installed.plugin_routes,
                &snapshot.plugin_routes,
                &installed.boot_route_paths,
            );
            // PERSIST-then-SWAP, fail-closed: the overlay takes the change FIRST; only if disk
            // accepts it does the engine swap. `commit_then` (not `commit`) so a governance
            // credential rotation fires only once persist AND swap have both returned `Ok`.
            let p = installed.clone();
            let persist_name = txn_name.clone();
            let persist_def = next_def.clone();
            Ok(Outcome::commit_then(
                installed.clone(),
                move || {
                    crate::config::overlay::persist_named_map(
                        p.overlay_path.as_deref(),
                        txn_section,
                        &persist_name,
                        persist_def.as_ref(),
                    )
                    .map_err(|e| {
                        format!(
                            "the `{}` change could not be persisted to the overlay: {e}; nothing \
                             was changed (the running engine is unaffected)",
                            txn_section.key()
                        )
                    })
                },
                move || {
                    if let Some(rotate) = gov_rotate {
                        rotate();
                    }
                    Ok(Outcome::Value(Ok((installed, awaiting_restart))))
                },
            ))
        }))
    })
    .await;

    let (installed, awaiting_restart) = match out {
        Ok(Ok(v)) => v,
        Ok(Err((e, cond))) => return reject(&e, cond, &actor),
        // The transaction's own error channel: the `If-Match` staleness guard (whose condition is
        // fixed, so it is named) and persist/infrastructure failures (which are not per-condition
        // documentable and ride the algorithmic responses).
        Err(e @ AdminError::VersionConflict(_)) => {
            return reject(&e, Cond::StaleIfMatch, &actor);
        }
        Err(e) => {
            audit::AUDIT.record_by(&action, &resource, audit::OUTCOME_REJECTED, &actor);
            return err_json(&e);
        }
    };
    audit::AUDIT.record_by(&action, &resource, audit::OUTCOME_APPLIED, &actor);
    installed.versions.record(
        installed.config_version,
        &actor,
        &format!("{action} {resource}"),
        &installed.hook_registry,
        &installed.global_hooks,
    );
    let version = installed.config_version;
    if removes {
        // 204 still carries the NEW config-plane ETag, so a scripted chain needs no re-read. A
        // removal never needs a restart notice: the path stays registered on the router and the
        // dispatcher, resolving the owner from the current snapshot, now finds nothing and 404s.
        return with_config_etag(StatusCode::NO_CONTENT.into_response(), version);
    }
    with_config_etag(
        respond(
            StatusCode::OK,
            super::service(&handle)
                .get_named_def(section, &name)
                .await
                .map(|def| MutatedDefView::new(def, awaiting_restart)),
        ),
        version,
    )
}

/// THE MUTATION RESPONSE for an upsert/settings write: the stored definition, PLUS the
/// restart-required signal when this mutation introduced a plugin route the running process cannot
/// serve.
///
/// `#[serde(flatten)]` keeps the definition's own fields exactly where they have always been, so the
/// signal is purely ADDITIVE — and both signal fields are omitted entirely when nothing is pending,
/// so the ordinary body is byte-identical to what it was. This is the `export:` named map's sibling of
/// `PUT /config/settings`'s `reload_to_apply`/`note` pair (`handlers::reload_to_apply_fields`), which
/// reports the same class of boot-frozen change for the single-value settings surface.
#[derive(serde::Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct MutatedDefView {
    #[serde(flatten)]
    def: crate::admin::v1::contract::NamedDefView,
    /// The plugin-route PATHS this mutation declared that the process cannot serve until it restarts,
    /// because the axum router registers each path once, at boot, and a config apply swaps only
    /// `Arc<App>`. Empty (and omitted) for every mutation that adds no such path — including every
    /// REMOVAL, which genuinely does apply live.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reload_to_apply: Vec<String>,
    /// The operator-facing sentence for [`Self::reload_to_apply`]; omitted with it.
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
}

impl MutatedDefView {
    /// Wrap one stored definition with the restart signal, if any.
    fn new(def: crate::admin::v1::contract::NamedDefView, awaiting_restart: Vec<String>) -> Self {
        let note = (!awaiting_restart.is_empty()).then(|| {
            format!(
                "stored and applied, EXCEPT the newly declared route(s) {} — each plugin route path \
                 is registered on the HTTP router once, at process start, and a config apply swaps \
                 only the config snapshot, so a route that did not exist at boot keeps answering 404 \
                 until the next RESTART (removing one, by contrast, takes effect immediately)",
                awaiting_restart.join(", ")
            )
        });
        Self {
            def,
            reload_to_apply: awaiting_restart,
            note,
        }
    }
}

/// Is `name` present in this section of the LIVE (effective) snapshot? The read-side twin of
/// `NamedMapSection::contains`, which answers the same question about BASE config.
fn section_contains(app: &App, section: NamedMapSection, name: &str) -> bool {
    match section {
        NamedMapSection::IdentityProviders => app.identity_providers.contains_key(name),
        NamedMapSection::Export => app.export_defs.contains_key(name),
    }
}

/// Structural validation of a PUT definition, BEFORE any rebuild: the name is a durable registry key
/// written verbatim into the overlay and every audit row, and `settings:` is persisted verbatim, so
/// both are bounded here exactly as the hooks write path bounds its own. The typed
/// `deny_unknown_fields` parse (the real schema check) runs inside [`apply`]'s transaction against
/// the section's own config struct, before anything is persisted — see the `validate_def` call
/// there.
fn validate_definition(
    section: NamedMapSection,
    name: &str,
    def: &serde_json::Value,
) -> Result<(), AdminError> {
    if name.trim().is_empty() {
        return Err(AdminError::Validation(format!(
            "{} name must not be empty",
            section.singular()
        )));
    }
    if name.len() > crate::admin::v1::service::MAX_HOOK_NAME_LEN {
        return Err(AdminError::Validation(format!(
            "{} name is {} chars; must be <= {}",
            section.singular(),
            name.len(),
            crate::admin::v1::service::MAX_HOOK_NAME_LEN
        )));
    }
    let Some(obj) = def.as_object() else {
        return Err(AdminError::Validation(format!(
            "a {} definition must be an object (`{{\"module\": …}}`)",
            section.singular()
        )));
    };
    let module = obj.get("module").and_then(|m| m.as_str()).unwrap_or("");
    if module.trim().is_empty() {
        return Err(AdminError::Validation(format!(
            "a {} must name its backing plugin via a non-empty `module:`",
            section.singular()
        )));
    }
    if let Some(serde_json::Value::Object(settings)) = obj.get("settings") {
        crate::admin::v1::service::validate_hook_settings_size(settings)?;
    }
    Ok(())
}

/// THE TRUST-CEILING GUARD. `Ok(())` unless the definition would RAISE this entry's
/// `max_admin_scope` above what is live today (a NEW entry's baseline is the most restrictive
/// default, so an API-created provider cannot be born with a raised ceiling either).
///
/// Comparison is by the scope LATTICE (`Scope::allows`), never by string equality, so it stays
/// correct if the scope model ever grows a rung. A ceiling token is reduced to a `Scope` by the SAME
/// rule the auth middleware applies (`module_admin_scope_cap`): absent is the most restrictive rung.
///
/// An UNRECOGNIZED token never reaches here: `NamedMapSection::parse_def` (run by the `validate_def`
/// call above, before this guard) rejects it with the boot validator's own check, so a ceiling the
/// engine would refuse to boot answers 400 rather than being read as "most restrictive, therefore
/// never a raise" and applied. `none` was exactly that case — it is not a value; the most
/// restrictive ceiling is `read-only` (or the key omitted), and granting NO admin authority is done
/// by granting no `admin_scope` under the provider's `role_bindings:`.
fn check_trust_ceiling(
    section: NamedMapSection,
    current: &App,
    name: &str,
    def: &serde_json::Value,
) -> Result<(), Rejection> {
    use crate::admin::v1::contract::Scope;
    if !section.has_trust_ceiling() {
        return Ok(());
    }
    /// One ceiling token → the scope it actually confers. Mirrors `auth::module_admin_scope_cap`'s
    /// `.and_then(Scope::parse).unwrap_or(Scope::ReadOnly)` exactly: two encodings of the ceiling
    /// rule is precisely how a guard drifts open.
    fn ceiling_of(token: Option<&str>) -> Scope {
        token.and_then(Scope::parse).unwrap_or(Scope::ReadOnly)
    }
    let requested_token = def.get("max_admin_scope").and_then(|v| v.as_str());
    let requested = ceiling_of(requested_token);
    // A name that does not exist yet has the DEFAULT (most restrictive) baseline — so an API-created
    // provider cannot be born with a raised ceiling either.
    let live_token = section.max_admin_scope(&current.identity_providers, name);
    let live = ceiling_of(live_token.as_deref());
    if live.allows(requested) {
        return Ok(());
    }
    Err((
        AdminError::Conflict(format!(
            "refusing to RAISE `identity-providers.{name}.max_admin_scope` to `{}` through the \
             admin API: the trust ceiling caps the admin authority obtainable through this identity \
             provider, so raising it is a privilege escalation this API does not perform. Lower it \
             here, or raise it in config.yaml (current ceiling: `{}`)",
            requested_token.unwrap_or(crate::config::DEFAULT_MAX_ADMIN_SCOPE),
            live.as_str()
        )),
        Cond::TrustCeilingRaise,
    ))
}

/// The OpenAPI path items for every named-map section — emitted in the SAME loop the router mounts
/// from, so the document and the router can never disagree about which sections exist. Returns
/// `(absolute path, path item)` pairs; the generator merges them into `paths` and then stamps the
/// scope annotation, the `If-Match` parameter, the algorithmic responses and the taxonomy-projected
/// 4xx set onto them exactly as it does for every hand-written entry.
#[cfg(feature = "openapi-schema")]
pub(crate) fn openapi_paths() -> Vec<(String, serde_json::Value)> {
    use serde_json::json;
    let name_param = json!({
        "name": "name", "in": "path", "required": true, "schema": {"type": "string"}
    });
    let mut out = Vec::new();
    for section in NamedMapSection::ALL {
        let key = section.key();
        let singular = section.singular();
        out.push((
            super::ap(section.path_root()),
            json!({
                "get": {
                    "summary": format!(
                        "Every `{key}:` DEFINITION (the 1.5.3 named-definition map: name -> \
                         {{module, settings, ...}}, referenced by bare name). Secrets are never \
                         projected"
                    ),
                    "responses": {"200": {"description": "OK"}}
                }
            }),
        ));
        out.push((
            super::ap(&format!("{}/{{name}}", section.path_root())),
            json!({
                "get": {
                    "summary": format!("One `{key}:` definition"),
                    "parameters": [name_param],
                    "responses": {"200": {"description": "OK"}}
                },
                "put": {
                    "summary": format!(
                        "Create or REPLACE one `{key}:` definition (upsert), persisted to the \
                         config overlay and live after an atomic rebuild-and-swap. A \
                         base-config-defined entry is 409 (edit config.yaml){}",
                        if section.has_trust_ceiling() {
                            "; RAISING `max_admin_scope` is refused outright (the trust ceiling is \
                             operator file policy)"
                        } else {
                            ""
                        }
                    ),
                    "parameters": [name_param],
                    "responses": {"200": {"description": format!(
                        "The stored {singular} definition. Additionally carries `reload_to_apply` \
                         (+ a `note`) when the mutation declared a plugin ROUTE this process cannot \
                         serve: each route path is registered on the HTTP router once, at process \
                         start, and an apply swaps only the config snapshot, so a path that did not \
                         exist at boot (e.g. `/metrics` for a first `prometheus` exporter) answers \
                         404 until the next RESTART. Both fields are omitted when nothing is pending"
                    )}}
                },
                "delete": {
                    "summary": format!(
                        "Remove one `{key}:` definition, refused while another config section \
                         still references it by bare name"
                    ),
                    "parameters": [name_param],
                    "responses": {"204": {"description": "Removed"}}
                }
            }),
        ));
        out.push((
            super::ap(&format!("{}/{{name}}/settings", section.path_root())),
            json!({
                "patch": {
                    "summary": format!(
                        "Replace ONLY the opaque `settings:` bag of one `{key}:` definition; every \
                         other field is left byte-identical"
                    ),
                    "parameters": [name_param],
                    "responses": {"200": {"description": format!(
                        "The updated {singular} definition (same `reload_to_apply` restart signal as \
                         the PUT, when the mutation declares a route the router lacks)"
                    )}}
                }
            }),
        ));
    }
    out
}
