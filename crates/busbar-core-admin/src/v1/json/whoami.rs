// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `GET /whoami` (ADMIN-API r5 section 2.2): who the admin chain says the caller is, and what that
//! caller may do. The verbs are computed with the gate's own predicate over the whole closed table.

use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::Response;
use busbar_contract::authz::Scope;
use busbar_kernel::auth::{AdminDoor, AdminWho, AdminWhoSlot};
use serde::Serialize;

use super::{respond, AppHandle};
use crate::v1::contract::AdminError;
use crate::verb::{admin_grant_rows, VerbScope};

/// The credential behind the caller.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct WhoamiCredential {
    /// `operator`, `key`, `identity_provider` or `open`.
    kind: &'static str,
    /// The key id for a `key`, the principal id for an `identity_provider`; `null` otherwise.
    id: Option<String>,
    /// The provider that identified the caller; `null` for a key and for the open posture.
    provider: Option<String>,
    /// The credential's expiry, Unix seconds; `null` when it states none.
    expires_at: Option<u64>,
}

/// One admin rate budget: its limit, the window it is counted over and what is left of it.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct WhoamiRate {
    /// Admitted requests per window; `0` marks a class that is not metered.
    limit: u32,
    /// The window, seconds.
    window_s: u64,
    /// What this principal has left in the current window.
    remaining: u32,
}

/// The four budget classes, by name.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct WhoamiRates {
    config: WhoamiRate,
    crud: WhoamiRate,
    plugin_inspect: WhoamiRate,
    read: WhoamiRate,
}

/// `GET /whoami`.
#[derive(Debug, Serialize)]
#[cfg_attr(feature = "openapi-schema", derive(schemars::JsonSchema))]
pub(crate) struct WhoamiView {
    /// The caller's principal id (`key:<id>` for a key; `anonymous` in the open posture).
    principal: String,
    credential: WhoamiCredential,
    /// `read-only` or `full`; `null` when the credential earns neither.
    scope: Option<&'static str>,
    /// Every verb this caller may call, sorted.
    verbs: Vec<&'static str>,
    /// Whether the caller holds every verb within its scope.
    verbs_all: bool,
    /// Whether mutations must carry `If-Match`.
    require_if_match: bool,
    rate: WhoamiRates,
}

fn rung(scope: VerbScope) -> Scope {
    match scope {
        VerbScope::ReadOnly => Scope::ReadOnly,
        VerbScope::Full => Scope::Full,
    }
}

/// Whether `door` admits the verb `name` needing `needed`: the gate's predicate, per table row.
pub(crate) fn door_admits_verb(door: &AdminDoor, name: &str, needed: Scope) -> bool {
    match door {
        AdminDoor::Open => true,
        AdminDoor::Identified(_, grants) => grants.allows(needed),
        AdminDoor::Listed(_, grants, list) => {
            grants.allows(needed) && list.admits(Some(name), needed)
        }
        AdminDoor::Denied | AdminDoor::Rejected(_) | AdminDoor::Unavailable(_) => false,
    }
}

fn scope_of(door: &AdminDoor) -> Option<&'static str> {
    let grants = match door {
        AdminDoor::Open => return Some(Scope::Full.as_str()),
        AdminDoor::Identified(_, grants) | AdminDoor::Listed(_, grants, _) => grants,
        AdminDoor::Denied | AdminDoor::Rejected(_) | AdminDoor::Unavailable(_) => return None,
    };
    [Scope::Full, Scope::ReadOnly]
        .into_iter()
        .find(|scope| grants.allows(*scope))
        .map(Scope::as_str)
}

fn principal_of(door: &AdminDoor) -> String {
    match door {
        AdminDoor::Identified(principal, _) | AdminDoor::Listed(principal, _, _) => {
            principal.id.clone()
        }
        _ => "anonymous".to_string(),
    }
}

fn rate_of(
    app: &busbar_kernel::state::App,
    actor: &str,
    class: busbar_kernel::ratelimit::MutationClass,
    now: u64,
) -> WhoamiRate {
    let limit = class.limit();
    WhoamiRate {
        limit,
        window_s: busbar_kernel::ratelimit::MUTATION_RATE_WINDOW_SECS,
        remaining: limit.saturating_sub(app.mutation_budget_used(actor, class, now)),
    }
}

pub(crate) fn view_of(app: &busbar_kernel::state::App, who: &AdminWho, now: u64) -> WhoamiView {
    use busbar_kernel::ratelimit::{MutationClass, MUTATION_RATE_WINDOW_SECS};
    let door = &who.door;
    let principal = principal_of(door);
    let mut verbs: Vec<&'static str> = admin_grant_rows()
        .filter(|row| door_admits_verb(door, row.name, rung(row.scope)))
        .map(|row| row.name)
        .collect();
    verbs.sort_unstable();
    verbs.dedup();
    WhoamiView {
        rate: WhoamiRates {
            config: rate_of(app, &principal, MutationClass::Config, now),
            crud: rate_of(app, &principal, MutationClass::Crud, now),
            plugin_inspect: rate_of(app, &principal, MutationClass::PluginInspect, now),
            read: WhoamiRate {
                limit: 0,
                window_s: MUTATION_RATE_WINDOW_SECS,
                remaining: 0,
            },
        },
        principal,
        credential: WhoamiCredential {
            kind: who.kind,
            id: who.id.clone(),
            provider: who.provider.clone(),
            expires_at: who.expires_at,
        },
        scope: scope_of(door),
        verbs,
        verbs_all: matches!(door, AdminDoor::Open | AdminDoor::Identified(..)),
        require_if_match: app.require_if_match,
    }
}

/// The caller's identity: the one the gate took before it struck the credential lines, else the chain
/// read again from the request (a path that did not pass the gate's slot).
pub(crate) async fn who_of(
    app: &busbar_kernel::state::App,
    slot: Option<AdminWhoSlot>,
    headers: &axum::http::HeaderMap,
) -> Option<AdminWho> {
    match slot {
        Some(slot) => slot.0,
        None => busbar_kernel::auth::admin_who(app, headers).await,
    }
}

pub(super) async fn get(
    State(handle): State<Arc<AppHandle>>,
    slot: Option<axum::Extension<AdminWhoSlot>>,
    headers: busbar_kernel::inbound::http_projection::AdminHeaders,
) -> Response {
    let app = handle.load();
    let who = who_of(&app, slot.map(|s| s.0), &headers).await;
    respond(
        StatusCode::OK,
        who.as_ref()
            .map(|who| view_of(&app, who, busbar_kernel::store::now()))
            .ok_or(AdminError::Internal),
    )
}
