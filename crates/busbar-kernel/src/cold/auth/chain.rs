// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth chain's cold paths: what a request spells only when it is refused.

/// The refusal door a refused request answers through, with the target it was refused on (owned:
/// the door renders it after the request is gone). Spelled only on a refusal.
#[cold]
#[inline(never)]
pub(crate) fn refusal_door(
    core_routes: &crate::core_routes::CoreRouteTable,
    path: &str,
    method: &axum::http::Method,
    target: &str,
) -> Option<crate::auth::RefusalDoor> {
    let refuse = core_routes.door_refusal(path, method)?;
    Some((
        refuse.clone(),
        busbar_contract::secure::SecureString::from(target.to_owned()),
    ))
}

/// The audit line of the first rate-limited admin mutation in a window: its class and path.
#[cold]
#[inline(never)]
pub(crate) fn record_admin_rate_limited(class: &str, path: &str, actor: &str) {
    crate::audit_ring::AUDIT.record_by(
        "admin.rate_limited",
        &format!("{class}:{path}"),
        crate::audit_ring::OUTCOME_REJECTED,
        actor,
    );
}
