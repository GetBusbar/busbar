// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::v1::contract::taxonomy::Cond;
use crate::v1::contract::AdminError;

pub use busbar_kernel::admin_verbs::{registered, PlaneTrust, PlaneVerbError};

pub fn audit(
    plane: &'static str,
    verb: &str,
    name: &str,
    outcome: &'static str,
    principal: &busbar_kernel::auth::AuthPrincipal,
) {
    let audit_kind = busbar_kernel::plane_driver::dispatch::plane_decl(plane).audit_kind;
    crate::v1::json::audit::AUDIT.record_by(
        &format!("{audit_kind}.{verb}"),
        &format!("{audit_kind}:{name}"),
        outcome,
        principal.actor_id(),
    );
}

pub fn to_admin_error(plane: &'static str, name: &str, err: PlaneVerbError) -> AdminError {
    match err {
        PlaneVerbError::NotFound => AdminError::not_found(format!(
            "{} `{name}`",
            busbar_kernel::plane_driver::dispatch::plane_decl(plane).subject_noun
        )),
        // The text is the plugin's: it rides in `details`, never in the message (section 1.3).
        PlaneVerbError::Validation(text) => {
            AdminError::plugin_text(Cond::PluginRejected, Some(text), None, None)
        }
        PlaneVerbError::ValidationOf(text, cond) => AdminError::plugin_text(
            Cond::PluginRejected,
            Some(text),
            None,
            Some(cond_of(cond).reason().to_string()),
        ),
        PlaneVerbError::Internal(_) => AdminError::Internal,
        PlaneVerbError::Unavailable => {
            AdminError::Unavailable("plane dependency is temporarily unavailable".into())
        }
    }
}

pub fn refusal_response(
    plane: &'static str,
    name: &str,
    err: PlaneVerbError,
) -> axum::response::Response {
    crate::v1::json::err_json(&to_admin_error(plane, name, err))
}

fn cond_of(
    cond: busbar_kernel::admin_verbs::PlaneAdminCond,
) -> crate::v1::contract::taxonomy::Cond {
    use busbar_kernel::admin_verbs::PlaneAdminCond;
    match cond {
        PlaneAdminCond::MalformedBody => Cond::MalformedBody,
        PlaneAdminCond::InvalidConfig => Cond::InvalidConfig,
    }
}

#[cfg(test)]
#[path = "tests/planeverbs_tests.rs"]
mod planeverbs_tests;
