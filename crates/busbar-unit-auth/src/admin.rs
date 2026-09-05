// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The open-admin posture.
//!
//! An operator who configures no admin chain has said, in the only way the configuration lets them
//! say it, that this deployment's administrative surface is not authenticated. Reproducing that
//! exactly matters more than improving on it: a deployment upgraded onto this code must keep
//! answering the same requests it answered yesterday, and an operator who wanted the surface closed
//! closes it by naming a module.
//!
//! So with no admin chain, an ABSENT principal is granted full scope, and the kernel-verb scope
//! check is satisfied for the anonymous principal on that posture.

use crate::principal::Principal;

/// What an administrative caller may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Reads only.
    ReadOnly,
    /// Everything.
    Full,
}

/// The scopes a caller holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grants {
    scope: Scope,
}

impl Grants {
    /// The grants for one scope.
    pub fn of(scope: Scope) -> Self {
        Grants { scope }
    }

    /// The scope held.
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// Whether these grants satisfy a required scope.
    pub fn satisfies(&self, needed: Scope) -> bool {
        self.scope >= needed
    }
}

/// The grants for an administrative caller under the deployment's admin posture.
///
/// `admin_chain_empty` is the operator's configuration: true when no admin module is named. On that
/// posture an absent principal is granted full scope. With a chain configured, an absent principal
/// holds nothing, and a resolved principal's grants come from the bindings rather than from here.
pub fn admin_grants(admin_chain_empty: bool, principal: Option<&Principal>) -> Option<Grants> {
    match (admin_chain_empty, principal) {
        (true, None) => Some(Grants::of(Scope::Full)),
        _ => None,
    }
}

/// Whether the kernel-verb scope check is satisfied for this caller.
///
/// The check ALWAYS runs — it is never skipped for a posture. On the open posture it is satisfied
/// for the anonymous principal, which is a different statement from not asking.
pub fn kernel_verb_scope_satisfied(admin_chain_empty: bool, principal: &Principal) -> bool {
    admin_chain_empty && principal.is_anonymous()
}
