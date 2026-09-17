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
///
/// Deliberately NOT `Ord`. Under a derived ordering, satisfaction is declaration order, so a rung
/// added to this enum acquires an answer to "does it satisfy `Full`?" from where it happens to be
/// written rather than from a decision anybody made — and a narrow new rung declared after `Full`
/// would silently confer every mutation. Satisfaction is spelled as an exhaustive match below
/// instead, so adding a rung stops the build until the answer is written down. `busbar-unit-scope`
/// is the authority for what each rung means; these arms mirror its `Scope::allows`, and a rung
/// added there must be added here with the same answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    ///
    /// Every rung reads, so `ReadOnly` is satisfied by anything; `Full` is satisfied only by
    /// `Full`. Written as a match on the pair rather than a comparison so neither half can gain a
    /// meaning by being declared in a particular place.
    pub fn satisfies(&self, needed: Scope) -> bool {
        match (self.scope, needed) {
            (_, Scope::ReadOnly) => true,
            (Scope::Full, Scope::Full) => true,
            (Scope::ReadOnly, Scope::Full) => false,
        }
    }
}

/// The open posture's non-principal, however the caller spells it.
///
/// `Auth::resolve` renders the unauthenticated open door as `Some(Principal::anonymous())`, while
/// other call sites pass `None`; both mean "no authenticated caller". The two admin gates below must
/// read them the SAME way, or the open-admin grant lands for one spelling and not the other — an
/// absent principal getting full scope from `admin_grants` while the resolved `Some(anonymous)` the
/// authenticate unit actually produces is turned away (or vice versa). Answering "is this the
/// open-posture non-principal?" in one place makes the two gates agree by construction.
fn is_open_posture_caller(principal: Option<&Principal>) -> bool {
    match principal {
        None => true,
        Some(p) => p.is_anonymous(),
    }
}

/// The grants for an administrative caller under the deployment's admin posture.
///
/// `admin_chain_empty` is the operator's configuration: true when no admin module is named. On that
/// posture the open-posture non-principal — an absent principal, or the anonymous principal the
/// authenticate unit renders the open door as — is granted full scope. With a chain configured, that
/// caller holds nothing, and a resolved principal's grants come from the bindings rather than here.
pub fn admin_grants(admin_chain_empty: bool, principal: Option<&Principal>) -> Option<Grants> {
    if admin_chain_empty && is_open_posture_caller(principal) {
        Some(Grants::of(Scope::Full))
    } else {
        None
    }
}

/// Whether the kernel-verb scope check is satisfied for this caller.
///
/// The check ALWAYS runs — it is never skipped for a posture. On the open posture it is satisfied
/// for the open-posture non-principal, which is a different statement from not asking. It shares
/// `is_open_posture_caller` with `admin_grants` so the two gates cannot drift apart.
pub fn kernel_verb_scope_satisfied(admin_chain_empty: bool, principal: &Principal) -> bool {
    admin_chain_empty && is_open_posture_caller(Some(principal))
}
