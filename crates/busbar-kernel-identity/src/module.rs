// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One link of the chain: what a module may answer, and the one thing it must declare about itself.

use crate::principal::Principal;

/// A module's answer for one credential.
///
/// Three arms and no fourth. "Identify" is a positive identification and ends the chain. "Reject"
/// means this module recognised the credential and refuses it, which stops the chain. "Pass" means
/// "not mine" and lets the next module look.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// This credential is this principal.
    Identify(Principal),
    /// This credential is recognised and refused.
    Reject,
    /// Not this module's credential.
    Pass,
}

/// A chain module.
///
/// `cacheable` defaults to **false**, and that default is load-bearing: an external module that
/// never overrides it is re-verified on every single request, which is the safe answer for a
/// verifier whose revocation posture nobody in this crate knows. A module opts in only when it can
/// say what its verdict's lifetime means.
pub trait AuthModule: Send + Sync {
    /// The module's own name, as it reports it.
    fn name(&self) -> &'static str;

    /// Judge the presented credential. `None` means no credential was presented at all.
    fn authenticate(&self, candidate: Option<&str>) -> AuthOutcome;

    /// Whether this module's verdicts may be cached. False unless the module says otherwise.
    fn cacheable(&self) -> bool {
        false
    }
}
