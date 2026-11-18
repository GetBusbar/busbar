// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE OPERATOR CLAIMS OF NATIVE (MIN-3) AUTH IMAGES (OPERATOR-FROM-ADMITTED-AUTH §3.2 over MIN-3).
//!
//! A door-era auth row stated the operator credential in its Statement (`operator_principal`); a MIN-3 auth image
//! states it in its describe answer (`auth::FB_OPERATOR`). The start stage's image prepare publishes one claim per
//! admitted auth image that sets the bit, and every judgement of the operator (process start, `--validate`, the
//! restart check) reads them beside the door rows' claims. Without this the linked `admin-tokens` image, once it
//! moved to MIN-3 (bd0105a0e9), was no operator, so `admin_auth: [admin-tokens]` had none (D-OPERATOR).
//!
//! The MIN-3 auth describe carries no principal item, so a native operator claim carries core's operator principal,
//! [`NATIVE_OPERATOR_PRINCIPAL`]: the id the first-party operator image answers as its `ID_SUBJECT` and the one
//! the door-era row stated, so role bindings and audit rows read the same principal as before the move.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use busbar_contract::auth_calls::{OperatorClaim, OperatorClaims};

/// The principal a native operator claim carries (the door-era admin-tokens row's stated `operator_principal`).
pub(crate) const NATIVE_OPERATOR_PRINCIPAL: &str = "admin";

/// The published native operator claims: one per process ([`NATIVE`]).
pub(crate) struct NativeOperator {
    claims: ArcSwapOption<Vec<OperatorClaim>>,
    /// Every name an admitted native auth image answers to (identity, alias, former names).
    auth_names: ArcSwapOption<std::collections::BTreeSet<String>>,
}

/// The process's native operator claims, published by the start stage's image prepare.
pub(crate) static NATIVE: NativeOperator = NativeOperator {
    claims: ArcSwapOption::const_empty(),
    auth_names: ArcSwapOption::const_empty(),
};

impl NativeOperator {
    /// Publish the claims of the images the start stage admitted.
    pub(crate) fn publish(&self, claims: Vec<OperatorClaim>) {
        self.claims.store(Some(Arc::new(claims)));
    }

    /// Publish the names the admitted native auth images answer to (the kernel's `RootInstall::native_auth`).
    pub(crate) fn publish_auth_names(&self, names: std::collections::BTreeSet<String>) {
        self.auth_names.store(Some(Arc::new(names)));
    }

    /// `claims` with the published native claims added. One canonical plugin is one claim: a native claim whose
    /// canonical name a door row already claims is not added twice.
    pub(crate) fn merged(&self, mut claims: OperatorClaims) -> OperatorClaims {
        if let Some(native) = self.claims.load_full() {
            for claim in native.iter() {
                if !claims.claims.iter().any(|c| c.canonical == claim.canonical) {
                    claims.claims.push(claim.clone());
                }
            }
        }
        claims
    }
}

/// The operator claims among admitted images: every auth image whose describe sets `FB_OPERATOR`, keyed by the
/// name configuration uses for it (`aliases`: identity and alias, as admission paired them).
pub(crate) fn claims_of(
    images: &busbar_plugin_loader::instance::Images,
    aliases: &[(String, String)],
) -> Vec<OperatorClaim> {
    use busbar_plugin_loader::admit::Signer;
    use busbar_plugin_loader::sign::Verdict;
    aliases
        .iter()
        .filter(|(identity, _)| {
            images.described(identity).is_some_and(|described| {
                described.kind == busbar_plugin_abi::types::KindCode::Auth
                    && described.facts & busbar_plugin_abi::auth::FB_OPERATOR != 0
            })
        })
        .map(|(identity, alias)| OperatorClaim {
            provider: alias.clone(),
            canonical: identity.clone(),
            principal: NATIVE_OPERATOR_PRINCIPAL.to_owned(),
            first_party: images.first_party(identity),
            // A MIN-3 header states no version this claim reads; the audit row shows it empty.
            version: String::new(),
            signer: match images.signer(identity) {
                Some(Signer::Linked) => "linked".to_owned(),
                Some(Signer::Dropped { verdict, .. }) => match verdict {
                    Verdict::Trusted { publisher, .. } => publisher.clone(),
                    Verdict::Allowed { reason, .. } => reason.clone(),
                },
                None => String::new(),
            },
        })
        .collect()
}

/// Every name an admitted auth image answers to: its identity, the alias admission paired it with, and its former names.
pub(crate) fn auth_names_of(
    images: &busbar_plugin_loader::instance::Images,
    aliases: &[(String, String)],
) -> std::collections::BTreeSet<String> {
    let mut names = std::collections::BTreeSet::new();
    for (identity, alias) in aliases {
        if images
            .described(identity)
            .is_some_and(|described| described.kind == busbar_plugin_abi::types::KindCode::Auth)
        {
            names.extend(images.names(identity).into_iter().map(str::to_owned));
            if !alias.is_empty() {
                names.insert(alias.clone());
            }
        }
    }
    names
}

/// The kernel's `RootInstall::native_auth`: whether an admitted native auth image answers `module`.
pub(crate) fn answers_auth(module: &str) -> bool {
    NATIVE
        .auth_names
        .load()
        .as_ref()
        .is_some_and(|names| names.contains(module))
}
