// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

pub mod tokens {
    use busbar_contract::caps::{
        Capability, DurabilityLost, Exit, Grant, KernelSeal, Origin, OriginKind, Outcome, Pass,
        Posted, Step, UnitEnd,
    };

    pub fn seal() -> KernelSeal {
        crate::seal::acquire()
    }

    pub fn pass<S: Step>() -> Pass<S> {
        Pass::mint(&seal())
    }

    pub fn grant<C: Capability>() -> Grant<C> {
        Grant::mint(&seal())
    }

    pub fn origin(kind: OriginKind) -> Origin {
        Origin::seal(&seal(), kind)
    }

    pub fn end(outcome: Outcome, posted: Result<Posted, DurabilityLost>) -> UnitEnd {
        UnitEnd::seal(&grant::<Exit>(), outcome, posted)
    }
}

/// The operator credential for a kernel test with no admitted auth rows (TST-7): the first-party
/// claim a linked `admin-tokens` row states, bound through the production process-start binding
/// ([`crate::preflight::install_operator`]). Nothing is bypassed: the config a test reads then
/// takes the closed default admin chain `[<operator>, keys]`, and the operator's settings are the
/// 1.6 `{sha256: ..}` object ([`SETTINGS_SHA256`]). The binding is process-global and the first one
/// stands (nextest runs each test in its own process).
pub mod operator {
    use busbar_contract::auth_calls::OperatorClaim;

    use crate::preflight::{install_operator, Judged, OperatorBinding};

    /// The operator row's config key, as the linked first-party row states it.
    pub const PROVIDER: &str = "admin-tokens";

    /// The operator token a test presents, as `Authorization: Bearer`.
    pub const TOKEN: &str = "test";

    /// The operator's settings: the SHA-256 of [`TOKEN`] as 64 lower-case hex characters.
    pub const SETTINGS_SHA256: &str =
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    /// Bind [`PROVIDER`] as this process's first-party operator credential and return the
    /// operator key configuration now names it by.
    pub fn bind() -> &'static str {
        install_operator(OperatorBinding::Bound(Judged {
            words: Ok(Some(OperatorClaim {
                provider: PROVIDER.to_owned(),
                canonical: "busbar-auth-admin-tokens".to_owned(),
                principal: "admin".to_owned(),
                first_party: true,
                version: env!("CARGO_PKG_VERSION").to_owned(),
                signer: "busbar".to_owned(),
            })),
            inert: Vec::new(),
        }));
        crate::config::operator_provider()
    }
}
