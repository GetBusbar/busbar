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

/// The boot's merge of installed and built-in plane declarations, for a dependent's registry
/// tests (dist registry_cross_plane): kept crate-private outside the test hooks (BP14).
pub fn merged_boot_plane_decls(
    installed: &[&'static crate::plane_driver::registry::PlaneDecl],
    builtins: &[&'static crate::plane_driver::registry::PlaneDecl],
) -> Vec<&'static crate::plane_driver::registry::PlaneDecl> {
    crate::off_path::plane_registry::merged_boot_plane_decls(installed, &[], builtins)
}

/// B-RATE-HOLD's way in: one rate hold's whole life against the governor.
pub mod rate_hold {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use busbar_contract::Count;

    use crate::governance::selected_resource::{
        EffectiveToken, EffectiveTokenView, RateHold, RateMetric, RateTerms, SelectedRates,
        TokenCoverage,
    };

    /// A governor on a stepped clock, with its rules, classes and view built once.
    pub struct Bench {
        rates: Arc<SelectedRates>,
        terms: Vec<RateTerms>,
        classes: Vec<&'static str>,
        view: EffectiveTokenView<'static>,
        /// Holds reserved in earlier minutes and never committed: they keep those minutes' cells.
        _earlier: Vec<RateHold>,
    }

    impl Bench {
        /// `rules` rules (1..=32) and `classes` classes (1..=64), beside `earlier_minutes` earlier
        /// minutes in which every scope still has a referenced cell.
        pub fn new(rules: usize, classes: usize, earlier_minutes: u64) -> Self {
            let clock = Arc::new(AtomicU64::new(0));
            let rates = Arc::new(SelectedRates::stepped(
                std::time::Instant::now(),
                Arc::clone(&clock),
            ));
            let terms: Vec<RateTerms> = (0..rules)
                .map(|i| RateTerms {
                    group_id: "g".into(),
                    rule_id: format!("r{i}").into(),
                    key_id: "k".into(),
                    instance: "p".into(),
                    resource: "x".into(),
                    metric: if i % 2 == 0 {
                        RateMetric::Requests
                    } else {
                        RateMetric::Tokens
                    },
                    // Large, because `blocked` multiplies it by 1,000,000 into an `i128`.
                    threshold: u64::MAX / 4_000_000,
                    policy_revision: 1,
                    activated_minute: 0,
                })
                .collect();
            // The rig is built a few times per run; the leak is the rig's, in a test-support build.
            let classes: Vec<&'static str> = (0..classes)
                .map(|j| &*Box::leak(format!("tokens.c{j:02}").into_boxed_str()))
                .collect();
            let view = EffectiveTokenView(
                classes
                    .iter()
                    .map(|class| EffectiveToken {
                        class,
                        quantity: Some(Count::from_integer(1).unwrap()),
                        authoritative: true,
                    })
                    .collect(),
            );
            let mut earlier = Vec::new();
            for minute in 0..earlier_minutes {
                clock.store(minute * 60_000, Ordering::Relaxed);
                earlier.push(
                    rates
                        .reserve_terms(terms.iter().cloned(), &classes)
                        .unwrap(),
                );
            }
            clock.store(earlier_minutes * 60_000, Ordering::Relaxed);
            Self {
                rates,
                terms,
                classes,
                view,
                _earlier: earlier,
            }
        }

        /// Reserve, commit, observe, finish, once. `true` when all four answered `Ok`.
        pub fn cycle(&mut self) -> bool {
            let Ok(mut hold) = self
                .rates
                .reserve_terms(self.terms.iter().cloned(), &self.classes)
            else {
                return false;
            };
            hold.commit().is_ok()
                && hold.observe(&self.view).is_ok()
                && hold.finish(TokenCoverage::Complete).is_ok()
        }
    }
}
