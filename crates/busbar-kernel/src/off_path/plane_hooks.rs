// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `plane_driver::hooks::policy`: a hook policy, built once per generation, and a hook's settings
//! schema, read for the admin surface.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::hook_calls::HookCalls;
use busbar_contract::hook_wire::reply as wire;
use busbar_contract::hooks::RoutingPolicy;

use crate::plane_driver::hooks::policy::{HookPolicy, Ranking};

/// The candidate facts a strategy word (`hooks: [word]`, `strategy: word`, `on_error: word`) is
/// granted: the form has no `signals:` key, and the strategies it names read the plane's
/// route-cost recipe at the card's prices (UPG-A23b). No request content and no caller facts, so
/// the policy stays content-blind.
const STRATEGY_WORD_SIGNALS: &[busbar_contract::Signal] =
    &[busbar_contract::Signal::CandidateRouteCost];

/// A hook's settings schema, as it described it.
pub(crate) type Described = serde_json::Value;

impl HookPolicy {
    pub(crate) fn policy(
        calls: Arc<dyn HookCalls>,
        name: &str,
        signals: &[busbar_contract::Signal],
    ) -> Arc<dyn RoutingPolicy> {
        Arc::new(Self {
            calls,
            name: Arc::from(name),
            signals: signals.to_vec(),
            child: None,
            statics: std::sync::Mutex::default(),
        })
    }

    /// A built-in ranking strategy: the gate hook that declares the word `name`, granted only
    /// [`STRATEGY_WORD_SIGNALS`] and no child dispatch, answering only `decide`. It is content-blind
    /// ([`RoutingPolicy::content_blind`]); every other hook policy is not.
    pub(crate) fn ranking(calls: Arc<dyn HookCalls>, name: &str) -> Arc<dyn RoutingPolicy> {
        Arc::new(Ranking(Self {
            calls,
            name: Arc::from(name),
            signals: STRATEGY_WORD_SIGNALS.to_vec(),
            child: None,
            statics: std::sync::Mutex::default(),
        }))
    }
}

/// The settings schema the hook behind `calls` describes, read once per admin ask.
pub(crate) async fn described(calls: &dyn HookCalls, budget: Duration) -> Option<Described> {
    let bytes = calls.describe(budget).await?;
    serde_json::from_slice::<wire::DescribeReply>(&bytes)
        .ok()?
        .schema
}
