// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable native hook inputs. The root resolves configuration once; the driver invokes
//! opened hook ports directly, without the legacy hook frames or a back-reference to App.

use std::sync::Arc;
use std::time::Duration;

use busbar_contract::hooks::BudgetBucketState;
use busbar_ports::hook::HookPort;

use crate::config::{PolicyOnError, PromptAccess, UserAccess};
use crate::cost::CostModel;
use crate::hooks::RequestedSignals;

use super::hooks::{CallerKey, HookRead};

mod view;

/// One configured call, including its finite, boot-validated fallback chain.
pub struct Call {
    pub name: Arc<str>,
    pub port: Arc<dyn HookPort>,
    pub timeout: Duration,
    pub prompt: PromptAccess,
    pub user: UserAccess,
    pub signals: RequestedSignals,
    pub on_error: PolicyOnError,
    pub on_empty: PolicyOnError,
    pub fallbacks: Vec<Arc<Call>>,
    /// The admitted D_WORD selected by a base-policy binding; absent for ordinary gates.
    pub strategy: Option<Arc<str>>,
}

#[derive(Clone, Default)]
pub struct Taps {
    pub request: Vec<Arc<Call>>,
    pub candidate: Vec<Arc<Call>>,
    pub routing: Vec<Arc<Call>>,
    pub response: Vec<Arc<Call>>,
}

/// One invocation's selection. Every service is already constructed and generation-bound.
#[derive(Clone)]
pub struct Selected {
    pub rewrites: Vec<Arc<Call>>,
    /// Stable priority order; concurrent results are reconciled in this order.
    pub gates: Vec<Arc<Call>>,
    pub policy: Option<Arc<Call>>,
    pub taps: Taps,
    pub key: Option<CallerKey>,
    pub budget: Vec<BudgetBucketState>,
    pub rate_headroom: Option<f64>,
    pub cost: Arc<CostModel>,
    pub reads: HookRead,
}

/// Selection uses the same configured scope as the native egress walk, never a body field.
pub struct Selection<'a> {
    pub route: u32,
    pub pool: &'a str,
    pub container: &'a str,
    pub dialect: &'a str,
    pub principal: Option<&'a str>,
    pub request_id: u64,
    pub now_s: u64,
}

/// Built by S9 from admitted metadata and the exact S8 hook ports before seats are published.
/// Implementations may retain concrete governance readers; they must not retain App or a generation.
pub trait Binder: Send + Sync {
    /// Includes possible pool/container attachments, not merely the currently known section hooks.
    fn active(&self, route: u32) -> bool;
    /// True when a gate, rewrite or routing policy can enforce this route.
    fn enforcing(&self, route: u32) -> bool;
    fn select(&self, input: &Selection<'_>) -> Result<Selected, &'static str>;
}
