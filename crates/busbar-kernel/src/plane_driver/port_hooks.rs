// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Immutable native hook inputs. The root resolves configuration once; the driver invokes
//! opened hook ports directly, without the legacy hook frames or a back-reference to App.

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use busbar_contract::hooks::BudgetBucketState;
use busbar_ports::hook::HookPort;

use crate::config::{PolicyOnError, PromptAccess, UserAccess};
use crate::cost::CostModel;
use crate::hooks::RequestedSignals;
use crate::snapshot::{ROUTE_POLICY_REJECTIONS_TOTAL, ROUTE_POLICY_SELECTIONS_TOTAL};

use super::hooks::{CallerKey, HookRead};

mod call;
pub(super) mod stage;
mod view;

use super::hooks::{CandidateFacts, HookJournal};
use super::port_session::{Answer, ExpectItem, SessionError};
use busbar_contract::secure::SecureVec;
use busbar_ports::{plane::UsageClass, FactVal};

/// Per-unit service inputs. Its context belongs to the selected generation, never to Binder.
pub struct Invocation {
    pub binder: Arc<dyn Binder>,
    pub principal: Option<Arc<str>>,
    pub now_s: u64,
    /// The instance's declared usage classes, shared with its driver (frozen when it bound).
    pub classes: Arc<[UsageClass]>,
    pub journal: Option<Arc<dyn HookJournal>>,
    pub unit: busbar_contract::UnitKey,
}

#[derive(Clone, Default)]
struct Projection {
    facts: Vec<(u32, FactVal)>,
    conversation: Option<SecureVec>,
    expects: Vec<ExpectItem>,
}

impl Drop for Projection {
    fn drop(&mut self) {
        for (_, value) in &mut self.facts {
            if let FactVal::Text(value) = value {
                wipe_text(value);
            }
        }
    }
}

/// Wipe a projected text fact's whole allocation through the counted secure wipe; the fact is
/// left empty. A `Box<str>` becomes its `String` without a copy.
fn wipe_text(text: &mut Box<str>) {
    let mut owned = std::mem::take(text).into_string();
    busbar_contract::secure::wipe_string(&mut owned);
}

impl Projection {
    fn absorb(&mut self, answer: &Answer) {
        for (key, value) in &answer.facts {
            if (busbar_plugin_abi::fail::fact::PJ_MODEL
                ..=busbar_plugin_abi::fail::fact::PJ_TEXT_COMPLETE)
                .contains(key)
            {
                self.facts.retain_mut(|(held, value)| {
                    if held != key {
                        return true;
                    }
                    if let FactVal::Text(text) = value {
                        wipe_text(text);
                    }
                    false
                });
                self.facts.push((*key, value.clone()));
            }
        }
        if let Some(conversation) = &answer.conversation {
            self.conversation = Some(conversation.clone());
        }
        for expected in &answer.expects {
            self.expects.retain(|held| held.class != expected.class);
            self.expects.push(expected.clone());
        }
    }

    fn rewritten(&mut self, bytes: SecureVec, answer: &Answer) {
        use busbar_plugin_abi::fail::fact::*;
        self.conversation = Some(bytes);
        self.facts.retain(|(key, _)| {
            !matches!(
                *key,
                PJ_TOTAL_CHARS
                    | PJ_MESSAGE_COUNT
                    | PJ_TOOL_COUNT
                    | PJ_SYSTEM_CHARS
                    | PJ_TEXT_COMPLETE
            )
        });
        self.absorb(answer);
    }

    fn shape(&self) -> Self {
        Self {
            facts: self
                .facts
                .iter()
                .filter(|(key, _)| *key != busbar_plugin_abi::fail::fact::PJ_END_USER)
                .cloned()
                .collect(),
            conversation: None,
            expects: Vec::new(),
        }
    }
}

#[derive(Clone)]
struct CandidateView {
    facts: CandidateFacts,
    lane: String,
}

fn quantities(
    classes: &[UsageClass],
    expected: &[ExpectItem],
) -> Result<Vec<(Box<str>, f64)>, SessionError> {
    if expected.iter().any(|item| {
        item.scale > super::usage::MAX_SCALE
            || !classes.iter().any(|class| class.class == item.class)
    }) {
        return Err(SessionError::Encode);
    }
    Ok(classes
        .iter()
        .filter_map(|class| {
            let quantity = expected
                .iter()
                .find(|item| item.class == class.class)
                .map(|item| item.amount as f64 / 10_f64.powi(item.scale as i32))
                .or(class.expected_units)?;
            (quantity.is_finite() && quantity >= 0.0).then(|| (class.class.clone(), quantity))
        })
        .collect())
}

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

impl Call {
    /// The name a decision by this call is known by: its strategy word when it is a bound
    /// strategy, otherwise its configured hook name.
    pub fn decider(&self) -> &Arc<str> {
        self.strategy.as_ref().unwrap_or(&self.name)
    }
}

/// The 4xx statuses a hook refusal can carry (`RefusalMap::for_hook` clamps to 400..=499).
const REJECT_STATUSES: usize = 100;

/// `busbar_route_policy_{selections,rejections}_total` for one bound walk pool: a handle per name
/// that can decide the walk (every rewrite, gate and base policy of the pool's scope and their
/// fallbacks, by [`Call::decider`]), resolved once when the walk is bound.
pub struct RouteCounters {
    pool: Arc<str>,
    deciders: BTreeMap<Arc<str>, Decider>,
}

struct Decider {
    selections: metrics::Counter,
    /// Rejections by status, slot `status - 400`. A slot registers its series on the first
    /// rejection at that status, so an unused status never shows as a zero series.
    rejections: Box<[OnceLock<metrics::Counter>; REJECT_STATUSES]>,
}

impl RouteCounters {
    pub fn bind<'c>(pool: &str, calls: impl IntoIterator<Item = &'c Arc<Call>>) -> Self {
        let pool: Arc<str> = Arc::from(pool);
        let mut deciders = BTreeMap::new();
        let mut pending: Vec<&Arc<Call>> = calls.into_iter().collect();
        while let Some(call) = pending.pop() {
            pending.extend(&call.fallbacks);
            deciders
                .entry(Arc::clone(call.decider()))
                .or_insert_with_key(|policy: &Arc<str>| Decider {
                    selections: metrics::counter!(
                        ROUTE_POLICY_SELECTIONS_TOTAL,
                        "policy" => Arc::clone(policy),
                        "pool" => Arc::clone(&pool),
                    ),
                    rejections: Box::new(std::array::from_fn(|_| OnceLock::new())),
                });
        }
        Self { pool, deciders }
    }

    /// The reconcile installed an order or a preferred set decided by `decider`.
    pub(crate) fn selected(&self, decider: &str) {
        if let Some(decider) = self.deciders.get(decider) {
            decider.selections.increment(1);
        }
    }

    /// `decider` rejected the request with the client refusal `status`.
    pub(crate) fn rejected(&self, decider: &str, status: u16) {
        let Some((policy, held)) = self.deciders.get_key_value(decider) else {
            return;
        };
        let Some(slot) = status
            .checked_sub(400)
            .and_then(|slot| held.rejections.get(usize::from(slot)))
        else {
            return;
        };
        slot.get_or_init(|| {
            metrics::counter!(
                ROUTE_POLICY_REJECTIONS_TOTAL,
                "policy" => Arc::clone(policy),
                "pool" => Arc::clone(&self.pool),
                "status" => crate::cold::route_policy_status_label(status),
            )
        })
        .increment(1);
    }
}

#[derive(Clone, Default)]
pub struct Taps {
    pub request: Arc<[Arc<Call>]>,
    pub candidate: Arc<[Arc<Call>]>,
    pub routing: Arc<[Arc<Call>]>,
    pub response: Arc<[Arc<Call>]>,
}

/// One invocation's selection. Every service is already constructed and generation-bound.
#[derive(Clone)]
pub struct Selected {
    /// Shared with the seat's frozen selection: a request clones the Arc, never the list.
    pub rewrites: Arc<[Arc<Call>]>,
    /// Stable priority order; concurrent results are reconciled in this order.
    pub gates: Arc<[Arc<Call>]>,
    pub policy: Option<Arc<Call>>,
    pub taps: Taps,
    pub key: Option<CallerKey>,
    pub budget: Vec<BudgetBucketState>,
    pub rate_headroom: Option<f64>,
    pub cost: Arc<CostModel>,
    pub reads: HookRead,
    /// The route-policy counters of the selected walk pool; `None` outside a pool walk.
    pub counters: Option<Arc<RouteCounters>>,
}

/// Selection uses the same configured scope as the native egress walk, never a body field.
pub struct Selection<'a> {
    pub route: u32,
    pub pool: &'a str,
    pub container: &'a str,
    pub dialect: &'a str,
    pub principal: Option<&'a str>,
    /// The exact admitted billing key retained by InvocationContext, including external keys.
    pub key: Option<&'a busbar_contract::records::VirtualKey>,
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

#[cfg(test)]
pub(crate) mod tests;
