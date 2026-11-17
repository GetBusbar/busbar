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
    pub classes: Vec<UsageClass>,
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
        use zeroize::Zeroize;
        for (_, value) in &mut self.facts {
            if let FactVal::Text(value) = value {
                value.as_mut().zeroize();
            }
        }
    }
}

impl Projection {
    fn absorb(&mut self, answer: &Answer) {
        for (key, value) in &answer.facts {
            if (busbar_plugin_abi::fail::fact::PJ_MODEL
                ..=busbar_plugin_abi::fail::fact::PJ_TEXT_COMPLETE)
                .contains(key)
            {
                self.facts.retain(|(held, _)| held != key);
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

    fn rewritten(&mut self, bytes: Vec<u8>, answer: &Answer) {
        use busbar_plugin_abi::fail::fact::*;
        self.conversation = Some(SecureVec::from(bytes));
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
