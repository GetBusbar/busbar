// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S KERNEL-SIDE ACTS A PLANE ASKS FOR (#43/#71): a plane reports units and the kernel
//! holds and meters, so the hold a plane's admission carries is opened here, never in the plane.

use busbar_contract::caps::{
    Admission, Admittance, Grant, Hold, MeterClassId, PrincipalId, QuantitySource, ReasonCode,
    Refusal, UsageLine,
};
use busbar_contract::caps::{AuditFacts, OpClassId};
use busbar_contract::{ClassDirection, FinishClass};

/// The admission of a unit the door admitted at zero: its own hold, reserving nothing, for this
/// principal, opened with the admittance grant the loop lent for this call.
pub fn admitted_at_zero(admit_token: &Grant<Admittance>, principal: PrincipalId) -> Admission {
    Admission::Own(Hold::open(admit_token, principal, 0))
}

/// A unit's arrival hold: the hold it carries into the in-flight table before it reaches the door.
/// It reserves nothing, since a unit refused at the gate spent nothing, and it opens only with the
/// admittance grant the kernel lends for this call.
pub fn arrival_hold(principal: PrincipalId, admit_token: &Grant<Admittance>) -> Hold {
    Hold::open(admit_token, principal, 0)
}

/// THE NODE'S ONE UNIT-KEY ALLOCATOR, from 1. A unit's identity is the kernel's to mint: a plane
/// that needs a key for a table it keeps (a served session's open calls) takes it from here.
#[derive(Debug, Default)]
pub struct UnitKeyMint(std::sync::atomic::AtomicU64);

impl UnitKeyMint {
    /// The next key, unique on this node.
    pub fn mint(&self) -> busbar_contract::ids::UnitKey {
        let n = self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        busbar_contract::ids::UnitKey::new(n + 1)
    }
}

/// THE NODE'S ONE `op_id` ALLOCATOR, the mint every store handle is handed: every store write's
/// `op_id` on this process. The node half is drawn ONCE per process from the OS CSPRNG (never `0`),
/// so a restarted process never re-issues an id an earlier boot wrote: the store's durable dedupe
/// would answer it as that write's replay and apply nothing (the store kind's dedupe outlives the process). The counter is one
/// process-global from 1.
pub fn op_id() -> busbar_contract::abi::store::OpId {
    IDS.mint()
}

/// THIS NODE: the node half of every `op_id` this process mints ([`op_id`]), the one node identity
/// the kernel draws. The fixed audit record names it as the node that sealed it (THE DESIGN §1:
/// "when (wall + monotonic, node)"), except on a chain the configured store keeps, whose records
/// name the id the store assigned the host. Never `0`.
#[must_use]
pub fn node() -> u64 {
    IDS.node
}

/// This boot's `op_id`s, drawn on first use.
static IDS: std::sync::LazyLock<OpIds> = std::sync::LazyLock::new(|| OpIds::boot(boot_node()));

/// One boot's `op_id`s: its node half and its counter.
#[derive(Debug)]
pub(crate) struct OpIds {
    node: u64,
    counter: std::sync::atomic::AtomicU64,
}

impl OpIds {
    /// A boot whose node half is `node`, counting from 1.
    pub(crate) fn boot(node: u64) -> Self {
        Self {
            node,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// The next id of this boot.
    pub(crate) fn mint(&self) -> busbar_contract::abi::store::OpId {
        let n = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        busbar_contract::abi::store::OpId::from_parts(self.node, n + 1)
    }
}

/// This boot's node half: a non-zero draw of the OS CSPRNG. No entropy source is a refused boot,
/// never a guessable id (a clock can roll back onto an earlier boot's).
fn boot_node() -> u64 {
    for _ in 0..8 {
        let mut b = [0u8; 8];
        if getrandom::fill(&mut b).is_ok() {
            let n = u64::from_le_bytes(b);
            if n != 0 {
                return n;
            }
        }
    }
    panic!("the OS entropy source answered nothing usable; a store op_id cannot be minted")
}

/// The door's admission answer, in the ADMIT step's terms: the verdict, whether the charge landed,
/// and the pool it landed on when a budget downgrade re-pooled it.
#[derive(Debug)]
pub struct AdmitVerdict {
    /// `Ok` when the door admitted the unit; the refusal when a budget in its chain had no headroom.
    pub verdict: Result<(), Refusal>,
    /// Whether the charge LANDED. An admission without a grant (governance off, no resolved key)
    /// charged nothing, so a non-2xx end must not refund it.
    pub charged: bool,
    /// `Some` when `on_exhaust: downgrade` re-pooled the admission onto this pool.
    pub effective_pool: Option<String>,
}

/// Read the door's admission outcome as the ADMIT step's verdict. `Ok` carries the grant (absent
/// when the door admitted without charging) and the downgrade pool; `Err` carries the refusal's
/// `Retry-After`, in whole seconds, as the door rendered it. A refusal here is always a budget in
/// the chain without headroom: the door refuses for no other reason.
pub fn admit_verdict(
    outcome: Result<(Option<&crate::plane_host::AdmitHandle>, Option<String>), Option<u32>>,
) -> AdmitVerdict {
    match outcome {
        Ok((grant, effective_pool)) => AdmitVerdict {
            verdict: Ok(()),
            charged: grant.is_some(),
            effective_pool,
        },
        Err(retry_after) => {
            let mut refusal = Refusal::new(ReasonCode::OverBudget);
            if let Some(secs) = retry_after {
                refusal = refusal.retry_after(secs);
            }
            AdmitVerdict {
                verdict: Err(refusal),
                charged: false,
                effective_pool: None,
            }
        }
    }
}

/// The unit's usage lines: one per non-zero tier, in canonical order. A response that reported
/// nothing reports no lines: zero, not a floor.
pub fn usage_lines(reported: Option<&busbar_contract::billing::TokenUsage>) -> Vec<UsageLine> {
    let mut lines = Vec::new();
    if let Some(u) = reported {
        push_line(&mut lines, CLASS_INPUT, ClassDirection::Input, u.input);
        push_line(&mut lines, CLASS_OUTPUT, ClassDirection::Response, u.output);
        push_line(
            &mut lines,
            CLASS_CACHE_READ,
            ClassDirection::CacheRead,
            u.cache_read.unwrap_or(0),
        );
        push_line(
            &mut lines,
            CLASS_CACHE_WRITE,
            ClassDirection::CacheWrite,
            u.cache_creation.unwrap_or(0),
        );
    }
    lines
}

const CLASS_INPUT: MeterClassId = MeterClassId::new(busbar_contract::records::UNIT_INPUT);
const CLASS_OUTPUT: MeterClassId = MeterClassId::new(busbar_contract::records::UNIT_OUTPUT);
const CLASS_CACHE_READ: MeterClassId = MeterClassId::new(busbar_contract::records::UNIT_CACHE_READ);
const CLASS_CACHE_WRITE: MeterClassId =
    MeterClassId::new(busbar_contract::records::UNIT_CACHE_WRITE);

/// One line, if the tier carries anything. A zero-quantity line is not a fact about anything.
fn push_line(
    lines: &mut Vec<UsageLine>,
    class: MeterClassId,
    direction: ClassDirection,
    quantity: u64,
) {
    if quantity == 0 {
        return;
    }
    lines.push(UsageLine {
        class,
        quantity,
        // The figure came from the destination's own response, read at the locator the dialect's
        // reader knows, not from a byte count of ours. The four directions partition the tiers:
        // uncached input, the response, and the two additive cache sides.
        source: QuantitySource::Locator {
            direction,
            ptr: busbar_contract::caps::LocatorPtr::new(class.as_str()),
        },
        estimated: false,
    });
}

/// The metering row a delivered response accrues, in the shape the flush writes to the store.
///
/// `model` is the config name of the SERVING lane (the lane that answered, after any failover):
/// it is the key the rate card is written against. A delivered response always counts its request,
/// whatever it consumed. The row is the unit's EVIDENCE of what the accrual wrote, not the durable
/// write: the durable row carries the card's instant, so `priced_from_ms` stays at its default here.
pub fn metering_row(
    key_id: &str,
    model: &str,
    provider: &str,
    usage: Option<&busbar_contract::billing::TokenUsage>,
) -> busbar_contract::records::MeteringRow {
    busbar_contract::records::MeteringRow {
        usage_units: Default::default(),
        key_id: key_id.to_owned(),
        model: model.to_owned(),
        provider: provider.to_owned(),
        tokens_input: usage.map(|u| u.input).unwrap_or(0),
        tokens_output: usage.map(|u| u.output).unwrap_or(0),
        tokens_cache_read: usage.and_then(|u| u.cache_read).unwrap_or(0),
        tokens_cache_write: usage.and_then(|u| u.cache_creation).unwrap_or(0),
        requests: 1,
        billable_requests: 1,
        key_group_at_use: String::new(),
        priced_from_ms: 0,
        pricing_version: String::new(),
    }
}

// ── VERIFY: WHERE A UNIT MAY GO ───────────────────────────────────────────────────────────────────
//
// The VERIFY step's three pre-admission guards, in the one order they may run in: the requested
// pool's allow-list, every fallback pool reachable from it, and, with a rate card present, a priced
// destination. The guards read the deployment through [`PoolView`] and answer with a named
// [`VerifyRefusal`], never with rendered bytes.

/// The closed refusal set of this step: two refusals, and there is no third.
///
/// They are kept apart rather than collapsed because they are different answers to different
/// questions and they carry different statuses. A pool the caller may not reach is settled before
/// pricing is asked about at all; a name with no configured rate is a bad request, not an exhausted
/// budget. Collapsing them would make two refusals indistinguishable to anything reading the record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyRefusal {
    /// The caller's key may not reach the pool it named, or a fallback pool reachable from it.
    ///
    /// One refusal for both, on purpose: a denial must be indistinguishable from outside whether it
    /// tripped on the requested pool or on a pool it would only have reached under exhaustion.
    NotAuthorized,
    /// A rate card is present and the name the caller supplied has no configured rate.
    NoRate {
        /// The name, as the caller spelled it — it appears in the message.
        name: String,
    },
}

impl VerifyRefusal {
    /// The status this refusal carries on the wire.
    ///
    /// Vendor-faithful and never 402: a pool the key may not reach is a permission answer, and an
    /// unbillable name is a bad request. No real provider answers either with a payment status, and
    /// emitting one would be a busbar tell.
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            VerifyRefusal::NotAuthorized => 403,
            VerifyRefusal::NoRate { .. } => 400,
        }
    }

    /// The dialect-shaped kind word, read from the same bank the live doors read it from rather
    /// than respelled here.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            VerifyRefusal::NotAuthorized => busbar_contract::protocol::KIND_PERMISSION,
            VerifyRefusal::NoRate { .. } => busbar_contract::protocol::KIND_INVALID_REQUEST,
        }
    }

    /// The caller-facing message, verbatim.
    ///
    /// The permission copy is vendor-plausible and names NOTHING of the operator's: not the key id,
    /// not the pool, not a word of governance vocabulary — a native vendor 403 never does, and the
    /// key id and pool go to the operator's own diagnostics instead (see [`verify`]).
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            VerifyRefusal::NotAuthorized => {
                "Your API key does not have permission to access this resource.".to_string()
            }
            VerifyRefusal::NoRate { name } => format!("no configured rate for model '{name}'"),
        }
    }

    /// The reason code the record files this refusal under.
    #[must_use]
    pub fn reason(&self) -> ReasonCode {
        match self {
            VerifyRefusal::NotAuthorized => ReasonCode::PoolNotPermitted,
            VerifyRefusal::NoRate { .. } => ReasonCode::NoRate,
        }
    }
}

/// Everything the three guards read about the deployment's pools and the caller's key.
///
/// A view rather than a snapshot: the live guards read these off the running app on the request
/// path, and copying them into a struct first would be a second reading that can disagree with the
/// one the door then charges against.
pub trait PoolView {
    /// Whether the caller presented a key at all. With no key every guard below is inert — that is
    /// the ungoverned posture, and it is one boolean rather than three absent checks.
    fn has_key(&self) -> bool;

    /// Whether the key names a pool restriction at all. `false` means it names none and admits
    /// every pool, so guard two has nothing to walk; an explicit EMPTY list is a restriction that
    /// denies everything, which is a different thing and is why this is not "is the list non-empty".
    fn key_is_scoped(&self) -> bool;

    /// Whether the key may use one pool.
    fn pool_allowed(&self, pool: &str) -> bool;

    /// The pool this one falls over to when it exhausts, where its exhaustion policy names one.
    /// `None` when the policy stays inside this pool, or the pool is not configured at all.
    fn on_exhausted_fallback(&self, pool: &str) -> Option<String>;

    /// Whether the name refers to a configured pool or a configured by-model lane. Either is priced
    /// by construction — boot refuses a card that does not cover them — so only an arbitrary
    /// caller-supplied name can reach the third guard.
    fn is_configured(&self, name: &str) -> bool;

    /// Whether a PRESENT card leaves this name unpriced — `false` for every name when no card is
    /// configured, because there is no card to miss (#42: rate_card absent reads 0, it never
    /// refuses). The card's presence is the kernel's question, answered inside this one read; the
    /// plane never asks whether billing is on (#43), so the guard below carries no billing branch.
    fn is_unpriced(&self, name: &str) -> bool;
}

/// Guard one: the requested pool's allow-list. Inert with no key.
fn pool_authorized(view: &dyn PoolView, pool: &str) -> Option<VerifyRefusal> {
    (view.has_key() && !view.pool_allowed(pool)).then_some(VerifyRefusal::NotAuthorized)
}

/// Guard two: every fallback pool the request could reach if the requested one exhausts.
///
/// Multi-level (A→B→C) and possibly cyclic (A→B→A), so the walk carries a visited set and stops for
/// the same reason the dispatch stops. A denial is the SAME refusal guard one raises.
fn fallback_pools_authorized(view: &dyn PoolView, pool: &str) -> Option<VerifyRefusal> {
    if !view.has_key() || !view.key_is_scoped() {
        return None;
    }
    let mut visited: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut current = pool.to_string();
    loop {
        if !visited.insert(current.clone()) {
            return None;
        }
        let next = view.on_exhausted_fallback(&current)?;
        if let Some(refusal) = pool_authorized(view, &next) {
            return Some(refusal);
        }
        current = next;
    }
}

/// Guard three: with a card present, every governed request must resolve to a priced destination.
///
/// With no card configured [`PoolView::is_unpriced`] is `false` for every name, so the guard is inert
/// without this step ever reading whether billing is on (#43).
fn priced(view: &dyn PoolView, name: &str) -> Option<VerifyRefusal> {
    (view.has_key() && !view.is_configured(name) && view.is_unpriced(name)).then(|| {
        VerifyRefusal::NoRate {
            name: name.to_string(),
        }
    })
}

/// The three guards, in their fixed order. Named separately from [`verify`] so the ORDER can be
/// checked without a token in hand, and so the composition root can ask the same question at a
/// boot-time dry run.
pub fn destination_guard(view: &dyn PoolView, pool: &str) -> Result<(), VerifyRefusal> {
    if let Some(r) = pool_authorized(view, pool) {
        return Err(r);
    }
    if let Some(r) = fallback_pools_authorized(view, pool) {
        return Err(r);
    }
    if let Some(r) = priced(view, pool) {
        return Err(r);
    }
    Ok(())
}

// ── AUDIT: HOW A UNIT ENDED ───────────────────────────────────────────────────────────────────────

/// THE AUDIT FACTS of a unit that passed the door: its op class and how it ended. The finish is the
/// one the plane reported from the answer's own end; where it reported none, the client-facing
/// status decides: a 2xx is `Complete` and anything else is `Error`.
pub fn admitted_facts(
    op_class: OpClassId,
    reported: Option<FinishClass>,
    success: bool,
) -> AuditFacts {
    let finish = reported.unwrap_or(if success {
        FinishClass::Complete
    } else {
        FinishClass::Error
    });
    AuditFacts { op_class, finish }
}

/// THE AUDIT FACTS of a unit the door or a step before it refused. A refusal is never a
/// completion, whatever status it wears.
pub fn refused_facts(op_class: OpClassId) -> AuditFacts {
    AuditFacts {
        op_class,
        finish: FinishClass::Error,
    }
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod door_tests;

#[cfg(test)]
#[path = "tests/door_destination_tests.rs"]
mod door_destination_tests;

#[cfg(test)]
#[path = "tests/door_op_id_tests.rs"]
mod door_op_id_tests;
