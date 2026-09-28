// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE DOOR'S KERNEL-SIDE ACTS A PLANE ASKS FOR (#43/#71): a plane reports units and the kernel
//! holds and meters, so the hold a plane's admission carries is opened here, never in the plane.

use busbar_contract::caps::{
    Admission, Admittance, Grant, Hold, MeterClassId, PrincipalId, QuantitySource, ReasonCode,
    Refusal, UsageLine,
};
use busbar_contract::ClassDirection;

/// The admission of a unit the door admitted at zero: its own hold, reserving nothing, for this
/// principal, opened with the admittance grant the loop lent for this call.
pub fn admitted_at_zero(admit_token: &Grant<Admittance>, principal: PrincipalId) -> Admission {
    Admission::Own(Hold::open(admit_token, principal, 0))
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

/// THE FEE the METER step decides: one per delivered client request that routed to an upstream.
/// The kind of leg and the client-facing status decide it, and nothing else.
pub fn fee_count(delivered: bool, upstream_leg: bool) -> u32 {
    u32::from(delivered && upstream_leg)
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

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod door_tests;
