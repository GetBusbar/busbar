// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **THE `adjust` VERB'S EFFECT** (MONEY-DESIGN §4, "Amendments become counts"): a root correction
//! to a key's COUNTS, as a SIGNED DELTA on the one ledger — the usage rows every money view prices.
//!
//! There is no amendment journal and no read-time correction any more: two nodes reading the same
//! counts report the same money (MONEY-REVIEW review 5, B9). The correction:
//!
//! - names the KEY, the LANE (model) the counts were earned on, and the card ENTRY they were priced
//!   with (its history position, as `GET /api/v1/admin/usage` names it in `rate_card_version`);
//! - names the POOL the unit was dispatched through (owner ruling Q64/Q67), so it lands on every
//!   bucket an accrual of the unit landed on: the key's own and each group bucket that pool
//!   participates in;
//! - is applied to the counts in RAM at once, all or nothing, and reaches the store as a signed
//!   `add_usage` delta through today's write-behind path (the poster replaces it, PR-B2);
//! - is REFUSED when it would take any count of its segment below zero: nothing is applied.
//!
//! The admin unit's own audit record is the trail: who asked, and that it applied.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::AdminAnswer;
use busbar_core_admin::GovernanceError;
use busbar_kernel::governance::AdjustRefused;

/// One correction, as the verb's body states it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Correction {
    /// The key whose counts are corrected.
    pub key: String,
    /// The lane (model) the counts were earned on.
    pub lane: String,
    /// The card entry the counts were priced with, by its history position.
    pub entry: u64,
    /// The pool the unit was dispatched through.
    pub pool: String,
    /// The signed delta per class.
    pub delta: BTreeMap<String, i64>,
}

/// Why the ledger would not take a correction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The history holds no entry at that position.
    UnknownEntry,
    /// The ledger refused it; nothing was applied.
    Ledger(AdjustRefused),
}

/// WHERE A CORRECTION LANDS: the node's live governance state. `Err` is a store that could not be
/// read, in its own words, for the node's log only.
pub type UsageAdjuster =
    Arc<dyn Fn(&Correction) -> Result<Result<(), Refused>, String> + Send + Sync>;

/// The adjuster of a node no root bound a ledger to: every correction is a store failure.
#[must_use]
pub fn no_ledger() -> UsageAdjuster {
    Arc::new(|_| Err("no ledger is bound on this node".to_string()))
}

/// The adjuster over `app`'s live governance state and dated rate-card history: the entry's
/// position resolves to the era its counts were dated with (its `effective_from`), and
/// [`busbar_kernel::governance::GovState::adjust_usage`] applies the delta.
#[must_use]
pub fn live_adjuster(app: Arc<busbar_kernel::state::AppHandle>) -> UsageAdjuster {
    Arc::new(move |c: &Correction| {
        let snapshot = app.load();
        let Some(gov) = snapshot.governance.clone() else {
            return Err("this node has no governance store".to_string());
        };
        let history = busbar_kernel::rate_apply::dated_history();
        let era = match history.as_deref() {
            Some(history) => match history.entries().iter().find(|e| e.seq().get() == c.entry) {
                Some(entry) => entry.effective_from(),
                None => return Ok(Err(Refused::UnknownEntry)),
            },
            // No dated history: every count is undated, era zero, priced by the one card.
            None if c.entry == busbar_kernel::cost::HistorySeq::OPENING.get() => 0,
            None => return Ok(Err(Refused::UnknownEntry)),
        };
        let adjustment = busbar_kernel::governance::Adjustment {
            key_id: &c.key,
            pool: &c.pool,
            model: &c.lane,
            entry_era: era,
            delta: &c.delta,
            now: busbar_kernel::store::now(),
        };
        crate::root::durability::off_runtime(|| gov.adjust_usage(&snapshot.cost, &adjustment))
            .map(|applied| applied.map_err(Refused::Ledger))
            .map_err(|e| e.to_string())
    })
}

/// The effect half of `adjust`: decode a COUNT correction and apply it to the one ledger.
///
/// The body is `{ "key": "<key id>", "lane": "<model>", "entry": <history position>,
/// "pool": "<pool name>", "delta": { "<class>": <signed whole count>, … }, "reason": "…" }`.
/// Counts are whole numbers and never a money figure (owner ruling Q9). `scope` is the scope the
/// caller was admitted under; the verbs unit admits `adjust` at `full` only, and it is checked again
/// here.
///
/// Refusals are client-safe: a malformed body, a blank reason, a scope below `full`, an entry the
/// history does not hold, or a delta that would take a count below zero is `400 invalid_request`
/// naming the fault; a key that does not exist is `NotFound`. A missing `pool`, or one `pool_known`
/// does not know, is `400` naming it (Q64/Q67). Nothing is applied on any refusal.
pub(crate) fn adjust_effect(
    body: &[u8],
    scope: busbar_contract::authz::Scope,
    pool_known: &dyn Fn(&str) -> bool,
    adjuster: &UsageAdjuster,
) -> Result<AdminAnswer, GovernanceError> {
    if scope != busbar_contract::authz::Scope::Full {
        return Err(GovernanceError::Validation);
    }
    let doc: serde_json::Value =
        serde_json::from_slice(body).map_err(|_| GovernanceError::Validation)?;
    let obj = doc.as_object().ok_or(GovernanceError::Validation)?;
    let text = |key: &str| {
        obj.get(key)
            .and_then(serde_json::Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .ok_or(GovernanceError::Validation)
    };
    let key = text("key")?;
    let lane = text("lane")?;
    let _reason = text("reason")?;
    let entry = obj
        .get("entry")
        .and_then(serde_json::Value::as_u64)
        .ok_or(GovernanceError::Validation)?;
    let Ok(pool) = text("pool") else {
        return Ok(super::error_answer_with_message(
            400,
            "invalid_request",
            "`pool` is required: name the pool the corrected unit was dispatched through",
        ));
    };
    if !pool_known(pool) {
        return Ok(super::error_answer_with_message(
            400,
            "invalid_request",
            &format!("`pool` names `{pool}`, which is not a configured pool"),
        ));
    }
    let mut delta = BTreeMap::new();
    for (class, n) in obj
        .get("delta")
        .and_then(serde_json::Value::as_object)
        .filter(|m| !m.is_empty())
        .ok_or(GovernanceError::Validation)?
    {
        let n = n.as_i64().ok_or(GovernanceError::Validation)?;
        delta.insert(class.clone(), n);
    }
    let correction = Correction {
        key: key.to_string(),
        lane: lane.to_string(),
        entry,
        pool: pool.to_string(),
        delta,
    };
    match adjuster(&correction) {
        Err(why) => {
            tracing::error!(why = %why, "an adjustment could not reach the ledger");
            Err(GovernanceError::Store)
        }
        Ok(Err(Refused::Ledger(AdjustRefused::UnknownKey))) => Err(GovernanceError::NotFound),
        Ok(Err(Refused::UnknownEntry)) => Ok(refused(&format!(
            "`entry` names {entry}, which is not a rate-card history position"
        ))),
        Ok(Err(Refused::Ledger(why))) => Ok(refused(&why.to_string())),
        Ok(Ok(())) => serde_json::to_vec(&serde_json::json!({
            "applied": true,
            "key": correction.key,
            "lane": correction.lane,
            "entry": correction.entry,
            "pool": correction.pool,
            "delta": correction.delta,
        }))
        .map(super::json_answer)
        .map_err(|_| GovernanceError::Store),
    }
}

/// The `400 invalid_request` a refused correction gets, in the admin envelope, with a message that
/// says what to fix.
fn refused(message: &str) -> AdminAnswer {
    AdminAnswer {
        status: 400,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: busbar_core_admin::admin_codec::refusal::envelope_of("invalid_request", message)
            .into_bytes(),
    }
}
