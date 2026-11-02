// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

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
    /// The immutable key of the card entry the counts were priced with.
    pub entry: busbar_kernel::cost::EntryKey,
    /// THE CARD EPOCH: the corrected unit's arrival instant in milliseconds. The correction lands
    /// in the window, card entry and metering day holding it.
    pub card_epoch_ms: u64,
    /// The pool the unit was dispatched through.
    pub pool: String,
    /// The signed delta per class.
    pub delta: BTreeMap<String, i64>,
}

/// Why the ledger would not take a correction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The history holds no entry with that key.
    UnknownEntry,
    /// The ledger refused it; nothing was applied.
    Ledger(AdjustRefused),
}

pub type UsageAdjuster =
    Arc<dyn Fn(&Correction) -> Result<Result<(), Refused>, String> + Send + Sync>;

#[must_use]
pub fn no_ledger() -> UsageAdjuster {
    Arc::new(|_| Err("no ledger is bound on this node".to_string()))
}

#[must_use]
pub fn live_adjuster(app: Arc<busbar_kernel::state::AppHandle>) -> UsageAdjuster {
    Arc::new(move |c: &Correction| {
        let snapshot = app.load();
        let Some(gov) = snapshot.governance.clone() else {
            return Err("this node has no governance store".to_string());
        };
        let history = busbar_kernel::rate_apply::dated_history();
        let era = match history.as_deref() {
            Some(history) => match history.entry(&c.entry) {
                Some(entry) => entry.effective_from(),
                None => return Ok(Err(Refused::UnknownEntry)),
            },

            None => return Ok(Err(Refused::UnknownEntry)),
        };
        let adjustment = busbar_kernel::governance::Adjustment {
            entry_id: None,
            key_id: &c.key,
            pool: &c.pool,
            model: &c.lane,
            entry_era: era,
            entry_id: Some(c.entry.id()),
            card_epoch_ms: c.card_epoch_ms,
            delta: &c.delta,
            now: busbar_kernel::store::now(),
        };
        crate::root::durability::off_runtime(|| gov.adjust_usage(&snapshot.cost, &adjustment))
            .map(|applied| applied.map_err(Refused::Ledger))
            .map_err(|e| e.to_string())
    })
}

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
    let entry = busbar_kernel::cost::EntryKey::parse_hex(text("entry")?)
        .ok_or(GovernanceError::Validation)?;
    let card_epoch_ms = obj
        .get("card_epoch_ms")
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
        card_epoch_ms,
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
            "`entry` names {entry}, which is not a known rate-card history key"
        ))),
        Ok(Err(Refused::Ledger(why))) => Ok(refused(&why.to_string())),
        Ok(Ok(())) => serde_json::to_vec(&serde_json::json!({
            "applied": true,
            "key": correction.key,
            "lane": correction.lane,
            "entry": correction.entry.hex(),
            "card_epoch_ms": correction.card_epoch_ms,
            "pool": correction.pool,
            "delta": correction.delta,
        }))
        .map(super::json_answer)
        .map_err(|_| GovernanceError::Store),
    }
}

fn refused(message: &str) -> AdminAnswer {
    AdminAnswer {
        status: 400,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: busbar_core_admin::admin_codec::refusal::envelope_of("invalid_request", message)
            .into_bytes(),
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;
    use std::sync::Mutex;

    #[test]
    fn an_adjustment_keeps_the_exact_entry_key_in_the_request_and_response() {
        let entry = busbar_kernel::cost::EntryKey::new(300, [7; 8], 1);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let received = seen.clone();
        let adjuster: UsageAdjuster = Arc::new(move |correction| {
            received.lock().unwrap().push(correction.entry);
            Ok(Ok(()))
        });
        let body = serde_json::to_vec(&serde_json::json!({
            "key": "key", "lane": "lane", "entry": entry.hex(), "card_epoch_ms": 350,
            "pool": "pool", "delta": {"input": 1}, "reason": "correct a count"
        }))
        .unwrap();
        let answer = adjust_effect(
            &body,
            busbar_contract::authz::Scope::Full,
            &|pool| pool == "pool",
            &adjuster,
        )
        .unwrap();
        assert_eq!(answer.status, 200);
        assert_eq!(*seen.lock().unwrap(), vec![entry]);
        let reply: serde_json::Value = serde_json::from_slice(&answer.body).unwrap();
        assert_eq!(reply["entry"], entry.hex());
    }

    #[test]
    fn an_adjustment_refuses_ordinal_and_malformed_tokens_before_the_ledger() {
        let adjuster: UsageAdjuster = Arc::new(|_| panic!("invalid entry reached the ledger"));
        for entry in [
            serde_json::json!(1),
            serde_json::json!("1"),
            serde_json::json!("not-a-key"),
            serde_json::json!("g".repeat(40)),
        ] {
            let body = serde_json::to_vec(&serde_json::json!({
                "key": "key", "lane": "lane", "entry": entry, "card_epoch_ms": 350,
                "pool": "pool", "delta": {"input": 1}, "reason": "correct a count"
            }))
            .unwrap();
            assert!(matches!(
                adjust_effect(
                    &body,
                    busbar_contract::authz::Scope::Full,
                    &|_| true,
                    &adjuster
                ),
                Err(GovernanceError::Validation)
            ));
        }
    }
}
