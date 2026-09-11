// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SUITE'S OWN RED PROOFS: each ruling here is driven against a backend built to have the
//! defect the ruling exists for, and is required to FIRE.
//!
//! A conformance ruling that has only ever been run against correct backends is a row nobody has to
//! agree with — the same argument the module header makes for why the reference backend is not
//! exempt from the suite, one level up. A green row means something only if a red one was reachable.

use super::*;

/// A backend with the defect [`assert_usage_survives_reopen_atomically`] exists for: the
/// BUCKET-level request counters are stored on its per-`(bucket, window, MODEL)` rows, so a delta
/// that names no model has nowhere to land. `add_usage` returns `Ok(())` and the count is gone.
///
/// This is not an invented shape. It is what a shipped first-party SQL backend does — its schema's
/// primary key carries `model`, and its accumulate applies `requests`/`billable_requests` inside
/// the per-model loop — measured end to end against the published binary, where a restarted node
/// read its key's spend back intact and its request count back at zero.
#[derive(Default)]
struct RequestsKeyedByModel {
    rows: std::sync::Mutex<std::collections::BTreeMap<(String, u64, String), ModelRow>>,
}

/// One `(bucket, window, model)` row — the shape that loses the count.
#[derive(Default, Clone)]
struct ModelRow {
    requests: u64,
    billable_requests: u64,
    units: std::collections::BTreeMap<String, u64>,
}

impl Store for RequestsKeyedByModel {
    fn add_usage(&self, bucket_id: &str, window_start: u64, delta: &UsageDelta) -> StoreResult<()> {
        let mut rows = self.rows.lock().expect("rows");
        // THE DEFECT, in one loop: the request counters are applied INSIDE the per-model
        // iteration, so a delta carrying no models applies them nowhere at all.
        for m in &delta.models {
            let row = rows
                .entry((bucket_id.to_string(), window_start, m.model.clone()))
                .or_default();
            row.requests = row.requests.saturating_add_signed(delta.requests);
            row.billable_requests = row
                .billable_requests
                .saturating_add_signed(delta.billable_requests);
            for (unit, d) in &m.usage_units {
                let cur = row.units.entry(unit.clone()).or_insert(0);
                *cur = cur.saturating_add_signed(*d);
            }
        }
        Ok(())
    }
    fn get_usage(&self, bucket_id: &str, window_start: u64) -> StoreResult<UsageLedger> {
        let rows = self.rows.lock().expect("rows");
        let mut out = UsageLedger::default();
        for ((b, w, model), row) in rows.iter() {
            if b != bucket_id || *w != window_start {
                continue;
            }
            out.requests = out.requests.saturating_add(row.requests);
            out.billable_requests = out.billable_requests.saturating_add(row.billable_requests);
            out.models.push(ModelTokens {
                model: model.clone(),
                usage_units: row.units.clone(),
            });
        }
        Ok(out)
    }
    fn put_usage(
        &self,
        _bucket_id: &str,
        _window_start: u64,
        _ledger: &UsageLedger,
    ) -> StoreResult<()> {
        Ok(())
    }
    // The remaining verbs with no default body: this double answers no key or metering question.
    fn put_key(&self, _key: &VirtualKey) -> StoreResult<()> {
        Ok(())
    }
    fn get_key(&self, _id: &str) -> StoreResult<Option<VirtualKey>> {
        Ok(None)
    }
    fn list_keys(&self) -> StoreResult<Vec<VirtualKey>> {
        Ok(Vec::new())
    }
    fn delete_key(&self, _id: &str) -> StoreResult<()> {
        Ok(())
    }
    fn add_metering(&self, _delta: &MeteringDelta) -> StoreResult<()> {
        Ok(())
    }
    fn list_metering(&self, _bucket: u64) -> StoreResult<Vec<MeteringRow>> {
        Ok(Vec::new())
    }
}

/// The atomic-reopen ruling FIRES against a backend that keys the request counters by model, and
/// fires with the message that names the defect — not merely with some panic.
///
/// The second half of the proof is what makes this a MONEY finding rather than a store that wrote
/// nothing: the double is required to have KEPT the tokens. Spend survives; the cap does not.
#[test]
fn the_atomic_ruling_reds_a_backend_that_keys_requests_by_model() {
    let store = Arc::new(RequestsKeyedByModel::default());
    let open = shared_opener(Arc::clone(&store));
    let fired = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_usage_survives_reopen_atomically(&open, "redproof")
    }));
    let err = fired.expect_err(
        "the ruling did NOT fire against a backend that keys the bucket-level request counters by \
         model — so it cannot catch the shape it exists for, and every green row it has ever \
         produced means nothing",
    );
    let msg = err
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| err.downcast_ref::<&str>().map(|s| (*s).to_string()))
        .unwrap_or_default();
    assert!(
        msg.contains("ONE record"),
        "the ruling fired, but not with the message that names the defect an operator has to act \
         on: {msg}"
    );

    let back = store
        .get_usage(&atomic_bucket("redproof"), ATOMIC_WINDOW)
        .expect("get_usage");
    assert_eq!(
        back.requests, 0,
        "the defective double was expected to LOSE the admission flush's request count"
    );
    assert_eq!(
        back.models,
        atomic_ledger().models,
        "the defective double was expected to KEEP the tokens — spend survives, the cap does not, \
         which is what makes this a money defect rather than a store that simply wrote nothing"
    );
}
