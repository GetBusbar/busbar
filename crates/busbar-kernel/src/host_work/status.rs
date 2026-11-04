// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::host::service::{
    WORK_STATUS_ABSENT, WORK_STATUS_LIVE, WORK_STATUS_SETTLED, WORK_STATUS_SETTLING,
};

use super::*;

impl WorkBook {
    /// Read-only instance-scoped settlement observation. Cached state and its in-flight marker
    /// are read under one lock; only `commit_settle` publishes a settled cached state. Cold
    /// observations read the durable row without adopting, rebinding, or disclosing its contents.
    pub fn status(
        &self,
        rows: &dyn RecordRows,
        instance: &Arc<str>,
        reference: &Reference,
        now_ms: u64,
        retain_ms: u64,
    ) -> Result<u64, StoreError> {
        {
            let book = self.lock();
            if let Some(handle) = book.by_ref.get(&(Arc::clone(instance), *reference)) {
                if let Some(work) = book.handles.get(handle) {
                    return Ok(if book.settling.contains(handle) {
                        WORK_STATUS_SETTLING
                    } else {
                        retained_status(work, now_ms, retain_ms)
                    });
                }
            }
        }
        let Some(row) = rows.record_get(WORK_SCHEMA, &work_key(instance, reference))? else {
            return Ok(WORK_STATUS_ABSENT);
        };
        // Sweeping writes an empty tombstone. A malformed nonempty row is an error, not absence
        // and especially not terminal evidence.
        if row.as_slice().is_empty() {
            return Ok(WORK_STATUS_ABSENT);
        }
        let work = Work::read(instance, *reference, row.as_slice()).ok_or(StoreError::Gap)?;
        Ok(retained_status(&work, now_ms, retain_ms))
    }
}

fn retained_status(work: &Work, now_ms: u64, retain_ms: u64) -> u64 {
    if work.live {
        WORK_STATUS_LIVE
    } else if work.settled_ms.saturating_add(retain_ms) > now_ms {
        WORK_STATUS_SETTLED
    } else {
        WORK_STATUS_ABSENT
    }
}
