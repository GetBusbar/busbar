// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_core_admin::GovernanceError;
use busbar_kernel_audit::expose;
use serde_json::{json, Value};

/// Each request examines at most this many journal positions, with at most 256
/// 512-byte parts per position. The ring fast path holds at most AUDIT_RING records.
const SCAN_POSITIONS: u64 = 64;

struct Cursor {
    node: u64,
    incarnation: u64,
    from: u64,
    to: u64,
    snapshot_to: u64,
    journal_end: u64,
    next_journal: u64,
    next_audit: u64,
    incomplete: bool,
}

impl Cursor {
    fn decode(token: &str) -> Option<Self> {
        if token.len() > 256 {
            return None;
        }
        let rest = token.strip_prefix("ar1.")?;
        let numbers: Vec<u64> = rest
            .split('.')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .ok()?;
        let [node, incarnation, from, to, snapshot_to, journal_end, next_journal, next_audit, incomplete] =
            numbers.as_slice()
        else {
            return None;
        };
        if *incomplete > 1
            || *next_journal == 0
            || next_journal > journal_end
            || next_audit < &(*from).max(1)
            || snapshot_to > to
        {
            return None;
        }
        Some(Self {
            node: *node,
            incarnation: *incarnation,
            from: *from,
            to: *to,
            snapshot_to: *snapshot_to,
            journal_end: *journal_end,
            next_journal: *next_journal,
            next_audit: *next_audit,
            incomplete: *incomplete == 1,
        })
    }

    fn encode(&self) -> String {
        format!(
            "ar1.{}.{}.{}.{}.{}.{}.{}.{}.{}",
            self.node,
            self.incarnation,
            self.from,
            self.to,
            self.snapshot_to,
            self.journal_end,
            self.next_journal,
            self.next_audit,
            u8::from(self.incomplete)
        )
    }
}

/// Captured under the durability lock; all Store calls run after releasing it.
pub struct AuditPagePlan {
    body: Value,
    cursor: Cursor,
    records: Vec<AuditRecord>,
    stored: Option<store_chain::HeldChain>,
    memory: Option<Vec<JournalRecord>>,
    scan_end: u64,
    exhausted: bool,
}

impl Durability {
    pub fn prepare_audit_page(
        &self,
        from: u64,
        to: u64,
        token: Option<&str>,
    ) -> Result<AuditPagePlan, GovernanceError> {
        if from > to {
            return Err(GovernanceError::Validation);
        }
        let cursor = if let Some(token) = token {
            let cursor = Cursor::decode(token).ok_or(GovernanceError::Validation)?;
            if cursor.node != self.journal.node()
                || cursor.incarnation != self.incarnation
                || cursor.from != from
                || cursor.to != to
                || cursor.journal_end > self.journal.next_seq()
                || cursor.snapshot_to > self.record.next_seq().saturating_sub(1)
            {
                return Err(GovernanceError::Validation);
            }
            cursor
        } else {
            Cursor {
                node: self.journal.node(),
                incarnation: self.incarnation,
                from,
                to,
                snapshot_to: to.min(self.record.next_seq().saturating_sub(1)),
                journal_end: self.journal.next_seq(),
                next_journal: 1,
                next_audit: from.max(1),
                incomplete: false,
            }
        };
        let mut body: Value =
            serde_json::from_str(&expose::range_body(&self.record, &[], from, to))
                .map_err(|_| GovernanceError::Store)?;
        // The upper bound is fixed by the first page; later appends cannot move it.
        body["snapshot_to"] = json!(cursor.snapshot_to.to_string());
        body["semantics"] = json!("bounded_live_range");
        body["retention"] = json!({
            "ring_from": self.audit_records.first().map(|r| r.seq.to_string()),
            "ring_to": self.audit_records.last().map(|r| r.seq.to_string()),
            "durable_from": null,
            "durable_from_known": false,
        });
        // Keep the legacy anchor field, but bind it to the pinned observation.
        let snapshot_body: Value = serde_json::from_str(&expose::range_body(
            &self.record,
            &[],
            from,
            cursor.snapshot_to,
        ))
        .map_err(|_| GovernanceError::Store)?;
        body["anchor"] = snapshot_body["anchor"].clone();
        let covered = self
            .audit_records
            .first()
            .is_some_and(|r| r.seq <= cursor.next_audit);
        let exhausted = cursor.next_audit > cursor.snapshot_to;
        let scan_end = cursor
            .next_journal
            .saturating_add(SCAN_POSITIONS)
            .min(cursor.journal_end);
        let mut memory = None;
        let (records, stored) = if exhausted || covered {
            (
                self.audit_records
                    .iter()
                    .filter(|r| r.seq >= cursor.next_audit && r.seq <= cursor.snapshot_to)
                    .cloned()
                    .collect(),
                None,
            )
        } else if let Some(lane) = self.store_kept() {
            (
                Vec::new(),
                Some(
                    store_chain::HeldChain::of(&self.journal, lane)
                        .map_err(|_| GovernanceError::Store)?,
                ),
            )
        } else {
            // Root builders use a bounded memory journal; legacy data_dir is never opened.
            let journal = self
                .journal
                .replay()
                .map_err(|_| GovernanceError::Store)?
                .map_err(|_| GovernanceError::Store)?;
            memory = Some(
                journal
                    .into_iter()
                    .filter(|r| r.node_seq >= cursor.next_journal && r.node_seq < scan_end)
                    .collect(),
            );
            (Vec::new(), None)
        };
        Ok(AuditPagePlan {
            body,
            cursor,
            records,
            stored,
            memory,
            scan_end,
            exhausted,
        })
    }
}

impl AuditPagePlan {
    pub fn finish(mut self) -> Result<Vec<u8>, GovernanceError> {
        let journal_page = if let Some(stored) = self.stored.take() {
            Some(
                stored
                    .read_audit_page(self.cursor.next_journal, self.scan_end)
                    .map_err(|_| GovernanceError::Store)?,
            )
        } else {
            self.memory.take().map(|records| {
                let incomplete =
                    records.len() as u64 != self.scan_end.saturating_sub(self.cursor.next_journal);
                (records, incomplete)
            })
        };
        let scanned = if let Some((records, incomplete)) = journal_page {
            let scanned = self.scan_end.saturating_sub(self.cursor.next_journal);
            self.cursor.incomplete |= incomplete;
            for record in records {
                if let Some(audit) = decode_audit(&record).map_err(|_| GovernanceError::Store)? {
                    if audit.seq >= self.cursor.next_audit && audit.seq <= self.cursor.snapshot_to {
                        self.records.push(audit);
                    }
                }
            }
            self.cursor.next_journal = self.scan_end;
            self.exhausted |= self.scan_end >= self.cursor.journal_end;
            scanned
        } else {
            self.exhausted = true;
            0
        };
        // Audit positions are monotonic even though the journal also carries non-audit records.
        let mut gaps = Vec::new();
        for record in &self.records {
            if record.seq < self.cursor.next_audit {
                return Err(GovernanceError::Store);
            }
            if record.seq > self.cursor.next_audit {
                gaps.push(json!({"from": self.cursor.next_audit.to_string(), "to": (record.seq - 1).to_string()}));
            }
            self.cursor.next_audit = record.seq.checked_add(1).ok_or(GovernanceError::Store)?;
        }
        self.exhausted |= self.cursor.next_audit > self.cursor.snapshot_to;
        if self.exhausted && self.cursor.next_audit <= self.cursor.to {
            gaps.push(json!({"from": self.cursor.next_audit.to_string(), "to": self.cursor.to.to_string()}));
        }
        self.cursor.incomplete |= !gaps.is_empty();
        self.body["records"] = serde_json::from_str(&expose::range_records_body(
            &self.records,
            self.cursor.from,
            self.cursor.to,
        ))
        .map_err(|_| GovernanceError::Store)?;
        self.body["returned_from"] = json!(self.records.first().map(|r| r.seq.to_string()));
        self.body["returned_to"] = json!(self.records.last().map(|r| r.seq.to_string()));
        self.body["next_cursor"] = json!((!self.exhausted).then(|| self.cursor.encode()));
        self.body["truncated"] = json!(!self.exhausted);
        self.body["complete"] = json!(self.exhausted && !self.cursor.incomplete);
        self.body["incomplete"] = json!(self.cursor.incomplete);
        self.body["gaps"] = json!(gaps);
        self.body["scanned_positions"] = json!(scanned.to_string());
        self.body["scan_limit"] = json!(SCAN_POSITIONS.to_string());
        serde_json::to_vec(&self.body).map_err(|_| GovernanceError::Store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::root::store_double::RecordSlots;
    use crate::root::units_admin::{AuditView, NodeAudit};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    fn seal_records(book: &mut Durability, units: std::ops::RangeInclusive<u64>) {
        let kernel = crate::root::kernel::new_kernel();
        let token = kernel.durability_token();
        for unit in units {
            book.seal_unit(
                super::super::audit::tests::inputs(unit),
                busbar_kernel::teller::verb_audit_pass(&kernel),
                &token,
            )
            .unwrap();
        }
    }

    fn book(slots: &RecordSlots, count: u64) -> Arc<Mutex<Durability>> {
        let lane = JournalLane::start(slots.calls(), "test-store").unwrap();
        let mut book = build_on_store(&DurabilityConfig::default(), 47, lane, None).unwrap();
        seal_records(&mut book, 1..=count);
        assert!(book
            .lane()
            .unwrap()
            .drain(std::time::Duration::from_secs(5)));
        Arc::new(Mutex::new(book))
    }

    fn page(view: &NodeAudit, from: u64, to: u64, cursor: Option<&str>) -> Value {
        serde_json::from_slice(&view.range_page(from, to, cursor).unwrap()).unwrap()
    }

    #[test]
    fn audit_range_pages_reconstruct_pinned_range_during_concurrent_appends() {
        let slots = RecordSlots::new();
        let count = AUDIT_RING as u64 + 200;
        let book = book(&slots, count);
        let view = NodeAudit::new(Arc::clone(&book));
        let scans = Arc::new(AtomicUsize::new(0));
        let appended = Arc::new(AtomicBool::new(false));
        let (observed, flag, held) = (
            Arc::clone(&scans),
            Arc::clone(&appended),
            Arc::downgrade(&book),
        );
        slots.on_scan(move || {
            observed.fetch_add(1, Ordering::Relaxed);
            let book = held.upgrade().unwrap();
            let mut book = book
                .try_lock()
                .expect("Store scans run outside durability lock");
            if !flag.swap(true, Ordering::SeqCst) {
                seal_records(&mut book, (count + 1)..=(count + 1));
            }
        });
        let mut cursor = None;
        let mut positions = Vec::new();
        let mut pages = 0;
        loop {
            let before = scans.load(Ordering::Relaxed);
            let body = page(&view, 1, count, cursor.as_deref());
            assert!(scans.load(Ordering::Relaxed) - before <= SCAN_POSITIONS as usize);
            assert_eq!(body["snapshot_to"], count.to_string());
            assert_eq!(body["incomplete"], false);
            for record in body["records"].as_array().unwrap() {
                positions.push(record["seq"].as_str().unwrap().parse::<u64>().unwrap());
            }
            pages += 1;
            cursor = body["next_cursor"].as_str().map(str::to_string);
            if cursor.is_none() {
                assert_eq!(body["complete"], true);
                break;
            }
            assert_eq!(body["complete"], false);
            assert!(pages < 100, "bounded progress even under writes");
        }
        assert!(appended.load(Ordering::SeqCst));
        assert!(pages > 1);
        assert_eq!(positions, (1..=count).collect::<Vec<_>>());
        slots.on_scan(|| {});
    }

    #[test]
    fn audit_range_reports_actual_bounds_gaps_and_unsealed_tail() {
        let slots = RecordSlots::new();
        let book = book(&slots, 5);
        book.lock().unwrap().audit_records.retain(|r| r.seq != 3);
        let view = NodeAudit::new(book);
        let body = page(&view, 1, 7, None);
        assert_eq!(body["returned_from"], "1");
        assert_eq!(body["returned_to"], "5");
        assert_eq!(body["snapshot_to"], "5");
        assert_eq!(
            body["gaps"],
            json!([{"from":"3", "to":"3"}, {"from":"6", "to":"7"}])
        );
        assert_eq!(body["complete"], false);
        assert_eq!(body["incomplete"], true);
        assert!(body["next_cursor"].is_null());
        assert_eq!(body["retention"]["ring_from"], "1");
        assert_eq!(body["retention"]["durable_from_known"], false);
    }

    #[test]
    fn audit_range_continues_empty_scan_pages_and_rejects_changed_scope() {
        let slots = RecordSlots::new();
        let book = book(&slots, AUDIT_RING as u64 + 200);
        let view = NodeAudit::new(Arc::clone(&book));
        // First 64 journal positions precede the requested audit range.
        let body = page(&view, 100, 150, None);
        assert!(body["records"].as_array().unwrap().is_empty());
        assert!(body["returned_from"].is_null());
        assert_eq!(body["truncated"], true);
        assert_eq!(body["complete"], false);
        let cursor = body["next_cursor"].as_str().unwrap();
        assert!(matches!(
            view.range_page(101, 150, Some(cursor)),
            Err(GovernanceError::Validation)
        ));
        book.lock().unwrap().incarnation += 1;
        assert!(matches!(
            view.range_page(100, 150, Some(cursor)),
            Err(GovernanceError::Validation)
        ));
        assert!(matches!(
            view.range_page(100, 150, Some("6f3a31")),
            Err(GovernanceError::Validation)
        ));
    }

    #[test]
    fn audit_range_retention_loss_between_pages_is_explicit() {
        let slots = RecordSlots::new();
        let book = book(&slots, AUDIT_RING as u64 + 200);
        let view = NodeAudit::new(Arc::clone(&book));
        let first = page(&view, 1, 1200, None);
        assert_eq!(first["incomplete"], false);
        let mut cursor = first["next_cursor"].as_str().map(str::to_string);
        // Change the live retained set after the first page. The later ring page
        // must expose this missing position, even though the initial capture saw it.
        book.lock().unwrap().audit_records.retain(|r| r.seq != 300);
        let mut gap_seen = false;
        for _ in 0..100 {
            let body = page(&view, 1, 1200, cursor.as_deref());
            gap_seen |= body["gaps"]
                .as_array()
                .unwrap()
                .iter()
                .any(|gap| gap == &json!({"from": "300", "to": "300"}));
            cursor = body["next_cursor"].as_str().map(str::to_string);
            if cursor.is_none() {
                assert!(gap_seen);
                assert_eq!(body["incomplete"], true);
                assert_eq!(body["complete"], false);
                return;
            }
        }
        panic!("the fixed upper bound must terminate");
    }
}
