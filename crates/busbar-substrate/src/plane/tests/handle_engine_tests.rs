// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral durable-handle engine, proven in isolation over a DEMO opaque row — no plane crate,
//! no plane noun. Exercises the mechanics the engine owns: the scoped anti-enumeration read, the
//! monotonic-cursor no-op-vs-advance, the retention cap sweep, and the boot rehydrate's counts.

use super::*;
use busbar_api::{PlaneDisposition, PlaneRecord, PlaneSelector, StoreResult};
use std::sync::{Arc, Mutex};

/// A stand-in plane row: the engine holds it opaquely and never names it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DemoRow {
    id: String,
    owner: String,
    updated_at: u64,
    terminal: bool,
    cursor: u64,
}

impl DemoRow {
    fn record(&self) -> PlaneRecord {
        PlaneRecord {
            kind: "demo".to_string(),
            id: self.id.clone(),
            parent: None,
            seq: 0,
            ts: self.updated_at,
            disposition: if self.terminal {
                PlaneDisposition::Terminal
            } else {
                PlaneDisposition::Active
            },
            body: serde_json::to_vec(&(
                &self.id,
                &self.owner,
                self.updated_at,
                self.terminal,
                self.cursor,
            ))
            .unwrap(),
        }
    }
    fn from_body(body: &[u8]) -> Option<Self> {
        let (id, owner, updated_at, terminal, cursor): (String, String, u64, bool, u64) =
            serde_json::from_slice(body).ok()?;
        Some(DemoRow {
            id,
            owner,
            updated_at,
            terminal,
            cursor,
        })
    }
    fn meta(&self) -> HandleMeta {
        HandleMeta {
            owner: self.owner.clone(),
            updated_at: self.updated_at,
            terminal: self.terminal,
            cursor: self.cursor,
        }
    }
    fn arc(self) -> Arc<dyn std::any::Any + Send + Sync> {
        Arc::new(self)
    }
}

/// A minimal in-memory `PlaneStore` — the durable sink stand-in.
#[derive(Default)]
struct MemStore {
    rows: Mutex<Vec<PlaneRecord>>,
    events: Mutex<Vec<PlaneRecord>>,
}

impl PlaneStore for MemStore {
    fn upsert_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        let mut rows = self.rows.lock().unwrap();
        if let Some(existing) = rows.iter_mut().find(|r| r.id == record.id) {
            *existing = record.clone();
        } else {
            rows.push(record.clone());
        }
        Ok(())
    }
    fn get_plane_record(&self, _kind: &str, id: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.body.clone()))
    }
    fn append_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        self.events.lock().unwrap().push(record.clone());
        Ok(())
    }
    fn list_plane_records(
        &self,
        _kind: &str,
        selector: &PlaneSelector,
    ) -> StoreResult<Vec<Vec<u8>>> {
        match selector {
            PlaneSelector::All => Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .map(|r| r.body.clone())
                .collect()),
            PlaneSelector::Parent(p) => {
                let mut evs: Vec<PlaneRecord> = self
                    .events
                    .lock()
                    .unwrap()
                    .iter()
                    .filter(|r| r.parent.as_deref() == Some(p.as_str()))
                    .cloned()
                    .collect();
                evs.sort_by_key(|r| r.seq);
                Ok(evs.into_iter().map(|r| r.body).collect())
            }
        }
    }
    fn list_plane_record_parents(&self, _kind: &str) -> StoreResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn purge_plane_records_before(&self, _kind: &str, before: u64) -> StoreResult<u64> {
        let mut rows = self.rows.lock().unwrap();
        let before_count = rows.len();
        rows.retain(|r| !(r.disposition == PlaneDisposition::Terminal && r.ts < before));
        Ok((before_count - rows.len()) as u64)
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> StoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> StoreResult<bool> {
        Ok(true)
    }
}

/// The abandon/report closures the sweep takes — the DEMO plane cancels an idle handle.
fn demo_abandon(
    _id: &str,
    row: &(dyn std::any::Any + Send + Sync),
    _pos: &ChainPosition,
    now: u64,
) -> Option<Mutation> {
    let row = row.downcast_ref::<DemoRow>()?;
    let mut next = row.clone();
    next.terminal = true;
    next.updated_at = now;
    let record = next.record();
    let meta = next.meta();
    Some(Mutation {
        row: Some(next.arc()),
        meta: Some(meta),
        row_record: Some(record),
        event: None,
    })
}

fn no_report(_id: &str, _e: &busbar_api::StoreError) {}

fn bounds() -> SweepBounds {
    SweepBounds {
        abandon_secs: 100,
        terminal_ttl_secs: 50,
        max_retained: 4,
    }
}

fn submit_demo(engine: &DurableHandleEngine, row: DemoRow, now: u64) {
    engine
        .submit(
            now,
            bounds(),
            |_pos| {
                let record = row.record();
                let meta = row.meta();
                Ok(SubmitRecord {
                    id: row.id.clone(),
                    row: row.clone().arc(),
                    meta,
                    row_record: record.clone(),
                    event: SealedEvent {
                        record,
                        tail_hash: format!("h-{}", row.id),
                    },
                })
            },
            demo_abandon,
            no_report,
        )
        .expect("submit");
}

#[test]
fn a_foreign_or_missing_id_is_one_indistinguishable_denial() {
    let engine = DurableHandleEngine::new();
    submit_demo(
        &engine,
        DemoRow {
            id: "a".into(),
            owner: "alice".into(),
            updated_at: 1,
            terminal: false,
            cursor: 0,
        },
        1,
    );
    // alice reads her own handle
    let got = engine.scoped_get("alice", "a").expect("alice sees hers");
    assert_eq!(got.downcast_ref::<DemoRow>().unwrap().owner, "alice");
    // a foreign owner and a missing id both deny identically
    let denied = |owner: &str, id: &str| {
        matches!(
            engine.scoped_get(owner, id),
            Err(HandleDenied::NotYours)
        )
    };
    assert!(denied("bob", "a"), "a foreign owner is denied");
    assert!(denied("alice", "nope"), "a missing id is denied");
    assert!(denied("", "a"), "an empty owner sees nothing");
}

#[test]
fn the_cursor_advances_monotonically_and_a_regress_is_a_no_op() {
    let engine = DurableHandleEngine::new();
    submit_demo(
        &engine,
        DemoRow {
            id: "a".into(),
            owner: "alice".into(),
            updated_at: 1,
            terminal: false,
            cursor: 5,
        },
        1,
    );
    let advance = |to: u64| {
        engine
            .mutate("a", |row, _pos| {
                let row = row.downcast_ref::<DemoRow>().unwrap();
                if to <= row.cursor {
                    return Ok(None);
                }
                let mut next = row.clone();
                next.cursor = to;
                let record = next.record();
                let meta = next.meta();
                Ok(Some(Mutation {
                    row: Some(next.arc()),
                    meta: Some(meta),
                    row_record: Some(record),
                    event: None,
                }))
            })
            .expect("mutate")
    };
    let r = advance(3); // regress: no-op, current row returned
    assert_eq!(r.downcast_ref::<DemoRow>().unwrap().cursor, 5);
    let r = advance(9);
    assert_eq!(r.downcast_ref::<DemoRow>().unwrap().cursor, 9);
    assert_eq!(engine.meta("a").unwrap().cursor, 9);
}

#[test]
fn the_cap_sweep_evicts_oldest_terminal_first_and_never_an_active() {
    let engine = DurableHandleEngine::new();
    // Four terminal (settled) handles at increasing ages, then one active — the cap is 4, so the
    // fifth submit sweeps the oldest TERMINAL, never the active ones.
    for i in 0..4u64 {
        submit_demo(
            &engine,
            DemoRow {
                id: format!("t{i}"),
                owner: "o".into(),
                updated_at: 10 + i,
                terminal: true,
                cursor: 0,
            },
            10 + i,
        );
    }
    assert_eq!(engine.len(), 4);
    // A fifth submit at now=20 (well within TTL of the terminal rows) drives the cap sweep.
    submit_demo(
        &engine,
        DemoRow {
            id: "live".into(),
            owner: "o".into(),
            updated_at: 20,
            terminal: false,
            cursor: 0,
        },
        20,
    );
    // Oldest terminal (t0) evicted; the new live handle is present.
    assert!(engine.get_unscoped("t0").is_none());
    assert!(engine.get_unscoped("live").is_some());
    assert!(engine.len() <= 4);
}

#[test]
fn an_idle_active_handle_is_abandoned_by_the_next_sweep() {
    let engine = DurableHandleEngine::new();
    submit_demo(
        &engine,
        DemoRow {
            id: "idle".into(),
            owner: "o".into(),
            updated_at: 0,
            terminal: false,
            cursor: 0,
        },
        0,
    );
    // A later submit at now past the abandon ceiling transitions the idle handle to terminal.
    submit_demo(
        &engine,
        DemoRow {
            id: "fresh".into(),
            owner: "o".into(),
            updated_at: 1000,
            terminal: false,
            cursor: 0,
        },
        1000,
    );
    assert!(
        engine.meta("idle").unwrap().terminal,
        "the idle handle was settled by the abandon rule"
    );
}

#[test]
fn a_boot_rehydrate_counts_active_terminal_and_unreadable() {
    let store = Arc::new(MemStore::default());
    // Seed the store directly: one active, one terminal, one undecodable row.
    store
        .upsert_plane_record(
            &DemoRow {
                id: "act".into(),
                owner: "o".into(),
                updated_at: 5,
                terminal: false,
                cursor: 0,
            }
            .record(),
        )
        .unwrap();
    store
        .upsert_plane_record(
            &DemoRow {
                id: "done".into(),
                owner: "o".into(),
                updated_at: 5,
                terminal: true,
                cursor: 0,
            }
            .record(),
        )
        .unwrap();
    store
        .upsert_plane_record(&PlaneRecord {
            kind: "demo".into(),
            id: "junk".into(),
            parent: None,
            seq: 0,
            ts: 5,
            disposition: PlaneDisposition::Active,
            body: b"not json".to_vec(),
        })
        .unwrap();

    let engine = DurableHandleEngine::new();
    let counts = engine
        .rehydrate(store.as_ref(), "demo", |_store, body| {
            let Some(row) = DemoRow::from_body(body) else {
                return Ok(RehydrateOutcome::Unreadable);
            };
            if row.terminal {
                return Ok(RehydrateOutcome::Terminal);
            }
            let meta = row.meta();
            Ok(RehydrateOutcome::Active {
                id: row.id.clone(),
                pos: ChainPosition::genesis(),
                row: row.arc(),
                meta,
                event_unreadable: 0,
            })
        })
        .expect("rehydrate");
    assert_eq!(
        counts,
        RehydrateCounts {
            active: 1,
            terminal: 1,
            unreadable: 1,
        }
    );
    assert!(engine.get_unscoped("act").is_some());
    assert!(engine.get_unscoped("done").is_none());
}
