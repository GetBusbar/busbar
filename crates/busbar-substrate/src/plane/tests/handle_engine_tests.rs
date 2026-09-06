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
    /// When set, every append fails -- the durable half of a submit that lands its row and then
    /// cannot open its chain.
    append_fails: std::sync::atomic::AtomicBool,
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
        if self.append_fails.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(busbar_api::StoreError("the append did not land".into()));
        }
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
    fn delete_plane_record(&self, kind: &str, id: &str) -> StoreResult<()> {
        self.rows
            .lock()
            .unwrap()
            .retain(|r| !(r.kind == kind && r.id == id));
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
    submit_demo_bounded(engine, row, now, bounds(), demo_abandon);
}

/// `submit_demo` with the sweep bounds and the abandon callback supplied — the retention tests need
/// to vary the ceilings and to COUNT how many times a handle is actually handed to abandon.
fn submit_demo_bounded<A>(
    engine: &DurableHandleEngine,
    row: DemoRow,
    now: u64,
    bounds: SweepBounds,
    abandon: A,
) where
    A: Fn(&str, &(dyn std::any::Any + Send + Sync), &ChainPosition, u64) -> Option<Mutation>,
{
    engine
        .submit(
            now,
            bounds,
            |_pos| {
                let record = row.record();
                let meta = row.meta();
                Ok(SubmitRecord {
                    id: row.id.clone(),
                    row: row.clone().arc(),
                    meta,
                    row_record: record.clone(),
                    event: Some(SealedEvent {
                        record,
                        tail_hash: format!("h-{}", row.id),
                    }),
                })
            },
            abandon,
            no_report,
        )
        .expect("submit");
}

/// THE SWEEP IS AMORTISED OVER SUBMITS, AND SKIPPING ONE CHANGES NOTHING BUT WHEN.
///
/// The sweep runs from a submit whose `now` has advanced past the last swept second — every bound the
/// sweep enforces is in whole seconds, so a second sweep inside one second cannot reach a different
/// verdict, and paying for it is paying to be told the same thing twice. Two facts:
///
/// - A submit that does NOT trigger the sweep leaves everything except its own insertion alone. The
///   durable store is byte-identical apart from the new handle's own row and event — in particular no
///   abandon write happened — and no resident handle's meta moved.
/// - The NEXT triggering submit reaches exactly the state a per-submit sweep would have been at by
///   then. Here that is `{a2, x, y, z}`: the deferred sweep evicts a0 and a1 together at `z` (the set
///   is two over the cap by then), where a per-submit sweep would have evicted a0 at `y` and a1 at
///   `z`. Same survivors, same order, one sweep instead of two.
#[test]
fn a_submit_that_skips_the_sweep_defers_it_without_changing_where_it_lands() {
    let store = Arc::new(MemStore::default());
    let engine = DurableHandleEngine::new();
    engine.set_sink(Arc::clone(&store) as Arc<dyn PlaneStore>);
    let live = |id: &str, at: u64| DemoRow {
        id: id.to_string(),
        owner: "o".into(),
        updated_at: at,
        terminal: false,
        cursor: 0,
    };
    let resident = |engine: &DurableHandleEngine| {
        let mut ids: Vec<String> = ["a0", "a1", "a2", "x", "y", "z"]
            .iter()
            .filter(|id| engine.get_unscoped(id).is_some())
            .map(|id| (*id).to_string())
            .collect();
        ids.sort();
        ids
    };

    // Three active handles at now=5, then a submit at now=200 whose sweep abandons all three. The
    // set is at the cap (4) and nothing is evicted yet.
    for i in 0..3u64 {
        submit_demo(&engine, live(&format!("a{i}"), 5), 5);
    }
    submit_demo(&engine, live("x", 200), 200);
    assert_eq!(resident(&engine), ["a0", "a1", "a2", "x"]);
    for i in 0..3u64 {
        let meta = engine.meta(&format!("a{i}")).expect("resident");
        assert!(meta.terminal && meta.updated_at == 200, "abandoned at now");
    }

    // A second submit in the SAME second. Its sweep is skipped, so the working set is allowed over
    // the cap and the durable store gains nothing but the new handle's own row and event.
    let rows_before = store.rows.lock().unwrap().clone();
    let events_before = store.events.lock().unwrap().clone();
    let metas_before: Vec<HandleMeta> = (0..3u64)
        .map(|i| engine.meta(&format!("a{i}")).expect("resident"))
        .collect();
    submit_demo(&engine, live("y", 200), 200);
    let rows_after = store.rows.lock().unwrap().clone();
    let events_after = store.events.lock().unwrap().clone();
    let y = live("y", 200).record();
    assert_eq!(
        rows_after,
        [rows_before, vec![y.clone()]].concat(),
        "a skipped sweep wrote nothing durable but the new handle's own row"
    );
    assert_eq!(
        events_after,
        [events_before, vec![y]].concat(),
        "a skipped sweep appended nothing but the new handle's own genesis event"
    );
    let metas_now: Vec<HandleMeta> = (0..3u64)
        .map(|i| engine.meta(&format!("a{i}")).expect("resident"))
        .collect();
    assert_eq!(metas_now, metas_before, "a skipped sweep moved no handle");
    assert_eq!(resident(&engine), ["a0", "a1", "a2", "x", "y"]);
    assert_eq!(engine.len(), 5, "the deferred cap is over its ceiling");

    // The next second's submit triggers the deferred sweep, and it lands where a per-submit sweep
    // would have been by now: the two oldest terminal handles go, oldest first by (updated_at, id).
    submit_demo(&engine, live("z", 201), 201);
    assert_eq!(
        resident(&engine),
        ["a2", "x", "y", "z"],
        "the deferred sweep evicted a0 and a1 — the same survivors a per-submit sweep leaves"
    );
    assert_eq!(engine.len(), 4, "the sweep brought the set back to the cap");
}

/// WHAT A SUBMIT COSTS ON A BIG WORKING SET — measured, not asserted. Ten thousand ACTIVE handles
/// against a cap of ten thousand is the exact shape the design note calls the cliff: the cap rule may
/// evict only TERMINAL handles, so it evicts nothing here and the set stays large, and every submit
/// pays whatever the sweep's mechanism costs to rediscover that there is nothing to do. Two hundred
/// submits are timed over twenty distinct `now` seconds (ten per second) so the AMORTISED trigger's
/// effect is in the number too. NO WALL-CLOCK BUDGET IS ASSERTED — a timing assertion is a flake on
/// somebody else's busy machine; the number is printed for the record (`--nocapture`) and only the
/// working-set invariants are asserted.
#[test]
fn what_a_submit_costs_on_a_ten_thousand_handle_working_set() {
    use std::time::Instant;

    const RESIDENT: u64 = 10_000;
    const SUBMITS: u64 = 200;
    let wide = SweepBounds {
        abandon_secs: 100,
        terminal_ttl_secs: 50,
        max_retained: RESIDENT as usize,
    };

    // Install the resident set through the boot rehydrate, which does NOT sweep — so the setup cost
    // is not itself the quantity under measurement.
    let rows: Vec<PlaneRecord> = (0..RESIDENT)
        .map(|i| {
            DemoRow {
                id: format!("r{i:05}"),
                owner: "o".into(),
                updated_at: 1_000,
                terminal: false,
                cursor: 0,
            }
            .record()
        })
        .collect();
    let store = MemStore {
        append_fails: std::sync::atomic::AtomicBool::new(false),
        rows: Mutex::new(rows),
        events: Mutex::new(Vec::new()),
    };
    let engine = DurableHandleEngine::new();
    let counts = engine
        .rehydrate(&store, "demo", |_store, body| {
            let row = DemoRow::from_body(body).expect("a seeded row decodes");
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
    assert_eq!(counts.active, RESIDENT as usize);

    let started = Instant::now();
    for i in 0..SUBMITS {
        // Fresh handles at a `now` that leaves the resident set inside `abandon_secs`, so no rule
        // fires and what is measured is the sweep's cost to decide exactly that.
        let now = 1_020 + i / 10;
        submit_demo_bounded(
            &engine,
            DemoRow {
                id: format!("n{i:05}"),
                owner: "o".into(),
                updated_at: now,
                terminal: false,
                cursor: 0,
            },
            now,
            wide,
            demo_abandon,
        );
    }
    let elapsed = started.elapsed();
    println!(
        "submit cost over a {RESIDENT}-handle working set: {SUBMITS} submits in {elapsed:?} \
         ({:?} per submit)",
        elapsed / u32::try_from(SUBMITS).expect("submit count fits a u32")
    );

    // The only assertions are the invariants: nothing was abandoned (nothing was idle), nothing was
    // evicted (nothing was terminal), and every submitted handle is resident.
    assert_eq!(engine.len(), (RESIDENT + SUBMITS) as usize);
    assert!(!engine.meta("r00000").expect("resident").terminal);
    assert!(engine
        .get_unscoped(&format!("n{:05}", SUBMITS - 1))
        .is_some());
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
    let denied =
        |owner: &str, id: &str| matches!(engine.scoped_get(owner, id), Err(HandleDenied::NotYours));
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
    // An ACTIVE handle OLDER than every terminal one. This is the row the rule is actually about: a
    // sweep that evicted by age alone would take this one first, dropping a caller's in-flight work
    // to make room, and it must survive precisely because it is not settled.
    submit_demo(
        &engine,
        DemoRow {
            id: "elder-live".into(),
            owner: "o".into(),
            updated_at: 1,
            terminal: false,
            cursor: 0,
        },
        1,
    );
    // Three terminal (settled) handles at increasing ages, all NEWER than the active one — the cap
    // is 4, so the fifth submit sweeps the oldest TERMINAL and nothing else.
    for i in 0..3u64 {
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
    // A fifth submit at now=20 — within the terminal TTL of every settled row and within the
    // abandon ceiling of the elder active one, so the cap is the only thing driving the eviction.
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
    // The exact surviving set: the oldest TERMINAL went and nothing else did. Asserted as a set
    // rather than as a count under the cap, which a sweep that evicted the elder active row — or one
    // that evicted three rows instead of one — would also satisfy.
    for surviving in ["elder-live", "t1", "t2", "live"] {
        assert!(
            engine.get_unscoped(surviving).is_some(),
            "{surviving} was swept and should not have been"
        );
    }
    assert!(
        engine.get_unscoped("t0").is_none(),
        "the oldest terminal handle survived the cap sweep"
    );
    assert_eq!(
        engine.len(),
        4,
        "the sweep evicted a different number of handles than the one the cap called for"
    );
}

/// THE SWEEP'S OBSERVABLE OUTCOME, PINNED BEFORE ITS MECHANISM IS CHANGED.
///
/// The sweep is due a redesign — it runs three full passes over the whole working set under the
/// engine's outer lock on EVERY submit, and it does the abandon callback's durable writes while
/// holding that lock (see the module header's lock-discipline note and the design note in
/// `docs/design/`). What that redesign must not change is any of the four facts below, which are
/// the whole of what a caller can see. They are asserted here first so a mechanism change that
/// alters one of them is a red test rather than a behaviour nobody noticed moving.
///
/// (1) An ACTIVE handle is never evicted to make room. `max_retained` is therefore a ceiling on the
///     TERMINAL population, not on the working set: a burst of active handles carries the set past
///     it and the set stays over the ceiling until those handles settle or go idle. This is the
///     designed answer — dropping a live handle would be forgetting work that is still running,
///     which is worse than holding memory — and it is asserted rather than described because the
///     word "hard ceiling" reads like a guarantee the sweep does not make.
/// (2) A handle idle past `abandon_secs` is settled by the plane's abandon callback, not dropped.
/// (3) The TERMINAL handles that survive the cap are the NEWEST ones — eviction is oldest-first by
///     `updated_at`, and it is a total order on that key.
/// (4) Every rule fires from a SUBMIT. Nothing sweeps on read, and nothing sweeps on a timer.
#[test]
fn the_sweep_keeps_every_active_handle_and_evicts_terminal_ones_oldest_first() {
    // (1) Ten ACTIVE handles, all fresh at the same instant, against a cap of four. None is
    // terminal, so rules (1) and (2) of the sweep have nothing to evict, and none is idle, so the
    // abandon rule does not fire either. Every one of the ten survives.
    let engine = DurableHandleEngine::new();
    for i in 0..10u64 {
        submit_demo(
            &engine,
            DemoRow {
                id: format!("a{i}"),
                owner: "o".into(),
                updated_at: 5,
                terminal: false,
                cursor: 0,
            },
            5,
        );
    }
    assert_eq!(
        engine.len(),
        10,
        "an active handle is never evicted to make room, so the set is over `max_retained` (4)"
    );
    for i in 0..10u64 {
        assert!(
            engine.get_unscoped(&format!("a{i}")).is_some(),
            "a{i} was evicted while active"
        );
        assert!(!engine.meta(&format!("a{i}")).unwrap().terminal);
    }

    // (2) One more submit, far enough past `abandon_secs` (100) that all ten are idle. The three
    // rules run IN ORDER inside one sweep, and the order is the whole of the outcome: the abandon
    // rule settles all ten first, which makes all ten TERMINAL, which is what then makes them
    // eligible for the cap rule in the SAME pass. So a handle is abandoned and evicted in one
    // sweep, and the seven the cap drops are the seven oldest under the sort key — every one of
    // them now carries the sweep's own `now`, so the tie is broken by the id. THIS IS THE FACT MOST
    // AT RISK from a mechanism change: a time-ordered index that abandoned in insertion order, or
    // that ran the cap before the abandon rule, would evict a different seven and be just as
    // defensible in isolation.
    submit_demo(
        &engine,
        DemoRow {
            id: "trigger".into(),
            owner: "o".into(),
            updated_at: 500,
            terminal: false,
            cursor: 0,
        },
        500,
    );
    let survives: Vec<u64> = (0..10u64)
        .filter(|i| engine.get_unscoped(&format!("a{i}")).is_some())
        .collect();
    assert_eq!(
        survives,
        vec![7, 8, 9],
        "the abandon rule settled all ten and the cap rule then dropped the seven oldest by \
         (updated_at, id) in the same sweep"
    );
    for i in survives {
        let id = format!("a{i}");
        let meta = engine.meta(&id).expect("a survivor is readable");
        assert!(meta.terminal, "{id} was left active past the abandon age");
        assert_eq!(meta.updated_at, 500, "{id} was stamped at the sweep's now");
    }
    assert_eq!(engine.len(), 4, "the sweep brought the set back to the cap");

    // (3) A second engine, five TERMINAL handles at distinct ages against the cap of four, and one
    // more submit inside the terminal TTL to drive the cap rule. The eviction is oldest-first on
    // `updated_at`: the two oldest go, every newer one stays, and the ordering is the whole of what
    // "oldest first" means — it is not a set property and a redesign could get the set right and
    // the order wrong.
    let engine = DurableHandleEngine::new();
    for i in 0..5u64 {
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
    let survives: Vec<u64> = (0..5u64)
        .filter(|i| engine.get_unscoped(&format!("t{i}")).is_some())
        .collect();
    assert_eq!(
        survives,
        vec![2, 3, 4],
        "the cap evicts the oldest terminal handles first and keeps the newest"
    );
    assert!(engine.get_unscoped("live").is_some());

    // (4) A READ sweeps nothing. The working set is unchanged after reading every id at a `now` far
    // past every age bound, because no read path takes a `now` at all.
    let before = engine.len();
    for i in 0..5u64 {
        let _ = engine.get_unscoped(&format!("t{i}"));
    }
    let _ = engine.get_unscoped("live");
    assert_eq!(before, engine.len(), "a read changed the working set");
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

#[test]
fn two_different_handles_mutate_concurrently_without_serializing_on_each_other() {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    // Two independent handles. Under the old single-global-lock shape, one handle's mutate held the
    // whole engine's lock across its store round-trip, so a second handle's mutate could not run until
    // the first returned. With the per-handle shard, a mutate holds only its OWN handle's inner lock,
    // so a different handle proceeds freely. This test parks handle "a"'s mutate INSIDE its plan (its
    // inner lock held) and proves handle "b"'s mutate runs to completion meanwhile — which is only
    // possible if the outer map lock was released before "a" took its inner lock.
    let engine = Arc::new(DurableHandleEngine::new());
    submit_demo(
        &engine,
        DemoRow {
            id: "a".into(),
            owner: "o".into(),
            updated_at: 1,
            terminal: false,
            cursor: 0,
        },
        1,
    );
    submit_demo(
        &engine,
        DemoRow {
            id: "b".into(),
            owner: "o".into(),
            updated_at: 1,
            terminal: false,
            cursor: 0,
        },
        1,
    );

    let (a_entered_tx, a_entered_rx) = mpsc::channel::<()>();
    let (release_a_tx, release_a_rx) = mpsc::channel::<()>();
    let (b_done_tx, b_done_rx) = mpsc::channel::<()>();

    // Thread 1: mutate "a", but block INSIDE the plan (holding "a"'s inner lock) until released.
    let e1 = Arc::clone(&engine);
    let t1 = thread::spawn(move || {
        e1.mutate("a", |row, _pos| {
            a_entered_tx.send(()).unwrap();
            release_a_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("a's plan is released after b completes");
            let row = row.downcast_ref::<DemoRow>().unwrap();
            let mut next = row.clone();
            next.cursor = 1;
            let record = next.record();
            let meta = next.meta();
            Ok(Some(Mutation {
                row: Some(next.arc()),
                meta: Some(meta),
                row_record: Some(record),
                event: None,
            }))
        })
        .expect("mutate a");
    });

    // Wait until "a"'s plan is running — its inner lock is now held.
    a_entered_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("a entered its plan");

    // Thread 2: mutate "b". This MUST complete while "a" is still parked, or the engine serialized.
    let e2 = Arc::clone(&engine);
    let t2 = thread::spawn(move || {
        e2.mutate("b", |row, _pos| {
            let row = row.downcast_ref::<DemoRow>().unwrap();
            let mut next = row.clone();
            next.cursor = 2;
            let record = next.record();
            let meta = next.meta();
            Ok(Some(Mutation {
                row: Some(next.arc()),
                meta: Some(meta),
                row_record: Some(record),
                event: None,
            }))
        })
        .expect("mutate b");
        b_done_tx.send(()).unwrap();
    });

    // The proof: "b" finishes while "a" is still holding its own handle lock inside its plan.
    b_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("b mutated concurrently while a held only its own handle's lock");

    // Now let "a" finish and confirm both writes landed.
    release_a_tx.send(()).unwrap();
    t1.join().unwrap();
    t2.join().unwrap();
    assert_eq!(engine.meta("a").unwrap().cursor, 1);
    assert_eq!(engine.meta("b").unwrap().cursor, 2);
}

/// TWO SUBMITS RACING THE SWEEP. The abandon rule's durable writes run with the OUTER lock released,
/// so two submits can be inside the sweep at once and both can see the same idle handle as a
/// candidate. What must hold either way: a handle is handed to the abandon callback AT MOST ONCE (the
/// re-read under the handle's own inner lock is what makes the second racer see an already-settled
/// handle and stand down), and no handle is lost — every pre-existing handle and every submitted one
/// is in the working set at the end.
#[test]
fn two_submits_racing_the_sweep_neither_double_abandon_nor_lose_a_handle() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    // Ceilings wide enough that NOTHING is evicted: the only rule that may fire is abandon, so a
    // missing handle at the end is a lost handle and not a retention decision.
    let wide = SweepBounds {
        abandon_secs: 100,
        terminal_ttl_secs: 1_000_000,
        max_retained: usize::MAX,
    };
    let calls = Arc::new(AtomicUsize::new(0));
    let counting = {
        let calls = Arc::clone(&calls);
        move |id: &str, row: &(dyn std::any::Any + Send + Sync), pos: &ChainPosition, now: u64| {
            calls.fetch_add(1, Ordering::SeqCst);
            demo_abandon(id, row, pos, now)
        }
    };

    // Eight ACTIVE handles at now=0, all of them idle past `abandon_secs` by the time the racers run.
    let engine = Arc::new(DurableHandleEngine::new());
    for i in 0..8u64 {
        submit_demo_bounded(
            &engine,
            DemoRow {
                id: format!("idle{i}"),
                owner: "o".into(),
                updated_at: 0,
                terminal: false,
                cursor: 0,
            },
            0,
            wide,
            &counting,
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0, "nothing was idle yet");

    // Two threads, eight submits each, every one of them at a `now` far past the abandon age — so
    // every submit's sweep sees the same eight idle handles as candidates.
    let threads: Vec<_> = (0..2u64)
        .map(|t| {
            let engine = Arc::clone(&engine);
            let counting = counting.clone();
            thread::spawn(move || {
                for k in 0..8u64 {
                    let now = 1_000 + k;
                    submit_demo_bounded(
                        &engine,
                        DemoRow {
                            id: format!("s{t}-{k}"),
                            owner: "o".into(),
                            updated_at: now,
                            terminal: false,
                            cursor: 0,
                        },
                        now,
                        wide,
                        &counting,
                    );
                }
            })
        })
        .collect();
    for t in threads {
        t.join().expect("a racing submitter panicked");
    }

    assert_eq!(
        calls.load(Ordering::SeqCst),
        8,
        "each idle handle was handed to abandon exactly once across both racers"
    );
    for i in 0..8u64 {
        let id = format!("idle{i}");
        let meta = engine
            .meta(&id)
            .expect("an abandoned handle stays resident");
        assert!(meta.terminal, "{id} was left active past the abandon age");
    }
    for t in 0..2u64 {
        for k in 0..8u64 {
            let id = format!("s{t}-{k}");
            assert!(engine.get_unscoped(&id).is_some(), "{id} was lost");
        }
    }
    assert_eq!(engine.len(), 24, "no handle was lost and none was evicted");
}

#[test]
fn scoped_mutate_owner_gates_the_write_with_one_indistinguishable_refusal() {
    use std::cell::Cell;

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

    // A plan that would bump the cursor to 9 — and RECORDS (into `plan_ran`) whether it was ever
    // invoked, so we can prove an unauthorized scoped_mutate refuses BEFORE running the plan (no side
    // channel). The plan closure borrows `plan_ran` by shared reference each call.
    let plan_ran = Cell::new(false);
    macro_rules! bump {
        () => {
            |row: &(dyn std::any::Any + Send + Sync), _pos: &ChainPosition| {
                plan_ran.set(true);
                let row = row.downcast_ref::<DemoRow>().unwrap();
                let mut next = row.clone();
                next.cursor = 9;
                let record = next.record();
                let meta = next.meta();
                Ok(Some(Mutation {
                    row: Some(next.arc()),
                    meta: Some(meta),
                    row_record: Some(record),
                    event: None,
                }))
            }
        };
    }

    // A foreign owner, a missing id, and an empty owner all refuse identically — and the plan never
    // runs, so the refusal cannot leak whether the handle exists.
    plan_ran.set(false);
    assert!(matches!(
        engine.scoped_mutate("bob", "a", bump!()),
        Err(ScopedMutateError::NotYours)
    ));
    assert!(
        !plan_ran.get(),
        "a foreign owner is refused before the plan runs"
    );

    plan_ran.set(false);
    assert!(matches!(
        engine.scoped_mutate("alice", "nope", bump!()),
        Err(ScopedMutateError::NotYours)
    ));
    assert!(
        !plan_ran.get(),
        "a missing id is refused before the plan runs"
    );

    plan_ran.set(false);
    assert!(matches!(
        engine.scoped_mutate("", "a", bump!()),
        Err(ScopedMutateError::NotYours)
    ));
    assert!(
        !plan_ran.get(),
        "an empty owner is refused before the plan runs"
    );

    // The refused writes left the row untouched.
    assert_eq!(engine.meta("a").unwrap().cursor, 0);

    // The rightful owner's scoped_mutate runs the plan and applies the write.
    plan_ran.set(false);
    let out = engine
        .scoped_mutate("alice", "a", bump!())
        .expect("the owner's scoped_mutate succeeds");
    assert!(plan_ran.get(), "the owner's plan runs");
    assert_eq!(out.downcast_ref::<DemoRow>().unwrap().cursor, 9);
    assert_eq!(engine.meta("a").unwrap().cursor, 9);
}

/// A SUBMIT WHOSE CHAIN NEVER OPENED LEAVES NOTHING BEHIND.
///
/// The row and the genesis event are two writes, not one transaction. When the second fails the
/// caller is told the submit failed -- but the row was already durable, and a row with no chain is
/// rehydrated ACTIVE at the next boot: a handle nobody was ever told about, holding a working-set
/// slot and answering reads, whose provenance starts at an event that does not exist. The row is
/// taken back with the failure.
#[test]
fn a_submit_whose_genesis_append_fails_leaves_no_durable_row() {
    let store = Arc::new(MemStore::default());
    let engine = DurableHandleEngine::new();
    engine.set_sink(store.clone() as Arc<dyn PlaneStore>);
    store
        .append_fails
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let row = DemoRow {
        id: "orphan".into(),
        owner: "alice".into(),
        updated_at: 1,
        terminal: false,
        cursor: 0,
    };
    let outcome = engine.submit(
        1,
        bounds(),
        |_pos| {
            let record = row.record();
            let meta = row.meta();
            Ok(SubmitRecord {
                id: row.id.clone(),
                row: row.clone().arc(),
                meta,
                row_record: record.clone(),
                event: Some(SealedEvent {
                    record,
                    tail_hash: "h-orphan".to_string(),
                }),
            })
        },
        demo_abandon,
        no_report,
    );
    assert!(
        matches!(outcome, Err(HandleEngineError::Store(_))),
        "the caller is told the submit did not land"
    );
    assert!(
        engine.meta("orphan").is_none(),
        "no working-set slot is taken"
    );
    assert!(
        store.rows.lock().unwrap().is_empty(),
        "the row was taken back with the failure that followed it"
    );

    // The proof that matters is the one a restart would give: a boot rehydrate finds nothing to
    // resume, so the handle nobody accepted never becomes active.
    let counts = engine
        .rehydrate(store.as_ref(), "demo", |_store, body| {
            let Some(row) = DemoRow::from_body(body) else {
                return Ok(RehydrateOutcome::Unreadable);
            };
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
    assert_eq!(counts.active, 0, "a boot resumes no orphan");
}
