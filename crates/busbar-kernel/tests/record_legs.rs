// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one runner of `PlaneRecord` legs, held to the architecture's own three-part rule.
//!
//! The rule is short — the schema is declared by the calling plane, the operation is within that
//! schema's declared operations, the body is within the record ceiling — and every cell here is one
//! way of getting past it. A leg that reached the sink with an undeclared schema, an undeclared
//! operation or an oversize body would be a hole in the check rather than a generous reading of it,
//! so each of the three is proved to refuse BEFORE the sink is touched: the sink records every call
//! it receives, and the refusal cells assert it recorded none.

use std::sync::Mutex;

use busbar_contract::dest::{DestinationFacts, Leg};
use busbar_contract::ids::RecordSchemaId;
use busbar_kernel::pump::{
    run_record_leg, run_record_plan, RecordAnswer, RecordKey, RecordRefusal, RecordSchemas,
    RecordStore, MAX_RECORD_BYTES,
};

/// A declared schema with the three verbs the contract names, plus a liveness question.
const ROWS: RecordSchemaId = RecordSchemaId::new("rows");

/// A declared schema that appends and scans and does nothing else, so "the operation is not in THIS
/// schema's table" is a different cell from "the operation is in no table at all".
const EVENTS: RecordSchemaId = RecordSchemaId::new("events");

/// A schema no plane here declares.
const STRANGER: RecordSchemaId = RecordSchemaId::new("stranger");

const OP_GET: &str = "get";
const OP_PUT: &str = "put";
const OP_SCAN: &str = "scan";
const OP_APPEND: &str = "append";
const OP_ASK: &str = "ask";

/// The plane's declaration, as the kernel reads it: two schemas, each with its own table.
struct Declared;

impl RecordSchemas for Declared {
    fn schemas(&self) -> &'static [RecordSchemaId] {
        &[ROWS, EVENTS]
    }

    fn operations_for(&self, schema: RecordSchemaId) -> &'static [&'static str] {
        match schema.as_str() {
            s if s == ROWS.as_str() => &[OP_GET, OP_PUT, OP_SCAN, OP_ASK],
            s if s == EVENTS.as_str() => &[OP_APPEND, OP_SCAN],
            _ => &[],
        }
    }
}

/// A sink that answers each operation and REMEMBERS every call, so a refusal can be proved to have
/// reached nothing rather than merely to have returned an error.
#[derive(Default)]
struct Recording {
    calls: Mutex<Vec<String>>,
    /// What the liveness question answers. `true` unless a cell says otherwise.
    live: Mutex<bool>,
    /// What the sink refuses with, where a cell wants a backend failure.
    refuse: Mutex<Option<String>>,
}

impl Recording {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }
}

impl RecordStore for Recording {
    fn perform(
        &self,
        schema: RecordSchemaId,
        op: &'static str,
        key: &RecordKey<'_>,
        body: &[u8],
    ) -> Result<RecordAnswer, String> {
        self.calls.lock().expect("calls").push(format!(
            "{op} {} {} {}",
            schema.as_str(),
            key.id,
            body.len()
        ));
        if let Some(why) = self.refuse.lock().expect("refuse").clone() {
            return Err(why);
        }
        match op {
            OP_GET => Ok(RecordAnswer {
                body: Some(b"row".to_vec()),
                ..RecordAnswer::default()
            }),
            OP_SCAN => Ok(RecordAnswer {
                bodies: vec![b"one".to_vec(), b"two".to_vec()],
                ..RecordAnswer::default()
            }),
            OP_ASK => Ok(RecordAnswer {
                live: Some(*self.live.lock().expect("live")),
                ..RecordAnswer::default()
            }),
            _ => Ok(RecordAnswer::default()),
        }
    }
}

/// A sink whose liveness answer starts LIVE and whose call log starts empty.
fn sink() -> Recording {
    Recording {
        calls: Mutex::new(Vec::new()),
        live: Mutex::new(true),
        refuse: Mutex::new(None),
    }
}

fn key(id: &str) -> RecordKey<'_> {
    RecordKey {
        id,
        parent: None,
        seq: 0,
        ts: 100,
        expires_at: 200,
        terminal: false,
    }
}

fn leg(schema: RecordSchemaId, op: &'static str) -> Leg {
    Leg {
        destination: DestinationFacts::PlaneRecord { schema, op },
    }
}

/// A put reaches the sink and carries the whole key and body through unchanged.
#[test]
fn a_declared_put_reaches_the_sink() {
    let store = sink();
    let answer = run_record_leg(&store, &Declared, ROWS, OP_PUT, &key("t-1"), b"body")
        .expect("the put is declared");
    assert_eq!(answer, RecordAnswer::default());
    assert_eq!(store.calls(), vec!["put rows t-1 4".to_string()]);
}

/// A get comes back with the body the sink held.
#[test]
fn a_declared_get_returns_the_body() {
    let store = sink();
    let answer = run_record_leg(&store, &Declared, ROWS, OP_GET, &key("t-1"), b"")
        .expect("the get is declared");
    assert_eq!(answer.body, Some(b"row".to_vec()));
    assert_eq!(store.calls(), vec!["get rows t-1 0".to_string()]);
}

/// A scan comes back with every body, in the sink's order.
#[test]
fn a_declared_scan_returns_every_body() {
    let store = sink();
    let answer = run_record_leg(&store, &Declared, EVENTS, OP_SCAN, &key("t-1"), b"")
        .expect("the scan is declared");
    assert_eq!(answer.bodies, vec![b"one".to_vec(), b"two".to_vec()]);
    assert_eq!(store.calls(), vec!["scan events t-1 0".to_string()]);
}

/// An append is a declared operation of the append-only schema, and reaches the sink as one.
#[test]
fn a_declared_append_reaches_the_sink() {
    let store = sink();
    run_record_leg(&store, &Declared, EVENTS, OP_APPEND, &key("t-1"), b"ev")
        .expect("the append is declared");
    assert_eq!(store.calls(), vec!["append events t-1 2".to_string()]);
}

/// A SCHEMA NO PLANE DECLARED is refused, and the sink is never asked.
#[test]
fn an_undeclared_schema_is_refused_before_the_sink() {
    let store = sink();
    let refusal = run_record_leg(&store, &Declared, STRANGER, OP_GET, &key("t-1"), b"")
        .expect_err("no plane declared that schema");
    assert_eq!(
        refusal,
        RecordRefusal::UndeclaredSchema {
            schema: STRANGER.as_str()
        }
    );
    assert!(
        store.calls().is_empty(),
        "the sink must never have been asked"
    );
}

/// AN OPERATION THE SCHEMA DOES NOT DECLARE is refused, even though another schema declares it.
///
/// The distinction is the whole cell: `put` is a real operation of `rows`, and asking the
/// append-only schema for it is still a refusal. A check that read the union of every schema's
/// table would pass this and would be no check at all.
#[test]
fn an_op_outside_the_schemas_own_table_is_refused() {
    let store = sink();
    let refusal = run_record_leg(&store, &Declared, EVENTS, OP_PUT, &key("t-1"), b"body")
        .expect_err("events does not declare put");
    assert_eq!(
        refusal,
        RecordRefusal::UndeclaredOp {
            schema: EVENTS.as_str(),
            op: OP_PUT,
        }
    );
    assert!(
        store.calls().is_empty(),
        "the sink must never have been asked"
    );
}

/// An operation no schema declares is refused the same way.
#[test]
fn an_op_in_no_table_at_all_is_refused() {
    let store = sink();
    let refusal = run_record_leg(&store, &Declared, EVENTS, OP_ASK, &key("t-1"), b"")
        .expect_err("events does not declare the liveness question");
    assert!(matches!(refusal, RecordRefusal::UndeclaredOp { .. }));
    assert!(store.calls().is_empty());
}

/// A BODY OVER THE RECORD CEILING is refused, and the sink is never asked.
#[test]
fn an_oversize_body_is_refused_before_the_sink() {
    let store = sink();
    let body = vec![b'x'; MAX_RECORD_BYTES + 1];
    let refusal = run_record_leg(&store, &Declared, ROWS, OP_PUT, &key("t-1"), &body)
        .expect_err("the body is over the ceiling");
    assert_eq!(
        refusal,
        RecordRefusal::Oversize {
            bytes: MAX_RECORD_BYTES + 1,
            cap: MAX_RECORD_BYTES,
        }
    );
    assert!(
        store.calls().is_empty(),
        "the sink must never have been asked"
    );
}

/// A body EXACTLY at the ceiling is a record, not an overrun. The boundary is inclusive and this is
/// the cell that pins which side of it the equal case falls on.
#[test]
fn a_body_exactly_at_the_ceiling_is_accepted() {
    let store = sink();
    let body = vec![b'x'; MAX_RECORD_BYTES];
    run_record_leg(&store, &Declared, ROWS, OP_PUT, &key("t-1"), &body)
        .expect("a record of exactly the ceiling is a record");
    assert_eq!(store.calls().len(), 1);
}

/// A backend failure is carried through as the backend's own words, not classified by the kernel.
#[test]
fn a_sink_failure_is_carried_through() {
    let store = sink();
    *store.refuse.lock().expect("refuse") = Some("the store is unavailable".to_string());
    let refusal = run_record_leg(&store, &Declared, ROWS, OP_PUT, &key("t-1"), b"body")
        .expect_err("the sink refused");
    assert_eq!(
        refusal,
        RecordRefusal::Sink("the store is unavailable".to_string())
    );
}

/// A plan runs its record legs IN ORDER and skips everything that is not one.
#[test]
fn a_plan_runs_its_record_legs_in_order() {
    let store = sink();
    let legs = vec![
        leg(ROWS, OP_GET),
        Leg {
            destination: DestinationFacts::KernelVerb { verb: "read_stats" },
        },
        leg(ROWS, OP_PUT),
        leg(EVENTS, OP_APPEND),
    ];
    let answers = run_record_plan(&store, &Declared, &legs, &key("t-1"), b"body")
        .expect("every record leg is declared");
    assert_eq!(answers.len(), 3, "the kernel-verb leg is not a record leg");
    assert_eq!(
        store.calls(),
        vec![
            "get rows t-1 4".to_string(),
            "put rows t-1 4".to_string(),
            "append events t-1 4".to_string(),
        ]
    );
}

/// A DEAD CAPABILITY STOPS THE PLAN, before any leg that would record something.
///
/// The reading is acted on rather than filed: the legs after the question never run, so a refused
/// callback writes nothing and leaves the stored state exactly as it was.
#[test]
fn a_leg_answering_not_live_stops_the_plan() {
    let store = sink();
    *store.live.lock().expect("live") = false;
    let legs = vec![leg(ROWS, OP_ASK), leg(ROWS, OP_PUT), leg(EVENTS, OP_APPEND)];
    let refusal = run_record_plan(&store, &Declared, &legs, &key("t-1"), b"body")
        .expect_err("the capability is dead");
    assert_eq!(refusal, RecordRefusal::NotLive);
    assert_eq!(
        store.calls(),
        vec!["ask rows t-1 4".to_string()],
        "nothing after the question may have run"
    );
}

/// A LIVE capability does not stop the plan, and asking twice answers the same twice.
#[test]
fn a_live_capability_lets_the_plan_finish() {
    let store = sink();
    let legs = vec![leg(ROWS, OP_ASK), leg(ROWS, OP_ASK), leg(ROWS, OP_PUT)];
    let answers =
        run_record_plan(&store, &Declared, &legs, &key("t-1"), b"body").expect("the token is live");
    assert_eq!(answers[0].live, Some(true));
    assert_eq!(answers[1].live, Some(true));
    assert_eq!(answers.len(), 3);
}

/// A refusal inside a plan stops it where it is, and the legs before it have already happened.
#[test]
fn a_refusal_inside_a_plan_stops_it_where_it_is() {
    let store = sink();
    let legs = vec![leg(ROWS, OP_PUT), leg(EVENTS, OP_PUT), leg(ROWS, OP_GET)];
    let refusal = run_record_plan(&store, &Declared, &legs, &key("t-1"), b"body")
        .expect_err("events does not declare put");
    assert!(matches!(refusal, RecordRefusal::UndeclaredOp { .. }));
    assert_eq!(
        store.calls(),
        vec!["put rows t-1 4".to_string()],
        "the leg before the refusal ran; the one after it did not"
    );
}
