//! Tests for `units_a2a.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;
use busbar_unit_admission::ChainWalk;
use std::sync::atomic::{AtomicU64, Ordering};

/// **The metered line's direction is the side its quantity was measured on.**
///
/// The quantity is the RESPONSE document's size — the draft's `response_bytes`, not its
/// `request_bytes` — so the locator that carries it says `Response`. A direction is not a label
/// on a line: it is the axis a class cap, a rate-card entry and the usage projection all
/// partition on, so a line metered as ingress while the deployment capped egress is a line that
/// is silently exempt from its own limit and still shows up on the bill.
///
/// The two fields are asserted against ONE draft whose two byte counts differ, so a line that
/// took its quantity from the other side would show up here as a quantity mismatch rather than
/// pass by coincidence.
#[test]
fn the_metered_lines_direction_is_the_side_its_quantity_came_from() {
    let draft = draft(ops::OP_MESSAGE_SEND);
    assert_ne!(
        draft.request_bytes, draft.response_bytes,
        "the fixture's two sides differ, so the quantity below names one of them"
    );

    let located = bytes_located(&draft);
    assert_eq!(located.class, CLASS_BYTES, "the plane's one class");
    assert_eq!(
        located.quantity, draft.response_bytes,
        "the quantity is measured off the answer document"
    );
    match located.source {
        busbar_caps::QuantitySource::Locator { direction, .. } => assert_eq!(
            direction,
            busbar_contract::ids::ClassDirection::Response,
            "and the direction says so, rather than naming the side it did not come from"
        ),
        other => panic!("this plane carries its quantity by locator, not {other:?}"),
    }
}

/// **The record's two clocks are two readings, and the monotonic one cannot be walked back.**
///
/// A wall clock is steppable — an operator sets it, NTP corrects it, a leap second repeats it —
/// and the audit record carries a second clock for exactly that reason: the wall reading DATES
/// the record and the monotonic reading ORDERS it. Filled from the wall clock, the second field
/// is a copy rather than a reading and the record orders nothing.
///
/// So: two units, and between them the wall clock goes BACKWARDS. Each record dates itself at
/// the epoch its own unit arrived at, which is the wall clock telling the truth about a
/// deployment whose clock moved. And the monotonic readings still run forwards, which is the
/// property that makes the pair of records readable in the order they happened.
#[test]
fn a_wall_clock_that_steps_backwards_does_not_reorder_the_audit_records() {
    const EARLIER: u64 = 1_700_000_040;
    // The correction: the operator's clock was forty seconds fast, so the SECOND unit to arrive
    // dates itself before the first.
    const LATER: u64 = 1_700_000_000;

    let deployment = deployment(one_call_at_a_time("a2a-team"));
    let who = PrincipalId::new("vk_agent");
    let chain = deployment.resolve(&who, Some("a2a-team"));
    let record = |now| {
        deployment.calling_at(chain.as_ref(), now).audit_inputs(
            &a2a_ctx(),
            Outcome::Completed,
            Some(&who),
        )
    };

    let first = record(EARLIER);
    let second = record(LATER);

    assert_eq!(
        first.wall, EARLIER,
        "the record dates itself at its arrival"
    );
    assert_eq!(second.wall, LATER, "and so does the one that followed it");
    assert!(
        first.wall > second.wall,
        "the wall clock went backwards between the two, which is the whole point"
    );
    assert!(
        second.mono > first.mono,
        "and the reading that ORDERS them did not: {} then {}",
        first.mono,
        second.mono
    );
    assert_ne!(
        first.mono, first.wall,
        "the two clocks are two readings, not one written twice"
    );
}

/// **Two units of one second are ordered by the monotonic stamp, not by the wall clock.**
///
/// The companion of the straddle above, from the other side: there the wall clock moved and the
/// ordering held; here the wall clock does not move at all — two units arriving inside one
/// second are indistinguishable by it — and the ordering still holds, because the reading that
/// orders them is not the one that dates them. Filled from the wall clock, both records carry
/// the same number twice and there is no order to read.
#[test]
fn two_units_of_one_second_are_ordered_by_the_monotonic_stamp() {
    const ONE_SECOND: u64 = 1_700_000_000;

    let deployment = deployment(one_call_at_a_time("a2a-team"));
    let who = PrincipalId::new("vk_agent");
    let chain = deployment.resolve(&who, Some("a2a-team"));
    let record = || {
        deployment
            .calling_at(chain.as_ref(), ONE_SECOND)
            .audit_inputs(&a2a_ctx(), Outcome::Completed, Some(&who))
    };

    let first = record();
    let second = record();

    assert_eq!(
        first.wall, second.wall,
        "the wall clock cannot tell these two apart, which is the point"
    );
    assert!(
        second.mono > first.mono,
        "and the reading that orders them can: {} then {}",
        first.mono,
        second.mono
    );
}

/// A panic somewhere else does not stop this plane from sealing and settling.
///
/// The node's durability is one lock, shared by every unit on every plane. A step that took it
/// and refused a poisoned one would turn a single unrelated panic into a node that can no longer
/// seal an audit record or settle an exit — for every later request, permanently. The lock is
/// read through instead, which is how the rest of the root reads it.
#[test]
fn a_poisoned_lock_does_not_stop_the_audit_chain() {
    let durability = Mutex::new(
        crate::root::durability::build(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            Box::new(busbar_unit_wal::NullShipper::new()),
            Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
        )
        .expect("a memory-buffered node cannot fail to open"),
    );

    // Poison it the only way a lock gets poisoned: a panic while it is held.
    let poisoning = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let _held = durability.lock().expect("the lock is not yet poisoned");
                panic!("a unit somewhere else panicked");
            })
            .join()
    });
    assert!(poisoning.is_err(), "the thread panicked under the lock");
    assert!(durability.is_poisoned(), "so the lock is poisoned");

    // The seam the audit and settlement steps take it through still hands back the node's one
    // durability, rather than taking the process with it.
    assert!(!read_through_poison(&durability).on_disk());

    // And the per-unit progress the exit reads is taken the same way.
    let progress = Mutex::new(Progress::default());
    let poisoning = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let mut held = progress.lock().expect("the lock is not yet poisoned");
                held.encoded = 7;
                panic!("a step panicked after writing");
            })
            .join()
    });
    assert!(poisoning.is_err());
    assert_eq!(
        read_through_poison(&progress).encoded,
        7,
        "what the step wrote before it panicked is still what the exit reads"
    );
}

/// The audit action is the word the gating rig reads.
///
/// The plugin crate spells the same word crate-privately, so the pin is against the rig, which
/// is the surface an operator and the ledger both see. If either moves, this goes red rather
/// than the audit chain quietly recording an action nothing queries.
#[test]
fn the_audit_action_is_the_word_the_rig_reads() {
    let rig = include_str!("../../../../../scripts/a2a-subject/h2-audit-record.sh");
    // Quoted, so a mention in a comment or in this file's own header (both bare, unquoted words)
    // cannot satisfy this: only the executable argument the rig actually asserts on can.
    assert!(
        rig.contains(&format!("\"{AUDIT_ACTION}\"")),
        "the rig's executable assertion no longer names \"{AUDIT_ACTION}\""
    );
    assert_eq!(AUDIT_ACTION, "agent.call");
}

/// The resource kind is the plane's own word, and the rig reads the pair.
#[test]
fn the_resource_is_the_agent() {
    let rig = include_str!("../../../../../scripts/a2a-subject/h2-audit-record.sh");
    // Quoted, for the same reason as the action pin above: a bare mention in prose must not
    // satisfy this.
    assert!(rig.contains(&format!("\"{SCOPE_KIND_AGENT}:probe\"")));
}

/// Every operation class the plane declares gets a scope entry.
///
/// Silence is a refusal, so a class the policy never mentions is unreachable. This is what
/// makes "the deployment forgot one" a compile-time-shaped question rather than a support call.
#[test]
fn every_operation_class_is_declared() {
    let policy = scope_policy(crate::root::policy::ScopePolicy::new());
    assert_eq!(policy.len(), ops::OP_CLASSES.len());
    for op in ops::OP_CLASSES {
        assert!(
            busbar_unit_scope::PolicyView::required_scope(&policy, CLAIM_A2A, *op).is_some(),
            "{op} has no scope entry"
        );
    }
}

/// The projections are read-only and everything that moves a task is not.
#[test]
fn a_projection_is_read_only_and_a_send_is_not() {
    assert_eq!(declared_scope(ops::OP_TASK_GET), Scope::ReadOnly);
    assert_eq!(declared_scope(ops::OP_TASK_LIST), Scope::ReadOnly);
    assert_eq!(declared_scope(ops::OP_AGENT_CARD), Scope::ReadOnly);
    assert_eq!(declared_scope(ops::OP_MESSAGE_SEND), Scope::Full);
    assert_eq!(declared_scope(ops::OP_TASK_CANCEL), Scope::Full);
    assert_eq!(declared_scope(ops::OP_PUSH_EVENT), Scope::Full);
}

/// A unit the table has no room for is refused AT arrival, and one it admits keeps the chain the
/// transport recorded.
///
/// THE arrival STEP, over the loop. The step has two things to decide and this drives both,
/// because either one alone is half the door:
///
/// - THE GATE, which is the kernel's and which this plane is UNDER. A2A arrives on the data
///   listener, so `admin_listener` is false and the exemption the admin leg gets does not reach
///   it: on a table with room the unit enters and its hold lives in the cell, and on a full one
///   it is refused with `InFlightCap`, stamped at `Arrival` because the origin is a client, with
///   the arrival hold handed straight back rather than dropped. A refusal here is the whole
///   unit: the loop runs `arrival` first and nothing after it, so decode never reads a byte and
///   nothing downstream can charge for one.
/// - THE PLANE'S ANSWER for a unit that got through, which is the transport's own record carried
///   forward whole. The composed chain is the field worth pinning: this unit came in over HTTP
///   composed on TCP, both layers are named, and the step reports what arrived rather than what
///   the plane would have guessed from its own claims.
#[test]
fn the_arrival_carries_the_transports_own_record_and_a_full_table_refuses_at_arrival() {
    use busbar_caps::{KernelSeal, OriginKind, StepName, UnitKey};
    use busbar_kernel::inflight::{arrival_hold, cap_refusal_step, Enter, InFlight};

    let kernel = busbar_kernel::teller::Kernel::new();
    let door = crate::root::kernel::AdmissionDoor;
    let seal = KernelSeal::acquire_for_kernel();

    // One slot, none held back: a table this plane can fill and then be measured against.
    let table = InFlight::new(1, 0);
    // What an a2a unit asks the table for. The data listener is the whole point — an a2a unit
    // that claimed the admin listener's exemption would be outside the cap the deployment set.
    let entering = |key: u64| Enter {
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        admin_listener: false,
        provider_of_open_session: false,
        zero_hold_tick: false,
        now: 0,
        arrival: arrival_hold(&kernel, &door, PrincipalId::new("caller")),
    };

    // ADMITTED: there is room, the unit is in the table, and its arrival hold is in the cell.
    let slot = table
        .insert(entering(1))
        .unwrap_or_else(|_| panic!("an empty table admits the first unit"));
    assert_eq!(table.len(), 1);
    assert_eq!(
        slot.cell().state(),
        busbar_caps::HoldCellState::Arrival,
        "the unit is in the table holding its arrival hold and nothing more"
    );

    // The step that unit then reaches carries the transport's record forward, both layers named.
    let draft = draft(ops::OP_MESSAGE_SEND);
    let record = arrival_answer(&draft, &UnitToken::mint(&seal))
        .into_result(&seal)
        .expect("the plane's arrival step admits a unit the gate let through");
    assert_eq!(record.transport_chain, vec!["tcp", "http"]);
    assert_eq!(record.source, draft.arrival.source);
    assert_eq!(record.port, draft.arrival.port);

    // REFUSED: the same shape, one slot later. The gate answers before any plane is asked.
    let Err(refused) = table.insert(entering(2)) else {
        panic!("a full table has nowhere to put a second unit");
    };
    assert_eq!(refused.reason, ReasonCode::InFlightCap);
    assert_eq!(refused.step, StepName::Arrival);
    assert_eq!(refused.step, cap_refusal_step(OriginKind::Client));
    // The hold comes back, because even a refusal is an event that has to balance — and it
    // comes back reserving nothing, which is what makes "a unit refused at the gate has spent
    // nothing" a fact about the ledger rather than a phrase.
    let handed_back = refused.hold;
    assert_eq!(
        handed_back.reserved(),
        0,
        "the arrival hold reserves nothing"
    );
    assert_eq!(handed_back.accrued(), 0);
    assert_eq!(table.len(), 1, "a refused unit took no slot");
}

/// A bad credential is refused before Verify is ever reached, through the node's own auth seams.
///
/// THE authenticate STEP, over the loop. The step is not this file's own opinion about a
/// credential — it shapes the plane's request and hands it to the chain with the three seams the
/// node holds one set of (the cache, the signed-key verifier, the revocation view). What this
/// pins is that the shaping is right and the refusal lands AT the step:
///
/// - a forged credential is `Unauthenticated`, not an admission;
/// - a credential minted for a DIFFERENT plane's audience is refused here too — the audience is
///   the plane boundary and the verifier is where it is enforced, so an a2a token is not an mcp
///   token and the reverse;
/// - a revoked credential is refused on a new unit, which is the answer `new_unit` exists for;
/// - the one approved credential reaches its principal, so the refusals above are the arm
///   deciding and not a door that was shut to everything.
///
/// ZERO EGRESS is the other half and it is structural: the draft carries an Upstream
/// destination, so this unit WOULD have dialled an agent, and every refusal below is a
/// `Decision<Authenticate>` — the kernel's loop runs no later step on a refusal, so Verify never
/// seals a destination and Route never gets a plan. The assertion that the draft really does
/// point at an agent is what keeps that meaningful: refusing a unit that was going nowhere would
/// prove nothing about egress.
#[test]
fn a_bad_credential_is_refused_before_verify_through_the_nodes_own_seams() {
    use crate::root::kernel::auth_bindings::AuthBindings;
    use busbar_caps::{Authenticated, KernelSeal};
    use busbar_contract::{KeyFacts, VirtualKeyDirectory};
    use busbar_unit_auth::{AuthChain, ChainVerdict};

    /// The audience this plane's ingress requires of a signed token.
    const AUD: &str = "a2a";

    struct OneKey;

    impl VirtualKeyDirectory for OneKey {
        fn operator_token_hash(&self) -> Option<String> {
            None
        }

        fn verify(
            &self,
            credential: &str,
            _now: u64,
            expected_aud: Option<&str>,
        ) -> Option<KeyFacts> {
            // The audience is the plane boundary, and the verifier is where it is enforced.
            // The burned credential is one this directory DID mint: a revocation withdraws an
            // identification, so the string it withdraws has to identify first.
            if expected_aud != Some(AUD) {
                return None;
            }
            match credential {
                "tok" => Some(KeyFacts {
                    id: "key-a2a-1".to_string(),
                    name: "an approved key".to_string(),
                    scopes: None,
                    enabled: true,
                    expires_at: None,
                    deleted_at: None,
                }),
                "burned" => Some(KeyFacts {
                    id: "key-a2a-burned".to_string(),
                    name: "a key that was minted and then burned".to_string(),
                    scopes: None,
                    enabled: true,
                    expires_at: None,
                    deleted_at: None,
                }),
                _ => None,
            }
        }

        fn is_revoked(&self, credential: &str) -> bool {
            credential == "burned"
        }
    }

    // A chain naming the signed-key arm and no boxed module: the door stays shut and the arm is
    // the one thing that can open it, which is what makes this cell about the arm.
    let auth = Auth::new(AuthChain::new(Vec::new(), true));
    assert!(!auth.chain().is_open());
    assert!(matches!(
        auth.chain().run_chain(Some("tok")),
        ChainVerdict::Denied
    ));

    let bindings = AuthBindings::new(std::sync::Arc::new(OneKey));
    let seal = KernelSeal::acquire_for_kernel();

    // The unit is pointed at an agent. Every refusal below is therefore a dial that did not
    // happen, rather than a unit that had no egress to refuse.
    let mut base = draft(ops::OP_MESSAGE_SEND);
    base.expected_aud = Some(AUD.to_string());
    assert!(
        base.has_upstream(),
        "the fixture must reach an agent or the zero-egress half proves nothing"
    );

    let decide = |credential: &str| {
        let mut d = draft(ops::OP_MESSAGE_SEND);
        d.expected_aud = Some(AUD.to_string());
        d.credential = Some(credential.to_string());
        let seams = &bindings;
        auth.resolve(
            &auth_request(&d, 100),
            seams.cache(),
            seams.directory(),
            None,
            &UnitToken::mint(&seal),
        )
        .into_result(&seal)
    };

    // A credential nobody minted.
    match decide("forged") {
        Err(refusal) => assert_eq!(refusal.reason(), ReasonCode::Unauthenticated),
        Ok(other) => panic!("a forged credential was admitted as {other:?}"),
    }

    // A credential that was minted, and then burned. The revocation view is asked because this
    // is a new unit; a bound session would not have asked.
    match decide("burned") {
        Err(refusal) => assert_eq!(refusal.reason(), ReasonCode::Revoked),
        Ok(other) => panic!("a revoked credential was admitted as {other:?}"),
    }

    // The approved credential, for the WRONG plane's audience: the same bytes that open this
    // plane do not open it under another plane's expectation.
    let mut elsewhere = draft(ops::OP_MESSAGE_SEND);
    elsewhere.expected_aud = Some("mcp".to_string());
    elsewhere.credential = Some("tok".to_string());
    let seams = &bindings;
    let crossed = auth
        .resolve(
            &auth_request(&elsewhere, 100),
            seams.cache(),
            seams.directory(),
            None,
            &UnitToken::mint(&seal),
        )
        .into_result(&seal);
    match crossed {
        Err(refusal) => assert_eq!(refusal.reason(), ReasonCode::Unauthenticated),
        Ok(other) => panic!("another plane's audience opened this one: {other:?}"),
    }

    // And the arm does open, for the one credential it was given.
    match decide("tok") {
        Ok(Authenticated::Principal(p)) => assert_eq!(p.as_str(), "key-a2a-1"),
        other => panic!("the bound seams did not reach the arm: {other:?}"),
    }
}

/// A read-only grant does not reach a send.
#[test]
fn a_read_only_grant_does_not_reach_a_send() {
    let held = Grants::of(Scope::ReadOnly);
    assert!(busbar_unit_scope::approve(held, declared_scope(ops::OP_TASK_GET)).is_ok());
    assert!(busbar_unit_scope::approve(held, declared_scope(ops::OP_MESSAGE_SEND)).is_err());
}

/// A leg naming an operation its schema does not declare is refused, not attempted.
#[test]
fn an_undeclared_operation_is_refused() {
    let legs = RecordLegs::new(Arc::new(RecordingStore::default()));
    let key = LegKey {
        id: "t-1",
        parent: None,
        seq: 0,
        ts: 0,
        expires_at: 0,
        terminal: false,
    };
    // The event chain is hash-linked, so it is append-and-read and never overwritten. Asking it
    // to accept a replacement is the exact mistake this refusal exists to catch.
    let err = legs
        .run(records::SCHEMA_TASK_EVENT, records::OP_PUT, &key, b"{}")
        .expect_err("an undeclared operation must not run");
    assert_eq!(
        err,
        LegError::UndeclaredOp {
            schema: records::SCHEMA_TASK_EVENT.as_str(),
            op: records::OP_PUT,
        }
    );
}

/// Every operation every schema declares reaches the store.
///
/// Totality over the plane's own declaration: an operation declared with no arm here would be a
/// leg the plan can name and nothing can run.
#[test]
fn every_declared_operation_reaches_the_store() {
    let store = Arc::new(RecordingStore::default());
    let legs = RecordLegs::new(store.clone());
    let key = LegKey {
        id: "t-1",
        parent: Some("p-1"),
        seq: 1,
        ts: 7,
        // Ahead of `ts`, so a liveness leg in this sweep is asked a question whose answer is not
        // decided by the deadline having already passed.
        expires_at: 70,
        terminal: false,
    };
    for schema in records::RECORD_SCHEMAS {
        for op in records::operations_for(*schema) {
            legs.run(*schema, op, &key, b"{}")
                .unwrap_or_else(|e| panic!("{schema} {op} did not run: {e:?}"));
        }
    }
    // Four schemas, and every one of them was reached under its own name.
    let seen = store.kinds();
    for schema in records::RECORD_SCHEMAS {
        assert!(
            seen.contains(&schema.as_str().to_string()),
            "{schema} unreached"
        );
    }
}

/// The four schemas this plane declares are the four the conversion table names.
#[test]
fn the_four_schemas_are_the_planes_own() {
    let names: Vec<&str> = records::RECORD_SCHEMAS.iter().map(|s| s.as_str()).collect();
    assert_eq!(names.len(), 4);
    assert!(names.contains(&records::SCHEMA_PUSH_CONFIG.as_str()));
    assert!(names.contains(&records::SCHEMA_PIN.as_str()));
}

/// A plan's record legs run in the plan's own order and its upstream leg is left alone.
///
/// The order is load-bearing: a cancellation reads the row, hops, writes the row and appends
/// the event. A run that reordered those would append an event for a state the row never
/// reached, and the hop is not this binding's to make.
#[test]
fn a_plan_runs_its_record_legs_in_order_and_skips_the_hop() {
    let store = Arc::new(RecordingStore::default());
    let legs = RecordLegs::new(store.clone());
    let plan = vec![
        leg_record(records::SCHEMA_TASK, records::OP_GET),
        Leg {
            destination: DestinationFacts::Upstream {
                transport: "http",
                address: busbar_contract::UpstreamAddress::socket("agent.example:443"),
                lane: LaneId::new("probe"),
            },
        },
        leg_record(records::SCHEMA_TASK, records::OP_PUT),
        leg_record(records::SCHEMA_TASK_EVENT, records::OP_APPEND),
    ];
    let key = LegKey {
        id: "t-1",
        parent: Some("t-1"),
        seq: 1,
        ts: 3,
        expires_at: 30,
        terminal: true,
    };
    let results = legs.run_plan(&plan, &key, b"{}").expect("the legs run");
    assert_eq!(results.len(), 3, "the hop is not a record leg");
    assert_eq!(
        store.calls(),
        vec![
            format!("get {}", records::SCHEMA_TASK),
            format!("put {}", records::SCHEMA_TASK),
            format!("append {}", records::SCHEMA_TASK_EVENT),
        ]
    );
}

/// A plan longer than the route plan can carry does not fit, and the ninth leg is where it
/// stops fitting.
///
/// The bound is the contract's, not this file's, and the question is asked before a leg runs.
/// The second half of this test is why: pushed rather than checked, the plan silently comes out
/// eight legs long, so the ninth leg would have happened and nothing in the answer would say it
/// had.
#[test]
fn a_plan_longer_than_the_route_plan_can_carry_does_not_fit() {
    let nine: Vec<Leg> = (0..9)
        .map(|_| leg_record(records::SCHEMA_TASK, records::OP_GET))
        .collect();
    assert!(!plan_fits(&nine));
    assert!(plan_fits(&nine[..busbar_contract::MAX_LEGS]));

    let mut plan = RoutePlan::default();
    for leg in &nine {
        let _ = plan.legs.push(Leg {
            destination: leg.destination,
        });
    }
    assert_eq!(
        plan.legs.len(),
        busbar_contract::MAX_LEGS,
        "the plan truncates, which is what the check above exists to catch first"
    );
}

/// A store that refuses stops the plan at the leg that refused.
#[test]
fn a_refusing_store_stops_the_plan() {
    let legs = RecordLegs::new(Arc::new(RefusingStore));
    let plan = vec![leg_record(records::SCHEMA_TASK, records::OP_PUT)];
    let key = LegKey {
        id: "t-1",
        parent: None,
        seq: 0,
        ts: 0,
        expires_at: 0,
        terminal: false,
    };
    assert!(matches!(
        legs.run_plan(&plan, &key, b"{}"),
        Err(LegError::Store(_))
    ));
}

/// A record leg carries no lane, so it never enters the sealed set.
///
/// Not an exclusion — a record is reached through the plan, not through the pool walk — and the
/// distinction matters because an excluded lane is one the walk skipped and a record leg was
/// never a lane at all.
#[test]
fn a_record_leg_is_not_priced_on_a_lane() {
    let record = DestinationFacts::PlaneRecord {
        schema: records::SCHEMA_TASK,
        op: records::OP_GET,
    };
    assert!(record.lane().is_none());
    let upstream = DestinationFacts::Upstream {
        transport: "http",
        address: busbar_contract::UpstreamAddress::socket("agent.example:443"),
        lane: LaneId::new("probe"),
    };
    assert_eq!(upstream.lane(), Some(LaneId::new("probe")));
}

/// A draft whose plan reaches an agent draws the fee; one that only touches records does not.
#[test]
fn only_a_hop_to_an_agent_carries_the_fee() {
    let mut draft = draft(ops::OP_TASK_LIST);
    draft.destination = DestinationFacts::PlaneRecord {
        schema: records::SCHEMA_TASK,
        op: records::OP_SCAN,
    };
    draft.legs = vec![leg_record(records::SCHEMA_TASK, records::OP_SCAN)];
    assert!(!draft.has_upstream());

    let mut sending = draft.clone();
    sending.destination = DestinationFacts::Upstream {
        transport: "http",
        address: busbar_contract::UpstreamAddress::socket("agent.example:443"),
        lane: LaneId::new("probe"),
    };
    assert!(sending.has_upstream());
}

/// The flat fee is decided from the caller, the leg and the answer that reached the caller.
///
/// Four ways for a unit to reach an agent and post nothing anyway: the push the agent sent, the
/// request that never got an answer to relay, the plan that only touched this node's records,
/// and the ending the plane itself called an error. Only the fifth shape pays, and it pays once.
#[test]
fn the_flat_fee_is_decided_from_caller_leg_and_relayed_answer() {
    use busbar_caps::OriginKind;
    use busbar_kernel::teller::fee_count;

    let served = draft(ops::OP_MESSAGE_SEND);
    assert!(served.has_upstream());
    assert_eq!(
        fee_count(&fee_evidence(&served, OriginKind::Client, true)).0,
        1
    );
    assert_eq!(
        fee_count(&fee_evidence(&served, OriginKind::Provider, true)).0,
        0
    );
    assert_eq!(
        fee_count(&fee_evidence(&served, OriginKind::Client, false)).0,
        0
    );

    // A RELAYED ANSWER THE PLANE THEN CALLS AN ERROR IS THE CONTRADICTION, not a free request.
    // The client was handed a frame that said the task was accepted; the plane says the unit
    // failed. Those are the fee's two readings disagreeing, and the kernel decides it the way it
    // decides it for every plane — the frame the client saw counts, and the posting is marked so
    // the disagreement is visible rather than absorbed. This assertion used to read 0, which was
    // the plane's finish deciding alone because this leg told the kernel there was no status leg
    // to reconcile it against.
    let mut failed = served.clone();
    failed.finish = FinishClass::Error;
    let (fee, flags) = fee_count(&fee_evidence(&failed, OriginKind::Client, true));
    assert_eq!(fee, 1);
    assert!(flags.contains(busbar_caps::PostingFlags::METER_DISPUTED));

    let mut records_only = served.clone();
    records_only.destination = DestinationFacts::PlaneRecord {
        schema: records::SCHEMA_TASK,
        op: records::OP_SCAN,
    };
    records_only.legs = vec![leg_record(records::SCHEMA_TASK, records::OP_SCAN)];
    assert!(!records_only.has_upstream());
    assert_eq!(
        fee_count(&fee_evidence(&records_only, OriginKind::Client, true)).0,
        0
    );
}

/// The four endings map one for one onto the audit unit's own four.
#[test]
fn every_ending_has_an_audited_spelling() {
    assert_eq!(
        audit_finish(FinishClass::Complete),
        busbar_unit_audit::FinishClass::Complete
    );
    assert_eq!(
        audit_finish(FinishClass::TurnComplete),
        busbar_unit_audit::FinishClass::TurnComplete
    );
    assert_eq!(
        audit_finish(FinishClass::Partial),
        busbar_unit_audit::FinishClass::Partial
    );
    assert_eq!(
        audit_finish(FinishClass::Error),
        busbar_unit_audit::FinishClass::Error
    );
}

/// A record leg has no address, so the guard has nothing to have judged and says so.
#[test]
fn a_record_leg_is_not_a_network_hop() {
    let resolver = FixedResolver(vec![]);
    assert!(guard_destination(
        &DestinationFacts::PlaneRecord {
            schema: records::SCHEMA_TASK,
            op: records::OP_GET,
        },
        &resolver,
        GuardPolicy::default(),
        &busbar_unit_trust::Denylist::default(),
    )
    .is_ok());
}

/// A kind that is not dialled at an address PASSES here, and pins nothing.
///
/// The trust unit's published door answers `NotAnUpstream` for these, because it is asked about
/// a destination that was already sealed and a caller reading that answer wants to know which
/// kind it holds. This caller is asking a narrower question — "is there an address here that
/// would fail the guard" — and for a verb, a delivery or a session accrual the answer is no.
/// Reading the unit's answer as a refusal would refuse every leg that never had an address.
#[test]
fn a_kind_that_is_not_dialled_at_an_address_passes_and_pins_nothing() {
    let resolver = FixedResolver(vec![]);
    for candidate in [
        DestinationFacts::KernelVerb { verb: "status" },
        DestinationFacts::SessionAccrual {
            lane: LaneId::new("probe"),
        },
        DestinationFacts::Upgrade { to: "ws" },
    ] {
        assert_eq!(
            guard_destination(
                &candidate,
                &resolver,
                GuardPolicy::default(),
                &busbar_unit_trust::Denylist::default(),
            ),
            Ok(None),
            "{candidate:?} has no address to have judged"
        );
    }
}

/// A cloud-metadata endpoint is refused, and it is refused whatever the deployment opted into.
///
/// An operator saying "this agent is on our internal network" has said nothing about the address
/// whose whole value to an attacker is that it hands out credentials to anyone inside. The two
/// arms are separate in the guard for exactly this reason and must not be merged.
#[test]
fn a_metadata_endpoint_is_refused_even_when_private_addressing_is_allowed() {
    let resolver = FixedResolver(vec!["169.254.169.254".parse().expect("an address")]);
    let permissive = GuardPolicy {
        allow_private: true,
        allow_plaintext: true,
        ..GuardPolicy::default()
    };
    let refusal = guard_destination(
        &upstream("http://metadata.google.internal/"),
        &resolver,
        permissive,
        &busbar_unit_trust::Denylist::default(),
    )
    .expect_err("a metadata endpoint is not reachable");
    assert!(matches!(
        refusal,
        busbar_unit_trust::NetworkRefusal::MetadataDenied(_)
    ));
}

/// A private address is refused by default and reachable only when the deployment said so.
///
/// Both halves matter: the default is what a deployment that wrote nothing gets, and the opt-in
/// is what the conformance rig's own loopback agent needs.
#[test]
fn a_private_address_needs_the_operators_word() {
    let resolver = FixedResolver(vec!["127.0.0.1".parse().expect("an address")]);
    let dest = upstream("http://agent.internal:8080/");
    assert!(guard_destination(
        &dest,
        &resolver,
        GuardPolicy::default(),
        &busbar_unit_trust::Denylist::default(),
    )
    .is_err());
    let opted_in = GuardPolicy {
        allow_private: true,
        ..GuardPolicy::default()
    };
    assert!(guard_destination(
        &dest,
        &resolver,
        opted_in,
        &busbar_unit_trust::Denylist::default(),
    )
    .is_ok());
}

/// A name that answers nothing is refused, and it is refused before anything is dialled.
#[test]
fn a_name_that_answers_nothing_is_refused() {
    let resolver = FixedResolver(vec![]);
    assert!(guard_destination(
        &upstream("https://agent.example/"),
        &resolver,
        GuardPolicy::default(),
        &busbar_unit_trust::Denylist::default(),
    )
    .is_err());
}

/// A public address over TLS is reached.
#[test]
fn a_public_address_over_tls_is_reached() {
    let resolver = FixedResolver(vec!["93.184.216.34".parse().expect("an address")]);
    assert!(guard_destination(
        &upstream("https://agent.example/"),
        &resolver,
        GuardPolicy::default(),
        &busbar_unit_trust::Denylist::default(),
    )
    .is_ok());
}

/// A bare `host:port` reaches the same judgement a URL does.
#[test]
fn a_bare_authority_is_judged_like_a_url() {
    let resolver = FixedResolver(vec!["127.0.0.1".parse().expect("an address")]);
    assert!(guard_destination(
        &upstream("agent.internal:8080"),
        &resolver,
        GuardPolicy::default(),
        &busbar_unit_trust::Denylist::default(),
    )
    .is_err());
}

/// An authority carrying userinfo is refused, because its two readings differ.
///
/// `user@agent.example:443` reads as `agent.example` to a URL parser and as `user@agent.example`
/// to a human skimming a config diff, and the trust unit's recogniser refuses a value whose two
/// readings differ rather than picking one. A guard that split on the last colon and never
/// looked for the `@` accepted it, resolved whatever the name answered with, and pinned that.
#[test]
fn a_userinfo_bearing_bare_authority_is_refused() {
    let resolver = FixedResolver(vec!["93.184.216.34".parse().expect("an address")]);
    assert!(guard_destination(
        &upstream("user@agent.example:443"),
        &resolver,
        GuardPolicy::default(),
        &busbar_unit_trust::Denylist::default(),
    )
    .is_err());
}

/// The guard the root runs and the guard the trust unit publishes answer identically.
///
/// This is the drift proof, and it is a table rather than a spot check because the two used to
/// be two implementations: what a second copy costs is not that it is wrong on the case someone
/// thought of, it is that it is wrong on the case nobody re-derived. Every row goes through both
/// doors and the verdicts must match.
#[test]
fn the_root_guard_and_the_trust_units_own_door_agree() {
    // The token the loop lends the trust unit, which is what seals a destination in a running
    // deployment. A private type carrying an impl of the contract's sealing trait would forge
    // the same value while reading as if that were the ordinary way to obtain one.
    let trust = busbar_caps::TrustToken::mint(&busbar_caps::KernelSeal::acquire_for_kernel());
    let resolver = FixedResolver(vec!["93.184.216.34".parse().expect("an address")]);
    for authority in [
        "https://agent.example/",
        "http://agent.example/",
        "agent.example:443",
        "user@agent.example:443",
        "https://user@agent.example/",
        "[::1]:443",
        "https://169.254.169.254/latest/meta-data",
    ] {
        let facts = upstream(authority);
        let sealed = busbar_contract::VerifiedDestination::seal(&trust, facts, "http", None);
        let through_the_root = guard_destination(
            &facts,
            &resolver,
            GuardPolicy::default(),
            &busbar_unit_trust::Denylist::default(),
        )
        .is_ok();
        // The published door answers `NotAnUpstream` for a kind that is not dialled at an
        // address; every row here IS an upstream, so the two verdicts are directly comparable.
        let through_the_unit = busbar_unit_trust::net::check_destination(
            &sealed,
            &[],
            &resolver,
            GuardPolicy::default(),
            &busbar_unit_trust::Denylist::default(),
        )
        .is_ok();
        assert_eq!(
            through_the_root, through_the_unit,
            "the two doors disagree about `{authority}`"
        );
    }
}

/// Every origin has a spelling on the trust unit's side.
#[test]
fn every_origin_has_a_trust_side_spelling() {
    use busbar_caps::OriginKind as K;
    assert_eq!(trust_origin(K::Client), OriginKind::Client);
    assert_eq!(trust_origin(K::Provider), OriginKind::Provider);
    assert_eq!(trust_origin(K::Tick), OriginKind::Tick);
    assert_eq!(trust_origin(K::Arrival), OriginKind::Arrival);
    assert_eq!(trust_origin(K::Handshake), OriginKind::Handshake);
    assert_eq!(trust_origin(K::Bootstrap), OriginKind::Bootstrap);
    let parent = busbar_contract::ids::UnitKey::new(1);
    assert_eq!(trust_origin(K::Nested { parent }), OriginKind::Nested);
    assert_eq!(trust_origin(K::Delivery { parent }), OriginKind::Delivery);
}

/// The origin gate over this plane's two destination kinds, read off the unit rather than
/// restated.
///
/// Both of this plane's kinds are reachable by a caller and by an agent's push — which is what
/// makes the push path run all the same steps as a request — and neither is reachable by an
/// arrival, which has not got as far as a plane. The one asymmetry is the hop: an agent pushing
/// to this node does not get to make this node dial out.
#[test]
fn the_origin_gate_over_this_planes_kinds() {
    let record = DestinationFacts::PlaneRecord {
        schema: records::SCHEMA_TASK,
        op: records::OP_GET,
    };
    let hop = upstream("https://agent.example/");
    assert!(kind_permitted(OriginKind::Client, &record));
    assert!(kind_permitted(OriginKind::Client, &hop));
    assert!(kind_permitted(OriginKind::Provider, &record));
    assert!(!kind_permitted(OriginKind::Provider, &hop));
    assert!(!kind_permitted(OriginKind::Arrival, &record));
    assert!(!kind_permitted(OriginKind::Arrival, &hop));
}

// ── fixtures ────────────────────────────────────────────────────────────────────────────────

/// One upstream destination at an authority.
fn upstream(authority: &'static str) -> DestinationFacts {
    DestinationFacts::Upstream {
        transport: "http",
        address: busbar_contract::UpstreamAddress::socket(authority),
        lane: LaneId::new("probe"),
    }
}

/// A resolver that answers the same addresses for every name.
///
/// Resolution is an input to the guard and never an ambient fact, which is what makes a guard
/// test a test rather than a network call.
struct FixedResolver(Vec<std::net::IpAddr>);

impl Resolver for FixedResolver {
    fn resolve(&self, _host: &str) -> Result<Vec<std::net::IpAddr>, String> {
        Ok(self.0.clone())
    }
}

/// One record leg of a plan.
fn leg_record(schema: RecordSchemaId, op: &'static str) -> Leg {
    Leg {
        destination: DestinationFacts::PlaneRecord { schema, op },
    }
}

/// A draft carrying the shape one served request has.
fn draft(op: OpClassId) -> A2aDraft {
    A2aDraft {
        op: Some(op),
        narrowing: Some("bearer"),
        declared_schemes: &["bearer"],
        from_session: false,
        credential: None,
        expected_aud: None,
        destination: DestinationFacts::Upstream {
            transport: "http",
            address: busbar_contract::UpstreamAddress::socket("agent.example:443"),
            lane: LaneId::new("probe"),
        },
        resource: Some(ResourceLocator {
            kind: SCOPE_KIND_AGENT,
            name: "probe",
        }),
        legs: Vec::new(),
        request_bytes: 128,
        response_bytes: 256,
        finish: FinishClass::Complete,
        streaming: false,
        arrival: ArrivalRecord {
            source: "127.0.0.1:1".to_string(),
            port: 8080,
            alpn: None,
            sni: None,
            peer_cert: None,
            transport_chain: vec!["tcp", "http"],
        },
    }
}

/// The eight governance methods the store contract requires and this file's legs never touch.
///
/// Written once as a macro rather than twice by hand: what these fixtures exist to exercise is
/// the record path, and a copy of the key and usage surface in each of them would be eighty
/// lines saying nothing about the thing under test. Every one is empty, which is exactly what a
/// store that keeps no governance rows does.
macro_rules! no_governance_rows {
    () => {
        fn put_key(&self, _key: &busbar_api::VirtualKey) -> busbar_api::StoreResult<()> {
            Ok(())
        }
        fn get_key(&self, _id: &str) -> busbar_api::StoreResult<Option<busbar_api::VirtualKey>> {
            Ok(None)
        }
        fn list_keys(&self) -> busbar_api::StoreResult<Vec<busbar_api::VirtualKey>> {
            Ok(Vec::new())
        }
        fn delete_key(&self, _id: &str) -> busbar_api::StoreResult<()> {
            Ok(())
        }
        fn get_usage(
            &self,
            _bucket_id: &str,
            _window_start: u64,
        ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
            Ok(busbar_api::UsageLedger::default())
        }
        fn put_usage(
            &self,
            _bucket_id: &str,
            _window_start: u64,
            _ledger: &busbar_api::UsageLedger,
        ) -> busbar_api::StoreResult<()> {
            Ok(())
        }
        fn add_metering(&self, _delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
            Ok(())
        }
        fn list_metering(
            &self,
            _bucket: u64,
        ) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
            Ok(Vec::new())
        }
    };
}

/// A store that remembers which kind-tagged operation it was asked for.
#[derive(Default)]
struct RecordingStore {
    calls: Mutex<Vec<String>>,
}

impl RecordingStore {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls lock").clone()
    }

    fn kinds(&self) -> Vec<String> {
        self.calls()
            .iter()
            .filter_map(|c| c.split_once(' ').map(|(_, k)| k.to_string()))
            .collect()
    }

    fn note(&self, what: &str, kind: &str) {
        self.calls
            .lock()
            .expect("calls lock")
            .push(format!("{what} {kind}"));
    }
}

impl busbar_api::Store for RecordingStore {
    no_governance_rows!();

    fn upsert_plane_record(&self, record: &busbar_api::PlaneRecord) -> busbar_api::StoreResult<()> {
        self.note("put", &record.kind);
        Ok(())
    }

    fn get_plane_record(&self, kind: &str, _id: &str) -> busbar_api::StoreResult<Option<Vec<u8>>> {
        self.note("get", kind);
        Ok(None)
    }

    fn append_plane_record(&self, record: &busbar_api::PlaneRecord) -> busbar_api::StoreResult<()> {
        self.note("append", &record.kind);
        Ok(())
    }

    fn list_plane_records(
        &self,
        kind: &str,
        _selector: &busbar_api::PlaneSelector,
    ) -> busbar_api::StoreResult<Vec<Vec<u8>>> {
        self.note("scan", kind);
        Ok(Vec::new())
    }

    fn delete_plane_record(&self, kind: &str, _id: &str) -> busbar_api::StoreResult<()> {
        self.note("delete", kind);
        Ok(())
    }

    fn redeem_plane_token(
        &self,
        kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> busbar_api::StoreResult<bool> {
        self.note("redeem", kind);
        Ok(true)
    }

    fn plane_token_live(
        &self,
        kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> busbar_api::StoreResult<bool> {
        self.note("verify_live", kind);
        Ok(true)
    }
}

/// A store that refuses everything, so a failure on the record path is a testable event.
struct RefusingStore;

impl busbar_api::Store for RefusingStore {
    no_governance_rows!();

    fn upsert_plane_record(
        &self,
        _record: &busbar_api::PlaneRecord,
    ) -> busbar_api::StoreResult<()> {
        Err(busbar_api::StoreError(
            "the store is unavailable".to_string(),
        ))
    }
}

/// A store that keeps a real push-callback capability table, so the liveness rules are exercised
/// against something that can actually answer `false`.
///
/// The three columns are the three the rule needs and nothing else: whether the row is there,
/// whether it is still `Active`, and — compared against the `now` and `expires_at` the leg
/// passes — whether it has lapsed. The body is never decoded, exactly as a real backend never
/// decodes one, so nothing here can pass by reading a state out of the bytes that the typed
/// columns were supposed to carry.
#[derive(Default)]
struct CapabilityStore {
    tokens: Mutex<Vec<(String, busbar_api::PlaneDisposition)>>,
    /// Every task body this store was asked to write, in order.
    ///
    /// Kept so a refusal can be asserted to have changed NOTHING, which is the half of "the
    /// callback was refused" that actually protects the customer's task. A refusal that still
    /// wrote the state it was refusing would be a worse defect than the replay it replaced.
    task_writes: Mutex<Vec<Vec<u8>>>,
}

impl CapabilityStore {
    /// Register a live callback token, the way the create-push-config plan does.
    fn register(&self, id: &str) {
        self.tokens
            .lock()
            .expect("tokens lock")
            .push((id.to_string(), busbar_api::PlaneDisposition::Active));
    }

    fn holds(&self, id: &str) -> bool {
        self.tokens
            .lock()
            .expect("tokens lock")
            .iter()
            .any(|(t, _)| t == id)
    }

    fn task_writes(&self) -> Vec<Vec<u8>> {
        self.task_writes.lock().expect("task writes lock").clone()
    }
}

impl busbar_api::Store for CapabilityStore {
    no_governance_rows!();

    fn upsert_plane_record(&self, record: &busbar_api::PlaneRecord) -> busbar_api::StoreResult<()> {
        if record.kind == records::SCHEMA_PUSH_CONFIG.as_str() {
            let mut tokens = self.tokens.lock().expect("tokens lock");
            match tokens.iter_mut().find(|(t, _)| *t == record.id) {
                Some(existing) => existing.1 = record.disposition,
                None => tokens.push((record.id.clone(), record.disposition)),
            }
        }
        if record.kind == records::SCHEMA_TASK.as_str() {
            self.task_writes
                .lock()
                .expect("task writes lock")
                .push(record.body.clone());
        }
        Ok(())
    }

    fn append_plane_record(
        &self,
        _record: &busbar_api::PlaneRecord,
    ) -> busbar_api::StoreResult<()> {
        Ok(())
    }

    fn delete_plane_record(&self, kind: &str, id: &str) -> busbar_api::StoreResult<()> {
        if kind == records::SCHEMA_PUSH_CONFIG.as_str() {
            self.tokens
                .lock()
                .expect("tokens lock")
                .retain(|(t, _)| t != id);
        }
        Ok(())
    }

    fn plane_token_live(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
        now: u64,
    ) -> busbar_api::StoreResult<bool> {
        if kind != records::SCHEMA_PUSH_CONFIG.as_str() {
            return Ok(false);
        }
        Ok(self
            .tokens
            .lock()
            .expect("tokens lock")
            .iter()
            .any(|(t, d)| {
                t == token && matches!(d, busbar_api::PlaneDisposition::Active) && now <= expires_at
            }))
    }
}

/// The key one push callback arrives on.
fn push_key<'a>(id: &'a str, now: u64, expires_at: u64, terminal: bool) -> LegKey<'a> {
    LegKey {
        id,
        parent: Some(id),
        seq: 1,
        ts: now,
        expires_at,
        terminal,
    }
}

/// The record legs of the push-event plan, in the plane's own order.
fn push_event_legs() -> Vec<Leg> {
    vec![
        leg_record(records::SCHEMA_PUSH_CONFIG, records::OP_VERIFY_LIVE),
        leg_record(records::SCHEMA_TASK, records::OP_PUT),
        leg_record(records::SCHEMA_TASK_EVENT, records::OP_APPEND),
        leg_record(records::SCHEMA_PUSH_CONFIG, records::OP_REVOKE),
    ]
}

/// Whether the plan's liveness leg said the token was live.
fn was_live(results: &[LegResult]) -> bool {
    results.first().expect("the liveness leg runs first").live
}

/// **THE REPLAY, CLOSED.** A token captured off one callback is refused once its task has ended.
///
/// This is the defect stated as the customer sees it. The leg used to pass one timestamp as both
/// the deadline and the clock — "is now past now" — which is false for every token ever
/// presented, so the expiry test could not refuse anything; underneath it the neutral verb's
/// default answered `true` unconditionally. A backend agent, or anyone who read one callback off
/// the wire, could keep addressing a finished task with the same bearer indefinitely.
///
/// The sequence is the real one and not a shortcut: a live token carries a non-terminal update,
/// then carries the update that ends the task, and only then is replayed. The replay is asserted
/// to REFUSE THE WHOLE PLAN and to have written nothing — the second half being the half that
/// protects the customer's task, since a refusal that still applied the state it was refusing
/// would be a worse defect than the replay it replaced.
#[test]
fn a_captured_callback_token_is_refused_once_its_task_has_ended() {
    let store = Arc::new(CapabilityStore::default());
    store.register("t-1");
    let legs = RecordLegs::new(store.clone());

    // Still running: the token works, and survives the update.
    let working = legs
        .run_plan(
            &push_event_legs(),
            &push_key("t-1", 100, 3_700, false),
            b"{}",
        )
        .expect("the legs run");
    assert!(was_live(&working), "a live token must carry a live task");
    assert!(store.holds("t-1"), "a task still running keeps its token");

    // The ending: the same token is still good FOR THIS CALLBACK, and is revoked by it.
    let completed = legs
        .run_plan(
            &push_event_legs(),
            &push_key("t-1", 200, 3_700, true),
            b"{}",
        )
        .expect("the legs run");
    assert!(
        was_live(&completed),
        "the callback that ENDS a task is the last honest use of its token, not the first \
         refused one"
    );
    assert!(
        !store.holds("t-1"),
        "the update that made the task terminal must revoke the token, not leave it lying live"
    );

    // And the replay, which is the whole point.
    let wrote_before = store.task_writes().len();
    let replayed = legs.run_plan(
        &push_event_legs(),
        &push_key("t-1", 300, 3_700, false),
        b"{}",
    );
    assert_eq!(
        replayed,
        Err(LegError::TokenNotLive),
        "a token captured off a finished task's callback still moved the task — this is the \
         replay. It must refuse as REVOKED and not as a store outage: the store answered \
         perfectly well, and telling an operator to go and look at a working database is the \
         wrong instruction."
    );
    assert_eq!(
        store.task_writes().len(),
        wrote_before,
        "the refused callback still wrote the task; the check has to STOP the plan, not merely \
         be recorded beside the write it was supposed to prevent"
    );
}

/// **One task, several callbacks, one token.** The check spends nothing.
///
/// The other half of the same bug, and the reason a single-use `redeem` could not simply have
/// been pointed at real arguments: A2A backends report `working`, then `input-required`, then
/// `completed`, so a token spent on the first callback would refuse the two honest ones after it
/// and the customer would lose exactly the notifications push exists to deliver. Three
/// non-terminal updates, one token, three acceptances.
#[test]
fn one_token_carries_every_callback_of_a_task_that_is_still_running() {
    let store = Arc::new(CapabilityStore::default());
    store.register("t-1");
    let legs = RecordLegs::new(store.clone());

    for (nth, now) in [100_u64, 200, 300].into_iter().enumerate() {
        let results = legs
            .run_plan(
                &push_event_legs(),
                &push_key("t-1", now, 3_700, false),
                b"{}",
            )
            .expect("the legs run");
        assert!(
            was_live(&results),
            "callback {} of a task that is still running was refused; the check spent the token",
            nth + 1
        );
    }
    assert!(
        store.holds("t-1"),
        "nothing terminal happened, so nothing should have been revoked"
    );
}

/// **A deadline that is a real deadline.** The lapsed token is refused.
///
/// Terminal revocation alone would leave a token live forever for a task whose backend accepted
/// the work and then went silent — there is no ending to revoke on. So the token is dead at
/// whichever comes first, and this is the other one. The two keys differ ONLY in the clock, so a
/// pass here cannot come from anything but the expiry comparison actually being made.
#[test]
fn a_callback_token_past_its_deadline_is_refused() {
    let store = Arc::new(CapabilityStore::default());
    store.register("t-1");
    let legs = RecordLegs::new(store.clone());

    let inside = legs
        .run_plan(
            &push_event_legs(),
            &push_key("t-1", 3_600, 3_700, false),
            b"{}",
        )
        .expect("the legs run");
    assert!(was_live(&inside), "a token inside its deadline is live");

    let wrote_before = store.task_writes().len();
    let lapsed = legs.run_plan(
        &push_event_legs(),
        &push_key("t-1", 3_701, 3_700, false),
        b"{}",
    );
    assert_eq!(
        lapsed,
        Err(LegError::TokenNotLive),
        "a token one second past its deadline still moved the task; the deadline and the clock \
         are the same number again"
    );
    assert_eq!(
        store.task_writes().len(),
        wrote_before,
        "the lapsed callback still wrote the task"
    );
}

/// **The neutral verb's default REFUSES.** A store that cannot answer must not be read as saying
/// yes.
///
/// `RefusingStore` overrides nothing but the upsert, so the liveness verb here is the trait's own
/// default — which is the posture every deployment whose store predates this verb runs on. For a
/// read, "this store remembers nothing" and "there is nothing to remember" are the same answer;
/// for a capability check they are opposites, and this asserts which one the default takes. The
/// sibling `redeem_plane_token` default is deliberately `Ok(true)` and stays that way — a store
/// that keeps no ledger genuinely has spent nothing — so the two are asserted apart here rather
/// than assumed to agree.
#[test]
fn the_default_liveness_answer_is_a_refusal() {
    use busbar_api::Store as _;

    let store = RefusingStore;
    assert!(
        !store
            .plane_token_live(records::SCHEMA_PUSH_CONFIG.as_str(), "t-1", u64::MAX, 0)
            .expect("the default answers rather than erroring"),
        "the default answered LIVE for a store that keeps no capability rows at all; every \
         deployment on an older store would accept a replayed callback"
    );
    assert!(
        store
            .redeem_plane_token("ask", "n-1", u64::MAX, 0)
            .expect("the default answers"),
        "the single-use redeem's default is the opposite one on purpose, and moving it would \
         break approvals rather than fix a replay"
    );
}

// ─────────────────────────────────────────────────────────────────────
// The configured group reaches the door
// ─────────────────────────────────────────────────────────────────────

/// A key that names no restriction, which is what the guards read as "ask me nothing".
///
/// Every method answers, and none of them answers by accident: the admission step reads none of
/// this, and the value that proves it is a view whose answers cannot admit or refuse anything.
struct UnrestrictedKey;

impl PoolView for UnrestrictedKey {
    fn key_scopes(&self) -> Option<&[String]> {
        None
    }
    fn pool_allowed(&self, _pool: &str) -> bool {
        true
    }
    fn on_exhausted_fallback(&self, _pool: &str) -> Option<String> {
        None
    }
    fn is_configured(&self, _name: &str) -> bool {
        true
    }
    fn pricing_enabled(&self) -> bool {
        false
    }
    fn is_unpriced(&self, _name: &str) -> bool {
        false
    }
    fn has_key(&self) -> bool {
        false
    }
}

/// A breaker with every lane open, so lane health is never the reason a unit in these cells did
/// not reach the door.
struct EveryLaneOpen;

impl BreakerView for EveryLaneOpen {
    fn ready(&self, _pool: &str, _lane: usize, _now: u64) -> bool {
        true
    }
    fn try_admit(
        &self,
        _pool: &str,
        _lane: usize,
        _now: u64,
    ) -> Result<(), busbar_unit_trust::Unavailable> {
        Ok(())
    }
}

/// A deployment whose per-kind rules all pass, so a destination question is never the reason a
/// unit in these cells did not reach the door.
struct EveryKindPasses;

impl KindFacts for EveryKindPasses {
    fn allow_listed(&self, _dest: &DestinationFacts) -> bool {
        true
    }
    fn transport_key_resolves(&self, _dest: &DestinationFacts) -> bool {
        true
    }
    fn lane_permitted_for_op_class(&self, _lane: &str) -> bool {
        true
    }
    fn session_upstream_ok(&self) -> bool {
        true
    }
    fn net_guard_passes(&self, _dest: &DestinationFacts) -> bool {
        true
    }
    fn unit_price_within_max(&self, _dest: &DestinationFacts) -> bool {
        true
    }
    fn breaker_admits(&self, _dest: &DestinationFacts, _at: &BreakerQuery<'_>) -> bool {
        true
    }
    fn session_principal_matches(&self) -> bool {
        true
    }
    fn client_selector_ok(&self) -> bool {
        true
    }
    fn await_deadline_ok(&self) -> bool {
        true
    }
    fn verb_scope_held(&self) -> bool {
        true
    }
    fn nested_plane_ok(&self) -> bool {
        true
    }
    fn plane_record_ok(&self) -> bool {
        true
    }
    fn peer_lease_live(&self) -> bool {
        true
    }
    fn upgrade_ok(&self) -> bool {
        true
    }
}

/// One group, one call at a time — the smallest cap an operator can write.
fn one_call_at_a_time(group: &str) -> busbar_unit_admission::GroupTable {
    let groups = std::collections::BTreeMap::from([(
        group.to_string(),
        busbar_substrate::config::groups::GroupCfg {
            parent: None,
            enabled: true,
            limits: vec![busbar_substrate::config::groups::LimitCfg {
                metric: busbar_substrate::config::groups::LimitMetric::Concurrent,
                amount: 1,
                per: None,
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }],
            child_default: None,
        },
    )]);
    // Through the interner the root uses at boot, so the name the slot records is the same
    // static the vocabulary holds rather than one this fixture invented.
    let mut vocabulary = crate::root::vocabulary::Vocabulary::new();
    let ids = vocabulary.group_ids(&crate::root::vocabulary::ConfigKeys {
        groups: vec![group.to_string()],
        ..crate::root::vocabulary::ConfigKeys::default()
    });
    crate::root::policy::group_table(&groups, &ids)
}

/// Everything the node's half of one A2A unit is assembled from, held together so a cell can
/// borrow from it for the length of the cell.
struct Deployment {
    auth: Auth,
    auth_bindings: crate::root::kernel::auth_bindings::AuthBindings,
    trust: busbar_caps::TrustToken,
    pools: UnrestrictedKey,
    kinds: EveryKindPasses,
    resolver: FixedResolver,
    denylist: busbar_unit_trust::Denylist,
    door: Door<busbar_unit_admission::InMemoryCells>,
    groups: busbar_unit_admission::GroupTable,
    pricer: Pricer,
    records: RecordLegs,
    meter_policy: crate::root::policy::MeterPolicyHandle,
    scope: crate::root::policy::ScopePolicy,
    durability: Mutex<crate::root::durability::Durability>,
    origin: busbar_caps::Origin,
    /// The node's monotonic source, as the composition root holds it: a counter that only ever
    /// goes up, whatever the wall clock does.
    mono: AtomicU64,
}

fn deployment(groups: busbar_unit_admission::GroupTable) -> Deployment {
    deployment_priced(groups, Pricer::flat(0))
}

fn deployment_priced(groups: busbar_unit_admission::GroupTable, pricer: Pricer) -> Deployment {
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_unit_wal::NullShipper::new()),
        Box::new(busbar_unit_ledger::legacy::RecordingRows::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");
    Deployment {
        auth: Auth::new(busbar_unit_auth::AuthChain::new(Vec::new(), false)),
        auth_bindings: crate::root::kernel::auth_bindings::AuthBindings::without_directory(),
        trust: busbar_caps::TrustToken::mint(&busbar_caps::KernelSeal::acquire_for_kernel()),
        pools: UnrestrictedKey,
        kinds: EveryKindPasses,
        resolver: FixedResolver(vec!["203.0.113.7".parse().expect("a public address")]),
        denylist: busbar_unit_trust::Denylist::default(),
        door: Door::new(busbar_unit_admission::InMemoryCells::new()),
        groups,
        pricer,
        records: RecordLegs::new(Arc::new(RecordingStore::default())),
        meter_policy: crate::root::policy::build(&crate::root::policy::MeterPolicyConfig::default()),
        scope: scope_policy(crate::root::policy::ScopePolicy::new()),
        durability: Mutex::new(durability),
        origin: busbar_kernel::teller::Kernel::new().origin(busbar_caps::OriginKind::Client),
        mono: AtomicU64::new(0),
    }
}

impl Deployment {
    /// Resolve one caller's chain, once — the step the root takes where it resolves the caller,
    /// and the only place a chain is built. `None` is the group this node does not have.
    fn resolve(
        &self,
        who: &PrincipalId,
        group: Option<&str>,
    ) -> Option<busbar_unit_admission::BucketChain> {
        self.groups.chain_for(who.as_str(), group).ok()
    }

    /// One unit of this deployment, lent a chain somebody already resolved.
    fn calling<'r>(
        &'r self,
        chain: Option<&'r busbar_unit_admission::BucketChain>,
    ) -> A2aUnits<'r, busbar_unit_admission::InMemoryCells> {
        self.calling_at(chain, 1_700_000_000)
    }

    /// The same unit, arriving at a named wall epoch — so a test can step the wall clock the
    /// way an operator or an NTP correction steps it and watch what the record does.
    fn calling_at<'r>(
        &'r self,
        chain: Option<&'r busbar_unit_admission::BucketChain>,
        now: u64,
    ) -> A2aUnits<'r, busbar_unit_admission::InMemoryCells> {
        A2aUnits::new(
            A2aBindings {
                auth: &self.auth,
                auth_bindings: &self.auth_bindings,
                trust_token: &self.trust,
                pools: &self.pools,
                kinds: &self.kinds,
                breaker: &EveryLaneOpen,
                resolver: &self.resolver,
                guard: GuardPolicy::default(),
                denylist: &self.denylist,
                pinned: &[],
                door: &self.door,
                chain,
                pricer: &self.pricer,
                bytes_nanos: 0,
                records: &self.records,
                meter_policy: &self.meter_policy,
                scope_policy: &self.scope,
                durability: &self.durability,
                pool: "agents",
                now,
                // An hour, which is long enough that no fixture here trips the deadline by
                // accident and short enough that a test meaning to trip it can just step the
                // wall clock past it.
                task_ttl_secs: 3_600,
                // One reading per unit, off the node's own counter, exactly as the root would
                // take it at arrival.
                mono: self.mono.fetch_add(1, Ordering::AcqRel),
                origin: self.origin,
            },
            draft(ops::OP_MESSAGE_SEND),
            Grants::of(Scope::Full),
        )
    }
}

fn a2a_ctx() -> UnitCtx {
    a2a_ctx_from(busbar_caps::OriginKind::Client)
}

fn a2a_ctx_from(origin: busbar_caps::OriginKind) -> UnitCtx {
    UnitCtx {
        key: busbar_caps::UnitKey::new(1),
        origin,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

/// Ask the door for one call, keeping what its yes counted.
fn ask_the_door(
    unit: &A2aUnits<'_, busbar_unit_admission::InMemoryCells>,
    who: &PrincipalId,
) -> (
    Result<busbar_caps::Admission, busbar_caps::Refusal>,
    GroupLeaseSlip,
) {
    ask_the_door_as(unit, who, busbar_caps::OriginKind::Client)
}

/// The same call, under a named origin — the one fact that decides whether a fee is coming.
fn ask_the_door_as(
    unit: &A2aUnits<'_, busbar_unit_admission::InMemoryCells>,
    who: &PrincipalId,
    origin: busbar_caps::OriginKind,
) -> (
    Result<busbar_caps::Admission, busbar_caps::Refusal>,
    GroupLeaseSlip,
) {
    let seal = busbar_caps::KernelSeal::acquire_for_kernel();
    let slip = GroupLeaseSlip::new();
    let decision = Units::admit(
        unit,
        &busbar_caps::UnitToken::mint(&seal),
        &busbar_caps::AdmitToken::mint(&seal),
        &a2a_ctx_from(origin),
        who,
        &[],
        &slip,
    );
    (decision.into_result(&seal), slip)
}

/// **The cap is a cap.** A deployment that wrote `concurrent: 1` against an A2A group gets one
/// agent call in the air at a time: the second is refused while the first is still running, and
/// it is admitted once the first has ended.
///
/// This is the whole point of the chain being the configured one. With an empty chain the door
/// walks no group, raises no gauge and says yes to both — which is what a node whose operator
/// wrote this cap down did, silently, with nothing on any surface to say the limit was inert.
#[test]
fn an_a2a_group_capped_at_one_call_refuses_the_second_and_admits_it_after_the_first_ends() {
    const GROUP: &str = "a2a-team";
    let deployment = deployment(one_call_at_a_time(GROUP));
    let who = PrincipalId::new("vk_agent");

    // Resolved once, where the root resolves the caller. Every unit below reads this one value.
    let chain = deployment.resolve(&who, Some(GROUP));

    let first = deployment.calling(chain.as_ref());
    let (admitted, held) = ask_the_door(&first, &who);
    assert!(admitted.is_ok(), "the first call of a group capped at one");
    assert_eq!(
        held.taken().len(),
        1,
        "and the yes names the one capped group it counted"
    );
    // The count itself, taken onto the slot as the loop takes it. Held for as long as the unit
    // it admitted is running, which is what makes the next line a refusal rather than a second
    // yes.
    let running = held.grant_taken().expect("the yes is holding a count");

    let second = deployment.calling(chain.as_ref());
    let (refused, _) = ask_the_door(&second, &who);
    assert_eq!(
        refused.expect_err("the group is full").reason(),
        ReasonCode::RateLimited,
        "an in-flight gauge is a count cap, not a spend cap"
    );

    // The unit ends: the slot gives back what it held, and the group has room again.
    drop(running);
    let third = deployment.calling(chain.as_ref());
    let (after, _) = ask_the_door(&third, &who);
    assert!(
        after.is_ok(),
        "the cap is instantaneous — it gates what is running, never what has run"
    );
}

/// **The hold reserves the fee the settlement could post, and nothing where it could post
/// none.**
///
/// One deployment, one flat fee, and two units differing in NOTHING but the origin the kernel
/// sealed them under. The caller's unit reserves the fee: it is coming, and a hold that did not
/// cover it would be a promise the settlement could break. The push the agent sent reserves
/// nothing at all, because the evidence that unit will settle from posts no fee — and the draw
/// against a hold is all-or-nothing, so a reservation for money nobody would ever take is a
/// caller refused over quota for a charge that was never going to land.
///
/// Sized by ONE rule, [`fee_could_land`], which reads the same evidence the audit row and the
/// settlement read. Spelled a second time at the door, the two answers drift and the one that
/// drifts is the one nobody re-derived.
#[test]
fn the_hold_reserves_a_fee_only_where_the_settlement_could_post_one() {
    const GROUP: &str = "a2a-team";
    // Five cents a request, and bytes priced at nothing: the fee is the whole of the hold, so
    // what is reserved IS the answer to whether one was sized for.
    const FEE_CENTS: i64 = 5;
    let who = PrincipalId::new("vk_agent");
    let reserved = |origin| {
        let deployment = deployment_priced(one_call_at_a_time(GROUP), Pricer::flat(FEE_CENTS));
        let chain = deployment.resolve(&who, Some(GROUP));
        let unit = deployment.calling(chain.as_ref());
        match ask_the_door_as(&unit, &who, origin)
            .0
            .expect("the group is uncapped on spend, so the door says yes to both")
        {
            busbar_caps::Admission::Own(hold) => hold.reserved(),
            // Nothing held is nothing reserved, which is exactly the answer for a unit priced
            // at zero.
            busbar_caps::Admission::ZeroHold => 0,
            busbar_caps::Admission::Accrual(_) => panic!("this unit has no parent"),
        }
    };

    let fee_nanos = u64::try_from(FEE_CENTS).expect("a positive fee") * NANOS_PER_CENT;
    assert_eq!(
        reserved(busbar_caps::OriginKind::Client),
        fee_nanos,
        "a caller's request is charged the flat fee, so the hold covers it"
    );
    assert_eq!(
        reserved(busbar_caps::OriginKind::Provider),
        0,
        "a push the agent sent posts no fee, so there is nothing for the hold to reserve"
    );
}

/// A caller bound to no group at all is admitted and attributed, and takes no lease: the
/// ordinary posture for a deployment with no `groups:` section, which must not become a
/// refusal because the chain is now resolved.
#[test]
fn an_a2a_caller_bound_to_no_group_is_admitted_and_counted_against_nothing() {
    let deployment = deployment(one_call_at_a_time("a2a-team"));
    let who = PrincipalId::new("vk_agent");
    let chain = deployment.resolve(&who, None);
    assert!(
        chain.is_some(),
        "no group binding still resolves — to one uncapped attribution bucket"
    );
    for _ in 0..3 {
        let unit = deployment.calling(chain.as_ref());
        let (decision, slip) = ask_the_door(&unit, &who);
        assert!(decision.is_ok(), "no group binding is no cap");
        assert!(slip.taken().is_empty(), "and nothing to name on the slot");
    }
}

/// A caller bound to a group this node's configuration does not have is refused, not admitted
/// under caps that could not be read. Fail-closed, and rendered as over-quota, which is what the
/// door itself answers for the same cause.
#[test]
fn an_a2a_caller_bound_to_an_unconfigured_group_is_refused() {
    let deployment = deployment(one_call_at_a_time("a2a-team"));
    let who = PrincipalId::new("vk_agent");
    let chain = deployment.resolve(&who, Some("a-group-this-node-never-had"));
    assert!(chain.is_none(), "the group is not in the table");
    let unit = deployment.calling(chain.as_ref());
    let (decision, _) = ask_the_door(&unit, &who);
    assert_eq!(
        decision
            .expect_err("nothing is admitted under caps that cannot be read")
            .reason(),
        ReasonCode::OverBudget
    );
}

/// **The chain is lent, never rebuilt.** The door is on every unit's path and a chain is a
/// vector of owned bucket ids; resolving one per unit would put that vector, and every string
/// in it, on the admitting path for an answer that cannot change while the caller and the
/// policy epoch stay the same.
///
/// So the binding holds a BORROW. Two units of one caller are handed the same address, which is
/// the property a per-unit `chain_for` cannot have however cheap it looks — the pin is on the
/// reference rather than on an allocation count because this crate has no library target for a
/// counting-allocator test binary to reach.
#[test]
fn two_units_of_one_caller_are_handed_the_same_chain() {
    const GROUP: &str = "a2a-team";
    let deployment = deployment(one_call_at_a_time(GROUP));
    let who = PrincipalId::new("vk_agent");
    let chain = deployment.resolve(&who, Some(GROUP)).expect("configured");

    let first = deployment.calling(Some(&chain));
    let second = deployment.calling(Some(&chain));
    let (Some(one), Some(two)) = (first.bindings.chain, second.bindings.chain) else {
        panic!("both units were lent a chain");
    };
    assert!(
        std::ptr::eq(one, two),
        "one resolved chain, lent twice — not two copies of one answer"
    );
    assert!(std::ptr::eq(one, &chain), "and it is the root's own value");
}

// ------------------------------------------------------------------------------------------------
// THE STATUS LEG THIS PLANE DECLARES, AND THE KERNEL ARM IT REACHES
// ------------------------------------------------------------------------------------------------

/// **THE PLANE SAYS WHERE ITS STATUS IS, AND THIS LEG READS IT.**
#[test]
fn the_leg_carries_the_status_leg_the_plane_declares() {
    let declared = <busbar_plane_a2a::A2aPlane as busbar_contract::plane::PlaneMeta>::STATUS_LEG;
    assert!(
        declared.is_some(),
        "this dialect answers on a frame, so it has a status leg to declare"
    );
    let draft = draft(ops::OP_MESSAGE_SEND);
    let evidence = fee_evidence(&draft, busbar_caps::OriginKind::Client, true);
    assert_eq!(
        evidence.status_at, declared,
        "the leg builds the kernel's evidence from what the plane declares"
    );
}

/// **A TASK LOST MID-STREAM REACHES THE KERNEL'S DISPUTE ARM.**
///
/// The agent accepted the task and the first frame said so; the stream then ends without the task
/// ever reaching a terminal state. The client saw an accepted request and the plane says the unit
/// failed, which is the contradiction the kernel has one arm and one policy for.
#[test]
fn a_task_lost_mid_stream_is_disputed() {
    let mut draft = draft(ops::OP_MESSAGE_SEND);
    draft.streaming = true;
    draft.finish = FinishClass::Error;
    let evidence = fee_evidence(&draft, busbar_caps::OriginKind::Client, true);
    let (fee, flags) = busbar_kernel::teller::fee_count(&evidence);
    assert_eq!(
        fee, 1,
        "the frame the client saw decides the fee, on this plane and on every other"
    );
    assert!(
        flags.contains(busbar_caps::PostingFlags::METER_DISPUTED),
        "the frame the client saw and the plane's finish contradict each other"
    );
}
