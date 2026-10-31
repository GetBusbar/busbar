// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! EVERY ADMIN UNIT SEALS ONE RECORD ON THE FIXED AUDIT CHAIN (audit R2#2, row 159): THE DESIGN §1,
//! "The audit step writes one fixed record, for every plane", and U14, one audit record per unit,
//! a refused unit included. The admin units' audit door handed its facts and pass back to a step
//! that dropped them, so no admin unit, a key mint included, was ever on `/audit/range`.

use super::*;

/// A dispatch whose every operation answers 200.
struct Answers;

impl AdminDispatch for Answers {
    fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
        AdminAnswer {
            status: 200,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: b"{}".to_vec(),
        }
    }
}

/// A key no other request in this binary is walking.
fn a_fresh_unit() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn request(method: &str, path: &str) -> AdminRequest {
    AdminRequest {
        method: method.to_string(),
        path: path.to_string(),
        credential: None,
        headers: Vec::new(),
        body: Vec::new(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    }
}

/// Walk `request` through an admin node whose door is `door`: the answer, and every record the
/// node's book holds afterwards.
fn walk(door: AdminDoorFn, request: AdminRequest) -> (AdminAnswer, Vec<AuditRecord>) {
    let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(Answers), door);
    let book = Arc::clone(&units.durability);
    let answer = AdminNode::new(crate::root::kernel::new_kernel(), units).answer(request);
    let mut held = Vec::new();
    NodeAudit::new(book).read(&mut |_, records| {
        held = records.map(<[_]>::to_vec).unwrap_or_default();
    });
    (answer, held)
}

/// AN ADMITTED ADMIN UNIT SEALS ONE RECORD, naming the unit, the operation class its audit door
/// stated, and how it ended.
#[test]
fn an_admitted_admin_unit_seals_one_record() {
    let walked = request("POST", "/api/v1/admin/keys");
    let unit = UnitKey::new(walked.unit);
    let (answer, records) = walk(open_door(), walked);
    assert_eq!(answer.status, 200, "the open door admits the mint");
    assert_eq!(
        records.len(),
        1,
        "an admin unit sealed {} records on the chain; one per unit",
        records.len()
    );
    let record = &records[0];
    assert_eq!(record.what.unit_key, unit);
    assert_eq!(record.outcome.unit_end, Outcome::Completed);
    assert_eq!(record.wall, 1_700_000_000);
}

/// A REFUSED ADMIN UNIT SEALS A RECORD TOO (U14: "a refused unit gets a record too"): the arrival,
/// never a principal nobody resolved, refused at the step that refused it.
#[test]
fn a_refused_admin_unit_seals_a_refused_record() {
    let walked = request("POST", "/api/v1/admin/keys");
    let unit = UnitKey::new(walked.unit);
    let refusing: AdminDoorFn = Arc::new(|_: &AdminRequest| {
        busbar_kernel::auth::AdminVerdict::from(busbar_kernel::auth::AdminDoor::Denied)
    });
    let (answer, records) = walk(refusing, walked);
    assert_eq!(answer.status, 401, "the door refuses the caller");
    assert_eq!(
        records.len(),
        1,
        "a refused admin unit sealed {} records on the chain; one per unit",
        records.len()
    );
    let record = &records[0];
    assert_eq!(record.what.unit_key, unit);
    assert!(
        matches!(record.outcome.unit_end, Outcome::Refused(..)),
        "the record says the unit was refused: {:?}",
        record.outcome.unit_end
    );
    assert_eq!(
        record.subject,
        busbar_kernel_audit::Subject::Arrival,
        "nobody was resolved, so the record names the arrival"
    );
}

/// THE PRODUCTION RECORD SINK WRITES THROUGH THE STORE'S V3 CALLS (C6): the record the admin
/// `plane-records` write hands the sink lands in the governance store's plane records, read back
/// through the same calls; governance whose store has no v3 calls keeps nothing and says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_live_record_sink_writes_through_the_store_calls() {
    busbar_kernel::snapshot::init();
    use busbar_contract::records::{PlaneDisposition, PlaneRecord};
    use busbar_contract::store_calls::StoreDoor;
    let opened = busbar_kernel::test_support::store_axis_stand_in()
        .open(
            StoreDoor::Linked(busbar_kernel::test_support::store_double::door),
            busbar_kernel::test_support::store_double::NAME,
            b"{}",
        )
        .expect("the store double opens through its door");
    let calls = opened
        .calls
        .clone()
        .expect("a door-opened store has its calls");
    let gov = std::sync::Arc::new(
        busbar_kernel::governance::GovState::new(opened.records, None).expect("governance"),
    );
    assert!(gov.attach_store_calls(std::sync::Arc::clone(&calls)));
    let app = busbar_kernel::test_support::TestApp::new()
        .governance(gov)
        .build();
    let sink = live_records(std::sync::Arc::new(busbar_kernel::state::AppHandle::new(
        app,
    )));
    let record = |id: &str| PlaneRecord {
        kind: "sink-probe".to_string(),
        id: id.to_string(),
        parent: None,
        seq: 0,
        ts: 1_700_000_000,
        disposition: PlaneDisposition::Active,
        body: b"{\"v\":1}".to_vec(),
    };
    let written = record("r1");
    tokio::task::spawn_blocking(move || sink(&written))
        .await
        .expect("the sink ran")
        .expect("the record is written");
    let back = crate::root::durability::wait_for(calls.get_plane_record("sink-probe", "r1"))
        .expect("the record reads back");
    assert_eq!(back, Some(b"{\"v\":1}".to_vec()));

    let bare = std::sync::Arc::new(
        busbar_kernel::governance::GovState::new(
            std::sync::Arc::new(busbar_kernel::governance::MemoryStore::new()),
            None,
        )
        .expect("governance"),
    );
    let app = busbar_kernel::test_support::TestApp::new()
        .governance(bare)
        .build();
    let sink = live_records(std::sync::Arc::new(busbar_kernel::state::AppHandle::new(
        app,
    )));
    let unkept = record("r2");
    assert!(
        tokio::task::spawn_blocking(move || sink(&unkept))
            .await
            .expect("the sink ran")
            .is_err(),
        "a store with no v3 calls keeps nothing and says so"
    );
}
