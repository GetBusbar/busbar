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
    let refusing: AdminDoorFn = Arc::new(|_: &AdminRequest| busbar_kernel::auth::AdminDoor::Denied);
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
