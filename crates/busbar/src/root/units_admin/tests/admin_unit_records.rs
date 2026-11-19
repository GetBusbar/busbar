// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

struct Answers;

#[async_trait::async_trait]
impl AdminDispatch for Answers {
    async fn execute(&self, _verb: KernelVerb, _request: &AdminRequest) -> AdminAnswer {
        AdminAnswer {
            status: 200,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: b"{}".to_vec(),
        }
    }
}

fn a_fresh_unit() -> u64 {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

fn request(method: &str, path: &str) -> AdminRequest {
    AdminRequest::test_fixture(crate::root::units_admin::TestAdminRequest {
        method: method.to_string(),
        path: path.to_string(),
        credential: None,
        headers: Vec::new(),
        body: Vec::new(),
        at: 1_700_000_000,
        unit: a_fresh_unit(),
    })
}

async fn walk(door: AdminDoorFn, request: AdminRequest) -> (AdminAnswer, Vec<AuditRecord>) {
    let units = crate::root::kernel::ProductionUnits::admin_only(Arc::new(Answers), door).await;
    let book = Arc::clone(&units.durability);
    let answer = AdminNode::new(crate::root::kernel::new_kernel(), units)
        .answer(request)
        .await;
    let mut held = Vec::new();
    NodeAudit::new(book).read(&mut |_, records| {
        held = records.map(<[_]>::to_vec).unwrap_or_default();
    });
    (answer, held)
}

#[tokio::test]
async fn an_admitted_admin_unit_seals_one_record() {
    let walked = request("POST", "/api/v1/admin/keys");
    let unit = UnitKey::new(walked.unit);
    let (answer, records) = walk(operator_door(), walked).await;
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

/// Clock standard: an admin record's `mono` is the node's monotonic reading taken for this
/// operation, never its unit key standing in for one (a unit key orders nothing on the node's
/// clock and repeats across boots).
#[tokio::test]
async fn an_admin_record_stamps_the_node_monotonic_reading_not_its_unit_key() {
    let mut walked = request("POST", "/api/v1/admin/keys");
    // Far above any reading this process's node has taken, so it cannot fall in the window.
    walked.unit = (1u64 << 48) + a_fresh_unit();
    let unit = walked.unit;
    let node = crate::root::plane_node::node();
    let before = node.checked_mono().unwrap();
    let (_, records) = walk(operator_door(), walked).await;
    let after = node.checked_mono().unwrap();
    let record = records
        .iter()
        .find(|record| record.what.unit_key.get() == unit)
        .expect("the admin unit sealed its record");
    assert_ne!(
        record.mono, unit,
        "the record's monotonic stamp is its unit key"
    );
    assert!(
        before < record.mono && record.mono < after,
        "the record's mono {} is not the node's reading between {before} and {after}",
        record.mono
    );
    assert_eq!(record.wall, 1_700_000_000, "the arrival's one wall reading");
}

#[tokio::test]
async fn a_refused_admin_unit_seals_a_refused_record() {
    let walked = request("POST", "/api/v1/admin/keys");
    let unit = UnitKey::new(walked.unit);
    let refusing: AdminDoorFn = Arc::new(|_: &AdminRequest| {
        Box::pin(std::future::ready(busbar_kernel::auth::AdminVerdict::from(
            busbar_kernel::auth::AdminDoor::Denied,
        )))
    });
    let (answer, records) = walk(refusing, walked).await;
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

/// An administrative action is answered only after its record is committed: while the store
/// holds the commit the answer is not given, and it is given once the commit lands.
#[tokio::test]
async fn an_admin_action_is_answered_only_after_its_record_is_committed() {
    use busbar_kernel::persistence::journal::{BufferBudget, RuntimeJournal};
    let budget = BufferBudget {
        records: 64,
        bytes: 1024 * 1024,
    };
    let faults = crate::root::store_double::NativeFaults::open().await;
    let backend: Arc<dyn busbar_contract::persistence::PersistenceBackend> = faults.clone();
    let core = crate::root::real_store::core_over(backend).await;
    let journal = RuntimeJournal::open(core, 1, budget).await.unwrap();
    let book = crate::root::durability::node_book(journal.clone(), budget)
        .await
        .unwrap();
    let units = crate::root::kernel::ProductionUnits::admin_only_sharing(
        Arc::new(Answers),
        operator_door(),
        Arc::clone(&book.durability),
        None,
    );
    let committed_before = journal.read_records(budget).await.unwrap().len();
    faults.pause(true);
    let node = AdminNode::new(crate::root::kernel::new_kernel(), units);
    let answering = node.answer(request("POST", "/api/v1/admin/keys"));
    tokio::pin!(answering);
    tokio::time::timeout(std::time::Duration::from_millis(200), &mut answering)
        .await
        .expect_err("no answer while the record's commit is held");
    assert!(
        faults.waiting() > 0,
        "the store's commit is what it waits on"
    );
    assert!(
        journal.pending_records() > 0,
        "its record is staged, not committed"
    );
    faults.pause(false);
    let answer = tokio::time::timeout(std::time::Duration::from_secs(5), answering)
        .await
        .expect("answered once the commit lands");
    assert_eq!(answer.status, 200);
    assert_eq!(
        journal.read_records(budget).await.unwrap().len(),
        committed_before + 1,
        "the answer followed its committed record"
    );
}

#[tokio::test]
async fn the_live_record_sink_writes_through_the_canonical_core_store() {
    use busbar_contract::records::{PlaneDisposition, PlaneRecord};
    use busbar_kernel::host_records_async::AsyncHistory;
    let core = crate::root::real_store::core().await;
    let sink = live_records(Arc::clone(&core));
    let decl = busbar_contract::plane::PlaneDeclaration {
        key: "sink-probe",
        fallback: false,
        config_section: "sink-probe",
        scope_kinds: &[],
        subject_noun: "probe",
        admin_noun: "probe",
        audit_kind: "probe",
        card_signing_domain: None,
        card_kid_prefix: None,
        owned_config_sections: &[],
        billable_classes: &[],
        class_parents: &[],
        fee_units: &[],
        metric_families: &[],
        record_kinds: &["note"],
        required_config_sections: &[],
        trust_keys: &[],
        served_op_classes: &[],
        caller_credential_refusal: None,
    };
    let kind = busbar_kernel::store::plane_view::plane_owned_kind(decl.key, "note").unwrap();
    let written = PlaneRecord {
        kind: kind.clone(),
        id: "r1".into(),
        parent: Some("opaque-metadata".into()),
        seq: 0,
        ts: 1_700_000_000,
        disposition: PlaneDisposition::Active,
        body: vec![0, 255, 1],
    };
    sink(&decl, &written).await.expect("canonical record write");
    let history = AsyncHistory::authorized_upserts(
        Arc::clone(&core),
        "busbar.admin.envelopes/sink-probe",
        [kind.clone()],
    )
    .expect("authorized envelope reader");
    assert_eq!(
        history.get(&kind, "r1").await.unwrap(),
        Some(written.clone())
    );

    // A cloned sink retains the same canonical owner; no legacy business Store
    // attachment or blocking worker is needed to publish its next envelope.
    let next_sink = Arc::clone(&sink);
    let mut next = written.clone();
    next.id = "r2".into();
    next_sink(&decl, &next).await.expect("same canonical owner");
    assert_eq!(history.get(&kind, "r2").await.unwrap(), Some(next));

    let mut foreign = written;
    foreign.kind = "undeclared".into();
    assert!(
        sink(&decl, &foreign).await.is_err(),
        "undeclared schema is refused"
    );
    assert_eq!(
        history.get(&kind, "r1").await.unwrap().unwrap().body,
        vec![0, 255, 1]
    );
}
