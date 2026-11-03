// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_live_record_sink_writes_through_the_store_calls() {
    crate::dist_root_install::install();
    use busbar_contract::records::{PlaneDisposition, PlaneRecord};
    let store = crate::root::real_store::store();
    let calls: std::sync::Arc<dyn busbar_contract::store_calls::StoreCalls> = store.clone();
    let gov = std::sync::Arc::new(
        busbar_kernel::governance::GovState::new(store, None).expect("governance"),
    );
    assert!(gov.attach_store_calls(std::sync::Arc::clone(&calls)));
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual Store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "admin-unit-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut built, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        crate::root::test_plugins::trusted_config(&directory),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the product builds the actual admin application");
    limits.keep().expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    built.governance = Some(gov);
    let app = std::sync::Arc::new(built);
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
        busbar_kernel::governance::GovState::new(crate::root::real_store::records(), None)
            .expect("governance"),
    );
    crate::dist_root_install::install();
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built Store"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual Store statement reads")
        .expect("the actual Store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual Store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual Store library reads");
    let directory = crate::root::test_plugins::scratch(&format!(
        "admin-unit-{}",
        busbar_kernel::door::op_id().counter(),
    ));
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.join("store.tar.gz"), archive).expect("stage the actual Store");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("actual Store settings are JSON");
    assert!(
        settings.is_object(),
        "the actual Store settings are an object"
    );
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {}, "models": {},
        "auth": {"chain": [], "admin_auth": []},
        "store": {"module": module, "settings": settings},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
    }))
    .expect("the real admin deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the real admin deployment resolves");
    let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
        as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (mut built, rotate, limits) = busbar_kernel::build_app_from_config(
        config,
        crate::root::test_plugins::trusted_config(&directory),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .expect("the product builds the actual admin application");
    limits.keep().expect("the real application limits commit");
    if let Some(rotate) = rotate {
        rotate();
    }
    built.governance = Some(bare);
    let app = std::sync::Arc::new(built);
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
