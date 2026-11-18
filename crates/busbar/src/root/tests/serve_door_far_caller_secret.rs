// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SINGLE-PATH SP-AU6: from the data door to the far end's route the caller secret is shared,
//! never copied. The unit's steps lend it on the host's unit records at authenticate, and the far
//! end is built with it on its route; neither makes a fresh plaintext buffer. Counted by the
//! dev-only stage probe (`Derive::SecretCopy`) on the actual door steps and door far end.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use busbar_contract::abi::plane::ROUTE_DIRECT;
use busbar_contract::caps::{Dial, PrincipalId};
use busbar_contract::conn::{InstanceId, NeedId};
use busbar_contract::ids::OpClassId;
use busbar_contract::stage_probe::{Derive, Scope};
use busbar_kernel::plane_driver::{DriverSteps as _, Egress, MemberRoute, DEFAULT_ERROR_BODY_MAX};
use busbar_kernel::teller::UnitCtx;
use busbar_kernel::test_hooks::tokens::grant;
use busbar_kernel_egress::ports::DestinationId;
use busbar_kernel_egress::{Failover, Member, OnExhausted, Pool, WeightedFloor};

use super::{BadGateway, Book, Free, Quiet, Wall};
use crate::root::door_steps::{door_facts, egress_pool, DoorCaller, DoorPools, DoorSteps};
use crate::root::serve::DoorFar;

async fn far_end_app() -> busbar_kernel::state::App {
    crate::dist_root_install::install();
    let module = crate::root::test_plugins::linked_store_module();
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {}, "models": {}, "auth": {"chain": []},
            "store": {"module": module, "settings": {}}
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the actual deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual deployment resolves");
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = crate::root::real_store::build_app(
        crate::root::test_plugins::plaintext_listeners(config),
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the actual root builds the far-end generation");
    limits.stage_boot();
    crate::root::kernel::ROOT_CARD
        .keep_in_store(
            app.governance
                .as_ref()
                .expect("the actual deployment configured governance")
                .core_store_handle()
                .expect("the actual configured Store exposes its native history owner"),
            124,
        )
        .expect("native rate history binds");
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .await
        .expect("the actual configured Store boots its rate history");
    limits.keep().await.expect("the actual limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    app
}

fn egress_over(pool_name: &str) -> Egress {
    let destination = DestinationId::new(1);
    Egress {
        caller: InstanceId(9),
        conns: Arc::new(BadGateway::default()),
        breaker: busbar_kernel::plane_driver::fixed_breaker(Arc::new(Book::default())),
        capacity: Arc::new(Free),
        clock: Arc::new(Wall),
        journal: Arc::new(Quiet),
        telemetry: Arc::new(Quiet),
        pools: foldhash::HashMap::from_iter([(
            pool_name.to_owned(),
            Pool {
                name: pool_name.to_owned(),
                members: vec![Member::new(destination, "e", 1)],
                failover: Failover {
                    timeout_secs: 30,
                    max_hops: 1,
                    exclusions: Vec::new(),
                },
                on_exhausted: OnExhausted::Status503,
                floor: WeightedFloor::new(),
                queued: Default::default(),
            },
        )]),
        routes: foldhash::HashMap::from_iter([(
            destination,
            MemberRoute {
                ride_anchors: Vec::new(),
                connection_required: false,
                need: NeedId(0),
                base_url: "https://far.test/".into(),
                auth: None,
                provider: "e".into(),
                keep: Default::default(),
                rides: Vec::new(),
                anchors: Default::default(),
                spelled: Vec::new(),
            },
        )]),
        stream_ceiling_secs: 600,
        stated_ceiling_secs: 0,
        error_body_max: DEFAULT_ERROR_BODY_MAX,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn the_caller_secret_is_shared_from_the_door_to_the_far_ends_route() {
    let app = Arc::new(far_end_app().await);
    let facts = door_facts(
        busbar_kernel::plane_driver::dispatch::LaneQualifier::parse("p").unwrap(),
        &[],
        &[],
        &[],
        "a",
        Vec::new(),
    );
    let section: busbar_contract::yaml::Value =
        busbar_contract::yaml::from_str("e: {}").expect("yaml");
    let pools = DoorPools::of(&section, busbar_contract::section::TOOL_CALL_SECTION_KEY)
        .expect("the pools");
    let records = Arc::new(busbar_kernel::host_units::UnitRecords::default());
    let ctx = UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: busbar_contract::UnitKey::new(1),
        origin: busbar_contract::caps::OriginKind::Client,
        session: None,
        generation: busbar_kernel::registry::Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    };

    let scope = Scope::open();
    let steps = DoorSteps::new(
        &facts,
        &pools,
        Arc::new(|_: &str| None),
        app,
        None,
        DoorCaller {
            principal: PrincipalId::new("vk_one"),
            key: None,
            open: true,
            arrived: 0,
            records: Some(Arc::clone(&records)),
            depth: 0,
            credential: Some(busbar_kernel::auth::CallerCredential::adopted(
                busbar_contract::Secret::new(b"sk-caller-secret".to_vec()),
            )),
            ticket: None,
        },
    );
    assert!(
        steps.authenticate(&ctx).is_ok(),
        "an open claim admits the unit and lends its credential on the unit's record"
    );
    steps.decoded(&ctx, OpClassId::new("op"), ROUTE_DIRECT, Some(b"e"));
    let _ = steps.verify(&grant::<Dial>(), &ctx, &PrincipalId::new("vk_one"));
    let pool_name = egress_pool("p", &steps.routed().expect("the unit is routed to `e`"));
    let egress = egress_over(&pool_name);
    let far = DoorFar {
        accept: Default::default(),
        observations: None,
        authorization: Arc::clone(&records),
        egress: Some(&egress),
        steps: &steps,
        unit: busbar_contract::UnitKey::new(1),
        credential: Some(busbar_kernel::auth::CallerCredential::adopted(
            busbar_contract::Secret::new(b"sk-caller-secret".to_vec()),
        )),
        far: OnceLock::new(),
        shown: None,
    };
    assert!(
        far.far().is_some(),
        "the far end is built over the routed pool, its route carrying the caller secret"
    );

    assert_eq!(
        scope.count(Derive::SecretCopy),
        0,
        "the unit's record and the far end's route share the caller's one buffer; neither copies it"
    );
}
