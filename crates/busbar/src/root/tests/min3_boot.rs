// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PLANE-SERVICES: what the MIN-3 boot installs into each plane seat's intents. The plane itself is an ffi handle,
//! so the request path runs in the image suite (W2-SW-PLANE e2e); these are the seams the boot builds.

use std::time::{Duration, Instant};

use busbar_kernel::plane_grants::{TicketAdmitted, TicketDenied, TicketMint};
use busbar_plugin_abi::plane::DEST_INTERNAL;

use super::*;

#[test]
fn a_refused_compiled_image_refuses_boot_instead_of_falling_back() {
    use busbar_plugin_loader::refusal::{Refusal, RefusalCode};
    let rows = [super::super::linked::LinkedImage {
        alias: "fixture",
        admit: || {
            Err(Refusal::new(
                RefusalCode::Layout,
                "layout",
                "old",
                "current",
            ))
        },
    }];
    let refusal = admit_linked_images(&rows).err().expect("boot must refuse");
    assert!(refusal.contains("layout"), "{refusal}");
    assert!(refusal.contains("old"), "{refusal}");
    assert!(refusal.contains("current"), "{refusal}");
}

struct Open;

impl Tickets for Open {
    fn mint<'a>(
        &'a self,
        _: &'a LoaderCaller<'_>,
        _: TicketMint<'a>,
    ) -> BoxFut<'a, Result<(Box<str>, u64), RecordsDenied>> {
        Box::pin(core::future::ready(Ok(("bbt1.minted".into(), 99))))
    }

    fn is_ticket(&self, credential: &str) -> bool {
        credential.starts_with("bbt1.")
    }

    fn admit<'a>(
        &'a self,
        _: &'a LoaderCaller<'_>,
        _: &'a str,
        _: &'a str,
        _: u64,
    ) -> BoxFut<'a, Result<TicketAdmitted, TicketDenied>> {
        Box::pin(core::future::ready(Err(TicketDenied::Invalid)))
    }
}

fn observations() -> ObsCustody {
    ObsCustody::new(Arc::new(busbar_kernel::store::now_ms))
}

#[test]
fn every_seat_is_given_the_services_the_boot_can_build_and_no_more() {
    let services = plane_services(&observations(), Arc::new(Open), None);
    assert!(
        services.judge.is_some(),
        "JUDGE answers, fail closed without a judge"
    );
    assert!(
        services.observations.is_some(),
        "OBS_SCOPE and OBSERVE have their custody"
    );
    assert!(
        services.tickets.is_some(),
        "MINT has the ticket store the seat was built with"
    );
    // Not built at boot: each answers its fail-closed value until its owner installs it.
    assert!(services.entitlements.is_none());
    assert!(services.signer.is_none());
    assert!(services.connections.is_none());
    assert!(services.trust.is_none());
    assert!(services.media.is_none());
}

#[tokio::test]
async fn a_process_with_no_destination_judge_answers_internal_for_every_destination() {
    let judge = plane_services(&observations(), Arc::new(ClosedTickets), None)
        .judge
        .unwrap();
    let verdict = judge
        .judge("example.com", 0, 0, Instant::now() + Duration::from_secs(1))
        .await;
    assert_eq!(verdict, DEST_INTERNAL);
}

#[test]
fn tickets_are_shut_without_a_signing_key_and_open_with_one() {
    let records = BootstrapRecords;
    let shut = ticket_store(&records, None);
    assert!(
        !shut.is_ticket("bbt1.abc"),
        "no host key: nothing is a ticket"
    );
    let signing = SecureVec::from(&[7u8; 32][..]);
    let keyed = ticket_store(&records, Some(&signing));
    assert!(
        !keyed.is_ticket("Bearer-token"),
        "a credential that is not a ticket is never one"
    );
    let services = plane_services(&observations(), Arc::new(Open), None);
    let tickets = services.tickets.unwrap();
    assert!(tickets.is_ticket("bbt1.abc"));
    assert!(!tickets.is_ticket("Bearer-token"));
}

#[tokio::test]
async fn a_mint_with_no_ticket_store_is_unavailable_not_a_made_up_ticket() {
    let tickets = ClosedTickets;
    let who = busbar_kernel::plane_driver::port_intents::Namespace {
        plugin: "plane-x".into(),
        name: "x".into(),
        instance: 1,
        slot: 0,
    };
    let minted = tickets
        .mint(
            &who.caller(),
            TicketMint {
                subject: "alice",
                scope: "s",
                audience: "a",
                ttl_s: 60,
                once: false,
                prefix: "",
                record: &[],
            },
        )
        .await;
    assert!(matches!(minted, Err(RecordsDenied::Unavailable)));
    let admitted = tickets.admit(&who.caller(), "a", "bbt1.x", 1).await;
    assert!(matches!(admitted, Err(TicketDenied::Unavailable)));
}

#[test]
fn work_is_opened_only_for_a_target_on_the_instances_recovery_routes() {
    let matches = recovery_matcher(vec!["/v1/jobs/{id}".into(), "/v1/batches/{id}/poll".into()]);
    assert!(matches("/v1/jobs/42"));
    assert!(matches("/v1/jobs/42?cursor=7"));
    assert!(matches("/v1/batches/b1/poll"));
    assert!(!matches("/v1/jobs"));
    assert!(!matches("/v1/jobs/42/extra"));
    assert!(!matches("/v1/other"));
    assert!(!matches(""));
    assert!(!recovery_matcher(Vec::new())("/v1/jobs/42"));
}

fn plane(identity: &str, alias: &str) -> PlaneImage {
    PlaneImage {
        identity: identity.to_owned(),
        alias: alias.to_owned(),
    }
}

/// W2-SW-PLANE: every admitted MIN-3 plane image is one configured plane instance (the operator serves a plane by
/// serving it, IF §12.23 rule 1), named by its manifest alias (today's plane name, IF §12.10), configured with the
/// document's section of that name (its 1.5.x bag, which the plane's own `migrate` converts) or `{}`.
#[test]
fn each_admitted_plane_image_is_one_instance_named_by_its_alias_with_its_section() {
    let mut sections = std::collections::BTreeMap::new();
    sections.insert(
        "mcp",
        busbar_contract::yaml::from_str::<busbar_contract::yaml::Value>(
            "canonical_uri: https://tools.example\n",
        )
        .unwrap(),
    );
    let planes = plane_instances(
        &[
            plane("busbar-plane-mcp", "mcp"),
            plane("busbar-plane-x", ""),
        ],
        &sections,
    )
    .unwrap();
    assert_eq!(planes.len(), 2);
    assert!(planes.iter().all(|p| matches!(p.kind, KindCode::Plane)));
    assert_eq!(
        (planes[0].identity.as_str(), planes[0].name.as_str()),
        ("busbar-plane-mcp", "mcp")
    );
    assert_eq!(
        audience_of(&planes[0].config).as_deref(),
        Some("https://tools.example"),
        "the plane's section reaches it, so its line session binds the audience it states"
    );
    assert_eq!(
        (planes[1].identity.as_str(), planes[1].name.as_str()),
        ("busbar-plane-x", "busbar-plane-x"),
        "an image with no alias is named by its identity"
    );
    assert_eq!(planes[1].config, b"{}");
}

#[test]
fn two_plane_images_answering_one_instance_name_are_refused() {
    let refusal = plane_instances(
        &[
            plane("busbar-plane-a", "dup"),
            plane("busbar-plane-b", "dup"),
        ],
        &std::collections::BTreeMap::new(),
    )
    .err()
    .expect("one instance name, two images");
    assert!(refusal.contains("`dup`"), "{refusal}");
}

/// K7: the boot's one upstream table is the config's `upstreams:` section, each entry typed with its binding
/// (IF §12.1), so every plane seat's walk and carrier compose over what the operator configured.
#[test]
fn the_boot_types_only_the_declared_registration_table() {
    use busbar_kernel::upstreams::Upstreams;
    let split = busbar_kernel::upstreams::declared(
        "plane",
        &busbar_contract::json::json!({
            "servers": {
                "docs": {"url": "https://docs.example/mcp", "auth": "corp-outbound"},
                "local": {"command": {"argv": ["/opt/mcp/server"]}},
            },
        }),
        &["/servers/*"],
        &busbar_kernel::plugin_config::upstream_anchor,
    )
    .expect("declared registrations parse");
    let table = split.definitions;
    assert_eq!(table.names().collect::<Vec<_>>(), ["docs", "local"]);
    let docs = table.get("docs").expect("docs is configured");
    assert_eq!(docs.url.as_deref(), Some("https://docs.example/mcp"));
    assert_eq!(
        docs.auth.as_ref().map(|auth| &*auth.instance),
        Some("corp-outbound")
    );
    assert!(table
        .get("local")
        .expect("local is configured")
        .command
        .is_some());
}

/// (sl3) on the MIN-3 path the recoverable gate knows the at-rest key while the store opens: the walk publishes
/// what `credentials.at_rest` resolved to through the open secret instances (2a) before the store's open (2b),
/// so a 1.5.5 store holding SigV4 credentials is admitted when a key is configured. With no block the gate
/// answers TEXT_ADD_KEY; a key that does not resolve answers the resolution's own text. One test: the verdict is
/// the process's.
#[tokio::test]
async fn the_recoverable_gate_sees_the_walks_at_rest_key_while_the_store_opens() {
    use crate::root::migrate::admit_for_host;
    let configured = SecretRef::None;
    let hex = "ab".repeat(32);
    publish_at_rest(Some(&configured), |_, _| {
        let hex = hex.clone();
        async move { Ok(SecureVec::from(hex.into_bytes())) }
    })
    .await;
    assert_eq!(
        admit_for_host(3),
        Ok(()),
        "a configured key admits the store's recoverable rows"
    );

    publish_at_rest(None, |_, _| async { Err("nothing is resolved".to_owned()) }).await;
    let no_key = admit_for_host(3).unwrap_err();
    assert!(no_key.contains("Set `auth.signing_key`"), "{no_key}");

    publish_at_rest(Some(&configured), |what, _| async move {
        Err(format!("{what} could not be resolved (Denied)"))
    })
    .await;
    assert_eq!(
        admit_for_host(3),
        Err("CONFIG: the signing key could not be resolved (Denied)".to_owned())
    );
    assert_eq!(admit_for_host(0), Ok(()), "no recoverable row asks nothing");
}

#[test]
fn configured_secret_instances_use_bound_image_and_implicit_empty_settings() {
    use busbar_contract::abi::mechanism::door::REWRITE_SUGAR;
    use busbar_kernel::config::grammar::SecretSource;
    use std::collections::BTreeMap;
    let mut sugars = busbar_contract::secret_ref::Sugars::default();
    sugars
        .declare(
            "fixture-secret",
            &[(REWRITE_SUGAR, "probe".into(), "key".into())],
        )
        .unwrap();
    let source = SecretSource {
        identity: "fixture-secret".into(),
        ref_schema: r#"{"type":"object"}"#.into(),
    };
    let grammar = busbar_kernel::config::Grammar::new(sugars, BTreeMap::new(), Vec::new())
        .with_secret_sources(BTreeMap::from([("fixture-secret".into(), source)]));
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: fixture-store, settings: {}}\nproviders: {}\nmodels: {}\n",
        &grammar,
    )
    .unwrap();
    let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    cfg.grammar = busbar_kernel::config::grammar::GrammarField::bound(
        grammar.bind_secret_instances(&cfg.secrets).unwrap(),
    );
    let implicit = configured(&cfg, &[]).unwrap();
    let secret = implicit
        .iter()
        .find(|item| item.kind == KindCode::Secret)
        .unwrap();
    assert_eq!(secret.name, "probe");
    assert_eq!(secret.identity, "fixture-secret");
    assert_eq!(secret.config, b"{}");
    assert_eq!(ref_schemas(&cfg).unwrap()[0].0.as_ref(), "probe");
}

#[test]
fn every_named_export_enters_the_reserved_instance_plan_with_authoring_settings() {
    let grammar =
        busbar_kernel::config::Grammar::new(Default::default(), Default::default(), Vec::new());
    let deploy = busbar_kernel::config::deploy_from_yaml_str(
        "store: {module: fixture-store, settings: {}}\nproviders: {}\nmodels: {}\n",
        &grammar,
    )
    .unwrap();
    let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default()).unwrap();
    cfg.grammar = busbar_kernel::config::grammar::GrammarField::bound(grammar);
    for name in ["first", "second"] {
        cfg.export_defs.insert(
            name.into(),
            busbar_contract::yaml::from_str(
                "module: fixture-export\nsettings: {path: /var/log/busbar/export.jsonl}\n",
            )
            .unwrap(),
        );
    }
    let instances = configured(&cfg, &[]).unwrap();
    let exports: Vec<_> = instances
        .iter()
        .filter(|one| one.kind == KindCode::Export)
        .collect();
    assert_eq!(
        exports
            .iter()
            .map(|one| one.name.as_str())
            .collect::<Vec<_>>(),
        ["first", "second"]
    );
    for export in exports {
        assert_eq!(export.identity, "fixture-export");
        assert_eq!(
            busbar_contract::json::parse_value(&export.config).unwrap(),
            busbar_contract::json::json!({"path": "/var/log/busbar/export.jsonl"})
        );
    }
}

#[test]
fn actual_plane_settlement_has_its_core_owned_block_and_described_lift_authority() {
    let instance = Configured {
        kind: KindCode::Plane,
        identity: "image".to_owned(),
        name: "plane".to_owned(),
        config: b"{}".to_vec(),
        limits: Default::default(),
    };
    let described = busbar_plugin_loader::instance::Described {
        kind: KindCode::Plane,
        methods: 0,
        facts: 0,
        items: vec![(
            busbar_plugin_abi::records::tag::D_SECRET_PATH,
            b"/token".to_vec(),
        )],
        schema: None,
        metrics: Vec::new(),
        error_codes_refused: None,
    };
    let raw = busbar_plugin_loader::instance::Settled {
        config_json: SecureVec::from(&br#"{"token":"literal","display":"public"}"#[..]),
        core_cfg: Vec::new(),
    };
    let answer = settlement::answer(7, &instance, &described, raw).unwrap();
    assert_eq!(answer.index, 7);
    assert_eq!(answer.path, ["plane"]);
    assert_eq!(answer.placement, busbar_migrate::BagPlacement::Block);
    assert_eq!(
        answer.allowed_lifts.into_iter().collect::<Vec<_>>(),
        ["/token"]
    );
    assert!(answer.settings.unwrap().as_str().contains("literal"));
}

#[test]
fn plugin_secret_paths_cannot_authorize_consumed_core_nonsecret_fields() {
    let instance = Configured {
        kind: KindCode::Plane,
        identity: "image".to_owned(),
        name: "plane".to_owned(),
        config: b"{}".to_vec(),
        limits: Default::default(),
    };
    let described = busbar_plugin_loader::instance::Described {
        kind: KindCode::Plane,
        methods: 0,
        facts: 0,
        items: vec![
            (
                busbar_plugin_abi::records::tag::D_UPSTREAM_PATH,
                b"/members/*".to_vec(),
            ),
            (
                busbar_plugin_abi::records::tag::D_SECRET_PATH,
                b"/members/x/url".to_vec(),
            ),
            (
                busbar_plugin_abi::records::tag::D_SECRET_PATH,
                b"/members/x/opaque".to_vec(),
            ),
        ],
        schema: None,
        metrics: Vec::new(),
        error_codes_refused: None,
    };
    let raw = busbar_plugin_loader::instance::Settled {
        config_json: SecureVec::from(&br#"{"members":{"x":{"url":"https://public","opaque":"plugin-secret","auth":{"bearer":"core-secret"}}}}"#[..]),
        core_cfg: Vec::new(),
    };
    let answer = settlement::answer(7, &instance, &described, raw).unwrap();
    assert_eq!(
        answer.allowed_lifts.into_iter().collect::<Vec<_>>(),
        ["/members/x/auth/bearer", "/members/x/opaque"]
    );
}
