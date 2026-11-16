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

fn shared() -> Shared {
    Shared::new(Records::default(), LatePush::default())
}

#[test]
fn every_seat_is_given_the_services_the_boot_can_build_and_no_more() {
    let services = plane_services(&shared(), Arc::new(Open), None);
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
    let judge = plane_services(&shared(), Arc::new(ClosedTickets), None)
        .judge
        .unwrap();
    let verdict = judge
        .judge("example.com", 0, 0, Instant::now() + Duration::from_secs(1))
        .await;
    assert_eq!(verdict, DEST_INTERNAL);
}

#[test]
fn tickets_are_shut_without_a_signing_key_and_open_with_one() {
    let records = Records::default();
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
    let services = plane_services(&shared(), Arc::new(Open), None);
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
fn the_boot_s_upstream_table_is_the_configured_upstreams_section() {
    use busbar_kernel::upstreams::Upstreams;
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {},
            "models": {},
            "upstreams": {
                "docs": {"url": "https://docs.example/mcp", "auth": "corp-outbound"},
                "local": {"command": {"argv": ["/opt/mcp/server"]}},
            },
        }),
        &busbar_kernel::config::Grammar::empty(),
    )
    .expect("a config with an upstreams section parses");
    let cfg =
        busbar_kernel::config::resolve(&deploy, &Default::default()).expect("the config resolves");
    let table = configured_upstreams(&cfg).expect("the table types");
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
    let configured = AtRestCfg {
        key: SecretRef::None,
        previous: None,
    };
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
    assert!(no_key.contains("Add an at-rest"), "{no_key}");

    publish_at_rest(Some(&configured), |what, _| async move {
        Err(format!("{what} could not be resolved (Denied)"))
    })
    .await;
    assert_eq!(
        admit_for_host(3),
        Err("CONFIG: the at-rest key could not be resolved (Denied)".to_owned())
    );
    assert_eq!(admit_for_host(0), Ok(()), "no recoverable row asks nothing");
}
