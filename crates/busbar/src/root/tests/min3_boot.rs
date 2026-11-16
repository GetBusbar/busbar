// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PLANE-SERVICES: what the MIN-3 boot installs into each plane seat's intents. The plane itself is an ffi handle,
//! so the request path runs in the image suite (W2-SW-PLANE e2e); these are the seams the boot builds.

use std::time::{Duration, Instant};

use busbar_kernel::plane_grants::{TicketAdmitted, TicketDenied, TicketMint};
use busbar_plugin_abi::plane::DEST_INTERNAL;

use super::*;

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
    let services = plane_services(&shared(), None);
    assert!(services.judge.is_some(), "JUDGE answers, fail closed without a judge");
    assert!(services.observations.is_some(), "OBS_SCOPE and OBSERVE have their custody");
    assert!(services.tickets.is_some(), "MINT has the late ticket store");
    // Not built at boot: each answers its fail-closed value until its owner installs it.
    assert!(services.entitlements.is_none());
    assert!(services.signer.is_none());
    assert!(services.connections.is_none());
    assert!(services.trust.is_none());
    assert!(services.media.is_none());
}

#[tokio::test]
async fn a_process_with_no_destination_judge_answers_internal_for_every_destination() {
    let judge = plane_services(&shared(), None).judge.unwrap();
    let verdict = judge
        .judge("example.com", 0, 0, Instant::now() + Duration::from_secs(1))
        .await;
    assert_eq!(verdict, DEST_INTERNAL);
}

#[test]
fn tickets_are_shut_until_the_signing_key_resolves_and_open_for_every_seat_after() {
    let shared = shared();
    let services = plane_services(&shared, None);
    let tickets = services.tickets.unwrap();
    assert!(!tickets.is_ticket("bbt1.abc"), "no host key yet: nothing is a ticket");
    shared.tickets.install(Arc::new(Open));
    assert!(
        tickets.is_ticket("bbt1.abc"),
        "a seat built before the key resolved sees the installed store"
    );
    assert!(!tickets.is_ticket("Bearer-token"));
}

#[tokio::test]
async fn a_mint_with_no_ticket_store_is_unavailable_not_a_made_up_ticket() {
    let tickets = LateTickets::default();
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
