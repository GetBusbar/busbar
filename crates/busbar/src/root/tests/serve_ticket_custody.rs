// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ticket custody is partitioned per key: one key's unredeemed tickets never lock another key
//! out, an open plane unit holds no minting slot, and a saturated key writes nothing.

use super::*;
use crate::root::durability::tests::NativeFixture;

/// An ungrouped key's cost: no limit stands between its admissions.
fn unlimited() -> Arc<CostModel> {
    Arc::new(CostModel::resolve_parts(None, 0, &BTreeMap::new()))
}

/// A fresh ungrouped key, as the host resolves it.
async fn ungrouped_key(g: &Governed, name: &str, now: u64) -> Arc<VirtualKey> {
    let (key, _) = g
        .gov
        .mint_signed_async(
            NewKeySpec {
                name: name.to_owned(),
                ..Default::default()
            },
            4_000_000_000,
            now,
        )
        .await
        .expect("the actual governor mints the key");
    g.gov
        .lookup_by_sub(&key.id)
        .expect("the host resolves the actual stored key")
}

/// The commits that put a `ticket` record: its schema is a framed part of the record's key.
fn ticket_record_commits(faults: &crate::root::store_double::NativeFaults) -> usize {
    use busbar_contract::persistence::Mutation;
    let kind = busbar_kernel::governance::TICKET_RECORD_KIND.as_bytes();
    let mut framed = u32::try_from(kind.len())
        .expect("a short schema")
        .to_be_bytes()
        .to_vec();
    framed.extend_from_slice(kind);
    faults
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|prepared| {
            prepared.candidate().mutations.iter().any(|mutation| {
                matches!(mutation, Mutation::Put { address, .. }
                    if address.key.windows(framed.len()).any(|w| w == framed.as_slice()))
            })
        })
        .count()
}

/// RED-BEFORE-GREEN (streams-mint T2): every plane unit registers a ticket source for its whole
/// life, minting or not. A node-wide cap on registrations let one key's open units refuse every
/// other key's mints; only a duplicate unit is refused.
#[tokio::test]
async fn registering_more_units_than_the_custody_cap_refuses_none() {
    let _one = PUBLISHING.lock().await;
    let g = governed("ticket-register-uncapped", true).await;
    let now = busbar_kernel::store::now();
    let key = ungrouped_key(&g, "ticket-register-uncapped", now).await;
    let live = g.served.planes[0].live.current();
    let node = g.post.node();
    let owners: Vec<_> = (0..4_097)
        .map(|_| {
            node.ticket_custody.register(
                node.mint(),
                Some(&key),
                &g.served.planes[0],
                &live,
                &g.app,
            )
        })
        .collect();
    let refused = owners.iter().filter(|owner| owner.is_none()).count();
    assert_eq!(
        refused, 0,
        "4,097 live units of one key register; {refused} were refused"
    );
}

/// RED-BEFORE-GREEN (streams-mint T3): one key mints its 256 unredeemed tickets; its 257th is
/// refused before anything is written, not written and then deleted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_saturated_key_is_refused_before_its_ticket_record_is_written() {
    use busbar_kernel::host_services::TicketPress as _;
    let _one = PUBLISHING.lock().await;
    let fixture = NativeFixture::new(busbar_kernel::door::op_id().counter()).await;
    let book = Arc::new(std::sync::Mutex::new(fixture.book().await));
    let node = Arc::new(Node::new());
    node.bind_book(Arc::clone(&book));
    let g = governed_full(
        "ticket-key-saturated",
        true,
        None,
        Screen::Nothing,
        Some((Arc::clone(&node), Arc::clone(&book), fixture.core.clone())),
        None,
        false,
    )
    .await;
    let now = busbar_kernel::store::now();
    let key = ungrouped_key(&g, "ticket-key-saturated", now).await;
    let cost = unlimited();
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(Arc::clone(&g.app)));
    let press = crate::root::serve::LiveTickets(Arc::downgrade(&handle));
    let caller = busbar_contract::services::Caller::for_test(
        Arc::from(g.served.planes[0].instance.as_str()),
        busbar_contract::abi::mechanism::KindCode::Plane,
    );
    let mut held = Vec::new();
    for n in 0..256 {
        let source = reserved_source_for(&g, Arc::clone(&key), Arc::clone(&cost), "", now);
        let minted = press
            .mint_for_unit(
                source.unit.get(),
                &caller,
                &key,
                "custody_test",
                600,
                b"opaque",
                now,
            )
            .await;
        assert!(minted.is_ok(), "mint {n} is under the per-key cap");
        held.push(source);
    }
    let written = ticket_record_commits(&fixture.faults);
    assert!(
        written >= 256,
        "each held ticket's record was committed ({written} seen)"
    );
    let source = reserved_source_for(&g, Arc::clone(&key), Arc::clone(&cost), "", now);
    let refused = press
        .mint_for_unit(
            source.unit.get(),
            &caller,
            &key,
            "custody_test",
            600,
            b"opaque",
            now,
        )
        .await;
    assert!(
        refused.is_err(),
        "the key's 257th unredeemed ticket is refused"
    );
    assert_eq!(
        ticket_record_commits(&fixture.faults),
        written,
        "a saturated key commits no ticket record"
    );
    drop((source, held));
}
