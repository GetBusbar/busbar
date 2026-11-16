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
    // The retained generation owns its mint inputs even after the outer AppHandle drops.
    drop(handle);
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

/// `source`'s key's held tickets, and whether its unit holds a pending one.
fn indexed(source: &ReservedSource) -> (usize, bool) {
    let entries = source.owner.custody.entries.lock().unwrap();
    (
        entries
            .by_key
            .get(source.key.id.as_str())
            .map_or(0, std::collections::BTreeSet::len),
        entries.pending.contains_key(&source.unit),
    )
}

/// streams-mint T4 (guard): every path that releases custody (claim, an unacknowledged terminal,
/// the owner's drop, the sweep after expiry, shutdown) leaves the key and unit indexes in step
/// with the map, and a saturated key's retry is its own earliest expiry plus one sweep cycle.
#[tokio::test]
async fn every_custody_release_keeps_the_key_and_unit_indexes_in_step() {
    use busbar_kernel::governance::TicketRefusal;
    let _one = PUBLISHING.lock().await;
    let g = governed("ticket-index-paths", true).await;

    let claimed = reserved_source(&g, "ticket-index-claim").await;
    let (credential, _) = mint_reserved_source(&g, &claimed, claimed.now).await;
    assert_eq!(indexed(&claimed), (1, true), "a bound ticket is pending");
    claimed.money.settle_end(claimed.unit, 200);
    claimed.owner.custody.terminal(claimed.unit, true);
    assert_eq!(
        indexed(&claimed),
        (1, false),
        "an acknowledged ticket is ready"
    );
    let identity = g
        .gov
        .prepare_ticket_redemption_async("custody_test", &credential, claimed.now)
        .await
        .unwrap();
    drop(
        claimed
            .owner
            .custody
            .claim(&identity)
            .expect("the ready ticket is claimed"),
    );
    assert_eq!(
        indexed(&claimed),
        (0, false),
        "a claim releases both indexes"
    );

    let burned = reserved_source(&g, "ticket-index-burn").await;
    mint_reserved_source(&g, &burned, burned.now).await;
    burned.money.settle_end(burned.unit, 200);
    burned.owner.custody.terminal(burned.unit, false);
    assert_eq!(
        indexed(&burned),
        (0, false),
        "an unacknowledged end burns it"
    );

    let owned = reserved_source(&g, "ticket-index-owner").await;
    mint_reserved_source(&g, &owned, owned.now).await;
    let custody = Arc::clone(&owned.owner.custody);
    let (key, unit) = (Arc::clone(&owned.key), owned.unit);
    drop(owned);
    {
        let entries = custody.entries.lock().unwrap();
        assert!(
            !entries.by_key.contains_key(key.id.as_str()) && !entries.pending.contains_key(&unit),
            "the owner's drop releases its pending ticket from both indexes"
        );
    }

    let swept = reserved_source(&g, "ticket-index-sweep").await;
    let at = busbar_kernel::store::now();
    let (_, expiry) = g
        .gov
        .mint_ticket_bound(
            &swept.key.id,
            "custody_test",
            2,
            None,
            b"opaque",
            at,
            |identity| swept.owner.custody.bind(&swept.owner.source, identity),
        )
        .await
        .expect("a live ticket is minted");
    swept.money.settle_end(swept.unit, 200);
    swept.owner.custody.terminal(swept.unit, true);
    tokio::time::sleep(std::time::Duration::from_secs(
        expiry
            .saturating_sub(busbar_kernel::store::now())
            .saturating_add(1),
    ))
    .await;
    swept.owner.custody.sweep().await;
    assert_eq!(
        indexed(&swept),
        (0, false),
        "the sweep releases an expired ticket"
    );

    let early = reserved_source(&g, "ticket-index-early").await;
    let late = reserved_source(&g, "ticket-index-late").await;
    let at = busbar_kernel::store::now();
    let mint = |source: &ReservedSource, ttl: u64| {
        let custody = Arc::clone(&source.owner.custody);
        let owned = Arc::clone(&source.owner.source);
        let key = source.key.id.clone();
        let gov = Arc::clone(&g.gov);
        async move {
            gov.mint_ticket_bound(&key, "custody_test", ttl, None, b"opaque", at, |identity| {
                custody.bind(&owned, identity)
            })
            .await
            .expect("a ticket under every cap")
            .1
        }
    };
    let early_expiry = mint(&early, 30).await;
    let late_expiry = mint(&late, 90).await;
    assert!(
        early_expiry < late_expiry,
        "another key holds the earlier expiry"
    );
    let admits = |per_key| {
        late.owner
            .custody
            .entries
            .lock()
            .unwrap()
            .admits(late.key.id.as_str(), per_key, at)
    };
    assert_eq!(
        admits(1),
        Err(TicketRefusal::KeySaturated {
            retry_after_secs: u32::try_from(late_expiry - at + 16).unwrap(),
        }),
        "a saturated key's retry is its own earliest expiry plus one sweep cycle"
    );
    assert_eq!(admits(2), Ok(()), "under its cap the key is admitted");

    late.owner.custody.shutdown();
    let entries = late.owner.custody.entries.lock().unwrap();
    assert!(
        entries.tickets.is_empty() && entries.by_key.is_empty() && entries.pending.is_empty(),
        "shutdown releases every index"
    );
    drop(entries);
    drop((claimed, burned, swept, early));
}
