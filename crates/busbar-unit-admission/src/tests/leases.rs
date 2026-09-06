// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the door's yes SAYS it counted.
//!
//! The gauges an [`AdmitGrant`](crate::decide::AdmitGrant) holds are handles: they say how many
//! groups were counted and they give the counts back, and they can say nothing about which. These
//! cases are about the names beside them — the interned ones the composition root handed the door
//! at registration — because a caller that keeps its own reading of what the node is running has to
//! know which group each count belongs to.
//!
//! The rule every case here defends is that the name takes no part in the decision. A group with an
//! interned name and a group without are counted identically, blocked identically and refused
//! identically; the only difference is whether the answer can be written down elsewhere.

use super::{card, door};
use crate::chain::{GroupBucket, GroupRuntime, GroupTable, STANDARD_TIER_BP};
use crate::decide::{Blocked, Metric};
use crate::window::WINDOW_MINUTE;

/// A group with a concurrency cap, and the interned name the root would have handed over.
fn capped(
    name: &str,
    lease_id: Option<&'static str>,
    cap: u64,
    parent: Option<usize>,
) -> GroupRuntime {
    GroupRuntime {
        name: name.to_string(),
        lease_id,
        enabled: true,
        concurrent_cap: Some(cap),
        tier_bp: STANDARD_TIER_BP,
        buckets: Vec::new(),
        parent,
    }
}

/// The nested pair every case walks: a team inside a tenant, both capped on `concurrent`.
fn tenant_and_team(team_lease: Option<&'static str>) -> GroupTable {
    GroupTable::new(vec![
        capped("tenant", Some("tenant"), 8, None),
        capped("team", team_lease, 4, Some(0)),
    ])
}

/// TWO capped groups, two names, innermost first — the chain's own order, so a reader of the names
/// sees the same walk the decision took.
#[test]
fn a_yes_names_every_capped_group_it_counted() {
    let d = door();
    let p = card(0, &[]);
    let t = tenant_and_team(Some("team"));
    let chain = super::chain(&t, "vk_1", Some("team"));

    let grant = d.try_admit(&p, &chain, "", 0).expect("admitted");

    assert_eq!(grant.held(), 2, "a lease per capped group");
    assert_eq!(grant.group_leases(), ["team", "tenant"]);
}

/// WHAT THE GRANT IS FOR: a group capped at one runs one unit at a time, and only for as long as
/// something holds the yes.
///
/// The `concurrent` cap is enforced by the gauge this grant holds up, and the grant releases it on
/// drop. So the cap is worth exactly the lifetime the CALLER gives the grant: held for the life of
/// the unit it admitted, the second arrival is refused while the first is in the air and admitted
/// once it has ended; dropped where the decision was taken, this cell's middle admission succeeds
/// and the cap has never refused anything.
///
/// The refusal names the group, the `concurrent` metric and no window — a gauge is instantaneous,
/// so there is nothing to roll and nothing to retry after — which is what the renderers read to
/// render it as the rate-limited answer rather than an over-quota one.
#[test]
fn a_group_capped_at_one_refuses_while_the_yes_it_gave_is_still_held() {
    let d = door();
    let p = card(0, &[]);
    let t = GroupTable::new(vec![capped("team", Some("team"), 1, None)]);
    let chain = super::chain(&t, "vk_4", Some("team"));

    let first = d
        .try_admit(&p, &chain, "", 0)
        .expect("the first is admitted");
    assert_eq!(first.held(), 1);
    assert_eq!(d.gauges().in_flight("team"), 1, "the group is running one");

    match d.try_admit(&p, &chain, "", 0) {
        Err(Blocked::Limit {
            group,
            metric,
            window,
            retry_after,
            ..
        }) => {
            assert_eq!(group, "team");
            assert_eq!(metric, Metric::Concurrent);
            assert_eq!(window, None, "a gauge has no window to roll");
            assert_eq!(retry_after, None, "and so nothing to wait for");
        }
        other => panic!("expected the group's concurrency block, got {other:?}"),
    }
    assert_eq!(
        d.gauges().in_flight("team"),
        1,
        "and the refusal counted nothing: the reading is still the one unit"
    );

    // The first unit ends.
    drop(first);
    assert_eq!(d.gauges().in_flight("team"), 0);

    let third = d
        .try_admit(&p, &chain, "", 0)
        .expect("the room the first unit gave back admits the next");
    assert_eq!(third.group_leases(), ["team"]);
}

/// A group the root never interned is counted exactly as before and simply is not named. The count
/// is the decision; the name is the record, and a missing record can never be a missing count.
#[test]
fn a_group_with_no_interned_name_is_still_counted() {
    let d = door();
    let p = card(0, &[]);
    let t = tenant_and_team(None);
    let chain = super::chain(&t, "vk_2", Some("team"));

    let grant = d.try_admit(&p, &chain, "", 0).expect("admitted");

    assert_eq!(grant.held(), 2, "both groups counted");
    assert_eq!(
        grant.group_leases(),
        ["tenant"],
        "only the named one is named"
    );
}

/// A refusal counted nothing, so it names nothing: the grant that would have carried the names is
/// dropped on the way out, and the gauges it took are given back with it.
#[test]
fn a_refusal_names_nothing() {
    let d = door();
    let p = card(0, &[]);
    let mut group = capped("team", Some("team"), 4, None);
    let mut bucket = GroupBucket::new("group:team@60s", WINDOW_MINUTE);
    bucket.requests_cap = Some(1);
    group.buckets.push(bucket);
    let t = GroupTable::new(vec![group]);
    let chain = super::chain(&t, "vk_3", Some("team"));

    // The one request the window allows, and the grant handed straight back.
    drop(
        d.try_admit(&p, &chain, "", 0)
            .expect("the first is admitted"),
    );
    match d.try_admit(&p, &chain, "", 0) {
        Err(Blocked::Limit { metric, .. }) => assert_eq!(metric, Metric::Requests),
        other => panic!("expected a requests block, got {other:?}"),
    }
    // And the gauge it briefly held is back: the next yes counts one, not two.
    let grant = d
        .try_admit(&p, &chain, "", 60_000)
        .expect("the window rolled");
    assert_eq!(grant.held(), 1);
    assert_eq!(grant.group_leases(), ["team"]);
}
