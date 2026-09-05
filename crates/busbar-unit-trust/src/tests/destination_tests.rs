// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which kinds each origin may reach, and the per-kind rules.

use crate::destination::{
    kind_permitted, kind_rule_passes, DestinationFacts, DestinationKind, KindFacts, OriginKind,
};

/// Facts that say yes to everything, so a test can turn exactly one answer off and see it land.
pub(crate) struct AllYes {
    pub(crate) allow_listed: bool,
    pub(crate) transport_key: bool,
    pub(crate) lane_permitted: bool,
    pub(crate) session_upstream: bool,
    pub(crate) session_principal: bool,
    pub(crate) client_selector: bool,
    pub(crate) await_deadline: bool,
    pub(crate) verb_scope: bool,
    pub(crate) nested: bool,
    pub(crate) record: bool,
    pub(crate) peer_lease: bool,
    pub(crate) upgrade: bool,
}

impl Default for AllYes {
    fn default() -> Self {
        AllYes {
            allow_listed: true,
            transport_key: true,
            lane_permitted: true,
            session_upstream: true,
            session_principal: true,
            client_selector: true,
            await_deadline: true,
            verb_scope: true,
            nested: true,
            record: true,
            peer_lease: true,
            upgrade: true,
        }
    }
}

impl KindFacts for AllYes {
    fn allow_listed(&self, _d: &DestinationFacts) -> bool {
        self.allow_listed
    }
    fn transport_key_resolves(&self, _d: &DestinationFacts) -> bool {
        self.transport_key
    }
    fn lane_permitted_for_op_class(&self, _lane: &str) -> bool {
        self.lane_permitted
    }
    fn session_upstream_ok(&self) -> bool {
        self.session_upstream
    }
    fn session_principal_matches(&self) -> bool {
        self.session_principal
    }
    fn client_selector_ok(&self) -> bool {
        self.client_selector
    }
    fn await_deadline_ok(&self) -> bool {
        self.await_deadline
    }
    fn verb_scope_held(&self) -> bool {
        self.verb_scope
    }
    fn nested_plane_ok(&self) -> bool {
        self.nested
    }
    fn plane_record_ok(&self) -> bool {
        self.record
    }
    fn peer_lease_live(&self) -> bool {
        self.peer_lease
    }
    fn upgrade_ok(&self) -> bool {
        self.upgrade
    }
}

pub(crate) fn dest(kind: DestinationKind) -> DestinationFacts {
    DestinationFacts {
        kind,
        lane: "lane-a".to_string(),
        lane_index: Some(0),
    }
}

#[test]
fn a_client_reaches_everything_but_peers_and_session_accrual() {
    use DestinationKind::*;
    for kind in [
        Upstream,
        SessionUpstream,
        Client,
        KernelVerb,
        NestedPlane,
        PlaneRecord,
        Upgrade,
    ] {
        assert!(kind_permitted(OriginKind::Client, &kind), "{kind:?}");
    }
    assert!(!kind_permitted(OriginKind::Client, &Peer));
    assert!(!kind_permitted(OriginKind::Client, &SessionAccrual));
}

#[test]
fn a_provider_push_can_never_address_a_verb() {
    use DestinationKind::*;
    for kind in [Client, SessionUpstream, NestedPlane, PlaneRecord] {
        assert!(kind_permitted(OriginKind::Provider, &kind), "{kind:?}");
    }
    for kind in [KernelVerb, Upstream, Peer, Upgrade, SessionAccrual] {
        assert!(!kind_permitted(OriginKind::Provider, &kind), "{kind:?}");
    }
}

#[test]
fn an_arrival_reaches_nothing_and_a_bootstrap_only_its_verb() {
    use DestinationKind::*;
    for kind in [
        Upstream,
        SessionUpstream,
        Client,
        KernelVerb,
        NestedPlane,
        PlaneRecord,
        Peer,
        Upgrade,
        SessionAccrual,
    ] {
        assert!(!kind_permitted(OriginKind::Arrival, &kind), "{kind:?}");
    }
    assert!(kind_permitted(OriginKind::Bootstrap, &KernelVerb));
    assert!(!kind_permitted(OriginKind::Bootstrap, &Upstream));
}

#[test]
fn a_handshake_reaches_only_an_upgrade_or_the_client_it_is_challenging() {
    use DestinationKind::*;
    assert!(kind_permitted(OriginKind::Handshake, &Upgrade));
    assert!(kind_permitted(OriginKind::Handshake, &Client));
    assert!(!kind_permitted(OriginKind::Handshake, &Upstream));
    assert!(!kind_permitted(OriginKind::Handshake, &KernelVerb));
}

#[test]
fn the_heartbeat_reaches_nothing_but_a_session_accrual() {
    use DestinationKind::*;
    assert!(kind_permitted(OriginKind::Tick, &SessionAccrual));
    for kind in [Upstream, Client, KernelVerb, NestedPlane, Peer] {
        assert!(!kind_permitted(OriginKind::Tick, &kind), "{kind:?}");
    }
}

#[test]
fn a_nested_call_never_goes_sideways_into_a_verb() {
    use DestinationKind::*;
    for kind in [Upstream, SessionUpstream, NestedPlane, PlaneRecord, Client] {
        assert!(kind_permitted(OriginKind::Nested, &kind), "{kind:?}");
    }
    assert!(!kind_permitted(OriginKind::Nested, &KernelVerb));
    assert!(!kind_permitted(OriginKind::Nested, &SessionAccrual));
}

#[test]
fn a_delivery_may_deliver_hop_or_dial_and_nothing_else() {
    use DestinationKind::*;
    for kind in [Client, Peer, Upstream] {
        assert!(kind_permitted(OriginKind::Delivery, &kind), "{kind:?}");
    }
    assert!(!kind_permitted(OriginKind::Delivery, &KernelVerb));
    assert!(!kind_permitted(OriginKind::Delivery, &SessionAccrual));
}

#[test]
fn an_upstream_needs_the_allow_list_the_key_and_the_lane() {
    let d = dest(DestinationKind::Upstream);
    assert!(kind_rule_passes(&d, &AllYes::default()));
    for (label, facts) in [
        (
            "not allow-listed",
            AllYes {
                allow_listed: false,
                ..AllYes::default()
            },
        ),
        (
            "no transport key",
            AllYes {
                transport_key: false,
                ..AllYes::default()
            },
        ),
        (
            "lane not permitted for the operation class",
            AllYes {
                lane_permitted: false,
                ..AllYes::default()
            },
        ),
    ] {
        assert!(!kind_rule_passes(&d, &facts), "{label}");
    }
}

#[test]
fn a_session_upstream_needs_the_pairing_and_the_principal() {
    let d = dest(DestinationKind::SessionUpstream);
    assert!(kind_rule_passes(&d, &AllYes::default()));
    assert!(!kind_rule_passes(
        &d,
        &AllYes {
            session_principal: false,
            ..AllYes::default()
        }
    ));
    assert!(!kind_rule_passes(
        &d,
        &AllYes {
            session_upstream: false,
            ..AllYes::default()
        }
    ));
}

#[test]
fn a_client_destination_needs_the_selector_and_the_deadline() {
    let d = dest(DestinationKind::Client);
    assert!(kind_rule_passes(&d, &AllYes::default()));
    assert!(!kind_rule_passes(
        &d,
        &AllYes {
            client_selector: false,
            ..AllYes::default()
        }
    ));
    assert!(!kind_rule_passes(
        &d,
        &AllYes {
            await_deadline: false,
            ..AllYes::default()
        }
    ));
}

#[test]
fn the_verb_scope_check_always_runs() {
    let d = dest(DestinationKind::KernelVerb);
    assert!(kind_rule_passes(&d, &AllYes::default()));
    assert!(
        !kind_rule_passes(
            &d,
            &AllYes {
                verb_scope: false,
                ..AllYes::default()
            }
        ),
        "the scope question is asked whatever the posture; the posture only changes the answer"
    );
}

#[test]
fn the_remaining_kinds_each_carry_their_own_rule() {
    for (kind, facts) in [
        (
            DestinationKind::NestedPlane,
            AllYes {
                nested: false,
                ..AllYes::default()
            },
        ),
        (
            DestinationKind::PlaneRecord,
            AllYes {
                record: false,
                ..AllYes::default()
            },
        ),
        (
            DestinationKind::Peer,
            AllYes {
                peer_lease: false,
                ..AllYes::default()
            },
        ),
        (
            DestinationKind::Upgrade,
            AllYes {
                upgrade: false,
                ..AllYes::default()
            },
        ),
    ] {
        let d = dest(kind.clone());
        assert!(kind_rule_passes(&d, &AllYes::default()), "{kind:?}");
        assert!(!kind_rule_passes(&d, &facts), "{kind:?}");
    }
}
