// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a destination's kind decides: which of them carry the flat request fee, and which of them
//! have a transport layer beneath them.
//!
//! Both rules are the KIND's rather than a caller's. The fee follows the kind, not the price: a
//! client unit whose route selected an upstream posts the fee with no rate card configured at all,
//! and every other kind posts nothing unless the card prices it. Re-addressing carries a seal down
//! a transport stack, and may never widen where a unit can go on the way. Both are written here as
//! a decision per variant rather than a spot check, so a new kind cannot default into either.

use busbar_contract::{
    ClientMode, DestinationFacts, LaneId, OpClassId, RecordSchemaId, StreamId, UpstreamAddress,
    UpstreamIdx, VerifiedDestination,
};

fn lane() -> LaneId {
    LaneId::new("gold")
}

#[test]
fn every_destination_kind_decides_whether_it_carries_the_fee() {
    let upstream = DestinationFacts::Upstream {
        transport: "http",
        address: UpstreamAddress::socket("api.example:443"),
        lane: lane(),
    };
    let session_upstream = DestinationFacts::SessionUpstream {
        upstream: UpstreamIdx(0),
        stream: Some(StreamId(1)),
        lane: lane(),
    };
    let client = DestinationFacts::Client {
        selector: "caller",
        mode: ClientMode::Deliver,
    };
    let kernel_verb = DestinationFacts::KernelVerb { verb: "health" };
    let nested = DestinationFacts::NestedPlane {
        plane: "llm",
        op: OpClassId::new("chat"),
    };
    let accrual = DestinationFacts::SessionAccrual { lane: lane() };
    let record = DestinationFacts::PlaneRecord {
        schema: RecordSchemaId::new("notes"),
        op: "put",
    };
    let peer = DestinationFacts::Peer {
        node: "b",
        selector: "caller",
    };
    let upgrade = DestinationFacts::Upgrade { to: "ws" };

    // The match is over the value rather than a list so that adding a variant fails to compile here
    // until somebody decides which side of the fee line it falls on.
    for facts in [
        upstream,
        session_upstream,
        client,
        kernel_verb,
        nested,
        accrual,
        record,
        peer,
        upgrade,
    ] {
        let expected = match facts {
            DestinationFacts::Upstream { .. } | DestinationFacts::SessionUpstream { .. } => true,
            DestinationFacts::Client { .. }
            | DestinationFacts::KernelVerb { .. }
            | DestinationFacts::NestedPlane { .. }
            | DestinationFacts::SessionAccrual { .. }
            | DestinationFacts::PlaneRecord { .. }
            | DestinationFacts::Peer { .. }
            | DestinationFacts::Upgrade { .. } => false,
        };
        assert_eq!(
            facts.is_upstream_kind(),
            expected,
            "{facts:?} fell on the wrong side of the fee line"
        );
    }
}

struct Seal;

impl busbar_contract::plugin::KernelSeal for Seal {
    fn seal_origin(&self) -> &'static str {
        "busbar-contract::tests"
    }
}

/// Re-addressing a sealed destination for the layer beneath it carries every judgement the trust
/// unit made, unchanged.
///
/// A composed transport dials through the layer below it, and that layer reads a socket address
/// where this one reads a URL. Only the spelling of where the bytes go may change: if the lane or
/// the remaining budget could be rewritten on the way down, walking a stack would be a way to widen
/// where a unit may go without ever being sealed again.
#[test]
fn walking_down_a_transport_stack_carries_the_seal_and_widens_nothing() {
    let sealed = VerifiedDestination::seal(
        &Seal,
        DestinationFacts::Upstream {
            transport: "ws",
            address: UpstreamAddress::socket("api.example:443"),
            lane: lane(),
        },
        "ws",
        Some(17),
    );

    let under = sealed
        .beneath("http", UpstreamAddress::socket("10.0.0.1:443"))
        .expect("an upstream has a layer beneath it");
    assert_eq!(under.lane(), sealed.lane(), "the priced lane travels down");
    assert_eq!(under.budget_remaining(), sealed.budget_remaining());
    assert_eq!(under.transport(), "http", "the lower layer dials it");
    assert_eq!(
        under.facts(),
        DestinationFacts::Upstream {
            transport: "http",
            address: UpstreamAddress::socket("10.0.0.1:443"),
            lane: lane(),
        }
    );

    // Twice down a stack — ws over http over tcp — still carries the original judgement.
    let twice = under
        .beneath("tcp", UpstreamAddress::socket("10.0.0.1:443"))
        .expect("still an upstream");
    assert_eq!(twice.lane(), sealed.lane());
    assert_eq!(twice.budget_remaining(), sealed.budget_remaining());

    // Nothing else has a layer beneath it, written as a decision per kind so a new kind cannot
    // default into having one.
    for facts in [
        DestinationFacts::Client {
            selector: "caller",
            mode: ClientMode::Deliver,
        },
        DestinationFacts::SessionUpstream {
            upstream: UpstreamIdx(0),
            stream: Some(StreamId(1)),
            lane: lane(),
        },
        DestinationFacts::KernelVerb { verb: "health" },
        DestinationFacts::NestedPlane {
            plane: "llm",
            op: OpClassId::new("chat"),
        },
        DestinationFacts::SessionAccrual { lane: lane() },
        DestinationFacts::PlaneRecord {
            schema: RecordSchemaId::new("notes"),
            op: "put",
        },
        DestinationFacts::Peer {
            node: "b",
            selector: "caller",
        },
        DestinationFacts::Upgrade { to: "ws" },
    ] {
        let sealed = VerifiedDestination::seal(&Seal, facts, "http", Some(17));
        assert!(
            sealed
                .beneath("tcp", UpstreamAddress::socket("10.0.0.1:443"))
                .is_none(),
            "{facts:?} has no layer beneath it"
        );
    }
}
