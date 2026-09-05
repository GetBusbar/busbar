// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which destination kinds the flat request fee follows.
//!
//! The rule is the kind's, not the price's: a client unit whose route selected an upstream posts
//! the fee with no rate card configured at all, and every other kind posts nothing unless the card
//! prices it. That makes the answer below money-affecting, so it is written as a decision per
//! variant rather than a spot check — a new kind cannot default into either side of it.

use busbar_contract::{
    ClientMode, DestinationFacts, LaneId, OpClassId, RecordSchemaId, StreamId, UpstreamAddress,
    UpstreamIdx,
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
