// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::{
    ClientMode, DestinationFacts, LaneId, OpClassId, RecordSchemaId, StreamId, UpstreamAddress,
    UpstreamIdx, VerifiedDestination,
};

fn lane() -> LaneId {
    LaneId::new("gold")
}

fn seal() -> busbar_contract::caps::Pass<busbar_contract::caps::Verify> {
    busbar_contract::caps::Pass::mint(&busbar_contract::caps::KernelSeal::acquire_for_kernel())
}

#[test]
fn walking_down_a_transport_stack_carries_the_seal_and_widens_nothing() {
    let sealed = VerifiedDestination::seal(
        &seal(),
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

    let twice = under
        .beneath("tcp", UpstreamAddress::socket("10.0.0.1:443"))
        .expect("still an upstream");
    assert_eq!(twice.lane(), sealed.lane());
    assert_eq!(twice.budget_remaining(), sealed.budget_remaining());

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
        let sealed = VerifiedDestination::seal(&seal(), facts, "http", Some(17));
        assert!(
            sealed
                .beneath("tcp", UpstreamAddress::socket("10.0.0.1:443"))
                .is_none(),
            "{facts:?} has no layer beneath it"
        );
    }
}
