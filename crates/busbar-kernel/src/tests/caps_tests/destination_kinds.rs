// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What a destination's kind decides about the transport layer beneath it: re-addressing carries a
//! seal down a transport stack, and may never widen where a unit can go on the way.
//!
//! Moved here from `busbar-contract/tests/destination_kinds.rs`: sealing a destination takes a
//! minted token, and a token constructor is spelled only inside the kernel (construction
//! `token-sealed`). The fee-line test in that file needs no token and stayed with the contract.

use busbar_contract::{
    ClientMode, DestinationFacts, LaneId, OpClassId, RecordSchemaId, StreamId, UpstreamAddress,
    UpstreamIdx, VerifiedDestination,
};

fn lane() -> LaneId {
    LaneId::new("gold")
}

// A REAL capability token, not a fixture seal: `Pass<Verify>` is one of the two
// types this crate implements the sealed `KernelSeal` for (#65).
fn seal() -> busbar_contract::caps::Pass<busbar_contract::caps::Verify> {
    busbar_contract::caps::Pass::mint(&busbar_contract::caps::KernelSeal::acquire_for_kernel())
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
