// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SEAM, from this crate's side: which classes have left the dispatch table, what the carrier
//! each transport supplies says, and the double every other battery in this crate is served
//! through.
//!
//! **What this file does NOT judge, deliberately.** Whether the door admits, whether the budget is
//! drawn, whether the audit row is sealed — those are the composition root's, they are proved by the
//! root's own cells (`crates/busbar/src/root/tests/node_mcp.rs`) and by the end-to-end battery
//! against the real binary (`crates/busbar/tests/mcp_stdio_serve.rs`), and a plane crate that
//! asserted them would be marking its own governance homework with a node it wrote itself.

use super::double::install_test_node;
use super::{installed, Carrier};

/// **THE CLASSES THAT HAVE LEFT THE DISPATCH TABLE**, and the seam is what answers them.
///
/// The structural half of the move, asserted where it cannot be faked: the node's own table names a
/// document for this class, which is only true for a class whose arm is gone — `document_for`'s rows
/// and `method::dispatch`'s arms are complements by construction, and a class in both would be two
/// serving paths.
#[test]
fn the_moved_classes_are_served_through_the_node_and_no_longer_by_the_dispatch_table() {
    assert!(
        super::document_for(busbar_plane_mcp::ops::OP_TOOLS_LIST).is_some(),
        "tools/list is a class the node has taken, so its document is named in the node's table"
    );
    assert!(
        super::document_for(busbar_plane_mcp::ops::OP_RESOURCES_LIST).is_some(),
        "resources/list is the second class the node has taken, so its document is named here too"
    );
    assert!(
        super::document_for(busbar_plane_mcp::ops::OP_PROMPTS_LIST).is_some(),
        "prompts/list is the third class the node has taken, so its document is named here too"
    );
    assert!(
        super::document_for(busbar_plane_mcp::ops::OP_RESOURCE_TEMPLATES_LIST).is_some(),
        "resources/templates/list is the fourth class the node has taken, so its document is here"
    );
    assert!(
        super::document_for(busbar_plane_mcp::ops::OP_COMPLETION).is_some(),
        "completion/complete is the fifth class the node has taken, so its document is named here"
    );
    assert!(
        super::document_for(busbar_plane_mcp::ops::OP_TOOL_CALL).is_none(),
        "tools/call has NOT moved: it is the last class, and it still has its arm"
    );
    assert!(
        super::document_for(busbar_plane_mcp::ops::OP_DISCOVER).is_none(),
        "server/discover has not moved either; a class with a row here and an arm there would be \
         two serving paths"
    );
}

/// A class the node has taken is not answered at all when nothing is installed.
///
/// The property that makes the deletion real rather than nominal: there is no fallback. This cell
/// can only observe it through the table, because the double is installed process-wide by the time
/// any battery runs — so what it asserts is the SHAPE of the decision (`served` needs a node) rather
/// than re-running it.
#[test]
fn the_seam_needs_a_node_and_carries_no_fallback() {
    install_test_node();
    assert!(
        installed(),
        "this test binary installs the double, which is what every other battery here is served \
         through"
    );
}

/// **THE CARRIER EACH TRANSPORT SUPPLIES ENDS AT ITS OWN CLAIM.**
///
/// Not cosmetic: `units_mcp::arrival` refuses an arrival record whose chain does not END at the
/// claim that matched, and it reads the top rather than membership precisely because the streamed
/// surface stands on the document one — a chain read by membership would let a stream be matched as
/// a request. A carrier whose chain ended anywhere else would be refused at step zero for a reason
/// no operator could read.
#[test]
fn each_transport_s_carrier_ends_at_its_own_claim() {
    assert_eq!(
        Carrier::pipe(77).request_bytes(),
        77,
        "the carrier reports the length it was handed, which is the frame's own"
    );
    let http = Carrier::document(128);
    let stdio = Carrier::pipe(128);
    for carrier in [http, stdio] {
        assert_eq!(
            carrier.chain().last(),
            Some(&carrier.claim_transport()),
            "the claim's transport is the TOP of the chain the carrier reports"
        );
        assert!(
            busbar_plane_mcp::claims::declares(carrier.claim_transport()),
            "a transport no claim of this plane names is one no unit of it may arrive on"
        );
    }
    assert_eq!(
        stdio.chain().len(),
        1,
        "a pipe has no TCP under it and no TLS over it, so its chain is one layer"
    );
}

/// A refusal the loop raised reads as this protocol's refusal, and names the gate rather than the
/// reason.
///
/// The reason is what a refusal may NOT carry: a reason names a cap, a lane or a rate, and a refusal
/// that told a caller about the deployment's money is the leak the unpriced refusal's own
/// documentation forbids. So the status is the step's and the sentence names the gate; the body
/// carries neither figure nor name.
#[test]
fn a_refusal_names_the_gate_and_never_the_reason() {
    let at = |step| busbar_contract::unit::Refusal {
        step,
        reason: busbar_contract::unit::RefusalReason::OverBudget,
        retry_after_secs: None,
        stream: None,
        correlates: None,
    };
    let cases = [
        (
            busbar_contract::unit::Step::Authenticate,
            axum::http::StatusCode::UNAUTHORIZED,
        ),
        (
            busbar_contract::unit::Step::Approve,
            axum::http::StatusCode::FORBIDDEN,
        ),
        (
            busbar_contract::unit::Step::Admit,
            axum::http::StatusCode::TOO_MANY_REQUESTS,
        ),
        (
            busbar_contract::unit::Step::Decode,
            axum::http::StatusCode::BAD_REQUEST,
        ),
        (
            busbar_contract::unit::Step::Route,
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
        ),
    ];
    for (step, expected) in cases {
        let response = super::refused(Some(serde_json::json!(1)), &at(step));
        assert_eq!(
            response.status(),
            expected,
            "the STEP decides the status, because which gate said no is the whole of what a caller \
             is owed"
        );
    }
}
