// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::transport::wire::WireStatusClass;

use super::harness::{frame, Script};
use super::{member, Node, Routed};
use busbar_kernel_egress::ports::{DestinationId, Outcome};

#[test]
fn an_incremental_answer_of_n_events_is_relayed_to_its_completion() {
    const N: usize = 4;
    let mut node = Node::with_lanes(&["a"]);
    node.pool("primary", vec![member(DestinationId::new(0), "a")]);
    node.wants_stream = true;
    node.conns.script(
        "a",
        Script::Frames(
            (0..N)
                .map(|_| frame(Some(WireStatusClass::Success), "event"))
                .collect(),
        ),
    );

    let outcome = node.route("primary");
    let Routed::Delivered(delivered) = &outcome else {
        panic!("a whole answer is delivered: {outcome:?}");
    };
    assert_eq!(
        delivered.pieces, N,
        "every event of the answer is relayed, up to and including the last one"
    );
    assert_eq!(
        node.breaker.outcomes("primary", DestinationId::new(0)),
        vec![Outcome::Success],
        "an answer that arrived whole records one success and no compensating failure"
    );
    assert_eq!(
        node.breaker.budget_net(DestinationId::new(0)),
        1,
        "and keeps the budget unit it spent"
    );
}
