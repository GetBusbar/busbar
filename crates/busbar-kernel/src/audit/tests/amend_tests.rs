// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// TWO NODES NEVER SHARE A JOURNAL (item 404): an access sealed on one node's journal is not read
/// off another's. The journal is an instance its node owns, never a process static.
#[test]
fn an_access_on_one_nodes_journal_is_not_read_by_another_nodes() {
    let (a, b) = (NodeAmendments::new(), NodeAmendments::new());
    hook_read(&a, "p2-404-hook", Some("key-a"), "openai", false);
    assert_eq!(
        a.recent().len(),
        1,
        "the access lands on the journal it was sealed on"
    );
    assert!(
        b.recent().is_empty(),
        "a second node's journal read an access it never sealed"
    );

    // Rebuilding a third journal from `a`'s run is that journal's act alone, under the
    // durable-write grant: `a` and `b` are untouched.
    let c = NodeAmendments::new();
    let token = crate::teller::Kernel::new().durability_token();
    let through = c.restore(a.recent(), &token).expect("a's run verifies");
    assert_eq!(through, 1);
    assert_eq!(c.recent(), a.recent());
    assert!(b.recent().is_empty());
}

/// A journal bound to a sink hands it every amendment it still holds above the position the sink
/// was told is durable, then every one sealed after: what is durable has no gap.
#[test]
fn a_bound_sink_takes_the_held_tail_then_every_new_amendment() {
    struct Count(std::sync::Mutex<Vec<u64>>);
    impl AmendSink for Count {
        fn sealed(&self, amendment: &Amendment) {
            self.0.lock().unwrap().push(amendment.seq);
        }
    }
    let journal = NodeAmendments::new();
    hook_read(&journal, "h", None, "openai", false);
    hook_read(&journal, "h", None, "openai", false);
    let first = journal.recent()[0].seq;
    let sink = std::sync::Arc::new(Count(std::sync::Mutex::new(Vec::new())));
    let token = crate::teller::Kernel::new().durability_token();
    journal.bind(
        Some(sink.clone() as std::sync::Arc<dyn AmendSink>),
        first,
        &token,
    );
    export_read(&journal, "sink", "logs", &serde_json::json!({ "a": 1 }));
    assert_eq!(*sink.0.lock().unwrap(), vec![first + 1, first + 2]);
}
