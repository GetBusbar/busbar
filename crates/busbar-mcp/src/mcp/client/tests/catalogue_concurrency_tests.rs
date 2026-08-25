// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE LOST-UPDATE REGRESSION, EXTENDED TO A MIXED INTERLEAVED LOAD.
//!
//! `catalogue_tests::concurrent_applies_to_distinct_keys_all_survive` proves distinct concurrent
//! INSERTS all land. This drives the harder shape the read-copy-update has to survive: EDITS of
//! pre-seeded servers interleaved with INSERTS of new ones, all released together on a barrier so
//! their clone-edit-swap windows overlap, for many rounds. The lost-update bug — cloning the pre-edit
//! map outside the write lock — drops whichever edits and inserts lose the final-swap race; the
//! atomic apply keeps every one. And because the generation is bumped once per apply under the same
//! lock, the number of applies is exactly the number of generation advances.

use crate::mcp::client::catalogue::{tool_digest, CatalogueCache};
use crate::mcp::client::support::{approved_server, sid, simple_tool};
use std::sync::{Arc, Barrier};

/// ~6 edits of pre-seeded servers + ~6 inserts of new servers, on a barrier, over ~80 rounds. Every
/// edit's new content and every insert must survive each round, and the generation must advance
/// exactly once per apply — no edit or insert silently dropped by a racing swap.
#[test]
fn interleaved_edits_and_inserts_all_survive_and_generation_advances_once_per_apply() {
    const EDITS: usize = 6;
    const INSERTS: usize = 6;
    const ROUNDS: usize = 80;

    for round in 0..ROUNDS {
        let cache = Arc::new(CatalogueCache::new());

        // Seed the servers that will be EDITED, each with a known original content. One apply.
        cache.apply(|servers| {
            for e in 0..EDITS {
                let id = format!("edit{e}");
                servers.insert(
                    id.clone(),
                    approved_server(&id, vec![simple_tool("t", "original")]),
                );
            }
        });
        assert_eq!(
            cache.generation(),
            1,
            "one seeding apply advances one generation"
        );

        // 12 workers: six re-write their own pre-seeded server to fresh content, six insert a brand
        // new server. All release together so the read-copy-update windows overlap.
        let barrier = Arc::new(Barrier::new(EDITS + INSERTS));
        let mut handles = Vec::new();

        for e in 0..EDITS {
            let cache = cache.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                let id = format!("edit{e}");
                // Content unique to this round AND this server, so a surviving-but-stale value is
                // caught as sharply as a dropped one.
                let content = format!("edited-r{round}-e{e}");
                barrier.wait();
                let content2 = content.clone();
                cache.apply(move |servers| {
                    servers.insert(
                        id.clone(),
                        approved_server(&id, vec![simple_tool("t", &content2)]),
                    );
                });
            }));
        }
        for i in 0..INSERTS {
            let cache = cache.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                let id = format!("insert{i}");
                barrier.wait();
                cache.apply(move |servers| {
                    servers.insert(
                        id.clone(),
                        approved_server(&id, vec![simple_tool("t", "inserted")]),
                    );
                });
            }));
        }
        for h in handles {
            h.join().unwrap();
        }

        let snap = cache.load();

        // Every EDIT survived at its NEW content — not the original, not a sibling's, not dropped.
        for e in 0..EDITS {
            let id = format!("edit{e}");
            let expected = format!("edited-r{round}-e{e}");
            let server = snap
                .server(&sid(&id))
                .unwrap_or_else(|| panic!("{id} vanished under a racing apply"));
            let def = server
                .observed
                .get("t")
                .expect("the edited tool is present");
            assert_eq!(
                def.description, expected,
                "{id} carries stale or lost content — the lost-update bug"
            );
            // Cross-check via the bound identity so the assertion is against the SAME digest the
            // dispatch gate would read, not merely the stored description.
            assert_eq!(
                server.bound_identity("t").unwrap().digest,
                tool_digest(def),
                "the edited server's bound identity matches its stored definition"
            );
        }

        // Every INSERT survived.
        for i in 0..INSERTS {
            let id = format!("insert{i}");
            assert!(
                snap.server(&sid(&id)).is_some(),
                "{id} was dropped by a racing apply"
            );
        }

        // The catalogue holds exactly the seeded-and-edited servers plus the inserts.
        assert_eq!(snap.servers.len(), EDITS + INSERTS);

        // GENERATION ADVANCES EXACTLY ONCE PER APPLY: one seed + twelve concurrent applies = 13.
        assert_eq!(
            cache.generation(),
            (1 + EDITS + INSERTS) as u64,
            "each apply bumps the generation exactly once, even under contention"
        );
    }
}
