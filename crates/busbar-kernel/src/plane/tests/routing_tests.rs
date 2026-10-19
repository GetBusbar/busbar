// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The routing tables are built from what a plane STATES, under whatever section name it states
//! (arch u26 RED (b); #47/#49): nothing here is a section, a plane or a field name the kernel knows.

use super::*;
use busbar_contract::abi::plane::{
    FACT_ATTEMPT_TIMEOUT_MS, FACT_CONCURRENCY_CAP, FACT_CONTEXT_WINDOW, FACT_FAILOVER_MAX_HOPS,
    FACT_FAILOVER_TIMEOUT_SECS, FACT_MAX_REQUESTS,
};

const PLANE: &str = "u26-novel-plane";
const SECTION: &str = "u26_novel_widgets";

fn member(lane: &str, weight: u32, facts: &[(u16, u64)]) -> RoutingMember {
    RoutingMember {
        lane: lane.to_string(),
        provider: "acme".to_string(),
        upstream: None,
        weight,
        tier: None,
        tags: Vec::new(),
        facts: facts.to_vec(),
    }
}

fn entry(
    section: &str,
    name: &str,
    fallback: Option<&str>,
    facts: &[(u16, u64)],
    members: Vec<RoutingMember>,
) -> RoutingEntry {
    RoutingEntry {
        section: section.to_string(),
        entry: name.to_string(),
        path: vec![section.to_string(), name.to_string()],
        fallback: fallback.map(str::to_string),
        exclude: Vec::new(),
        facts: facts.to_vec(),
        members,
    }
}

/// A lane's own facts, stated identically on every member naming it.
const ALPHA: &[(u16, u64)] = &[
    (FACT_CONCURRENCY_CAP, 4),
    (FACT_MAX_REQUESTS, 100),
    (FACT_CONTEXT_WINDOW, 8192),
];

fn no_reserved(_: &[String]) -> Option<String> {
    None
}

/// RED (b): a plane stating its routing under a section the kernel has never seen gets a lane table
/// and an entry table from it, with no kernel edit: lanes ordered by name, each lane's store row
/// carrying its cap and budget, each member its weight and attempt bound (its own over its entry's).
#[test]
fn a_plane_under_a_new_section_name_routes_with_no_kernel_edit() {
    let stated = [
        entry(SECTION, "beta", None, &[], vec![member("beta", 1, &[])]),
        entry(
            SECTION,
            "pair",
            None,
            &[
                (FACT_ATTEMPT_TIMEOUT_MS, 900),
                (FACT_FAILOVER_TIMEOUT_SECS, 30),
                (FACT_FAILOVER_MAX_HOPS, 2),
            ],
            vec![
                member("beta", 1, &[]),
                member(
                    "alpha",
                    3,
                    &[ALPHA[0], ALPHA[1], ALPHA[2], (FACT_ATTEMPT_TIMEOUT_MS, 250)],
                ),
            ],
        ),
        entry(SECTION, "alpha", None, &[], vec![member("alpha", 1, ALPHA)]),
    ];
    let tables = RoutingTables::build(
        &[StatedRouting {
            plane: PLANE,
            entries: &stated,
        }],
        &no_reserved,
    )
    .expect("the stated routing builds");

    let names: Vec<&str> = tables.lanes().iter().map(|l| l.name.as_str()).collect();
    assert_eq!(names, ["alpha", "beta"], "lanes are ordered by name");
    assert_eq!(tables.lane(PLANE, "alpha"), Some(0));
    let alpha = &tables.lanes()[0];
    assert_eq!(
        (
            alpha.max_concurrent,
            alpha.max_requests,
            alpha.context_window
        ),
        (Some(4), Some(100), Some(8192))
    );

    let rows = tables.lane_data();
    assert_eq!(
        (rows[0].max, rows[0].limited, rows[0].budget),
        (4, true, 100)
    );
    assert_eq!(
        (rows[1].max, rows[1].limited, rows[1].budget),
        (tokio::sync::Semaphore::MAX_PERMITS, false, -1),
        "an unstated cap and budget are unbounded"
    );
    assert_eq!(
        (rows[0].member.as_str(), rows[0].route.as_str()),
        ("alpha", "acme")
    );

    let pair = tables.entry(PLANE, SECTION, "pair").expect("the entry");
    assert_eq!(pair.path, [SECTION, "pair"]);
    assert_eq!(
        (pair.failover_timeout_secs, pair.failover_max_hops),
        (Some(30), Some(2))
    );
    let picks: Vec<(usize, u32, Option<u64>)> = pair
        .members
        .iter()
        .map(|m| (m.lane, m.weight, m.attempt_timeout_ms))
        .collect();
    assert_eq!(
        picks,
        [(1, 1, Some(900)), (0, 3, Some(250))],
        "members keep their order; a member's attempt bound wins over its entry's"
    );
    assert_eq!(
        tables.entry_names(PLANE, SECTION).collect::<Vec<_>>(),
        ["beta", "pair", "alpha"]
    );
    assert!(tables.entry(PLANE, "another_section", "pair").is_none());
}

/// Every member naming a lane states the lane's own facts identically; two that disagree are the
/// plane's contradiction, refused naming the lane and the second entry.
#[test]
fn a_lane_stated_with_two_different_lane_facts_is_refused() {
    let stated = [
        entry(SECTION, "alpha", None, &[], vec![member("alpha", 1, ALPHA)]),
        entry(
            SECTION,
            "pair",
            None,
            &[],
            vec![member("alpha", 1, &[(FACT_CONCURRENCY_CAP, 9)])],
        ),
    ];
    let errors = RoutingTables::build(
        &[StatedRouting {
            plane: PLANE,
            entries: &stated,
        }],
        &no_reserved,
    )
    .expect_err("refused");
    assert!(
        errors
            .iter()
            .any(|e| e.contains("lane `alpha`") && e.contains(&format!("`{SECTION}.pair`"))),
        "{errors:?}"
    );
}

#[test]
fn one_entry_stated_twice_is_refused() {
    let stated = [
        entry(SECTION, "alpha", None, &[], vec![member("alpha", 1, ALPHA)]),
        entry(SECTION, "alpha", None, &[], vec![member("alpha", 1, ALPHA)]),
    ];
    let errors = RoutingTables::build(
        &[StatedRouting {
            plane: PLANE,
            entries: &stated,
        }],
        &no_reserved,
    )
    .expect_err("refused");
    assert!(
        errors
            .iter()
            .any(|e| e.contains(&format!("states `{SECTION}.alpha` twice"))),
        "{errors:?}"
    );
}

/// THE GENERIC FALLBACK REFUSALS speak the previous release's sentences with the entry's noun taken
/// from data: an unknown target, a self-reference and a ring (reported once). An entry the plane
/// states no fallback for takes the one its reserved sub-keys name.
#[test]
fn fallback_refusals_name_the_plane_declared_noun_and_read_the_reserved_fallback() {
    let stated = [
        entry(SECTION, "a", Some("ghost"), &[], vec![member("x", 1, &[])]),
        entry(SECTION, "b", Some("b"), &[], vec![member("x", 1, &[])]),
        entry(SECTION, "c", Some("d"), &[], vec![member("x", 1, &[])]),
        // `d` states no fallback: its reserved sub-keys name `c`, closing the ring c -> d -> c.
        entry(SECTION, "d", None, &[], vec![member("x", 1, &[])]),
    ];
    let reserved = |path: &[String]| -> Option<String> {
        (path.last().map(String::as_str) == Some("d")).then(|| "c".to_string())
    };
    let tables = RoutingTables::build(
        &[StatedRouting {
            plane: PLANE,
            entries: &stated,
        }],
        &reserved,
    )
    .expect("builds");
    assert_eq!(
        tables
            .entry(PLANE, SECTION, "d")
            .and_then(|e| e.fallback.clone()),
        Some("c".to_string())
    );
    let errors = tables.fallback_refusals(&|plane, section| {
        assert_eq!((plane, section), (PLANE, SECTION));
        "gizmo".to_string()
    });
    assert!(errors
        .contains(&"gizmo 'a' on_exhausted references unknown fallback gizmo 'ghost'".to_string()));
    assert!(
        errors.iter().any(|e| e
            .starts_with("gizmo 'b' on_exhausted references itself as its fallback gizmo ('b');")),
        "{errors:?}"
    );
    let rings: Vec<&String> = errors
        .iter()
        .filter(|e| e.starts_with("fallback_pool cycle detected: c -> d -> c;"))
        .collect();
    assert_eq!(rings.len(), 1, "a ring is reported once: {errors:?}");
}

/// The previous release's sentences, byte for byte, when the plane's noun is the previous
/// release's (the oracle judges the served bytes; this pins the kernel's half).
#[test]
fn the_fallback_sentences_are_the_previous_releases_with_its_noun() {
    let stated = [entry(
        "pools",
        "fast",
        Some("slow"),
        &[],
        vec![member("x", 1, &[])],
    )];
    let tables = RoutingTables::build(
        &[StatedRouting {
            plane: PLANE,
            entries: &stated,
        }],
        &no_reserved,
    )
    .expect("builds");
    assert_eq!(
        tables.fallback_refusals(&|_, _| "pool".to_string()),
        ["pool 'fast' on_exhausted references unknown fallback pool 'slow'"]
    );
}
