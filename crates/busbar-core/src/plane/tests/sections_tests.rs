// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared pools/tools/agents container: one code object, three sibling sections, and a
//! resolver that REFUSES a cross-plane reference by name.

use super::*;

/// Two entry types, so the container is exercised as the generic it claims to be rather than as a
/// thing that happens to hold one shape. The same discipline the trust lifecycle is held to.
#[derive(Debug, PartialEq, Clone)]
struct Entry(&'static str);
#[derive(Debug, PartialEq, Clone)]
struct OtherEntry(u32);

fn sections() -> PlaneSections<Entry> {
    let mut s = PlaneSections::default();
    s.insert("llm", "fast", Entry("a pool"));
    s.insert("mcp", "filesystem", Entry("an mcp server"));
    s.insert("a2a", "planner", Entry("an agent"));
    s
}

/// EVERY plane behaves identically. Looping over the plane registry keys rather than writing three
/// copies is what stops one plane quietly acquiring a special case.
#[test]
fn every_plane_stores_and_reads_back_the_same_way() {
    let mut s: PlaneSections<OtherEntry> = PlaneSections::default();
    for (i, plane) in crate::plane::plane_keys().enumerate() {
        s.insert(plane, "shared-name", OtherEntry(i as u32));
    }
    for (i, plane) in crate::plane::plane_keys().enumerate() {
        assert_eq!(
            s.get(plane, "shared-name"),
            Some(&OtherEntry(i as u32)),
            "{plane:?} must read back its own entry"
        );
    }
}

/// THE SIBLING RULE: the three sections are independent namespaces. One name may exist in all three
/// and each resolves to its own entry. They are siblings, so a name is not globally unique and must
/// not be treated as if it were.
#[test]
fn one_name_may_exist_independently_in_every_plane() {
    let mut s = PlaneSections::default();
    s.insert("llm", "shared", Entry("llm"));
    s.insert("mcp", "shared", Entry("mcp"));
    s.insert("a2a", "shared", Entry("a2a"));
    assert_eq!(s.resolve("llm", "shared"), Ok(&Entry("llm")));
    assert_eq!(s.resolve("mcp", "shared"), Ok(&Entry("mcp")));
    assert_eq!(s.resolve("a2a", "shared"), Ok(&Entry("a2a")));
}

/// THE NO-CROSS-REFERENCE RULE, and the reason this container exists: a name defined on one plane is
/// NOT resolvable from another. Resolution looks only in the plane doing the referencing.
#[test]
fn a_name_from_another_plane_never_resolves() {
    let s = sections();
    for (from, name) in [
        ("mcp", "fast"),
        ("a2a", "fast"),
        ("llm", "filesystem"),
        ("a2a", "filesystem"),
        ("llm", "planner"),
        ("mcp", "planner"),
    ] {
        assert!(
            s.resolve(from, name).is_err(),
            "{name} must not resolve from {from:?}"
        );
        assert_eq!(
            s.get(from, name),
            None,
            "and the plain read must not leak it either"
        );
    }
}

/// The refusal DIAGNOSES rather than merely denying: it names the plane the entry actually lives on,
/// so the operator is told "that is an agent, referenced from a tools entry" instead of "unknown
/// name". A bare not-found here sends someone hunting for a typo that is not there.
#[test]
fn a_cross_plane_reference_names_the_plane_the_entry_lives_on() {
    let s = sections();
    assert_eq!(
        s.resolve("mcp", "planner"),
        Err(RefError::CrossPlane {
            name: "planner".to_string(),
            referenced_from: "mcp",
            defined_in: "a2a",
        })
    );
}

/// A genuinely unknown name is a DIFFERENT error from a cross-plane reference. Collapsing the two
/// would throw away the only information that makes the cross-plane case actionable.
#[test]
fn an_unknown_name_is_not_a_cross_plane_reference() {
    let s = sections();
    assert_eq!(
        s.resolve("mcp", "nowhere"),
        Err(RefError::Unknown {
            name: "nowhere".to_string(),
            plane: "mcp",
        })
    );
}

/// The rendered message says which plane, which name, and where it actually lives. This is the text
/// an operator sees at boot, so it is pinned rather than left to drift.
#[test]
fn the_refusal_message_is_actionable() {
    let s = sections();
    let msg = s.resolve("mcp", "planner").unwrap_err().to_string();
    assert!(msg.contains("planner"), "names the entry: {msg}");
    assert!(
        msg.contains("tools"),
        "names the referencing section: {msg}"
    );
    assert!(msg.contains("agents"), "names the defining section: {msg}");

    let unknown = s.resolve("mcp", "nowhere").unwrap_err().to_string();
    assert!(unknown.contains("nowhere"));
    assert!(unknown.contains("tools"));
    assert!(
        !unknown.contains("agents"),
        "an unknown name must not invent a plane it lives on: {unknown}"
    );
}

/// A section read is scoped to its plane and nothing else, so a caller iterating one plane's entries
/// can never walk another's.
#[test]
fn a_section_read_is_scoped_to_its_own_plane() {
    let s = sections();
    let llm = s.section("llm").expect("the llm section holds an entry");
    assert_eq!(llm.len(), 1);
    assert!(llm.contains_key("fast"));
    assert!(!llm.contains_key("filesystem"));
    assert!(!llm.contains_key("planner"));
}

/// Iteration covers every plane in registry-key (LAYERING) order and reports each entry against the
/// plane it belongs to. The config validator walks this, so a plane missing here is a plane that is
/// never validated.
#[test]
fn iteration_covers_every_plane_and_attributes_each_entry() {
    let s = sections();
    let mut seen: Vec<(&'static str, &str)> = s.iter().map(|(p, n, _)| (p, n)).collect();
    seen.sort();
    assert_eq!(
        seen,
        vec![("llm", "fast"), ("mcp", "filesystem"), ("a2a", "planner"),]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
    );
    let planes: std::collections::BTreeSet<&'static str> = s.iter().map(|(p, _, _)| p).collect();
    assert_eq!(
        planes.len(),
        crate::plane::plane_keys().count(),
        "every plane is represented"
    );
}

/// An EMPTY container refuses everything, and refuses it as unknown rather than cross-plane. The
/// fail-closed floor: nothing resolves until something is declared.
#[test]
fn an_empty_container_resolves_nothing() {
    let s: PlaneSections<Entry> = PlaneSections::default();
    for plane in crate::plane::plane_keys() {
        assert!(matches!(
            s.resolve(plane, "anything"),
            Err(RefError::Unknown { .. })
        ));
        assert!(s.section(plane).is_none_or(|m| m.is_empty()));
    }
    assert_eq!(s.iter().count(), 0);
}

/// The cross-plane check reports the FIRST plane in registry-key (LAYERING) order that defines the name, and
/// does so deterministically when several do. A nondeterministic diagnostic is worse than none: it
/// makes a boot failure unreproducible.
#[test]
fn a_name_defined_on_several_other_planes_diagnoses_deterministically() {
    let mut s = PlaneSections::default();
    s.insert("llm", "shared", Entry("llm"));
    s.insert("a2a", "shared", Entry("a2a"));
    for _ in 0..8 {
        assert_eq!(
            s.resolve("mcp", "shared"),
            Err(RefError::CrossPlane {
                name: "shared".to_string(),
                referenced_from: "mcp",
                defined_in: "llm",
            }),
            "the diagnosis must be stable across repeated resolution"
        );
    }
}
