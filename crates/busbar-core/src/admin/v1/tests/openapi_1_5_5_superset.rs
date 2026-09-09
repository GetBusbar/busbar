// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PB-75, AS A TEST RATHER THAN A PROMISE: the served OpenAPI document is a SUPERSET of 1.5.5's.
//!
//! PB-75 binds `GET /api/v1/admin/openapi.json` to the 1.5.5 document byte-for-byte except for
//! additive endpoints. "Additive" is checkable, so this checks it, against the published 1.5.5
//! document itself (`testing/shadow-oracle/fixtures/openapi-1.5.5.json`) rather than against a
//! restatement of it:
//!
//!   * every key 1.5.5 carries is still present, with an EQUAL value; and
//!   * every array 1.5.5 carries is a strict PREFIX of the 1.6.0 one — so nothing is dropped,
//!     re-valued, or REORDERED. (A `required` list is an array, which is why a 1.6.0 field spliced
//!     into the middle of a struct reads here as a break: see `hook_view_wire_order`.)
//!
//! New keys, new paths and longer arrays are free. That is the whole of "additive".
//!
//! The point of pinning it here, in-tree, is that the shadow oracle can only catch this by BUILDING
//! a binary and diffing a served body; this catches it at `cargo test` on the generated document,
//! naming the exact JSON pointer that broke. Every entry in [`ACCEPTED`] below is a divergence an
//! owner has ruled on, and each one carries the reason it is not simply fixed.

/// THE RULED-ON DIVERGENCES. Anything else failing the superset rule is a regression.
///
/// Kept as an explicit list, not a prefix match, so a new divergence cannot hide under an existing
/// allowance — adding one is an edit an owner reviews.
// Read only by the two `#[cfg(feature = "openapi-schema")]` tests below, so this (and
// `V155_FIXTURE`/`superset_violations`) are dead in a `cargo test`/`clippy` run that does not
// enable that feature — same reason `busbar-substrate::api::ap` carries the same allowance.
#[cfg_attr(not(feature = "openapi-schema"), allow(dead_code))]
const ACCEPTED: &[(&str, &str)] = &[
    (
        "/info/version",
        "The binary reports its true version. The plane-admin codec rewrites this field per client \
         (`codec::set_info_version`), so a 1.5.5 client is served `1.5.5` here; the generated \
         document necessarily says 1.6.0. A dedicated oracle cell pins the rewrite.",
    ),
    (
        // plane-purity: frozen-wire the OpenAPI 3.1 keyword in a pointer, not the LLM dialect
        "/paths/~1api~1v1~1admin~1overlay~1{section}/delete/responses/400/description",
        "The overlay `section` enumeration, DERIVED from `OverlaySection::all()` and grown by the \
         1.6.0 sections. LIST GROWTH ONLY: the spelling is 1.5.5's own bare-pipe run (the DOCUMENT's \
         spelling, not the 400 body's Oxford one — see the PB-75 ruling on \
         `OverlaySection::valid_names_piped`), and \
         `the_openapi_section_list_keeps_1_5_5_pipe_spelling` below pins these bytes against the \
         1.5.5 fixture, so this allowance covers the appended names and nothing else.",
    ),
    (
        "/paths/~1api~1v1~1admin~1overlay~1{section}/delete/summary",
        "Same derived section enumeration, and the same bare-pipe spelling, as the 400 description \
         above; pinned by the same test.",
    ),
    (
        // plane-purity: frozen-wire the OpenAPI 3.1 keyword in a pointer, not the LLM dialect
        "/paths/~1api~1v1~1admin~1overlay~1{section}/delete/responses/409/description",
        "PB-75 REGISTERED CORRECTION (owner ruling 2026-09-08), and also a new error condition, not \
         a prose edit: 1.6.0 added `Conflict/StillReferenced` (a section reset that would leave \
         base config.yaml naming a definition it removes). The description is generated from the \
         endpoint's declared taxonomy, so restoring 1.5.5's string means UN-DECLARING a reachable \
         409 — which `declared_error_set_is_exactly_what_the_handlers_emit` correctly refuses. \
         Documenting a real failure is the additive reading. Registered in \
         testing/shadow-oracle/accepted-differences.json (F-011c, `description_corrections`) with \
         its own CHANGELOG line.",
    ),
    (
        "/components/schemas/OverlayResetView/properties/reset/description",
        "The overlay `section` enumeration again, on the RESULT view. LIST GROWTH ONLY, in 1.5.5's \
         own spaced-pipe spelling (a third spelling of the same set — see \
         `OverlaySection::valid_names_spaced_piped`). Frozen verbatim it was a published document \
         asserting a reset of `export` could not happen while the route answered it; under PB-75 \
         the wording stays and the list grows. Pinned by \
         `the_overlay_reset_description_grows_the_live_section_set`.",
    ),
    (
        "/components/schemas/NamedDefView/properties/max_admin_scope/description",
        "PB-75 REGISTERED CORRECTION (owner ruling 2026-09-08): the 1.5.5 text advertised a `none` \
         ceiling token that 1.5.5's own parser never accepted — `Scope` has exactly two variants \
         (`ReadOnly`, `Full`) in both releases, and `Scope::parse_ceiling` is byte-identical between \
         them, rejecting `none` with the same message in both. A published error corrected, not a \
         behavior change. The description now states the ceiling tokens the parser actually accepts \
         (`read-only` | `full`). Registered in testing/shadow-oracle/accepted-differences.json \
         (F-011c, `description_corrections`) with its own CHANGELOG line.",
    ),
];

/// The published 1.5.5 document — the contract this one is measured against.
#[cfg_attr(not(feature = "openapi-schema"), allow(dead_code))]
const V155_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testing/shadow-oracle/fixtures/openapi-1.5.5.json"
);

/// Walk 1.5.5's document and collect the JSON pointer of every place 1.6.0's is not a superset.
#[cfg_attr(not(feature = "openapi-schema"), allow(dead_code))]
fn superset_violations(old: &serde_json::Value, new: &serde_json::Value) -> Vec<String> {
    fn esc(k: &str) -> String {
        k.replace('~', "~0").replace('/', "~1")
    }
    fn walk(old: &serde_json::Value, new: &serde_json::Value, at: &str, out: &mut Vec<String>) {
        match old {
            serde_json::Value::Object(o) => {
                let Some(n) = new.as_object() else {
                    out.push(at.to_string());
                    return;
                };
                for (k, v) in o {
                    let p = format!("{at}/{}", esc(k));
                    match n.get(k) {
                        // A key 1.5.5 published and 1.6.0 dropped: never additive.
                        None => out.push(p),
                        Some(nv) => walk(v, nv, &p, out),
                    }
                }
            }
            serde_json::Value::Array(o) => {
                let Some(n) = new.as_array() else {
                    out.push(at.to_string());
                    return;
                };
                for (i, v) in o.iter().enumerate() {
                    let p = format!("{at}/{i}");
                    // 1.5.5 must be a PREFIX: same values at the same indices. A shorter 1.6.0
                    // array, or a different value at any 1.5.5 index, is a reorder or a removal.
                    match n.get(i) {
                        None => out.push(p),
                        Some(nv) => walk(v, nv, &p, out),
                    }
                }
            }
            // A leaf: additive means UNCHANGED.
            _ => {
                if old != new {
                    out.push(at.to_string());
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(old, new, "", &mut out);
    out
}

/// THE GATE. The generated document is a superset of 1.5.5's, modulo the ruled-on list.
#[cfg(feature = "openapi-schema")]
#[test]
fn the_served_document_is_an_additive_superset_of_1_5_5() {
    let old: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(V155_FIXTURE).expect("read the 1.5.5 fixture"),
    )
    .expect("1.5.5 fixture is JSON");
    let new = crate::admin::v1::json::openapi_doc();

    let violations = superset_violations(&old, &new);
    let accepted: std::collections::BTreeSet<&str> = ACCEPTED.iter().map(|(p, _)| *p).collect();

    let unexpected: Vec<&String> = violations
        .iter()
        .filter(|p| !accepted.contains(p.as_str()))
        .collect();
    assert!(
        unexpected.is_empty(),
        "the served OpenAPI document is no longer an additive superset of 1.5.5 at:\n  {}\n\nA \
         1.5.5 client reads these. Either restore the 1.5.5 value, or add the pointer to ACCEPTED \
         with the reason an owner ruled it acceptable.",
        unexpected
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("\n  ")
    );

    // And the allowance list stays HONEST: an entry that no longer diverges is stale and must go,
    // or it silently licenses a future regression at that pointer.
    let stale: Vec<&str> = accepted
        .iter()
        .filter(|p| !violations.iter().any(|v| v == *p))
        .copied()
        .collect();
    assert!(
        stale.is_empty(),
        "ACCEPTED lists pointers that no longer diverge from 1.5.5 — delete them: {stale:?}"
    );
}

/// THE FROZEN DESCRIPTIONS, named individually. The gate above would catch a change to any of
/// these, but only as a pointer; this says out loud WHICH prose is load-bearing and why, so the
/// next person to improve a doc comment on one of these fields learns it is a wire edit from the
/// test name rather than from a shadow-oracle diff three days later.
#[cfg(feature = "openapi-schema")]
#[test]
fn the_1_5_5_schema_descriptions_are_frozen_verbatim() {
    let old: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(V155_FIXTURE).expect("read the 1.5.5 fixture"),
    )
    .expect("1.5.5 fixture is JSON");
    let new = crate::admin::v1::json::openapi_doc();

    // `NamedDefView/properties/max_admin_scope/description` is deliberately NOT here any more: it
    // is a PB-75 registered correction (see `ACCEPTED` above), not a frozen 1.5.5 string.
    let frozen: &[(&str, &str)] = &[
        ("HookView", "description"),
        ("HookView", "properties/at/description"),
        ("NamedDefView", "description"),
        ("NamedDefView", "properties/module/description"),
    ];
    // `OverlayResetView/properties/reset/description` is deliberately NOT here any more: it
    // ENUMERATES the sections, so freezing it froze a list that had gone stale. Under PB-75 it now
    // grows in 1.5.5's own wording, pinned by
    // `the_overlay_reset_description_grows_the_live_section_set` below.
    for (schema, rel) in frozen {
        let mut o = &old["components"]["schemas"][schema];
        let mut n = &new["components"]["schemas"][schema];
        for seg in rel.split('/') {
            o = &o[seg];
            n = &n[seg];
        }
        assert!(!o.is_null(), "1.5.5 fixture has no {schema}/{rel}");
        assert_eq!(
            n, o,
            "{schema}/{rel} drifted from its 1.5.5 text. schemars generates this from a doc \
             comment, so editing that comment edits the PUBLISHED contract. Put the new prose on a \
             1.6.0 field instead — a new property's description is additive."
        );
    }
}

/// THE DOCUMENT'S SPELLING OF THE SECTION LIST IS 1.5.5's, NOT THE MESSAGE'S.
///
/// The overlay-section enumeration reaches TWO surfaces, and 1.5.5 spelled them differently: the
/// `DELETE /overlay/{section}` 400 BODY an operator reads used an Oxford list (`` `a`, `b`, or
/// `c` ``), while openapi.json's 400 DESCRIPTION used a bare-pipe list (`` `a`|`b`|`c` ``). Routing
/// both through `OverlaySection::valid_names_oxford` therefore did not remove drift — it INTRODUCED
/// it, rewriting a published document string into the message's punctuation.
///
/// Owner ruling PB-75 (2026-09-08): openapi.json descriptions are verbatim except REGISTERED
/// factual corrections, and an Oxford-comma rewrite is neither verbatim nor a correction. So the
/// document keeps 1.5.5's pipe spelling (`OverlaySection::valid_names_piped`) and the message keeps
/// 1.5.5's Oxford spelling (`OverlaySection::valid_names_oxford`). The document is a frozen
/// contract; the message is product text. The SET cannot drift between them — both render from
/// `OverlaySection::all` — so only the punctuation is per-surface.
///
/// This asserts the served prose is 1.5.5's bytes with ONLY the list grown: 1.5.5's string, with
/// its four-name pipe run replaced by the eight-name pipe run, must equal what is served, byte for
/// byte. A separator change, a reworded frame or a reordered list each fail here, on the exact
/// leaf, instead of surfacing as an anonymous pointer in a shadow-oracle diff days later.
#[cfg(feature = "openapi-schema")]
#[test]
fn the_openapi_section_list_keeps_1_5_5_pipe_spelling() {
    use crate::config::overlay::OverlaySection;

    let old: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(V155_FIXTURE).expect("read the 1.5.5 fixture"),
    )
    .expect("1.5.5 fixture is JSON");
    let new = crate::admin::v1::json::openapi_doc();

    // 1.5.5's own four, in 1.5.5's order, spelled the way each DOCUMENT leaf spelled them. The two
    // leaves differ: the 400 description backticks each name, the operation summary does not. Both
    // join with a bare pipe, and both are 1.5.5's bytes — so both are reproduced, not normalised.
    let bare: Vec<&str> = OverlaySection::all().iter().map(|s| s.as_str()).collect();
    let runs: [(&str, String); 2] = [
        (
            "`groups`|`hooks`|`root`|`plugin_versions`",
            OverlaySection::valid_names_piped(),
        ),
        ("groups|hooks|root|plugin_versions", bare.join("|")),
    ];
    for (old_run, new_run) in &runs {
        assert!(
            new_run.starts_with(old_run),
            "the document's section list must keep 1.5.5's four names first, in 1.5.5's order and \
             spelling; got {new_run}"
        );
    }

    let path = "/api/v1/admin/overlay/{section}";
    for (rel, (old_run, new_run)) in [&["responses", "400", "description"][..], &["summary"][..]]
        .into_iter()
        .zip(&runs)
    {
        let mut o = &old["paths"][path]["delete"];
        let mut n = &new["paths"][path]["delete"];
        for seg in rel {
            o = &o[seg];
            n = &n[seg];
        }
        let o = o.as_str().expect("1.5.5 fixture leaf is a string");
        let n = n.as_str().expect("served leaf is a string");
        assert!(
            o.contains(old_run),
            "the 1.5.5 fixture leaf no longer carries the pipe run this test is about: {o}"
        );
        assert_eq!(
            n,
            o.replace(old_run, new_run),
            "the served overlay-section prose at delete/{} is not 1.5.5's bytes with only the list \
             grown. 1.5.5's DOCUMENT spells this list with bare pipes; the Oxford spelling belongs \
             to the 400 BODY, not here. Render `OverlaySection::valid_names_piped` from the error \
             taxonomy, never `valid_names_oxford`.",
            rel.join("/")
        );
    }
}

/// THE RESET VIEW'S SECTION LIST IS LIVE, AND IN 1.5.5's WORDING.
///
/// `OverlayResetView.reset`'s description enumerates the sections, and schemars generates it from a
/// doc comment — a static string, which is precisely how it went stale: 1.5.5 named four sections,
/// 1.6.0 has eight, and the served document therefore told a client that a reset of `export` could
/// not happen while the route was answering it. Freezing it verbatim preserved that lie; rewriting
/// it freely would edit a published contract.
///
/// Owner ruling PB-75 (2026-09-08), the same rule F-013 applies to the wire message: THE WORDING
/// STAYS 1.5.5's, THE LIST GROWS. This asserts both halves at once — the served description is
/// 1.5.5's fixture bytes with ONLY the enumeration replaced by the live set, in 1.5.5's own
/// SPACED-pipe spelling (`` `a` | `b` ``, a third spelling of this same set; the 400 description
/// uses bare pipes and the 400 body uses Oxford commas, and PB-75 freezes each surface's
/// punctuation as it found it).
///
/// The set is not restated here: it is read from `OverlaySection::all()`, so adding a section
/// updates this expectation and the document together, and the failure mode this test exists to
/// catch — a description that stops tracking the sections — cannot come back.
#[cfg(feature = "openapi-schema")]
#[test]
fn the_overlay_reset_description_grows_the_live_section_set() {
    use crate::config::overlay::OverlaySection;

    let old: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(V155_FIXTURE).expect("read the 1.5.5 fixture"),
    )
    .expect("1.5.5 fixture is JSON");
    let new = crate::admin::v1::json::openapi_doc();

    let old_run = "`groups` | `hooks` | `root` | `plugin_versions`";
    let new_run = OverlaySection::valid_names_spaced_piped();
    assert!(
        new_run.starts_with(old_run),
        "the reset view's section list must keep 1.5.5's four names first, in 1.5.5's order and \
         spaced-pipe spelling; got {new_run}"
    );

    let o = old["components"]["schemas"]["OverlayResetView"]["properties"]["reset"]["description"]
        .as_str()
        .expect("1.5.5 fixture has OverlayResetView/properties/reset/description");
    let n = new["components"]["schemas"]["OverlayResetView"]["properties"]["reset"]["description"]
        .as_str()
        .expect("served OverlayResetView/properties/reset/description");

    assert!(
        o.contains(old_run),
        "the 1.5.5 fixture leaf no longer carries the spaced-pipe run this test is about: {o}"
    );
    assert_eq!(
        n,
        o.replace(old_run, &new_run),
        "the served `reset` description is not 1.5.5's sentence with only the section list grown. \
         It must name the LIVE set (`OverlaySection::all`) in 1.5.5's spaced-pipe spelling — a \
         frozen four-name copy is a document that denies a reset the route performs, and a \
         respelled one edits the published contract."
    );

    // The whole point: the live sections really are in there, not just 1.5.5's four.
    for s in OverlaySection::all() {
        assert!(
            n.contains(&format!("`{}`", s.as_str())),
            "the served `reset` description omits the live section `{}`: {n}",
            s.as_str()
        );
    }
}
