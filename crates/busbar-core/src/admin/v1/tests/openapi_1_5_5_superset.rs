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
        "The overlay `section` enumeration, which is DERIVED from `OverlaySection::valid_names()` \
         and grew with the 1.6.0 sections. Owned by the overlay-section change, not restated here.",
    ),
    (
        "/paths/~1api~1v1~1admin~1overlay~1{section}/delete/summary",
        "Same derived section enumeration as the 400 description above.",
    ),
    (
        // plane-purity: frozen-wire the OpenAPI 3.1 keyword in a pointer, not the LLM dialect
        "/paths/~1api~1v1~1admin~1overlay~1{section}/delete/responses/409/description",
        "A NEW ERROR CONDITION, not a prose edit: 1.6.0 added `Conflict/StillReferenced` (a \
         section reset that would leave base config.yaml naming a definition it removes). The \
         description is generated from the endpoint's declared taxonomy, so restoring 1.5.5's \
         string means UN-DECLARING a reachable 409 — which \
         `declared_error_set_is_exactly_what_the_handlers_emit` correctly refuses. Documenting a \
         real failure is the additive reading; the owner rules on the wording.",
    ),
];

/// The published 1.5.5 document — the contract this one is measured against.
const V155_FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../testing/shadow-oracle/fixtures/openapi-1.5.5.json"
);

/// Walk 1.5.5's document and collect the JSON pointer of every place 1.6.0's is not a superset.
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

    let frozen: &[(&str, &str)] = &[
        ("HookView", "description"),
        ("HookView", "properties/at/description"),
        ("NamedDefView", "description"),
        ("NamedDefView", "properties/module/description"),
        ("NamedDefView", "properties/max_admin_scope/description"),
        ("OverlayResetView", "properties/reset/description"),
    ];
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
