// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for [`super::merge_entry`], the RAW per-entry merge patch (RFC 7386) the config overlay
//! uses to record ONE field of a named-map entry without restating the rest of it.
use super::merge_entry;
use serde_json::json;

/// The named fields land and every UNNAMED field of the target survives byte-identical. This is
/// the whole reason the primitive exists: an approval that records a schema-hash must not
/// rewrite the operator's endpoint on its way past.
#[test]
fn named_fields_land_and_unnamed_fields_survive() {
    let mut target = json!({
        "url": "https://mcp.internal/fs",
        "transport": "http",
        "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==" }
    });
    merge_entry(&mut target, &json!({ "transport": "stdio" }));
    assert_eq!(
        target,
        json!({
            "url": "https://mcp.internal/fs",
            "transport": "stdio",
            "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==" }
        })
    );
}

/// Objects merge RECURSIVELY, so one nested leaf can be set without restating its siblings.
#[test]
fn objects_merge_recursively() {
    let mut target = json!({ "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==" } });
    merge_entry(&mut target, &json!({ "pin": { "fingerprint": "abc" } }));
    assert_eq!(
        target,
        json!({
            "pin": { "mechanism": "cert_spki", "key": "sha256/PIN==", "fingerprint": "abc" }
        })
    );
}

/// `null` REMOVES a key (RFC 7386). Without a remove spelling, a patch overlay can only ever
/// grow a document, so a field the operator set in the file could never be unset at runtime.
#[test]
fn null_removes_a_key_and_can_reach_a_nested_one() {
    let mut target = json!({ "a": 1, "b": { "c": 2, "d": 3 } });
    merge_entry(&mut target, &json!({ "a": null, "b": { "c": null } }));
    assert_eq!(target, json!({ "b": { "d": 3 } }));
    // Removing an absent key is a no-op, never an error and never a null-valued key.
    merge_entry(&mut target, &json!({ "nope": null }));
    assert_eq!(target, json!({ "b": { "d": 3 } }));
}

/// An ARRAY is replaced wholesale, never element-merged (RFC 7386). Config lists are ordered,
/// meaningful wholes — `hooks: [a, b]` is a pipeline, not a set — so index-wise merging would
/// invent an ordering nobody wrote.
#[test]
fn arrays_are_replaced_not_element_merged() {
    let mut target = json!({ "hooks": ["a", "b", "c"] });
    merge_entry(&mut target, &json!({ "hooks": ["z"] }));
    assert_eq!(target, json!({ "hooks": ["z"] }));
}

/// A non-object patch REPLACES the target outright — which is what makes whole-entry replace a
/// special case of patching rather than a second, divergent code path. The scalar-over-object
/// case is the one that matters: a field that was a map may legitimately become a scalar.
#[test]
fn a_non_object_patch_replaces_the_target() {
    let mut target = json!({ "a": { "b": 1 } });
    merge_entry(&mut target, &json!({ "a": 7 }));
    assert_eq!(target, json!({ "a": 7 }));

    let mut whole = json!({ "a": 1 });
    merge_entry(&mut whole, &json!("replaced"));
    assert_eq!(whole, json!("replaced"));
}

/// Patching a target that is NOT an object turns it into one, so an entry can be built from
/// nothing. This is the "there is no base entry yet" case: the caller starts from `null`.
#[test]
fn a_patch_onto_a_non_object_builds_an_object() {
    let mut target = json!(null);
    merge_entry(&mut target, &json!({ "url": "https://x" }));
    assert_eq!(target, json!({ "url": "https://x" }));
}

/// IDEMPOTENCE: applying the same patch twice equals applying it once. The overlay replays its
/// patches on every boot and every rebuild, so a patch that drifted on re-application would
/// make the effective config depend on how many times busbar had reloaded.
#[test]
fn applying_a_patch_twice_equals_applying_it_once() {
    let base = json!({ "url": "https://x", "pin": { "key": "k" }, "hooks": ["a"] });
    let patch = json!({ "pin": { "fingerprint": "f" }, "hooks": ["b"], "url": null });
    let mut once = base.clone();
    merge_entry(&mut once, &patch);
    let mut twice = once.clone();
    merge_entry(&mut twice, &patch);
    assert_eq!(once, twice);
}

/// An EMPTY patch changes nothing. The no-op reset case, and the reason an idempotent-success
/// short-circuit upstream can trust "this patch is empty" to mean "nothing to persist".
#[test]
fn an_empty_patch_is_a_no_op() {
    let base = json!({ "url": "https://x", "hooks": ["a"] });
    let mut target = base.clone();
    merge_entry(&mut target, &json!({}));
    assert_eq!(target, base);
}
