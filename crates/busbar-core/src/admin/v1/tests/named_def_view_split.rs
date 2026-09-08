// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE 1.5.5 NAMED-DEFINITION VIEW IS FROZEN; THE PLANE SECTIONS GOT THEIR OWN.
//!
//! `identity-providers:` and `export:` shipped in 1.5.5. `tools:` and `agents:` are new in 1.6.0.
//! All four are served by ONE generic handler, and 1.6.0 briefly gave all four ONE schema too —
//! which cost the older pair real contract ground. An `agents:` entry names no plugin, so `module`
//! acquired `#[serde(skip_serializing_if = "String::is_empty")]`, and schemars duly dropped it from
//! `NamedDefView.required`. That is a NARROWING for `/export` and `/identity-providers`, whose
//! bodies have never once omitted `module` — and `NamedDefView` is `$ref`ed by twelve operations
//! that all shipped in 1.5.5, so PB-75's byte-for-byte bind broke on a field nobody meant to touch.
//!
//! The fix splits the VIEW, not the handler: `NamedDefView` is frozen at the 1.5.5 shape and
//! `PlaneNamedDefView` carries the plane sections. `NamedMapSection::requires_module()` — already
//! the predicate the WRITE path enforces — is what selects between them, in the projection and in
//! the OpenAPI registration alike, so the document and the body cannot disagree about a section.
//!
//! The 1.5.5 fixtures below are the bytes a real 1.6.0 binary served, taken from the
//! `admin.ops|GetExportName|ok` and `admin.ops|GetIdentityProvidersName|ok` shadow-oracle cells.

use crate::admin::v1::contract::{AnyNamedDefView, NamedDefView, PlaneNamedDefView};
use crate::config::named_map::NamedMapSection;

/// `GET /export/metrics` as recorded: `{name, module, settings_keys}` and nothing else. Written in
/// DECLARATION order (which is what `json::ok_json`'s `serde_json::to_string` emits) rather than the
/// recording's alphabetical order — the oracle harness stores bodies parsed, so its key order is a
/// `BTreeMap` artifact. The recorded `content-length: 75` is what pins this string as the real wire
/// bytes: it matches this spelling exactly, and does not match the alphabetical one.
const RECORDED_EXPORT_BODY: &str =
    r#"{"name":"metrics","module":"prometheus","settings_keys":["buffer_seconds"]}"#;

/// `GET /identity-providers/admin-tokens` as recorded, likewise in declaration order; the recorded
/// `content-length: 123` matches this string.
const RECORDED_IDP_BODY: &str = r#"{"name":"admin-tokens","module":"admin-tokens","settings_keys":[],"token_configured":true,"browser_login_configured":false}"#;

/// THE FROZEN 1.5.5 EXPORT BODY, byte for byte. An `export:` definition serialises to exactly the
/// bytes the recorded cell carries — same members, same order, same values, no additions.
#[test]
fn an_export_def_serialises_to_the_recorded_1_5_5_bytes() {
    let view = NamedDefView {
        name: "metrics".to_string(),
        module: "prometheus".to_string(),
        settings_keys: vec!["buffer_seconds".to_string()],
        max_admin_scope: None,
        token_configured: None,
        browser_login_configured: None,
        unparseable: None,
    };
    assert_eq!(
        serde_json::to_string(&view).expect("serialises"),
        RECORDED_EXPORT_BODY,
        "the /export/{{name}} body must stay byte-identical to what 1.5.5 (and the recorded 1.6.0 \
         binary) served"
    );
}

/// The same freeze for `identity-providers:`, which additionally carries its two credential
/// booleans — and, crucially, still carries them in the 1.5.5 positions.
#[test]
fn an_identity_provider_def_serialises_to_the_recorded_1_5_5_bytes() {
    let view = NamedDefView {
        name: "admin-tokens".to_string(),
        module: "admin-tokens".to_string(),
        settings_keys: Vec::new(),
        max_admin_scope: None,
        token_configured: Some(true),
        browser_login_configured: Some(false),
        unparseable: None,
    };
    assert_eq!(
        serde_json::to_string(&view).expect("serialises"),
        RECORDED_IDP_BODY,
        "the /identity-providers/{{name}} body must stay byte-identical to the recorded cell"
    );
}

/// Wrapping either view in the zero-byte union the generic handler returns must not change one
/// byte: `#[serde(untagged)]` serialises the variant's contents with no discriminant. This is the
/// whole basis for keeping ONE handler across two schemas.
#[test]
fn the_union_wrapper_is_byte_transparent() {
    let view = NamedDefView {
        name: "metrics".to_string(),
        module: "prometheus".to_string(),
        settings_keys: vec!["buffer_seconds".to_string()],
        max_admin_scope: None,
        token_configured: None,
        browser_login_configured: None,
        unparseable: None,
    };
    let bare = serde_json::to_string(&view).expect("serialises");
    let wrapped =
        serde_json::to_string(&AnyNamedDefView::Instance(view)).expect("wrapped serialises");
    assert_eq!(bare, wrapped, "AnyNamedDefView must add no bytes");
    assert_eq!(wrapped, RECORDED_EXPORT_BODY);
}

/// AN AGENTS DEF OMITS `module` ENTIRELY — the reason the plane sections needed their own view. Not
/// `"module":""`: an empty string would assert a backing plugin that does not exist.
#[test]
fn an_agents_def_serialises_without_a_module_key() {
    let view = PlaneNamedDefView {
        name: "partner-bot".to_string(),
        module: None,
        settings_keys: Vec::new(),
        pin_mechanism: Some("jws_issuer_key".to_string()),
        fingerprint_pinned: Some(false),
        reverify_ttl: Some("24h".to_string()),
        unparseable: None,
    };
    let body = serde_json::to_string(&view).expect("serialises");
    assert!(
        !body.contains("\"module\""),
        "an agents registration names no module, so the key is OMITTED, not empty-stringed: {body}"
    );
    assert_eq!(
        body,
        r#"{"name":"partner-bot","settings_keys":[],"pin_mechanism":"jws_issuer_key","fingerprint_pinned":false,"reverify_ttl":"24h"}"#
    );
}

/// `tools:` uses the SAME plane view but does fill `module` — with the authenticity root, which for
/// a remote endpoint is what "what is behind this entry" means. So the plane view's `module` is
/// genuinely optional (present here, absent above), which is exactly why it cannot share a schema
/// with the frozen 1.5.5 view.
#[test]
fn a_tools_def_fills_the_optional_module_with_its_pin_mechanism() {
    let view = PlaneNamedDefView {
        name: "search".to_string(),
        module: Some("cert_spki".to_string()),
        settings_keys: vec!["web.search".to_string()],
        pin_mechanism: None,
        fingerprint_pinned: None,
        reverify_ttl: None,
        unparseable: None,
    };
    assert_eq!(
        serde_json::to_string(&view).expect("serialises"),
        r#"{"name":"search","module":"cert_spki","settings_keys":["web.search"]}"#
    );
}

/// THE UNPARSEABLE PATH, which is the one projection that can reach EITHER view and the only way a
/// 1.5.5 section can have no module to report. On a plugin-instance section it emits `"module":""`
/// — precisely what 1.5.5 served for this case, and the reason `module` can stay in that schema's
/// `required` without the schema lying.
#[test]
fn an_unparseable_1_5_5_section_entry_emits_an_empty_module_rather_than_omitting_it() {
    let entry = crate::config::overlay::UnparseableNamedDef {
        raw: serde_json::json!({}),
        error: "unknown field `wat`".to_string(),
    };
    let view = crate::admin::v1::named_def_views::unparseable_def_view(
        NamedMapSection::Export,
        "broken",
        &entry,
    );
    let body = serde_json::to_string(&view).expect("serialises");
    assert!(
        body.contains(r#""module":"""#),
        "a plugin-instance section must always carry `module`, empty when unknown: {body}"
    );
    assert_eq!(
        body,
        r#"{"name":"broken","module":"","settings_keys":[],"unparseable":"unknown field `wat`"}"#
    );
}

/// The same entry on a PLANE section omits the key instead — the asymmetry is the section's, not
/// the projection's, and it is read off the one predicate that already governs the write path.
#[test]
fn an_unparseable_plane_section_entry_omits_the_module_key() {
    let entry = crate::config::overlay::UnparseableNamedDef {
        raw: serde_json::json!({}),
        error: "unknown field `wat`".to_string(),
    };
    let view = crate::admin::v1::named_def_views::unparseable_def_view(
        NamedMapSection::Plane("agents"),
        "broken",
        &entry,
    );
    let body = serde_json::to_string(&view).expect("serialises");
    assert!(
        !body.contains("\"module\""),
        "a plane section omits `module` when the raw document has none: {body}"
    );
}

/// THE SCHEMA HALF, asserted against the generated document rather than the committed artefact so
/// it fails on the CODE change. `NamedDefView.required` is back to the 1.5.5 list — `module`
/// included — and the schema carries only the 1.5.5 properties.
#[cfg(feature = "openapi-schema")]
#[test]
fn named_def_view_is_restored_to_its_1_5_5_schema() {
    let doc = crate::admin::v1::json::openapi_doc();
    let schema = &doc["components"]["schemas"]["NamedDefView"];

    let required: Vec<&str> = schema["required"]
        .as_array()
        .expect("NamedDefView.required is an array")
        .iter()
        .map(|v| v.as_str().expect("string"))
        .collect();
    assert_eq!(
        required,
        vec!["name", "module", "settings_keys"],
        "1.5.5's NamedDefView.required, restored verbatim"
    );

    let mut props: Vec<&str> = schema["properties"]
        .as_object()
        .expect("NamedDefView.properties is an object")
        .keys()
        .map(String::as_str)
        .collect();
    props.sort_unstable();
    assert_eq!(
        props,
        vec![
            "browser_login_configured",
            "max_admin_scope",
            "module",
            "name",
            "settings_keys",
            "token_configured",
            "unparseable",
        ],
        "the three agents-only properties must live on PlaneNamedDefView, not here"
    );
}

/// The new schema exists, `module` is optional on it, and it carries the plane columns.
#[cfg(feature = "openapi-schema")]
#[test]
fn plane_named_def_view_is_the_additive_new_schema() {
    let doc = crate::admin::v1::json::openapi_doc();
    let schema = &doc["components"]["schemas"]["PlaneNamedDefView"];

    let required: Vec<&str> = schema["required"]
        .as_array()
        .expect("PlaneNamedDefView.required is an array")
        .iter()
        .map(|v| v.as_str().expect("string"))
        .collect();
    assert_eq!(
        required,
        vec!["name", "settings_keys"],
        "`module` is genuinely optional on a plane section"
    );
    for column in ["pin_mechanism", "fingerprint_pinned", "reverify_ttl"] {
        assert!(
            schema["properties"].get(column).is_some(),
            "PlaneNamedDefView must carry the plane column `{column}`"
        );
    }
}

/// EACH PATH `$ref`s THE ONE VIEW IT CAN SERVE. The 1.5.5 named-map paths must still point at
/// `NamedDefView`, and the 1.6.0-new ones at `PlaneNamedDefView` — a section pointing at the wrong
/// schema is the bug this whole split exists to prevent, and it would be invisible in the schema
/// definitions alone.
#[cfg(feature = "openapi-schema")]
#[test]
fn each_named_map_path_refs_the_view_its_section_serves() {
    let doc = crate::admin::v1::json::openapi_doc();
    for section in NamedMapSection::sections() {
        let expected = if section.requires_module() {
            "NamedDefView"
        } else {
            "PlaneNamedDefView"
        };
        // `path_root()` is the router-relative path; the document keys are absolute.
        let item = format!("/api/v1/admin{}/{{name}}", section.path_root());
        let body = serde_json::to_string(&doc["paths"][&item]["get"]["responses"]["200"])
            .expect("serialises");
        assert!(
            body.contains(&format!("#/components/schemas/{expected}")),
            "GET {item} must $ref {expected}; got {body}"
        );
    }
}

/// NEITHER INTERNAL WRAPPER LEAKS INTO THE DOCUMENT. `AnyNamedDefView` derives `JsonSchema` only to
/// satisfy the bound on `MutatedDefView`, which flattens it; if either name ever reached
/// `components/schemas` a 1.5.5 client would be told `/export` might answer a `oneOf` of two shapes,
/// which is false and is the exact weakening this split undoes.
#[cfg(feature = "openapi-schema")]
#[test]
fn the_internal_union_wrappers_never_reach_the_document() {
    let doc = crate::admin::v1::json::openapi_doc();
    let schemas = doc["components"]["schemas"]
        .as_object()
        .expect("components.schemas is an object");
    for leaked in ["AnyNamedDefView", "MutatedDefView"] {
        assert!(
            !schemas.contains_key(leaked),
            "`{leaked}` is an internal handler type and must not be a documented schema"
        );
    }
}
