// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S DIALECT DECLARATIONS, held to their recorded facts. Re-homed from the composition
//! root's protocol-axis suite (`busbar/src/root/tests/linked_protocols.rs`), which proved these
//! through the kernel's protocol registry; the registry is gone (ARCHITECT ruling 2026-10-07: a
//! plane reading its own declarations instead of the kernel's protocol registry is an accepted
//! mechanical change), so each fact is proved here over the declarations and folds this plane owns.
//! The names, paths, headers and bodies are fixture data (`fixtures/linked_protocols.json`).

use busbar_contract::operation::OpVerb;
use busbar_contract::protocol::ProtocolDecl;
use busbar_plane_llm::codec::DECLS;
use busbar_plane_llm::exchange::arrive::{detect, envelope_for, residual};
use serde_json::Value;
use std::sync::LazyLock;

static FIXTURE: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("fixtures/linked_protocols.json"))
        .expect("the protocols fixture is JSON")
});

fn strs(v: &Value) -> Vec<&str> {
    v.as_array()
        .expect("an array")
        .iter()
        .map(|s| s.as_str().expect("a string"))
        .collect()
}

fn fields(v: &Value) -> Vec<(Vec<u8>, Vec<u8>)> {
    v.as_array()
        .expect("header pairs")
        .iter()
        .map(|p| {
            (
                p[0].as_str().expect("name").as_bytes().to_vec(),
                p[1].as_str().expect("value").as_bytes().to_vec(),
            )
        })
        .collect()
}

fn detected(path: &str, f: &[(Vec<u8>, Vec<u8>)]) -> Option<&'static str> {
    let head: Vec<(&[u8], &[u8])> = f
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    detect(path, &head)
}

fn decl(name: &str) -> &'static ProtocolDecl {
    DECLS
        .iter()
        .copied()
        .find(|d| d.name == name)
        .unwrap_or_else(|| panic!("{name} is declared"))
}

/// A sorted, deduplicated fold of what the declarations state.
fn folded<'a>(items: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut v: Vec<&str> = items.collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// **THE METRIC-SURFACE PIN.** The dialect names are metric labels and `providers.*.protocol`
/// values, and telemetry banks its per-dialect families BY POSITION in this list (the tail's
/// dialects). Held to the fixture, in the published 1.5.5 order.
#[test]
fn the_derived_protocol_list_is_byte_identical_to_the_const_it_replaced() {
    let names: Vec<&str> = DECLS
        .iter()
        .filter(|d| d.codec.is_some())
        .map(|d| d.name)
        .collect();
    assert_eq!(names, strs(&FIXTURE["protocol_order"]));
}

/// THE LIST IS NEVER EMPTY: an empty one would refuse every provider with an empty "must be one
/// of:" tail.
#[test]
fn the_derived_protocol_list_is_not_empty() {
    assert!(DECLS.iter().any(|d| d.codec.is_some()));
}

/// The three sweeps the kernel registry once folded produce the sets they produced, folded over the
/// plane's own declarations.
#[test]
fn the_absorbed_sweeps_produce_the_sets_they_produced_before() {
    assert_eq!(
        folded(DECLS.iter().filter_map(|d| d.streaming_content_type)),
        strs(&FIXTURE["streaming_content_types"])
    );
    assert_eq!(
        folded(DECLS.iter().filter_map(|d| d.array_stream_shim_key)),
        strs(&FIXTURE["array_stream_shim_keys"])
    );
    assert_eq!(
        folded(
            DECLS
                .iter()
                .flat_map(|d| d.head_keys.iter().copied().chain(d.array_stream_shim_key))
        ),
        strs(&FIXTURE["head_keys"])
    );
}

/// A declaration that CLAIMS a verb it does not serve 404s a working route; one that HIDES a verb
/// it serves makes the metric label space a lie. Both directions, over every declaration.
#[test]
fn the_declared_verbs_are_the_verbs_the_handler_serves() {
    let mut all: Vec<OpVerb> = OpVerb::ALL.to_vec();
    for d in DECLS {
        all.extend(d.verbs.iter().copied());
    }
    all.sort_unstable_by_key(|op| op.name());
    all.dedup_by_key(|op| op.name());
    for d in DECLS {
        let handler = d
            .handler
            .unwrap_or_else(|| panic!("{} declares no handler", d.name));
        let mut served: Vec<&str> = all
            .iter()
            .filter(|op| handler.operation_handler(**op).is_some())
            .map(|op| op.name())
            .collect();
        let mut declared: Vec<&str> = d.verbs.iter().map(|v| v.name()).collect();
        served.sort_unstable();
        declared.sort_unstable();
        assert_eq!(declared, served, "{}", d.name);
        assert_eq!(handler.protocol_name(), d.name);
    }
}

/// EXHAUSTIVENESS: every verb a declaration claims resolves to a serving cell.
#[test]
fn every_declared_verb_has_a_serving_handler() {
    assert!(DECLS.iter().any(|d| !d.verbs.is_empty()));
    for d in DECLS {
        let Some(handler) = d.handler else { continue };
        for verb in d.verbs {
            assert!(
                handler.operation_handler(*verb).is_some(),
                "{} declares verb '{}' but serves no cell for it",
                d.name,
                verb.name()
            );
        }
    }
}

/// Two declarations of one name would make one unroutable: the plane's dialect names are unique.
#[test]
fn two_declarations_of_one_name_are_refused() {
    let names = folded(DECLS.iter().map(|d| d.name));
    assert_eq!(names.len(), DECLS.len(), "each dialect is declared once");
}

/// The resolver table through the two-step pipeline: the fold IDs the dialect, then that dialect's
/// handler decides the operation — including collision defaults, ordering, and the cases the body
/// disambiguates.
#[test]
fn resolver_table() {
    for case in FIXTURE["resolver"].as_array().expect("resolver") {
        let path = case[0].as_str().expect("path");
        let got = detected(path, &fields(&case[1])).and_then(|proto| {
            decl(proto)
                .handler
                .and_then(|rh| rh.resolve_operation(path, b""))
                .map(|op| (proto, op.name()))
        });
        let want = case[2]
            .as_array()
            .map(|w| (w[0].as_str().expect("proto"), w[1].as_str().expect("verb")));
        assert_eq!(got, want, "path {path:?} headers {}", case[1]);
    }
    for case in FIXTURE["body_resolver"].as_array().expect("body_resolver") {
        let (path, body) = (
            case[0].as_str().expect("path"),
            case[1].as_str().expect("body"),
        );
        let proto = detected(path, &[]).expect(path);
        assert_eq!(proto, case[2][0].as_str().expect("proto"), "{path:?}");
        let op = decl(proto)
            .handler
            .and_then(|rh| rh.resolve_operation(path, body.as_bytes()))
            .expect(path);
        assert_eq!(op.name(), case[2][1].as_str().expect("verb"), "{path:?}");
    }
}

/// A request carrying a dialect's mandatory header resolves to that dialect even on a path another
/// dialect's ordering would also claim.
#[test]
fn mandatory_header_beats_path_ordering() {
    let case = &FIXTURE["mandatory_header"];
    let p = detected(case[0].as_str().expect("path"), &fields(&case[1]));
    assert_eq!(p, case[2].as_str());
}

/// The headerless residual classifier: a model id that CONTAINS a colon stays with its dialect, and
/// only the known action suffixes move to another — each row as the fixture records it.
#[test]
fn test_residual_dialect_colon_model_id_is_openai_not_gemini() {
    for case in FIXTURE["residual"].as_array().expect("residual") {
        let path = case[0].as_str().expect("path");
        assert_eq!(residual(path), case[1].as_str(), "{path:?}");
    }
}

/// A PATH THAT NAMES NO DIALECT ANSWERS `None`. The positive control first, so the fold is live.
#[test]
fn test_residual_dialect_names_none_rather_than_defaulting_to_openai() {
    let live = &FIXTURE["residual_live"];
    assert_eq!(residual(live[0].as_str().expect("path")), live[1].as_str());
    for path in strs(&FIXTURE["residual_none"]) {
        assert_eq!(residual(path), None, "`{path}` names no dialect");
    }
}

/// A no-route 404 on a dialect's path answers in that dialect's native envelope (`application/json`,
/// the envelope's own key) with the vendor head fields a real endpoint always emits: the kernel's
/// no-route refusal (`no_route`) as this plane's `refusal` renders it from the target.
#[test]
fn the_fallback_404_on_a_dialects_path_is_its_native_envelope_with_its_head_fields() {
    // The host's entropy source, as the kernel arms it at boot: a request id is minted from it.
    busbar_contract::codec::install_entropy_source(|out| getrandom::fill(out).is_ok());
    let case = &FIXTURE["fallback_native_404"];
    let path = case["path"].as_str().expect("path");
    let no_route = busbar_contract::abi::plane::RefusalCode::NoRoute.code();
    let r = busbar_plane_llm::exchange::refuse::kernel_refusal(
        envelope_for(path),
        no_route,
        404,
        "missing",
        0,
    );
    assert_eq!(r.status, 404);
    let field = |n: &str| r.fields.iter().find(|(k, _)| k.eq_ignore_ascii_case(n));
    assert_eq!(
        field("content-type").map(|(_, v)| v.as_slice()),
        Some(&b"application/json"[..])
    );
    for name in strs(&case["headers"]) {
        assert!(field(name).is_some(), "the 404 must carry {name}");
    }
    let v: Value = serde_json::from_slice(&r.body).expect("a JSON body");
    assert!(
        v.get(case["body_key"].as_str().expect("body_key"))
            .is_some(),
        "the native envelope: {v}"
    );
}
