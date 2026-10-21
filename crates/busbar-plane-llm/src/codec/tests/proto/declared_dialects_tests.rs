// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THIS PLANE'S DIALECT DECLARATIONS, PROVEN BY THE PLANE. These cells moved here from the
//! composition root's linked-protocols suite when the root's protocol axis was deleted: the kernel
//! and the root hold no protocol set and read a plane's facts only through its door
//! (BUSBAR-1.6.0.md l.4965, l.1194), so how this plane detects and serves its own dialects is this
//! crate's to prove. The paths, headers and bodies they are held to are fixture DATA
//! (`declared_dialects.json`), unchanged from the root's fixture they moved out of.
//!
//! Two of them hold the plane's declarations to what its door states, so the root's door reads
//! cannot drift from what the plane serves: the door's dialects are the codec dialects, and the
//! `stream_media` its `declares` section states are the streaming content types its writers emit
//! beyond the contract's event stream (ARCHITECT ruling on the stream-media carrier, l.246).

use crate::codec::DECLS;
use busbar_contract::codec::RequestHandler;
use busbar_contract::operation::OpVerb;
use busbar_contract::protocol::ProtocolDecl;
use serde_json::Value;
use std::sync::LazyLock;

/// The fixture the assertions below are held to.
static FIXTURE: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("declared_dialects.json"))
        .expect("the declared-dialects fixture is JSON")
});

/// Every dialect declaration this plane makes, in its order.
fn decls() -> Vec<&'static ProtocolDecl> {
    DECLS.to_vec()
}

/// A fixture's header pairs, as the field lines a claim reads.
fn fields(v: &Value) -> Vec<(Vec<u8>, Vec<u8>)> {
    v.as_array()
        .expect("header pairs")
        .iter()
        .map(|pair| {
            (
                pair[0].as_str().expect("name").as_bytes().to_vec(),
                pair[1].as_str().expect("value").as_bytes().to_vec(),
            )
        })
        .collect()
}

/// The dialect a request speaks, as the declarations' own claims fold it: every declaration's
/// [`ProtocolDecl::claim_over`] in order, the TIGHTEST claim kept, a tie broken by order.
fn detect_protocol(path: &str, headers: &Value) -> Option<&'static str> {
    let owned = fields(headers);
    let lines: Vec<(&[u8], &[u8])> = owned
        .iter()
        .map(|(n, v)| (n.as_slice(), v.as_slice()))
        .collect();
    decls()
        .into_iter()
        .filter_map(|d| d.claim_over(path, &lines).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

/// The dialect a path names from its shape alone, as the declarations' residual claims fold it
/// (`ProtocolDecl::residual_claims`), the tightest kept.
fn residual_dialect_for_path(path: &str) -> Option<&'static str> {
    decls()
        .into_iter()
        .filter_map(|d| d.residual_claims.and_then(|c| c(path)).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

/// Every verb a declaration serves, in order, deduped.
fn declared_verbs() -> Vec<OpVerb> {
    let mut verbs: Vec<OpVerb> = Vec::new();
    for d in decls() {
        for v in d.verbs {
            if !verbs.contains(v) {
                verbs.push(*v);
            }
        }
    }
    verbs
}

fn strs(v: &Value) -> Vec<&str> {
    v.as_array()
        .expect("an array")
        .iter()
        .map(|s| s.as_str().expect("a string"))
        .collect()
}

/// The cell a declaration states, by its name.
fn request_handler(proto: &str) -> Option<&'static dyn RequestHandler> {
    decls()
        .into_iter()
        .find(|d| d.name == proto)
        .and_then(|d| d.handler)
}

// ══ WHAT THE DOOR STATES IS WHAT THE PLANE SERVES ════════════════════════════════════════════════

/// The dialects the door's Statement tail states are exactly the codec dialects the declarations
/// carry, in order: the root reads the tail, so a tail that drifted from the codec would name a
/// dialect nothing translates.
#[test]
fn the_doors_dialects_are_the_codec_dialects() {
    let codec: Vec<&str> = decls()
        .into_iter()
        .filter(|d| d.codec.is_some())
        .map(|d| d.name)
        .collect();
    let stated: Vec<&str> = crate::dialect::DIALECTS.iter().map(|d| d.name).collect();
    assert_eq!(
        stated, codec,
        "the door's dialects and the codec's disagree"
    );
}

/// The `stream_media` the plane's `declares` section states are the streaming content types its
/// writers emit beyond the contract's event stream, sorted and deduped. RED arm: a writer that
/// streams a framing the section does not state has its lengthed replies sent whole by the host.
#[test]
fn the_declared_stream_media_are_the_writers_streaming_content_types() {
    let declares: Value =
        serde_json::from_str(crate::DECLARES).expect("the declares section is JSON");
    let declared: Vec<&str> = strs(&declares["stream_media"]);
    let mut written: Vec<&str> = decls()
        .into_iter()
        .filter_map(|d| d.streaming_content_type)
        .filter(|media| *media != busbar_contract::protocol::TEXT_EVENT_STREAM)
        .collect();
    written.sort_unstable();
    written.dedup();
    assert!(
        !written.is_empty(),
        "the positive control: a writer streams a framing of its own"
    );
    assert_eq!(
        declared, written,
        "the declared stream media and the writers' disagree"
    );
}

/// A declaration that CLAIMS a verb it does not serve 404s a working route; one that HIDES a verb it
/// serves makes the metric label space a lie. Both directions, over every declaration.
#[test]
fn the_declared_verbs_are_the_verbs_the_handler_serves() {
    for decl in decls() {
        let handler = decl
            .handler
            .unwrap_or_else(|| panic!("{} declares no handler", decl.name));
        let mut candidates: Vec<OpVerb> = OpVerb::ALL
            .iter()
            .chain(declared_verbs().iter())
            .copied()
            .collect();
        candidates.sort_unstable_by_key(|op| op.name());
        candidates.dedup_by_key(|op| op.name());
        let mut served: Vec<&'static str> = candidates
            .iter()
            .filter(|op| handler.operation_handler(**op).is_some())
            .map(|op| op.name())
            .collect();
        let mut declared: Vec<&'static str> = decl.verbs.iter().map(|v| v.name()).collect();
        declared.sort_unstable();
        served.sort_unstable();
        assert_eq!(
            declared, served,
            "{}'s declaration and its handler disagree about which verbs it serves",
            decl.name
        );
        assert_eq!(
            handler.protocol_name(),
            decl.name,
            "a handler filed under a name it does not answer to is a registry key that means nothing"
        );
    }
}

/// The EXHAUSTIVENESS contract: every verb a declaration claims resolves to a serving cell on that
/// declaration's handler.
#[test]
fn every_declared_verb_has_a_serving_handler() {
    assert!(
        !declared_verbs().is_empty(),
        "the declarations must declare at least the plane's verbs"
    );
    for decl in decls() {
        let Some(handler) = decl.handler else {
            continue;
        };
        for verb in decl.verbs {
            assert!(
                handler.operation_handler(*verb).is_some(),
                "{} declares verb '{}' but its handler serves no cell for it",
                decl.name,
                verb.name(),
            );
        }
    }
}

// ══ DETECTION ════════════════════════════════════════════════════════════════════════════════════

/// The resolver table through the two-step pipeline: the declarations' fold IDs the protocol, then
/// that protocol's `RequestHandler::resolve_operation` decides the operation — including collision
/// defaults and ordering, then the cases the body disambiguates.
#[test]
fn resolver_table() {
    for case in FIXTURE["resolver"].as_array().expect("resolver") {
        let path = case[0].as_str().expect("path");
        let got = detect_protocol(path, &case[1]).and_then(|proto| {
            request_handler(proto)
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
        let proto = detect_protocol(path, &Value::Array(Vec::new())).expect(path);
        assert_eq!(
            proto,
            case[2][0].as_str().expect("proto"),
            "protocol for {path:?}"
        );
        let op = request_handler(proto)
            .and_then(|rh| rh.resolve_operation(path, body.as_bytes()))
            .expect(path);
        assert_eq!(
            op.name(),
            case[2][1].as_str().expect("verb"),
            "operation for {path:?}"
        );
    }
}

/// A request carrying a dialect's mandatory header resolves to that dialect even on a path that
/// another dialect's ordering would also claim.
#[test]
fn mandatory_header_beats_path_ordering() {
    let case = &FIXTURE["mandatory_header"];
    let p = detect_protocol(case[0].as_str().expect("path"), &case[1]).unwrap();
    assert_eq!(p, case[2].as_str().expect("proto"));
}

/// The headerless residual classifier: a model id that CONTAINS a colon stays with its dialect, and
/// only the known action suffixes move to another — each row as the fixture records it.
#[test]
fn test_residual_dialect_colon_model_id_is_openai_not_gemini() {
    for case in FIXTURE["residual"].as_array().expect("residual") {
        let path = case[0].as_str().expect("path");
        assert_eq!(
            residual_dialect_for_path(path),
            case[1].as_str(),
            "residual classification of {path:?}"
        );
    }
}

/// A PATH THAT NAMES NO DIALECT ANSWERS `None` — including the paths other planes are mounted at. The
/// positive control first: the fold must be live, or the `None` assertions prove nothing.
#[test]
fn test_residual_dialect_names_none_rather_than_defaulting_to_openai() {
    let live = &FIXTURE["residual_live"];
    assert_eq!(
        residual_dialect_for_path(live[0].as_str().expect("path")),
        live[1].as_str(),
        "the residual fold must be live, or the `None` assertions below prove nothing"
    );
    for path in strs(&FIXTURE["residual_none"]) {
        assert_eq!(
            residual_dialect_for_path(path),
            None,
            "`{path}` names no dialect — the classifier must say so, not name a default"
        );
    }
}
