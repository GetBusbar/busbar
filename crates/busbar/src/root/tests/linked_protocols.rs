//! THE PROTOCOL AXIS AS THE SHIPPED BUILD LINKS IT — the linked planes' own dialect declarations,
//! read off the linked table (`crate::LINKED.protocols`), never named.
//!
//! These assertions moved here from the composition root's integration suites (ARCHITECT on N4,
//! option (b)): what they prove is a property of the composition — what this build links — so the
//! root holds them. The protocol names, paths, headers and bodies they are held to are fixture DATA
//! (`fixtures/linked_protocols.json`, ARCHITECT F-T), so this source names no plane. The kernel holds
//! no protocol set (a plane resolves its own dialects, spec Part 1, Law 5): the folds below are this
//! suite's own reading of the declarations, the plane's statements about its dialects.
//!
//! Compiled only in a build that links every plane (`linked_every_plane`): the fixture is the shipped
//! composition's, and a single-plane build links a different protocol set.

use busbar_contract::codec::RequestHandler;
use busbar_contract::operation::OpVerb;
use busbar_contract::protocol::ProtocolDecl;
use http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;
use std::sync::LazyLock;

/// The fixture the assertions below are held to.
static FIXTURE: LazyLock<Value> = LazyLock::new(|| {
    serde_json::from_str(include_str!("fixtures/linked_protocols.json"))
        .expect("the linked-protocols fixture is JSON")
});

/// Every protocol declaration the root links, in the linked table's order.
fn linked_decls() -> Vec<&'static ProtocolDecl> {
    crate::LINKED
        .protocols
        .iter()
        .flat_map(|decls| decls.iter().copied())
        .collect()
}

/// The dialect a request speaks, as the linked declarations' own claims fold it: every declaration's
/// [`ProtocolDecl::claim_over`] in the linked order, the TIGHTEST claim kept, a tie broken by order.
fn detect_protocol(path: &str, headers: &HeaderMap) -> Option<&'static str> {
    let fields: Vec<(&[u8], &[u8])> = headers
        .iter()
        .map(|(n, v)| (n.as_str().as_bytes(), v.as_bytes()))
        .collect();
    linked_decls()
        .into_iter()
        .filter_map(|d| d.claim_over(path, &fields).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

/// The dialect a path names from its shape alone, as the linked declarations' residual claims fold
/// it (`ProtocolDecl::residual_claims`), the tightest kept.
fn residual_dialect_for_path(path: &str) -> Option<&'static str> {
    linked_decls()
        .into_iter()
        .filter_map(|d| d.residual_claims.and_then(|c| c(path)).map(|s| (s, d.name)))
        .min_by(|a, b| a.0.cmp(&b.0))
        .map(|(_, name)| name)
}

/// Every verb a linked declaration serves, in the linked order, deduped.
fn declared_verbs() -> Vec<OpVerb> {
    let mut verbs: Vec<OpVerb> = Vec::new();
    for d in linked_decls() {
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

fn headers(v: &Value) -> HeaderMap {
    let mut h = HeaderMap::new();
    for pair in v.as_array().expect("header pairs") {
        let (k, val) = (
            pair[0].as_str().expect("name"),
            pair[1].as_str().expect("value"),
        );
        h.insert(
            HeaderName::from_bytes(k.as_bytes()).expect("a header name"),
            HeaderValue::from_str(val).expect("a header value"),
        );
    }
    h
}

/// The cell a linked declaration states, by its name.
fn request_handler(proto: &str) -> Option<&'static dyn RequestHandler> {
    linked_decls()
        .into_iter()
        .find(|d| d.name == proto)
        .and_then(|d| d.handler)
}

// ══ THE SURFACE THAT MUST NOT MOVE ═══════════════════════════════════════════════════════════════

/// The stream media the root relays piece by piece ([`crate::root::linked::stream_media`]) are the
/// event-stream content types the linked declarations state.
#[test]
fn the_linked_stream_media_are_the_declared_event_content_types() {
    assert_eq!(
        crate::root::linked::stream_media(&crate::LINKED),
        strs(&FIXTURE["event_content_types"]),
        "the event-stream content types the linked declarations state"
    );
}

/// A declaration that CLAIMS a verb it does not serve 404s a working route; one that HIDES a verb it
/// serves makes the metric label space a lie. Both directions, over every linked declaration.
#[test]
fn the_declared_verbs_are_the_verbs_the_handler_serves() {
    for decl in linked_decls() {
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
        "the linked declarations must declare at least the linked planes' verbs"
    );
    for decl in linked_decls() {
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
        let got = detect_protocol(path, &headers(&case[1])).and_then(|proto| {
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
        let proto = detect_protocol(path, &HeaderMap::new()).expect(path);
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
    let p = detect_protocol(case[0].as_str().expect("path"), &headers(&case[1])).unwrap();
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

/// THE AUTHENTICATION REFUSAL'S TAP LABEL IS ITS PATH'S, WHATEVER THE VERB. v1.5.5 told a
/// `rejected_by_auth` response tap the dialect it read off the path alone
/// (`crates/busbar/src/auth/mod.rs:1167` at v1.5.5, `proto_for_path(path)`), so neither the verb nor
/// the route a request matched moved it. Each fixture row is a request and that function's answer
/// for it, verbatim; the kernel computes the label with no verb and no route in hand
/// ([`busbar_kernel::ingress::native::labelled_dialect`]), over the path dialects this root installs
/// ([`crate::root::linked::path_dialects`]), on a path no plane is mounted at.
#[test]
fn an_auth_denial_is_tapped_under_the_1_5_5_label_of_its_path_whatever_the_verb() {
    let dialects = crate::root::linked::path_dialects(&crate::LINKED);
    let rows = FIXTURE["auth_denial_label"]
        .as_array()
        .expect("auth_denial_label");
    assert!(!rows.is_empty(), "the fixture names the requests");
    for row in rows {
        let method = row[0].as_str().expect("method");
        let path = row[1].as_str().expect("path");
        assert_eq!(
            busbar_kernel::ingress::native::labelled_dialect(
                busbar_kernel::plane::Ingress::Fallback,
                path,
                Some(&dialects),
            ),
            row[2].as_str(),
            "the tap label of an authentication refusal to {method} {path}"
        );
    }
}

// ══ THE METRIC LABELS ARE DECLARED DATA (ARCHITECT ruling 2026-10-16 item 4) ═════════════════════════

/// The fallback plane every linked door row folds to, as the composition root folds it: the one
/// linked door whose Statement tail flags it the fallback.
fn fallback_door_row() -> &'static busbar_kernel::plane::registry::PlaneDecl {
    use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
    let mut fallbacks: Vec<_> = crate::LINKED
        .plane_doors
        .iter()
        .map(|door| registration(linked_probe(*door, "fallback-dialects")).expect("binds"))
        .filter(|reg| reg.fallback)
        .collect();
    assert_eq!(fallbacks.len(), 1, "one linked door is the fallback plane");
    busbar_kernel::plane::door::fold(fallbacks.remove(0)).expect("the door folds")
}

/// **THE `/metrics` LABEL VOCABULARY IS UNCHANGED FROM 1.5.5.** The kernel banks
/// `busbar_requests_total{ingress_protocol,..}`, `busbar_request_duration_seconds{ingress_protocol,..}`
/// and `busbar_translations_total{from,to}` over the fallback plane's DECLARED dialects (its door's
/// Statement tail, read through its registry row), never a codec list; telemetry indexes the families
/// by position, so the order is load-bearing too. Held to the 1.5.5 list (the fixture's
/// `protocol_order`, the published binary's). RED arm: a fallback door that declared a different
/// list, or one in another order, renames or renumbers every banked series.
#[test]
fn the_fallback_doors_declared_dialects_are_the_1_5_5_metric_labels() {
    let row = fallback_door_row();
    assert_eq!(
        (row.wire_format_names)(),
        strs(&FIXTURE["protocol_order"]).as_slice(),
        "the banked ingress_protocol / from / to labels, and their order, are 1.5.5's"
    );
}

/// **THE PROVIDER PROTOCOLS ARE DECLARED DATA, AND 1.5.5'S** (ARCHITECT ruling 2026-10-16 item 3). The
/// boot accepts a provider whose `protocol` a registered plane declares provider-capable (its
/// door's `dialect_auth` lines flagged `DIALECT_PROVIDER`), and the validator's `must be one of:`
/// tail and the lane build's `(supported: …)` list are that declaration, in order. Held to the 1.5.5
/// list (the fixture's `protocol_order`); `tests/cli_validate.rs` holds the binary's refusal bytes.
/// RED arm: a fallback door that flagged no dialect refuses every provider, and one that flagged
/// them in another order reorders the operator's refusal.
#[test]
fn the_fallback_doors_provider_dialects_are_the_1_5_5_provider_protocols() {
    let row = fallback_door_row();
    assert_eq!(
        (row.provider_dialects)(),
        strs(&FIXTURE["protocol_order"]).as_slice(),
        "the provider protocols a config may name, and their order, are 1.5.5's"
    );
}
