//! THE PROTOCOL AXIS AS THE SHIPPED BUILD LINKS IT — the registry and detection folds over the REAL
//! declarations the root installs, read off the linked table (`crate::LINKED.protocols`), never named.
//!
//! These assertions moved here from the composition root's integration suites (ARCHITECT on N4,
//! option (b)): what they prove is a property of the composition — the host's folds over what this
//! build links — so the root holds them. The protocol names, paths, headers and bodies they are held
//! to are fixture DATA (`fixtures/linked_protocols.json`, ARCHITECT F-T), so this source names no
//! plane. The registry's own machinery over synthetic declarations is the kernel's to prove
//! (`busbar-kernel`'s `proto` tests, `registry_fold`).
//!
//! Compiled only in a build that links every plane (`linked_every_plane`): the fixture is the shipped
//! composition's, and a single-plane build links a different protocol set.

use busbar_contract::codec::RequestHandler;
use busbar_contract::http::{HeaderMap, HeaderName, HeaderValue};
use busbar_contract::operation::OpVerb;
use busbar_contract::protocol::ProtocolDecl;
use busbar_kernel::proto::{detect_protocol, residual_dialect_for_path, Registry};
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

/// Seed the process registry with the linked declarations, exactly as the root's boot does — before
/// any fold is read, so no verdict depends on which test ran first.
fn registered() {
    for decls in crate::LINKED.protocols {
        busbar_kernel::proto::register_test_protocols(decls);
    }
}

/// The registry the linked declarations build, as production folds it.
fn builtins() -> Registry {
    Registry::new(linked_decls())
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

/// The cell a protocol declares, read off the process registry the linked table seeded.
fn request_handler(proto: &str) -> Option<&'static dyn RequestHandler> {
    busbar_kernel::proto::decl_for(proto).and_then(|d| d.handler)
}

// ══ THE SURFACE THAT MUST NOT MOVE ═══════════════════════════════════════════════════════════════

/// **THE METRIC-SURFACE PIN.** Protocol names are metric LABELS and `providers.*.protocol` config
/// keys, and telemetry indexes its per-protocol families BY POSITION in this list. Held to the
/// fixture, not derived from the declarations it checks. The order is the published 1.5.5 binary's
/// (shadow-oracle `boot.refusal|BOOT-020|validate`).
#[test]
fn the_derived_protocol_list_is_byte_identical_to_the_const_it_replaced() {
    registered();
    assert_eq!(
        busbar_kernel::proto::known_protocols(),
        strs(&FIXTURE["protocol_order"]).as_slice(),
        "the protocol name set AND ITS ORDER are operator-visible: the order indexes telemetry's \
         metric families and the set is what the config validator accepts"
    );
}

/// THE DERIVED LIST IS NEVER EMPTY IN A BUILD THAT SHIPS A PROTOCOL: an empty fold would make the
/// validator reject every provider with an empty "must be one of:" tail.
#[test]
fn the_derived_protocol_list_is_not_empty() {
    registered();
    assert!(
        !busbar_kernel::proto::known_protocols().is_empty(),
        "the codec-protocol list is derived from the declarations; an empty one means the built-in \
         table stopped being read, and every operator config would be refused with no cause named"
    );
}

/// The three `OnceLock` sweeps the registry absorbed produce exactly these sets, folded from the
/// declarations at boot.
#[test]
fn the_absorbed_sweeps_produce_the_sets_they_produced_before() {
    registered();
    assert_eq!(
        busbar_kernel::proto::streaming_content_types(),
        strs(&FIXTURE["streaming_content_types"]).as_slice(),
        "absorbed proto::streaming_content_types()"
    );
    assert_eq!(
        busbar_kernel::proto::array_stream_shim_keys(),
        strs(&FIXTURE["array_stream_shim_keys"]).as_slice(),
        "absorbed proto::array_stream_shim_keys()"
    );
    assert_eq!(
        builtins().head_keys(),
        strs(&FIXTURE["head_keys"]).as_slice(),
        "absorbed proxy::lazy_body::captured_head_keys() — the four core keys plus every declared \
         shim key, sorted and deduped exactly as the sweep produced them"
    );
}

/// A declaration that CLAIMS a verb it does not serve 404s a working route; one that HIDES a verb it
/// serves makes the metric label space a lie. Both directions, over every linked declaration.
#[test]
fn the_declared_verbs_are_the_verbs_the_handler_serves() {
    registered();
    for decl in builtins().decls() {
        let handler = decl
            .handler
            .unwrap_or_else(|| panic!("{} declares no handler", decl.name));
        let mut candidates: Vec<OpVerb> = OpVerb::ALL
            .iter()
            .chain(busbar_kernel::proto::declared_verbs())
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

/// The registry-level EXHAUSTIVENESS contract: every verb a declaration claims resolves to a serving
/// cell on that declaration's handler.
#[test]
fn every_declared_verb_has_a_serving_handler() {
    registered();
    assert!(
        !busbar_kernel::proto::declared_verbs().is_empty(),
        "the registry must declare at least the linked planes' verbs"
    );
    for decl in builtins().decls() {
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

/// A linked protocol that declares no codec still resolves, still dispatches, and MUST NOT be offered
/// to a provider lane: it is absent from the codec-protocol list, without anything comparing its
/// name. Every such linked declaration is checked; the build links at least one.
#[test]
fn a_declaration_without_a_codec_dispatches_but_is_not_a_provider_protocol() {
    registered();
    assert!(
        !busbar_kernel::proto::known_protocols().is_empty(),
        "the exclusion below is asserted against a NON-EMPTY codec fold"
    );
    let codec_less: Vec<&'static ProtocolDecl> = linked_decls()
        .into_iter()
        .filter(|d| d.codec.is_none())
        .collect();
    assert!(
        !codec_less.is_empty(),
        "the shipped build links a codec-less protocol"
    );
    for decl in codec_less {
        let d = busbar_kernel::proto::decl_for(decl.name).expect("it declares itself");
        assert!(d.codec.is_none());
        assert!(d.handler.is_some(), "{} serves operations", d.name);
        assert!(
            !busbar_kernel::proto::known_protocols().contains(&d.name),
            "a provider lane cannot name {}, which has no wire codec",
            d.name
        );
    }
}

/// Two declarations of one name would make one unroutable; a boot panic is the only honest answer.
#[test]
#[should_panic(expected = "two protocol declarations claim the same name")]
fn two_declarations_of_one_name_are_refused() {
    let mut decls = linked_decls();
    decls.push(decls[0]);
    let _ = Registry::new(decls);
}

/// **THE FOLD-AHEAD RULE IS SAFE FOR A CODEC-LESS PROTOCOL.** The operator-visible list is
/// `codec_protocols`, built by SKIPPING every declaration whose `codec` is `None`, so a codec-less
/// declaration at the TAIL (the monolith's shape) or the HEAD (the extracted binary's shape) derives
/// the identical list over the linked codec declarations.
#[test]
fn a_codec_less_declaration_does_not_move_the_operator_visible_list_when_it_is_folded_ahead() {
    static CODEC_LESS: ProtocolDecl = ProtocolDecl::named("codec-less");
    let with_codecs: Vec<&'static ProtocolDecl> = linked_decls()
        .into_iter()
        .filter(|d| d.codec.is_some())
        .collect();
    let at_the_tail: Vec<&'static ProtocolDecl> = with_codecs
        .iter()
        .copied()
        .chain(std::iter::once(&CODEC_LESS))
        .collect();
    let at_the_head: Vec<&'static ProtocolDecl> = std::iter::once(&CODEC_LESS)
        .chain(with_codecs.iter().copied())
        .collect();
    assert_ne!(
        at_the_tail.iter().map(|d| d.name).collect::<Vec<_>>(),
        at_the_head.iter().map(|d| d.name).collect::<Vec<_>>(),
        "the two declaration orders must actually differ or the assertion below is vacuous"
    );
    assert_eq!(
        Registry::new(at_the_tail).codec_protocols(),
        Registry::new(at_the_head).codec_protocols(),
        "a declaration that ships no wire codec contributes no entry to the operator-visible list"
    );
}

// ══ DETECTION ════════════════════════════════════════════════════════════════════════════════════

/// The resolver table through the REAL two-step pipeline: the fold IDs the protocol, then that
/// protocol's `RequestHandler::resolve_operation` decides the operation — including collision
/// defaults and ordering, then the cases the body disambiguates.
#[test]
fn resolver_table() {
    registered();
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
    registered();
    let case = &FIXTURE["mandatory_header"];
    let p = detect_protocol(case[0].as_str().expect("path"), &headers(&case[1])).unwrap();
    assert_eq!(p, case[2].as_str().expect("proto"));
}

/// The headerless residual classifier: a model id that CONTAINS a colon stays with its dialect, and
/// only the known action suffixes move to another — each row as the fixture records it.
#[test]
fn test_residual_dialect_colon_model_id_is_openai_not_gemini() {
    registered();
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
/// positive control first: an unseeded registry answers `None` everywhere, so the fold must be live.
#[test]
fn test_residual_dialect_names_none_rather_than_defaulting_to_openai() {
    registered();
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
