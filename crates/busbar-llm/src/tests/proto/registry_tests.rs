// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROTOCOL REGISTRY'S OWN TESTS — and the acceptance test for the whole step.
//!
//! The claim under test is not "the lookup works". It is that **a protocol is now a DECLARATION**:
//! that adding one costs a `ProtocolDecl` plus the cells it names, and costs NO EDIT TO CORE. The
//! model is `audit/tests/chain_tests.rs::a_fourth_stream_costs_a_record_type_and_nothing_else`,
//! which proves the audit chain spans a stream nobody wrote by writing one and chaining it.
//! [`a_protocol_nobody_wrote_costs_a_declaration_and_nothing_else`] is the same claim, one axis over.

use busbar_api::operation::Operation;
use busbar_core::proto::registry::{IngressAuth, ProtocolDecl, Registry};
use busbar_substrate::handlers::{CodecError, IngressReject, OperationHandler, RequestHandler};
use busbar_substrate::ir::subscribe::{SubscribeIntent, SubscribeReq, SubscribeResp};
use busbar_substrate::wire::{EgressCtx, WireBody};
use bytes::Bytes;

/// The registry as PRODUCTION builds it, for THIS plugin's dialects — `busbar_llm::DECLS`, the slice
/// the composition root installs. `busbar-core`'s own `builtin_decls()` is now empty under
/// `test-support` (the `#[path]` witness rows that used to net these dialects into core are deleted),
/// so this crate's registry tests build a `Registry` from the plugin's OWN declarations — which is
/// exactly the set a shipped binary registers through `install_protocols`.
fn builtins() -> Registry {
    Registry::new(crate::DECLS.iter().copied())
}

// ══ THE SURFACE THAT MUST NOT MOVE ═══════════════════════════════════════════════════════════════

/// **THE METRIC-SURFACE PIN.** Protocol names are metric LABELS and `providers.*.protocol` config
/// keys, and `telemetry::AppSlots::build` indexes its per-protocol families BY POSITION in this
/// list. Spelled as literals on purpose: a golden value derived from the same source it is checking
/// would be a tautology.
///
/// THE ORDER IS `busbar_llm::DECLS`' ORDER, WHICH IS WHAT PRODUCTION SHIPS. Before the LLM plugin
/// consolidation this const read `anthropic, openai, gemini, …` — core's own built-in TABLE order —
/// while the SHIPPED binary installed `anthropic, gemini, openai, …` through the composition root
/// (register_protocols), because `merged_boot_decls` folds the installed set ahead of the built-ins.
/// The two silently disagreed, and this pin was guarding the fixture, not the metric surface an
/// operator actually sees. The consolidation put core's fixture table into `DECLS`' order too, so
/// this const now states the ONE order both the fixture and the shipped binary use — and it did NOT
/// move production (the shipped order was `anthropic, gemini, openai` before and after). The
/// black-box `cli_validate.rs::the_operator_visible_protocol_order_is_exactly_the_shipped_one`
/// pins the same sequence on the real binary.
#[test]
fn the_derived_protocol_list_is_byte_identical_to_the_const_it_replaced() {
    crate::ensure_test_protocols_registered();
    assert_eq!(
        busbar_core::proto::known_protocols(),
        &[
            "anthropic",
            "gemini",
            "openai",
            "bedrock",
            "responses",
            "cohere"
        ],
        "the protocol name set AND ITS ORDER are operator-visible: the order indexes telemetry's \
         metric families and the set is what the config validator accepts"
    );
}

/// THE DERIVED LIST IS NEVER EMPTY IN A BUILD THAT SHIPS A PROTOCOL, and this is the sharp end of
/// deriving it. `config_validate` validates an operator's `providers.*.protocol` against this list
/// and `telemetry` banks a metric family per entry; the list used to be a compile-time const that
/// could not be empty, and it is now a fold over the declarations. An empty fold would make the
/// validator reject every provider with an empty "must be one of:" tail, so `config_validate` has an
/// arm that names THAT cause once instead — and this test is the other half: in a build that ships
/// six codecs, the fold must find them.
#[test]
fn the_derived_protocol_list_is_not_empty() {
    crate::ensure_test_protocols_registered();
    assert!(
        !busbar_core::proto::known_protocols().is_empty(),
        "the codec-protocol list is derived from the declarations; an empty one means the built-in \
         table stopped being read, and every operator config would be refused with no cause named"
    );
}

/// The three `OnceLock` sweeps this step absorbed produced exactly these three sets. They are now
/// folded from the declarations at boot; the VALUES may not have changed while the mechanism did.
#[test]
fn the_absorbed_sweeps_produce_the_sets_they_produced_before() {
    crate::ensure_test_protocols_registered();
    assert_eq!(
        busbar_substrate::proto::streaming_content_types(),
        &["application/vnd.amazon.eventstream", "text/event-stream"],
        "absorbed proto::streaming_content_types()"
    );
    assert_eq!(
        busbar_substrate::proto::array_stream_shim_keys(),
        &[crate::gemini::GEMINI_JSON_ARRAY_SHIM_KEY],
        "absorbed proto::array_stream_shim_keys()"
    );
    assert_eq!(
        builtins().head_keys(),
        &[
            crate::gemini::GEMINI_JSON_ARRAY_SHIM_KEY,
            "model",
            "stream",
            "stream_options",
            "system",
        ],
        "absorbed proxy::lazy_body::captured_head_keys() — the four core keys plus every declared \
         shim key, sorted and deduped exactly as the sweep produced them"
    );
}

/// A declaration that CLAIMS a verb it does not serve would make `handlers::op_for`'s reject fire on
/// a legitimate route (a 404 on a working path); a declaration that HIDES a verb it does serve would
/// make the verb set — which is what bounds the metric label space — a lie. Both directions, over
/// every declaration and every operation, so neither can drift.
#[test]
fn the_declared_verbs_are_the_verbs_the_handler_serves() {
    crate::ensure_test_protocols_registered();
    for decl in builtins().decls() {
        let handler = decl
            .handler
            .unwrap_or_else(|| panic!("{} declares no handler", decl.name));
        // The candidate set is the WHOLE vocabulary — the core-owned shape verbs plus every verb
        // ANY declaration serves (`declared_verbs()` folds them at boot) — so this sweep cannot
        // silently stop covering a verb that was added, and a handler quietly serving a verb some
        // OTHER protocol declared is caught the same as one serving its own undeclared verb.
        let mut candidates: Vec<Operation> = Operation::ALL
            .iter()
            .chain(busbar_core::proto::registry::declared_verbs())
            .copied()
            .collect();
        // ALL and the declared half share the shape verbs (MCP declares `invoke`/`subscribe`);
        // dedup by name so the served list counts each verb once.
        candidates.sort_unstable_by_key(|op| op.name());
        candidates.dedup_by_key(|op| op.name());
        let served: Vec<&'static str> = candidates
            .iter()
            .filter(|op| handler.operation_handler(**op).is_some())
            .map(|op| op.name())
            .collect();
        let mut declared: Vec<&'static str> = decl.verbs.iter().map(|v| v.name()).collect();
        let mut served_sorted = served.clone();
        declared.sort_unstable();
        served_sorted.sort_unstable();
        assert_eq!(
            declared, served_sorted,
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

/// **A4b scaffolding (G6 step A4a.4): the registry-driven EXHAUSTIVENESS contract.** It replaces the
/// compile-time "an 8th operation is an error" gate the `IrReq`/`IrResp` enum `match` gives today
/// (`ir::variant`), which A4b removes when the hub dissolves onto `Box<dyn ir::handle::IrHandle>`.
///
/// The rustc gate said: every operation variant must be handled, or the code does not compile. Its
/// runtime replacement, landed BEFORE the dissolve so the safety net exists first: every verb a
/// declaration claims MUST resolve to a serving cell on that declaration's handler — so a verb added
/// without a handler to serve it (the runtime analog of a non-exhaustive match) fails HERE, loudly,
/// instead of silently 404ing a live route. When the per-operation `IrHandle` impls land at A4b this
/// is where "…and each served verb yields an `IrHandle`" is additionally asserted, completing the
/// rustc gate's replacement.
#[test]
fn every_declared_verb_has_a_serving_handler() {
    // The whole declared vocabulary — the registry's own answer to "which operations exist", folded
    // from the declarations at boot. Non-empty or the registry has forgotten the LLM/plane verbs.
    assert!(
        !busbar_core::proto::registry::declared_verbs().is_empty(),
        "the registry must declare at least the LLM/plane verbs"
    );
    for decl in builtins().decls() {
        let Some(handler) = decl.handler else {
            continue;
        };
        for verb in decl.verbs {
            assert!(
                handler.operation_handler(*verb).is_some(),
                "{} declares verb '{}' but its handler serves no cell for it — the registry-level \
                 exhaustiveness the dissolved enum match enforced at compile time",
                decl.name,
                verb.name(),
            );
        }
    }
}

/// A protocol that declares no codec (MCP) still resolves, still dispatches, and MUST NOT be offered
/// to a provider lane — `protocol_for` answers `None` for it, which is what keeps a `protocol: mcp`
/// provider out of the config-validated set without anything comparing the name "mcp".
#[test]
fn a_declaration_without_a_codec_dispatches_but_is_not_a_provider_protocol() {
    // Register the REAL MCP protocol declaration the way the composition root does — MCP is an
    // extracted crate (`busbar-mcp`), and the deleted `#[path]` witness used to net its codec into
    // core's test binary. `busbar-llm` dev-depends on `busbar-mcp` solely for this assertion.
    busbar_substrate::proto::register_test_protocol(&busbar_mcp::PROTO_DECL);
    let d = busbar_substrate::proto::decl_for("mcp").expect("mcp declares itself");
    assert!(d.codec.is_none());
    assert!(d.handler.is_some(), "mcp serves operations");
    assert!(
        crate::proto_codec::protocol_for("mcp").is_none(),
        "no codec means no cross-dialect translation into or out of it"
    );
    assert!(
        !busbar_core::proto::known_protocols().contains(&"mcp"),
        "a provider lane cannot name a protocol that has no wire codec"
    );
}

/// Two declarations of one name would make one of them unroutable — silently, since the lookup takes
/// the first. A boot panic is the only honest answer.
#[test]
#[should_panic(expected = "two protocol declarations claim the same name")]
fn two_declarations_of_one_name_are_refused() {
    let mut decls: Vec<&'static ProtocolDecl> = crate::DECLS.to_vec();
    decls.push(decls[0]);
    let _ = Registry::new(decls);
}

// ══ THE ACCEPTANCE TEST: A PROTOCOL NOBODY WROTE ═════════════════════════════════════════════════

/// `telex` — a protocol busbar does not have, deliberately unlike the six.
///
/// It is not a chat dialect: its wire is a LINE OF TEXT rather than a JSON object, so its body has
/// no `messages`, no `model` and no `stream`; it point-reads a head key none of the six declare
/// (`dest`); it authenticates with SigV4 rather than a bearer token; it declares no codec, no
/// streaming content type and no tool-id prefix; and it serves ONE verb, `subscribe`, which NONE of
/// the six LLM protocols serve. Nothing about it was anticipated by the six, which is the point: a
/// registry that only carried protocols shaped like the ones already in the tree would be a lookup
/// table for six things rather than a seam.
///
/// It lands on an EXISTING `Operation` shape, and that is the design's prediction rather than a
/// limitation of the fixture: `design/protocol-plugin-abi.md` §4.2 tests seven candidate protocols
/// and none of them needs a new variant, because the six are SHAPES. Telex registering interest in
/// a named target is the `Subscribe` shape whoever sends it.
struct TelexHandler;

/// The one cell `telex` serves. A pure codec over its own wire shape.
struct TelexSubscribe;

const TELEX_DECL: ProtocolDecl = ProtocolDecl {
    name: "telex",
    // A protocol with no cross-dialect codec — like MCP, and for the same reason: its IR is its own.
    codec: None,
    handler: Some(&TelexHandler),
    verbs: &[Operation::SUBSCRIBE],
    head_keys: &["dest"],
    streaming_content_type: None,
    array_stream_shim_key: None,
    native_tool_id_prefix: None,
    ingress_auth: IngressAuth::SigV4,
    egress_auth_headers: None,
    egress_auth_lane_constant: false,
    stream_usage_requires_opt_in: false,
    // Promoted writer facts (G6 step A1): a codec-less fixture, so every fact is the trait default.
    requires_max_tokens: false,
    stop_sequence_cap: None,
    cache_markers_model_gated: false,
    fills_thought_signature: false,
    frame_after_message_start: None,
    reshapes_body_at_path_base: false,
    max_cache_control_breakpoints: None,
    quota_exceeded_status: axum::http::StatusCode::TOO_MANY_REQUESTS,
    ingress_is_eventstream: false,
    emits_sse_done_terminator: false,
    max_citations_per_delta: None,
    egress_user_agent: busbar_core::proxy::EGRESS_UA_DEFAULT,
    has_model_in_url: false,
    auth_failure_status_and_kind: (
        axum::http::StatusCode::UNAUTHORIZED,
        busbar_core::proto::openai_family::ERR_TYPE_AUTHENTICATION,
    ),
    ingress_relays_amzn_headers: false,
    ingress_relayed_response_header_names: &[],
    auth_failure_message: "authentication failed",
    uses_array_stream_shim: false,
    has_native_path_not_found: false,
    egress_stream_accept: busbar_core::proxy::TEXT_EVENT_STREAM,
    models_list_envelope: None,
    claims: None,
    residual_claims: None,
    residual_default: false,
    vendor_response_metadata: None,
    list_models_fingerprint_headers: &[],
};

impl RequestHandler for TelexHandler {
    fn protocol_name(&self) -> &'static str {
        "telex"
    }
    fn operation_handler(&self, op: Operation) -> Option<&dyn OperationHandler> {
        (op == Operation::SUBSCRIBE).then_some(&TelexSubscribe as &dyn OperationHandler)
    }
    fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<Operation> {
        (path == "/telex/directory").then_some(Operation::SUBSCRIBE)
    }
    fn upstream_path(&self, _ctx: &EgressCtx) -> String {
        "/telex/directory".to_string()
    }
}

impl OperationHandler for TelexSubscribe {
    fn read_request(
        &self,
        body: &[u8],
        _content_type: &str,
    ) -> Result<Box<dyn busbar_substrate::ir::handle::IrHandle>, IngressReject> {
        // The telex wire is not JSON-object-shaped like the six: it is `TO <dest>` on one line.
        let dest = std::str::from_utf8(body)
            .ok()
            .and_then(|s| s.strip_prefix("TO "))
            .ok_or_else(|| {
                IngressReject::BadRequest("not a telex directory request".to_string())
            })?;
        Ok(Box::new(TelexReqHandle(SubscribeReq {
            intent: SubscribeIntent::Register,
            target: dest.trim().to_string(),
            extra: Default::default(),
        })))
    }
    fn read_response(
        &self,
        wire: &[u8],
    ) -> Result<Box<dyn busbar_substrate::ir::handle::IrHandle>, CodecError> {
        let text = std::str::from_utf8(wire)
            .map_err(|e| CodecError::Malformed(e.to_string()))?
            .to_string();
        Ok(Box::new(TelexRespHandle(SubscribeResp {
            registration: Some(serde_json::Value::String(text)),
            extra: Default::default(),
        })))
    }
}

// G6 A4b: writes inverted off the trait onto the handle. This synthetic protocol's cell yields its
// own handles that carry its telex wire — the same mechanism a real dialect uses (its handle writes
// itself), demonstrated here for a protocol nobody in core wrote. `Sealed` is implementable because
// this test lives inside busbar-core.
struct TelexReqHandle(SubscribeReq);
struct TelexRespHandle(SubscribeResp);
impl busbar_substrate::ir::handle::sealed::Sealed for TelexReqHandle {}
impl busbar_substrate::ir::handle::sealed::Sealed for TelexRespHandle {}
impl busbar_substrate::ir::handle::IrHandle for TelexReqHandle {
    fn verb(&self) -> Operation {
        Operation::SUBSCRIBE
    }
    fn write_egress_request_bytes(&mut self, _egress_proto: &str, _model: &str) -> Bytes {
        Bytes::from(format!("TO {}", self.0.target))
    }
}
impl busbar_substrate::ir::handle::IrHandle for TelexRespHandle {
    fn verb(&self) -> Operation {
        Operation::SUBSCRIBE
    }
    fn write_ingress_response(
        &self,
        _ingress_protocol: &str,
        _ingress_serves_op: bool,
    ) -> busbar_substrate::wire::TranslatedResponse {
        busbar_substrate::wire::TranslatedResponse::Typed(WireBody::typed(
            Bytes::from(
                self.0
                    .registration
                    .as_ref()
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string(),
            ),
            "application/x-telex",
        ))
    }
}

/// **THE ACCEPTANCE TEST FOR THE WHOLE STEP.** A protocol nobody wrote RESOLVES, DISPATCHES and is
/// OBSERVABLE, and the only thing written for it is the declaration above and the cell it names.
///
/// Not one line of core was edited to admit it: it is not in `BUILTIN_DECLS`, no `match` gained an
/// arm, no `#[cfg(feature)]` was added, and it reaches the registry through
/// [`Registry::new`] — the SAME constructor `registry()` calls with the built-ins. What a loader
/// would do differently is supply the declaration from a `dlopen`ed crate instead of from this file.
#[test]
fn a_protocol_nobody_wrote_costs_a_declaration_and_nothing_else() {
    let reg = Registry::new(
        busbar_core::proto::registry::builtin_decls()
            .iter()
            .copied()
            .chain(std::iter::once(&TELEX_DECL)),
    );

    // 1. IT RESOLVES — by name, through the same lookup every layer of core uses.
    let d = reg.decl("telex").expect("a declared protocol resolves");
    assert_eq!(d.name, "telex");
    assert!(
        reg.decl("telegram").is_none(),
        "a name nobody declared still resolves to nothing"
    );

    // 2. IT DISPATCHES — path → operation → cell → its own wire, round-tripped, with core naming
    //    neither the protocol nor its verb.
    let handler = d.handler.expect("it declared a handler");
    let op = handler
        .resolve_operation("/telex/directory", b"TO paris")
        .expect("its own path resolves to its own operation");
    assert_eq!(op.name(), "subscribe");
    assert!(
        d.verbs.contains(&op),
        "the verb it dispatches is the verb it declared"
    );
    let cell = handler
        .operation_handler(op)
        .expect("the declared verb has a cell");
    let mut ir = cell
        .read_request(b"TO paris", "application/x-telex")
        .expect("its cell reads its own wire");
    // The write inverted onto the handle (G6 A4b): the cell's handle writes its own telex wire.
    assert_eq!(&ir.write_egress_request_bytes("telex", "")[..], b"TO paris");
    let resp = cell
        .read_response(b"REGISTERED paris")
        .expect("its cell reads its own response");
    let busbar_substrate::wire::TranslatedResponse::Typed(out) =
        resp.write_ingress_response("telex", true)
    else {
        panic!("telex response writes a typed body");
    };
    assert_eq!(&out.bytes[..], b"REGISTERED paris");

    // 3. IT IS OBSERVABLE — its declaration lands in the aggregates core reads. `head_keys` is what
    //    the lazy-body head projection captures, so `dest` is now point-read DOM-free on the
    //    pre-materialized path; and a protocol that had declared a codec would appear in
    //    `codec_protocols()`, which is the list telemetry indexes its metric families by.
    assert!(
        reg.head_keys().contains(&"dest"),
        "a head key nobody in core has heard of is captured because it was DECLARED: {:?}",
        reg.head_keys()
    );
    assert!(
        d.uses_sigv4_ingress_auth(),
        "the auth layer reads its declared scheme without comparing its name"
    );

    // 4. AND NOTHING IN CORE LEARNED ITS NAME. The process registry — the one production reads —
    //    still knows only the built-ins, which is the proof that admitting `telex` above required
    //    no edit here rather than a hidden one.
    assert!(
        busbar_substrate::proto::decl_for("telex").is_none(),
        "the built-in table was not touched"
    );
}

/// A minimal declaration for the boot-fold tests below: `merged_boot_decls` reads nothing but
/// `name`, and giving it a handler or codec would drag two fixture impls into a test that is about
/// LIST ORDER. Codec-less, handler-less declarations are representable on purpose (the field docs
/// say what each `None` means), so the fixture states only what the function under test reads.
const fn named_decl(name: &'static str) -> ProtocolDecl {
    ProtocolDecl {
        name,
        codec: None,
        handler: None,
        verbs: &[],
        head_keys: &[],
        streaming_content_type: None,
        array_stream_shim_key: None,
        native_tool_id_prefix: None,
        ingress_auth: IngressAuth::Bearer,
        egress_auth_headers: None,
        egress_auth_lane_constant: false,
        stream_usage_requires_opt_in: false,
        // Promoted writer facts (G6 step A1): a name-only fixture, so every fact is the trait default.
        requires_max_tokens: false,
        stop_sequence_cap: None,
        cache_markers_model_gated: false,
        fills_thought_signature: false,
        frame_after_message_start: None,
        reshapes_body_at_path_base: false,
        max_cache_control_breakpoints: None,
        quota_exceeded_status: axum::http::StatusCode::TOO_MANY_REQUESTS,
        ingress_is_eventstream: false,
        emits_sse_done_terminator: false,
        max_citations_per_delta: None,
        egress_user_agent: busbar_core::proxy::EGRESS_UA_DEFAULT,
        has_model_in_url: false,
        auth_failure_status_and_kind: (
            axum::http::StatusCode::UNAUTHORIZED,
            busbar_core::proto::openai_family::ERR_TYPE_AUTHENTICATION,
        ),
        ingress_relays_amzn_headers: false,
        ingress_relayed_response_header_names: &[],
        auth_failure_message: "authentication failed",
        uses_array_stream_shim: false,
        has_native_path_not_found: false,
        egress_stream_accept: busbar_core::proxy::TEXT_EVENT_STREAM,
        models_list_envelope: None,
        claims: None,
        residual_claims: None,
        residual_default: false,
        vendor_response_metadata: None,
        list_models_fingerprint_headers: &[],
    }
}

/// **THE FOLD-AHEAD RULE IS SAFE FOR A CODEC-LESS PROTOCOL, AND THIS IS WHY IT HAD TO BE PROVEN.**
///
/// `install_protocols` folds installed declarations AHEAD of the built-ins, and its doc justifies
/// that by `anthropic` — a dialect that already LED the built-in table, so prepending reproduced the
/// monolith's order exactly. `mcp` is the case that rule was not written for: it was the LAST row of
/// `BUILTIN_DECLS`, and extracting it to `busbar-mcp` moves it from the tail to the head of
/// the production binary's declaration list. Nothing in core's own test build can catch that — the
/// test build carries the dialect as a built-in and never calls `install_protocols` — so the
/// question is settled here, on the derivation itself.
///
/// The answer is that it is invisible, and the reason is structural rather than lucky: the
/// operator-visible list is `codec_protocols` (what `known_protocols()` returns — the metric-family
/// order and the config-error `must be one of:` order), and it is built by SKIPPING every
/// declaration whose `codec` is `None`. MCP declares no codec, so wherever it sits it contributes no
/// entry and shifts no other entry's index.
///
/// This test states that as a property rather than as a claim about MCP: the same declarations, with
/// a codec-less one at the TAIL (the monolith's shape) and at the HEAD (the extracted binary's
/// shape), derive the identical operator-visible list.
#[test]
fn a_codec_less_declaration_does_not_move_the_operator_visible_list_when_it_is_folded_ahead() {
    static CODEC_LESS: ProtocolDecl = named_decl("codec-less");
    let with_codecs: Vec<&'static ProtocolDecl> = crate::DECLS
        .iter()
        .copied()
        .filter(|d| d.codec.is_some())
        .collect();

    let at_the_tail: Vec<&'static ProtocolDecl> = with_codecs
        .iter()
        .copied()
        .chain(std::iter::once(&CODEC_LESS))
        .collect();
    let at_the_head: Vec<&'static ProtocolDecl> = std::iter::once(&CODEC_LESS as &ProtocolDecl)
        .chain(with_codecs.iter().copied())
        .collect();

    // The fixture must be able to fail: if the tail/head lists were equal, this would prove nothing.
    assert_ne!(
        at_the_tail.iter().map(|d| d.name).collect::<Vec<_>>(),
        at_the_head.iter().map(|d| d.name).collect::<Vec<_>>(),
        "the two declaration orders must actually differ or the assertion below is vacuous"
    );

    assert_eq!(
        Registry::new(at_the_tail).codec_protocols(),
        Registry::new(at_the_head).codec_protocols(),
        "a declaration that ships no wire codec contributes no entry to the operator-visible \
         protocol list, so moving it to the head of the declaration order — which is what \
         extracting it to a crate does — re-bases no dashboard and re-words no config refusal"
    );
}

/// THE COMPOSITION ROOT'S DECLARATIONS COME FIRST. The protocol list is operator-visible —
/// `known_protocols()` order is the dashboards' metric-family order and the config-error
/// `must be one of:` order — and the first protocol to be extracted (`anthropic`) has led that
/// list since 1.0. `install_protocols`' doc promises the shipped binary keeps the monolith's
/// order on the day a protocol becomes a crate; this is that promise, pinned.
#[test]
fn installed_declarations_are_folded_ahead_of_the_builtins() {
    static EXTRACTED: ProtocolDecl = named_decl("extracted");
    static BUILTIN_A: ProtocolDecl = named_decl("builtin-a");
    static BUILTIN_B: ProtocolDecl = named_decl("builtin-b");
    let merged =
        busbar_core::proto::registry::merged_boot_decls(&[&EXTRACTED], &[&BUILTIN_A, &BUILTIN_B]);
    let names: Vec<&str> = merged.iter().map(|d| d.name).collect();
    assert_eq!(
        names,
        ["extracted", "builtin-a", "builtin-b"],
        "installed declarations lead, built-ins follow, both in their stated order"
    );
}

/// A LATER REGISTRATION OF AN ALREADY-DECLARED NAME IS SKIPPED, NOT MERGED AND NOT FATAL. Under
/// `cargo test`'s feature unification the `test-support` build of core carries the extracted
/// dialect as a built-in while the composition root still registers the crate's copy of the same
/// protocol — identical code from two sources. The fold keeps the FIRST and drops the later one
/// audibly; `Registry::new`'s duplicate-name assert stays armed for the case it exists for (two
/// DIFFERENT protocols claiming one name in a single source list), which test
/// `two_declarations_of_one_name_refuse_to_boot` below drives.
#[test]
fn a_later_registration_of_a_declared_name_is_skipped_keeping_the_first() {
    static INSTALLED_COPY: ProtocolDecl = named_decl("anthro-like");
    static BUILTIN_COPY: ProtocolDecl = named_decl("anthro-like");
    static OTHER: ProtocolDecl = named_decl("other");
    let merged = busbar_core::proto::registry::merged_boot_decls(
        &[&INSTALLED_COPY],
        &[&BUILTIN_COPY, &OTHER],
    );
    assert_eq!(merged.len(), 2, "one entry per name");
    assert!(
        std::ptr::eq(merged[0], &INSTALLED_COPY),
        "the FIRST registration (the composition root's) is the one that serves"
    );
    assert_eq!(merged[1].name, "other");
}

/// The duplicate-name assert `merged_boot_decls` deliberately does NOT relax: two different
/// declarations claiming one name inside a single source list is a wiring bug, and `Registry::new`
/// still refuses it. Watched here so the skip semantics above cannot be misread as "duplicates are
/// fine now".
#[test]
#[should_panic(expected = "two protocol declarations claim the same name")]
fn two_declarations_of_one_name_refuse_to_boot() {
    static A: ProtocolDecl = named_decl("dup");
    static B: ProtocolDecl = named_decl("dup");
    let _ = Registry::new([&A, &B]);
}

/// **D5 — THE EMPTY REGISTRY IS CONSTRUCTIBLE, AND THIS IS THE PROOF IT IS NOT A STRAW MAN.**
///
/// [`the_derived_protocol_list_is_not_empty`] above asserts the shipped build's list is non-empty —
/// i.e. that `config_validate`'s empty-list refusal arm is UNREACHABLE TODAY. Left alone that is
/// exactly the shape the sign-off audit calls the breaker disease: a refusal whose input the suite
/// asserts can never occur, so the refusal is never watched to fire and the tests that "cover" it
/// prove nothing.
///
/// The two statements are both true and they are not in tension, and this test is what makes that
/// legible: TODAY's built-in table has six codecs, and the registry's OWN BOOT PATH
/// ([`merged_boot_decls`] + [`Registry::new`], the exact pair the process `OnceLock` runs) yields
/// an EMPTY codec-protocol list when it is handed nothing — which is what a build with every
/// protocol crate's dependency edge removed hands it, and what step 5's deletion gate constructs on
/// purpose. So the empty set the validator refuses is a set this registry produces, not a slice a
/// test invented.
///
/// WHAT IS STILL OWED: the process registry is a `OnceLock` over a non-empty `BUILTIN_DECLS`, so
/// `known_protocols()` itself cannot be driven empty IN THIS PROCESS until the last dialect leaves
/// core. This test is the closest honest proof available before that lands; the boot-proof belongs
/// to the last extraction.
#[test]
fn a_registry_with_no_declarations_reports_no_protocols_at_all() {
    // The boot fold with nothing installed AND nothing built in — a build with every protocol edge
    // removed. Not a hand-written empty slice: the function the process registry initializes with.
    let decls = busbar_core::proto::registry::merged_boot_decls(&[], &[]);
    assert!(decls.is_empty(), "no declarations in, no declarations out");

    let empty = Registry::new(decls);
    assert!(
        empty.codec_protocols().is_empty(),
        "a registry that declares no protocol must report no protocol — this is the input \
         `config_validate`'s refusal arm and `Plane::sole_of`'s zero arm exist for"
    );
    assert!(empty.decls().is_empty());
    assert!(empty.head_keys().is_empty());
    assert!(empty.streaming_content_types().is_empty());
    assert!(empty.array_stream_shim_keys().is_empty());
    assert!(
        empty.decl("anthropic").is_none(),
        "an empty registry resolves NO name — including one the built-ins declare today"
    );
}

/// THE BOOT PARITY RULE THE COMPOSITION ROOT ASSERTS (Batch C-6). A declaration whose model is in the
/// URL (`has_model_in_url`) MUST register a `path_ingress` arrival, or a request naming its URL model
/// silently falls through to the body-model branch — a wrong-behavior 404-shaped bug, not a compile
/// error. `install_protocols_with_path_ingress` panics on it at boot; here we drive the pure guard
/// (`first_path_model_without_arrival`) red-then-green so the invariant is proven without touching the
/// process singletons the installer writes.
#[test]
fn a_url_model_protocol_without_a_registered_arrival_is_caught() {
    // A path-model fixture: same shape as gemini/bedrock in the one fact that matters here.
    const URL_MODEL_DECL: ProtocolDecl = ProtocolDecl {
        has_model_in_url: true,
        ..TELEX_DECL
    };
    let decls: &[&'static ProtocolDecl] = &[&URL_MODEL_DECL];

    // RED: the URL-model protocol declared, but no arrival registered → the guard names it.
    assert_eq!(
        busbar_core::proto::registry::first_path_model_without_arrival(decls, &[]),
        Some("telex"),
        "a has_model_in_url decl with no arrival must be reported by name"
    );

    // GREEN: register the arrival by the SAME name → the guard is satisfied.
    assert_eq!(
        busbar_core::proto::registry::first_path_model_without_arrival(decls, &["telex"]),
        None,
        "once its arrival is registered under the same name, the parity rule holds"
    );

    // A body-model protocol (has_model_in_url == false) needs no arrival and is never reported.
    let body_model: &[&'static ProtocolDecl] = &[&TELEX_DECL];
    assert_eq!(
        busbar_core::proto::registry::first_path_model_without_arrival(body_model, &[]),
        None,
        "a body-model protocol declares no URL model, so it needs no arrival"
    );
}
