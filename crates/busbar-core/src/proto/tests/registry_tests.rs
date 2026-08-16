// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PROTOCOL REGISTRY'S OWN TESTS — and the acceptance test for the whole step.
//!
//! The claim under test is not "the lookup works". It is that **a protocol is now a DECLARATION**:
//! that adding one costs a `ProtocolDecl` plus the cells it names, and costs NO EDIT TO CORE. The
//! model is `audit/tests/chain_tests.rs::a_fourth_stream_costs_a_record_type_and_nothing_else`,
//! which proves the audit chain spans a stream nobody wrote by writing one and chaining it.
//! [`a_protocol_nobody_wrote_costs_a_declaration_and_nothing_else`] is the same claim, one axis over.

use crate::handlers::{
    CodecError, EgressCtx, IngressReject, OperationHandler, RequestHandler, WireBody,
};
use crate::ir::subscribe::{SubscribeIntent, SubscribeReq, SubscribeResp};
use crate::ir::variant::{IrReq, IrResp};
use crate::operation::Operation;
use crate::proto::registry::{IngressAuth, ProtocolDecl, Registry};
use bytes::Bytes;

/// The registry as PRODUCTION builds it — the built-in declarations and nothing else.
fn builtins() -> Registry {
    Registry::new(crate::proto::registry::builtin_decls().iter().copied())
}

// ══ THE SURFACE THAT MUST NOT MOVE ═══════════════════════════════════════════════════════════════

/// **THE METRIC-SURFACE PIN.** Protocol names are metric LABELS and `providers.*.protocol` config
/// keys, and `telemetry::AppSlots::build` indexes its per-protocol families BY POSITION in this
/// list. Deriving the list from the declarations must therefore reproduce the hand-maintained
/// `KNOWN_PROTOCOLS` const it replaced EXACTLY — same names, same order — or every operator's
/// dashboard re-bases silently. Spelled as literals on purpose: a golden value derived from the
/// same source it is checking would be a tautology.
#[test]
fn the_derived_protocol_list_is_byte_identical_to_the_const_it_replaced() {
    assert_eq!(
        crate::proto::known_protocols(),
        &[
            "anthropic",
            "openai",
            "gemini",
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
    assert!(
        !crate::proto::known_protocols().is_empty(),
        "the codec-protocol list is derived from the declarations; an empty one means the built-in \
         table stopped being read, and every operator config would be refused with no cause named"
    );
}

/// The three `OnceLock` sweeps this step absorbed produced exactly these three sets. They are now
/// folded from the declarations at boot; the VALUES may not have changed while the mechanism did.
#[test]
fn the_absorbed_sweeps_produce_the_sets_they_produced_before() {
    assert_eq!(
        crate::proto::streaming_content_types(),
        &["application/vnd.amazon.eventstream", "text/event-stream"],
        "absorbed proto::streaming_content_types()"
    );
    assert_eq!(
        crate::proto::array_stream_shim_keys(),
        &[crate::proto::gemini::GEMINI_JSON_ARRAY_SHIM_KEY],
        "absorbed proto::array_stream_shim_keys()"
    );
    assert_eq!(
        builtins().head_keys(),
        &[
            crate::proto::gemini::GEMINI_JSON_ARRAY_SHIM_KEY,
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
            .chain(crate::proto::registry::declared_verbs())
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

/// A protocol that declares no codec (MCP) still resolves, still dispatches, and MUST NOT be offered
/// to a provider lane — `protocol_for` answers `None` for it, which is what keeps a `protocol: mcp`
/// provider out of the config-validated set without anything comparing the name "mcp".
#[test]
fn a_declaration_without_a_codec_dispatches_but_is_not_a_provider_protocol() {
    let d = crate::proto::decl_for("mcp").expect("mcp declares itself");
    assert!(d.codec.is_none());
    assert!(d.handler.is_some(), "mcp serves operations");
    assert!(
        crate::proto::protocol_for("mcp").is_none(),
        "no codec means no cross-dialect translation into or out of it"
    );
    assert!(
        !crate::proto::known_protocols().contains(&"mcp"),
        "a provider lane cannot name a protocol that has no wire codec"
    );
}

/// Two declarations of one name would make one of them unroutable — silently, since the lookup takes
/// the first. A boot panic is the only honest answer.
#[test]
#[should_panic(expected = "two protocol declarations claim the same name")]
fn two_declarations_of_one_name_are_refused() {
    let mut decls: Vec<&'static ProtocolDecl> = crate::proto::registry::builtin_decls().to_vec();
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
    // NO PATH INGRESS: this dialect keeps its model in the BODY, so the catch-all resolves the
    // operation through the `RequestHandler` and serves it on the universal ingress.
    path_ingress: None,
    stream_usage_requires_opt_in: false,
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
    fn read_request(&self, body: &[u8], _content_type: &str) -> Result<IrReq, IngressReject> {
        // The telex wire is not JSON-object-shaped like the six: it is `TO <dest>` on one line.
        let dest = std::str::from_utf8(body)
            .ok()
            .and_then(|s| s.strip_prefix("TO "))
            .ok_or_else(|| {
                IngressReject::BadRequest("not a telex directory request".to_string())
            })?;
        Ok(IrReq::Subscribe(SubscribeReq {
            intent: SubscribeIntent::Register,
            target: dest.trim().to_string(),
            extra: Default::default(),
        }))
    }
    fn write_request(&self, ir: &IrReq) -> Bytes {
        match ir {
            IrReq::Subscribe(s) => Bytes::from(format!("TO {}", s.target)),
            _ => Bytes::new(),
        }
    }
    fn read_response(&self, wire: &[u8]) -> Result<IrResp, CodecError> {
        let text = std::str::from_utf8(wire)
            .map_err(|e| CodecError::Malformed(e.to_string()))?
            .to_string();
        Ok(IrResp::Subscribe(SubscribeResp {
            registration: Some(serde_json::Value::String(text)),
            extra: Default::default(),
        }))
    }
    fn write_response(&self, ir: &IrResp) -> WireBody {
        match ir {
            IrResp::Subscribe(s) => WireBody::typed(
                Bytes::from(
                    s.registration
                        .as_ref()
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                ),
                "application/x-telex",
            ),
            _ => WireBody::typed(Bytes::new(), "application/x-telex"),
        }
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
        crate::proto::registry::builtin_decls()
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
    let ir = cell
        .read_request(b"TO paris", "application/x-telex")
        .expect("its cell reads its own wire");
    assert_eq!(&cell.write_request(&ir)[..], b"TO paris");
    let resp = cell
        .read_response(b"REGISTERED paris")
        .expect("its cell reads its own response");
    let out = cell.write_response(&resp);
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
        crate::proto::decl_for("telex").is_none(),
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
        path_ingress: None,
        stream_usage_requires_opt_in: false,
    }
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
        crate::proto::registry::merged_boot_decls(&[&EXTRACTED], &[&BUILTIN_A, &BUILTIN_B]);
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
    let merged =
        crate::proto::registry::merged_boot_decls(&[&INSTALLED_COPY], &[&BUILTIN_COPY, &OTHER]);
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
