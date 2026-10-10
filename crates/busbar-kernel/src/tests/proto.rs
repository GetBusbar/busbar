//! Tests for `proto.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches what it
//! always did.
//!
//! ONE assertion, and it is the whole reason the fold exists: a declaration whose model is in the URL
//! path must arrive with an arrival. The success path is NOT tested here — both installs behind it are
//! set-once per process and this crate's test binary is shared — and it does not need to be: the two
//! installs are the leaf's and this crate's own, each already covered where it is defined. What is only
//! true HERE is that the parity is checked BEFORE either of them, so the refusal leaves both seams
//! unwritten rather than one of the two.

use super::*;

/// The one field this fold reads that is not the neutral zero. Everything else comes from the
/// leaf's own name-only row ([`ProtocolDecl::named`]), so a field added to the declaration is added
/// in one place and this fixture does not have to be found and edited to stay compiling.
static URL_MODEL_WITHOUT_ARRIVAL: ProtocolDecl = ProtocolDecl {
    has_model_in_url: true,
    ..ProtocolDecl::named("telex")
};

/// A path-model declaration installed with NO arrival would resolve no arrival and fall through to the
/// body-model branch — a silent, 404-shaped wrong answer on a protocol the operator did install. The
/// fold refuses the boot instead, and refuses it BEFORE either seam is written: this test's process
/// never reaches `install_protocols`, so a panic here is the guard and not an install.
#[test]
#[should_panic(expected = "registered no path_ingress arrival")]
fn a_url_model_declaration_without_its_arrival_refuses_the_boot() {
    install_protocols_with_path_ingress(vec![&URL_MODEL_WITHOUT_ARRIVAL], Vec::new());
}

// ══ THE KERNEL'S REGISTRY MACHINERY, OVER SYNTHETIC DECLARATIONS ═════════════════════════════════
//
// Moved from the composition root's protocol-registry suite (ARCHITECT on N4, option (b)): every test
// here builds its own declarations — a protocol nobody wrote, name-only rows — and proves the
// registry's own fold, refusals and boot merge, so it is the kernel's to hold and names no plane. The
// same suite's assertions over the REAL linked declarations live with the root, which links them
// (`crates/busbar/src/root/tests/linked_protocols.rs`).
mod registry_fold {
    use crate::proto::{ProtocolDecl, Registry};
    use busbar_contract::codec::{CodecError, IngressReject, OperationHandler, RequestHandler};
    use busbar_contract::codec::{EgressCtx, WireBody};
    use busbar_contract::ir::subscribe::{SubscribeIntent, SubscribeReq, SubscribeResp};
    use busbar_contract::operation::OpVerb;
    use busbar_contract::protocol::IngressAuth;
    use busbar_contract::SlabBytes;

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
    /// limitation of the fixture: `design/protocol-plugin-abi.md` tests seven candidate protocols
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
        verbs: &[OpVerb::SUBSCRIBE],
        head_keys: &["dest"],
        streaming_content_type: None,
        array_stream_shim_key: None,
        native_tool_id_prefix: None,
        ingress_auth: IngressAuth::SigV4,
        egress_auth_headers: None,
        egress_auth_lane_constant: false,
        egress_scheme: None,
        stream_usage_requires_opt_in: false,
        // Promoted writer facts (G6 step A1): a codec-less fixture, so every fact is the trait default.
        requires_max_tokens: false,
        stop_sequence_cap: None,
        cache_markers_model_gated: false,
        fills_thought_signature: false,
        frame_after_message_start: None,
        reshapes_body_at_path_base: false,
        max_cache_control_breakpoints: None,
        quota_exceeded_status: busbar_contract::http::StatusCode::TOO_MANY_REQUESTS,
        ingress_is_eventstream: false,
        emits_sse_done_terminator: false,
        max_citations_per_delta: None,
        egress_user_agent: busbar_contract::protocol::EGRESS_UA_DEFAULT,
        has_model_in_url: false,
        auth_failure_status_and_kind: (
            busbar_contract::http::StatusCode::UNAUTHORIZED,
            busbar_contract::protocol::ERR_TYPE_AUTHENTICATION,
        ),
        ingress_relays_amzn_headers: false,
        ingress_relayed_response_header_names: &[],
        auth_failure_message: "authentication failed",
        uses_array_stream_shim: false,
        has_native_path_not_found: false,
        egress_stream_accept: busbar_contract::protocol::TEXT_EVENT_STREAM,
        models_list_envelope: None,
        claims: None,
        residual_claims: None,
        residual_default: false,
        vendor_response_metadata: None,
        list_models_fingerprint_headers: &[],
        static_headers: &[],
    };

    impl RequestHandler for TelexHandler {
        fn protocol_name(&self) -> &'static str {
            "telex"
        }
        fn operation_handler(&self, op: OpVerb) -> Option<&dyn OperationHandler> {
            (op == OpVerb::SUBSCRIBE).then_some(&TelexSubscribe as &dyn OperationHandler)
        }
        fn resolve_operation(&self, path: &str, _body: &[u8]) -> Option<OpVerb> {
            (path == "/telex/directory").then_some(OpVerb::SUBSCRIBE)
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
        ) -> Result<Box<dyn busbar_contract::ir::handle::IrHandle>, IngressReject> {
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
        ) -> Result<Box<dyn busbar_contract::ir::handle::IrHandle>, CodecError> {
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
    impl busbar_contract::ir::handle::sealed::Sealed for TelexReqHandle {}
    impl busbar_contract::ir::handle::sealed::Sealed for TelexRespHandle {}
    impl busbar_contract::ir::handle::IrHandle for TelexReqHandle {
        fn verb(&self) -> OpVerb {
            OpVerb::SUBSCRIBE
        }
        fn write_egress_request_bytes(&mut self, _egress_proto: &str, _model: &str) -> SlabBytes {
            SlabBytes::from(format!("TO {}", self.0.target))
        }
    }
    impl busbar_contract::ir::handle::IrHandle for TelexRespHandle {
        fn verb(&self) -> OpVerb {
            OpVerb::SUBSCRIBE
        }
        fn write_ingress_response(
            &self,
            _ingress_protocol: &str,
            _ingress_serves_op: bool,
        ) -> busbar_contract::codec::TranslatedResponse {
            busbar_contract::codec::TranslatedResponse::Typed(WireBody::typed(
                SlabBytes::from(
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
        let mut ir = cell
            .read_request(b"TO paris", "application/x-telex")
            .expect("its cell reads its own wire");
        // The write inverted onto the handle (G6 A4b): the cell's handle writes its own telex wire.
        assert_eq!(&ir.write_egress_request_bytes("telex", "")[..], b"TO paris");
        let resp = cell
            .read_response(b"REGISTERED paris")
            .expect("its cell reads its own response");
        let busbar_contract::codec::TranslatedResponse::Typed(out) =
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
            egress_auth_lane_constant: false,
            egress_scheme: None,
            stream_usage_requires_opt_in: false,
            // Promoted writer facts (G6 step A1): a name-only fixture, so every fact is the trait default.
            requires_max_tokens: false,
            stop_sequence_cap: None,
            cache_markers_model_gated: false,
            fills_thought_signature: false,
            frame_after_message_start: None,
            reshapes_body_at_path_base: false,
            max_cache_control_breakpoints: None,
            quota_exceeded_status: busbar_contract::http::StatusCode::TOO_MANY_REQUESTS,
            ingress_is_eventstream: false,
            emits_sse_done_terminator: false,
            max_citations_per_delta: None,
            egress_user_agent: busbar_contract::protocol::EGRESS_UA_DEFAULT,
            has_model_in_url: false,
            auth_failure_status_and_kind: (
                busbar_contract::http::StatusCode::UNAUTHORIZED,
                busbar_contract::protocol::ERR_TYPE_AUTHENTICATION,
            ),
            ingress_relays_amzn_headers: false,
            ingress_relayed_response_header_names: &[],
            auth_failure_message: "authentication failed",
            uses_array_stream_shim: false,
            has_native_path_not_found: false,
            egress_stream_accept: busbar_contract::protocol::TEXT_EVENT_STREAM,
            models_list_envelope: None,
            claims: None,
            residual_claims: None,
            residual_default: false,
            vendor_response_metadata: None,
            list_models_fingerprint_headers: &[],
            static_headers: &[],
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
        let merged = crate::proto::merged_boot_decls(&[&EXTRACTED], &[&BUILTIN_A, &BUILTIN_B]);
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
        let merged = crate::proto::merged_boot_decls(&[&INSTALLED_COPY], &[&BUILTIN_COPY, &OTHER]);
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
        let decls = crate::proto::merged_boot_decls(&[], &[]);
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
            crate::proto::first_path_model_without_arrival(decls, &[]),
            Some("telex"),
            "a has_model_in_url decl with no arrival must be reported by name"
        );

        // GREEN: register the arrival by the SAME name → the guard is satisfied.
        assert_eq!(
            crate::proto::first_path_model_without_arrival(decls, &["telex"]),
            None,
            "once its arrival is registered under the same name, the parity rule holds"
        );

        // A body-model protocol (has_model_in_url == false) needs no arrival and is never reported.
        let body_model: &[&'static ProtocolDecl] = &[&TELEX_DECL];
        assert_eq!(
            crate::proto::first_path_model_without_arrival(body_model, &[]),
            None,
            "a body-model protocol declares no URL model, so it needs no arrival"
        );
    }
}
