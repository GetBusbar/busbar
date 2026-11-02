mod registry_fold {
    use crate::ingress::protocols::{ProtocolDecl, Registry};
    use busbar_contract::codec::{CodecError, IngressReject, OperationHandler, RequestHandler};
    use busbar_contract::codec::{EgressCtx, WireBody};
    use busbar_contract::ir::subscribe::{SubscribeIntent, SubscribeReq, SubscribeResp};
    use busbar_contract::operation::OpVerb;
    use busbar_contract::protocol::IngressAuth;
    use busbar_contract::SlabBytes;

    struct TelexHandler;

    struct TelexSubscribe;

    const TELEX_DECL: ProtocolDecl = ProtocolDecl {
        name: "telex",

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

        requires_max_tokens: false,
        stop_sequence_cap: None,
        cache_markers_model_gated: false,
        fills_thought_signature: false,
        frame_after_message_start: None,
        reshapes_body_at_path_base: false,
        max_cache_control_breakpoints: None,
        quota_exceeded_status: busbar_contract::http::StatusCode::TOO_MANY_REQUESTS.as_u16(),
        ingress_is_eventstream: false,
        emits_sse_done_terminator: false,
        max_citations_per_delta: None,
        egress_user_agent: busbar_contract::protocol::EGRESS_UA_DEFAULT,
        has_model_in_url: false,
        auth_failure_status_and_kind: (
            busbar_contract::http::StatusCode::UNAUTHORIZED.as_u16(),
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
            _host: &dyn busbar_contract::codec::CodecHost,
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
            _host: &dyn busbar_contract::codec::CodecHost,
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

    #[test]
    fn a_protocol_nobody_wrote_costs_a_declaration_and_nothing_else() {
        let reg = Registry::new(
            crate::testkit::neutral_protocols::NEUTRAL_PROTOCOLS
                .iter()
                .copied()
                .chain(std::iter::once(&TELEX_DECL)),
        );

        let d = reg.decl("telex").expect("a declared protocol resolves");
        assert_eq!(d.name, "telex");
        assert!(
            reg.decl("telegram").is_none(),
            "a name nobody declared still resolves to nothing"
        );

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

        assert_eq!(&ir.write_egress_request_bytes("telex", "")[..], b"TO paris");
        let resp = cell
            .read_response(crate::ingress::protocols::CODEC_HOST, b"REGISTERED paris")
            .expect("its cell reads its own response");
        let busbar_contract::codec::TranslatedResponse::Typed(out) =
            resp.write_ingress_response(crate::ingress::protocols::CODEC_HOST, "telex", true)
        else {
            panic!("telex response writes a typed body");
        };
        assert_eq!(&out.bytes[..], b"REGISTERED paris");

        assert!(
            reg.head_keys().contains(&"dest"),
            "a head key nobody in core has heard of is captured because it was DECLARED: {:?}",
            reg.head_keys()
        );
        assert!(
            d.uses_sigv4_ingress_auth(),
            "the auth layer reads its declared scheme without comparing its name"
        );

        assert!(
            crate::ingress::protocols::decl_for("telex").is_none(),
            "the built-in table was not touched"
        );
    }

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

            requires_max_tokens: false,
            stop_sequence_cap: None,
            cache_markers_model_gated: false,
            fills_thought_signature: false,
            frame_after_message_start: None,
            reshapes_body_at_path_base: false,
            max_cache_control_breakpoints: None,
            quota_exceeded_status: busbar_contract::http::StatusCode::TOO_MANY_REQUESTS.as_u16(),
            ingress_is_eventstream: false,
            emits_sse_done_terminator: false,
            max_citations_per_delta: None,
            egress_user_agent: busbar_contract::protocol::EGRESS_UA_DEFAULT,
            has_model_in_url: false,
            auth_failure_status_and_kind: (
                busbar_contract::http::StatusCode::UNAUTHORIZED.as_u16(),
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

    #[test]
    fn installed_declarations_are_folded_ahead_of_the_builtins() {
        static EXTRACTED: ProtocolDecl = named_decl("extracted");
        static BUILTIN_A: ProtocolDecl = named_decl("builtin-a");
        static BUILTIN_B: ProtocolDecl = named_decl("builtin-b");
        let merged =
            crate::ingress::protocols::merged_boot_decls(&[&EXTRACTED], &[&BUILTIN_A, &BUILTIN_B]);
        let names: Vec<&str> = merged.iter().map(|d| d.name).collect();
        assert_eq!(
            names,
            ["extracted", "builtin-a", "builtin-b"],
            "installed declarations lead, built-ins follow, both in their stated order"
        );
    }

    #[test]
    fn a_later_registration_of_a_declared_name_is_skipped_keeping_the_first() {
        static INSTALLED_COPY: ProtocolDecl = named_decl("anthro-like");
        static BUILTIN_COPY: ProtocolDecl = named_decl("anthro-like");
        static OTHER: ProtocolDecl = named_decl("other");
        let merged = crate::ingress::protocols::merged_boot_decls(
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

    #[test]
    #[should_panic(expected = "two protocol declarations claim the same name")]
    fn two_declarations_of_one_name_refuse_to_boot() {
        static A: ProtocolDecl = named_decl("dup");
        static B: ProtocolDecl = named_decl("dup");
        let _ = Registry::new([&A, &B]);
    }

    #[test]
    fn a_registry_with_no_declarations_reports_no_protocols_at_all() {
        let decls = crate::ingress::protocols::merged_boot_decls(&[], &[]);
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
}
