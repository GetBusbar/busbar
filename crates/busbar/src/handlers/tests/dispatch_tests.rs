use super::*;

#[test]
fn chat_declares_its_capabilities() {
    let chat = CHAT;
    assert_eq!(chat.name(), "chat");
    assert!(chat.streaming(), "chat streams");
    assert!(
        chat.taps_nonstream_usage(),
        "chat bills tokens from the body"
    );
    assert!(
        chat.wants_stream(&serde_json::json!({"stream": true})),
        "chat reads the stream boolean"
    );
    assert!(!chat.wants_stream(&serde_json::json!({})));
    assert_eq!(
        chat.body_affinity_key(&serde_json::json!({"system": "you are helpful"})),
        Some("you are helpful")
    );
    assert_eq!(
        chat.body_affinity_key(&serde_json::json!({"system": ""})),
        None
    );
}

/// The load-bearing invariant of the operations axis: the forward engine branches on the
/// *capabilities* an OperationHandler declares, never on an operation's *identity*. If someone adds
/// `if op.name() == "embeddings"` or `match op.name() { ... }` to the engine, chat stops being
/// just operation #1 and the "add an operation without touching the engine" property is lost.
/// (`op.name()` used as a value — a tracing span field — is fine; only comparisons/matches are
/// forbidden.)
#[test]
fn engine_never_branches_on_operation_identity() {
    // Scan EVERY file of the forward engine (the module split must not open a blind spot): the proxy
    // hub, each area-module, and the engine core + failover walk.
    let engine_files = [
        ("src/proxy/mod.rs", include_str!("../../proxy/mod.rs")),
        ("src/proxy/wire.rs", include_str!("../../proxy/wire.rs")),
        ("src/proxy/hooks.rs", include_str!("../../proxy/hooks.rs")),
        ("src/proxy/select.rs", include_str!("../../proxy/select.rs")),
        ("src/proxy/usage.rs", include_str!("../../proxy/usage.rs")),
        ("src/proxy/egress.rs", include_str!("../../proxy/egress.rs")),
        (
            "src/proxy/response_body.rs",
            include_str!("../../proxy/response_body.rs"),
        ),
        (
            "src/proxy/engine/mod.rs",
            include_str!("../../proxy/engine/mod.rs"),
        ),
        (
            "src/proxy/engine/walk.rs",
            include_str!("../../proxy/engine/walk.rs"),
        ),
    ];
    let forbidden = [
        "op.name() ==",
        "op.name()==",
        "== op.name()",
        "==op.name()",
        "match op.name()",
    ];
    for (file, engine) in engine_files {
        for pat in forbidden {
            assert!(
                    !engine.contains(pat),
                    "{file} contains a forbidden operation-identity branch (`{pat}`). The \
                     engine must read capabilities off the OperationHandler, never branch on op.name()."
                );
        }
    }
}

/// A NON-CHAT operation's failure reaches the breaker with a status attributed.
///
/// The `(mcp, Invoke)` cell is the one cell in the tree with no `Lane` behind it and no chat reader
/// to borrow: before the attributed outcome became a property of the operation codec, an outbound
/// attempt on this cell had no way to tell the breaker anything at all, because the only route to a
/// `RawUpstreamError` ran through `lane.protocol.reader()`. It says the status and claims no
/// provider vocabulary — the most restrictive USEFUL answer — and that status is enough for the
/// breaker to classify the attempt as a transient upstream failure.
#[test]
fn a_non_chat_operation_failure_reaches_the_breaker_with_a_status_attributed() {
    let cell = crate::handlers::op_for("mcp", Operation::Invoke, crate::transport::Transport::Http)
        .expect("the (mcp, Invoke) cell is registered");

    let raw = cell.extract_error(503, br#"{"jsonrpc":"2.0","error":{"code":-32000}}"#);

    assert_eq!(raw.http_status, 503, "the status is attributed");
    assert_eq!(raw.provider_code, None, "no provider vocabulary claimed");
    assert_eq!(raw.structured_type, None, "no provider vocabulary claimed");
    assert_eq!(
        raw.retry_after_secs, None,
        "headers are the forwarding layer's to fill in"
    );

    let sig = crate::breaker::normalize_raw_error(&raw, &std::collections::HashMap::new());
    assert_eq!(
        crate::breaker::classify(&sig),
        crate::breaker::Disposition::TransientUpstream,
        "a status alone is enough for the breaker to classify the attempt"
    );
}

/// EVERY OPERATION OF THE SIX LLM PROTOCOLS REPORTS EXACTLY WHAT ITS PROTOCOL READER REPORTS.
///
/// The breaker's Stage 1a used to run the lane's chat reader over every non-2xx body, whatever
/// operation had been dispatched. It now runs the CELL's codec, so this sweeps the whole matrix —
/// six protocols x every operation each serves x a spread of statuses and real error envelopes —
/// and pins each answer to the protocol reader's, field for field. Any drift in what one of the six
/// reports is a change to how an operator's `error_map` classifies their traffic.
#[test]
fn every_cell_of_the_six_protocols_reports_its_protocol_vocabulary() {
    /// Every variant, listed once — the same written-out sweep `operation.rs`'s tests use, so a new
    /// operation is not silently skipped by this matrix.
    const ALL_OPERATIONS: [Operation; 13] = [
        Operation::Chat,
        Operation::Embeddings,
        Operation::Moderation,
        Operation::Image,
        Operation::Transcription,
        Operation::Speech,
        Operation::Rerank,
        Operation::Invoke,
        Operation::Catalogue,
        Operation::Fetch,
        Operation::Task,
        Operation::Subscribe,
        Operation::Control,
    ];
    // Real envelopes from each family, plus the two shapes that exercise the readers' edges: a body
    // that is not JSON at all, and one whose prose alone signals context length.
    const BODIES: [&[u8]; 8] = [
        br#"{"error":{"message":"You exceeded your quota","type":"insufficient_quota","code":"insufficient_quota"}}"#,
        br#"{"error":{"code":429,"message":"Resource has been exhausted","status":"RESOURCE_EXHAUSTED"}}"#,
        br#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
        br#"{"message":"Rate exceeded","__type":"ThrottlingException"}"#,
        br#"{"message":"too many tokens: prompt is too long for this model"}"#,
        br#"{"error":{"message":"prompt is too long: 300000 tokens > 200000 maximum","type":"invalid_request_error"}}"#,
        br#"{}"#,
        b"upstream is not speaking JSON today",
    ];
    const STATUSES: [u16; 12] = [400, 401, 403, 404, 408, 413, 422, 429, 500, 502, 503, 529];

    for protocol in crate::proto::KNOWN_PROTOCOLS {
        let p = crate::proto::protocol_for(protocol)
            .unwrap_or_else(|| panic!("{protocol} is a registered protocol"));
        for operation in ALL_OPERATIONS {
            let Some(cell) =
                crate::handlers::op_for(protocol, operation, crate::transport::Transport::Http)
            else {
                continue; // an operation this protocol does not serve — the no-handler 404
            };
            for status in STATUSES {
                for body in BODIES {
                    let got = cell.extract_error(status, body);
                    let want = p.reader().extract_error(
                        axum::http::StatusCode::from_u16(status).expect("a valid status"),
                        body,
                    );
                    assert_eq!(
                        (
                            got.http_status,
                            &got.provider_code,
                            &got.structured_type,
                            got.retry_after_secs
                        ),
                        (
                            want.http_status,
                            &want.provider_code,
                            &want.structured_type,
                            want.retry_after_secs
                        ),
                        "{protocol}/{} attributed {status} differently from its protocol reader",
                        operation.name()
                    );
                }
            }
        }
    }
}
