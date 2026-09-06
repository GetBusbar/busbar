// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The mid-stream error seam, across every declared writer.
//!
//! `proxy::wire` frames a mid-stream terminal error by calling `ProtocolWriter::write_error_frame`
//! — the NEUTRAL seam that lets core emit a native in-band stream-error event without naming the
//! concrete `IrStreamEvent`. The trait default returns `None` (fall back to core's dialect-free
//! frame), so a protocol that forgets to override it would silently downgrade a native error frame
//! to a bare `data:` one. This battery pins, for EVERY protocol in `DECLS`, that the override
//! exists and returns `Some` — the guard against that silent downgrade.
//!
//! Byte-identity to the delegated `write_response_event(&IrStreamEvent::Error(..))` is NOT asserted
//! here, and cannot be by re-invoking: the Responses writer synthesizes a `response.id` and a
//! `now_unix_secs()` `created_at` for a terminal error with no preceding `MessageStart`, so two
//! separate calls legitimately differ on those volatile fields. In production the seam IS that
//! single `write_response_event` call, so identity is exact; the streaming witness batteries in core
//! (`stream_translate_tests`, the mid-stream-error/`response.failed` tests) exercise that live path.

use super::*;
use crate::proto_codec::protocol_for;
use busbar_substrate_values::breaker::{CanonicalSignal, StatusClass};

fn a_mid_stream_error() -> CanonicalSignal {
    // The exact shape `proxy::wire::mid_stream_error_bytes` constructs: a server-class transport
    // failure carrying the human detail as the provider signal.
    CanonicalSignal {
        class: StatusClass::ServerError,
        provider_signal: Some("mid-stream transport failure".to_string()),
        retry_after: None,
        ..Default::default()
    }
}

/// A MID-STREAM error has no HTTP status of its own — it rides inside a 200 body — so the only
/// status a client ever sees is the one the ingress writer reconstructs. Reconstructing it from the
/// lossy `StatusClass` alone rewrote what the upstream actually said: Gemini's 404/`NOT_FOUND`
/// came out 400/`INVALID_ARGUMENT`, Bedrock's `ModelStreamErrorException` came out
/// `InternalServerException`, and OpenAI's prose was replaced by its code. The exact status, name
/// and message the upstream reported must survive to the frame.
#[test]
fn a_mid_stream_error_frames_the_status_and_message_the_upstream_reported() {
    // What a Gemini `streamGenerateContent` sends when the model name is wrong: a `google.rpc.Status`
    // with code 404, status NOT_FOUND and a sentence. `NOT_FOUND` classifies as ClientError, whose
    // class-derived Gemini pair is (400, INVALID_ARGUMENT) — the wrong answer for this error.
    let err = CanonicalSignal {
        class: StatusClass::ClientError,
        provider_signal: Some("NOT_FOUND".to_string()),
        retry_after: None,
        detail: busbar_substrate_values::breaker::ProviderErrorDetail {
            http_status: Some(404),
            status_name: Some("NOT_FOUND".to_string()),
            message: Some("models/nope is not found for API version v1beta".to_string()),
        },
    };

    let gemini = protocol_for("gemini")
        .expect("gemini resolves")
        .writer()
        .write_error_frame(&err)
        .expect("gemini frames a stream error");
    assert_eq!(
        gemini.1.pointer("/error/code"),
        Some(&serde_json::json!(404)),
        "the upstream's own status must reach the client, not the class-derived 400: {}",
        gemini.1
    );
    assert_eq!(
        gemini.1.pointer("/error/status"),
        Some(&serde_json::json!("NOT_FOUND"))
    );
    assert_eq!(
        gemini.1.pointer("/error/message"),
        Some(&serde_json::json!(
            "models/nope is not found for API version v1beta"
        ))
    );

    // Bedrock names the exception itself. `ModelStreamErrorException` is a member of the
    // ConverseStream output union; the class-derived name for a ClientError is `ValidationException`.
    let bedrock_err = CanonicalSignal {
        class: StatusClass::ServerError,
        provider_signal: Some("ModelStreamErrorException".to_string()),
        retry_after: None,
        detail: busbar_substrate_values::breaker::ProviderErrorDetail {
            http_status: Some(424),
            status_name: Some("ModelStreamErrorException".to_string()),
            message: Some("the model stream failed".to_string()),
        },
    };
    let bedrock = protocol_for("bedrock")
        .expect("bedrock resolves")
        .writer()
        .write_error_frame(&bedrock_err)
        .expect("bedrock frames a stream error");
    assert_eq!(
        bedrock.0, "ModelStreamErrorException",
        "the exception the upstream named must be the one framed, not the class-derived \
         InternalServerException"
    );
    assert_eq!(
        bedrock.1.pointer("/message"),
        Some(&serde_json::json!("the model stream failed"))
    );

    // OpenAI chat: the prose must not be replaced by the code.
    let openai_err = CanonicalSignal {
        class: StatusClass::ClientError,
        provider_signal: Some("model_not_found".to_string()),
        retry_after: None,
        detail: busbar_substrate_values::breaker::ProviderErrorDetail {
            http_status: Some(404),
            status_name: Some("invalid_request_error".to_string()),
            message: Some("The model `nope` does not exist".to_string()),
        },
    };
    let openai = protocol_for("openai")
        .expect("openai resolves")
        .writer()
        .write_error_frame(&openai_err)
        .expect("openai frames a stream error");
    assert_eq!(
        openai.1.pointer("/error/message"),
        Some(&serde_json::json!("The model `nope` does not exist")),
        "the provider's own sentence must reach the client, not its code: {}",
        openai.1
    );
    assert_eq!(
        openai.1.pointer("/error/code"),
        Some(&serde_json::json!("model_not_found"))
    );
}

#[test]
fn every_declared_writer_frames_a_stream_error_in_band() {
    let err = a_mid_stream_error();
    let mut checked = 0usize;
    for decl in DECLS {
        // A protocol without a cross-dialect codec (none today; MCP would be one) has no writer.
        if decl.codec.is_none() {
            continue;
        }
        let proto = protocol_for(decl.name).expect("a codec protocol resolves its writer");
        assert!(
            proto.writer().write_error_frame(&err).is_some(),
            "{}: write_error_frame returned None — a mid-stream error would fall back to core's \
             dialect-free frame instead of this protocol's native stream-error shape",
            decl.name
        );
        checked += 1;
    }
    // The sweep asserts nothing if it iterates nothing. `DECLS` shrinking, or every row losing its
    // `codec`, would `continue` past every assertion and report this battery green over ZERO
    // protocols — the silent downgrade it exists to catch, on all six at once.
    assert_eq!(
        checked, 6,
        "all six codec dialects must be swept for a native stream-error frame; swept {checked}"
    );
}
