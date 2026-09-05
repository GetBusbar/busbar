// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Regression net: a top-level `IrBlock::Media` (document/audio/video) on Cohere egress must be
//! dropped WITH the standard drop-with-warn `warn!`, never silently — the IR Media contract. The
//! Cohere `/chat` message-content shape carries only text and `image_url` parts, so a document
//! attachment (e.g. an Anthropic→Cohere hop) has no slot and is deliberately, observably dropped.

use super::*;
use busbar_substrate_values::testkit::warn_capture::WarnCapture;
use tracing_subscriber::layer::SubscriberExt as _;

#[test]
fn anthropic_to_cohere_document_media_warns_not_silent() {
    let ir = crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![
                crate::ir::IrBlock::Text {
                    text: "summarize this".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                crate::ir::IrBlock::Media {
                    kind: crate::ir::IrMediaKind::Document,
                    source: crate::ir::IrImageSource::Base64 {
                        media_type: "application/pdf".to_string(),
                        data: "JVBERi0=".to_string(),
                    },
                    name: Some("report.pdf".to_string()),
                    cache_control: None,
                },
            ],
        }],
        ..Default::default()
    };

    let cap = WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    let out = tracing::subscriber::with_default(subscriber, || {
        let w = CohereWriter;
        w.write_request(&ir)
    });

    // The document block is NOT projected onto the wire (Cohere has no content slot for it)...
    let msgs = out["messages"].as_array().expect("messages array");
    let user = msgs.last().expect("a user message");
    let dump = serde_json::to_string(user).unwrap();
    assert!(
        !dump.contains("application/pdf") && !dump.contains("JVBERi0="),
        "the document Media must not leak onto the Cohere message content: {dump}"
    );

    // ...but the drop is OBSERVABLE: the standard drop-with-warn fired, naming the kind.
    assert!(
        cap.contains("dropping attachment on Cohere egress"),
        "a dropped top-level Media block must warn (drop-with-warn, never silently): {:?}",
        cap.messages()
    );
    assert!(
        cap.messages()
            .iter()
            .any(|m| m.contains("media_kind=document")),
        "the warn must name the dropped media kind: {:?}",
        cap.messages()
    );
}
