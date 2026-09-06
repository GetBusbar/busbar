//! Regression net for the image-source bug class (closed by the typed `IrImageSource`). The key
//! invariant: a writer can NEVER emit a corrupt block from a misread sentinel — a `Vendor`
//! reference it doesn't own is dropped, a neutral `Base64`/`Url` is projected natively.
use super::*;
use crate::ir::{IrBlock, IrImageSource, IrMessage, IrRole};

fn req_with_image(source: IrImageSource) -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        messages: vec![IrMessage {
            role: IrRole::User,
            content: vec![IrBlock::Image {
                source,
                cache_control: None,
            }],
        }],
        ..Default::default()
    }
}

/// A FOREIGN vendor reference (one the writer doesn't own) must never reach the wire as a corrupt
/// block — every writer drops it. (The OWNING protocol re-emits its own; covered per-protocol.)
#[test]
fn foreign_vendor_image_ref_never_corrupts_any_writer() {
    // A Responses file_id reference projected by every NON-Responses writer must be dropped.
    let foreign = IrImageSource::Vendor {
        vendor: "responses",
        value: serde_json::json!({ "file_id": "file-x" }),
    };
    let req = req_with_image(foreign);
    let cohere = CohereWriter;
    let gemini = GeminiWriter;
    let bedrock = BedrockWriter;
    let o = serde_json::to_string(&OpenAiWriter.write_request(&req)).unwrap();
    let a = serde_json::to_string(&anthropic_writer().write_request(&req)).unwrap();
    let g = serde_json::to_string(&gemini.write_request(&req)).unwrap();
    let b = serde_json::to_string(&bedrock.write_request(&req)).unwrap();
    let c = serde_json::to_string(&cohere.write_request(&req)).unwrap();
    for (name, wire) in [
        ("openai", o),
        ("anthropic", a),
        ("gemini", g),
        ("bedrock", b),
        ("cohere", c),
    ] {
        assert!(
            !wire.contains("file-x"),
            "{name} writer must DROP a foreign vendor image ref, not leak it: {wire}"
        );
    }
}

/// A neutral base64 image projects to a real inline-image shape on every writer that supports
/// images, and no writer corrupts it.
///
/// The doc has always claimed EVERY writer; only the OpenAI one was ever read, so a writer that
/// truncated or mangled the payload was caught for one dialect out of five. The same five writers
/// the foreign-vendor test above sweeps are swept here: each must carry the payload verbatim (a
/// neutral base64 image is native to all five), and none may leave a half-written block behind.
#[test]
fn base64_image_projects_intact_on_every_writer() {
    let req = req_with_image(IrImageSource::Base64 {
        media_type: "image/png".to_string(),
        data: "QUJD".to_string(),
    });
    // Each dialect names the media type in its OWN wire word — Bedrock's Converse shape carries a
    // bare `format` token where the others carry the MIME string — so the expected token is stated
    // per writer rather than assumed uniform.
    let gemini = GeminiWriter;
    let bedrock = BedrockWriter;
    let cohere = CohereWriter;
    for (name, media_token, wire) in [
        ("openai", "image/png", OpenAiWriter.write_request(&req)),
        (
            "anthropic",
            "image/png",
            anthropic_writer().write_request(&req),
        ),
        ("gemini", "image/png", gemini.write_request(&req)),
        ("bedrock", "\"png\"", bedrock.write_request(&req)),
        ("cohere", "image/png", cohere.write_request(&req)),
    ] {
        let s = serde_json::to_string(&wire).unwrap();
        assert!(
            s.contains("QUJD"),
            "{name} writer must carry the base64 payload to the wire intact: {s}"
        );
        // The media type rides with the payload; a writer that kept the bytes but lost the type
        // emits a block the far side cannot decode.
        assert!(
            s.contains(media_token),
            "{name} writer must carry the image media type beside the payload: {s}"
        );
    }
}
