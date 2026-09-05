// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Regression net: the Gemini egress Image-URL arm must emit `fileData` WITH a `mimeType`. Gemini's
//! `fileData` requires a `mimeType` to decode the referenced file (writer.rs invariant); the arm
//! previously emitted `fileData{fileUri}` alone, diverging from the Media-URL arm and producing a
//! part the backend rejects. A bare (mimeless) OpenAI/Anthropic image URL derives a representative
//! `image/*` from its extension, defaulting to `image/jpeg`.

use super::*;

fn image_url_req(uri: &str) -> crate::ir::IrRequest {
    crate::ir::IrRequest {
        messages: vec![crate::ir::IrMessage {
            role: crate::ir::IrRole::User,
            content: vec![crate::ir::IrBlock::Image {
                source: crate::ir::IrImageSource::Url(uri.to_string()),
                cache_control: None,
            }],
        }],
        ..Default::default()
    }
}

fn file_data(out: &serde_json::Value) -> serde_json::Value {
    out["contents"][0]["parts"]
        .as_array()
        .and_then(|parts| parts.iter().find(|p| p.get("fileData").is_some()))
        .and_then(|p| p.get("fileData"))
        .cloned()
        .expect("a fileData part")
}

#[test]
fn openai_url_image_to_gemini_emits_filedata_with_mimetype() {
    let w = GeminiWriter;
    let out = w.write_request(&image_url_req("https://ex.com/cat.png"));
    let fd = file_data(&out);
    assert_eq!(fd["fileUri"], "https://ex.com/cat.png");
    assert_eq!(
        fd["mimeType"], "image/png",
        "fileData must carry a mimeType derived from the URL: {out}"
    );
}

#[test]
fn extensionless_url_image_defaults_to_jpeg_mimetype() {
    let w = GeminiWriter;
    let out = w.write_request(&image_url_req("https://ex.com/generate?id=42"));
    let fd = file_data(&out);
    assert!(
        fd.get("mimeType").and_then(|m| m.as_str()).is_some(),
        "fileData must ALWAYS carry a mimeType, never be omitted: {out}"
    );
    assert_eq!(
        fd["mimeType"], "image/jpeg",
        "no extension → image/jpeg default"
    );
}
