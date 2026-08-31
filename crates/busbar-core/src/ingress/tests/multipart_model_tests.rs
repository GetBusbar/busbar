// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/ingress/dispatch.rs`.

use super::multipart_model;

#[test]
fn extracts_model_from_head_ignoring_large_binary_tail() {
    // A well-formed transcription: the `model` text part precedes a large binary audio part.
    // multipart_model must find the model in the head without touching the (here 1 MiB) tail.
    let mut body = Vec::new();
    body.extend_from_slice(
        b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"model\"\r\n\r\nwhisper-1\r\n",
    );
    body.extend_from_slice(
        b"--BOUNDARY\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a\"\r\n\r\n",
    );
    body.extend(std::iter::repeat_n(0u8, 1 << 20)); // 1 MiB of binary, not valid UTF-8
    body.extend_from_slice(b"\r\n--BOUNDARY--\r\n");
    assert_eq!(multipart_model(&body).as_deref(), Some("whisper-1"));
}

#[test]
fn absent_model_is_none() {
    let body = b"--B\r\nContent-Disposition: form-data; name=\"file\"\r\n\r\nx\r\n--B--\r\n";
    assert_eq!(multipart_model(body), None);
}
