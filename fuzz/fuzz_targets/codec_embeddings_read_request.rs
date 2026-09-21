#![no_main]
//! Fuzz the ingress decode of an untrusted embeddings request body.
//!
//! `embeddings_read_request` dispatches to each provider dialect's production
//! `read_embeddings_request` reader — the code path that turns bytes off the wire into typed IR.
//! The invariant under test: **arbitrary bytes must never panic the reader.** A malformed body is
//! a `Result::Err` (`IngressReject`), never a crash — so libFuzzer only fails on a genuine panic,
//! abort, OOM, or timeout, i.e. a real robustness defect in the parse surface.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    // Steer coverage across every dialect that has an embeddings reader, using the first byte so
    // the mutator can explore each parser; the remainder is the untrusted body.
    let proto = match data[0] % 4 {
        0 => "openai",
        1 => "cohere",
        2 => "bedrock",
        _ => "gemini",
    };
    let body = &data[1..];

    // content_type is part of the ingress contract; fuzz JSON and a non-JSON value so the reader's
    // content-type branch is exercised too.
    let content_type = if data[0] & 0x80 != 0 {
        "application/json"
    } else {
        "application/octet-stream"
    };

    let _ = busbar_llm_codec::leaf_codec::embeddings_read_request(proto, body, content_type);
});
