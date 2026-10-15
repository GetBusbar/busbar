// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A SAME-DIALECT USAGE-TAPPING BODY PAST THE TAP'S CAP BILLS NO TOKENS (status row 155, from the
//! codec lane's #846; ARCHITECT 2026-10-13), `$`: 1.5.5 kept only the body's first `cap` bytes, its
//! reading found no usage, and the request billed no tokens (v1.5.5 proxy/response_body.rs:230-262,
//! "this request's tokens are undercounted"). The relay billed a FLOOR estimate over the bytes it
//! kept instead. The cap is the relay's own `translate_cap`, set here at 64 bytes.

use busbar_contract::operation::OpVerb;
use busbar_plane_llm::exchange::reply::relay::{Relay, RelayCtx};

/// The codec host these relays are handed: the OS CSPRNG and the system clock in whole seconds.
struct TestHost;

impl busbar_contract::codec::CodecHost for TestHost {
    fn fill_entropy(&self, out: &mut [u8]) -> bool {
        getrandom::fill(out).is_ok()
    }

    fn wall_clock_now(&self) -> Option<u64> {
        Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs()),
        )
    }
}

/// The handle every codec call here is handed.
const HOST: &dyn busbar_contract::codec::CodecHost = &TestHost;

/// The usage tap's cap these relays carry.
const CAP: usize = 64;

fn embeddings_handler() -> &'static dyn busbar_contract::codec::OperationHandler {
    busbar_plane_llm::codec::DECLS
        .iter()
        .find(|d| d.name == "openai")
        .and_then(|d| d.handler)
        .and_then(|rh| rh.operation_handler(OpVerb::EMBEDDINGS))
        .expect("the openai dialect serves embeddings")
}

fn relay() -> Relay {
    Relay::new(RelayCtx {
        ingress: "openai",
        egress: "openai",
        far_is_stream: false,
        json_array: false,
        client_include_usage: false,
        request: None,
        handler: embeddings_handler(),
        meter: true,
        translate_cap: CAP,
    })
}

/// An embeddings answer of `pad` floats before its usage (5 tokens).
fn body(pad: usize) -> Vec<u8> {
    let floats = vec!["0.25"; pad].join(",");
    format!(
        "{{\"object\":\"list\",\"data\":[{{\"object\":\"embedding\",\"index\":0,\"embedding\":[{floats}]}}],\"model\":\"m\",\"usage\":{{\"prompt_tokens\":5,\"total_tokens\":5}}}}"
    )
    .into_bytes()
}

/// RED: the relay billed the floor over the bytes past the cap instead of none.
#[test]
fn a_body_past_the_usage_taps_cap_bills_no_tokens_and_one_under_it_bills_its_usage() {
    let over = body(200);
    assert!(over.len() > CAP);
    let mut r = relay();
    for piece in over.chunks(16) {
        let _ = r.feed(HOST, piece);
    }
    assert!(
        r.incurred_usage().is_none(),
        "nothing incurred past the cap"
    );
    let end = r.end(HOST);
    assert!(
        end.usage.is_none(),
        "no tokens past the cap: {:?}",
        end.usage
    );

    // THE CONTROL, under the cap: the body's own usage bills.
    let under: &[u8] = br#"{"data":[],"usage":{"prompt_tokens":5,"total_tokens":5}}"#;
    assert!(under.len() <= CAP);
    let mut r = relay();
    let _ = r.feed(HOST, under);
    let end = r.end(HOST);
    assert!(end.usage.is_some(), "a body under the cap bills its usage");
}
