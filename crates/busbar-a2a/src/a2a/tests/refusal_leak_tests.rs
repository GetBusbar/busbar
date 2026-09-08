// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! NO REFUSAL BODY NAMES THE BACKEND — the negative scan over every hop-refusal rendering that
//! reaches a CALLER.
//!
//! `agents.<agent>.url:` is the operator's, and `docs/a2a.md` states it is never client-visible:
//! callers reach a backend through busbar and are never told where it is. `super::serve`'s whole
//! `BackendLeak` apparatus refuses to publish a CARD that names it. The refusal path had one arm
//! that echoed it anyway — `receive::refuse_hop_early` put the refusal's `Display` straight into the
//! response body, and `Display` is the OPERATOR's rendering, which names the endpoint on purpose.
//!
//! So there are now two renderings and they are tested apart:
//!
//! * [`RelayRefusal::client_text`] — the CALLER's. A stable diagnostic code and a fixed sentence.
//!   Every arm is scanned below against a sentinel planted in every field a backend address could
//!   ride in, and the scan is proven non-vacuous by a control that finds the same sentinel in
//!   `Display`.
//! * `Display` — the OPERATOR's, unchanged, and the one the journal takes. Losing the endpoint
//!   there would be the opposite defect, so the control below REQUIRES it to still be present.
//!
//! The totality rule: [`arms`] builds one value per `RelayRefusal` variant and the `match` in
//! `client_text` is exhaustive, so a new arm cannot be added without a compiler error at the
//! rendering and a deliberate line here.

use crate::a2a::relay::RelayRefusal;

/// The needle. A host, a port and a path a caller must never be handed back, in the shape an
/// operator's `url:` really takes.
const BACKEND: &str = "https://planner.vendor.internal:8443/a2a";
/// The authority alone, because a rendering that took `url.host()` rather than the whole string
/// would slip past a scan that only looked for the full URL.
const BACKEND_HOST: &str = "planner.vendor.internal";
/// The backend's own prose. Not an address, and equally not the caller's to read: it is another
/// party's error text, reproduced verbatim into a body busbar signs its name to.
const BACKEND_PROSE: &str = "quota exhausted for tenant acme on shard 7";

/// ONE VALUE PER VARIANT, every address-bearing field carrying the sentinel.
fn arms() -> Vec<(&'static str, RelayRefusal)> {
    vec![
        (
            "Guard",
            RelayRefusal::Guard(crate::a2a::fetch::FetchRefusal::Transport {
                url: BACKEND.to_string(),
                err: "connection refused".to_string(),
            }),
        ),
        (
            "Transport",
            RelayRefusal::Transport {
                url: BACKEND.to_string(),
                err: "connection refused".to_string(),
            },
        ),
        (
            "Status",
            RelayRefusal::Status {
                url: BACKEND.to_string(),
                status: 500,
            },
        ),
        (
            "BodyTooLarge",
            RelayRefusal::BodyTooLarge {
                url: BACKEND.to_string(),
                bytes: 9_000_000,
            },
        ),
        (
            "NotJson",
            RelayRefusal::NotJson {
                url: BACKEND.to_string(),
                err: "expected value at line 1".to_string(),
            },
        ),
        (
            "BackendError",
            RelayRefusal::BackendError {
                code: "-32000".to_string(),
                message: BACKEND_PROSE.to_string(),
                jsonrpc_code: Some(-32000),
            },
        ),
        (
            "Uncorrelated",
            RelayRefusal::Uncorrelated {
                url: BACKEND.to_string(),
                reason: "the answer's id names another request".to_string(),
            },
        ),
        // `binding` deliberately carries NO sentinel. It is the transport word off the agent's own
        // card — the card says HOW, the operator's `url:` says WHERE — so it is not a place the
        // operator's endpoint can be. It is also the one word an operator has to act on when a card
        // declares a binding this build cannot speak, and `client_leg_tests` requires the refusal
        // to name it. The sentinel goes in `reason`, which is composed over the BACKEND'S BYTES on
        // the three framing sites and is exactly the free text the caller's rendering must drop.
        (
            "Unframable",
            RelayRefusal::Unframable {
                binding: "grpc".to_string(),
                method: "GetTask".to_string(),
                reason: format!("this build cannot spell it for {BACKEND}"),
            },
        ),
        (
            "BreakerOpen",
            RelayRefusal::BreakerOpen {
                agent_id: "planner".to_string(),
                retry_after_secs: 30,
            },
        ),
    ]
}

/// THE SCAN. No arm of the caller-facing rendering may name the backend — not the URL, not the
/// authority on its own, and not the backend's own prose.
#[test]
fn no_client_facing_hop_refusal_names_the_backend() {
    let mut offenders = Vec::new();
    for (name, refusal) in arms() {
        let text = refusal.client_text();
        for needle in [BACKEND, BACKEND_HOST, BACKEND_PROSE] {
            if text.contains(needle) {
                offenders.push(format!(
                    "RelayRefusal::{name} renders `{needle}` to the CALLER: {text}"
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "a hop refusal handed the caller the operator's backend address or the backend's own \
         words. `agents.<agent>.url:` is never client-visible — callers reach a backend through \
         busbar. The endpoint belongs in the journal, which `Display` still carries:\n{}",
        offenders.join("\n")
    );
}

/// EVERY ARM CARRIES A STABLE CODE, and no two arms share one. The code is the whole of what a
/// caller can quote to an operator now that the prose is fixed, so an arm that returned an empty or
/// duplicated code would make the generic text unactionable rather than merely safe.
#[test]
fn every_hop_refusal_carries_its_own_stable_code() {
    let mut seen: Vec<&'static str> = Vec::new();
    for (name, refusal) in arms() {
        let code = refusal.client_code();
        assert!(
            code.starts_with("a2a.hop."),
            "RelayRefusal::{name} has code `{code}`, which is not in the plane's `a2a.hop.` family"
        );
        assert!(
            !seen.contains(&code),
            "RelayRefusal::{name} reuses the code `{code}`; a code that names two different \
             refusals tells an operator nothing"
        );
        assert!(
            refusal.client_text().contains(code),
            "RelayRefusal::{name}'s caller-facing text does not carry its own code `{code}`, so \
             there is nothing for the caller to quote"
        );
        seen.push(code);
    }
}

/// THE CONTROL. Two claims at once, and the scan above is worthless without either.
///
/// 1. The scanner CAN find the sentinel — `Display` is the operator's rendering and still names the
///    endpoint, so a refusal whose backend became unreachable is still diagnosable from the journal.
/// 2. The two renderings are therefore genuinely different, rather than the scan passing because
///    every arm happened to be built without a URL in it.
#[test]
fn the_operator_rendering_still_names_the_backend() {
    let mut named = 0usize;
    for (_, refusal) in arms() {
        if refusal.to_string().contains(BACKEND) {
            named += 1;
        }
    }
    assert!(
        named >= 6,
        "the journal rendering names the backend in only {named} arms — either the scanner cannot \
         find the sentinel at all (so the negative scan above proves nothing) or the endpoint has \
         been dropped from the operator's own diagnosis too, which is the opposite defect"
    );
}

/// THE TWO UNTRUSTED WORDS ARE BOUNDED. `Unframable` is the one arm that quotes anything busbar did
/// not author, and both of the words it quotes come from a document somebody else controls: the
/// binding name off the agent's card, and the method name off the caller's envelope. So the bound
/// is asserted rather than assumed — a URL cannot survive it, a control character cannot survive
/// it, and a paragraph is truncated.
#[test]
fn the_untrusted_words_in_a_refusal_are_bounded() {
    let long = "a".repeat(4096);
    let hostile = RelayRefusal::Unframable {
        binding: format!("{BACKEND}\r\nX-Injected: 1"),
        method: long.clone(),
        reason: String::new(),
    };
    let text = hostile.client_text();
    assert!(
        !text.contains(&long),
        "a 4096-char method was quoted back whole; the bound does not truncate: {text}"
    );
    assert!(
        !text.contains('\r') && !text.contains('\n'),
        "a CRLF survived into a refusal body, so this arm is a header-injection channel: {text:?}"
    );
    assert!(
        !text.contains("https:") && !text.contains(":8443"),
        "a scheme or an authority survived the bound, so a URL can still be written through the \
         binding word: {text}"
    );
    // The control: an ordinary word an operator really has to act on passes through UNCHANGED, or
    // the bound has made the refusal useless instead of safe.
    let real = RelayRefusal::Unframable {
        binding: "SOAP-1.2-OVER-CARRIER-PIGEON".to_string(),
        method: "message/send".to_string(),
        reason: String::new(),
    };
    let text = real.client_text();
    assert!(
        text.contains("SOAP-1.2-OVER-CARRIER-PIGEON") && text.contains("message/send"),
        "the bound mangled the word an operator has to act on and the method the caller sent, so \
         the refusal names neither end of the problem: {text}"
    );
}

/// AND THE PATH THE REPORT NAMED. A refused `GetExtendedAgentCard` on `Target::Named` relays, and a
/// relay refusal on a card fetch renders through `receive::refuse_hop_early` — the one arm that
/// echoed. Driven at the renderer rather than over a socket because that is where the leak was: the
/// body builder, on every arm it can be handed, on all three bindings at once.
#[test]
fn the_card_fetch_refusal_body_names_no_backend() {
    let rpc_id = serde_json::json!(7);
    let mut offenders = Vec::new();
    for (name, refusal) in arms() {
        let body = crate::a2a::receive::refuse_hop_early_body(&rpc_id, &refusal);
        let rendered = serde_json::to_string(&body).expect("the refusal body serializes");
        for needle in [BACKEND, BACKEND_HOST, BACKEND_PROSE] {
            if rendered.contains(needle) {
                offenders.push(format!(
                    "the card-fetch refusal body for RelayRefusal::{name} carries `{needle}`: \
                     {rendered}"
                ));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "`GetExtendedAgentCard` against a named agent whose backend is down handed the caller the \
         operator's endpoint. It is reachable by any key holding a grant on the agent, on all \
         three bindings:\n{}",
        offenders.join("\n")
    );
}
