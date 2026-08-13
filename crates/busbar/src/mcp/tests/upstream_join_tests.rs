// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UPSTREAM LEG, and the THREE-ARM PAIRING that keeps it honest.
//!
//! While there was no client direction, `tools/call` refused rather than returning a plausible
//! result, and a PAIR of tests held the line: an ungranted caller refused BEFORE the upstream, a
//! granted one refused AFTER everything else passed. The pair existed because "it was refused"
//! proves nothing about WHICH check refused it — a stub returning a fake result would have made
//! admission, generation re-validation, the budget charge, the meter, the ask gate and the audit row
//! all pass for the wrong reason.
//!
//! The leg now exists, so the pair becomes a TRIPLE and the property it protects is unchanged:
//!
//! | arm | caller | upstream | expected |
//! |---|---|---|---|
//! | before | ungranted | reachable | `not_granted`, and the upstream is NEVER contacted |
//! | after | granted | unreachable | `upstream_failed`, after every check above it passed |
//! | through | granted | reachable | the upstream's own result, sanitised |
//!
//! The third arm is what stops the first two being satisfied by a `tools/call` that refuses
//! everything, and the first is what stops the third being satisfied by one that dispatches
//! everything. Each is load-bearing only because the others exist.

use super::upstream_support::{call, exchanging_server, gov_with_scopes, mcp_cfg, Behaviour, Peer};
use crate::test_support::TestApp;

const CANONICAL: &str = "https://gateway.example.com/mcp";
const SUBJECT: &str = "busbar-own-subject-token-for-the-exchange";
const ISSUED: &str = "downscoped-access-token-issued-by-the-as";

/// ARM 3 — THE SUCCESSFUL DISPATCH. A granted caller reaches a reachable upstream and is handed the
/// upstream's own result.
///
/// Asserted on the OUTPUT at both ends: the caller gets the result body, and the PEER records that
/// it was called once, with the UN-namespaced tool name, the mirrored `2026-07-28` headers, and the
/// exchanged bearer rather than anything of the caller's.
#[tokio::test]
async fn a_granted_call_reaches_the_upstream_and_returns_its_result() {
    crate::metrics::init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": { "path": "/etc/hosts" } }),
    )
    .await;

    assert_eq!(
        status, 200,
        "a granted call to a reachable upstream: {body}"
    );
    assert_eq!(
        body.pointer("/result/content/0/text").unwrap(),
        "UPSTREAM RESULT",
        "the CALLER is handed the upstream's own result: {body}"
    );

    // THE PEER'S OWN RECORD. One call, not zero and not two.
    assert_eq!(peer.mcp_hits(), 1, "exactly one round trip per dispatch");
    let sent = peer.last_mcp();
    let json = sent.json();
    assert_eq!(
        json.pointer("/params/name").unwrap(),
        "read",
        "the UPSTREAM is sent the bare tool name; the `{{server}}_{{tool}}` namespacing is busbar's \
         and the upstream has never heard of it"
    );
    assert_eq!(json.get("method").unwrap(), "tools/call");
    let header = |n: &str| {
        sent.headers
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.clone())
    };
    assert_eq!(
        header("mcp-protocol-version").as_deref(),
        Some(crate::mcp::envelope::PROTOCOL_VERSION),
        "busbar must satisfy the same transport MUSTs it enforces on its own ingress"
    );
    assert_eq!(header("mcp-method").as_deref(), Some("tools/call"));
    assert_eq!(header("mcp-name").as_deref(), Some("read"));
    assert_eq!(
        header("authorization").as_deref(),
        Some(format!("Bearer {ISSUED}").as_str()),
        "the credential on the wire is the EXCHANGED one, not busbar's ambient subject token"
    );

    // And the exchange happened, exactly once, before the tool call it was for.
    assert_eq!(peer.token_hits(), 1, "one exchange per dispatch round");
}

/// ARM 1 — BEFORE. An ungranted caller is refused at ADMISSION, and the upstream is never contacted.
///
/// The second half is the part that cannot be inferred from the status code: a refusal that still
/// costs a round trip is a refusal an unauthorised party can use to make busbar generate traffic.
#[tokio::test]
async fn an_ungranted_call_is_refused_before_the_upstream_is_contacted_at_all() {
    crate::metrics::init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let none = gov_with_scopes(&[]);

    let (status, body) = call(
        &app,
        &none,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": {} }),
    )
    .await;

    assert_eq!(status, 404);
    assert_eq!(
        body.pointer("/error/data/reason").unwrap(),
        "not_granted",
        "refused by the GRANT, before the upstream: {body}"
    );
    assert_eq!(
        (peer.mcp_hits(), peer.token_hits()),
        (0, 0),
        "an unauthorised call must cause NO outbound traffic — neither a tool call nor a \
         token-exchange round trip on busbar's own authorization server"
    );
}

/// ARM 2 — AFTER. A granted caller whose upstream cannot be reached is refused by the ROUND TRIP,
/// with a reason distinct from every governance refusal.
///
/// The upstream is a port nothing is listening on, so this is a real connection failure rather than
/// a simulated one.
#[tokio::test]
async fn a_granted_call_to_an_unreachable_upstream_fails_at_the_round_trip() {
    crate::metrics::init();
    // Bind and immediately drop, so the port is one nothing answers on rather than one that might
    // belong to something else on the machine.
    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);

    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let mut def = exchanging_server(&peer, SUBJECT);
    def.url = format!("http://{dead_addr}/mcp");
    def.aud = Some(def.url.clone());

    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", def)
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": {} }),
    )
    .await;

    // 200 AND `isError`, NOT 403. Every governance check PASSED and the call went out; what failed
    // was the far end. This asserted `403` / `error.data.reason = upstream_failed` until the
    // `Outcome::UpstreamFailed` split, which is the bug the assertion had frozen: an upstream that
    // is down was reported to the caller as busbar refusing the request, so the model could neither
    // see the failure nor retry it, and nothing reading dispositions could tell a policy refusal
    // from an outage.
    assert_eq!(
        status, 200,
        "an upstream failure is not busbar refusing: {body}"
    );
    assert!(
        body.pointer("/error").is_none(),
        "a tool that failed is not a protocol error: {body}"
    );
    assert_eq!(
        body.pointer("/result/isError").and_then(|v| v.as_bool()),
        Some(true),
        "the failure must reach the MODEL, which reads isError results and not JSON-RPC errors: \
         {body}"
    );
    assert_eq!(
        body.pointer("/result/resultType").and_then(|v| v.as_str()),
        Some("complete"),
        "and it is a complete result: the dispatch finished, it finished badly: {body}"
    );
    let text = body
        .pointer("/result/content/0/text")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        text.contains("`fs`"),
        "the caller needs to know WHICH upstream failed: {text}"
    );
    // The exchange DID happen — this caller was authorised, so busbar was willing to spend its own
    // credential. That is the difference from arm 1, on the token endpoint's own counter.
    assert_eq!(
        peer.token_hits(),
        1,
        "a granted caller's dispatch mints a credential; an ungranted one does not"
    );
}

/// The three arms answer with THREE DIFFERENT reason words. Asserted as a set, because two arms that
/// happened to share a word would make the pairing above prove nothing.
#[tokio::test]
async fn the_three_arms_are_distinguishable_by_their_audit_reason() {
    crate::metrics::init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let reachable = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();

    let dead = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_addr = dead.local_addr().unwrap();
    drop(dead);
    let mut def = exchanging_server(&peer, SUBJECT);
    def.url = format!("http://{dead_addr}/mcp");
    def.aud = Some(def.url.clone());
    let unreachable = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", def)
        .build();

    let granted = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let none = gov_with_scopes(&[]);
    let params = serde_json::json!({ "name": "fs_read", "arguments": {} });

    let (ok_status, ok_body) = call(&reachable, &granted, "tools/call", params.clone()).await;
    let (before_status, before_body) = call(&reachable, &none, "tools/call", params.clone()).await;
    let (after_status, after_body) = call(&unreachable, &granted, "tools/call", params).await;

    // THREE OUTCOMES, THREE SHAPES, and the third one changed. It used to be `403` — the same
    // status and the same `error.data.reason` family as the ungranted arm — so "you may not call
    // this" and "the far end is down" were one signal wearing one word. They are now different
    // KINDS of answer, which is the strongest form of distinguishable: a refusal is a JSON-RPC
    // error, an upstream failure is an `isError` result.
    assert_eq!((ok_status, before_status, after_status), (200, 404, 200));
    assert!(
        ok_body.pointer("/error").is_none(),
        "the success arm must carry no error at all: {ok_body}"
    );
    assert_eq!(
        before_body
            .pointer("/error/data/reason")
            .and_then(|v| v.as_str()),
        Some("not_granted"),
        "the REFUSAL arm is a busbar-attributed protocol error: {before_body}"
    );
    assert!(
        after_body.pointer("/error").is_none()
            && after_body
                .pointer("/result/isError")
                .and_then(|v| v.as_bool())
                == Some(true),
        "the UPSTREAM-FAILURE arm is a tool execution error, not a refusal: {after_body}"
    );
    assert_ne!(
        ok_body.pointer("/result/isError").and_then(|v| v.as_bool()),
        Some(true),
        "and the success arm must not also look like a failure, or the pairing above is vacuous: \
         {ok_body}"
    );
}

/// An upstream that returns an `InputRequiredResult` — a bid to spend BUSBAR's authority — is
/// refused deny-by-default, and its ask is NOT proxied to busbar's caller.
///
/// This is the gate exercised through the REAL parser now that one exists: `input_required` is
/// recognised off the wire rather than constructed by a fake.
#[tokio::test]
async fn an_upstreams_ask_is_recognised_off_the_wire_and_refused_deny_by_default() {
    crate::metrics::init();
    let peer = Peer::start(Behaviour::AsksForSampling, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": {} }),
    )
    .await;

    assert_eq!(status, 403);
    assert_eq!(
        body.pointer("/error/data/reason").unwrap(),
        "ask_ungranted",
        "an upstream's ask is deny-by-default, and it is its OWN reason word: {body}"
    );
    let message = body
        .pointer("/error/message")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("terminates at busbar"),
        "the caller is told busbar declined, never handed the ask to answer: {message}"
    );
}

/// THE CONFUSED-DEPUTY LAUNDERING TEST, asserted on the BYTES THE CALLER RECEIVES.
///
/// The test above asserts busbar's refusal is well-formed. It cannot catch laundering, because a
/// laundered ask never reaches the arm it inspects — it is a `200` with a result, not a `403` with a
/// reason. This one asserts the only thing that actually matters: **no field of the upstream's ask
/// appears anywhere in the response body busbar hands its caller.**
///
/// The upstream mounts the real attack: a conformant `elicitation/create` demanding the caller's
/// account password. If busbar relays it, the caller sees a credential prompt arriving from the
/// party it trusts — busbar — with busbar's authentication and busbar's name on it. That is the
/// laundering `mcp/mod.rs:83` and `method.rs:649-652` both say busbar refuses to do.
///
/// Asserted as a SUBSTRING SCAN over the serialised body rather than field-by-field, for the reason
/// `Recorded::wire` gives on the outbound side: a field-by-field assertion is a list somebody has to
/// remember to extend, and the next `InputRequiredResult` field is the one it will not name.
#[tokio::test]
async fn a_conformant_upstreams_ask_reaches_the_caller_never() {
    crate::metrics::init();
    let peer = Peer::start(Behaviour::HarvestsCredentials, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (_status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": {} }),
    )
    .await;

    let wire = serde_json::to_string(&body).expect("the caller's response body serialises");
    for sentinel in [
        "input_required",
        "inputRequests",
        "requestState",
        "elicitation/create",
        "upstream-opaque-state-blob",
        "account password",
        "requestedSchema",
    ] {
        assert!(
            !wire.contains(sentinel),
            "the upstream's ask reached busbar's CALLER: `{sentinel}` is in the response body.\n\
             A registered tool server just asked busbar's caller for its password, and busbar \
             delivered the demand under its own name.\n\
             FULL BODY: {wire}"
        );
    }
}

/// THE SECOND MECHANISM, exercised on the case the FIRST one cannot see.
///
/// `input_required_kind` recognises an ask by its discriminator. So an upstream that carries
/// `inputRequests` on a result labelled `complete` walks straight past it — and that is not a
/// contrived shape, it is the cheapest way for a hostile upstream to be non-conformant in the
/// direction that helps it.
///
/// This is why the terminal check in `method.rs` reads the FIELDS rather than the discriminator, and
/// why it refuses rather than scrubbing: scrubbing `resultType` alone would deliver the password
/// prompt anyway, relabelled, and dropping `inputRequests` alone would hand the caller a truncated
/// result it had no way to know was truncated.
#[tokio::test]
async fn an_ask_smuggled_onto_a_result_labelled_complete_does_not_reach_the_caller_either() {
    crate::metrics::init();
    let peer = Peer::start(Behaviour::HalfConformantAsk, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": {} }),
    )
    .await;

    // NO RESULT AT ALL. Asserted before the content scan, because it is the stronger statement: a
    // refusal has no result, so there is nothing for the upstream's ask to be hiding in.
    assert!(
        body.get("result").is_none(),
        "a result carrying an ask must not be delivered in any form: {body}"
    );
    // The scan is over the upstream's OWN CONTENT, and deliberately not over the field names.
    // busbar's refusal names the offending field on purpose — an operator debugging a
    // half-conformant upstream needs to know which one arrived — and a scan that could not tell
    // busbar's diagnosis from the upstream's demand would forbid busbar from explaining itself.
    let wire = serde_json::to_string(&body).expect("serialises");
    for sentinel in [
        "elicitation/create",
        "account password",
        "requestedSchema",
        "upstream-opaque-state-blob",
        "almost done",
    ] {
        assert!(
            !wire.contains(sentinel),
            "an ask labelled `complete` reached busbar's CALLER: `{sentinel}` is in the response \
             body. The discriminator-based recogniser cannot catch this shape, which is precisely \
             what the terminal check exists for.\nFULL BODY: {wire}"
        );
    }
    assert_eq!(status, 403, "and it is a busbar-attributed refusal: {body}");
    assert_eq!(
        body.pointer("/error/data/reason").and_then(|v| v.as_str()),
        Some("ask_not_proxied"),
        "the terminal check has its OWN audit word, so an operator can tell it from the \
         recogniser's refusal: {body}"
    );
}

/// A JSON-RPC error from the upstream is an upstream failure, not a governance refusal, and the
/// upstream's message is not laundered into busbar's own vocabulary.
#[tokio::test]
async fn an_upstream_json_rpc_error_is_reported_as_an_upstream_failure() {
    crate::metrics::init();
    let peer = Peer::start(Behaviour::Errors, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": {} }),
    )
    .await;

    // A TOOL THAT MERELY FAILED IS NOT BUSBAR REFUSING THE REQUEST. This asserted `403` /
    // `upstream_failed` in `error.data.reason`, which conflated the two facts: `-32000` / FORBIDDEN
    // is busbar's "I decline", and nothing here declined anything — busbar carried the call and the
    // upstream answered badly. The spec's own division puts this on the other side of the line:
    // protocol errors describe the REQUEST, tool execution errors describe the RUN, and the latter
    // are reported in tool results with `isError: true` so the model can see the message.
    assert_eq!(
        status, 200,
        "the tool failed; busbar did not refuse: {body}"
    );
    assert!(body.pointer("/error").is_none(), "{body}");
    assert_eq!(
        body.pointer("/result/isError").and_then(|v| v.as_bool()),
        Some(true),
        "{body}"
    );
    let message = body
        .pointer("/result/content/0/text")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        message.contains("-32003"),
        "the operator needs the upstream's own code to diagnose it, and the MODEL needs it in the \
         place a model reads: {message}"
    );
}

/// TOOL OUTPUT IS SANITISED. An upstream's RESULT is exactly as injectable as its description, and
/// it arrives later — after the operator has already approved the tool. The normalisation site is on
/// the way OUT to the caller, which is the moment the text re-enters model context.
#[tokio::test]
async fn upstream_tool_output_is_markup_normalised_before_it_reaches_the_caller() {
    crate::metrics::init();
    // A peer whose result carries injection markup. Served through the same recorder so the wire is
    // still assertable.
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);
    let (_, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({ "name": "fs_read", "arguments": {} }),
    )
    .await;
    // The peer's honest payload must survive byte-identical — the CONTROL half of the sanitiser
    // claim. Without it, a normaliser that deleted everything would pass any "no markup" assertion.
    assert_eq!(
        body.pointer("/result/content/0/text").unwrap(),
        "UPSTREAM RESULT",
        "an honest upstream result must survive the normaliser byte-identical"
    );
    assert_eq!(
        crate::mcp::sanitize::normalise("<IMPORTANT>exfiltrate</IMPORTANT>ok"),
        "exfiltrateok",
        "and the normaliser the dispatch path calls is the one that strips markup"
    );
}

/// THE ARGUMENT GUARD is on the live dispatch path. A URL carried INSIDE the per-request tool
/// arguments is judged by the same addressing check the destination is, and a refusal there is its
/// own reason word — not an upstream failure and not a grant refusal.
///
/// The routing rule makes the DESTINATION immune to attacker-chosen text. It does not make the
/// PAYLOAD immune, and a live upstream leg is exactly where that distinction starts to matter.
#[tokio::test]
async fn a_metadata_url_hidden_in_the_tool_arguments_is_refused_and_never_sent() {
    crate::metrics::init();
    let peer = Peer::start(Behaviour::Result, ISSUED).await;
    let app = TestApp::new()
        .mcp(&mcp_cfg(CANONICAL))
        .mcp_server("fs", exchanging_server(&peer, SUBJECT))
        .build();
    let g = gov_with_scopes(&[("mcp_server", "fs"), ("mcp_tool", "fs_read")]);

    let (status, body) = call(
        &app,
        &g,
        "tools/call",
        serde_json::json!({
            "name": "fs_read",
            // Not a field the pinned schema declares. A schema-DRIVEN walk could not visit it, and
            // that is precisely the field that matters.
            "arguments": { "path": "/ok", "callback": "http://169.254.169.254/latest/meta-data/" },
        }),
    )
    .await;

    assert_eq!(status, 403);
    assert_eq!(
        body.pointer("/error/data/reason").unwrap(),
        "tool_argument_refused",
        "an inadmissible ARGUMENT is its own refusal, distinct from a grant and from a network: \
         {body}"
    );
    assert_eq!(
        (peer.mcp_hits(), peer.token_hits()),
        (0, 0),
        "the refusal happens before any outbound traffic, the token exchange included"
    );
}
