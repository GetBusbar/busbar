// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE BOUNDARY TESTS of the five kinds whose shipped plugins change only by recompiling: auth, store, secret,
//! export, hook. One side of each test is the ENGINE'S REAL HALF (admission, the loader's adapter for the kind,
//! the reference host's driver and validator, reached through [`Harness`]); the other is the kind's REFERENCE
//! IMPLEMENTATION (`fixtures/ref_<kind>.rs`), written to hold the host to exactly what the revision changes on
//! that kind. So each kind proves alone, on one compile of the contract:
//!
//! - the adapter packs the method's `head`, `texts` and `blobs` in the order the kind's layout states (a
//!   reference reads them by position and records or checks what it read);
//! - the element the revision moved or added on that kind arrives and is honoured end to end (secret:
//!   `F_LEASE_S` reaches `SecretAnswer::lease_s`; export: `deliver`'s `lines` is the batch's record count;
//!   hook: the three stages, and only they; auth: the host's HMAC over parts equals the MAC of the
//!   concatenation, by a published known answer; store: the whole store suite on the in-tree store);
//! - the kind's own conformance suite passes on the reference, so the suite and the engine agree on the kind
//!   before any shipped plugin is pointed at either.
//!
//! The other direction (a REAL plugin against the reference host) is each plugin repository's own
//! `tests/suite.rs`, which calls the same `suites::<kind>` on its own image: fleet-proof.sh runs it against
//! this tree by a path override. A failure there with these tests green is the plugin's; a failure here is the
//! contract's or the adapter's. That split is what the boot test then only confirms.

use std::time::{Duration, Instant};

use busbar_plugin_abi::auth::BAD_CREDENTIAL;
use busbar_plugin_abi::hook::{
    CandidateRec, POINT_NOTIFY, POINT_REWRITE, POINT_ROUTE, STAGE_CANDIDATE, STAGE_RESPONSE,
    STAGE_ROUTING, S_STAGE, VERB_ABSTAIN, VERB_PREFER,
};
use busbar_plugin_abi::types::{Bytes, Pair, Str};
use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites::harness::Harness;
use busbar_plugin_test::suites::{self, AuthCase, Expect};
use busbar_ports::auth::AuthIn;
use busbar_ports::export::Delivered;
use busbar_ports::hook::{CandidateIn, HookAnswer, HookCall, HookView};
use busbar_ports::{CallCx, FactRef, PortError};

use crate::{min3_store, ref_auth, ref_export, ref_hook, ref_secret};

/// One header as the engine hands it to an auth plugin: a borrowed name and a borrowed value.
fn header<'a>(name: &'a str, value: &'a [u8]) -> Pair<'a> {
    header(Str::new(name), Bytes::new(value))
}

fn cx() -> CallCx {
    CallCx {
        request_id: 1,
        deadline: Instant::now() + Duration::from_secs(30),
        stack: Default::default(),
    }
}

// ---------------------------------------------------------------------------------------------------------
// secret 3.0
// ---------------------------------------------------------------------------------------------------------

/// The secret suite on the reference: the suite and the engine's secret adapter agree on the kind.
#[test]
fn secret_the_suite_passes_over_the_reference() {
    suites::secret(
        ref_secret::PLUGIN.plugin(),
        br#"{"db":"hunter2-zq81","api":"k-93ac0d","lease_s":"300"}"#,
        FakeNeeds::new(),
        &[
            (br#"{"name":"db"}"#, b"hunter2-zq81"),
            (br#"{"name":"api"}"#, b"k-93ac0d"),
        ],
        &[br#"{"name":"busbar-suite-no-such-secret-7f3a"}"#],
    );
}

/// E.6: a source that states a lease is read as one. The fact is written by the plugin, crosses in the
/// answer, and is the adapter's `lease_s`, to the second.
#[test]
fn secret_a_stated_lease_reaches_the_engine_as_lease_s() {
    let h =
        Harness::admit(&ref_secret::PLUGIN, FakeNeeds::new()).expect("the reference is admitted");
    let leased = h
        .open_secret("leased", br#"{"db":"hunter2-zq81","lease_s":"300"}"#)
        .expect("opens");
    let answer = h
        .block_on(leased.resolve(cx(), br#"{"name":"db"}"#))
        .expect("resolves");
    assert_eq!(answer.value.as_slice(), b"hunter2-zq81");
    assert_eq!(answer.lease_s, Some(300));
}

/// A source that states no lease writes no fact: the engine's own TTL applies, and `lease_s` is `None`, never 0.
#[test]
fn secret_no_stated_lease_is_none_not_zero() {
    let h =
        Harness::admit(&ref_secret::PLUGIN, FakeNeeds::new()).expect("the reference is admitted");
    let plain = h
        .open_secret("plain", br#"{"db":"hunter2-zq81"}"#)
        .expect("opens");
    let answer = h
        .block_on(plain.resolve(cx(), br#"{"name":"db"}"#))
        .expect("resolves");
    assert_eq!(answer.value.as_slice(), b"hunter2-zq81");
    assert_eq!(answer.lease_s, None);
    // A lease of zero or of no number is refused at open: it never becomes a fact.
    for bad in [
        &br#"{"db":"x","lease_s":"0"}"#[..],
        br#"{"db":"x","lease_s":"-1"}"#,
        br#"{"db":"x","lease_s":"soon"}"#,
    ] {
        assert!(
            h.open_secret("bad", bad).is_err(),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
}

// ---------------------------------------------------------------------------------------------------------
// export 4.0
// ---------------------------------------------------------------------------------------------------------

/// The export suite on the reference sink (which refuses any batch whose record count is not the stated
/// `lines`): every delivery the suite makes is one the adapter counted correctly.
#[test]
fn export_the_suite_passes_over_the_reference() {
    suites::export(ref_export::PLUGIN.plugin(), b"{}", FakeNeeds::new());
}

/// E.7: `deliver` states its line count in its head. For batches of 0, 1, 3 and 200 lines (a newline inside a
/// line is part of that line, an empty line is still a line) the reference reads `lines` equal to the records
/// it counts, and every other number of the head arrives where the layout puts it.
#[test]
fn export_deliver_states_the_batchs_line_count_and_every_head_number() {
    let h =
        Harness::admit(&ref_export::PLUGIN, FakeNeeds::new()).expect("the reference is admitted");
    let port = h.open_export("sink", b"{}").expect("opens");
    let many: Vec<String> = (0..200).map(|i| format!("{{\"n\":{i}}}")).collect();
    let many: Vec<&[u8]> = many.iter().map(String::as_bytes).collect();
    let batches: [&[&[u8]]; 4] = [
        &[],
        &[b"{\"one\":1}"],
        &[b"{\"a\":\"x\\ny\"}", b"", b"line\nwith a newline byte"],
        &many,
    ];
    for (i, lines) in batches.iter().enumerate() {
        let (delivery, attempt) = (0x1122_3344_5566_7700 + i as u64, 1 + i as u32);
        let answer = h
            .block_on(port.deliver(
                cx(),
                busbar_plugin_abi::export::STREAM_LOGS,
                delivery,
                attempt,
                lines,
            ))
            .unwrap_or_else(|e| panic!("batch {i} was refused: {e:?}"));
        match answer {
            Delivered::Acked { accepted, .. } => {
                assert_eq!(accepted, lines.len() as u64, "batch {i}")
            }
            other => panic!("batch {i}: the reference only ACKs, got {other:?}"),
        }
        let head = ref_export::LAST
            .lock()
            .expect("the reference's record")
            .expect("the reference saw the delivery");
        assert_eq!(
            head,
            ref_export::Head {
                stream: busbar_plugin_abi::export::STREAM_LOGS,
                delivery,
                attempt,
                lines: lines.len() as u32,
                found: lines.len() as u64,
            },
            "batch {i}: the head as the plugin read it"
        );
    }
}

// ---------------------------------------------------------------------------------------------------------
// hook 3.0
// ---------------------------------------------------------------------------------------------------------

/// The hook suite on the reference: every view the suite builds (stage taps included) gets a legal verdict.
#[test]
fn hook_the_suite_passes_over_the_reference() {
    suites::hook(ref_hook::PLUGIN.plugin(), b"{}", FakeNeeds::new());
}

fn settle(h: &Harness, call: HookCall<'_>) -> Result<HookAnswer, PortError> {
    match call {
        HookCall::Done(answer) => answer,
        HookCall::Io(future) => h.block_on(future),
    }
}

fn view<'a>(signals: &'a [(u32, FactRef<'a>)], candidates: &'a [CandidateIn<'a>]) -> HookView<'a> {
    HookView {
        signals,
        candidates,
        budgets: &[],
        conversation: None,
        body: None,
        identity: None,
    }
}

/// E.8: the reference declares no `FB_*` fact (`FB_WANTS_BODY` is gone; identity is not asked for), serves the
/// three decision points, and each of the three stages reaches it as its own number at POINT_NOTIFY.
#[test]
fn hook_the_three_stages_cross_as_themselves_and_no_fact_is_declared() {
    let h = Harness::admit(&ref_hook::PLUGIN, FakeNeeds::new()).expect("the reference is admitted");
    let port = h.open_hook("hook", b"{}").expect("opens");
    assert_eq!(
        port.facts(),
        0,
        "the reference asks for no prompt, body or identity"
    );
    assert_eq!(
        port.points(),
        (1 << POINT_ROUTE) | (1 << POINT_REWRITE) | (1 << POINT_NOTIFY)
    );
    for stage in [STAGE_CANDIDATE, STAGE_ROUTING, STAGE_RESPONSE] {
        let signals = [(S_STAGE, FactRef::U(stage))];
        let answer = settle(&h, port.on(cx(), POINT_NOTIFY, &view(&signals, &[])))
            .unwrap_or_else(|e| panic!("stage {stage} was refused: {e:?}"));
        assert_eq!(answer.verb, VERB_ABSTAIN, "stage {stage}");
        let seen = *ref_hook::SEEN
            .lock()
            .expect("the reference's record")
            .last()
            .expect("the reference saw the call");
        assert_eq!(
            seen,
            ref_hook::Seen {
                point: POINT_NOTIFY,
                stage: Some(stage),
                candidates: 0,
            }
        );
    }
}

/// The point is the head's one number and the view is the one blob: at POINT_ROUTE the reference answers the
/// candidates in the order the view listed them, and the adapter returns that order unchanged.
#[test]
fn hook_route_hands_over_the_candidates_in_view_order() {
    let h = Harness::admit(&ref_hook::PLUGIN, FakeNeeds::new()).expect("the reference is admitted");
    let port = h.open_hook("hook", b"{}").expect("opens");
    let rec = |index| CandidateRec {
        index,
        flags: 0,
        context_max: 0,
        cost_per_mtok_micros: 0,
        latency_ms: 0,
        budget_remaining_micros: 0,
        error_rate_ppm: 0,
        breaker: 0,
        rate_headroom_ppm: 0,
        _r: 0,
        weight: 1,
        available_concurrency: 1,
    };
    let candidate = |index, model| CandidateIn {
        rec: rec(index),
        model,
        provider: "p",
        tier: None,
        tags: &[],
        cost_terms: &[],
    };
    let candidates = [candidate(0, "m0"), candidate(1, "m1"), candidate(2, "m2")];
    let answer =
        settle(&h, port.on(cx(), POINT_ROUTE, &view(&[], &candidates))).expect("a verdict");
    assert_eq!(answer.verb, VERB_PREFER);
    assert_eq!(answer.order, [0, 1, 2]);
    let seen = *ref_hook::SEEN
        .lock()
        .expect("the reference's record")
        .last()
        .expect("the reference saw the call");
    assert_eq!(seen.point, POINT_ROUTE);
    assert_eq!(seen.candidates, 3);
}

// ---------------------------------------------------------------------------------------------------------
// auth 4.0
// ---------------------------------------------------------------------------------------------------------

/// RFC 4231 test case 2: HMAC-SHA256 under the key `Jefe` of `what do ya want for nothing?`.
const RFC4231_CASE_2: &[u8] = b"5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";
/// The reference's config for that key.
const JEFE: &[u8] = br#"{"key":"Jefe","subject":"reference-caller"}"#;
/// The message, cut where the reference's two parts meet: the id header's value, then the body.
const ID: &[u8] = b"what do ya want ";
const BODY: &[u8] = b"for nothing?";

fn request<'a>(headers: &'a [Pair<'a>], body: &'a [u8]) -> AuthIn<'a> {
    AuthIn {
        method: "POST",
        path: "/hook",
        query: "",
        authority: "example",
        headers,
        peer: "",
        tls_peer_cert: &[],
        body,
        now_s: 1000,
    }
}

/// E.4 with E.1: the host's HMAC over parts is the MAC of the parts' concatenation (a published known answer),
/// the body arrives in the body blob because the image declared FB_NEEDS_BODY, and the header list is the
/// pair list. One wrong byte in either part, or a signature that is no 64-digit hex, is BAD_CREDENTIAL; no
/// credential header is NOT_MINE.
#[test]
fn auth_the_hmac_over_parts_is_the_mac_of_the_concatenation() {
    let signed = [
        header(ref_auth::ID_HEADER, ID),
        header(ref_auth::SIGNATURE_HEADER, RFC4231_CASE_2),
    ];
    let other_id = [
        header(ref_auth::ID_HEADER, b"what do ya want"),
        header(ref_auth::SIGNATURE_HEADER, RFC4231_CASE_2),
    ];
    let not_hex = [
        header(ref_auth::ID_HEADER, ID),
        header(
            ref_auth::SIGNATURE_HEADER,
            b"5BDCC146BF60754E6A042426089575C75A003F089D2739839DEC58B964EC3843",
        ),
    ];
    let no_credential = [header(ref_auth::ID_HEADER, ID)];
    let cases = [
        AuthCase {
            req: request(&signed, BODY),
            expect: Expect::Subject("reference-caller"),
        },
        // The same parts cut elsewhere are the same message: the id and the body are concatenated, no separator.
        AuthCase {
            req: request(&other_id, b" for nothing?"),
            expect: Expect::Subject("reference-caller"),
        },
        AuthCase {
            req: request(&signed, b"for nothing!"),
            expect: Expect::Rejected(BAD_CREDENTIAL),
        },
        AuthCase {
            req: request(&signed, b""),
            expect: Expect::Rejected(BAD_CREDENTIAL),
        },
        AuthCase {
            req: request(&not_hex, BODY),
            expect: Expect::Rejected(BAD_CREDENTIAL),
        },
        AuthCase {
            req: request(&no_credential, BODY),
            expect: Expect::NotMine,
        },
    ];
    suites::auth(ref_auth::PLUGIN.plugin(), JEFE, FakeNeeds::new(), &cases);
}

// ---------------------------------------------------------------------------------------------------------
// store 4.0
// ---------------------------------------------------------------------------------------------------------

/// The store contract changes for a plugin only in how `migrate_admit` is reached (store service 1) and in the
/// call shape under `read`, `scan`, `commit` and `clock`; nothing a store author writes moves. The whole store
/// suite on the in-tree store image is therefore the boundary test: every method crosses by the one call
/// shape, through the engine's store adapter, against the suite's own model of the answers.
#[test]
fn store_the_suite_passes_over_the_in_tree_store() {
    suites::store(min3_store::inline::PLUGIN.plugin(), b"{}", FakeNeeds::new());
}
