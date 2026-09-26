// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THIS PLANE'S SERVED-LEG WITNESSES — a live session opened at the plane's served door, through
//! whatever session runner the host has registered for this plane's capability key, each witness
//! asserting ONE capability or ONE loop step on what came out.
//!
//! ## Why they live here and run elsewhere
//!
//! In a deployment a session is opened by the composition root's kernel-loop session rider: the root
//! registers it under [`crate::PLANE_KEY`] at boot, and every governed open (`begin_session`, the
//! choke point every served door funnels through) asks `run_gauntlet_session`, which hands the open to
//! it. That rider lives in the binary crate, which this crate cannot link, so in THIS crate's own test
//! binary the same open runs `run_gauntlet_session`'s inline fallback. The witnesses are therefore
//! compiled under `test-support` and exported through [`crate::testkit::SERVED`]: the binary crate's
//! test build links this crate, installs its real rider, runs every witness, and checks that this
//! plane's session opens actually ran inside the loop the number of times the witness says they
//! should. The composition root names no plane to do it — it reads the table its build script
//! generated from the manifest.
//!
//! ## What the session leg is, and what it is not
//!
//! The rider carries a session's OPEN: the plane's verify and the door, before any account, durable
//! row or socket exists. Everything after it — the turns, their counts on the kernel's session
//! account, the audit row, the durable chain, the provider dial — is the plane's own served session
//! over the live host (OWNER RULING Q21b: a served session is metered by the kernel's session account,
//! per turn). So each witness opens its session at the served door and then drives the part of that
//! session its capability lives in.
//!
//! ## What a witness returns
//!
//! The number of session opens it expects the served path to have carried through the rider: every
//! open the door handed to the governed open. A caller the door refuses before it (a key with no
//! session grant) is not an open and is not counted — which is exactly what the caller checks.
//!
//! They drive the same host double and the same door the plane's own batteries drive
//! (`FixtureHost`, `open_governed`, `begin_session`), so the served witnesses and the plane's tests
//! cannot drift onto two deployments.

use crate::ir::codec::{OpenAiRealtimeCodec, WireEvent};
use crate::ir::config::SessionConfig;
use crate::mount::{open_governed, GovernedOpen, Ingress};
use crate::runtime::{Carrier, SessionCore, TurnMeter, VoiceRuntime};
use crate::testkit::fixture_host::FixtureHost;
use crate::topology::telephony::{begin_telephony, g711_config};
use crate::topology::{begin_session, dial_provider, stream_breaker_key, DialProviderError};
use futures::channel::mpsc::unbounded;
use futures::StreamExt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// One served-leg witness: drive the served path, assert, and return the number of session opens the
/// served path must have carried through this plane's registered session runner.
pub type Witness = fn() -> Pin<Box<dyn Future<Output = u64>>>;

/// THE WITNESS TABLE, keyed by the loop step (`qa/teller-steps.json`) or the core capability
/// (`qa/capability-equality.json`) each one proves on the served path. The `session-*` keys are the
/// session plane's own shape of a step or capability whose one-shot witness asks something a session
/// does not do: its caller is attributed rather than re-authenticated per call, its verify admits the
/// destination the session is then metered under, its route is the two-way relay a turn rides, it
/// meters per turn and per declared class, and what it reports is the session it opened.
pub(crate) const WITNESSES: &[(&str, Witness)] = &[
    ("arrival", || {
        Box::pin(each_served_open_is_one_unit_reported_once())
    }),
    ("decode", || {
        Box::pin(a_frame_the_plane_cannot_read_is_carried_nowhere())
    }),
    ("session-authenticate", || {
        Box::pin(the_session_answers_for_the_key_the_door_resolved())
    }),
    ("session-verify", || {
        Box::pin(the_destination_the_gate_judged_is_the_one_metered())
    }),
    ("approve", || {
        Box::pin(a_key_granted_no_session_never_reaches_the_gate())
    }),
    ("admit", || {
        Box::pin(a_dry_key_is_refused_at_the_open_past_the_gate())
    }),
    ("session-route", || {
        Box::pin(a_served_session_relays_both_directions())
    }),
    ("session-meter", || {
        Box::pin(a_served_turn_is_ledgered_per_declared_class())
    }),
    ("audit", || Box::pin(a_served_open_lands_one_audit_row())),
    ("exit", || {
        Box::pin(a_served_session_ends_once_and_settles_its_open_turn())
    }),
    ("audit-chain", || {
        Box::pin(the_served_sessions_row_seals_at_genesis_and_reads_back())
    }),
    ("governance-budget", || {
        Box::pin(a_served_session_is_charged_to_the_presenting_key_and_closed_dry())
    }),
    ("session-metrics", || {
        Box::pin(a_served_open_is_reported_under_the_planes_own_labels())
    }),
    ("breaker-fastfail", || {
        Box::pin(a_served_sessions_dial_fast_fails_on_a_tripped_cell())
    }),
];

// ── FIXTURES ────────────────────────────────────────────────────────────────────────────────────

/// The pool a voice session is served on — the value a `session` grant names.
const VOICE_POOL: &str = "voice-server";

/// The model a witness session targets, and so the ledger lane its turns land under.
const MODEL: &str = "witness-realtime";

/// The plane's own per-generation runtime (its build hook over no `streams:` section), bound to `host`
/// the way every served door binds it.
fn hosted(host: &Arc<FixtureHost>) -> VoiceRuntime {
    let base = crate::runtime::build_runtime(&(), None)
        .downcast::<VoiceRuntime>()
        .expect("the plane's build hook builds its own runtime");
    crate::runtime::build_runtime_hosted(&base, host.clone())
}

/// A caller whose key holds no scope list — granted every kind, a voice session included.
fn caller(id: &str) -> busbar_contract::records::VirtualKey {
    busbar_contract::records::VirtualKey {
        id: id.to_string(),
        name: id.to_string(),
        ..Default::default()
    }
}

/// One open at the served door, over `host`, as `vkey` (or ungoverned).
fn served_open<'a>(
    rt: &'a VoiceRuntime,
    host: &Arc<FixtureHost>,
    call_id: &str,
    vkey: Option<busbar_contract::records::VirtualKey>,
) -> GovernedOpen<'a> {
    GovernedOpen {
        rt,
        host: host.clone(),
        provider: None,
        ingress: Ingress::Sideband,
        owner: "acct-witness".to_string(),
        call_id: call_id.to_string(),
        vkey,
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        now: 1,
    }
}

/// The governed open the served door runs, keeping the session core and its durable handle so the
/// witness can drive the session the door opened. `key` is the caller the door resolved (the turn
/// meter is that key's), or `None` for an ungoverned caller.
fn open_session(
    rt: &VoiceRuntime,
    host: &Arc<FixtureHost>,
    call_id: &str,
    key: Option<&busbar_contract::records::VirtualKey>,
) -> (
    Arc<SessionCore<OpenAiRealtimeCodec>>,
    crate::runtime::SessionHandle,
) {
    let meter =
        key.map(|k| TurnMeter::new(host.clone(), k.clone(), VOICE_POOL, crate::OPENAI_REALTIME));
    begin_session(
        rt,
        OpenAiRealtimeCodec,
        "acct-witness",
        call_id,
        Some(SessionConfig {
            model: Some(MODEL.to_string()),
            ..SessionConfig::default()
        }),
        Carrier::sideband(),
        meter,
        1,
    )
    .unwrap_or_else(|e| panic!("the served door opens the session: {e}"))
}

/// One OpenAI Realtime wire frame.
fn frame(json: serde_json::Value) -> WireEvent {
    WireEvent(bytes::Bytes::from(
        serde_json::to_vec(&json).expect("a frame serializes"),
    ))
}

/// The upstream's usage report closing one turn: `a_in`/`t_in` audio/text in, `a_out`/`t_out` out.
fn usage(a_in: u64, t_in: u64, a_out: u64, t_out: u64) -> WireEvent {
    frame(serde_json::json!({
        "type": "response.done",
        "response": { "usage": {
            "input_token_details": { "audio_tokens": a_in, "text_tokens": t_in },
            "output_token_details": { "audio_tokens": a_out, "text_tokens": t_out },
        }},
    }))
}

/// The upstream frames a plan writes, as one string.
fn upstream_text(plan: &crate::runtime::Outbound) -> String {
    plan.upstream
        .iter()
        .map(|w| String::from_utf8_lossy(&w.0).to_string())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The ledger lane a witness session's turns land under: this plane's key, the separator, the model.
fn lane() -> String {
    format!("voice\u{1f}{MODEL}")
}

/// What `key` has ledgered under the witness lane for `class`, or `None`.
fn ledgered(host: &FixtureHost, key: &str, class: &str) -> Option<u64> {
    host.ledger_rows(key)
        .get(&(lane(), class.to_string()))
        .copied()
}

// ── THE WITNESSES ───────────────────────────────────────────────────────────────────────────────

/// ARRIVAL: each call at the served door is one unit, and each is reported once.
async fn each_served_open_is_one_unit_reported_once() -> u64 {
    let host = Arc::new(FixtureHost::new());
    let rt = hosted(&host);
    for call in ["call-arrival-1", "call-arrival-2"] {
        let resp = open_governed(served_open(&rt, &host, call, None)).await;
        assert_eq!(
            resp.status(),
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "{call}: the served open succeeds; the provider leg is uncomposed here"
        );
    }
    assert_eq!(
        host.finished_requests().len(),
        2,
        "two calls at the door are two units, each reported exactly once"
    );
    2
}

/// DECODE: the plane reads what a served session's client sends, and a frame it cannot read is
/// carried to no upstream at all.
async fn a_frame_the_plane_cannot_read_is_carried_nowhere() -> u64 {
    let host = Arc::new(FixtureHost::new());
    let rt = hosted(&host);
    let (core, _handle) = open_session(&rt, &host, "call-decode", None);

    let read = core.on_client_frame(frame(serde_json::json!({
        "type": "input_audio_buffer.append", "audio": "AAAA"
    })));
    assert!(
        upstream_text(&read).contains("input_audio_buffer.append"),
        "a client event the plane reads is carried to the upstream: {}",
        upstream_text(&read)
    );

    let unread = core.on_client_frame(WireEvent(bytes::Bytes::from_static(b"not a frame {")));
    assert!(
        unread.upstream.is_empty(),
        "a frame the plane cannot read reaches the upstream on no wire: {}",
        upstream_text(&unread)
    );
    1
}

/// AUTHENTICATE: the session answers for the key the door resolved and for nobody else — its turns
/// land on that key's own ledger, and a caller the door resolved no key for is attributed nothing.
async fn the_session_answers_for_the_key_the_door_resolved() -> u64 {
    let host = Arc::new(FixtureHost::new().governed());
    let rt = hosted(&host);
    let presenting = caller("vk-presenting");

    let (keyed, _h1) = open_session(&rt, &host, "call-auth-keyed", Some(&presenting));
    let _ = keyed.on_server_frame(usage(0, 0, 7, 0)).await;
    assert_eq!(
        ledgered(&host, "vk-presenting", "audio_tokens_out"),
        Some(7),
        "the turn lands on the key the door resolved"
    );

    let (anonymous, _h2) = open_session(&rt, &host, "call-auth-anon", None);
    let _ = anonymous.on_server_frame(usage(0, 0, 9, 0)).await;
    assert_eq!(
        ledgered(&host, "vk-presenting", "audio_tokens_out"),
        Some(7),
        "a session the door resolved no key for is attributed to nobody, the presenting key included"
    );
    assert!(
        host.ledger_usage("").is_none() && host.ledger_usage("anonymous").is_none(),
        "and no anonymous principal is invented to carry it"
    );
    2
}

/// VERIFY (the session plane's shape): the destination the open-pass gate admitted is the destination
/// the session is metered under — the gate and the ledger read one model.
async fn the_destination_the_gate_judged_is_the_one_metered() -> u64 {
    let host = Arc::new(FixtureHost::new().governed());
    let rt = hosted(&host);
    let key = caller("vk-verify");
    let (core, _handle) = open_session(&rt, &host, "call-verify", Some(&key));
    let _ = core.on_server_frame(usage(0, 0, 5, 0)).await;
    let rows = host.ledger_rows("vk-verify");
    assert_eq!(
        rows.keys()
            .map(|(lane, _)| lane.as_str())
            .collect::<Vec<_>>(),
        vec![lane().as_str()],
        "every count lands under the lane of the one destination the gate judged: {rows:?}"
    );
    1
}

/// APPROVE: a key valid for the door but granted no session scope is refused before the gate; a
/// granted key reaches it.
async fn a_key_granted_no_session_never_reaches_the_gate() -> u64 {
    let host = Arc::new(FixtureHost::new());
    let rt = hosted(&host);
    let ungranted = busbar_contract::records::VirtualKey {
        allowed_scopes: Some(vec![busbar_contract::records::ScopeRef::pool("fast")]),
        ..caller("vk-no-session")
    };
    let refused = open_governed(served_open(&rt, &host, "call-approve-no", Some(ungranted))).await;
    assert_eq!(
        refused.status(),
        axum::http::StatusCode::FORBIDDEN,
        "a key holding no session scope is refused with the plane's own answer"
    );
    assert!(host.audit_log().is_empty(), "and nothing was opened for it");

    let granted = busbar_contract::records::VirtualKey {
        allowed_scopes: Some(vec![busbar_contract::records::ScopeRef {
            kind: "session".to_string(),
            value: VOICE_POOL.to_string(),
        }]),
        ..caller("vk-session")
    };
    let opened = open_governed(served_open(&rt, &host, "call-approve-yes", Some(granted))).await;
    assert_eq!(
        opened.status(),
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "a key granted the session reaches the governed open"
    );
    1
}

/// ADMIT: a caller whose chain already reads dry is refused at the open — after the gate, and before
/// any durable row or account exists — while a caller with room opens.
async fn a_dry_key_is_refused_at_the_open_past_the_gate() -> u64 {
    let host = Arc::new(FixtureHost::new().governed().with_count_cap(10));
    let rt = hosted(&host);

    // Spend the key's chain dry on a first session.
    let key = caller("vk-admit");
    let (core, _handle) = open_session(&rt, &host, "call-admit-spend", Some(&key));
    let plan = core.on_server_frame(usage(0, 0, 12, 0)).await;
    assert!(
        plan.close,
        "the turn that dried the chain closes its carrier"
    );

    let refused = open_governed(served_open(&rt, &host, "call-admit-dry", Some(key))).await;
    assert_eq!(
        refused.status(),
        axum::http::StatusCode::PAYMENT_REQUIRED,
        "a dry key is refused at the open"
    );
    let rows_before = host.audit_log().len();
    let room = open_governed(served_open(
        &rt,
        &host,
        "call-admit-room",
        Some(caller("vk-room")),
    ))
    .await;
    assert_eq!(
        room.status(),
        axum::http::StatusCode::NOT_IMPLEMENTED,
        "a key with room opens"
    );
    assert_eq!(
        host.audit_log().len(),
        rows_before + 1,
        "only the open that was admitted wrote a row"
    );
    3
}

/// ROUTE (the session plane's shape): a served session relays the provider's audio down to the client
/// and the client's audio up to the provider.
async fn a_served_session_relays_both_directions() -> u64 {
    let host = Arc::new(FixtureHost::new());
    let rt = hosted(&host);
    let proxy = begin_telephony(
        &rt,
        OpenAiRealtimeCodec,
        "acct-witness",
        "call-route",
        g711_config(),
        None,
        1,
    )
    .unwrap_or_else(|e| panic!("the served door opens the telephony session: {e}"));

    let (prov_in_tx, prov_in_rx) = unbounded::<Vec<u8>>();
    let (prov_out_tx, mut prov_out_rx) = unbounded::<Vec<u8>>();
    let (cli_in_tx, cli_in_rx) = unbounded::<Vec<u8>>();
    let (cli_out_tx, mut cli_out_rx) = unbounded::<Vec<u8>>();
    prov_in_tx
        .unbounded_send(
            serde_json::to_vec(&serde_json::json!({
                "type": "response.output_audio.delta", "delta": "AAAA"
            }))
            .expect("serializes"),
        )
        .expect("queued");
    cli_in_tx
        .unbounded_send(
            serde_json::to_vec(&serde_json::json!({
                "type": "input_audio_buffer.append", "audio": "BBBB"
            }))
            .expect("serializes"),
        )
        .expect("queued");
    drop(prov_in_tx);
    drop(cli_in_tx);
    proxy
        .run(prov_in_rx, prov_out_tx, cli_in_rx, cli_out_tx)
        .await;

    let kinds = |frames: Vec<Vec<u8>>| -> Vec<String> {
        frames
            .iter()
            .filter_map(|f| serde_json::from_slice::<serde_json::Value>(f).ok())
            .filter_map(|v| v["type"].as_str().map(str::to_string))
            .collect()
    };
    cli_out_rx.close();
    let down = kinds(cli_out_rx.by_ref().collect().await);
    prov_out_rx.close();
    let up = kinds(prov_out_rx.by_ref().collect().await);
    assert!(
        down.contains(&"response.output_audio.delta".to_string()),
        "the provider's audio reached the client: {down:?}"
    );
    assert!(
        up.contains(&"input_audio_buffer.append".to_string()),
        "the client's audio reached the provider: {up:?}"
    );
    1
}

/// METER: one served turn is ledgered on the presenting key per class the plane declares, the two
/// text halves on their own classes rather than summed.
async fn a_served_turn_is_ledgered_per_declared_class() -> u64 {
    let host = Arc::new(FixtureHost::new().governed());
    let rt = hosted(&host);
    let key = caller("vk-meter");
    let (core, _handle) = open_session(&rt, &host, "call-meter", Some(&key));
    let _ = core.on_server_frame(usage(10, 3, 20, 4)).await;
    for (class, count) in [
        ("audio_tokens_in", 10),
        ("text_tokens_in", 3),
        ("audio_tokens_out", 20),
        ("text_tokens_out", 4),
    ] {
        assert_eq!(
            ledgered(&host, "vk-meter", class),
            Some(count),
            "the served turn's `{class}` lands on the presenting key, exactly"
        );
    }
    1
}

/// AUDIT: a served open lands exactly one admin-audit row, naming the session and its principal.
async fn a_served_open_lands_one_audit_row() -> u64 {
    let host = Arc::new(FixtureHost::new());
    let rt = hosted(&host);
    let resp = open_governed(served_open(&rt, &host, "call-audit", None)).await;
    assert_eq!(resp.status(), axum::http::StatusCode::NOT_IMPLEMENTED);
    let log = host.audit_log();
    assert_eq!(log.len(), 1, "one served open, one row: {log:?}");
    let row = &log[0];
    assert_eq!(
        (
            row.action.as_str(),
            row.resource.as_str(),
            row.outcome.as_str(),
            row.principal.as_str()
        ),
        (
            crate::mount::SESSION_AUDIT_ACTION,
            "voice:call-audit",
            "applied",
            "acct-witness"
        ),
        "the row names the mutation, the session, its outcome and its principal"
    );
    1
}

/// EXIT: a served session ends once — the turn still open when the carrier ends is ledgered with the
/// session, and the durable row is settled and evicted.
async fn a_served_session_ends_once_and_settles_its_open_turn() -> u64 {
    let host = Arc::new(FixtureHost::new().governed());
    let rt = hosted(&host);
    let key = caller("vk-exit");
    let (core, handle) = open_session(&rt, &host, "call-exit", Some(&key));

    // Two seconds of PCM16 at 24 kHz (96 000 zero bytes, which base64 spells as 128 000 `A`s),
    // admitted uplink, with no usage report to close the turn.
    let audio = "A".repeat(128_000);
    let _ = core.on_client_frame(frame(serde_json::json!({
        "type": "input_audio_buffer.append", "audio": audio
    })));
    assert_eq!(
        ledgered(&host, "vk-exit", "audio_seconds_in"),
        None,
        "nothing is ledgered while the turn is open"
    );

    crate::runtime::serve_to_teardown(Arc::clone(&core), handle, async {}, || 9).await;
    assert_eq!(
        ledgered(&host, "vk-exit", "audio_seconds_in"),
        Some(2),
        "the turn open at the end is ledgered with the session, in the class's own seconds"
    );
    assert!(
        rt.bind_session("acct-witness", "call-exit").get().is_none(),
        "the durable row is settled and evicted: the session ended"
    );
    1
}

/// AUDIT-CHAIN: the served session's durable row seals at genesis, a turn checkpoint bumps it, and it
/// reads back to its owner and to nobody else.
async fn the_served_sessions_row_seals_at_genesis_and_reads_back() -> u64 {
    let host = Arc::new(FixtureHost::new());
    let rt = hosted(&host);
    let (_core, handle) = open_session(&rt, &host, "call-chain", None);
    let row = handle
        .get()
        .expect("the genesis row the served open sealed reads back");
    assert_eq!(
        (row.turns, row.owner.as_str()),
        (0, "acct-witness"),
        "a fresh genesis row, attributed to the session's principal"
    );
    assert_eq!(handle.bump_turn(2).expect("the owner checkpoints"), 1);
    assert_eq!(
        rt.bind_session("acct-witness", "call-chain")
            .get()
            .map(|r| r.turns),
        Some(1),
        "a reattach reads the checkpoint back off the durable chain"
    );
    assert!(
        rt.bind_session("mallory", "call-chain").get().is_none(),
        "a foreign owner reads nothing"
    );
    1
}

/// GOVERNANCE-BUDGET: a served session's turns are charged to the presenting key, the turn that dries
/// its chain closes the carrier, and that key's next open is refused.
async fn a_served_session_is_charged_to_the_presenting_key_and_closed_dry() -> u64 {
    let host = Arc::new(FixtureHost::new().governed().with_count_cap(50));
    let rt = hosted(&host);
    let key = caller("vk-budget");
    let (core, _handle) = open_session(&rt, &host, "call-budget", Some(&key));
    assert!(
        !core.on_server_frame(usage(0, 0, 30, 0)).await.close,
        "30 of 50: the session stays open"
    );
    assert!(
        core.on_server_frame(usage(0, 0, 30, 0)).await.close,
        "60 of 50: the chain is dry and the carrier closes"
    );
    assert!(core.carrier().is_closed(), "the carrier is hard-closed");
    assert_eq!(
        ledgered(&host, "vk-budget", "audio_tokens_out"),
        Some(60),
        "every delivered count is charged to the presenting key, the drying turn included"
    );
    let next = open_governed(served_open(&rt, &host, "call-budget-next", Some(key))).await;
    assert_eq!(
        next.status(),
        axum::http::StatusCode::PAYMENT_REQUIRED,
        "the dry key's next session is refused at the open"
    );
    2
}

/// METRICS: a served open is reported under the plane's own key, its dialect and its pool, with a
/// duration sample.
async fn a_served_open_is_reported_under_the_planes_own_labels() -> u64 {
    let host = Arc::new(FixtureHost::new());
    let rt = hosted(&host);
    let _ = open_governed(served_open(&rt, &host, "call-metrics", None)).await;
    let reported = host.finished_requests();
    assert_eq!(reported.len(), 1, "one served open, reported once");
    let r = &reported[0];
    assert_eq!(
        (
            r.plane.as_str(),
            r.ingress_protocol.as_str(),
            r.pool.as_str()
        ),
        (crate::PLANE_KEY, crate::OPENAI_REALTIME, VOICE_POOL),
        "the plane's key, the dialect the door speaks and the pool it serves"
    );
    assert!(
        r.seconds.is_finite() && r.seconds >= 0.0,
        "a duration sample rides the same report: {}",
        r.seconds
    );
    1
}

/// BREAKER-FASTFAIL: a served session's provider dial is refused before any socket once the
/// provider's cell has tripped, with the cell's own `Retry-After`.
async fn a_served_sessions_dial_fast_fails_on_a_tripped_cell() -> u64 {
    let host = Arc::new(FixtureHost::new());
    let rt = hosted(&host);
    let (_core, _handle) = open_session(&rt, &host, "call-breaker", None);
    let pool = stream_breaker_key("witness-provider");

    // A target busbar's own guard refuses is a definitive failure: it trips the provider's cell.
    let first = dial_provider(&*host, &pool, 0, "wss://127.0.0.1/", Default::default())
        .await
        .err();
    assert!(
        matches!(first, Some(DialProviderError::Dial(_))),
        "the guard-refused dial fails: {first:?}"
    );
    assert_ne!(
        host.breaker_state(&pool, 0),
        host.breaker_state("never-dialled", 0),
        "the provider's cell is no longer Closed"
    );

    // The next dial is refused at admission, before the guard or any socket is reached.
    match dial_provider(&*host, &pool, 0, "wss://127.0.0.1/", Default::default()).await {
        Err(DialProviderError::BreakerOpen { retry_after_secs }) => assert!(
            retry_after_secs >= 1,
            "the fast-fail carries the cell's own Retry-After"
        ),
        other => panic!(
            "a tripped cell must fast-fail before the dial, got {:?}",
            other.err()
        ),
    }
    1
}
