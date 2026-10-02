// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MOUNT TESTS (behind `runtime`): the voice plane's data-route mount is STRUCTURAL — the four routes
//! MOUNT, the claim + admission BIND the plane's RFC 8707 audience from `public_url`, and a route's
//! arrival runs the governed session-open through `run_gauntlet_session` (verify-before-charge). No
//! live provider is called: a clean open answers `501`
//! (governed, but the live serving leg is the deployment's to compose).

use super::{
    voice_admission, voice_build, voice_claims, voice_hydrate, voice_routes, voice_start,
    MOUNT_PATH,
};
use crate::ir::codec::OpenAiRealtimeCodec;
// Test-support-only: the governed-open battery (`governed_open` + its gauntlet-open test) drives
// `open_governed` over `Ingress`; both are used ONLY under `#[cfg(feature = "test-support")]`, so gate
// the imports to keep a `runtime`-without-`test-support` build (the workspace clippy default now that
// voice ships default-on) clean.
#[cfg(feature = "test-support")]
use super::Ingress;
#[cfg(feature = "test-support")]
use crate::mount::open_governed;
use crate::runtime::scope::rehydrate_sessions;
use crate::runtime::{EchoToolExecutor, SessionHandle, VoiceRuntime};
use crate::topology::telephony::{begin_telephony, g711_config};
use busbar_contract::abi::mechanism::route::{RouteAuth, RouteMethod};
use busbar_contract::records::{
    PlaneRecord, PlaneRecordRef, PlaneSelector, RecordStoreError, RecordStoreResult,
};
use busbar_kernel::plane::handle_engine::DurableHandleEngine;
use busbar_kernel::plane::registry::{BuildCtx, CardIssuer, PlaneBootCtx, RestoredSummary};
use busbar_kernel::plane::store::PlaneStore;
use busbar_kernel::plane_host::EngineHost;
use futures::channel::mpsc::unbounded;
use futures::StreamExt;
use std::sync::{Arc, Mutex};

const PUBLIC_URL: &str = "https://gw.example.com";

/// A minimal in-memory [`PlaneStore`] — the durable sink stand-in a boot rehydrate reads back. Only the
/// row upsert + `All` list are backed; the rest are the neutral no-ops a session restore never reaches.
/// A store built [`MemStore::down`] refuses every row upsert, so a session's durable open fails.
#[derive(Default)]
pub(super) struct MemStore {
    rows: Mutex<Vec<PlaneRecord>>,
    down: bool,
}

impl MemStore {
    /// A store whose every row upsert fails.
    pub(super) fn down() -> Self {
        MemStore {
            down: true,
            ..MemStore::default()
        }
    }
}

impl PlaneStore for MemStore {
    fn upsert_plane_record(&self, record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        let record = &record.to_record();
        if self.down {
            return Err(RecordStoreError("store down".to_string()));
        }
        let mut rows = self.rows.lock().unwrap();
        if let Some(existing) = rows.iter_mut().find(|r| r.id == record.id) {
            *existing = record.clone();
        } else {
            rows.push(record.clone());
        }
        Ok(())
    }
    fn get_plane_record(&self, _kind: &str, id: &str) -> RecordStoreResult<Option<Vec<u8>>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.body.clone()))
    }
    fn append_plane_record(&self, _record: PlaneRecordRef<'_>) -> RecordStoreResult<()> {
        Ok(())
    }
    fn list_plane_records(
        &self,
        _kind: &str,
        selector: &PlaneSelector,
    ) -> RecordStoreResult<Vec<Vec<u8>>> {
        match selector {
            PlaneSelector::All => Ok(self
                .rows
                .lock()
                .unwrap()
                .iter()
                .map(|r| r.body.clone())
                .collect()),
            PlaneSelector::Parent(_) => Ok(Vec::new()),
        }
    }
    fn list_plane_record_parents(&self, _kind: &str) -> RecordStoreResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn purge_plane_records_before(&self, _kind: &str, _before: u64) -> RecordStoreResult<u64> {
        Ok(0)
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> RecordStoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(true)
    }
    /// The multi-use capability check. `false` — the fail-closed direction the neutral trait
    /// defaults to — because this fixture keeps no capability rows to be live.
    fn plane_token_live(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> RecordStoreResult<bool> {
        Ok(false)
    }
}

/// A minimal [`PlaneBootCtx`] carrying only the plane-narrowed store: enough to drive the voice boot
/// hooks, which read `plane_store()` and nothing else. The methods a voice hook never calls
/// (`engine_host`, the MCP call-log surface, `card_issuer`) are inert stand-ins.
struct FakeBootCtx {
    store: Option<Arc<dyn PlaneStore>>,
}

impl PlaneBootCtx for FakeBootCtx {
    fn has_store(&self) -> bool {
        self.store.is_some()
    }
    fn register_call_stream(&self) {}
    fn restore_call_log(&self) -> Result<RestoredSummary, String> {
        Ok(RestoredSummary::default())
    }
    fn attach_durable_sinks(&self) {}
    fn plane_store(&self) -> Option<Arc<dyn PlaneStore>> {
        self.store.clone()
    }
    fn card_issuer(&self) -> Option<CardIssuer> {
        None
    }
    fn engine_host(&self) -> Arc<dyn EngineHost> {
        unimplemented!("the voice boot hooks never mint the engine host")
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Build the voice dispatch slot the way `appbuild` does — a `BuildCtx` carrying the deployment's
/// `public_url`. The other `BuildCtx` fields are the neutral absences the voice plane never reads.
fn slot_from_public_url(public_url: Option<&str>) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
    let unit = ();
    let ctx = BuildCtx {
        endpoint_slot: None,
        agent_defs: &unit,
        public_url,
        prior: None,
    };
    voice_build(&ctx)
}

/// A session runtime with no metered caller behind it — used to drive
/// `open_governed` without any provider. `model` seeds the gauntlet destination.
fn runtime_for(model: &str) -> VoiceRuntime {
    let mut rt = VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(EchoToolExecutor),
    );
    rt.session_defaults.model = Some(model.to_string());
    rt
}

#[test]
fn build_binds_the_audience_from_public_url_and_none_without() {
    // No `public_url` ⇒ no receiving side ⇒ no slot, no claim, no admission (delegation-only asymmetry).
    assert!(
        slot_from_public_url(None).is_none(),
        "no public_url ⇒ the plane fronts nothing and binds no audience"
    );

    let slot = slot_from_public_url(Some(PUBLIC_URL)).expect("a public_url ⇒ a dispatch slot");

    // The claim is the ONE audience-checked base every voice route sits under, spoken in the first
    // dialect — so `/v1/realtime/*` is audience-checked by segment-boundary match (R1's invariant).
    // K4: a SECOND claim for the Gemini Live route, under its own dialect label — the A2A precedent of
    // more than one `(path, wire)` pair per plane, so the Gemini leg's traffic is never mislabelled
    // under the OpenAI constant.
    let claims = voice_claims(slot.as_ref());
    assert_eq!(
        claims,
        vec![
            (MOUNT_PATH.to_string(), crate::OPENAI_REALTIME),
            ("/v1/realtime/gemini".to_string(), crate::GEMINI_LIVE),
        ],
        "the plane claims one audience-checked base per dialect route"
    );

    // The admission BINDS the audience derived from `public_url` — the confused-deputy defence: a token
    // minted for another resource is refused here (R2: a claim without an admission refuses boot).
    let admission =
        voice_admission(slot.as_ref()).expect("a claimed plane must admit (mounted ⇒ admitted)");
    assert_eq!(
        admission.audience,
        format!("{PUBLIC_URL}/v1/realtime"),
        "the audience is one reading of public_url + the voice resource path"
    );
    assert_eq!(
        admission.resource_metadata,
        format!("{PUBLIC_URL}/.well-known/oauth-protected-resource/v1/realtime"),
        "the refused-caller metadata URL is the same reading of public_url"
    );
}

#[test]
fn the_five_ingress_doors_mount_audience_checked_across_the_http_and_ws_seams() {
    let slot = slot_from_public_url(Some(PUBLIC_URL)).expect("a public_url ⇒ a dispatch slot");

    // The TWO one-shot HTTP doors ride the buffered-body `routes` seam: ek_ mint + SDP broker.
    let http: Vec<(String, RouteMethod, RouteAuth)> = voice_routes(slot.as_ref())
        .into_iter()
        .map(|r| (r.path, r.method, r.auth))
        .collect();
    assert_eq!(
        http,
        vec![
            (
                "/v1/realtime/client_secrets".to_string(),
                RouteMethod::Post,
                RouteAuth::Key
            ),
            (
                "/v1/realtime/calls".to_string(),
                RouteMethod::Post,
                RouteAuth::Key
            ),
            (
                "/.well-known/oauth-protected-resource/v1/realtime".to_string(),
                RouteMethod::Get,
                RouteAuth::None
            ),
        ],
        "the two one-shot HTTP doors mount, each RouteAuth::Key behind the plane's one audience"
    );

    // The TWO inbound WS-accept doors ride the neutral WS-accept seam instead (an upgrade cannot ride
    // the buffered-body adapter): sideband + telephony, SAME RouteAuth::Key under the same audience,
    // keyed to the plane's decl slot so the core mount resolves the live runtime.
    let ws: Vec<(String, RouteAuth, &'static str)> = crate::mount::voice_ws_arrivals()
        .into_iter()
        .map(|a| (a.path, a.auth, a.slot_key))
        .collect();
    assert_eq!(
        ws,
        vec![
            (
                "/v1/realtime/sideband/{call_id}".to_string(),
                RouteAuth::Key,
                crate::PLANE_DECLARATION.key
            ),
            (
                "/v1/realtime/telephony/{call_id}".to_string(),
                RouteAuth::Key,
                crate::PLANE_DECLARATION.key
            ),
            (
                "/v1/realtime/gemini/{call_id}".to_string(),
                RouteAuth::Key,
                crate::PLANE_DECLARATION.key
            ),
        ],
        "the THREE WS-accept doors declare through the neutral seam, RouteAuth::Key under the plane's key"
    );

    // No receiving side ⇒ no HTTP routes, exactly as it claims and admits nothing.
    assert!(
        voice_routes(&()).is_empty(),
        "a slot that is not a VoiceMount mounts no routes"
    );
}

/// One `GovernedOpen` over a real host double, no provider configured — the shape the route handler
/// builds. Gated on `test-support` (the host double needs a bare app).
#[cfg(feature = "test-support")]
fn governed_open<'a>(
    rt: &'a VoiceRuntime,
    host: Arc<dyn EngineHost>,
    ingress: Ingress,
    call_id: &str,
) -> crate::mount::GovernedOpen<'a> {
    crate::mount::GovernedOpen {
        rt,
        host,
        provider: None,
        ingress,
        owner: "acct".to_string(),
        call_id: call_id.to_string(),
        vkey: None,
        body: axum::body::Bytes::new(),
        headers: axum::http::HeaderMap::new(),
        now: 1,
    }
}

#[cfg(feature = "test-support")]
#[tokio::test]
async fn arrival_passes_the_gauntlet_and_opens_the_governed_session() {
    let host = crate::testkit::fixture_host::FixtureHost::new().into_host();
    // A destination proceeds PAST the open-pass gate and opens the governed session; with no provider
    // configured the one-shot mint/SDP passes answer 501 (governed, uncomposed). Only Mint/Sdp route
    // through `open_governed`; the Sideband/Telephony WS legs route through `ws_accept` (the inbound
    // WS-accept seam) — their governed open + operator-gate screening is proven by
    // `hook_gate_tests::a_reject_all_operator_gate_refuses_a_ws_accept_before_the_upgrade` and their
    // route mounting by `the_five_ingress_doors_mount_audience_checked_across_the_http_and_ws_seams`.
    let allowed = runtime_for("allowed-model");
    for ingress in [Ingress::Mint, Ingress::Sdp] {
        let opened = open_governed(governed_open(
            &allowed,
            Arc::clone(&host),
            ingress,
            "call-ok",
        ))
        .await;
        assert_eq!(
            opened.status(),
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "{ingress:?}: the governed open succeeds; the live provider/media leg is uncomposed here"
        );
    }
}

#[test]
fn hydrate_is_a_noop_under_the_ephemeral_posture_and_start_confirms_ready() {
    // No configured store (the in-process posture this mount runs): the boot rehydrate has no durable
    // working-set to restore, so it skips cleanly — exactly the first move the A2A/MCP hydrate makes.
    let ctx = FakeBootCtx { store: None };
    assert!(
        voice_hydrate(&ctx).is_ok(),
        "hydrate under no store is a clean no-op"
    );
    assert!(voice_start(&ctx).is_ok(), "start confirms readiness");
}

#[test]
fn hydrate_rehydrates_the_durable_session_working_set() {
    // Persist two sessions through an engine with the store attached as its durable sink: one left
    // ACTIVE, one driven TERMINAL. A boot rehydrate must restore the active one and count the terminal.
    let store: Arc<dyn PlaneStore> = Arc::new(MemStore::default());
    let engine = Arc::new(DurableHandleEngine::new());
    engine.set_sink(store.clone());

    let active = SessionHandle::bind(Arc::clone(&engine), "acct", "sess-active");
    active.open(10).expect("active session opens durably");

    let terminal = SessionHandle::bind(Arc::clone(&engine), "acct", "sess-terminal");
    terminal.open(10).expect("terminal session opens durably");
    terminal
        .settle_terminal(11)
        .expect("the session drives terminal");

    // A FRESH engine restores purely from the durable store — the boot path a restart takes.
    let restored = Arc::new(DurableHandleEngine::new());
    let counts = rehydrate_sessions(&restored, store.as_ref()).expect("rehydrate reads the store");
    assert_eq!(counts.active, 1, "the active session is restored");
    assert_eq!(
        counts.terminal, 1,
        "the terminal session is counted, not restored"
    );
    assert_eq!(counts.unreadable, 0, "every durable row decoded");

    // The restored active handle is readable by its owner — the durable binding survived the restart.
    let reattached = SessionHandle::bind(restored, "acct", "sess-active");
    assert_eq!(
        reattached.get().map(|r| r.id),
        Some("sess-active".to_string()),
        "the restored session reattaches by (owner, id)"
    );

    // And the hydrate HOOK drives the same restore off the boot store without error.
    assert!(
        voice_hydrate(&FakeBootCtx { store: Some(store) }).is_ok(),
        "the hydrate hook restores the durable working-set off the boot store"
    );
}

#[tokio::test]
async fn duplex_session_runs_in_process_through_the_gauntlet_after_hydrate() {
    // (1) HYDRATE first, before any listener — the ephemeral no-op gate.
    assert!(voice_hydrate(&FakeBootCtx { store: None }).is_ok());

    // (2) ARRIVAL: begin_telephony opens the session THROUGH `run_gauntlet_session` (verify strictly
    // before the kernel account's budget check). g711 carries no model, so the destination is unset and admitted.
    let rt = runtime_for("");
    let proxy = begin_telephony(
        &rt,
        OpenAiRealtimeCodec,
        "acct",
        "call-x",
        g711_config(),
        None,
        1,
    )
    .expect("the open-pass gauntlet admits and the session opens");

    // (3) HANDLER: drive the session over the neutral pump with an in-process MOCK PEER — four
    // in-memory channels stand in for the provider socket and the client socket. No live provider.
    let (prov_in_tx, prov_in_rx) = unbounded::<Vec<u8>>();
    let (prov_out_tx, mut prov_out_rx) = unbounded::<Vec<u8>>();
    let (cli_in_tx, cli_in_rx) = unbounded::<Vec<u8>>();
    let (cli_out_tx, mut cli_out_rx) = unbounded::<Vec<u8>>();

    prov_in_tx
        .unbounded_send(
            serde_json::to_vec(&serde_json::json!({
                "type":"response.output_audio.delta","delta":"AAAA"
            }))
            .unwrap(),
        )
        .unwrap();
    cli_in_tx
        .unbounded_send(
            serde_json::to_vec(&serde_json::json!({
                "type":"input_audio_buffer.append","audio":"BBBB"
            }))
            .unwrap(),
        )
        .unwrap();
    drop(prov_in_tx);
    drop(cli_in_tx);

    proxy
        .run(prov_in_rx, prov_out_tx, cli_in_rx, cli_out_tx)
        .await;

    // Downlink: the provider's audio reached the client. Uplink: the client's audio reached the provider.
    cli_out_rx.close();
    let mut downlink = Vec::new();
    while let Some(f) = cli_out_rx.next().await {
        let v: serde_json::Value = serde_json::from_slice(&f).unwrap();
        downlink.push(v["type"].as_str().unwrap().to_string());
    }
    assert!(
        downlink.contains(&"response.output_audio.delta".to_string()),
        "the governed session relayed provider downlink audio to the client: {downlink:?}"
    );

    prov_out_rx.close();
    let mut uplink = Vec::new();
    while let Some(f) = prov_out_rx.next().await {
        let v: serde_json::Value = serde_json::from_slice(&f).unwrap();
        uplink.push(v["type"].as_str().unwrap().to_string());
    }
    assert!(
        uplink.contains(&"input_audio_buffer.append".to_string()),
        "the governed session relayed client uplink audio to the provider: {uplink:?}"
    );
}

/// THE PROVIDER CREDENTIAL DOES NOT REACH THE LOG. The Gemini leg's native provider scheme carries the
/// API key in the dial URL, and the neutral dialer's URL-shaped refusal quotes the target it could not
/// use back verbatim — so the one line the failed-dial arm writes is a line the deployment's resolved
/// provider credential can ride out on. This drives the exact pair that arm composes: the URL the leg
/// builds, and the rendering of the error a `base_url` the dialer cannot parse produces.
#[test]
fn a_failed_gemini_dial_does_not_write_the_provider_key_into_the_log() {
    const KEY: &str = "AIzaSyTOPSECRETVALUE";
    // The URL the Gemini leg dials — the key rides the query, which is that dialect's native scheme.
    let url = super::provider_ws_url(
        "https://generativelanguage.googleapis.com",
        crate::GEMINI_LIVE,
        KEY,
    );
    assert!(
        url.contains(KEY),
        "the premise: the Gemini dial target really does carry the credential in its query"
    );

    // A `base_url` the neutral dialer cannot use quotes the whole target back — key and all.
    let refusal = crate::topology::DialProviderError::Dial(
        busbar_kernel::egress::duplex_ws::DialError::Url(url.clone()),
    );
    let raw = refusal.to_string();
    assert!(
        raw.contains(KEY),
        "the premise: the dialer's own refusal quotes the target verbatim, so the raw error is not \
         a thing this plane may hand to a logger"
    );

    // What the arm actually logs.
    let logged = super::redact_url_credentials(&raw);
    assert!(
        !logged.contains(KEY),
        "the logged line must not carry the provider credential; it read: {logged}"
    );
    assert!(
        logged.contains("generativelanguage.googleapis.com"),
        "and it must still name the target an operator has to fix: {logged}"
    );
}

/// #71 EXIT TEST (money-model integrity, P2-voicefix, architect ruling): a plane's DECLARED
/// BILLABLE CLASSES must be pairwise DISJOINT, because money = Σ count(class) × rate(class) only
/// holds when no class is a subset of another. The upstream `cached_tokens` figure both duplex
/// dialects report is a SUBSET of the input token classes (nested inside
/// `input_token_details`/`promptTokensDetails`, never a sibling count), so it must not appear in
/// `PLANE_DECLARATION.billable_classes` — a streams card that priced it too would double-bill the same
/// cached input. This asserts the declared list excludes it and stays pairwise distinct.
#[test]
fn billable_classes_are_pairwise_disjoint_and_exclude_cached_tokens() {
    let classes: Vec<&str> = crate::PLANE_DECLARATION
        .billable_classes
        .iter()
        .map(|c| c.class)
        .collect();
    assert!(
        !classes.contains(&"cached_tokens"),
        "cached_tokens is a subset of audio_tokens_in/text_tokens_in, not a billable class beside \
         them (#71) — declaring it would double-bill the same cached input; declared classes: \
         {classes:?}"
    );
    let mut seen = std::collections::BTreeSet::new();
    for class in &classes {
        assert!(
            seen.insert(*class),
            "declared billable classes must be pairwise disjoint (#71) — {class:?} repeats in \
             {classes:?}"
        );
    }
}

/// The presenting key the session-fee cells below open under.
#[cfg(feature = "test-support")]
fn fee_key() -> busbar_contract::records::VirtualKey {
    busbar_contract::records::VirtualKey {
        id: "vk-session-fee".to_string(),
        name: "session-fee".to_string(),
        ..Default::default()
    }
}

/// The presenting key's meter over `host`, as the governed open builds it.
#[cfg(feature = "test-support")]
fn fee_meter(host: &Arc<crate::testkit::fixture_host::FixtureHost>) -> crate::runtime::TurnMeter {
    crate::runtime::TurnMeter::new(
        Arc::clone(host) as Arc<dyn EngineHost>,
        fee_key(),
        "streaming-server",
        crate::OPENAI_REALTIME,
    )
}

/// A governed host with room on the key's chain, holding ONE KEPT SESSION: opened and served to its
/// end through the one serving loop, so its session fee is on the budget book and stays there. A
/// failed open's refund that gave back more than its own fee would eat this one.
#[cfg(feature = "test-support")]
async fn host_with_one_kept_session(
    rt: &VoiceRuntime,
) -> Arc<crate::testkit::fixture_host::FixtureHost> {
    let host = Arc::new(
        crate::testkit::fixture_host::FixtureHost::new()
            .governed()
            .with_count_cap(1_000),
    );
    let hosted = crate::runtime::build_runtime_hosted(rt, Arc::clone(&host) as Arc<dyn EngineHost>);
    let (core, handle) = crate::topology::begin_session(
        &hosted,
        OpenAiRealtimeCodec,
        "acct",
        "call-kept",
        None,
        crate::runtime::Carrier::sideband(),
        Some(fee_meter(&host)),
        1,
    )
    .expect("the kept session opens");
    crate::runtime::serve_with_sweep(core, async {}).await;
    handle.finish(1);
    assert_eq!(
        host.ledger_usage(&fee_key().id).map_or(0, |u| u.sessions),
        1,
        "the premise: the kept session's fee is on the budget book"
    );
    host
}

/// TODO 17(b) (ARCHITECT R4): `failed` opens each counted their session fee AT THE OPEN, under the
/// same dry check, and each gave it back EXACTLY ONCE through the governance refund. The metering
/// row keeps every count (the refund adjusts the budget book only, as v1.5.5's fee refund did); the
/// budget book holds the kept session's fee alone.
#[cfg(feature = "test-support")]
#[track_caller]
fn assert_each_failed_open_refunded_once(
    host: &crate::testkit::fixture_host::FixtureHost,
    failed: u64,
    what: &str,
) {
    assert_eq!(
        host.session_rows(&fee_key().id),
        1 + failed,
        "{what}: each failed open counted its session fee at the open, under the dry check"
    );
    assert_eq!(
        host.ledger_usage(&fee_key().id).map_or(0, |u| u.sessions),
        1,
        "{what}: each failed open's fee is given back exactly once, and the kept session's stays"
    );
}

/// A loopback provider that FAILS both one-shot passes: `POST /v1/realtime/client_secrets` (the mint)
/// and `POST /v1/realtime/calls` (the SDP broker) answer `500`, and each request reaching it is
/// counted in `hits`, so a cell can prove its failure came from the provider leg and not from an
/// earlier refusal.
#[cfg(feature = "test-support")]
async fn spawn_failing_provider(
    hits: Arc<std::sync::atomic::AtomicUsize>,
) -> super::ProviderEndpoint {
    async fn fail(
        axum::extract::State(hits): axum::extract::State<Arc<std::sync::atomic::AtomicUsize>>,
    ) -> axum::http::StatusCode {
        hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    }
    let app = axum::Router::new()
        .route("/v1/realtime/client_secrets", axum::routing::post(fail))
        .route("/v1/realtime/calls", axum::routing::post(fail))
        .with_state(hits);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback port");
    let addr = listener.local_addr().expect("its address");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the provider serves");
    });
    super::ProviderEndpoint {
        base_url: format!("http://{addr}"),
        api_key: "sk-test".to_string(),
    }
}

/// One governed one-shot open of `ingress` for the fee key on `host`, through `provider`.
#[cfg(feature = "test-support")]
async fn open_one_shot(
    rt: &VoiceRuntime,
    host: &Arc<crate::testkit::fixture_host::FixtureHost>,
    provider: Option<&super::ProviderEndpoint>,
    ingress: Ingress,
    call_id: &str,
) -> axum::http::StatusCode {
    let mut open = governed_open(
        rt,
        Arc::clone(host) as Arc<dyn EngineHost>,
        ingress,
        call_id,
    );
    open.provider = provider;
    open.vkey = Some(fee_key());
    open_governed(open).await.status()
}

/// A FAILED MINT REFUNDS ITS SESSION FEE EXACTLY ONCE (TODO 17(b)): the provider's mint answers `500`,
/// so the browser is handed no secret and the session never opened. RED with the fee counted at
/// `served()`: the open counted nothing to refund.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn a_failed_mint_refunds_its_session_fee_exactly_once() {
    let rt = runtime_for("allowed-model");
    let host = host_with_one_kept_session(&rt).await;
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let provider = spawn_failing_provider(Arc::clone(&hits)).await;
    let status = open_one_shot(
        &rt,
        &host,
        Some(&provider),
        Ingress::Mint,
        "call-mint-fails",
    )
    .await;
    assert_eq!(
        status,
        axum::http::StatusCode::BAD_GATEWAY,
        "the premise: the mint failed at the provider"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the premise: the open reached the provider's mint"
    );
    assert_each_failed_open_refunded_once(&host, 1, "a failed mint");
}

/// A FAILED SDP BROKER REFUNDS ITS SESSION FEE EXACTLY ONCE (TODO 17(b)): the provider answers the
/// brokered offer `500`, so no call was set up and the session never opened. The cell opens under its
/// own call id and proves the broker was reached, so the failure is the broker's and not a durable
/// refusal of a reused id. RED with the fee counted at `served()`.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn a_failed_sdp_broker_refunds_its_session_fee_exactly_once() {
    let rt = runtime_for("allowed-model");
    let host = host_with_one_kept_session(&rt).await;
    let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let provider = spawn_failing_provider(Arc::clone(&hits)).await;
    let status = open_one_shot(&rt, &host, Some(&provider), Ingress::Sdp, "call-sdp-fails").await;
    assert_eq!(
        status,
        axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        "the premise: the provider refused the brokered offer, and the answer carries its status"
    );
    assert_eq!(
        hits.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the premise: the open reached the provider's SDP broker"
    );
    assert_each_failed_open_refunded_once(&host, 1, "a failed SDP broker");
}

/// AN UNREACHABLE PROVIDER REFUNDS THE SESSION FEE ON EACH ONE-SHOT PASS (TODO 17(b)): nothing listens
/// on the discard port, so the mint and the SDP broker each fail at connect and answer `502`. Each pass
/// opens under its own call id, so neither failure is a durable refusal of a reused id. RED with the
/// fee counted at `served()`.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn an_unreachable_provider_refunds_the_session_fee_on_each_one_shot_pass() {
    let rt = runtime_for("allowed-model");
    let host = host_with_one_kept_session(&rt).await;
    let down = super::ProviderEndpoint {
        base_url: "http://127.0.0.1:9".to_string(),
        api_key: "sk-test".to_string(),
    };
    for (ingress, call) in [
        (Ingress::Mint, "call-mint-down"),
        (Ingress::Sdp, "call-sdp-down"),
    ] {
        let status = open_one_shot(&rt, &host, Some(&down), ingress, call).await;
        assert_eq!(
            status,
            axum::http::StatusCode::BAD_GATEWAY,
            "{ingress:?}: the premise: the provider leg failed at connect"
        );
    }
    assert_each_failed_open_refunded_once(&host, 2, "an unreachable provider");
}

/// AN OPEN ANSWERED `501` REFUNDS ITS SESSION FEE EXACTLY ONCE (TODO 17(b)): with no provider composed,
/// every HTTP open the governed door answers `501` serves nothing, so it is a failed open: the mint,
/// the SDP broker, the HTTP telephony open and the HTTP sideband open each give their fee back. RED
/// with the fee counted at `served()`.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn an_open_answered_501_refunds_its_session_fee_exactly_once() {
    let rt = runtime_for("allowed-model");
    let host = host_with_one_kept_session(&rt).await;
    let opens = [
        (Ingress::Mint, "call-mint-501"),
        (Ingress::Sdp, "call-sdp-501"),
        (Ingress::Telephony, "call-telephony-501"),
        (Ingress::Sideband, "call-sideband-501"),
    ];
    for (ingress, call) in opens {
        let status = open_one_shot(&rt, &host, None, ingress, call).await;
        assert_eq!(
            status,
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "{ingress:?}: the premise: the open is governed and nothing serves it"
        );
    }
    assert_each_failed_open_refunded_once(&host, 4, "an open answered 501");
}

/// A FAILED PROVIDER DIAL REFUNDS ITS SESSION FEE EXACTLY ONCE (TODO 17(b)): the WS telephony / Gemini
/// leg opens the session, then dials the provider; a failed dial settles the session through
/// [`super::settle_undialed`], the arm `ws_accept` takes, and never serves it. RED with the fee
/// counted at `served()`.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn a_failed_provider_dial_refunds_its_session_fee_exactly_once() {
    let base = runtime_for("allowed-model");
    let host = host_with_one_kept_session(&base).await;
    let rt = crate::runtime::build_runtime_hosted(&base, Arc::clone(&host) as Arc<dyn EngineHost>);
    let proxy = crate::topology::telephony::open_admitted_telephony(
        &rt,
        OpenAiRealtimeCodec,
        "acct",
        "call-dial-fails",
        g711_config(),
        Some(fee_meter(&host)),
        1,
        None,
    )
    .expect("the session opens");
    super::settle_undialed(proxy, 2);
    assert_each_failed_open_refunded_once(&host, 1, "a failed provider dial");
/// THE CHALLENGE'S POINTER RESOLVES. A refused caller is sent to the admission's resource-metadata
/// URL; the plane serves that document there, without a credential, naming the audience a token
/// must carry.
#[cfg(feature = "test-support")]
#[tokio::test]
async fn the_resource_metadata_the_challenge_points_at_is_served() {
    let slot = slot_from_public_url(Some(PUBLIC_URL)).expect("a public_url ⇒ a dispatch slot");
    let admission = crate::mount::voice_admission(slot.as_ref()).expect("a slot admits");
    let path = admission
        .resource_metadata
        .strip_prefix(PUBLIC_URL)
        .expect("the pointer is under the public URL")
        .to_string();
    let route = voice_routes(slot.as_ref())
        .into_iter()
        .find(|r| r.path == path && r.method == RouteMethod::Get)
        .expect("the pointer's path is a route the plane serves");
    assert_eq!(route.auth, RouteAuth::None, "readable without a credential");
    let host = crate::testkit::fixture_host::FixtureHost::new().into_host();
    let ctx = super::PlaneReqCtx {
        path: path.clone(),
        uri: axum::http::Uri::default(),
        method: RouteMethod::Get,
        headers: axum::http::HeaderMap::new(),
        body: bytes::Bytes::new(),
        path_params: Vec::new(),
        caller_principal: None,
        gov: None,
        principal: None,
        host,
        engine: Arc::new(()),
        slot: Arc::clone(&slot),
    };
    let resp = (route.handler)(ctx).await;
    assert_eq!(resp.status(), axum::http::StatusCode::OK);
    let body = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .expect("body")
        .to_bytes();
    let doc: serde_json::Value = serde_json::from_slice(&body).expect("json");
    assert_eq!(doc["resource"], admission.audience.as_str());
}
