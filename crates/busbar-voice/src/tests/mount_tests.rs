// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MOUNT TESTS (behind `runtime`): the voice plane's data-route mount is STRUCTURAL — the four routes
//! MOUNT, the claim + admission BIND the plane's RFC 8707 audience from `public_url`, and a route's
//! arrival runs the governed session-open through `run_gauntlet_session` (verify-before-charge). No
//! live provider is called: a denied destination is refused at the gate, a clean open answers `501`
//! (governed, but the live serving leg is the deployment's to compose).

use super::{
    voice_admission, voice_build, voice_claims, voice_hydrate, voice_routes, voice_start,
    MOUNT_PATH,
};
use crate::ir::codec::OpenAiRealtimeCodec;
// Test-support-only: the governed-open battery (`governed_open` + its denied-destination test) drives
// `open_governed` over `Ingress`; both are used ONLY under `#[cfg(feature = "test-support")]`, so gate
// the imports to keep a `runtime`-without-`test-support` build (the workspace clippy default now that
// voice ships default-on) clean.
#[cfg(feature = "test-support")]
use super::Ingress;
#[cfg(feature = "test-support")]
use crate::mount::open_governed;
use crate::runtime::scope::rehydrate_sessions;
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, SessionHandle, VoiceRuntime};
use crate::topology::telephony::{begin_telephony, g711_config};
use crate::topology::SessionBudget;
use busbar_api::{PlaneRecord, PlaneSelector, StoreResult};
use busbar_plugin::cold::http_endpoint::{RouteAuth, RouteMethod};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane::registry::{BuildCtx, CardIssuer, PlaneBootCtx, RestoredSummary};
use busbar_substrate::plane::store::PlaneStore;
use busbar_substrate::plane_host::EngineHost;
use futures::channel::mpsc::unbounded;
use futures::StreamExt;
use std::sync::{Arc, Mutex};

const PUBLIC_URL: &str = "https://gw.example.com";

/// A minimal in-memory [`PlaneStore`] — the durable sink stand-in a boot rehydrate reads back. Only the
/// row upsert + `All` list are backed; the rest are the neutral no-ops a session restore never reaches.
#[derive(Default)]
struct MemStore {
    rows: Mutex<Vec<PlaneRecord>>,
}

impl PlaneStore for MemStore {
    fn upsert_plane_record(&self, record: &PlaneRecord) -> StoreResult<()> {
        let mut rows = self.rows.lock().unwrap();
        if let Some(existing) = rows.iter_mut().find(|r| r.id == record.id) {
            *existing = record.clone();
        } else {
            rows.push(record.clone());
        }
        Ok(())
    }
    fn get_plane_record(&self, _kind: &str, id: &str) -> StoreResult<Option<Vec<u8>>> {
        Ok(self
            .rows
            .lock()
            .unwrap()
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.body.clone()))
    }
    fn append_plane_record(&self, _record: &PlaneRecord) -> StoreResult<()> {
        Ok(())
    }
    fn list_plane_records(
        &self,
        _kind: &str,
        selector: &PlaneSelector,
    ) -> StoreResult<Vec<Vec<u8>>> {
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
    fn list_plane_record_parents(&self, _kind: &str) -> StoreResult<Vec<String>> {
        Ok(Vec::new())
    }
    fn purge_plane_records_before(&self, _kind: &str, _before: u64) -> StoreResult<u64> {
        Ok(0)
    }
    fn delete_plane_record(&self, _kind: &str, _id: &str) -> StoreResult<()> {
        Ok(())
    }
    fn redeem_plane_token(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> StoreResult<bool> {
        Ok(true)
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
    fn attach_mcp_durable_sinks(&self) {}
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
        mcp_slot: None,
        agent_defs: &unit,
        public_url,
        prior: None,
    };
    voice_build(&ctx)
}

/// A session runtime with no live money hop — the in-process `LocalMeteringPort` — used to drive
/// `open_governed` without any provider. `model` seeds the gauntlet destination; `deny` is the plane's
/// open-pass denial set.
fn runtime_for(model: &str, deny: &[&str]) -> VoiceRuntime {
    let mut rt = VoiceRuntime::new(
        Arc::new(DurableHandleEngine::new()),
        Arc::new(LocalMeteringPort),
        Arc::new(EchoToolExecutor),
    )
    .with_denied_destinations(deny.iter().copied());
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
                crate::PLANE_DECL.key
            ),
            (
                "/v1/realtime/telephony/{call_id}".to_string(),
                RouteAuth::Key,
                crate::PLANE_DECL.key
            ),
            (
                "/v1/realtime/gemini/{call_id}".to_string(),
                RouteAuth::Key,
                crate::PLANE_DECL.key
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
async fn arrival_runs_run_gauntlet_session_refusing_a_denied_destination_before_charge() {
    // ARRIVAL runs `run_gauntlet_session`: a denied destination is REFUSED at the open-pass gate before
    // any lease/durable open — the governed open returns the gate's `403`, proving the gate ran. This
    // is the D3 call-site invariant at the ROUTE layer: no byte, no charge on a refused destination.
    let host = busbar_substrate::testkit::fixture_host::FixtureHost::new().into_host();
    let denied = runtime_for("blocked-model", &["blocked-model"]);
    // Mint is a live `open_governed` production ingress (the browser `ek_` pass); the Sideband/Telephony
    // WS legs prove the same verify-before-charge through `ws_accept`'s destination gauntlet + the
    // substrate `accept_gauntlet_refuse_returns_refusal_and_spawns_zero_socket_tasks` witness.
    let refused = open_governed(governed_open(
        &denied,
        Arc::clone(&host),
        Ingress::Mint,
        "call-denied",
    ))
    .await;
    assert_eq!(
        refused.status(),
        axum::http::StatusCode::FORBIDDEN,
        "a denied destination is refused at the gate (run_gauntlet_session ran, verify-before-charge)"
    );

    // A non-denied destination proceeds PAST the gate and opens the governed session; with no provider
    // configured the one-shot mint/SDP passes answer 501 (governed, uncomposed). Only Mint/Sdp route
    // through `open_governed`; the Sideband/Telephony WS legs route through `ws_accept` (the inbound
    // WS-accept seam) — their governed open + operator-gate screening is proven by
    // `hook_gate_tests::a_reject_all_operator_gate_refuses_a_ws_accept_before_the_upgrade` and their
    // route mounting by `the_five_ingress_doors_mount_audience_checked_across_the_http_and_ws_seams`.
    let allowed = runtime_for("allowed-model", &["blocked-model"]);
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
    // before the D2 lease reserve). g711 carries no model, so the destination is unset and admitted.
    let rt = runtime_for("", &[]);
    let budget = SessionBudget {
        estimate_nanos: 1_000,
        fee_nanos: 0,
        cap_nanos: None,
    };
    let proxy = begin_telephony(
        &rt,
        OpenAiRealtimeCodec,
        "acct",
        "call-x",
        g711_config(),
        budget,
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
