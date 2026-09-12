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
// Test-support-only: the governed-open battery (`governed_open` + its denied-destination test) drives
// `open_governed` over `Ingress`; both are used ONLY under `#[cfg(feature = "test-support")]`, so gate
// the imports to keep a `runtime`-without-`test-support` build (the workspace clippy default now that
// voice ships default-on) clean.
#[cfg(feature = "test-support")]
use super::Ingress;
#[cfg(feature = "test-support")]
use crate::mount::open_governed;
use crate::runtime::scope::rehydrate_sessions;
use crate::runtime::SessionHandle;
// The runtime a governed open is driven over is composed only by the `test-support` battery below.
#[cfg(feature = "test-support")]
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use busbar_api::{PlaneRecord, PlaneSelector, StoreResult};
use busbar_plane_streams::dialect::redact_url_credentials;
use busbar_plugin::cold::http_endpoint::{RouteAuth, RouteMethod};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane::registry::{BuildCtx, CardIssuer, PlaneBootCtx, RestoredSummary};
use busbar_substrate::plane::store::PlaneStore;
use busbar_substrate::plane_host::EngineHost;
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
    /// The multi-use capability check. `false` — the fail-closed direction the neutral trait
    /// defaults to — because this fixture keeps no capability rows to be live.
    fn plane_token_live(
        &self,
        _kind: &str,
        _token: &str,
        _expires_at: u64,
        _now: u64,
    ) -> StoreResult<bool> {
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

/// BUILD THE DISPATCH SLOT THE WAY `appbuild` DOES — the ONE `BuildCtx` this crate's cells construct,
/// so every one of them is handed a context of the same shape and a field added to the seam is added
/// here once. Its siblings under `mount` reach it rather than writing a second one.
pub(crate) fn slot_from(
    sections: &[(&'static str, &dyn std::any::Any)],
    public_url: Option<&str>,
    upstreams: Option<&dyn busbar_substrate::plane::registry::UpstreamCatalog>,
    composed: &[(&'static str, Arc<dyn std::any::Any + Send + Sync>)],
    prior: Option<&dyn busbar_substrate::plane_host::PlaneSlots>,
) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
    let ctx = BuildCtx {
        mcp_slot: None,
        sections,
        composed,
        upstreams,
        public_url,
        prior,
    };
    voice_build(&ctx)
}

/// The slot a deployment that wrote NO section gets: its own defaults, which is byte-identically what
/// it already got.
fn slot_from_public_url(public_url: Option<&str>) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
    slot_from(&[], public_url, None, &[], None)
}

/// A session runtime with no live money hop — the in-process `LocalMeteringPort` — used to drive
/// `open_governed` without any provider. `model` seeds the gauntlet destination; `deny` is the plane's
/// open-pass denial set.
#[cfg(feature = "test-support")]
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
fn the_two_one_shot_ingress_doors_mount_audience_checked_across_the_http_seam() {
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

    // The THREE inbound WS-accept doors are NOT here: an upgrade cannot ride the buffered-body
    // adapter, and they are now declared by the ROOT off `SURFACE.bindings`
    // (`crates/busbar/src/root/ws_arrival.rs::MountedStreams::arrivals`). The claim that each of the
    // three mounts RouteAuth::Key and serves a session is made by `busbar --test
    // streams_served_session`.

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
    // Mint is a live `open_governed` production ingress (the browser `ek_` pass); the three duplex WS
    // legs are served by the ROOT-mounted streams driver now, and their verify-before-charge is the
    // unit loop's own — proven at the mount by
    // `root::ws_arrival::tests::the_socket_is_bound_only_after_unit_zero_admitted`.
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
    // configured the one-shot mint/SDP passes answer 501 (governed, uncomposed). Mint/Sdp are the only
    // two that route through `open_governed` at all now: the three duplex WS legs are mounted by the
    // root, and their operator-gate screening is proven by
    // `root::ws_arrival::tests::a_reject_all_operator_gate_refuses_the_open_before_the_upgrade`, their
    // mounting by `busbar --test streams_served_session`.
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

// THE IN-PROCESS DUPLEX SESSION — the cell MOVED with the body it drove. `begin_telephony` opened
// the session through `run_gauntlet_session`; the telephony WS leg is now served by the ROOT-mounted
// streams driver, so the claim (hydrate, then a served session relays both directions through the
// gauntlet) is made by `busbar --test streams_served_session`.

// THE PROVIDER CREDENTIAL DOES NOT REACH THE LOG — the cell MOVED with the body it drove. The
// Gemini leg's dial URL was composed here by `provider_ws_url`, which died with the plane's own
// dial; the leg is now dialled by the ROOT's guarded egress, so the claim (a query-credential dial
// records a REDACTED url in the audit record) is made by
// `root::tests::session_driver::a_query_credential_dial_records_a_redacted_url`. What survives here
// is the narrow shape of the redaction itself.

/// The redaction is narrow: a `key=` that is not a query parameter is ordinary text, and a message
/// with no credential in it survives byte-identical — an error line an operator reads is not worth
/// mangling to cover a secret that was never in it.
#[test]
fn redaction_leaves_a_message_that_carries_no_query_credential_alone() {
    let plain = "connecting to the pinned address failed: connection refused";
    assert_eq!(redact_url_credentials(plain), plain);
    let worded = "the monkey=business key=";
    assert_eq!(redact_url_credentials(worded), worded);
    assert_eq!(
        redact_url_credentials("wss://h/p?key=abc&alt=sse"),
        "wss://h/p?key=<redacted>&alt=sse"
    );
}

/// A block an operator actually WROTE — the defaults with one ceiling moved, so `PlaneCfg::is_present`
/// answers `true` the way a real one does. A ceiling rather than a session field because the second
/// cell below reads it straight back off what was built.
#[cfg(feature = "test-support")]
fn a_written_streams_section() -> crate::config::StreamsCfg {
    crate::config::StreamsCfg {
        session_max_secs: 120,
        ..crate::config::StreamsCfg::default()
    }
}

/// Built from the two things the door is a function of: the OWN section handed across the seam under
/// the key this declaration carries, and the deployment's receiving origin.
#[cfg(feature = "test-support")]
fn slot_from_declaration(
    written: &crate::config::StreamsCfg,
    public_url: Option<&str>,
) -> Option<Arc<dyn std::any::Any + Send + Sync>> {
    slot_from(
        &[(crate::PLANE_DECL.config_section, written)],
        public_url,
        None,
        &[],
        None,
    )
}

/// A DECLARED `streams:` with no `public_url` is a BOOT REFUSAL, not seven silent 404s.
///
/// The shape this pins built nothing at all, so every path the operator had configured fell through to
/// the catch-all and answered 401/404 with nothing anywhere saying why. What it does instead is what
/// the composition's R2 ratchet already refuses a boot on by name, rather than a refusal of this
/// crate's invention: claimed, and no RFC 8707 audience bound. Both halves of that pair are asserted
/// here, because either one alone is a different bug.
#[cfg(feature = "test-support")]
#[test]
fn a_declared_streams_section_with_no_public_url_mounts_and_binds_no_admission() {
    let written = a_written_streams_section();

    let slot = slot_from_declaration(&written, None).expect(
        "a written `streams:` DECLARES this plane, so it mounts — the silent no-mount is the defect",
    );
    assert!(
        !voice_claims(slot.as_ref()).is_empty(),
        "the mount claims the paths it declared; a plane absent from the claim set is a plane the \
         route table never hears about, which is the 404 this cell exists to keep gone"
    );
    assert!(
        voice_admission(slot.as_ref()).is_none(),
        "and it binds no audience, because there is no receiving origin to derive one from — the \
         pair `build_dispatch` refuses a boot on rather than serving an audience-less session door"
    );

    // The two shapes either side of it are UNMOVED. No declaration and no origin is still no slot —
    // a 1.5.5-shaped config that never mentioned this plane boots exactly as it did.
    assert!(
        slot_from_public_url(None).is_none(),
        "nothing declared and nothing to front ⇒ no slot, no claim, no admission, as before"
    );
    // And an origin still binds the audience, whether or not a block was written.
    let addressed = slot_from_declaration(&written, Some(PUBLIC_URL))
        .expect("a public_url ⇒ a dispatch slot, declaration or not");
    assert!(
        voice_admission(addressed.as_ref()).is_some(),
        "an addressed mount binds its audience exactly as it always has"
    );
}

/// The posture carried is the section the ROOT parsed for THIS generation — not a copy parked in
/// process-global state and read back later. Two builds in one process, two different answers: a
/// latch would give both the same one, and the last config PARSED would win over the one being BUILT.
#[cfg(feature = "test-support")]
#[test]
fn the_slot_carries_the_section_this_generation_was_built_from() {
    let written = a_written_streams_section();
    let generation =
        slot_from_declaration(&written, Some(PUBLIC_URL)).expect("a public_url ⇒ a dispatch slot");
    let mount = generation
        .downcast_ref::<super::VoiceMount>()
        .expect("the voice dispatch slot is a VoiceMount");
    assert_eq!(
        mount.runtime.session_max_secs, written.session_max_secs,
        "the ceiling the pump enforces is the one THIS generation's section wrote"
    );

    let unwritten = slot_from_public_url(Some(PUBLIC_URL)).expect("a public_url ⇒ a dispatch slot");
    let defaults = unwritten
        .downcast_ref::<super::VoiceMount>()
        .expect("the voice dispatch slot is a VoiceMount");
    assert_eq!(
        defaults.runtime.session_max_secs,
        crate::config::StreamsCfg::default().session_max_secs,
        "and a generation built from no written section reads the plane's own defaults — which is \
         byte-identically what a deployment that writes nothing already got"
    );
}
