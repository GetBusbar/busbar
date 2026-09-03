// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MOUNT TESTS (behind `runtime`): the voice plane's data-route mount is STRUCTURAL — the four routes
//! MOUNT, the claim + admission BIND the plane's RFC 8707 audience from `public_url`, and a route's
//! arrival runs the governed session-open through `run_gauntlet_session` (verify-before-charge). No
//! live provider is called: a denied destination is refused at the gate, a clean open answers `501`
//! (governed, but the live serving leg is the deployment's to compose).

use super::{voice_admission, voice_build, voice_claims, voice_routes, Ingress, MOUNT_PATH};
use crate::mount::open_governed;
use crate::runtime::{EchoToolExecutor, LocalMeteringPort, VoiceRuntime};
use busbar_plugin::cold::http_endpoint::{RouteAuth, RouteMethod};
use busbar_substrate::plane::handle_engine::DurableHandleEngine;
use busbar_substrate::plane::registry::BuildCtx;
use std::sync::Arc;

const PUBLIC_URL: &str = "https://gw.example.com";

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
    let claims = voice_claims(slot.as_ref());
    assert_eq!(
        claims,
        vec![(MOUNT_PATH.to_string(), crate::OPENAI_REALTIME)],
        "the plane claims exactly its one audience-checked base"
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
fn the_four_ingress_routes_mount_audience_checked() {
    let slot = slot_from_public_url(Some(PUBLIC_URL)).expect("a public_url ⇒ a dispatch slot");
    let routes = voice_routes(slot.as_ref());

    // The four ingress doors: ek_ mint + SDP broker (one-shot HTTP) and the two WS accepts.
    let mounted: Vec<(&str, &RouteMethod, &RouteAuth)> = routes
        .iter()
        .map(|r| (r.path.as_str(), &r.method, &r.auth))
        .collect();
    assert_eq!(
        mounted,
        vec![
            (
                "/v1/realtime/client_secrets",
                &RouteMethod::Post,
                &RouteAuth::Key
            ),
            ("/v1/realtime/calls", &RouteMethod::Post, &RouteAuth::Key),
            (
                "/v1/realtime/sideband/{call_id}",
                &RouteMethod::Get,
                &RouteAuth::Key
            ),
            (
                "/v1/realtime/telephony/{call_id}",
                &RouteMethod::Get,
                &RouteAuth::Key
            ),
        ],
        "all four voice ingress routes mount, each RouteAuth::Key behind the plane's one audience"
    );

    // No receiving side ⇒ no routes, exactly as it claims and admits nothing.
    assert!(
        voice_routes(&()).is_empty(),
        "a slot that is not a VoiceMount mounts no routes"
    );
}

#[test]
fn arrival_runs_run_gauntlet_session_refusing_a_denied_destination_before_charge() {
    // ARRIVAL runs `run_gauntlet_session`: a denied destination is REFUSED at the open-pass gate before
    // any lease/durable open — the governed open returns the gate's `403`, proving the gate ran. This
    // is the D3 call-site invariant at the ROUTE layer: no byte, no charge on a refused destination.
    let denied = runtime_for("blocked-model", &["blocked-model"]);
    let refused = open_governed(
        &denied,
        Ingress::Sideband,
        "acct".to_string(),
        "call-denied".to_string(),
        1,
    );
    assert_eq!(
        refused.status(),
        axum::http::StatusCode::FORBIDDEN,
        "a denied destination is refused at the gate (run_gauntlet_session ran, verify-before-charge)"
    );

    // A non-denied destination proceeds PAST the gate and opens the governed session; the live serving
    // leg is the deployment's to compose, so the structural mount answers 501 (governed, uncomposed).
    let allowed = runtime_for("allowed-model", &["blocked-model"]);
    for ingress in [
        Ingress::Mint,
        Ingress::Sdp,
        Ingress::Sideband,
        Ingress::Telephony,
    ] {
        let opened = open_governed(
            &allowed,
            ingress,
            "acct".to_string(),
            "call-ok".to_string(),
            1,
        );
        assert_eq!(
            opened.status(),
            axum::http::StatusCode::NOT_IMPLEMENTED,
            "{ingress:?}: the governed open succeeds; the live provider/media leg is uncomposed here"
        );
    }
}
