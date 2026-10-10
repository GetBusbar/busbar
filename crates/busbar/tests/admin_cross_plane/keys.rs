// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin service's keys-module tests that need a linked plane (moved from
//! busbar-core-admin's `src/tests/tests.rs`, assertions unchanged), with the error-surface
//! drivers they share.

use busbar_kernel::governance::{GovState, MemoryStore, NewKeySpec};
use busbar_kernel::proto::PROTO_ANTHROPIC;
use std::sync::Arc;

// ── KEYS ERROR SURFACE — BYTE-PARITY LOCK ────────────────────────────────────────────────────────
//
// The keys handlers historically spoke their OWN error vocabulary (`error_response` + `ERR_TYPE_*`,
// re-mapped onto the frozen `code` enum in a second place) while every other v1 handler spoke
// `AdminError` + `err_json`. That second vocabulary is collapsed onto the one
// taxonomy. The collapse must be INVISIBLE on the wire: this test pins the EXACT status,
// content-type and body BYTES of every keys error path, so the refactor is provably a no-op for
// clients and any future divergence between the two surfaces is a red test, not a support ticket.
//
// Regenerate deliberately with `UPDATE_KEYS_ERROR_GOLDEN=1 cargo test -p busbar
// keys_error_surface_is_byte_stable` — a diff in that file is a WIRE CHANGE on a frozen surface.

/// The governance posture a keys error case is exercised against.
#[derive(Clone, Copy, PartialEq, Eq)]
enum KeysFixture {
    /// Governance on, signing key present — the normal server.
    Signing,
    /// Governance on, NO signing key — mint and signing-key rotate have nothing to sign with.
    NoSigner,
    /// Governance off entirely — the whole keys resource is unavailable.
    Off,
}

/// One pinned keys error case: a request, and the fixture it runs against.
struct KeysErrCase {
    name: &'static str,
    fixture: KeysFixture,
    method: &'static str,
    /// Path relative to `/api/v1/admin`; `{live}` is substituted with the id of a minted key.
    path: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body: Option<&'static str>,
}

/// The committed byte-for-byte snapshot of the keys error wire.
const KEYS_ERROR_GOLDEN: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../busbar-core-admin/src/tests/keys_error_wire.json"
);

/// Terse constructor for a [`KeysErrCase`] row.
const fn c(
    name: &'static str,
    fixture: KeysFixture,
    method: &'static str,
    path: &'static str,
    headers: &'static [(&'static str, &'static str)],
    body: Option<&'static str>,
) -> KeysErrCase {
    KeysErrCase {
        name,
        fixture,
        method,
        path,
        headers,
        body,
    }
}

// ── WITNESS DRIVER FOR THE DECLARED ERROR SET ─────────────────────────────────────────────────────
//
// `contract::taxonomy::declared_errors` is what `openapi.json` documents. Under-claim (a handler
// emits a kind the declaration omits) is already fatal on the spot — the v1 router's recording layer
// panics inside whichever test triggered it. OVER-claim (the declaration lists a response no handler
// can produce) has no such moment: it needs a WITNESS. This test is the driver that produces one for
// every declared entry the rest of the suite does not already exercise, so
// `declared_error_set_has_no_over_claim` (in the json tests) can assert that every documented error
// is a real one. A declared 409 nobody can trigger is a lie in the contract; this is how it stays
// impossible to keep.

/// `declared_error_set_is_exactly_what_the_handlers_emit` requires every declared `(operation,
/// ErrKind, Cond)` to be witness-backed. Where an operation declares the SAME `ErrKind` under two or
/// more conditions, an untagged emission proves only that SOME condition fired -- so the emission
/// has to name its condition (`err_json_cond`) for the declaration to mean anything. These are the
/// declarations that do not yet.
///
/// The entry is enforced in BOTH directions, which is what makes it a ratchet rather than a
/// suppression list: nothing outside it may be unwitnessed (a NEW ambiguous declaration is rejected
/// on arrival), and every row in it must still be a live declaration AND still unwitnessed (so a row
/// cannot be left behind once its emission starts naming its condition, or its declaration is
/// deleted). The list can only shrink.
const COND_WITNESS_DEBT: &[(
    busbar_core_admin::v1::contract::taxonomy::MethodTag,
    &str,
    busbar_core_admin::v1::contract::taxonomy::ErrKind,
    busbar_core_admin::v1::contract::taxonomy::Cond,
)] = {
    use busbar_core_admin::v1::contract::taxonomy::Cond::*;
    use busbar_core_admin::v1::contract::taxonomy::ErrKind::*;
    use busbar_core_admin::v1::contract::taxonomy::MethodTag::*;
    &[
        (Delete, "/groups/{name}", Conflict, BaseDefined),
        (Delete, "/groups/{name}", Conflict, BoundKeys),
        (Delete, "/groups/{name}", Conflict, StillParent),
        (Delete, "/overlay/{section}", Validation, InvalidConfig),
        (Delete, "/overlay/{section}", Validation, MalformedIfMatch),
        (Delete, "/overlay/{section}", Validation, NoDiskBase),
        (Delete, "/overlay/{section}", Validation, UnknownSection),
        (Patch, "/groups/{name}", Validation, InvalidTree),
        (Patch, "/groups/{name}", Validation, MalformedBody),
        (Patch, "/hooks/{name}/settings", Conflict, BaseDefined),
        (Patch, "/hooks/{name}/settings", Conflict, SettingsPush),
        (Patch, "/hooks/{name}/settings", Validation, HookNoAck),
        (Patch, "/hooks/{name}/settings", Validation, MalformedBody),
        (Post, "/config/apply", Validation, InvalidConfig),
        (Post, "/config/apply", Validation, MalformedBody),
        (Post, "/config/apply", Validation, MalformedIfMatch),
        (Post, "/config/reload", Validation, InvalidConfig),
        (Post, "/config/reload", Validation, NoDiskBase),
        (Post, "/config/rollback", Validation, InvalidConfig),
        (Post, "/config/rollback", Validation, MalformedBody),
        (Post, "/groups", Validation, InvalidTree),
        (Post, "/groups", Validation, MalformedBody),
        (Post, "/hooks", Conflict, BaseDefined),
        (Post, "/hooks", Conflict, GrantChange),
        (Post, "/hooks", Validation, MalformedBody),
        (Post, "/keys", Conflict, AtKeyCap),
        (Post, "/keys", Conflict, BaseDefined),
        (Post, "/keys", Conflict, IdempotencyInFlight),
        (Post, "/keys", Validation, InvalidTree),
        (Post, "/keys", Validation, Overlong),
        (Post, "/keys/{id}/rotate", Conflict, IdempotencyInFlight),
        (Post, "/plugins", Conflict, NameCollision),
        (Post, "/plugins", Conflict, UntrustedUpload),
        (Post, "/plugins", Validation, InvalidFilename),
        (Post, "/plugins", Validation, MalformedBody),
        (Post, "/plugins", Validation, NotLoadable),
        (Post, "/plugins/rollback", Validation, InvalidFilename),
        (Post, "/plugins/rollback", Validation, MalformedBody),
        (Post, "/plugins/rollback", Validation, NoDiskBase),
        (Put, "/admin-auth", Validation, MalformedBody),
        (Put, "/admin-auth", Validation, UnknownModule),
        (Put, "/config/settings", Validation, InvalidConfig),
        (Put, "/config/settings", Validation, MalformedBody),
        (Put, "/config/settings", Validation, NoDiskBase),
        (Put, "/groups/{name}", Validation, InvalidTree),
        (Put, "/groups/{name}", Validation, MalformedBody),
        (Put, "/hooks/{name}", Conflict, BaseDefined),
        (Put, "/hooks/{name}", Conflict, GrantChange),
        (Put, "/hooks/{name}", Validation, MalformedBody),
    ]
};

/// A TEST-LINKED DOOR PLANE'S INSTANCE, opened over `settings` and published on the kernel's serve
/// table as the composition root publishes it (K-SERVE): the instance serving its stated admin
/// routes for as long as the guard lives. The door is the one whose folded row owns `section`.
struct PublishedDoor(String);

impl Drop for PublishedDoor {
    fn drop(&mut self) {
        busbar_kernel::plane_driver::serve::withdraw(&self.0);
    }
}

/// Build a `GovState` that CAN mint 1.5.0 signed-token keys: it carries a deterministic
/// `TokenSigner` (fixed key bytes + the default kid) so `POST /keys` issues a `bbk_` token instead
/// of a 409 "signed-token minting is unavailable". Every admin test that mints (directly or over
/// HTTP) builds its gov through this so the signer is always present; a read-only test could stay on
/// `GovState::new`, but giving them all a signer keeps the fixtures uniform and future-proof.
fn gov_with_signer(
    store: Arc<dyn busbar_kernel::governance::RecordStore>,
    admin_token: Option<String>,
) -> Arc<GovState> {
    Arc::new(
        GovState::new_with_signer(
            store,
            admin_token,
            Some(
                busbar_kernel::governance::signing::TokenSigner::from_secret_bytes(
                    &[9u8; 32],
                    busbar_kernel::governance::signing::DEFAULT_KID,
                ),
            ),
        )
        .unwrap(),
    )
}

/// Spin up an already-built `router` on an ephemeral local port: the listener bind, the address
/// read-back, the live `axum::serve` task, and a fresh client to hit it — the "spin up a real
/// router" preamble every v1-transport test in this file repeated inline.
async fn spin_up(
    router: axum::Router,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    reqwest::Client,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (addr, handle, reqwest::Client::new())
}

/// OWNER RULING Q25b (#42): with a rate card PRESENT, a usage read over a class the card does not
/// price answers a NAMED `409 unpriced_class` whose message names the lane and the class — on all
/// three usage reads — instead of the bare `500 internal` they answered after 789d55a78.
///
/// The card prices lane `m`'s `input` class and holds its `output` class UNPRICED (a negative
/// rate is not a rate the card can represent, item 22). One response of 700 input + 200 output
/// tokens is accrued to key `k` (bucket `k`, window total) and its group `team` (budget, total),
/// and metered into today's `/usage` bucket. Returns `(path, status, body)` for each read, and
/// is the witness the declared-error audit drives for the three `unpriced_class` declarations.
async fn drive_unpriced_usage_reads() -> Vec<(String, u16, serde_json::Value)> {
    busbar_kernel::snapshot::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let card: std::collections::BTreeMap<String, busbar_kernel::config::RateEntryCfg> =
        std::collections::BTreeMap::from([(
            "m".to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: 500.0,
                output_utok: -1.0,
                ..Default::default()
            },
        )]);
    let groups = std::collections::BTreeMap::from([(
        "team".to_string(),
        busbar_kernel::config::GroupCfg {
            enabled: true,
            limits: vec![busbar_kernel::config::groups::LimitCfg {
                metric: busbar_kernel::config::groups::LimitMetric::Budget,
                amount: 1_000_000,
                per: Some(busbar_kernel::config::groups::LimitWindow::Total),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
                admission: None,
                on_exhaustion: None,
            }],
            ..Default::default()
        },
    )]);
    let cost = busbar_kernel::cost::CostModel::resolve_parts(Some(&card), 0, &groups);
    let now = busbar_kernel::store::now();
    let (minted, _secret) = gov
        .create_key(
            NewKeySpec {
                name: "k".to_string(),
                ..Default::default()
            },
            now,
        )
        .unwrap();
    // Accrue through the group chain the way the engine does (the chain reads `key.group`).
    let mut in_team = minted.clone();
    in_team.group = Some("team".to_string());
    let units = std::collections::BTreeMap::from([
        (busbar_contract::records::UNIT_INPUT.to_string(), 700u64),
        (busbar_contract::records::UNIT_OUTPUT.to_string(), 200u64),
    ]);
    gov.record_usage(&cost, &in_team, "", "m", &units, now);
    let usage = busbar_kernel::billing::TokenUsage {
        input: 700,
        output: 200,
        ..Default::default()
    };
    gov.record_metering(&minted.id, "m", "vendor", Some(&usage), now);
    gov.flush_metering();
    let app = crate::new_test_app().governance(gov).cost(cost).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let mut out = Vec::new();
    for path in [
        format!("/api/v1/admin/keys/{}/usage", minted.id),
        "/api/v1/admin/groups/team/usage".to_string(),
        "/api/v1/admin/usage".to_string(),
    ] {
        let resp = client
            .get(format!("http://{addr}{path}"))
            .header("x-admin-token", "admintok")
            .send()
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let body: serde_json::Value = resp.json().await.unwrap_or(serde_json::Value::Null);
        out.push((path, status, body));
    }
    handle.abort();
    out
}

/// The read of [`drive_unpriced_usage_reads`] whose path starts with `prefix`, asserted: `409`, `code = unpriced_class`, and a
/// message naming the lane `m` and the class `output`.
async fn assert_unpriced_usage_read_is_named(prefix: &str) {
    let reads = drive_unpriced_usage_reads().await;
    let (path, status, body) = reads
        .iter()
        .find(|(p, _, _)| p.starts_with(prefix))
        .expect("the driver reads every usage path");
    assert_eq!(
        *status, 409,
        "{path}: an unpriced class under a present rate card is a NAMED 409 (Q25b), not a bare \
         500: {body}"
    );
    assert_eq!(body["error"]["code"], "unpriced_class", "{path}: {body}");
    let message = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("`m`") && message.contains("`output`"),
        "{path}: the refusal names the lane and the class: {body}"
    );
}

/// ARCHITECT RULING (card-epoch): `POST /config/apply` accepts EXACTLY the shape boot config
/// accepts, PLANE SECTIONS INCLUDED — no `unknown field`. A plane's fee is that plane's own reserved
/// key (#47: `<section>.fees`, lifted off the section by the 1.6.0 pre-pass), so a live fee change
/// is an apply carrying the plane section, and the applied App must price that plane at the new fee.
///
/// RED before the fix: `ApplyConfigReq` derived `Deserialize` straight onto the frozen
/// `deny_unknown_fields` `DeployCfg`, skipping the pre-pass, so the plane section was refused
/// (`400 malformed config body: unknown field ...`) while the identical document boots clean.
/// The control half: a key NO registered plane declares is still refused, so apply is exactly
/// boot's shape and not a looser one.
#[tokio::test]
async fn config_apply_accepts_a_plane_section_and_moves_that_planes_own_fee() {
    use http_body_util::BodyExt;
    busbar_kernel::snapshot::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let overlay = std::env::temp_dir().join(format!(
        "busbar-apply-plane-fee-{}-{}.json",
        std::process::id(),
        busbar_kernel::store::now()
    ));
    let _ = std::fs::remove_file(&overlay);
    let app = crate::new_test_app()
        .governance(gov)
        .overlay_path(overlay.clone())
        .build();
    // The plane the registry says owns the `tools:` section, so the test names no plane crate.
    let section = "tools";
    let plane = busbar_kernel::plane::registry::plane_decl_for_config_section(section)
        .expect("a plane is registered to own the `tools:` section");
    let fee_lane = busbar_kernel_ledger::cost::plane_fee_lane(plane.key);
    let handle = Arc::new(busbar_kernel::state::AppHandle::new(app));
    let fee =
        |h: &busbar_kernel::state::AppHandle| h.load().cost.card().plane_lane(&fee_lane).0.fee();
    assert_eq!(fee(&handle), 0, "the test App configures no plane fee");

    let apply = |config: serde_json::Value| {
        let handle = handle.clone();
        async move {
            let body = axum::body::Bytes::from(
                serde_json::json!({ "config": config, "providers": {} }).to_string(),
            );
            let resp = busbar_core_admin::test_support::apply_config(
                axum::extract::State(handle),
                axum::Extension(busbar_kernel::auth::AuthPrincipal(None)),
                axum::http::HeaderMap::new(),
                body,
            )
            .await;
            let status = resp.status().as_u16();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            (status, String::from_utf8_lossy(&bytes).into_owned())
        }
    };
    let base = || {
        serde_json::json!({
            "providers": {},
            "models": {},
            "store": {"module": "memory"}
        })
    };

    let mut with_plane = base();
    with_plane[section] = serde_json::json!({ "fees": { "per_request": 7 } });
    let (status, body) = apply(with_plane).await;
    assert_eq!(
        status, 200,
        "a document carrying a plane section (as boot accepts it) must apply: {body}"
    );
    assert_eq!(
        fee(&handle),
        7,
        "the applied App prices the plane's requests at the plane's own applied fee (#47)"
    );

    let mut unknown = base();
    unknown["no_plane_declares_this"] = serde_json::json!({});
    let (status, body) = apply(unknown).await;
    assert_eq!(
        status, 400,
        "a key no registered plane declares is still refused, as boot refuses it: {body}"
    );
    assert!(
        body.contains("unknown field"),
        "named as boot names it: {body}"
    );
    assert_eq!(fee(&handle), 7, "a refused apply changes nothing");

    let _ = std::fs::remove_file(&overlay);
}

/// `GET openapi.json` serves the PRE-GZIPPED embedded bytes to a client whose `Accept-Encoding`
/// allows gzip — `Content-Encoding: gzip`, inflating byte-identical to the identity body — and
/// the identity body to a client that does not ask. This is what lets the process retain NO
/// inflated copy of the 366 KB+ document (the old `OnceLock<String>` held it forever after the
/// first GET); the gzip client costs zero inflation, the identity client a per-request inflate.
#[tokio::test]
async fn test_admin_v1_openapi_gzip_negotiation() {
    busbar_kernel::snapshot::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, client) = spin_up(router).await;
    let url = format!("http://{addr}/api/v1/admin/openapi.json");

    // Identity: no Accept-Encoding -> plain JSON, no Content-Encoding (the shape every pre-gzip
    // client always got). This reqwest client has no gzip feature, so it sends no Accept-Encoding
    // and performs no transparent decode — the bytes observed here are the wire bytes.
    let identity = client
        .get(&url)
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(identity.status().as_u16(), 200);
    assert!(
        identity.headers().get("content-encoding").is_none(),
        "a client that did not ask for gzip must get an identity body"
    );
    let identity_body = identity.text().await.unwrap();
    assert!(
        identity_body.starts_with('{'),
        "identity body is the JSON document"
    );

    // Gzip: Accept-Encoding: gzip -> Content-Encoding: gzip, and the payload inflates to the
    // EXACT identity bytes (same committed document, lighter wire + no retained inflation).
    let gz = client
        .get(&url)
        .header("x-admin-token", "admintok")
        .header("accept-encoding", "gzip")
        .send()
        .await
        .unwrap();
    assert_eq!(gz.status().as_u16(), 200);
    assert_eq!(
        gz.headers().get("content-encoding").map(|v| v.as_bytes()),
        Some(b"gzip".as_ref()),
        "a gzip-accepting client gets the pre-compressed bytes"
    );
    let gz_body = gz.bytes().await.unwrap();
    let mut inflated = String::new();
    std::io::Read::read_to_string(
        &mut flate2::read::GzDecoder::new(gz_body.as_ref()),
        &mut inflated,
    )
    .expect("the served gzip payload inflates");
    assert_eq!(
        inflated, identity_body,
        "gzip and identity must be the SAME document, differing only in transfer encoding"
    );

    // An explicit refusal (`gzip;q=0`) is honored: identity again.
    let refused = client
        .get(&url)
        .header("x-admin-token", "admintok")
        .header("accept-encoding", "gzip;q=0")
        .send()
        .await
        .unwrap();
    assert!(
        refused.headers().get("content-encoding").is_none(),
        "gzip;q=0 is an explicit refusal — identity body"
    );

    handle.abort();
}

/// Build an UNSIGNED (structurally valid) plugin tarball in memory for the HTTP lifecycle tests.
fn admin_test_tarball(name: &str, alias: &str) -> Vec<u8> {
    admin_test_tarball_versioned(name, alias, "1.0.0")
}

/// As `admin_test_tarball`, with an explicit version so a test can build two SAME-NAME tarballs that
/// differ only in version (and thus filename) - the same-name-different-file case.
fn admin_test_tarball_versioned(name: &str, alias: &str, version: &str) -> Vec<u8> {
    let lib = format!("junk library bytes for {name} {version} (never dlopened)").into_bytes();
    let lib = lib.as_slice();
    let m = busbar_plugin_loader::sign::Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "store".into(),
        version: version.into(),
        publisher: "acme".into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .expect("store abi"),
        sha256: busbar_plugin_loader::sign::sha256_hex(lib),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
        declares: Default::default(),
        statement: None,
        former_names: Vec::new(),
    };
    busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap()
}

/// A `budget` limit for a group tree (helper to keep the test trees readable).
fn budget_limit(cents: u64) -> busbar_kernel::config::groups::LimitCfg {
    busbar_kernel::config::groups::LimitCfg {
        metric: busbar_kernel::config::groups::LimitMetric::Budget,
        amount: cents,
        per: Some(busbar_kernel::config::groups::LimitWindow::Month),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
        admission: None,
        on_exhaustion: None,
    }
}

/// The three anti-sprawl refusals, driven end-to-end. Split out of the `#[tokio::test]` so the
/// class-level drift test can run it too.
///
/// 1. **`PATCH /keys/{id}` rebind into an at-cap group**. Only its pure
///    predicate (`check_key_cap`) was tested; the HANDLER arm that turns it into a 409 had no test
///    at all, so `contract::taxonomy` never declared `Conflict/AtKeyCap` for that operation and
///    `openapi.json` documented a `409` that named only `GovernanceOff`. The under-claim guard could
///    not catch it either: it compared `ErrKind` alone, and `Conflict` WAS declared.
/// 2. **RE-ENABLE past the cap** — the same ratchet, reached through the other field. `check_key_cap` counts LIVE keys, so `disable → mint → re-enable` walks a bucket past
///    its ceiling with every single request passing the guard. Now gated by the same 409.
///
/// (1.5.2 scope collapse removed the former case 3 — the delegated-mint-must-bind 400 — since the
/// narrower `mint` scope that could reach it no longer exists; only a `full` operator mints, and the
/// operator may legitimately mint an unbound key.)
///
/// It also asserts the audit consequence: every one of these refusals writes a `rejected` row —
/// a refused mint is an attempt to issue a credential, and it must leave a trace.
async fn drive_key_cap_and_delegation_errors() {
    busbar_kernel::snapshot::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let groups = std::collections::BTreeMap::from([
        (
            "capped".to_string(),
            busbar_kernel::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
        (
            "roomy".to_string(),
            busbar_kernel::config::GroupCfg {
                limits: vec![budget_limit(1_000_000)],
                ..Default::default()
            },
        ),
    ]);
    let mut app = crate::new_test_app()
        .governance(gov)
        .groups_tree(groups)
        .build();
    {
        let inner = Arc::get_mut(&mut app).expect("sole owner");
        inner.max_keys_per_principal = 2;
    }
    let router = crate::build_router(app);
    let (addr, server, client) = spin_up(router).await;
    let keys_url = format!("http://{addr}/api/v1/admin/keys");

    let mint = |name: &'static str, group: &'static str| {
        let (c, u) = (client.clone(), keys_url.clone());
        async move {
            let r = c
                .post(&u)
                .header("x-admin-token", "admintok")
                .json(&serde_json::json!({"name": name, "group": group}))
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 201, "mint {name}/{group}");
            let b: serde_json::Value = r.json().await.unwrap();
            b["id"].as_str().unwrap().to_string()
        }
    };
    let patch = |id: String, body: serde_json::Value| {
        let (c, u) = (client.clone(), keys_url.clone());
        async move {
            c.patch(format!("{u}/{id}"))
                .header("x-admin-token", "admintok")
                .json(&body)
                .send()
                .await
                .unwrap()
        }
    };

    // Fill `capped` to its ceiling of 2, and park one key in `roomy` to rebind with.
    let cap_a = mint("a", "capped").await;
    let _cap_b = mint("b", "capped").await;
    let roamer = mint("roamer", "roomy").await;

    // ── 1. REBIND into an at-cap bucket → 409 `conflict` naming the cap ───────────────────────
    let r = patch(roamer.clone(), serde_json::json!({"group": "capped"})).await;
    assert_eq!(r.status().as_u16(), 409, "rebind into an at-cap group");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("max_keys_per_principal"),
        "the rebind 409 names the cap: {body}"
    );

    // ── 2. RE-ENABLE past the cap → the SAME 409 ──────────────────────────────────────────────
    // Disable one of `capped`'s keys: the bucket now counts 1 live, so a fresh mint is admitted.
    assert_eq!(
        patch(cap_a.clone(), serde_json::json!({"enabled": false}))
            .await
            .status()
            .as_u16(),
        200,
        "disabling is always allowed — it can only free a slot"
    );
    let _cap_c = mint("c", "capped").await;
    // …and NOW re-enabling the parked key would make 3 live keys in a bucket capped at 2.
    let r = patch(cap_a.clone(), serde_json::json!({"enabled": true})).await;
    assert_eq!(
        r.status().as_u16(),
        409,
        "re-enabling past the cap is the same admission as a rebind past the cap"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap_or("")
            .contains("max_keys_per_principal"),
        "the re-enable 409 names the cap: {body}"
    );
    // A DISABLED key can still be edited in every other way — the guard fires on admission, not on
    // touching an at-cap bucket (otherwise an at-cap bucket would freeze).
    assert_eq!(
        patch(cap_a.clone(), serde_json::json!({"enabled": false}))
            .await
            .status()
            .as_u16(),
        200,
        "a no-op disable of a key in an at-cap bucket is not an admission"
    );

    // The operator (`full`) may mint an UNBOUND key — the tree's owner is not gated (1.5.2 removed
    // the delegated-mint-must-bind refusal along with the narrower `mint` scope).
    let r = client
        .post(&keys_url)
        .header("x-admin-token", "admintok")
        .json(&serde_json::json!({"name": "unbound-by-operator"}))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        201,
        "the operator owns the tree and may still mint an unbound key"
    );

    // ── THE AUDIT CONSEQUENCE ─────────────────────────────────────────────────────────────────
    // Every refusal above wrote a `rejected` row: a refused mint is a stopped attempt to issue a
    // credential, and must leave a trace. The rows are asserted through
    // the live `GET /audit` surface, and only for EXISTENCE (the log is a process-global other
    // tests append to, so "at least one" is the only stable predicate).
    let audit_rows = |action: &'static str| {
        let (c, a) = (client.clone(), addr);
        async move {
            let r = c
                .get(format!("http://{a}/api/v1/admin/audit?action={action}"))
                .header("x-admin-token", "admintok")
                .send()
                .await
                .unwrap();
            let b: serde_json::Value = r.json().await.unwrap();
            b["items"].as_array().cloned().unwrap_or_default()
        }
    };
    // The cap refusals above are `key.patch` (rebind + re-enable); each must leave a `rejected` row.
    for action in ["key.patch"] {
        let rejected = audit_rows(action)
            .await
            .iter()
            .filter(|e| e["outcome"] == "rejected")
            .count();
        assert!(
            rejected > 0,
            "no `{action}` audit row with outcome=rejected — a refusal that leaves no trail is \
             the gap `KeyAudit` exists to make unrepresentable"
        );
    }

    server.abort();
}

/// The `#[tokio::test]` wrapper for [`drive_key_cap_and_delegation_errors`].
#[tokio::test]
async fn key_cap_and_delegation_refusals_are_reachable_declared_and_audited() {
    drive_key_cap_and_delegation_errors().await;
}

/// The unknown-section refusal keeps 1.5.5's EXACT sentence shape — "expected `a`, `b`, or `c`",
/// serial comma, `or` before the last name — with the longer list (owner ruling Q54: 1.5.5's four
/// sections plus `identity-providers` and `export`, the two named-map sections a 1.5.5-shaped config
/// serves; a configured plane's section joins the list). 1.5.5 answered "expected `groups`, `hooks`, `root`, or `plugin_versions`"; a rewording
/// onto "expected one of …" is a customer-visible change no ruling allows.
#[tokio::test]
async fn test_admin_v1_overlay_reset_unknown_section_keeps_1_5_5_sentence_shape() {
    busbar_kernel::snapshot::init();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app().governance(gov).build();
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;

    let r = reqwest::Client::new()
        .delete(format!("http://{addr}/api/v1/admin/overlay/limits"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 400);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    // This lib-test app links no plane registry, so every named-map section is served and the list
    // runs on to `tools`/`agents`; on a 1.5.5-shaped config (no plane sections) those two are not
    // sections and the list ends `…, or `export`` — the oracle cell
    // `admin.ops|DeleteOverlaySection|not-found` pins that form. The SHAPE is what this pins.
    assert_eq!(
        body["error"]["message"],
        "unknown overlay section `limits`: expected `groups`, `hooks`, `root`, \
         `plugin_versions`, `identity-providers`, `export`, `tools`, or `agents`",
        "1.5.5's sentence shape (serial comma, `or` before the last name) with the longer list"
    );

    handle.abort();
}

/// RESET a NAMED-MAP section (`DELETE /overlay/export`): every API-applied exporter definition is
/// discarded and the section reverts to base `config.yaml` truth, exactly as `groups`/`hooks`/`root`
/// already did.
///
/// `named_maps` was in NONE of `OverlaySection`'s variants, so there was no way to revert
/// API-applied identity-provider or export definitions to config.yaml at all: the endpoint answered
/// `400 unknown overlay section`. Every other durable overlay section had a revert and this one did
/// not, while the docs listed the four-value set as COMPLETE.
#[tokio::test]
async fn test_admin_v1_overlay_reset_named_map_section_reverts_to_base() {
    // `request-log-file` (K9b) and `prometheus` (K9d) are rows of the export axis, as a linked
    // build's are.
    linked_export_axis();
    let (dir, overlay, addr, handle) = named_map_app("resetnamedmap", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // An API-applied exporter, alongside the fixture's base-config `base-metrics`.
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/runtime-sink")))
        .body(
            serde_json::json!({
                "module": "request-log-file",
                "settings": {"path": dir.join("req.jsonl").to_string_lossy()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    assert!(
        busbar_kernel::config::overlay::read(&overlay)
            .expect("overlay written")
            .named_maps
            .get("export")
            .is_some_and(|e| e.contains_key("runtime-sink")),
        "the definition is in the overlay before the reset"
    );

    // RESET the section.
    let reset = admin(client.delete(format!("http://{addr}/api/v1/admin/overlay/export")))
        .send()
        .await
        .unwrap();
    assert_eq!(reset.status().as_u16(), 200, "{:?}", reset.text().await);
    let body: serde_json::Value = reset.json().await.unwrap();
    assert_eq!(body["reset"], "export");
    assert_eq!(body["changed"], true, "the reset discarded a mutation");

    // The API-applied exporter is gone; the base-config one is untouched.
    let gone = admin(client.get(format!("http://{addr}/api/v1/admin/export/runtime-sink")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        gone.status().as_u16(),
        404,
        "the API-applied definition reverted to base"
    );
    let base = admin(client.get(format!("http://{addr}/api/v1/admin/export/base-metrics")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        base.status().as_u16(),
        200,
        "a base config.yaml definition is NOT what a reset removes"
    );
    // The durable half: the section is cleared on disk, so the revert survives a restart.
    assert!(
        busbar_kernel::config::overlay::read(&overlay)
            .is_none_or(|d| !d.named_maps.contains_key("export")),
        "the overlay `export` section is cleared on disk"
    );
    // A SIBLING named-map section is untouched by another section's reset.
    let idp = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/base-idp"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(idp.status().as_u16(), 200, "sibling sections survive");

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// REFERENTIAL INTEGRITY on a BULK reset: a section reset that would leave another config site
/// naming a definition that no longer exists is refused as a terminal `conflict` NAMING both the
/// entry and its referent, and nothing changes.
///
/// This is the guard the per-entry `DELETE /identity-providers/{name}` already had, applied to the
/// bulk path. Without it a reset would be accepted, the rebuild would fail deeper down with the far
/// less actionable "references X, which is not defined", and the operator would be left guessing
/// which of the definitions they just discarded was the one still in use.
#[tokio::test]
async fn test_admin_v1_overlay_reset_named_map_refuses_a_dangling_reference() {
    let (dir, _overlay, addr, handle) = named_map_app("resetdangling", true).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    // The fixture's base `auth.admin_auth:` names `corp-ad`; this PUT is the only definition of it.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(
        serde_json::json!({
            "module": "admin-tokens",
            "token": {"file": dir.join("corp.token").to_string_lossy()}
        })
        .to_string(),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);

    let reset = admin(client.delete(format!(
        "http://{addr}/api/v1/admin/overlay/identity-providers"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        reset.status().as_u16(),
        409,
        "a reset that would dangle a reference is refused"
    );
    let body: serde_json::Value = reset.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("corp-ad") && msg.contains("auth.admin_auth"),
        "the refusal names the entry AND the referent so an operator knows what to fix: {body}"
    );

    // NOTHING changed: the definition is still live and still on disk.
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        200,
        "the refused reset changed nothing"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Serve one fixture, returning its address, the server task, and the id of a live key (empty for
/// the postures that cannot mint).
async fn serve_keys_fixture(
    fixture: KeysFixture,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>, String) {
    let store: Arc<dyn busbar_kernel::governance::RecordStore> = Arc::new(MemoryStore::new());
    let app = match fixture {
        KeysFixture::Signing => {
            let gov = gov_with_signer(store, Some("admintok".to_string()));
            crate::new_test_app().governance(gov).build()
        }
        KeysFixture::NoSigner => {
            let gov = Arc::new(GovState::new(store, Some("admintok".to_string())).unwrap());
            crate::new_test_app().governance(gov).build()
        }
        // Governance OFF: there is no governance to hold an operator token, so the fixture uses
        // the explicit `admin_auth: []` OPEN posture (the documented dev posture) to authenticate.
        // Otherwise every case would 401 in the middleware and never reach a keys handler.
        KeysFixture::Off => {
            let cfg = busbar_kernel::config::AuthCfg {
                admin_auth: Vec::new(),
                ..busbar_kernel::config::AuthCfg::default_none()
            };
            crate::new_test_app()
                .auth(Arc::new(busbar_kernel::auth::AuthMiddleware::new_builtin(
                    &cfg,
                )))
                .admin_chain(Vec::new())
                .build()
        }
    };
    let router = crate::build_router(app.clone());
    let (addr, handle, _) = spin_up(router).await;
    // A live key id for the stale-ETag cases (only mintable on the signing fixture).
    let live = if fixture == KeysFixture::Signing {
        let (key, _) = app
            .governance
            .as_ref()
            .unwrap()
            .mint_signed(
                NewKeySpec {
                    name: "live".into(),
                    allowed_pools: None,
                    group: None,
                    labels: Default::default(),
                    ..Default::default()
                },
                busbar_kernel::store::now() + 3600,
                busbar_kernel::store::now(),
            )
            .unwrap();
        key.id
    } else {
        String::new()
    };
    (addr, handle, live)
}

/// BYTE-PARITY LOCK: every keys error response — status, content-type and body
/// BYTES — is pinned. The keys surface is frozen v1; collapsing its private error vocabulary onto
/// `AdminError` + `err_json` may change how the bytes are PRODUCED, never what they ARE.
#[tokio::test]
async fn keys_error_surface_is_byte_stable() {
    drive_keys_error_surface().await;
}

/// Drive every pinned keys error path and assert the wire is byte-identical to the golden. Split
/// out of the `#[tokio::test]` so the class-level over-claim test can RUN it (and collect its
/// emissions) without depending on test ordering.
async fn drive_keys_error_surface() {
    busbar_kernel::snapshot::init();
    // A 65-character id (the cap is 64) and an id that cannot exist.
    const OVERLONG: &str = "vk_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const MISSING: &str = "vk_0000000000000000";
    // A well-formed but WRONG key ETag (16 hex chars) — the stale-If-Match guard, not the parser.
    const STALE_ETAG: &str = "\"00000000000000ff\"";
    let cases: &[KeysErrCase] = &[
        // ── GET /keys — the query string is validated at the door ─────────────────────────────
        c(
            "list_bad_cursor",
            KeysFixture::Signing,
            "GET",
            "/keys?cursor=%21%21",
            &[],
            None,
        ),
        c(
            "list_bad_enabled",
            KeysFixture::Signing,
            "GET",
            "/keys?enabled=maybe",
            &[],
            None,
        ),
        c(
            "list_bad_limit",
            KeysFixture::Signing,
            "GET",
            "/keys?limit=lots",
            &[],
            None,
        ),
        // ── POST /keys ────────────────────────────────────────────────────────────────────────
        c(
            "mint_bad_json",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some("{"),
        ),
        c(
            "mint_reserved_label",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","labels":{"key":"v"}}"#),
        ),
        c(
            "mint_both_expiry_fields",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","expires_in":"1h","expires_at":9999999999}"#),
        ),
        c(
            "mint_bad_duration",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","expires_in":"1x"}"#),
        ),
        c(
            "mint_expires_in_the_past",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","expires_at":1}"#),
        ),
        c(
            "mint_parent_without_group",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","parent":"team"}"#),
        ),
        c(
            "mint_unknown_group_no_parent",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","group":"nope"}"#),
        ),
        c(
            "mint_unknown_parent",
            KeysFixture::Signing,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k","group":"leaf","parent":"nope"}"#),
        ),
        c(
            "mint_no_signing_key",
            KeysFixture::NoSigner,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k"}"#),
        ),
        c(
            "mint_governance_off",
            KeysFixture::Off,
            "POST",
            "/keys",
            &[],
            Some(r#"{"name":"k"}"#),
        ),
        // ── GET /keys/{id} ────────────────────────────────────────────────────────────────────
        c(
            "read_overlong_id",
            KeysFixture::Signing,
            "GET",
            "/keys/{overlong}",
            &[],
            None,
        ),
        c(
            "read_unknown",
            KeysFixture::Signing,
            "GET",
            "/keys/{missing}",
            &[],
            None,
        ),
        c(
            "read_governance_off",
            KeysFixture::Off,
            "GET",
            "/keys/{missing}",
            &[],
            None,
        ),
        // ── PATCH /keys/{id} ──────────────────────────────────────────────────────────────────
        c(
            "patch_overlong_id",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{overlong}",
            &[],
            Some("{}"),
        ),
        c(
            "patch_malformed_if_match",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{missing}",
            &[("if-match", "not-an-etag")],
            Some("{}"),
        ),
        c(
            "patch_bad_json",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{missing}",
            &[],
            Some("{"),
        ),
        c(
            "patch_rebind_target_missing",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{missing}",
            &[],
            Some(r#"{"group":"nope"}"#),
        ),
        c(
            "patch_unknown",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{missing}",
            &[],
            Some("{}"),
        ),
        c(
            "patch_stale_etag",
            KeysFixture::Signing,
            "PATCH",
            "/keys/{live}",
            &[("if-match", STALE_ETAG)],
            Some("{}"),
        ),
        c(
            "patch_governance_off",
            KeysFixture::Off,
            "PATCH",
            "/keys/{missing}",
            &[],
            Some("{}"),
        ),
        // ── DELETE /keys/{id} ─────────────────────────────────────────────────────────────────
        c(
            "delete_overlong_id",
            KeysFixture::Signing,
            "DELETE",
            "/keys/{overlong}",
            &[],
            None,
        ),
        c(
            "delete_malformed_if_match",
            KeysFixture::Signing,
            "DELETE",
            "/keys/{missing}",
            &[("if-match", "not-an-etag")],
            None,
        ),
        c(
            "delete_unknown",
            KeysFixture::Signing,
            "DELETE",
            "/keys/{missing}",
            &[],
            None,
        ),
        c(
            "delete_stale_etag",
            KeysFixture::Signing,
            "DELETE",
            "/keys/{live}",
            &[("if-match", STALE_ETAG)],
            None,
        ),
        c(
            "delete_governance_off",
            KeysFixture::Off,
            "DELETE",
            "/keys/{missing}",
            &[],
            None,
        ),
        // ── GET /keys/{id}/usage ──────────────────────────────────────────────────────────────
        c(
            "usage_overlong_id",
            KeysFixture::Signing,
            "GET",
            "/keys/{overlong}/usage",
            &[],
            None,
        ),
        c(
            "usage_unknown",
            KeysFixture::Signing,
            "GET",
            "/keys/{missing}/usage",
            &[],
            None,
        ),
        c(
            "usage_governance_off",
            KeysFixture::Off,
            "GET",
            "/keys/{missing}/usage",
            &[],
            None,
        ),
        // ── POST /keys/{id}/rotate ────────────────────────────────────────────────────────────
        c(
            "rotate_overlong_id",
            KeysFixture::Signing,
            "POST",
            "/keys/{overlong}/rotate",
            &[],
            None,
        ),
        c(
            "rotate_unknown",
            KeysFixture::Signing,
            "POST",
            "/keys/{missing}/rotate",
            &[],
            None,
        ),
        c(
            "rotate_governance_off",
            KeysFixture::Off,
            "POST",
            "/keys/{missing}/rotate",
            &[],
            None,
        ),
        // ── POST /keys/{id}/revoke ────────────────────────────────────────────────────────────
        c(
            "revoke_overlong_id",
            KeysFixture::Signing,
            "POST",
            "/keys/{overlong}/revoke",
            &[],
            None,
        ),
        c(
            "revoke_unknown",
            KeysFixture::Signing,
            "POST",
            "/keys/{missing}/revoke",
            &[],
            None,
        ),
        c(
            "revoke_governance_off",
            KeysFixture::Off,
            "POST",
            "/keys/{missing}/revoke",
            &[],
            None,
        ),
        // ── POST /signing-key/rotate ──────────────────────────────────────────────────────────
        c(
            "signing_rotate_no_key",
            KeysFixture::NoSigner,
            "POST",
            "/signing-key/rotate",
            &[],
            None,
        ),
        c(
            "signing_rotate_governance_off",
            KeysFixture::Off,
            "POST",
            "/signing-key/rotate",
            &[],
            None,
        ),
    ];

    let client = reqwest::Client::new();
    let mut observed = serde_json::Map::new();
    for fixture in [
        KeysFixture::Signing,
        KeysFixture::NoSigner,
        KeysFixture::Off,
    ] {
        let (addr, server, live) = serve_keys_fixture(fixture).await;
        for case in cases.iter().filter(|c| c.fixture == fixture) {
            let path = case
                .path
                .replace("{overlong}", OVERLONG)
                .replace("{missing}", MISSING)
                .replace("{live}", &live);
            let mut req = client
                .request(
                    reqwest::Method::from_bytes(case.method.as_bytes()).unwrap(),
                    format!("http://{addr}/api/v1/admin{path}"),
                )
                .header("x-admin-token", "admintok");
            for (k, v) in case.headers {
                req = req.header(*k, *v);
            }
            if let Some(body) = case.body {
                req = req
                    .header("content-type", "application/json")
                    .body(body.to_string());
            }
            let resp = req.send().await.unwrap();
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            let body = resp.text().await.unwrap();
            assert!(
                (400..600).contains(&status),
                "{} expected an error response, got {status}: {body}",
                case.name
            );
            observed.insert(
                case.name.to_string(),
                serde_json::json!({"status": status, "content_type": content_type, "body": body}),
            );
        }
        server.abort();
    }

    let fresh = format!(
        "{}\n",
        serde_json::to_string_pretty(&serde_json::Value::Object(observed))
            .expect("serialize keys error wire")
    );
    if std::env::var("UPDATE_KEYS_ERROR_GOLDEN").is_ok_and(|v| v == "1") {
        std::fs::write(KEYS_ERROR_GOLDEN, &fresh)
            .unwrap_or_else(|e| panic!("write {KEYS_ERROR_GOLDEN}: {e}"));
        return;
    }
    let committed = std::fs::read_to_string(KEYS_ERROR_GOLDEN)
        .unwrap_or_else(|e| panic!("read {KEYS_ERROR_GOLDEN}: {e}"));
    assert_eq!(
        committed, fresh,
        "the keys error WIRE changed — status/content-type/body bytes on a FROZEN surface. If this \
         is deliberate, regenerate with `UPDATE_KEYS_ERROR_GOLDEN=1`."
    );
}

/// Drive the non-keys admin error paths that the rest of the suite leaves unexercised: the group
/// CRUD errors, the version-guard errors on every If-Match-guarded mutation, the list-GET query
/// rejections and the config-plane read errors. Assertions are deliberately thin (status + code) —
/// the POINT of the test is the emission, which the router's recording layer witnesses.
#[tokio::test]
async fn admin_error_surface_witnesses_every_declared_response() {
    drive_admin_error_surface().await;
}

/// Build a FRESH admin fixture for the error-surface driver: a base-config group (`team`) and hook
/// (`basehook`) — file-owned, so the `conflict` base-defined arms are reachable — plus an OVERLAY
/// group (`og`) and hook (`oh`) created over the API, for the arms that must NOT hit the
/// base-defined guard. Returns the address and the server task.
///
/// Each batch of cases gets its own fixture: the admin surface enforces a per-principal, per-class
/// MUTATION BUDGET (10/min for the config plane), and a driver that exercises every declared error
/// blows straight through it. A fresh App carries a fresh limiter, so the batching keeps the driver
/// exercising HANDLERS rather than the rate limiter.
async fn admin_error_fixture() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app()
        .governance(gov)
        .group(
            "team",
            busbar_kernel::config::GroupCfg {
                parent: None,
                enabled: true,
                limits: vec![],
                child_default: None,
            },
        )
        .base_hook(
            "basehook",
            busbar_kernel::config::HookCfg {
                kind: busbar_kernel::config::HookKind::Gate,
                plugin: "test-hook".to_string(),
                timeout_ms: 25,
                on_error: "reject".to_string(),
                prompt: busbar_kernel::config::PromptAccess::No,
                user: busbar_kernel::config::UserAccess::No,
                priority: 0,
                settings: serde_json::Map::new(),
                at: None,
                on_empty: None,
                global: false,
                default: false,
                signals: Vec::new(),
                groups: Vec::new(),
                phase: Vec::new(),
            },
        )
        .build();
    let router = crate::build_router(app);
    let (addr, server, client) = spin_up(router).await;
    for (rel, body) in [
        (
            "/groups",
            r#"{"name":"og","config":{"parent":"team","limits":[]}}"#,
        ),
        (
            "/hooks",
            r#"{"name":"oh","config":{"kind":"gate","module":"test-hook"}}"#,
        ),
    ] {
        let created = client
            .post(format!("http://{addr}/api/v1/admin{rel}"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await
            .unwrap();
        assert_eq!(created.status().as_u16(), 201, "fixture: POST {rel}");
    }
    (addr, server)
}

/// See the test above. Split out so the class-level over-claim test can drive it directly.
async fn drive_admin_error_surface() {
    busbar_kernel::snapshot::init();
    // A syntactically valid but WRONG config-plane ETag — the stale guard, not the parser.
    const STALE: &str = "\"999999\"";
    const BAD_ETAG: &str = "not-an-etag";
    let group_body = r#"{"config":{"limits":[]}}"#;
    // (label, method, rel, if-match, body, expected status, expected code)
    /// One driven error case: (label, method, relative path, `If-Match`, body, expected status,
    /// expected frozen `code`).
    type ErrCase = (
        &'static str,
        &'static str,
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
        u16,
        &'static str,
    );
    let cases: &[ErrCase] = &[
        // ── POST /groups ──────────────────────────────────────────────────────────────────────
        (
            "groups_post_invalid_tree",
            "POST",
            "/groups",
            None,
            Some(r#"{"name":"x","config":{"parent":"ghost","limits":[]}}"#),
            400,
            "invalid_request",
        ),
        (
            "groups_post_base_defined",
            "POST",
            "/groups",
            None,
            Some(r#"{"name":"team","config":{"limits":[]}}"#),
            409,
            "conflict",
        ),
        (
            "groups_post_stale",
            "POST",
            "/groups",
            Some(STALE),
            Some(r#"{"name":"z","config":{"limits":[]}}"#),
            409,
            "version_conflict",
        ),
        (
            "groups_post_bad_if_match",
            "POST",
            "/groups",
            Some(BAD_ETAG),
            Some(r#"{"name":"z","config":{"limits":[]}}"#),
            400,
            "invalid_request",
        ),
        // ── PUT /groups/{name} ────────────────────────────────────────────────────────────────
        (
            "groups_put_bad_if_match",
            "PUT",
            "/groups/og",
            Some(BAD_ETAG),
            Some(group_body),
            400,
            "invalid_request",
        ),
        (
            "groups_put_unknown",
            "PUT",
            "/groups/ghost",
            None,
            Some(group_body),
            404,
            "not_found",
        ),
        (
            "groups_put_base_defined",
            "PUT",
            "/groups/team",
            None,
            Some(group_body),
            409,
            "conflict",
        ),
        (
            "groups_put_stale",
            "PUT",
            "/groups/og",
            Some(STALE),
            Some(group_body),
            409,
            "version_conflict",
        ),
        // ── PATCH /groups/{name} ──────────────────────────────────────────────────────────────
        (
            "groups_patch_bad_if_match",
            "PATCH",
            "/groups/og",
            Some(BAD_ETAG),
            Some("{}"),
            400,
            "invalid_request",
        ),
        (
            "groups_patch_unknown",
            "PATCH",
            "/groups/ghost",
            None,
            Some("{}"),
            404,
            "not_found",
        ),
        (
            "groups_patch_base_defined",
            "PATCH",
            "/groups/team",
            None,
            Some("{}"),
            409,
            "conflict",
        ),
        (
            "groups_patch_stale",
            "PATCH",
            "/groups/og",
            Some(STALE),
            Some("{}"),
            409,
            "version_conflict",
        ),
        (
            "groups_patch_invalid_tree",
            "PATCH",
            "/groups/og",
            None,
            Some(r#"{"parent":"ghost"}"#),
            400,
            "invalid_request",
        ),
        // ── DELETE /groups/{name} ─────────────────────────────────────────────────────────────
        (
            "groups_delete_bad_if_match",
            "DELETE",
            "/groups/og",
            Some(BAD_ETAG),
            None,
            400,
            "invalid_request",
        ),
        (
            "groups_delete_unknown",
            "DELETE",
            "/groups/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "groups_delete_base_defined",
            "DELETE",
            "/groups/team",
            None,
            None,
            409,
            "conflict",
        ),
        (
            "groups_delete_stale",
            "DELETE",
            "/groups/og",
            Some(STALE),
            None,
            409,
            "version_conflict",
        ),
        // ── Hooks: the version-guard arms the escalation tests don't reach ─────────────────────
        (
            "hooks_post_stale",
            "POST",
            "/hooks",
            Some(STALE),
            Some(r#"{"name":"h2","config":{"kind":"gate","module":"test-hook"}}"#),
            409,
            "version_conflict",
        ),
        (
            "hooks_put_bad_if_match",
            "PUT",
            "/hooks/oh",
            Some(BAD_ETAG),
            Some(r#"{"config":{"kind":"gate","module":"test-hook"}}"#),
            400,
            "invalid_request",
        ),
        (
            "hooks_delete_bad_if_match",
            "DELETE",
            "/hooks/oh",
            Some(BAD_ETAG),
            None,
            400,
            "invalid_request",
        ),
        (
            "hooks_delete_stale",
            "DELETE",
            "/hooks/oh",
            Some(STALE),
            None,
            409,
            "version_conflict",
        ),
        (
            "hook_settings_bad_if_match",
            "PATCH",
            "/hooks/oh/settings",
            Some(BAD_ETAG),
            Some(r#"{"settings":{}}"#),
            400,
            "invalid_request",
        ),
        (
            "hook_settings_base_defined",
            "PATCH",
            "/hooks/basehook/settings",
            None,
            Some(r#"{"settings":{}}"#),
            409,
            "conflict",
        ),
        (
            "hook_settings_stale",
            "PATCH",
            "/hooks/oh/settings",
            Some(STALE),
            Some(r#"{"settings":{}}"#),
            409,
            "version_conflict",
        ),
        // ── List/read GETs whose query string is rejected at the door ─────────────────────────
        (
            "pools_bad_detail",
            "GET",
            "/pools?detail=maybe",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "usage_bad_window",
            "GET",
            "/usage?window=soon",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "audit_bad_cursor",
            "GET",
            "/audit?cursor=%21%21",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "versions_bad_cursor",
            "GET",
            "/config/versions?cursor=%21%21",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "diff_missing_params",
            "GET",
            "/config/diff",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "diff_unknown_version",
            "GET",
            "/config/diff?from=900&to=901",
            None,
            None,
            404,
            "not_found",
        ),
        // ── Config plane ──────────────────────────────────────────────────────────────────────
        (
            "config_rollback_bad_body",
            "POST",
            "/config/rollback",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "config_rollback_bad_if_match",
            "POST",
            "/config/rollback",
            Some(BAD_ETAG),
            Some(r#"{"version":1}"#),
            400,
            "invalid_request",
        ),
        (
            "config_apply_bad_body",
            "POST",
            "/config/apply",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "config_settings_bad_if_match",
            "PUT",
            "/config/settings",
            Some(BAD_ETAG),
            Some("{}"),
            400,
            "invalid_request",
        ),
        (
            "admin_auth_bad_if_match",
            "PUT",
            "/admin-auth",
            Some(BAD_ETAG),
            Some(r#"{"admin_auth":[]}"#),
            400,
            "invalid_request",
        ),
        // ── Plugins ───────────────────────────────────────────────────────────────────────────
        (
            "plugin_rollback_bad_body",
            "POST",
            "/plugins/rollback",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "plugin_rollback_bad_if_match",
            "POST",
            "/plugins/rollback",
            Some(BAD_ETAG),
            Some(r#"{"file":"p.tar.gz"}"#),
            400,
            "invalid_request",
        ),
        (
            "plugin_rollback_stale",
            "POST",
            "/plugins/rollback",
            Some(STALE),
            Some(r#"{"file":"p.tar.gz"}"#),
            409,
            "version_conflict",
        ),
        // ── Single-resource reads: the 404 every templated GET carries ────────────────────────
        (
            "pool_unknown",
            "GET",
            "/pools/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hook_unknown",
            "GET",
            "/hooks/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hook_health_unknown",
            "GET",
            "/hooks/ghost/health",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hook_schema_unknown",
            "GET",
            "/hooks/ghost/schema",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hook_status_unknown",
            "GET",
            "/hooks/ghost/status",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "plugins_schema_unknown",
            "GET",
            "/plugins/ghost/schema",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "group_unknown",
            "GET",
            "/groups/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "group_usage_unknown",
            "GET",
            "/groups/ghost/usage",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "version_non_numeric",
            "GET",
            "/config/versions/abc",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "version_unknown",
            "GET",
            "/config/versions/999",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "plugins_missing_type",
            "GET",
            "/plugins",
            None,
            None,
            400,
            "invalid_request",
        ),
        // ── POST /restart's 3 declared conditions ─────────────────────────────────────────────
        // These 3 have their own dedicated behavioral test (`test_admin_v1_restart_refuses_when_
        // it_cannot_restart`, which also asserts the exact refusal MESSAGE distinguishing the two
        // 409s) -- but that test's witnesses must not be this audit's only source of them, per
        // this function's own doc comment ("independent of whether they [other tests] ran"). Under
        // parallel `cargo test` scheduling there is no guarantee that test's HTTP calls land before
        // this function's caller takes its `observed::snapshot()`, so relying on it alone is a real
        // race, not just a theoretical one -- these 3 rows close it. `can_restart()` is backed by a
        // `OnceLock` never populated in a test binary, so `confirm: true` deterministically reaches
        // the NotRestartable gate regardless of environment; `restart_no_supervisor` forces the
        // unsupervised environment deterministically (see `restart::with_forced_unsupervised`'s doc
        // comment) rather than assuming the real env lacks the supervisor markers -- CI runners were
        // found to genuinely set INVOCATION_ID themselves, which broke that original assumption.
        (
            "restart_malformed_body",
            "POST",
            "/restart",
            None,
            Some(r#"{"confrim": true}"#),
            400,
            "invalid_request",
        ),
        (
            "restart_no_supervisor",
            "POST",
            "/restart",
            None,
            None,
            409,
            "conflict",
        ),
        (
            "restart_not_restartable",
            "POST",
            "/restart",
            None,
            Some(r#"{"confirm": true}"#),
            409,
            "conflict",
        ),
        // ── Hook definition lifecycle ─────────────────────────────────────────────────────────
        (
            "hooks_post_bad_body",
            "POST",
            "/hooks",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "hooks_post_bad_if_match",
            "POST",
            "/hooks",
            Some(BAD_ETAG),
            Some(r#"{"name":"h3","config":{"kind":"gate","module":"test-hook"}}"#),
            400,
            "invalid_request",
        ),
        (
            "hooks_post_base_defined",
            "POST",
            "/hooks",
            None,
            Some(r#"{"name":"basehook","config":{"kind":"gate","module":"test-hook"}}"#),
            409,
            "conflict",
        ),
        (
            "hooks_post_grant_change",
            "POST",
            "/hooks",
            None,
            Some(r#"{"name":"oh","config":{"kind":"tap","module":"test-hook"}}"#),
            409,
            "conflict",
        ),
        (
            "hooks_put_unknown",
            "PUT",
            "/hooks/ghost",
            None,
            Some(r#"{"config":{"kind":"gate","module":"test-hook"}}"#),
            404,
            "not_found",
        ),
        (
            "hooks_put_base_defined",
            "PUT",
            "/hooks/basehook",
            None,
            Some(r#"{"config":{"kind":"gate","module":"test-hook"}}"#),
            409,
            "conflict",
        ),
        (
            "hooks_put_stale",
            "PUT",
            "/hooks/oh",
            Some(STALE),
            Some(r#"{"config":{"kind":"gate","module":"test-hook"}}"#),
            409,
            "version_conflict",
        ),
        (
            "hooks_delete_unknown",
            "DELETE",
            "/hooks/ghost",
            None,
            None,
            404,
            "not_found",
        ),
        (
            "hooks_delete_base_defined",
            "DELETE",
            "/hooks/basehook",
            None,
            None,
            409,
            "conflict",
        ),
        (
            "hook_settings_unknown",
            "PATCH",
            "/hooks/ghost/settings",
            None,
            Some(r#"{"settings":{}}"#),
            404,
            "not_found",
        ),
        // ── Overlay reset ─────────────────────────────────────────────────────────────────────
        (
            "overlay_unknown_section",
            "DELETE",
            "/overlay/nosuch",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "overlay_stale",
            "DELETE",
            "/overlay/groups",
            Some(STALE),
            None,
            409,
            "version_conflict",
        ),
        // ── Config plane ──────────────────────────────────────────────────────────────────────
        (
            "cache_flush_bad_body",
            "POST",
            "/auth/cache/flush",
            None,
            Some("["),
            400,
            "invalid_request",
        ),
        (
            "config_validate_bad_body",
            "POST",
            "/config/validate",
            None,
            Some("{"),
            400,
            "invalid_request",
        ),
        (
            "config_reload_ephemeral",
            "POST",
            "/config/reload",
            None,
            None,
            400,
            "invalid_request",
        ),
        (
            "config_apply_stale",
            "POST",
            "/config/apply",
            Some(STALE),
            Some(
                r#"{"config":{"listen":"127.0.0.1:0","store":{"module":"memory"},"providers":{},"models":{},"pools":{}}}"#,
            ),
            409,
            "version_conflict",
        ),
        (
            "config_rollback_unknown",
            "POST",
            "/config/rollback",
            None,
            Some(r#"{"version":999}"#),
            404,
            "not_found",
        ),
        (
            "config_rollback_stale",
            "POST",
            "/config/rollback",
            Some(STALE),
            Some(r#"{"version":1}"#),
            409,
            "version_conflict",
        ),
        (
            "config_settings_stale",
            "PUT",
            "/config/settings",
            Some(STALE),
            Some("{}"),
            409,
            "version_conflict",
        ),
        (
            "admin_auth_unknown_module",
            "PUT",
            "/admin-auth",
            None,
            Some(r#"{"admin_auth":["definitely-not-a-module"]}"#),
            400,
            "invalid_request",
        ),
        (
            "admin_auth_stale",
            "PUT",
            "/admin-auth",
            Some(STALE),
            Some(r#"{"admin_auth":["admin-tokens"]}"#),
            409,
            "version_conflict",
        ),
        (
            "admin_auth_lockout",
            "PUT",
            "/admin-auth",
            None,
            Some(r#"{"admin_auth":["test-scope-module"]}"#),
            409,
            "conflict",
        ),
    ];

    // The per-principal mutation budget is 10/min for the config class, so run the table in small
    // batches, each against a fresh fixture (and therefore a fresh limiter).
    let client = reqwest::Client::new();
    for batch in cases.chunks(6) {
        let (addr, server) = admin_error_fixture().await;
        for (label, method, rel, if_match, body, want_status, want_code) in batch {
            let mut req = client
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    format!("http://{addr}/api/v1/admin{rel}"),
                )
                .header("x-admin-token", "admintok");
            if let Some(tag) = if_match {
                req = req.header("if-match", *tag);
            }
            if let Some(b) = body {
                req = req.header("content-type", "application/json").body(*b);
            }
            // `restart_no_supervisor` needs a deterministically-unsupervised environment to reach
            // the real NoSupervisor 409 through the real handler -- CI runners were found to
            // genuinely set INVOCATION_ID themselves, so the env alone can't be trusted. See
            // `restart::with_forced_unsupervised`'s doc comment for why this is thread-local, not
            // an env var.
            let resp = if *label == "restart_no_supervisor" {
                crate::restart::with_forced_unsupervised(|| req.send()).await
            } else {
                req.send().await
            }
            .unwrap();
            let status = resp.status().as_u16();
            let parsed: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                status, *want_status,
                "{label}: expected {want_status}, got {status} ({parsed})"
            );
            assert_eq!(parsed["error"]["code"], *want_code, "{label}");
        }
        server.abort();
    }
}

/// WITNESS: the two `POST /plugins/rollback` errors that need a real plugins directory —
/// a target file that is not there (404 `not_found`) and one that IS there but does not pass the
/// running trust posture even with the anti-downgrade floor lowered to its own version (409
/// `conflict`; a rollback authenticates the OPERATOR, never the bytes).
#[tokio::test]
async fn plugin_rollback_reports_missing_and_untrusted_targets() {
    drive_plugin_rollback_errors().await;
}

/// `POST /plugins/reload` 400s when the on-disk config no longer rebuilds. The operation declared NO
/// 4xx at all until this driver existed -- `openapi.json` hid a response clients hit, and the
/// router's under-claim panic could not catch it because nothing produced it.
#[tokio::test]
async fn plugin_reload_reports_an_unrebuildable_disk_config() {
    drive_plugin_reload_errors().await;
}

/// See the test above. Split out so the class-level over-claim test can drive it directly.
async fn drive_plugin_reload_errors() {
    busbar_kernel::snapshot::init();
    // `pid` alone collides: this helper is called from TWO `#[tokio::test]`s in the same binary
    // (`plugin_reload_reports_an_unrebuildable_disk_config` and
    // `declared_error_set_is_exactly_what_the_handlers_emit`), which can run concurrently and would
    // otherwise `remove_dir_all` / overwrite each other's fixture mid-request. A per-CALL monotonic
    // ticket makes every call's directory unique, matching the `stage.rs::next_seq` idiom (pid+tag
    // is not enough here because it's the SAME tag from two call sites, not distinct ones).
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-reload-witness-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // DISK TRUTH that does not parse: the rebuild is reached (not the ephemeral branch) and fails.
    let config = dir.join("config.yaml");
    let providers = dir.join("providers.yaml");
    std::fs::write(&config, "this: [is not: valid: yaml\n").unwrap();
    std::fs::write(&providers, "providers: {}\n").unwrap();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app()
        .governance(gov)
        .plugins_dir(dir.clone())
        .disk_paths(config, providers)
        .build();
    let router = crate::build_router(app);
    let (addr, server, client) = spin_up(router).await;

    let r = client
        .post(format!("http://{addr}/api/v1/admin/plugins/reload"))
        .header("x-admin-token", "admintok")
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(status, 400, "an unrebuildable disk config: {body}");
    assert_eq!(body["error"]["code"], "invalid_request");

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// See the test above. Split out so the class-level over-claim test can drive it directly.
async fn drive_plugin_rollback_errors() {
    busbar_kernel::snapshot::init();
    // Same per-call collision as `drive_plugin_reload_errors` above (two callers, same pid) — see
    // that function's comment.
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-rollback-witness-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let overlay = dir.join("overlay.yaml");
    // An UNSIGNED artifact sitting in the plugins directory, under the DEFAULT trust posture
    // (unsigned not opted in) — so it is present but not loadable.
    let tarball = admin_test_tarball("rollme", "rollme");
    let file = "rollme-1.0.0.tar.gz";
    std::fs::write(dir.join(file), &tarball).unwrap();
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app()
        .governance(gov)
        .plugins_dir(dir.clone())
        .plugins_cfg(busbar_kernel::config::PluginsCfg::default())
        .overlay_path(overlay)
        .build();
    let router = crate::build_router(app);
    let (addr, server, client) = spin_up(router).await;
    let rollback = |body: String| {
        client
            .post(format!("http://{addr}/api/v1/admin/plugins/rollback"))
            .header("x-admin-token", "admintok")
            .header("content-type", "application/json")
            .body(body)
            .send()
    };

    let r = rollback(r#"{"file":"nosuch-9.9.9.tar.gz"}"#.to_string())
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        status, 404,
        "a target that is not in the plugins dir: {body}"
    );
    assert_eq!(body["error"]["code"], "not_found");

    let r = rollback(format!(r#"{{"file":"{file}"}}"#)).await.unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        status, 409,
        "an untrusted target is a terminal conflict, not a validation error: {body}"
    );
    assert_eq!(body["error"]["code"], "conflict");

    // The sibling INSTALL + REMOVE errors, driven against the same directory: a malformed body, a
    // filename that is not a plugin archive, an artifact the trust posture rejects, and a removal
    // of something that was never installed.
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&tarball);
    for (label, rel, method, body, want_status, want_code) in [
        (
            "install_bad_body",
            "/plugins",
            "POST",
            Some("{".to_string()),
            400,
            "invalid_request",
        ),
        (
            "install_bad_filename",
            "/plugins",
            "POST",
            Some(format!(
                r#"{{"file":"not-an-archive","tarball_b64":"{b64}"}}"#
            )),
            400,
            "invalid_request",
        ),
        (
            "install_untrusted",
            "/plugins",
            "POST",
            Some(format!(
                r#"{{"file":"fresh-1.0.0.tar.gz","tarball_b64":"{b64}"}}"#
            )),
            409,
            "conflict",
        ),
        (
            "remove_bad_filename",
            "/plugins/not-an-archive",
            "DELETE",
            None,
            400,
            "invalid_request",
        ),
        (
            "remove_unknown",
            "/plugins/ghost-1.0.0.tar.gz",
            "DELETE",
            None,
            404,
            "not_found",
        ),
    ] {
        let mut req = client
            .request(
                reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                format!("http://{addr}/api/v1/admin{rel}"),
            )
            .header("x-admin-token", "admintok");
        if let Some(b) = body {
            req = req.header("content-type", "application/json").body(b);
        }
        let r = req.send().await.unwrap();
        let status = r.status().as_u16();
        let parsed: serde_json::Value = r.json().await.unwrap();
        assert_eq!(status, want_status, "{label}: {parsed}");
        assert_eq!(parsed["error"]["code"], want_code, "{label}");
    }
    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE CONDITION-WITNESS DEBT LEDGER — a ratchet, not a suppression.
///
/// Witness driver for `POST /plugins/inspect`'s declared 400 (`Validation`): a body whose
/// `tarball_b64` is not valid base64 is rejected with `invalid_request`. The wire behavior itself is
/// also asserted in `test_admin_v1_plugins_inspect_previews_without_installing`; this driver exists
/// so `declared_error_set_is_exactly_what_the_handlers_emit` witnesses the emission through the v1
/// router's recording layer without depending on test order.
async fn drive_plugin_inspect_errors() {
    busbar_kernel::snapshot::init();
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-admin-inspect-witness-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let overlay = dir.join("overlay.yaml");
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let app = crate::new_test_app()
        .governance(gov)
        .plugins_dir(dir.clone())
        .plugins_cfg(busbar_kernel::config::PluginsCfg::default())
        .overlay_path(overlay)
        .build();
    let router = crate::build_router(app);
    let (addr, server, client) = spin_up(router).await;

    // tarball_b64 that is not valid base64 → AdminError::Validation → 400 invalid_request. This is the
    // witness for the operation's declared 400.
    let r = client
        .post(format!("http://{addr}/api/v1/admin/plugins/inspect"))
        .header("x-admin-token", "admintok")
        .header("content-type", "application/json")
        .body(r#"{"file":"witness-1.0.0.tar.gz","tarball_b64":"not-base64!!"}"#.to_string())
        .send()
        .await
        .unwrap();
    let status = r.status().as_u16();
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(status, 400, "invalid base64 tarball_b64: {body}");
    assert_eq!(body["error"]["code"], "invalid_request");

    server.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE CLASS-LEVEL GUARANTEE: for EVERY documented operation, the declared error set
/// equals the set the handlers can actually emit. The two directions are enforced by two different
/// mechanisms, both structural:
///
/// - **UNDER-CLAIM** (a handler emits a kind the declaration omits → `openapi.json` would hide a
/// response clients hit) is fatal AT THE EMISSION: the v1 router's recording layer panics inside
/// whichever test produced it. Every test in the suite is a driver; nothing accumulates and
/// nothing depends on test order. That check is live for the whole suite, not just this test.
/// - **OVER-CLAIM** (the declaration lists a response no handler can produce → `openapi.json`
/// documents fiction) needs a WITNESS, which is what this test drives. It runs the error-surface
/// drivers directly — no reliance on other tests having run — and then asserts every declared
/// entry was seen. A declared 409 no test can trigger IS an over-claim until proven otherwise.
///
/// The witness is required at **`(operation, ErrKind, Cond)`** granularity, which is what the design
/// claims and what an `(operation, ErrKind)` check silently did not give: a 409 whose code path had
/// been deleted (`GroupRaceOnMint`, removed with the mint race) stayed documented indefinitely
/// because a SIBLING 409 on the same operation kept the check green. Where an operation declares one
/// condition per kind the untagged witness is unambiguous and still counts; where it declares
/// several, only a `err_json_cond`-tagged emission distinguishes them, and the declarations not yet
/// tagged are ledgered in `COND_WITNESS_DEBT`, which only shrinks.
///
/// Consequence: what used to be a per-endpoint hunt for "another missing 4xx" is now a
/// machine set-comparison over every operation at once. There is no endpoint left to be next.
#[tokio::test]
async fn declared_error_set_is_exactly_what_the_handlers_emit() {
    use busbar_core_admin::v1::contract::taxonomy::declared_errors;
    // Drive every error path the declaration claims. (Other tests contribute to the same registry;
    // calling the drivers here makes the assertion independent of whether they ran.)
    drive_admin_error_surface().await;
    drive_keys_error_surface().await;
    drive_plugin_rollback_errors().await;
    drive_plugin_reload_errors().await;
    drive_plugin_inspect_errors().await;
    drive_key_cap_and_delegation_errors().await;
    drive_named_map_errors().await;
    drive_door_verb_errors().await;
    drive_unpriced_usage_reads().await;
    // Every linked plane's own error-surface driver (its trust verbs), called here for the same reason
    // as every line above it: a condition witnessed only by a sibling test is witnessed nowhere. Looped
    // from the kernel's test-seam registry, so this names no plane; a plane whose driver went missing
    // leaves its declared verbs unwitnessed and fails the over-claim walk below, and an empty registry
    // is refused outright rather than read as "no plane verbs to witness".
    crate::ensure_seam();
    let plane_drivers: Vec<_> = busbar_kernel::test_support::seam::test_plane_seams()
        .iter()
        .filter_map(|seam| seam.error_surface_driver)
        .collect();
    assert!(
        !plane_drivers.is_empty(),
        "no linked plane registered an error-surface driver: the plane verbs' declared errors \
         would go unwitnessed"
    );
    for drive in plane_drivers {
        drive().await;
    }

    let witnessed = crate::witness::snapshot();
    // Every (operation, ErrKind) the suite has actually produced, and every (operation, ErrKind,
    // Cond) TRIPLE for the emissions that named their condition. Keyed on the NEUTRAL string form the
    // process-wide substrate ledger stores (so a witness produced through EITHER copy of busbar-core —
    // the crate-under-test or the plane crates' dependency copy — counts), and looked up below via the
    // same `{:?}`/`as_str()` spellings `taxonomy::observed` records with.
    let seen: std::collections::BTreeSet<(String, String, String)> = witnessed
        .iter()
        .map(|(rel, method, kind, _cond)| (rel.clone(), method.clone(), kind.clone()))
        .collect();
    let seen_triple: std::collections::BTreeSet<(String, String, String, String)> = witnessed
        .iter()
        .filter_map(|(rel, method, kind, cond)| {
            cond.clone()
                .map(|c| (rel.clone(), method.clone(), kind.clone(), c))
        })
        .collect();

    // Walk the DOCUMENTED operations and require a witness for each declared entry AT CONDITION
    // GRANULARITY, which is what the design claims and what a `(op, ErrKind)` check does not give.
    //
    // The two cases differ in what counts as proof, and the difference is exact, not a concession:
    // * the op declares this ErrKind under exactly ONE Cond — then no other condition on this
    // operation can produce that kind, so ANY witness of the kind witnesses that condition;
    // * the op declares the SAME ErrKind under two or more Conds — then an untagged witness is
    // genuinely ambiguous (it proves one of them, and cannot say which), so the emission must
    // name its condition via `err_json_cond` for the declaration to be witness-backed at all.
    // A declared condition that only the ambiguous case can reach is therefore an over-claim until
    // its emission site says which condition it is: that is precisely how a 409 whose code path was
    // deleted (`GroupRaceOnMint`, removed with the mint race) went on being documented while a
    // sibling 409 on the same operation kept the check green.
    let mut over_claimed = Vec::new();
    for (rel, method) in documented_operations() {
        let declared = declared_errors(method, &rel);
        for de in declared {
            let ambiguous = declared.iter().filter(|o| o.kind == de.kind).count() > 1;
            let proven = if ambiguous {
                seen_triple.contains(&(
                    rel.clone(),
                    method.as_str().to_string(),
                    format!("{:?}", de.kind),
                    format!("{:?}", de.cond),
                ))
            } else {
                seen.contains(&(
                    rel.clone(),
                    method.as_str().to_string(),
                    format!("{:?}", de.kind),
                ))
            };
            if !proven {
                if COND_WITNESS_DEBT.contains(&(method, rel.as_str(), de.kind, de.cond)) {
                    continue;
                }
                over_claimed.push(format!(
                    "{} {rel} declares {:?}/{:?} ({} {}) — {}",
                    method.as_str().to_uppercase(),
                    de.kind,
                    de.cond,
                    de.kind.status(),
                    de.kind.code(),
                    if ambiguous {
                        "no test produced it with its CONDITION named (this operation declares \
                         several conditions for the same kind, so an untagged emission proves \
                         nothing about which one is reachable — emit it via `err_json_cond`)"
                    } else {
                        "no test ever produced it"
                    },
                ));
            }
        }
    }
    assert!(
        over_claimed.is_empty(),
        "OpenAPI OVER-CLAIM — openapi.json documents {} response(s) nothing can emit:\n  {}\n\
         Either the declaration is wrong (delete the entry) or the condition is real and needs a \
         negative test that triggers it. A documented error no test can produce is not a contract.",
        over_claimed.len(),
        over_claimed.join("\n  ")
    );

    // THE RATCHET'S OTHER DIRECTION: a debt row must still name a LIVE, AMBIGUOUS declaration.
    // Delete the declaration (as `GroupRaceOnMint` was) or give its kind a single condition, and the
    // row has to go with it -- otherwise the ledger would quietly become a permanent exemption list
    // that outlives the thing it exempted.
    //
    // Deliberately keyed on the DECLARATION TABLE and not on "was it witnessed": `observed` is a
    // process-global registry that accumulates whatever tests happened to run, so a witness-based
    // staleness check would pass or fail depending on the test filter. The declaration table is the
    // same in every run.
    let stale: Vec<_> = COND_WITNESS_DEBT
        .iter()
        .filter(|(m, rel, k, c)| {
            let declared = declared_errors(*m, rel);
            let ambiguous = declared.iter().filter(|o| o.kind == *k).count() > 1;
            !ambiguous || !declared.iter().any(|d| d.kind == *k && d.cond == *c)
        })
        .map(|(m, rel, k, c)| format!("{} {rel} {k:?}/{c:?}", m.as_str().to_uppercase()))
        .collect();
    assert!(
        stale.is_empty(),
        "COND_WITNESS_DEBT has {} row(s) whose declaration is gone or no longer ambiguous — delete \
         them; the ledger only shrinks:\n  {}",
        stale.len(),
        stale.join("\n  ")
    );

    // Sanity: the drivers really did exercise the surface (a registry that silently stopped
    // recording would make the assertion above vacuously true).
    assert!(
        seen.len() >= 60,
        "the error-surface drivers witnessed only {} (operation, kind) pairs — the recording layer \
         is probably not installed",
        seen.len()
    );
}

/// Every (relative path, method) the admin surface documents — read off the COMMITTED
/// `openapi.json`, the exact bytes the runtime serves via `include_str!`.
///
/// This used to be a hand-maintained list that nothing tied to anything: an operation could be added
/// to the router and the doc and simply never appear here, and its declared 4xx set would go
/// unaudited forever. The committed doc is a projection of the code (`openapi_json_matches_committed_file`
/// fails the build the moment it drifts) and every operation in it that this crate's router answers
/// is proven mounted with a documented status, and every router route proven documented
/// (`test_admin_v1_openapi_paths_all_resolve`), so keying off it closes the loop: router → doc →
/// this audit.
fn documented_operations() -> Vec<(String, busbar_core_admin::v1::contract::taxonomy::MethodTag)> {
    use busbar_core_admin::v1::contract::taxonomy::MethodTag;
    let doc: serde_json::Value =
        serde_json::from_str(&busbar_core_admin::test_support::openapi_json())
            .expect("the committed openapi.json parses");
    let paths = doc["paths"]
        .as_object()
        .expect("openapi.json has a paths object");
    let mut ops = Vec::new();
    for (abs, item) in paths {
        let rel = abs
            .strip_prefix(busbar_core_admin::v1::contract::ADMIN_PREFIX)
            .unwrap_or(abs);
        for key in item.as_object().into_iter().flatten().map(|(k, _)| k) {
            // `x-*` specification extensions share the path-item object with real operations.
            if let Some(m) = MethodTag::from_op_key(key) {
                ops.push((rel.to_string(), m));
            }
        }
    }
    assert!(
        ops.len() >= 40,
        "only {} operations read out of the committed openapi.json — the projection is broken",
        ops.len()
    );
    ops
}

/// `docs/admin-api.md`'s mutation rate-limit table names the CONFIG-class (10/min) endpoint set by
/// hand. Until this test existed, nothing tied that prose list to
/// `ratelimit::classify_mutation` — the classifier that actually decides which budget a request
/// spends from. This walks every mutation operation in the committed `openapi.json`
/// (`documented_operations`, itself a projection nothing can silently drift from), classifies each
/// one, and requires the resulting CONFIG set to equal the doc's `config` row EXACTLY — under- and
/// over-listing both fail, same bidirectional-equality idiom as
/// `declared_error_set_is_exactly_what_the_handlers_emit`.
#[test]
fn rate_limit_doc_table_matches_classifier() {
    use busbar_core_admin::v1::contract::taxonomy::MethodTag;
    // The classifier folds each registered plane's named-map section into the CONFIG class, so the
    // planes must be registered before it is asked — independent of which test ran first.
    crate::ensure_seam();
    // The 1.6.0 kernel verbs are answered by the node's administrative loop, which rate-classes
    // them by VERB (`rate::MutationClass::for_verb`), never by this path classifier: they are in
    // the one document but not in this table's jurisdiction.
    let loop_verbs: std::collections::BTreeSet<&'static str> = crate::verb::NEW_VERBS
        .iter()
        .chain(crate::verb::LEDGER_VERBS)
        .chain(crate::verb::AUDIT_VERBS)
        .filter_map(|v| crate::verb::verb_name(*v))
        .collect();
    let answered_by_loop = |rel: &str, method: MethodTag| {
        crate::admin_codec::verbs::resolve(
            &method.as_str().to_uppercase(),
            &format!("{}{rel}", busbar_core_admin::v1::contract::ADMIN_PREFIX),
        )
        .is_some_and(|row| loop_verbs.contains(row.verb))
    };

    // The doc's `config` row, parsed straight out of the committed file — not retyped here — so
    // editing the row is the only step needed to change what this test expects.
    let doc = include_str!("../../../../docs/admin-api.md");
    let row = doc
        .lines()
        .find(|l| l.trim_start().starts_with("| config | 10/min |"))
        .expect("docs/admin-api.md has a `config` row in the mutation rate-limit table");
    let doc_config: std::collections::BTreeSet<(String, MethodTag)> = row
        .split('`')
        .skip(1)
        .step_by(2)
        .map(|token| {
            let mut parts = token.splitn(2, ' ');
            let method = parts.next().unwrap();
            let path = parts.next().unwrap_or_else(|| {
                panic!("doc token {token:?} is not \"METHOD /path\"");
            });
            let m = MethodTag::from_op_key(&method.to_lowercase())
                .unwrap_or_else(|| panic!("unrecognized HTTP method {method:?} in doc row"));
            (path.to_string(), m)
        })
        .collect();
    assert!(
        doc_config.len() >= 6,
        "only parsed {} endpoints out of the doc's config row — the parser is broken: {row:?}",
        doc_config.len()
    );

    // `documented_operations` yields `/overlay/{section}` verbatim (the templated openapi path),
    // matching the doc's literal spelling — no normalization needed on either side.
    let code_config: std::collections::BTreeSet<(String, MethodTag)> = documented_operations()
        .into_iter()
        .filter(|(rel, method)| {
            matches!(
                method,
                MethodTag::Post | MethodTag::Put | MethodTag::Patch | MethodTag::Delete
            ) && !answered_by_loop(rel, *method)
                && busbar_kernel::ratelimit::classify_mutation(rel)
                    == busbar_kernel::ratelimit::MutationClass::Config
        })
        .collect();

    let missing_from_doc: Vec<_> = code_config.difference(&doc_config).collect();
    let missing_from_code: Vec<_> = doc_config.difference(&code_config).collect();
    assert!(
        missing_from_doc.is_empty() && missing_from_code.is_empty(),
        "docs/admin-api.md's config-class row has drifted from ratelimit::classify_mutation.\n\
         In classifier's CONFIG class but not in the doc: {missing_from_doc:?}\n\
         In the doc but not classified CONFIG: {missing_from_code:?}"
    );
}

/// `docs/admin-api.md`'s `DELETE /overlay/{section}` row names the valid section set by hand, and
/// it called that set COMPLETE while it was not: `named_maps` shipped as a durable, API-writable
/// overlay section with no reset at all, and the reference documentation asserted the resulting
/// functional gap did not exist. Prose that describes a gap as a closed set is worse than prose that
/// says nothing, because it stops the reader from looking.
///
/// So the row is parsed out of the committed file and required to equal `OverlaySection::all()`
/// EXACTLY, in both directions: a section live in the code but missing from the doc fails, and a
/// section the doc claims but the parser rejects fails too.
#[test]
fn overlay_reset_doc_row_matches_the_section_set() {
    use busbar_kernel::config::overlay::OverlaySection;
    // Register the plane config sections (`tools`/`agents`) so `OverlaySection::all()`/`parse` see
    // them — busbar-core's own `cfg(test)` binary has them as builtins; here the plane testkits must
    // be installed first (this test builds no `App`, so nothing else triggers the install).
    crate::ensure_seam();

    let doc = include_str!("../../../../docs/admin-api.md");
    let row = doc
        .lines()
        .find(|l| {
            l.trim_start()
                .starts_with("| `DELETE /overlay/{section}` |")
        })
        .expect("docs/admin-api.md has a `DELETE /overlay/{section}` row");
    // The set is spelled `(`section` ∈ `a` \| `b` \| …)`. Take the backticked tokens between the
    // marker and the closing paren, which is the only place the row enumerates section names.
    let (_, after) = row
        .split_once("(`section` ∈ ")
        .expect("the row states the section set as \"(`section` ∈ …)\"");
    let enumerated = after
        .split_once(')')
        .expect("the section set is parenthesised")
        .0;
    let doc_sections: std::collections::BTreeSet<&str> =
        enumerated.split('`').skip(1).step_by(2).collect();
    assert!(
        doc_sections.len() >= 4,
        "only parsed {} section names out of the doc row; the parser is broken and this test must \
         not report a pass on an empty set: {enumerated:?}",
        doc_sections.len()
    );

    let all = OverlaySection::all();
    let code_sections: std::collections::BTreeSet<&str> = all.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        code_sections.len(),
        all.len(),
        "OverlaySection::all() yields a duplicate wire name"
    );
    let missing_from_doc: Vec<_> = code_sections.difference(&doc_sections).collect();
    let missing_from_code: Vec<_> = doc_sections.difference(&code_sections).collect();
    assert!(
        missing_from_doc.is_empty() && missing_from_code.is_empty(),
        "docs/admin-api.md's `DELETE /overlay/{{section}}` row has drifted from \
         OverlaySection::all().\nLive in the code but absent from the doc (an operator is told the \
         section does not exist): {missing_from_doc:?}\nClaimed by the doc but rejected by \
         `OverlaySection::parse` (an operator is told to call something that 400s): \
         {missing_from_code:?}"
    );

    // Every name the doc lists really is accepted by the parser, not merely present in the enum.
    for name in &doc_sections {
        assert!(
            OverlaySection::parse(name).is_some(),
            "the doc lists section `{name}` but `OverlaySection::parse` rejects it"
        );
    }
}

/// THE EXPORT AXIS these tests resolve an `export:` block against — once, as the composition root
/// installs it: the scrape sink (`module: prometheus`) LINKED through the one admission.
fn linked_export_axis() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        busbar_kernel::test_support::export_axis::install_first_party_door(
            busbar_export_prometheus::NAME,
            busbar_export_prometheus::ALIAS,
            busbar_export_prometheus::door::door,
        );
    });
}

/// Write the on-disk base config the named-map tests rebuild against: one model/pool plus a BASE
/// entry in each named map (the base-protection target).
///
/// `reference_corp_ad` additionally makes `auth.admin_auth:` name `corp-ad` — a REFERENCE SITE whose
/// definition lives only in the overlay. That is the shape the dangling-reference test needs: create
/// `corp-ad` through the API (the rebuild resolves, because the overlay supplies the definition),
/// then watch the DELETE get refused because the reference would be left dangling. Every other
/// fixture leaves it off, since a config whose chain names an undefined provider cannot resolve.
/// `base_export == false` writes a config that declares NO exporter at all — the deployment that
/// booted without `export.prometheus`, so `/metrics` was never registered on the router.
fn write_named_map_fixture(
    tag: &str,
    reference_corp_ad: bool,
    base_export: bool,
) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    linked_export_axis();
    static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "busbar-namedmap-{}-{}-{}",
        tag,
        std::process::id(),
        SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let providers_path = dir.join("providers.yaml");
    let config_path = dir.join("config.yaml");
    std::fs::write(
        &providers_path,
        format!(
            "test-provider:
  protocol: {PROTO_ANTHROPIC}
  base_url: http://127.0.0.1:1/
  api_key_env: BUSBAR_TEST_NAMEDMAP_NO_SUCH_KEY
"
        ),
    )
    .unwrap();
    std::fs::write(
        &config_path,
        ("listen: 127.0.0.1:0
store: {module: memory}
providers:
  test-provider:
    api_key: none
models:
  m0:
    provider: test-provider
    max_concurrent: 4
pools:
  p:
    members:
      - model: m0
identity-providers:
  base-idp:
    module: keys
  admin-tokens:
    module: admin-tokens
    token: { file: ADMIN_TOKEN_FILE }
tools:
  base-tools:
    url: https://tools.internal/fs
    pin: { mechanism: cert_spki, key: \"sha256/BASE=\" }
agents:
  base-agent:
    url: https://agents.example/planner
    pin:
      mechanism: unpinned
"
        .to_string()
            + if base_export {
                "export:\n  base-metrics:\n    module: prometheus\n    settings: { buffer_seconds: 60 }\n"
            } else {
                ""
            })
        .replace(
            "ADMIN_TOKEN_FILE",
            &dir.join("admin.token").to_string_lossy(),
        ) + if reference_corp_ad {
            "auth:\n  admin_auth: [admin-tokens, corp-ad]\n"
        } else {
            ""
        },
    )
    .unwrap();
    // The operator credential lives in the FILE the base config points at, so it survives every
    // rebuild-and-swap these tests trigger — a fixture whose admin token only existed on the
    // pre-mutation `App` would start 401-ing the moment a mutation succeeded.
    std::fs::write(dir.join("admin.token"), "admintok").unwrap();
    if reference_corp_ad {
        // The overlay-defined `corp-ad` is a SECOND `admin-tokens` provider on the admin chain, with
        // its own credential file — so the rebuilt chain still admits the fixture's own `admintok`
        // through the first entry, and the test is measuring the dangling guard rather than an
        // accidentally-broken admin credential.
        std::fs::write(dir.join("corp.token"), "corp-secret").unwrap();
    }
    (dir, config_path, providers_path)
}

/// A running admin server over the named-map disk fixture. The live `App` is seeded with the SAME
/// base entries the file declares (a `TestApp` does not parse config.yaml), so the read surface and
/// disk truth agree exactly as they do after a real boot.
async fn named_map_app(
    tag: &str,
    reference_corp_ad: bool,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    named_map_app_opts(tag, reference_corp_ad, true).await
}

/// [`named_map_app`] with the base `export:` entry made OPTIONAL. `base_export == false` is the
/// deployment that BOOTED WITH NO EXPORTER: no `export:` in the base config, no export definition on
/// the live snapshot, and — the part that matters — an empty `boot_route_paths`, i.e. `/metrics` was
/// never registered on this process's router.
async fn named_map_app_opts(
    tag: &str,
    reference_corp_ad: bool,
    base_export: bool,
) -> (
    std::path::PathBuf,
    std::path::PathBuf,
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
) {
    linked_export_axis();
    busbar_kernel::snapshot::init();
    let (dir, config_path, providers_path) =
        write_named_map_fixture(tag, reference_corp_ad, base_export);
    // Disk truth, read back before the paths move into the fixture: the plane sections below are
    // seeded from it.
    let disk: serde_yaml::Value =
        serde_yaml::from_str(&std::fs::read_to_string(&config_path).unwrap()).unwrap();
    // The DEFAULT overlay filename next to config.yaml — the same path `load_config_from_disk`
    // resolves for a config with no explicit `config.overlay` block. A named-map mutation rebuilds
    // from disk truth PLUS the on-disk overlay, so a fixture whose live overlay path differed from
    // the resolved one would silently lose every prior API-applied definition on the next mutation.
    let overlay = dir.join(busbar_kernel::config::overlay::DEFAULT_OVERLAY_FILENAME);
    let store = Arc::new(MemoryStore::new());
    let gov = gov_with_signer(store, Some("admintok".to_string()));
    let mut builder = crate::new_test_app()
        .governance(gov)
        .overlay_path(overlay.clone())
        .disk_paths(config_path, providers_path)
        .identity_provider(
            "base-idp",
            serde_json::from_value(serde_json::json!({"module": "keys"})).unwrap(),
        )
        .identity_provider(
            "admin-tokens",
            serde_json::from_value(serde_json::json!({
                "module": "admin-tokens",
                "token": {"file": dir.join("admin.token").to_string_lossy()}
            }))
            .unwrap(),
        );
    // The plane sections' base entries, seeded FROM config.yaml itself (a `TestApp` does not parse
    // config.yaml, so without this the read surface and disk truth would disagree and the
    // base-protection guard would be measuring the disagreement rather than the guard). Each section
    // reaches its plane through the NEUTRAL registry — the decl that owns the config section parses
    // it and builds the runtime, exactly as `appbuild` does at boot — so this helper names no plane,
    // no plane crate and no plane type.
    let owner = |section: &str| {
        busbar_kernel::plane::registry::plane_decl_for_config_section(section)
            .unwrap_or_else(|| panic!("no plane is registered to own the `{section}:` section"))
    };
    let parse = |section: &str| {
        let decl = owner(section);
        let parse = decl
            .parse_section
            .unwrap_or_else(|| panic!("the `{section}:` plane parses its own section"));
        let cfg = parse(&disk[section]).unwrap_or_else(|e| panic!("`{section}:` parses: {e}"));
        (
            decl,
            std::sync::Arc::<dyn busbar_kernel::plane::config::PlaneCfg>::from(cfg),
        )
    };
    // `tools:` — a per-generation runtime built through the plane's own `build_runtime`, installed
    // under its runtime slot; a plane served through its door (its row folded from its Statement)
    // has none, and builds its slot through its own `build` instead, as `appbuild` does — the slot
    // its named-map reads project.
    {
        let (decl, cfg) = parse("tools");
        match decl.build_runtime {
            Some(build) => {
                builder.install_plane_runtime(
                    busbar_kernel::state::runtime_slot_key(decl.key),
                    build(cfg.as_any(), None),
                );
            }
            None => {
                let ctx = busbar_kernel::plane::registry::BuildCtx {
                    endpoint_slot: None,
                    agent_defs: &(),
                    tool_defs: cfg.as_any(),
                    public_url: Some("https://busbar.example"),
                    prior: None,
                    providers: None,
                };
                if let Some(slot) = (decl.build)(&ctx) {
                    builder.install_plane_runtime(decl.key, slot);
                }
            }
        }
    }
    // `agents:` — the App's type-erased named-definition handle (the admin agents named-map reads
    // it), and the plane object its admin verbs re-read the registry off, built from the SAME
    // section through the plane's own `build` so the runtime this generation carries holds
    // `base-agent` (or a patch of it 404s).
    {
        let (decl, cfg) = parse("agents");
        builder.set_plane_defs_any(decl.key, cfg.clone());
        let ctx = busbar_kernel::plane::registry::BuildCtx {
            endpoint_slot: None,
            agent_defs: cfg.as_any(),
            tool_defs: &(),
            public_url: Some("https://busbar.example"),
            prior: None,
            providers: None,
        };
        if let Some(plane) = (decl.build)(&ctx) {
            builder.install_plane_runtime(decl.key, plane);
        }
    }
    builder = if base_export {
        builder.export_def(
            "base-metrics",
            serde_json::from_value(serde_json::json!({
                "module": "prometheus", "settings": {"buffer_seconds": 60}
            }))
            .unwrap(),
        )
    } else {
        // No exporter at boot ⇒ no plugin route was ever mounted on this process's router. The
        // explicit form matters: the harness's default table keys on the PROCESS-GLOBAL recorder
        // (`metrics::init()` above), so merely omitting the definition would still yield `/metrics`.
        builder.no_plugin_routes()
    };
    let app = builder.build();
    let router = crate::build_router(app);
    let (addr, handle, _) = spin_up(router).await;
    (dir, overlay, addr, handle)
}

/// LIST / GET / PUT for EVERY named-map section through the one generic handler: the base entry is
/// listed and readable, a PUT creates a new definition that is immediately readable, the config
/// version bumps, and the definition lands in the `named_maps` overlay section (so it survives a
/// restart). `identity-providers` additionally projects its ceiling/credential fields while
/// `/export` omits them entirely — the one-view-per-pattern contract.
#[tokio::test]
async fn test_admin_v1_named_maps_list_get_and_put_round_trip() {
    // `request-log-file` (K9b) and `prometheus` (K9d) are rows of the export axis, as a linked
    // build's are.
    linked_export_axis();
    let (dir, overlay, addr, handle) = named_map_app("roundtrip", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    // (section, base entry, the definition a PUT stores under `new-<section>`)
    let cases: [(&str, &str, serde_json::Value); 2] = [
        (
            "identity-providers",
            "base-idp",
            serde_json::json!({"module": "keys", "max_admin_scope": "read-only"}),
        ),
        (
            "export",
            "base-metrics",
            serde_json::json!({
                "module": "request-log-file",
                "settings": {"path": dir.join("req.jsonl").to_string_lossy()}
            }),
        ),
    ];
    for (section, base, def) in &cases {
        // LIST — the base entry is there, and the list carries the config-plane ETag.
        let r = admin(client.get(format!("http://{addr}/api/v1/admin/{section}")))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 200, "GET /{section}");
        let etag = r
            .headers()
            .get("etag")
            .expect("the list read emits the config-plane ETag")
            .to_str()
            .unwrap()
            .to_string();
        let body: serde_json::Value = r.json().await.unwrap();
        let names: Vec<&str> = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .map(|i| i["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(base), "GET /{section} lists {base}: {body}");

        // GET one.
        let one: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/{section}/{base}")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(one["name"], *base);
        assert!(one["module"].is_string(), "the definition names its module");
        if *section == "identity-providers" {
            assert_eq!(
                one["token_configured"], false,
                "an identity provider projects WHETHER a credential is configured, never the \
                 reference itself"
            );
        } else {
            assert!(
                one.get("max_admin_scope").is_none() && one.get("token_configured").is_none(),
                "an exporter carries no ceiling and no credential, so those fields are omitted \
                 entirely: {one}"
            );
        }

        // PUT a NEW definition, chaining the ETag we just read into the guard.
        let name = format!("new-{section}");
        let put = admin(client.put(format!("http://{addr}/api/v1/admin/{section}/{name}")))
            .header("if-match", etag)
            .body(def.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(
            put.status().as_u16(),
            200,
            "PUT /{section}/{name}: {:?}",
            put.text().await
        );

        // Readable immediately (the swap already happened) …
        let after: serde_json::Value =
            admin(client.get(format!("http://{addr}/api/v1/admin/{section}/{name}")))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
        assert_eq!(
            after["name"], name,
            "the PUT definition reads back: {after}"
        );
        assert_eq!(after["module"], def["module"]);

        // … and DURABLE: the raw definition is in the overlay's `named_maps` section, so a restart
        // replays exactly the document that was PUT.
        let doc = busbar_kernel::config::overlay::read(&overlay).expect("overlay written");
        assert_eq!(
            doc.named_maps[*section][&name], *def,
            "the overlay stores the definition VERBATIM"
        );
    }
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// OPTIMISTIC CONCURRENCY: a stale `If-Match` on a named-map write is a RETRYABLE
/// `version_conflict` (409) and changes nothing — the same one mechanism every other config-plane
/// mutation speaks. Driven on both sections, since they share one guard.
#[tokio::test]
async fn test_admin_v1_named_map_put_honors_expected_version() {
    linked_export_axis();
    let (dir, _overlay, addr, handle) = named_map_app("ifmatch", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    for (section, def) in [
        ("identity-providers", serde_json::json!({"module": "keys"})),
        (
            "export",
            serde_json::json!({"module": "prometheus", "settings": {"buffer_seconds": 30}}),
        ),
    ] {
        let r = admin(client.put(format!("http://{addr}/api/v1/admin/{section}/stale")))
            .header("if-match", "\"9999\"")
            .body(def.to_string())
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 409, "a stale guard rejects");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            body["error"]["code"], "version_conflict",
            "RETRYABLE, distinct from a terminal conflict: {body}"
        );
        // Nothing was created.
        let after = admin(client.get(format!("http://{addr}/api/v1/admin/{section}/stale")))
            .send()
            .await
            .unwrap();
        assert_eq!(
            after.status().as_u16(),
            404,
            "the rejected PUT stored nothing"
        );
    }
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE TRUST-CEILING RULE: `identity-providers.<name>.max_admin_scope` may be LOWERED or left
/// alone through the admin API, and RAISING it is refused outright (409 `conflict`) — including on
/// a brand-new provider, whose baseline is the most restrictive default, so an escalating ceiling
/// cannot ride in on a create either. Every attempt is audited.
///
/// AND the token must be one the ENGINE accepts: exactly `read-only` or `full`. There is no `none`
/// — omit the key for the most restrictive default (`read-only`), and to grant NO admin authority
/// through a provider grant no `admin_scope` under that provider's `role_bindings:`. An unknown
/// token is a hard boot error (`config_validate`'s chain-entry rule, reached because `resolve_auth`
/// copies the definition's ceiling onto every resolved chain entry), so accepting it here would
/// answer 200 to a write that leaves the deployment unbootable.
#[tokio::test]
async fn test_admin_v1_identity_provider_refuses_raising_max_admin_scope() {
    let (dir, addr, handle) = {
        let (dir, _overlay, addr, handle) = named_map_app("ceiling", false).await;
        (dir, addr, handle)
    };
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // (a) A NEW provider asking for `full` is a RAISE over the default baseline — refused.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"full"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 409, "raising the ceiling is refused");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("max_admin_scope"),
        "the refusal names the ceiling: {body}"
    );
    // Nothing was stored.
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the refused PUT stored nothing"
    );

    // (b) A ceiling token the ENGINE does not accept is refused by the API too. The accepted values
    // are exactly `read-only` and `full` — the two `Scope::parse` knows; `config_validate`'s
    // chain-entry rule turns anything else into a HARD BOOT ERROR, because `resolve_auth` copies the
    // definition's ceiling onto every resolved chain entry. `none` in particular is NOT a value:
    // there is no "no admin authority" ceiling. Omit the key for the most restrictive default
    // (`read-only`); to grant no admin authority through a provider, grant no `admin_scope` under
    // that provider's `role_bindings:`. Accepting `none` here reported success on a write that left
    // the deployment unbootable at the next restart.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"none"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "`none` is not a ceiling the engine accepts, so the API must refuse it"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("expected read-only or full"),
        "the refusal names the accepted values: {body}"
    );
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the refused PUT stored nothing"
    );

    // (b2) The most restrictive ceiling the engine DOES accept is `read-only` — applied.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"read-only"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        200,
        "`read-only` can never be a raise: {:?}",
        r.text().await
    );

    // (c) …and a subsequent RAISE on the now-existing provider is still refused.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"full"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 409, "a raise in place is refused too");
    let still: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    assert_eq!(
        still["max_admin_scope"], "read-only",
        "the live ceiling is untouched by the refused raise: {still}"
    );

    // AUDITED — both the applied change and the refusals.
    let audit: serde_json::Value = admin(client.get(format!(
        "http://{addr}/api/v1/admin/audit?resource=identity-provider:corp-ad"
    )))
    .send()
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let items = audit["items"].as_array().unwrap();
    assert!(
        items
            .iter()
            .any(|i| i["outcome"] == "rejected" && i["action"] == "identity-provider.replace"),
        "a refused ceiling raise is audited: {audit}"
    );
    assert!(
        items
            .iter()
            .any(|i| i["outcome"] == "applied" && i["action"] == "identity-provider.replace"),
        "the accepted change is audited: {audit}"
    );
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A MUTATION THAT ADDS A ROUTE SAYS "RESTART REQUIRED", instead of reporting
/// plain success for a route this process will never serve.
///
/// Each declared plugin-route PATH is registered on the axum router ONCE, at boot; a config apply
/// swaps only `Arc<App>` and never rebuilds the router. So a `PUT /export/{name}` that introduces a
/// `prometheus` instance where none existed at boot is durably stored, live on the snapshot, and
/// `/metrics` keeps 404ing until the process restarts. The `export:` named map had no restart-required
/// signal (unlike `PUT /config/settings`'s `reload_to_apply`), so the operator was told nothing.
///
/// The signal must be exact in BOTH directions, which is why this walks all four cases: an exporter
/// that declares no route is silent, the route-adding PUT flags exactly `/metrics`, a LATER unrelated
/// mutation does not re-flag it (the signal is keyed on the mutation's own delta), and a REMOVAL is
/// silent because removing genuinely does take effect live.
#[tokio::test]
async fn test_admin_v1_export_put_that_adds_a_route_reports_restart_required() {
    linked_export_axis();
    // `base_export: false` ⇒ booted with NO exporter, so `/metrics` was never mounted.
    let (dir, _overlay, addr, handle) = named_map_app_opts("bootfrozen", false, false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // (1) An exporter that declares NO plugin route (a PUSH sink) is fully live on the swap — silent.
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/reqlog")))
        .body(
            serde_json::json!({
                "module": "request-log-file",
                "settings": {"path": dir.join("req.jsonl").to_string_lossy()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    let body: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/export/reqlog")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert!(
        body.get("reload_to_apply").is_none(),
        "a sink that declares no route needs no restart: {body}"
    );

    // (2) THE DEFECT: adding a `prometheus` instance introduces `GET /metrics`, which this process's
    // router does not have. Accepted (it is stored, and correct after a restart) but NOT reported as
    // simply applied.
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/prom")))
        .body(
            serde_json::json!({
                "module": "prometheus", "settings": {"buffer_seconds": 30}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "the definition is still stored");
    let body: serde_json::Value = r.json().await.unwrap();
    let empty = Vec::new();
    let flagged: Vec<&str> = body["reload_to_apply"]
        .as_array()
        .unwrap_or(&empty)
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert_eq!(
        flagged,
        vec!["/metrics"],
        "the ADDED route the router cannot serve is named: {body}"
    );
    assert!(
        body["note"].as_str().unwrap_or("").contains("RESTART"),
        "the note tells the operator what to do about it: {body}"
    );
    // The response is still the stored definition — the signal is ADDITIVE, not a replacement body.
    assert_eq!(body["name"], "prom");
    assert_eq!(body["module"], "prometheus");
    // And the route really is unserved on this process, which is what the signal is about.
    assert_eq!(
        client
            .get(format!("http://{addr}/metrics"))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        404,
        "`/metrics` is not mounted, exactly as the response just said"
    );

    // (3) NO SPURIOUS RE-FLAG: a later mutation that introduces no new path is silent, even though
    // `/metrics` is still pending a restart (the same "keyed on what this request changed" rule
    // `reload_to_apply_fields` follows).
    let r = admin(client.patch(format!("http://{addr}/api/v1/admin/export/reqlog/settings")))
        .body(
            serde_json::json!({"settings": {"path": dir.join("req2.jsonl").to_string_lossy()}})
                .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(
        body.get("reload_to_apply").is_none(),
        "an edit that adds no path must not re-flag an already-pending route: {body}"
    );

    // (4) REMOVAL is live (the dispatcher resolves the owner from the current snapshot and 404s), so
    // it carries no notice at all.
    let r = admin(client.delete(format!("http://{addr}/api/v1/admin/export/prom")))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 204, "a removal applies live");

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// AN UNREFERENCED DEFINITION IS STILL VALIDATED. Most of the identity-provider rules live in
/// `resolve_auth`, which only ever sees providers already NAMED by `auth.chain:`/`auth.admin_auth:`
/// — so a definition written through the admin API and not yet referenced used to escape them: the
/// API answered 200, persisted the definition into the overlay, and the error surfaced only later,
/// when something finally named the provider (or, for a `config.yaml` edit that named it, at the
/// next BOOT, which then failed). The definition-side write path now runs the same rules on the same
/// shared functions, so the value is refused where it is written.
#[tokio::test]
async fn test_admin_v1_identity_provider_validates_an_unreferenced_definition() {
    let (dir, addr, handle) = {
        let (dir, _overlay, addr, handle) = named_map_app("unreferenced", false).await;
        (dir, addr, handle)
    };
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    // `token:` is the built-in `admin-tokens` operator credential. On any other module it is inert —
    // a MISPLACED SECRET the config grammar fails loud on (`resolve_auth`). Nothing references
    // `stray` yet, so nothing used to check it.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/stray"
    )))
    .body(r#"{"module":"keys","token":{"env":"BUSBAR_STRAY_TOKEN"}}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "a `token:` on a non-`admin-tokens` module is a misplaced secret, referenced or not"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("meaningless on `module: keys`"),
        "the refusal states the placement rule: {body}"
    );
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/stray"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the refused PUT stored no credential"
    );

    // Same for a ceiling token the engine cannot boot with, on a provider in no chain: the chain-entry
    // rule in `config_validate` never sees this definition, so the DEFINITION-side check is the only
    // thing standing between the operator and an unbootable next restart.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/stray"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"none"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "an unreferenced provider's ceiling is checked where it is written"
    );

    // The legal shape is accepted.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/stray"
    )))
    .body(r#"{"module":"keys","max_admin_scope":"read-only"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// AN UNREFERENCED DEFINITION'S `module:` MUST NAME A MODULE THAT EXISTS. The sibling rules above
/// are VALUE-level (a token, a ceiling) and need only the definition itself; this one needs the
/// plugin REGISTRY, because a valid identity-provider module is either a built-in
/// (`BUILTIN_IDENTITY_PROVIDERS`) or a loaded `kind: auth` plugin. `export:` has had this check
/// since 1.5.3 (`resolve_export` refuses an unknown exporter and names the built-ins), but the
/// identity-provider side had nothing: `resolve_auth` is keyed off the RESOLVED chain and
/// `plugins_preflight` derived its auth refs from `auth.chain` alone, so a definition that nothing
/// references — the exact thing this endpoint writes — was checked by no layer at all. The API
/// answered 200 and stored a provider that can never authenticate anyone.
#[tokio::test]
async fn test_admin_v1_identity_provider_rejects_an_unknown_module() {
    let (dir, addr, handle) = {
        let (dir, _overlay, addr, handle) = named_map_app("unknown-module", false).await;
        (dir, addr, handle)
    };
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/typo"
    )))
    .body(r#"{"module":"not-a-real-idp"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "a `module:` naming nothing that exists must be refused where it is written"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    let msg = body["error"]["message"].as_str().unwrap_or_default();
    assert!(
        msg.contains("not-a-real-idp"),
        "the refusal names the unknown module: {body}"
    );
    assert!(
        msg.contains("keys") && msg.contains("admin-tokens"),
        "the refusal lists the valid modules, the way every other section's module refusal names \
         its whole valid set: {body}"
    );
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/typo"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the refused PUT stored nothing"
    );

    // The CONTROL: a built-in module through the identical path is still accepted, so the new rule
    // rejects the unknown name and nothing else.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/typo"
    )))
    .body(r#"{"module":"keys"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// DANGLING-REFERENCE GUARD: a DELETE that would leave another config section naming a definition
/// that no longer exists is refused as a TERMINAL `conflict` naming the referent — never applied
/// and then discovered at the next resolve. The fixture's base `auth.role_bindings` names
/// `corp-ad`, so creating that provider through the API and then deleting it is exactly the
/// dangling case.
#[tokio::test]
async fn test_admin_v1_identity_provider_delete_rejects_a_dangling_reference() {
    // `request-log-file` (K9b) and `prometheus` (K9d) are rows of the export axis, as a linked
    // build's are.
    linked_export_axis();
    let (dir, _overlay, addr, handle) = named_map_app("dangling", true).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };
    // Create the referenced provider (the fixture's `auth.admin_auth:` already names it, with no
    // definition anywhere but the overlay this PUT writes).
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .body(
        serde_json::json!({
            "module": "admin-tokens",
            "token": {"file": dir.join("corp.token").to_string_lossy()}
        })
        .to_string(),
    )
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);

    // … then try to delete it while `auth.role_bindings.corp-ad` still names it.
    let r = admin(client.delete(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(r.status().as_u16(), 409, "a dangling delete is refused");
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "conflict");
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("auth.admin_auth"),
        "the refusal NAMES the referent so an operator knows what to fix: {body}"
    );
    // Still live.
    let after = admin(client.get(format!(
        "http://{addr}/api/v1/admin/identity-providers/corp-ad"
    )))
    .send()
    .await
    .unwrap();
    assert_eq!(
        after.status().as_u16(),
        200,
        "the refused delete changed nothing"
    );

    // An UNREFERENCED definition deletes cleanly — the guard is about references, not about
    // refusing deletes.
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/spare")))
        .body(
            serde_json::json!({
                "module": "request-log-file",
                "settings": {"path": dir.join("spare.jsonl").to_string_lossy()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
    let r = admin(client.delete(format!("http://{addr}/api/v1/admin/export/spare")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        204,
        "an unreferenced definition deletes"
    );
    let after = admin(client.get(format!("http://{addr}/api/v1/admin/export/spare")))
        .send()
        .await
        .unwrap();
    assert_eq!(after.status().as_u16(), 404, "and is gone");
    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

fn publish_door(section: &str, settings: &str) -> PublishedDoor {
    use busbar_plugin_loader::dispatch::kinds::plane::{open_door, Plane};
    use busbar_plugin_loader::dispatch::{
        load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    crate::ensure_seam();
    let owner = busbar_kernel::plane::registry::plane_decl_for_config_section(section)
        .unwrap_or_else(|| panic!("a test-linked plane owns `{section}:`"));
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    let (instance, plane) = crate::test_seams::linked_doors()
        .iter()
        .find_map(|(label, door)| {
            let row = LinkedRow::of(*door).ok()?;
            let instance = format!("{label}-published");
            let plane = load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from(instance.as_str()),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: dispatcher.adopter(),
                    conns: busbar_plugin_loader::dispatch::ConnTable::Probe,
                },
            )
            .ok()?;
            (plane.served().section == owner.config_section).then_some((instance, plane))
        })
        .expect("the owning plane's door is test-linked");
    let snapshot = open_door(&plane, settings.as_bytes(), b"", None).expect("the door opens");
    let routes = snapshot
        .admin_routes
        .iter()
        .map(|r| busbar_kernel::plane_driver::serve::ServeRoute {
            verb: r.verb.clone(),
            target: r.target.clone(),
            flags: r.flags,
            audit_verb: r.audit_verb.clone(),
        })
        .collect();
    let audit_kind = plane.served().audit_kind.to_string();
    let calls = Arc::new(
        busbar_plugin_loader::dispatch::plane_calls::PlaneInstance::new(plane, dispatcher, 0),
    );
    busbar_kernel::plane_driver::serve::publish(
        busbar_kernel::plane_driver::serve::ServeTable {
            instance: instance.clone(),
            audit_kind,
            calls,
            caps: busbar_kernel::plane_driver::BufferCaps::default(),
            routes,
            records: None,
        },
        &[],
    )
    .expect("its admin routes publish");
    PublishedDoor(instance)
}

/// THE DOOR PLANE'S TRUST VERBS' DECLARED ERRORS, produced through the admin router by the door's
/// own `serve` op (ARCHITECT Q-L3B-VERBS; P3 DEL-MCP: the deleted engine's error-surface driver
/// witnessed these): an unregistered name is `404 not_found` on every verb, and `connect` on a
/// `passthrough` registration is `400 invalid_request` (its credential belongs to a caller, and an
/// operator's refresh has none).
async fn drive_door_verb_errors() {
    let _published = publish_door(
        "tools",
        r#"{"base-tools": {"url": "https://pass.example/rpc", "pin": {"mechanism": "pinned_pubkey", "key": "sha256/K="}, "upstream_credentials": "passthrough", "tools_allow": {"read": {"schema_hash": "sha256:aa"}}}}"#,
    );
    let (_dir, _overlay, addr, handle) = named_map_app("door-verbs", false).await;
    let client = reqwest::Client::new();
    let send = |method: reqwest::Method, path: &str| {
        client
            .request(method, format!("http://{addr}/api/v1/admin{path}"))
            .header("x-admin-token", "admintok")
            .send()
    };
    for (method, path) in [
        (reqwest::Method::POST, "/tools/nope/connect"),
        (reqwest::Method::GET, "/tools/nope/changes"),
        (reqwest::Method::GET, "/tools/nope/health"),
    ] {
        let r = send(method.clone(), path).await.unwrap();
        assert_eq!(r.status(), 404, "{method} {path}");
        let body: serde_json::Value = r.json().await.unwrap();
        assert_eq!(body.pointer("/error/code").unwrap(), "not_found", "{body}");
    }
    let r = send(reqwest::Method::POST, "/tools/base-tools/connect")
        .await
        .unwrap();
    assert_eq!(r.status(), 400);
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(
        body.pointer("/error/code").unwrap(),
        "invalid_request",
        "{body}"
    );
    handle.abort();
}

/// WITNESS DRIVER for the generic named-map surface: produces EVERY `(operation, ErrKind, Cond)`
/// triple `contract::taxonomy::declared_errors` claims for `/identity-providers` and `/export`, so
/// `declared_error_set_is_exactly_what_the_handlers_emit` can prove none of them is an over-claim.
/// Every emission on this surface names its condition (`err_json_cond`), so nothing here needs a
/// `COND_WITNESS_DEBT` row.
///
/// Batched: these are CONFIG-class mutations (10/min per principal — each rebuilds and swaps the
/// whole App), and a driver that walked the whole table on one fixture would measure the rate
/// limiter instead of the handlers. A fresh fixture carries a fresh limiter.
async fn drive_named_map_errors() {
    linked_export_axis();
    let big_settings = {
        let mut m = serde_json::Map::new();
        m.insert("blob".into(), serde_json::json!("x".repeat(70_000)));
        serde_json::json!({ "settings": m }).to_string()
    };
    let ok_def = |section: &str| match section {
        "identity-providers" => r#"{"module":"keys"}"#.to_string(),
        // The tools plane has no backing plugin, so its valid definition names no `module:` —
        // which is exactly the asymmetry `NamedMapSection::requires_module` exists to carry.
        "tools" => r#"{"url":"https://x/","pin":{"mechanism":"unpinned"}}"#.to_string(),
        // The agents plane's entries are NOT plugin instances, so a legal definition names a URL
        // and a pin rather than a module. That asymmetry is the reason `requires_module()` exists.
        "agents" => {
            r#"{"url":"https://agent.example/x","pin":{"mechanism":"unpinned"}}"#.to_string()
        }
        _ => r#"{"module":"prometheus","settings":{"buffer_seconds":30}}"#.to_string(),
    };
    // (label, method, relative path, If-Match, body, want status, want code)
    type Case = (
        String,
        &'static str,
        String,
        Option<&'static str>,
        Option<String>,
        u16,
        &'static str,
    );
    let mut cases: Vec<Case> = Vec::new();
    for (section, base) in [
        ("identity-providers", "base-idp"),
        ("export", "base-metrics"),
        ("tools", "base-tools"),
        ("agents", "base-agent"),
    ] {
        let c = |label: &str,
                 method: &'static str,
                 rel: String,
                 im: Option<&'static str>,
                 body: Option<String>,
                 status: u16,
                 code: &'static str|
         -> Case {
            (
                format!("{section}_{label}"),
                method,
                rel,
                im,
                body,
                status,
                code,
            )
        };
        cases.extend([
            // PUT — the upsert. Every declared Validation condition, plus the base-config guard.
            c(
                "put_malformed_body",
                "PUT",
                format!("/{section}/x"),
                None,
                Some("{".into()),
                400,
                "invalid_request",
            ),
            c(
                "put_bad_ifmatch",
                "PUT",
                format!("/{section}/x"),
                Some("not-a-version"),
                Some(ok_def(section)),
                400,
                "invalid_request",
            ),
            c(
                // On a plugin-instance section this is the empty-`module:` guard. On `tools:` there
                // is no `module:` at all, so the same document is refused by the typed
                // `deny_unknown_fields` parse — one status, two reasons, and both are the section's
                // own grammar rather than a hardcoded rule in the handler.
                "put_bad_definition",
                "PUT",
                format!("/{section}/x"),
                None,
                Some(if section == "agents" {
                    // A pin whose mechanism needs material and carries none. On the other sections
                    // the equivalent nonsense is an empty `module:`; the CONDITION being witnessed
                    // (`Validation/InvalidConfig`) is the same one either way.
                    r#"{"url":"https://agent.example/x","pin":{"mechanism":"jws_issuer_key"}}"#
                        .to_string()
                } else {
                    r#"{"module":""}"#.to_string()
                }),
                400,
                "invalid_request",
            ),
            c(
                "put_base_defined",
                "PUT",
                format!("/{section}/{base}"),
                None,
                Some(ok_def(section)),
                409,
                "conflict",
            ),
            c(
                "put_stale_ifmatch",
                "PUT",
                format!("/{section}/x"),
                Some("\"9999\""),
                Some(ok_def(section)),
                409,
                "version_conflict",
            ),
            // PATCH …/settings.
            c(
                "patch_malformed_body",
                "PATCH",
                format!("/{section}/{base}/settings"),
                None,
                Some("{".into()),
                400,
                "invalid_request",
            ),
            c(
                "patch_bad_ifmatch",
                "PATCH",
                format!("/{section}/{base}/settings"),
                Some("not-a-version"),
                Some(r#"{"settings":{}}"#.into()),
                400,
                "invalid_request",
            ),
            c(
                "patch_oversized_settings",
                "PATCH",
                format!("/{section}/{base}/settings"),
                None,
                Some(big_settings.clone()),
                400,
                "invalid_request",
            ),
            c(
                "patch_unknown",
                "PATCH",
                format!("/{section}/ghost/settings"),
                None,
                Some(r#"{"settings":{}}"#.into()),
                404,
                "not_found",
            ),
            c(
                "patch_base_defined",
                "PATCH",
                format!("/{section}/{base}/settings"),
                None,
                Some(r#"{"settings":{}}"#.into()),
                409,
                "conflict",
            ),
            c(
                "patch_stale_ifmatch",
                "PATCH",
                format!("/{section}/{base}/settings"),
                Some("\"9999\""),
                Some(r#"{"settings":{}}"#.into()),
                409,
                "version_conflict",
            ),
            // DELETE.
            c(
                "delete_bad_ifmatch",
                "DELETE",
                format!("/{section}/{base}"),
                Some("not-a-version"),
                None,
                400,
                "invalid_request",
            ),
            c(
                "delete_unknown",
                "DELETE",
                format!("/{section}/ghost"),
                None,
                None,
                404,
                "not_found",
            ),
            c(
                "delete_base_defined",
                "DELETE",
                format!("/{section}/{base}"),
                None,
                None,
                409,
                "conflict",
            ),
            c(
                "delete_stale_ifmatch",
                "DELETE",
                format!("/{section}/{base}"),
                Some("\"9999\""),
                None,
                409,
                "version_conflict",
            ),
            // The single-definition READ.
            c(
                "get_unknown",
                "GET",
                format!("/{section}/ghost"),
                None,
                None,
                404,
                "not_found",
            ),
        ]);
        if section == "identity-providers" {
            cases.push(c(
                "put_raises_trust_ceiling",
                "PUT",
                format!("/{section}/ceil"),
                None,
                Some(r#"{"module":"keys","max_admin_scope":"full"}"#.into()),
                409,
                "conflict",
            ));
        }
    }

    let client = reqwest::Client::new();
    for (batch_i, batch) in cases.chunks(8).enumerate() {
        let (dir, _overlay, addr, handle) =
            named_map_app(&format!("witness-{batch_i}"), false).await;
        for (label, method, rel, if_match, body, want_status, want_code) in batch {
            let mut req = client
                .request(
                    reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                    format!("http://{addr}/api/v1/admin{rel}"),
                )
                .header("x-admin-token", "admintok");
            if let Some(tag) = if_match {
                req = req.header("if-match", *tag);
            }
            if let Some(b) = body {
                req = req
                    .header("content-type", "application/json")
                    .body(b.clone());
            }
            let resp = req.send().await.unwrap();
            let status = resp.status().as_u16();
            let parsed: serde_json::Value = resp.json().await.unwrap();
            assert_eq!(
                status, *want_status,
                "{label}: expected {want_status}, got {status} ({parsed})"
            );
            assert_eq!(parsed["error"]["code"], *want_code, "{label}: {parsed}");
        }
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // NO DISK BASE: an EPHEMERAL busbar (started without config files) has no base truth to merge a
    // named-map change onto, so every write verb refuses up front — the condition the disk fixtures
    // above can never reach.
    //
    // ONE SERVER PER SECTION, and that is about the RATE LIMITER rather than isolation. Every verb
    // below is a CONFIG-class admin mutation, budgeted at 10/min PER PRINCIPAL, and failed attempts
    // spend the budget too (that is the anti-enumeration rule, working as designed). The section
    // list is now four long — the two 1.5.3 sections plus a plane section each for `tools:` and
    // `agents:` — so twelve probes against one server would start answering 429 at the eleventh and
    // the error taxonomy this test exists to pin would go unchecked from there on. The limiter is a
    // field on `App`, so a fresh fixture is a fresh budget; raising the limit instead would have
    // made the test pass by weakening the thing it shares with production.
    for section in ["identity-providers", "export", "tools", "agents"] {
        busbar_kernel::snapshot::init();
        let store = Arc::new(MemoryStore::new());
        let gov = gov_with_signer(store, Some("admintok".to_string()));
        let app = crate::new_test_app().governance(gov).build();
        let router = crate::build_router(app);
        let (addr, handle, _) = spin_up(router).await;
        {
            for (label, method, rel, body) in [
                (
                    "put",
                    "PUT",
                    format!("/{section}/x"),
                    Some(r#"{"module":"keys"}"#),
                ),
                (
                    "patch",
                    "PATCH",
                    format!("/{section}/x/settings"),
                    Some(r#"{"settings":{}}"#),
                ),
                ("delete", "DELETE", format!("/{section}/x"), None),
            ] {
                let mut req = client
                    .request(
                        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                        format!("http://{addr}/api/v1/admin{rel}"),
                    )
                    .header("x-admin-token", "admintok");
                if let Some(b) = body {
                    req = req.header("content-type", "application/json").body(b);
                }
                let resp = req.send().await.unwrap();
                let status = resp.status().as_u16();
                let parsed: serde_json::Value = resp.json().await.unwrap();
                assert_eq!(status, 400, "{section} {label} (ephemeral): {parsed}");
                assert_eq!(parsed["error"]["code"], "invalid_request");
            }
        }
        handle.abort();
    }

    // STILL REFERENCED: the dangling-delete conflict needs a config that already NAMES a provider
    // the overlay defines, so it gets its own fixture (see `write_named_map_fixture`).
    {
        let (dir, _overlay, addr, handle) = named_map_app("witness-dangling", true).await;
        let admin = |r: reqwest::RequestBuilder| {
            r.header("x-admin-token", "admintok")
                .header("content-type", "application/json")
        };
        let r = admin(client.put(format!(
            "http://{addr}/api/v1/admin/identity-providers/corp-ad"
        )))
        .body(
            serde_json::json!({
                "module": "admin-tokens",
                "token": {"file": dir.join("corp.token").to_string_lossy()}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
        assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);
        let r = admin(client.delete(format!(
            "http://{addr}/api/v1/admin/identity-providers/corp-ad"
        )))
        .send()
        .await
        .unwrap();
        let status = r.status().as_u16();
        let parsed: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            status, 409,
            "a dangling delete is a terminal conflict: {parsed}"
        );
        assert_eq!(parsed["error"]["code"], "conflict");

        // ...and the BULK twin, on the same fixture (the refused per-entry delete above left
        // `corp-ad` in place, which is exactly the state a dangling reset needs).
        //
        // This drives `DELETE /overlay/{section}`'s `Conflict/StillReferenced`. It has a test of
        // its own (`test_admin_v1_overlay_reset_named_map_refuses_a_dangling_reference`), and that
        // was not enough: the gate calls these drivers precisely SO THAT its verdict does not
        // depend on whether some other test ran, so a condition witnessed only by a sibling test is
        // witnessed nowhere as far as the gate is concerned. It read as an OVER-CLAIM — a
        // documented 409 nothing could produce — while the guard, and a passing test for it, were
        // both sitting right there. A driver that covers the per-entry case and skips its bulk twin
        // is the same "scoped to where the bug was first seen" shape the whole taxonomy exists to
        // catch.
        let r = admin(client.delete(format!(
            "http://{addr}/api/v1/admin/overlay/identity-providers"
        )))
        .send()
        .await
        .unwrap();
        let status = r.status().as_u16();
        let parsed: serde_json::Value = r.json().await.unwrap();
        assert_eq!(
            status, 409,
            "a bulk reset that would dangle a reference is a terminal conflict: {parsed}"
        );
        assert_eq!(parsed["error"]["code"], "conflict");
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// The driver above, as a test in its own right — so the named-map error surface is exercised even
/// when the class-level audit is filtered out of a run.
#[tokio::test]
async fn named_map_error_surface_answers_its_declared_taxonomy() {
    drive_named_map_errors().await;
}

/// CONFIG STABILITY: THE ADMIN API AND THE FILE PARSER MUST SHARE ONE GRAMMAR. A PUT body
/// carrying a field the section's `deny_unknown_fields` config struct rejects is exactly what
/// `config.yaml` would refuse at boot — so the API must refuse it too, loudly and BEFORE persisting.
///
/// It did not. The handler only did a generic `serde_json::Value` parse plus "is it an object with a
/// non-empty `module`", answered 200, wrote the document verbatim into the overlay, and then DROPPED
/// it at the rebuild (`apply_named_maps_to_deploy` swallowed the typed parse error into a
/// `tracing::error!`). The operator got a success for config that never took effect and vanished on
/// every subsequent read — two paths disagreeing about the one frozen 1.5.3 grammar.
#[tokio::test]
async fn test_admin_v1_named_map_put_rejects_what_the_file_parser_rejects() {
    linked_export_axis();
    let (dir, overlay, addr, handle) = named_map_app("typedparse", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| {
        r.header("x-admin-token", "admintok")
            .header("content-type", "application/json")
    };

    // `buffer` is not a field of `ExportDefCfg` (the operator meant `settings.buffer_seconds`).
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/spare")))
        .body(r#"{"module":"prometheus","buffer":30}"#)
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "an unknown field is the same loud reject config.yaml gives"
    );
    let body: serde_json::Value = r.json().await.unwrap();
    assert_eq!(body["error"]["code"], "invalid_request");
    let msg = body["error"]["message"].as_str().unwrap();
    assert!(
        msg.contains("buffer"),
        "the refusal carries serde's own message naming the offending field: {body}"
    );

    // NOTHING was persisted and nothing is readable — the reject happens before the overlay write.
    let after = admin(client.get(format!("http://{addr}/api/v1/admin/export/spare")))
        .send()
        .await
        .unwrap();
    assert_eq!(
        after.status().as_u16(),
        404,
        "the rejected definition was never stored"
    );
    if let Ok(bytes) = std::fs::read(&overlay) {
        let doc: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(
            doc["named_maps"]["export"]["spare"].is_null(),
            "the rejected definition is absent from the overlay: {doc}"
        );
    }

    // The SAME shape with the fields spelled correctly is accepted — this is a grammar check, not
    // a blanket refusal.
    let good = serde_json::json!({
        "module": "request-log-file",
        "settings": {"path": dir.join("spare.jsonl").to_string_lossy()}
    });
    let r = admin(client.put(format!("http://{addr}/api/v1/admin/export/spare")))
        .body(good.to_string())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200, "{:?}", r.text().await);

    // The identity-providers section speaks the same rule through the same generic path.
    let r = admin(client.put(format!(
        "http://{addr}/api/v1/admin/identity-providers/typo-idp"
    )))
    .body(r#"{"module":"keys","max_admin_scopes":"none"}"#)
    .send()
    .await
    .unwrap();
    assert_eq!(
        r.status().as_u16(),
        400,
        "the typed parse is per-section and driven by the section's own struct: {:?}",
        r.text().await
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

/// DISCOVERABILITY: an overlay-stored definition this binary cannot parse is DROPPED
/// at every rebuild. It used to be announced exactly once, at boot, in a log line — and the API read
/// surface answered 404 for the name, which is indistinguishable from "you never wrote it". An
/// operator who does not tail boot logs could not discover their own stored-but-inert config.
///
/// It is now surfaced through the READ, explicitly flagged (`unparseable` carries the parse error),
/// on both the collection and the single-entry read. The operator's data is only ever REPORTED —
/// never auto-deleted, never rewritten.
#[tokio::test]
async fn test_admin_v1_named_map_read_flags_an_unparseable_overlay_entry() {
    linked_export_axis();
    let (dir, overlay, addr, handle) = named_map_app("unparseable", false).await;
    let client = reqwest::Client::new();
    let admin = |r: reqwest::RequestBuilder| r.header("x-admin-token", "admintok");

    // An overlay holding a definition whose typed struct rejects it (a downgrade whose struct lost
    // the field, or a hand-edited overlay) — never applied, so absent from the live `export:` map.
    std::fs::write(
        &overlay,
        serde_json::json!({
            "version": 1,
            "named_maps": {
                "export": {
                    "ghost": {"module": "prometheus", "from_the_future": true,
                              "settings": {"buffer_seconds": 60}}
                }
            }
        })
        .to_string(),
    )
    .unwrap();

    let body: serde_json::Value = admin(client.get(format!("http://{addr}/api/v1/admin/export")))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let ghost = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|i| i["name"] == "ghost")
        .unwrap_or_else(|| {
            panic!("the stored-but-inert entry is discoverable in the list: {body}")
        });
    assert!(
        ghost["unparseable"]
            .as_str()
            .is_some_and(|e| e.contains("from_the_future")),
        "and is EXPLICITLY flagged with the parse error rather than looking live: {ghost}"
    );
    assert_eq!(
        ghost["module"], "prometheus",
        "the operator's own raw document is projected back so they can see what they wrote"
    );

    // The single-entry read answers the flagged view rather than a 404 for a name that is sitting in
    // the operator's own overlay.
    let one = admin(client.get(format!("http://{addr}/api/v1/admin/export/ghost")))
        .send()
        .await
        .unwrap();
    assert_eq!(one.status().as_u16(), 200);
    let one: serde_json::Value = one.json().await.unwrap();
    assert!(one["unparseable"].is_string(), "{one}");

    // A LIVE definition is never flagged.
    let base: serde_json::Value =
        admin(client.get(format!("http://{addr}/api/v1/admin/export/base-metrics")))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    assert!(
        base["unparseable"].is_null(),
        "a parseable, live definition carries no flag: {base}"
    );

    handle.abort();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn key_usage_over_an_unpriced_class_answers_named_409() {
    assert_unpriced_usage_read_is_named("/api/v1/admin/keys/").await;
}

#[tokio::test]
async fn group_usage_over_an_unpriced_class_answers_named_409() {
    assert_unpriced_usage_read_is_named("/api/v1/admin/groups/").await;
}

#[tokio::test]
async fn admin_usage_over_an_unpriced_class_answers_named_409() {
    assert_unpriced_usage_read_is_named("/api/v1/admin/usage").await;
}
