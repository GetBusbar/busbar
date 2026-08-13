// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar/src/admin/v1/service.rs`.

use super::*;
use crate::config::{HookCfg, HookKind, PromptAccess, UserAccess};
use crate::test_support::TestApp;

fn hook(kind: HookKind, global: bool) -> HookCfg {
    HookCfg {
        kind,
        plugin: "test-hook".to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        priority: 0,
        at: None,
        settings: serde_json::Map::new(),
        on_empty: None,
        global,
        default: false,
        signals: Vec::new(),
        groups: Vec::new(),
        phase: Vec::new(),
    }
}

/// `build_with_hook` registers a GLOBAL tap into the registry + global wiring AND re-resolves it
/// into the fired tap transports — so after the caller swaps the returned snapshot, the tap is live.
/// Lanes/store are shared (unchanged), proving the store-constraint-free subset.
#[test]
fn build_with_hook_registers_and_wires_global_tap() {
    let Some(env) = crate::test_support::test_hook_env(&["test-hook"], Default::default()) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = TestApp::new().hook_env(env).build();
    assert_eq!(app.tap_hooks.len(), 0, "fixture starts with no taps");
    let next = build_with_hook(&app, "logger", hook(HookKind::Tap, true))
        .expect("a valid global tap registers");
    assert!(next.hook_registry.contains_key("logger"));
    assert!(
        next.global_hooks.iter().any(|n| n == "logger"),
        "global tap wired into global_hooks"
    );
    assert_eq!(
        next.tap_hooks.len(),
        1,
        "the global tap re-resolved into the fired tap transports (live after swap)"
    );
    // Live state is shared, not rebuilt: the store Arc is the SAME instance.
    assert!(
        std::sync::Arc::ptr_eq(&app.store, &next.store),
        "the store (live breaker state) is preserved across the apply, not re-indexed"
    );
}

/// A PUT that REPLACES a `global: true` hook with `global: false` must
/// DE-WIRE it from the global fan-out — remove it from `global_hooks` AND drop it from the fired
/// transports — so the demotion actually takes effect. The prior code only ever APPENDED on
/// `global: true` and never removed, so a demoted hook kept firing on every request and still
/// reported `global: true`.
#[test]
fn build_with_hook_demotes_global_false_removes_wiring() {
    let Some(env) = crate::test_support::test_hook_env(&["test-hook"], Default::default()) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = TestApp::new().hook_env(env).build();
    // Register a GLOBAL tap, then PUT the same name with global: false.
    let promoted =
        build_with_hook(&app, "logger", hook(HookKind::Tap, true)).expect("global tap registers");
    assert!(promoted.global_hooks.iter().any(|n| n == "logger"));
    assert_eq!(promoted.tap_hooks.len(), 1, "global tap is live");

    let demoted = build_with_hook(&promoted, "logger", hook(HookKind::Tap, false))
        .expect("demotion to global: false is a valid same-grant replace");
    assert!(
        !demoted.global_hooks.iter().any(|n| n == "logger"),
        "a global: false PUT must REMOVE the hook from global_hooks, not leave it firing"
    );
    assert_eq!(
        demoted.tap_hooks.len(),
        0,
        "the demoted hook must drop out of the fired global tap transports"
    );
    assert!(
        demoted.hook_registry.contains_key("logger"),
        "the hook definition itself survives — only its global membership is dropped"
    );
}

/// A hook registered through the ADMIN API must become live on the OTHER TWO PLANES too, not only
/// on the pool plane.
///
/// The failure this pins is specific and silent: an operator writes `tools.<server>.hooks: [screen]`
/// in the file and registers the `screen` DEFINITION later through the API. At boot the name
/// resolved to nothing (no definition yet), so the server's gate chain was empty — and without
/// `reresolve_plane_gates` the register would answer `200 OK` while that chain stayed empty
/// forever, leaving the operator believing a control is attached that is not. The pool plane's own
/// three `resolve_*` calls exist for exactly this reason; this is the same fail-open on the two
/// planes that gained firing sites in 1.6.0.
#[test]
fn build_with_hook_makes_an_mcp_attach_live() {
    let Some(env) = crate::test_support::test_hook_env(&["test-hook"], Default::default()) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let server = crate::mcp::config::McpServerDefCfg {
        url: "https://mcp.internal/fs".to_string(),
        pin: crate::mcp::config::ServerPinCfg {
            mechanism: crate::mcp::config::McpPinMechanism::CertSpki,
            key: Some("sha256/PIN==".to_string()),
        },
        refresh_ttl: None,
        timeout: None,
        tools_allow: Default::default(),
        prompts_allow: Default::default(),
        resources_allow: Default::default(),
        resource_templates_allow: Default::default(),
        transport: None,
        aud: None,
        grants: Default::default(),
        max_input_required_rounds: None,
        max_caller_ask_rounds: None,
        allow_private: false,
        token_exchange: None,
        upstream_credentials: None,
        hooks: vec!["screen".to_string()],
    };
    let app = TestApp::new()
        .hook_env(env)
        .mcp_server("fs", server)
        .build();
    assert!(
        !app.mcp_server_gates.contains_key("fs"),
        "the attach names a hook no registry entry defines yet, so it resolves to nothing"
    );

    let next = build_with_hook(&app, "screen", hook(HookKind::Gate, false))
        .expect("a valid gate registers");
    assert_eq!(
        next.mcp_server_gates
            .get("fs")
            .map(|g| g.len())
            .unwrap_or_default(),
        1,
        "registering the DEFINITION must make the server's existing attach resolve — a 200 OK that \
         leaves the chain empty is an operator told a control is attached when it is not"
    );
}

/// The `settings` map size cap enforced by PATCH must ALSO gate
/// register/PUT (both funnel through `build_with_hook`) — else an unbounded map could be
/// registered/replaced, bloating the durable state and the reconnect path the cap protects.
#[test]
fn build_with_hook_caps_oversized_settings() {
    let app = TestApp::new().build();
    // Just over the key cap.
    let mut too_many = hook(HookKind::Tap, false);
    for i in 0..=MAX_SETTINGS_KEYS {
        too_many
            .settings
            .insert(format!("k{i}"), serde_json::json!(1));
    }
    assert!(
        matches!(
            build_with_hook(&app, "big", too_many),
            Err(AdminError::Validation(_))
        ),
        "a settings map over the key cap must reject at register/PUT, not just PATCH"
    );

    // Just over the byte cap (few keys, huge value).
    let mut too_big = hook(HookKind::Tap, false);
    too_big.settings.insert(
        "blob".to_string(),
        serde_json::json!("x".repeat(MAX_SETTINGS_BYTES + 1)),
    );
    assert!(matches!(
        build_with_hook(&app, "big", too_big),
        Err(AdminError::Validation(_))
    ));

    // A modest settings map still registers.
    let mut ok = hook(HookKind::Tap, false);
    ok.settings
        .insert("level".to_string(), serde_json::json!("info"));
    assert!(build_with_hook(&app, "fine", ok).is_ok());
}

/// The hook NAME (a registry key persisted to the config overlay + every
/// audit row) must be length-capped, like the key id / settings map — else a `hooks-register`
/// token could POST a megabyte-long name and bloat the durable overlay / audit / reconnect path.
#[test]
fn build_with_hook_caps_oversized_name() {
    let app = TestApp::new().build();
    let huge = "n".repeat(MAX_HOOK_NAME_LEN + 1);
    assert!(
        matches!(
            build_with_hook(&app, &huge, hook(HookKind::Tap, false)),
            Err(AdminError::Validation(_))
        ),
        "a name over the cap must reject"
    );
    // A name AT the cap is fine.
    let at_cap = "n".repeat(MAX_HOOK_NAME_LEN);
    assert!(build_with_hook(&app, &at_cap, hook(HookKind::Tap, false)).is_ok());
}

/// Validation is fail-closed BEFORE any mutation: `prompt: rw` on a tap and a missing transport
/// both reject with `invalid_request`.
#[test]
fn build_with_hook_rejects_invalid_definitions() {
    let app = TestApp::new().build();
    let mut rw_tap = hook(HookKind::Tap, false);
    rw_tap.prompt = PromptAccess::Rw;
    assert!(matches!(
        build_with_hook(&app, "t", rw_tap),
        Err(AdminError::Validation(_))
    ));

    let mut no_transport = hook(HookKind::Gate, false);
    no_transport.plugin = String::new();
    assert!(matches!(
        build_with_hook(&app, "x", no_transport),
        Err(AdminError::Validation(_))
    ));

    let empty_name = hook(HookKind::Gate, false);
    assert!(matches!(
        build_with_hook(&app, "  ", empty_name),
        Err(AdminError::Validation(_))
    ));
}

/// GRANT IMMUTABILITY: re-registering an existing hook with DIFFERENT kind/prompt/user is a
/// `conflict`; re-registering with the SAME grants is allowed (idempotent). Closes the escalation
/// path (register `prompt: no`, then widen to `rw`).
#[test]
fn build_with_hook_enforces_grant_immutability() {
    let app = TestApp::new().build();
    // First registration: a gate with prompt: no.
    let after_first = build_with_hook(&app, "g", hook(HookKind::Gate, false)).unwrap();

    // Re-register the SAME name with a WIDENED grant (prompt: rw) → conflict.
    let mut escalated = hook(HookKind::Gate, false);
    escalated.prompt = PromptAccess::Rw;
    assert!(
        matches!(
            build_with_hook(&after_first, "g", escalated),
            Err(AdminError::Conflict(_))
        ),
        "widening a grant in place must be a conflict"
    );

    // Re-register with the SAME grants → allowed (idempotent).
    assert!(
        build_with_hook(&after_first, "g", hook(HookKind::Gate, false)).is_ok(),
        "re-registering with identical grants is allowed"
    );
}

// ── plugin admin surface (tarball world) ────────────────────────────────────────────────────

use busbar_plugin_sign::{sign, Manifest, SigningKey};

/// A unique temp plugins directory for one test (isolated so parallel tests never collide).
fn tmp_plugins_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!(
        "busbar-plugin-admin-{}-{n}-{tag}",
        std::process::id(),
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A well-formed manifest for tests (sha256/signature completed by `sign`).
fn test_manifest(name: &str, alias: &str, publisher: &str, version: &str) -> Manifest {
    Manifest {
        name: name.into(),
        alias: alias.into(),
        kind: "store".into(),
        version: version.into(),
        publisher: publisher.into(),
        abi_version: *busbar_plugin_loader::supported_abi("store")
            .iter()
            .max()
            .expect("store abi"),
        sha256: String::new(),
        signature: String::new(),
        description: String::new(),
        homepage: String::new(),
        license: String::new(),
        needs: Default::default(),
        settings_schema: None,
        schema_derived: false,
        host: None,
    }
}

/// Package a signed plugin tarball in memory.
fn signed_tarball(key: &SigningKey, m: Manifest, lib: &[u8]) -> Vec<u8> {
    let m = sign(key, m, lib);
    busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap()
}

/// Build a service over an App whose plugins dir + `plugins.*` posture are the given ones.
fn svc_with(dir: std::path::PathBuf, cfg: crate::config::PluginsCfg) -> AdminService {
    let app = TestApp::new().plugins_dir(dir).plugins_cfg(cfg).build();
    AdminService::new(app)
}

/// The STRICT default posture: no publishers, no opt-ins.
fn strict_posture() -> crate::config::PluginsCfg {
    crate::config::PluginsCfg::default()
}

/// A permissive posture (allow_unsigned): an unsigned upload installs "unverified".
fn unsigned_ok_posture() -> crate::config::PluginsCfg {
    let mut cfg = crate::config::PluginsCfg::default();
    cfg.trust.allow_unsigned = true;
    cfg
}

/// A posture that allowlists one third-party publisher key.
fn publisher_posture(name: &str, key: &SigningKey) -> crate::config::PluginsCfg {
    let mut cfg = crate::config::PluginsCfg::default();
    cfg.trust.publishers = vec![crate::config::PluginPublisher {
        name: name.into(),
        public_key: hex::encode(key.verifying_key().to_bytes()),
    }];
    cfg
}

// ── POST /plugins/inspect ──────────────────────────────────────────────────────────────────

/// A trusted, unsigned-under-`allow_unsigned` candidate previews cleanly: the SAME response
/// shape `GET /plugins/{name}/schema` carries, PLUS `name`/`version`/`kind` — and NOTHING is
/// written to disk (an inspect is stateless: no install, no conflict check).
#[test]
fn inspect_previews_a_trusted_candidate_without_installing() {
    let dir = tmp_plugins_dir("inspect-ok");
    let mut m = test_manifest("acme-store-preview", "preview", "acme", "1.0.0");
    m.kind = "secret".into();
    m.abi_version = *busbar_plugin_loader::supported_abi("secret")
        .iter()
        .max()
        .expect("secret abi");
    m.settings_schema = Some(
        serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {"key": {"type": "string", "x-busbar-secret": true}},
        })
        .to_string(),
    );
    m.sha256 = busbar_plugin_sign::sha256_hex(b"lib bytes");
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", b"lib bytes").unwrap();
    let svc = svc_with(dir.clone(), unsigned_ok_posture());

    let v = svc.inspect_plugin(&tarball).expect("inspect succeeds");
    assert_eq!(v["name"], "acme-store-preview");
    assert_eq!(v["version"], "1.0.0");
    assert_eq!(v["kind"], "secret");
    assert_eq!(v["trust"], "unverified");
    assert_eq!(v["source"], "manifest");
    assert_eq!(v["schema_error"], serde_json::Value::Null);
    assert!(
        v["schema"].is_object(),
        "schema round-trips as real JSON: {v}"
    );
    // `secret` kind defaults to restart-required.
    assert_eq!(v["restart_required_default"], true);

    // NOTHING was written — inspect never installs, never touches `plugins.dir`.
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "inspect must not write anything to disk"
    );
}

/// An UNTRUSTED (unsigned, strict posture) candidate is REPORTED as `trust: "rejected"`, not
/// refused with an error — the whole point of inspect is previewing what a not-yet-trusted
/// plugin would need without ever installing or executing it.
#[test]
fn inspect_reports_rejected_trust_rather_than_erroring() {
    let dir = tmp_plugins_dir("inspect-rejected");
    let mut m = test_manifest("acme-store-untrusted", "untrusted", "acme", "1.0.0");
    m.sha256 = busbar_plugin_sign::sha256_hex(b"lib bytes");
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", b"lib bytes").unwrap();
    // STRICT posture: no publishers allowlisted, no allow_unsigned opt-in.
    let svc = svc_with(dir, strict_posture());

    let v = svc
        .inspect_plugin(&tarball)
        .expect("inspect still succeeds");
    assert_eq!(v["trust"], "rejected");
    assert_eq!(v["name"], "acme-store-untrusted");
}

/// Structurally invalid bytes (not a tarball at all) are a `Validation` error, same as install's
/// structural gate — inspect shares the exact same in-memory unpack path.
#[test]
fn inspect_rejects_invalid_tarball() {
    let dir = tmp_plugins_dir("inspect-garbage");
    let svc = svc_with(dir, unsigned_ok_posture());
    assert!(matches!(
        svc.inspect_plugin(b"not a tarball at all"),
        Err(AdminError::Validation(_))
    ));
}

/// A decoded tarball over `MAX_TARBALL_FILE_BYTES` is refused BEFORE `unpack` ever runs — a
/// hard cap on the raw upload, checked before touching the decoder.
#[test]
fn inspect_rejects_oversized_tarball_before_unpacking() {
    let dir = tmp_plugins_dir("inspect-oversized");
    let svc = svc_with(dir, unsigned_ok_posture());
    let huge = vec![0u8; (busbar_plugin_loader::tarball::MAX_TARBALL_FILE_BYTES + 1) as usize];
    let err = svc.inspect_plugin(&huge).unwrap_err();
    assert!(
        matches!(&err, AdminError::Validation(msg) if msg.contains("byte cap")),
        "got {err:?}"
    );
}

/// A manifest whose `settings_schema` nests far deeper than the depth cap is refused as a
/// `schema_error` on the response (never a hard error, and never a parser stack-overflow risk —
/// the depth guard runs BEFORE `serde_json::from_str` ever sees the text). A pathological
/// SCHEMA document is a distinct attack from a pathological tarball.
#[test]
fn inspect_bounds_pathological_schema_nesting_depth() {
    let dir = tmp_plugins_dir("inspect-depth-bomb");
    let mut m = test_manifest("acme-store-depthbomb", "depthbomb", "acme", "1.0.0");
    // A tiny document that nests far past the depth cap: `[[[[...]]]]`.
    let bomb = format!("{}{}", "[".repeat(500), "]".repeat(500));
    m.settings_schema = Some(bomb);
    m.sha256 = busbar_plugin_sign::sha256_hex(b"lib bytes");
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", b"lib bytes").unwrap();
    let svc = svc_with(dir, unsigned_ok_posture());

    let v = svc
        .inspect_plugin(&tarball)
        .expect("inspect itself still succeeds");
    assert_eq!(v["schema"], serde_json::Value::Null);
    let err = v["schema_error"].as_str().expect("schema_error is set");
    assert!(err.contains("nests deeper"), "got {err:?}");
}

/// Install rejects a filename that isn't a bare `.tar.gz` name (path traversal / wrong
/// extension) BEFORE any bytes touch disk.
#[test]
fn install_rejects_bad_filenames() {
    let dir = tmp_plugins_dir("badname");
    let svc = svc_with(dir.clone(), unsigned_ok_posture());
    for bad in [
        "../escape.tar.gz",
        "sub/dir.tar.gz",
        "no_extension",
        "plain.so",
        "",
    ] {
        assert!(
            matches!(
                svc.install_store_plugin(bad, b"bytes"),
                Err(AdminError::Validation(_))
            ),
            "filename `{bad}` must reject"
        );
    }
    // Nothing was written for any rejected name.
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
}

/// Install rejects an upload that is not a valid plugin tarball, and leaves NOTHING behind.
#[test]
fn install_rejects_invalid_tarball() {
    let dir = tmp_plugins_dir("nontarball");
    let svc = svc_with(dir.clone(), unsigned_ok_posture());
    assert!(
        matches!(
            svc.install_store_plugin("x.tar.gz", b"garbage, not a tarball"),
            Err(AdminError::Validation(_))
        ),
        "non-tarball bytes must fail structural validation"
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
}

/// A VALIDLY-SIGNED but structurally malformed manifest (bad `kind`) is a 400 — structural
/// validation is independent of trust.
#[test]
fn install_rejects_signed_but_malformed_manifest() {
    let dir = tmp_plugins_dir("malformed");
    let key = SigningKey::from_bytes(&[5u8; 32]);
    let mut m = test_manifest("acme-store-x", "x", "acme", "1.0.0");
    m.kind = "widget".into();
    let tarball = signed_tarball(&key, m, b"lib bytes");
    let svc = svc_with(dir.clone(), publisher_posture("acme", &key));
    let err = svc.install_store_plugin("x.tar.gz", &tarball).unwrap_err();
    assert!(
        matches!(&err, AdminError::Validation(msg) if msg.contains("kind")),
        "got {err:?}"
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
}

/// Under the STRICT default posture, an UNSIGNED upload is rejected as a conflict naming the
/// opt-in flag, and nothing is written. The endpoint is MANIFEST-ONLY: the (junk) library
/// bytes are never executed, so pushing over the API cannot bypass the trust model.
#[test]
fn install_strict_posture_rejects_unsigned() {
    let dir = tmp_plugins_dir("strict");
    let lib = b"\x7fELF junk that would crash if ever dlopened";
    let mut m = test_manifest("acme-store-x", "x", "acme", "1.0.0");
    m.sha256 = busbar_plugin_sign::sha256_hex(lib);
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();
    let svc = svc_with(dir.clone(), strict_posture());
    let err = svc.install_store_plugin("x.tar.gz", &tarball).unwrap_err();
    assert!(
        matches!(&err, AdminError::Conflict(msg) if msg.contains("allow_third_party")
                || msg.contains("allow_unsigned")),
        "the rejection names the opt-in flag: {err:?}"
    );
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
}

/// End-to-end install of an unsigned tarball under `allow_unsigned`: installs "unverified",
/// the catalog reports it, reload reports only the dynamic set, and `remove` deletes it.
/// (No dlopen anywhere — the lib bytes are junk on purpose.)
#[test]
fn install_catalog_remove_roundtrip() {
    let dir = tmp_plugins_dir("roundtrip");
    let svc = svc_with(dir.clone(), unsigned_ok_posture());
    let lib = b"junk lib bytes";
    let mut m = test_manifest("acme-store-junk", "junkstore", "acme", "1.0.0");
    m.sha256 = busbar_plugin_sign::sha256_hex(lib);
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();

    let view = svc
        .install_store_plugin("junk.tar.gz", &tarball)
        .expect("an unsigned tarball installs under allow_unsigned");
    assert_eq!(view.trust, "unverified");
    assert_eq!(view.name, "acme-store-junk");
    assert!(dir.join("junk.tar.gz").exists(), "tarball published");

    // Catalog: the memory head + our dynamic plugin.
    let cat = svc.store_plugin_catalog();
    assert_eq!(cat[0].name, "memory");
    let dyn_row = cat
        .iter()
        .find(|p| p.loader == "dynamic-library")
        .expect("dynamic plugin in catalog");
    assert_eq!(dyn_row.valid, Some(true));
    assert_eq!(dyn_row.name, "acme-store-junk");
    assert_eq!(dyn_row.target.as_deref(), Some("junk.tar.gz"));
    assert_eq!(dyn_row.trust, Some("unverified"));

    // Reload reports only the dynamic set (no memory head).
    let reload = svc.reload_store_plugins().unwrap();
    assert!(reload.plugins.iter().all(|p| p.loader == "dynamic-library"));
    assert_eq!(reload.plugins.len(), 1);

    // Remove deletes it; a second remove is a 404.
    svc.remove_store_plugin("junk.tar.gz").expect("remove");
    assert!(!dir.join("junk.tar.gz").exists());
    assert!(matches!(
        svc.remove_store_plugin("junk.tar.gz"),
        Err(AdminError::NotFound { .. })
    ));
}

/// The amplification this test guards against: `store_plugin_catalog` (behind `GET
/// /plugins?type=store`) used to fully re-read and re-unpack EVERY tarball in the plugins
/// directory on EVERY call, and that GET is deliberately unmetered by the admin rate limiter
/// (reads never reach `auth::classify_for_rate_limit`) — so nothing bounded how often a caller
/// could pay that cost. Repeated GETs against an UNCHANGED directory must now reuse the cached
/// scan (one `misses` increment total), while a real change (installing a new plugin) must
/// still be picked up on the very next call with no explicit invalidation call anywhere.
#[test]
fn catalog_repeat_gets_reuse_the_cached_scan() {
    let dir = tmp_plugins_dir("cache-reuse");
    let svc = svc_with(dir.clone(), unsigned_ok_posture());
    let lib = b"junk lib bytes";
    let mut m = test_manifest("acme-store-cache", "cachestore", "acme", "1.0.0");
    m.sha256 = busbar_plugin_sign::sha256_hex(lib);
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();
    svc.install_store_plugin("cache.tar.gz", &tarball)
        .expect("install");

    // Repeated GETs against an unchanged directory: only the FIRST one is a real scan.
    for _ in 0..5 {
        let cat = svc.store_plugin_catalog();
        assert!(cat.iter().any(|p| p.name == "acme-store-cache"));
    }
    let misses_after_repeats = catalog_cache().lock().unwrap()[&dir].misses;
    assert_eq!(
        misses_after_repeats, 1,
        "5 repeat GETs over an unchanged directory must cost exactly 1 real scan"
    );

    // A real change (a second install) is picked up on the very next call, no explicit
    // invalidation call required.
    let lib2 = b"junk lib bytes two";
    let mut m2 = test_manifest("acme-store-cache-2", "cachestore2", "acme", "1.0.0");
    m2.sha256 = busbar_plugin_sign::sha256_hex(lib2);
    let tarball2 = busbar_plugin_loader::tarball::package(&m2, "lib.so", lib2).unwrap();
    svc.install_store_plugin("cache2.tar.gz", &tarball2)
        .expect("install");

    let cat = svc.store_plugin_catalog();
    assert!(
        cat.iter().any(|p| p.name == "acme-store-cache-2"),
        "the newly installed plugin is visible on the very next GET"
    );
    let misses_after_change = catalog_cache().lock().unwrap()[&dir].misses;
    assert_eq!(
        misses_after_change, 2,
        "a real directory change must invalidate the cache and cost exactly 1 more scan"
    );
}

/// `list_plugins("store")`'s catalog read — the fingerprint I/O AND, on a cold cache, the full
/// tarball scan — must not park the single worker of a `worker_threads = 1` multi-thread
/// runtime. Mirrors `admin::audit`'s `valve_write_through_does_not_park_the_reactor` proof
/// shape, with one deliberate difference: that precedent proves its point with a DETERMINISTIC
/// delay (`SlowAuditStore` sleeps a fixed 500ms), not real I/O volume — this test originally
/// relied on 2000 real signed tarballs being "genuinely slow… on ordinary hardware", but
/// inline-vs-offloaded changes only WHETHER the scan blocks other work, never how long the scan
/// itself takes, so on fast-enough CI hardware the real scan could finish under the 300ms
/// threshold even with the bug present (`spawn_blocking` removed), silently defeating the
/// proof. `catalog_scan_test_hooks::set_delay` injects a fixed, hardware-independent minimum
/// scan duration well above the threshold, so the distinction is observable regardless of how
/// fast the machine is; the 2000 real tarballs stay (smaller count would do for timing alone)
/// purely to keep the `page.items.len() > 2000` correctness assertion meaningful.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn list_plugins_store_scan_does_not_park_the_reactor() {
    let dir = tmp_plugins_dir("no-park");
    let key = SigningKey::from_bytes(&[2u8; 32]);
    for i in 0..2000 {
        let lib = format!("lib bytes {i}").into_bytes();
        let m = test_manifest(
            &format!("acme-store-{i}"),
            &format!("s{i}"),
            "acme",
            "1.0.0",
        );
        let tarball = signed_tarball(&key, m, &lib);
        std::fs::write(dir.join(format!("p{i}.tar.gz")), &tarball).unwrap();
    }
    let app = TestApp::new()
        .plugins_dir(dir.clone())
        .plugins_cfg(publisher_posture("acme", &key))
        .build();
    let svc = AdminService::new(app);

    // Deterministic floor, independent of hardware speed: if the scan ran inline on the
    // reactor, the concurrently-spawned sleep below could not be polled until AT LEAST this
    // long had passed, comfortably clearing the 300ms assertion threshold on any hardware.
    // Scoped to `dir` (see `catalog_scan_test_hooks`), so it cannot slow down any other test's
    // concurrently-running scan of a different directory.
    let _delay_guard =
        catalog_scan_test_hooks::set_delay(dir, std::time::Duration::from_millis(400));

    let scanner =
        tokio::spawn(async move { svc.list_plugins("store").await.expect("catalog read ok") });
    let start = std::time::Instant::now();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let elapsed = start.elapsed();
    let page = scanner.await.unwrap();
    assert!(
        elapsed < std::time::Duration::from_millis(300),
        "a 50ms sleep took {elapsed:?} — the catalog scan parked the reactor"
    );
    assert!(
        page.items.len() > 2000,
        "the scan actually ran and produced rows: got {}",
        page.items.len()
    );
}

/// `store_plugin_catalog_async`'s `match` on
/// `spawn_blocking`'s result has an `Err(join_err)` arm for when the CLOSURE ITSELF PANICS (not
/// just returns an error) — it logs and falls back to the compiled-in `memory`-only row rather
/// than propagating the panic to the caller. That arm was untested: nothing in the suite ever
/// made the blocking closure actually panic. `catalog_scan_test_hooks::set_panic` injects a
/// real, deliberate panic into the scan (a genuine unwind on the `spawn_blocking` thread,
/// exactly the scenario the fallback exists for) rather than exploiting some unrelated
/// malformed-input defect, so this proves the fallback ARM, not an accidental bug elsewhere.
#[tokio::test]
async fn store_plugin_catalog_async_survives_a_spawn_blocking_panic() {
    let dir = tmp_plugins_dir("panic-fallback");
    let app = TestApp::new()
        .plugins_dir(dir.clone())
        .plugins_cfg(unsigned_ok_posture())
        .build();
    let svc = AdminService::new(app);

    // Scoped to `dir` (see `catalog_scan_test_hooks`) so no other concurrently-running test's
    // scan of a different directory is affected by this panic.
    let _panic_guard = catalog_scan_test_hooks::set_panic(dir);

    let page = svc
        .list_plugins("store")
        .await
        .expect("a panicking scan must fall back gracefully, never propagate as an error");
    assert_eq!(
        page.items.len(),
        1,
        "the panic fallback must be exactly the one compiled-in `memory` row: {:?}",
        page.items
    );
    assert_eq!(page.items[0].name, "memory");
    assert_eq!(page.items[0].loader, "compiled-in");
}

/// A caller that cannot even ACQUIRE
/// `CATALOG_SCAN_GATE` within `CATALOG_SCAN_GATE_WAIT` (a scan holding the gate that never
/// returns, e.g. a stale/hung `plugins_dir`
/// mount) must be answered with a clear, retryable error rather than hang forever. Runs on
/// PAUSED virtual time (`start_paused = true` + `tokio::time::advance`) so the test proves the
/// bound without a real multi-second sleep.
#[tokio::test(start_paused = true)]
async fn store_plugin_catalog_async_times_out_when_gate_is_held() {
    let dir = tmp_plugins_dir("gate-timeout");
    let app = TestApp::new()
        .plugins_dir(dir)
        .plugins_cfg(unsigned_ok_posture())
        .build();
    let svc = AdminService::new(app);

    // Hold the gate ourselves for the life of this test — standing in for a scan that started
    // and never came back (the wedged-mount scenario), which is exactly what a caller queued
    // behind `CATALOG_SCAN_GATE.lock().await` with no timeout would see forever.
    let _held = CATALOG_SCAN_GATE.lock().await;

    let call = tokio::spawn(async move { svc.list_plugins("store").await });
    tokio::time::advance(CATALOG_SCAN_GATE_WAIT + std::time::Duration::from_millis(1)).await;
    let result = call.await.expect("caller task must not panic");
    assert!(
        matches!(result, Err(AdminError::Unavailable(_))),
        "a caller that cannot acquire the gate within the wait bound must get a clear, \
             retryable error instead of hanging: {result:?}"
    );
}

/// The single-flight bound: N concurrent
/// `list_plugins("store")` callers that ALL miss the cache at the same instant (the very first
/// reads against a freshly-built `App`, before any entry exists — e.g. right after boot or a
/// config reload) must cost exactly ONE real `inventory_tarballs` scan, not one per caller. Every
/// caller still gets a correct, complete catalog — single-flighting must never mean 9 of the 10
/// see a truncated or stale result.
#[tokio::test]
async fn list_plugins_store_single_flights_concurrent_misses() {
    let dir = tmp_plugins_dir("single-flight");
    let lib = b"junk lib bytes";
    let mut m = test_manifest("acme-store-sf", "sfstore", "acme", "1.0.0");
    m.sha256 = busbar_plugin_sign::sha256_hex(lib);
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();
    std::fs::write(dir.join("sf.tar.gz"), &tarball).unwrap();

    let app = TestApp::new()
        .plugins_dir(dir.clone())
        .plugins_cfg(unsigned_ok_posture())
        .build();

    let mut tasks = Vec::new();
    for _ in 0..10 {
        let app = app.clone();
        tasks.push(tokio::spawn(async move {
            AdminService::new(app)
                .list_plugins("store")
                .await
                .expect("catalog read ok")
        }));
    }
    for t in tasks {
        let page = t.await.unwrap();
        assert!(
            page.items.iter().any(|p| p.name == "acme-store-sf"),
            "every one of the 10 concurrent callers must see the real (not truncated) catalog"
        );
    }

    let misses = catalog_cache().lock().unwrap()[&dir].misses;
    assert_eq!(
            misses, 1,
            "10 concurrent cache-miss callers must single-flight into exactly 1 real scan, got {misses}"
        );
}

/// `CATALOG_CACHE` has no eviction of its own beyond the
/// fingerprint/trust `key` match, so an entry for a `plugins_dir` the process no longer serves
/// would sit in the map forever. Mirrors how `admin/mod.rs` proves `idempotency_cache`'s own
/// TTL+`retain()` bound (reaching into the cache directly — there is no public "age an entry"
/// API, by design, same as the idempotency cache has none): age an entry past
/// `CATALOG_CACHE_TTL_SECS` by rewriting its `inserted_at` stamp, then prove the NEXT cache
/// access anywhere (not necessarily a read of the SAME directory — `retain()` runs on every
/// call, exactly like `idempotency_cache`'s prune-before-check) sweeps it.
#[test]
fn catalog_cache_ttl_prunes_stale_entries() {
    let dir = tmp_plugins_dir("ttl");
    let svc = svc_with(dir.clone(), unsigned_ok_posture());
    let _ = svc.store_plugin_catalog();
    assert!(
        catalog_cache().lock().unwrap().contains_key(&dir),
        "the scan above must have seeded a cache entry"
    );

    // Age the entry past the TTL directly.
    {
        let mut cache = catalog_cache().lock().unwrap();
        let entry = cache.get_mut(&dir).expect("entry present");
        entry.inserted_at = crate::store::now().saturating_sub(CATALOG_CACHE_TTL_SECS + 1);
    }

    // A cache access against a DIFFERENT directory still prunes the aged entry — `retain()` runs
    // unconditionally at the top of every `store_plugin_catalog` call, not scoped to `dir`.
    let other_dir = tmp_plugins_dir("ttl-other");
    let other_svc = svc_with(other_dir.clone(), unsigned_ok_posture());
    let _ = other_svc.store_plugin_catalog();

    assert!(
        !catalog_cache().lock().unwrap().contains_key(&dir),
        "an entry older than CATALOG_CACHE_TTL_SECS must be pruned on the next cache access"
    );
}

/// A bare `now.saturating_sub(inserted_at)` avoids an
/// underflow PANIC when `inserted_at` is in the future (a backward system-clock jump) but
/// silently floors the computed age at 0 — the entry then looks brand-new and never ages out
/// until real time catches back up to `inserted_at`, quietly defeating the TTL bound for that
/// one entry. An `inserted_at` in the future means the entry's true age is UNKNOWN, and this
/// treats unknown-age as stale (the safe default), not as ageless.
#[test]
fn catalog_cache_future_inserted_at_is_treated_as_stale() {
    let dir = tmp_plugins_dir("ttl-future-clock");
    let svc = svc_with(dir.clone(), unsigned_ok_posture());
    let _ = svc.store_plugin_catalog();
    assert!(
        catalog_cache().lock().unwrap().contains_key(&dir),
        "the scan above must have seeded a cache entry"
    );

    // Simulate a backward clock jump: the entry's `inserted_at` is now AHEAD of `now()`.
    {
        let mut cache = catalog_cache().lock().unwrap();
        let entry = cache.get_mut(&dir).expect("entry present");
        entry.inserted_at = crate::store::now() + CATALOG_CACHE_TTL_SECS + 1;
    }

    // Any cache access prunes it — a future `inserted_at` must not make the entry immortal.
    let other_dir = tmp_plugins_dir("ttl-future-clock-other");
    let other_svc = svc_with(other_dir.clone(), unsigned_ok_posture());
    let _ = other_svc.store_plugin_catalog();

    assert!(
        !catalog_cache().lock().unwrap().contains_key(&dir),
        "an entry whose inserted_at is in the future (backward clock jump) must be treated as \
             stale, not ageless"
    );
}

/// The staleness scenario this guards against.
/// FIRST, an empty-but-READABLE plugins dir caches fine (unchanged behavior — same as a MISSING
/// dir, both legitimately mean "no plugins"). THEN the directory becomes UNREADABLE (permission
/// denied) with its CONTENTS unchanged — the exact case the old `unwrap_or_default()` collapsed
/// to the SAME fingerprint as the empty dir, serving the stale cached `[]` forever instead of
/// the real `INVALID` row. The fixed version must never serve that stale cache and must surface
/// the real `INVALID: ...` row on every read while unreadable, not just the first.
#[cfg(unix)]
#[test]
fn catalog_unreadable_dir_does_not_serve_stale_cache() {
    use std::os::unix::fs::PermissionsExt;

    let dir = tmp_plugins_dir("unreadable");
    let svc = svc_with(dir.clone(), unsigned_ok_posture());

    // Empty + readable: caches fine, no dynamic-library rows — the unchanged half of the fix.
    let cat = svc.store_plugin_catalog();
    assert!(
        cat.iter().all(|p| p.loader != "dynamic-library"),
        "an empty, readable plugins dir has no dynamic-library rows"
    );
    assert!(
        catalog_cache().lock().unwrap().contains_key(&dir),
        "an empty dir's (empty) scan is cached, exactly like a missing dir would be"
    );

    // Restoring permissions with a bare `set_permissions` call at the
    // END of the test left a window — the two `store_plugin_catalog()` reads below AND the
    // `read_dir` probe above all run un-guarded, and a panic (e.g. an assertion failure inside
    // `store_plugin_catalog`, or any future change to it) during that window would leave the
    // temp dir at `0o000` permanently: nothing later ever restores it, potentially breaking
    // this test's OWN cleanup or a later test that reuses the same `temp_dir()` infrastructure.
    // An RAII guard restores the original mode on drop — including on an early return or a
    // panic unwinding through this scope — so there is no code path that leaves the directory
    // unreadable.
    struct RestorePermsOnDrop<'a> {
        dir: &'a std::path::Path,
        mode: u32,
    }
    impl Drop for RestorePermsOnDrop<'_> {
        fn drop(&mut self) {
            let _ = std::fs::set_permissions(self.dir, std::fs::Permissions::from_mode(self.mode));
        }
    }

    let original_mode = std::fs::metadata(&dir).unwrap().permissions().mode();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
    let _restore = RestorePermsOnDrop {
        dir: &dir,
        mode: original_mode,
    };

    // Some environments (containers running as root) ignore permission bits entirely — skip
    // rather than false-fail if `read_dir` still succeeds. `_restore` drops (restoring
    // permissions) when this early return unwinds the scope.
    if std::fs::read_dir(&dir).is_ok() {
        eprintln!("skip: running with privileges that bypass directory permission bits");
        return;
    }

    let cat_after = svc.store_plugin_catalog();
    // And every SUBSEQUENT read while STILL unreadable surfaces the SAME real row again — the
    // scan is never memoized while it's failing, so there is no stale state to fall back to.
    let cat_again = svc.store_plugin_catalog();

    let row = cat_after
        .iter()
        .find(|p| p.loader == "dynamic-library")
        .expect("an unreadable dir must surface a row, never silently serve the stale empty cache");
    assert_eq!(row.valid, Some(false));
    assert!(
            row.error.as_deref().is_some_and(|e| e.starts_with("INVALID:")),
            "must be the real INVALID row surfaced by inventory_tarballs/discover, not stale data: {row:?}"
        );

    let row_again = cat_again
        .iter()
        .find(|p| p.loader == "dynamic-library")
        .expect("a second read while still unreadable surfaces the row again, every time");
    assert_eq!(row_again.error, row.error);
}

/// ROLLBACK RESOLUTION (1.5.0), the EXPLICIT-downgrade core: a TRUSTED third-party artifact whose
/// version is BELOW its configured base floor — which the AUTOMATIC path (`install`) rejects as an
/// anti-downgrade — is ACCEPTED by `resolve_plugin_rollback`, because the rollback lowers the floor
/// to the target's own version. It returns the target manifest + the merged pin map (prior pins
/// preserved, this plugin pinned to the target version).
#[test]
fn rollback_resolves_a_trusted_below_floor_target_and_merges_pins() {
    let dir = tmp_plugins_dir("rollback-ok");
    let acme = SigningKey::from_bytes(&[11u8; 32]);
    // Base posture: allowlist acme AND floor this plugin at 2.0.0.
    let mut cfg = publisher_posture("acme", &acme);
    cfg.min_versions
        .insert("acme-store-x".to_string(), "2.0.0".to_string());
    let svc = svc_with(dir.clone(), cfg);

    // The PRIOR artifact at 1.4.0 (the rollback target) sits in the plugins dir.
    let lib = b"prior artifact bytes";
    let tarball = signed_tarball(
        &acme,
        test_manifest("acme-store-x", "x", "acme", "1.4.0"),
        lib,
    );
    std::fs::write(dir.join("old.tar.gz"), &tarball).unwrap();

    // The automatic install path REJECTS the below-floor artifact (anti-downgrade).
    let install_err = svc
        .install_store_plugin("old.tar.gz", &tarball)
        .unwrap_err();
    assert!(
        matches!(install_err, AdminError::Conflict(_)),
        "automatic install of a below-floor artifact is a conflict, got {install_err:?}"
    );

    // The EXPLICIT rollback resolves it, lowering the floor to 1.4.0, and merges the pin onto a
    // pre-existing pin for a DIFFERENT plugin (which must be preserved).
    let prior =
        std::collections::BTreeMap::from([("other-plugin".to_string(), "3.0.0".to_string())]);
    let (manifest, pins) = svc
        .resolve_plugin_rollback("old.tar.gz", &prior)
        .expect("rollback resolves the trusted below-floor target");
    assert_eq!(manifest.name, "acme-store-x");
    assert_eq!(manifest.version, "1.4.0");
    assert_eq!(
        pins.get("acme-store-x").map(String::as_str),
        Some("1.4.0"),
        "this plugin is pinned to the target version"
    );
    assert_eq!(
        pins.get("other-plugin").map(String::as_str),
        Some("3.0.0"),
        "a prior pin for another plugin is preserved"
    );
}

/// ROLLBACK is FAIL-CLOSED: an ABSENT target is a 404, and an UNTRUSTED target (unsigned under a
/// strict posture) is refused even with the floor lowered — a rollback authenticates the OPERATOR,
/// never the ARTIFACT. Nothing is pinned in either case.
#[test]
fn rollback_is_fail_closed_on_absent_or_untrusted_target() {
    let dir = tmp_plugins_dir("rollback-closed");
    let svc = svc_with(dir.clone(), strict_posture());
    let empty = std::collections::BTreeMap::new();

    // Absent file → NotFound.
    assert!(matches!(
        svc.resolve_plugin_rollback("nope.tar.gz", &empty),
        Err(AdminError::NotFound { .. })
    ));

    // An UNSIGNED artifact present in the dir, under the STRICT posture: trust refuses it even for
    // a rollback (the floor was lowered, but the signature/opt-in gate still fails).
    let lib = b"unsigned prior artifact";
    let mut m = test_manifest("acme-store-x", "x", "acme", "1.4.0");
    m.sha256 = busbar_plugin_sign::sha256_hex(lib);
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();
    std::fs::write(dir.join("unsigned.tar.gz"), &tarball).unwrap();
    let err = svc
        .resolve_plugin_rollback("unsigned.tar.gz", &empty)
        .unwrap_err();
    assert!(
        matches!(err, AdminError::Conflict(_)),
        "an untrusted rollback target is refused (a rollback never launders trust), got {err:?}"
    );
}

/// SECURITY: under the DEFAULT (strict) posture, an unsigned tarball present in the plugins dir
/// is reported present + `rejected` by the catalog WITHOUT ever being `dlopen`ed — the catalog
/// path is manifest-only (pure data), so the junk library bytes here can never execute.
#[test]
fn catalog_does_not_dlopen_an_untrusted_plugin() {
    let dir = tmp_plugins_dir("untrusted-catalog");
    let svc = svc_with(dir.clone(), strict_posture());
    let lib = b"\x7fELF definitely not a loadable library";
    let mut m = test_manifest("acme-store-evil", "evil", "acme", "1.0.0");
    m.sha256 = busbar_plugin_sign::sha256_hex(lib);
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();
    std::fs::write(dir.join("evil.tar.gz"), &tarball).unwrap();

    let cat = svc.store_plugin_catalog();
    let row = cat
        .iter()
        .find(|p| p.target.as_deref() == Some("evil.tar.gz"))
        .expect("the untrusted plugin is listed in the catalog");
    assert_eq!(
        row.trust,
        Some("rejected"),
        "an unsigned plugin under the strict default posture is reported rejected"
    );
    assert_eq!(row.valid, Some(false), "and it is not loadable");
    assert!(
        row.error.as_deref().is_some_and(|e| e.contains("SKIPPED")),
        "the exact skip reason is surfaced: {:?}",
        row.error
    );
}

/// A SIGNED upload from an allowlisted third-party publisher installs as `trusted`, and the
/// catalog reports the signed metadata + trusted verdict.
#[test]
fn install_signed_is_trusted() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let lib = b"signed lib bytes";
    let tarball = signed_tarball(
        &key,
        test_manifest("acme-store-sqlite", "acmesqlite", "acme", "2.1.0"),
        lib,
    );
    let dir = tmp_plugins_dir("signed");
    let svc = svc_with(dir.clone(), publisher_posture("acme", &key));

    let view = svc
        .install_store_plugin("acme.tar.gz", &tarball)
        .expect("a signed, allowlisted upload installs under the strict posture");
    assert_eq!(view.trust, "trusted");
    assert_eq!(view.publisher.as_deref(), Some("acme"));
    assert_eq!(view.version.as_deref(), Some("2.1.0"));
    assert_eq!(view.name, "acme-store-sqlite");

    let cat = svc.store_plugin_catalog();
    let row = cat
        .iter()
        .find(|p| p.loader == "dynamic-library")
        .expect("dynamic plugin");
    assert_eq!(row.trust, Some("trusted"));
    assert_eq!(row.publisher.as_deref(), Some("acme"));
    assert_eq!(row.version.as_deref(), Some("2.1.0"));
    assert_eq!(row.name, "acme-store-sqlite");
}

/// ANTI-DOWNGRADE at the ADMIN INSTALL boundary: a `plugins.min_versions` floor rejects a
/// VALIDLY-SIGNED but older release of the same plugin (keyed on the manifest NAME) — a
/// rollback/replay is a `409`, nothing is written. The release at/above the floor installs.
#[test]
fn install_downgraded_version_is_rejected_by_floor() {
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let lib = b"lib bytes";
    let mut cfg = publisher_posture("acme", &key);
    cfg.min_versions
        .insert("acme-store-sqlite".to_string(), "2.0.0".to_string());
    let dir = tmp_plugins_dir("downgrade");
    let svc = svc_with(dir.clone(), cfg);

    // A validly-signed 1.9.0 is below the 2.0.0 floor -> rejected, nothing published.
    let old = signed_tarball(
        &key,
        test_manifest("acme-store-sqlite", "acmesqlite", "acme", "1.9.0"),
        lib,
    );
    let err = svc.install_store_plugin("old.tar.gz", &old).unwrap_err();
    assert!(
        matches!(&err, AdminError::Conflict(msg) if msg.contains("anti-downgrade")),
        "got {err:?}"
    );
    assert!(!dir.join("old.tar.gz").exists());

    // The current 2.1.0 clears the floor and installs as trusted.
    let cur = signed_tarball(
        &key,
        test_manifest("acme-store-sqlite", "acmesqlite", "acme", "2.1.0"),
        lib,
    );
    let view = svc
        .install_store_plugin("cur.tar.gz", &cur)
        .expect("a signed release at/above the floor installs");
    assert_eq!(view.trust, "trusted");
    assert_eq!(view.version.as_deref(), Some("2.1.0"));
}

/// A signed upload whose publisher is NOT allowlisted is untrusted; under the strict default it
/// is a conflict (rejected), and nothing is written.
#[test]
fn install_unknown_publisher_rejected() {
    let key = SigningKey::from_bytes(&[3u8; 32]);
    let tarball = signed_tarball(
        &key,
        test_manifest("stranger-store-x", "strangerx", "stranger", "1.0.0"),
        b"lib",
    );
    let dir = tmp_plugins_dir("unknownpub");
    let svc = svc_with(dir.clone(), strict_posture());
    assert!(matches!(
        svc.install_store_plugin("x.tar.gz", &tarball),
        Err(AdminError::Conflict(_))
    ));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
}

/// CONFLICT at the ADMIN INSTALL boundary: an upload whose alias collides with a DIFFERENT
/// already-installed loadable plugin is a `409` naming both ("can't use valkey and a
/// third-party valkey"); overwriting the SAME plugin (same name, same file) is a legal upgrade.
#[test]
fn install_alias_conflict_is_rejected() {
    let key = SigningKey::from_bytes(&[9u8; 32]);
    let dir = tmp_plugins_dir("conflict");
    let svc = svc_with(dir.clone(), publisher_posture("acme", &key));

    let first = signed_tarball(
        &key,
        test_manifest("acme-store-valkey", "valkey", "acme", "1.0.0"),
        b"lib a",
    );
    svc.install_store_plugin("first.tar.gz", &first)
        .expect("first install");

    // A DIFFERENT plugin claiming the same alias -> conflict naming both.
    let clash = signed_tarball(
        &key,
        test_manifest("other-store-valkey", "valkey", "acme", "1.0.0"),
        b"lib b",
    );
    let err = svc
        .install_store_plugin("clash.tar.gz", &clash)
        .unwrap_err();
    assert!(
        matches!(&err, AdminError::Conflict(msg)
                if msg.contains("acme-store-valkey") && msg.contains("other-store-valkey")),
        "names both plugins: {err:?}"
    );
    assert!(!dir.join("clash.tar.gz").exists());

    // Upgrading the SAME plugin in place (same name, same file) is allowed.
    let upgrade = signed_tarball(
        &key,
        test_manifest("acme-store-valkey", "valkey", "acme", "1.1.0"),
        b"lib a v2",
    );
    svc.install_store_plugin("first.tar.gz", &upgrade)
        .expect("same-name overwrite is a legal upgrade");
}

// ---- groups read surface ----

use crate::config::groups::{ChildDefault, LimitMetric, LimitWindow};
use crate::config::{GroupCfg, LimitCfg};

fn budget(cents: u64, per: LimitWindow) -> LimitCfg {
    LimitCfg {
        metric: LimitMetric::Budget,
        amount: cents,
        per: Some(per),
        scope: None,
        on_exhaust: None,
        downgrade_to: None,
    }
}

/// `list_groups` projects every `groups:` entry (name-sorted by the BTreeMap), faithfully
/// carrying parent, enabled, the ordered limits, and the `child_default` budget template.
#[tokio::test]
async fn list_groups_projects_the_limit_tree() {
    let team = GroupCfg {
        limits: vec![budget(20_000, LimitWindow::Month)],
        child_default: Some(ChildDefault {
            limits: vec![budget(2_000, LimitWindow::Month)],
        }),
        ..Default::default()
    };
    let bob = GroupCfg {
        parent: Some("team".into()),
        limits: vec![budget(3_000, LimitWindow::Month)],
        ..Default::default()
    };
    let app = TestApp::new()
        .group("team", team)
        .group("user:bob", bob)
        .build();
    let svc = AdminService::new(app);

    let page = svc
        .list_groups(0, crate::admin::v1::contract::LIST_LIMIT_DEFAULT)
        .await
        .expect("list ok");
    // BTreeMap order: "team" < "user:bob".
    assert_eq!(page.items.len(), 2);
    let team = &page.items[0];
    assert_eq!(team.name, "team");
    assert_eq!(team.parent, None);
    assert!(team.enabled);
    assert_eq!(team.limits.len(), 1);
    assert_eq!(team.limits[0].metric, "budget");
    assert_eq!(team.limits[0].amount, 20_000);
    assert_eq!(team.limits[0].per, Some("month"));
    // The child_default template projects as an explicit limit list.
    let cd = team.child_default.as_ref().expect("child_default present");
    assert_eq!(cd.len(), 1);
    assert_eq!(cd[0].amount, 2_000);

    let bob = &page.items[1];
    assert_eq!(bob.name, "user:bob");
    assert_eq!(bob.parent.as_deref(), Some("team"));
    assert!(bob.child_default.is_none());
}

/// `GET /groups` is a GROWABLE collection (unlike `/pools`/`/models`/`/hooks`, which are bounded
/// by static config, `plan_mint_group` auto-provisions a leaf group per self-service key mint), so
/// it must obey the SAME `?limit=`/`?cursor=` cursor envelope every other growable list
/// (keys/audit/config-versions) does — never a single unbounded page. A `limit` below the total
/// bounds the page and sets `next_cursor`; feeding that cursor back resumes exactly where the
/// prior page ended; the final page carries `next_cursor: None`.
#[tokio::test]
async fn list_groups_is_cursor_paginated() {
    let mut builder = TestApp::new();
    for i in 0..5 {
        builder = builder.group(
            &format!("g{i}"),
            GroupCfg {
                limits: vec![budget(1_000, LimitWindow::Month)],
                ..Default::default()
            },
        );
    }
    let app = builder.build();
    let svc = AdminService::new(app);

    let p1 = svc.list_groups(0, 2).await.expect("list ok");
    assert_eq!(
        p1.items.len(),
        2,
        "a `limit` below the total must bound the page"
    );
    let names: Vec<&str> = p1.items.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["g0", "g1"], "BTreeMap order: name-sorted");
    let c1 = p1
        .next_cursor
        .as_deref()
        .expect("more rows remain -> a next_cursor is present");
    let start2 = crate::admin::v1::contract::decode_offset_cursor(c1).expect("valid cursor");

    let p2 = svc.list_groups(start2, 2).await.expect("list ok");
    assert_eq!(p2.items.len(), 2);
    let names: Vec<&str> = p2.items.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["g2", "g3"]);
    let c2 = p2.next_cursor.as_deref().expect("one row remains");
    let start3 = crate::admin::v1::contract::decode_offset_cursor(c2).expect("valid cursor");

    let p3 = svc.list_groups(start3, 2).await.expect("list ok");
    assert_eq!(p3.items.len(), 1, "final page holds the remainder");
    let names: Vec<&str> = p3.items.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["g4"]);
    assert!(
        p3.next_cursor.is_none(),
        "last page has no next_cursor: {p3:?}"
    );
}

/// `get_group` returns one entry by name; an unknown name is `not_found`.
#[tokio::test]
async fn get_group_by_name_and_not_found() {
    let app = TestApp::new()
        .group(
            "acme",
            GroupCfg {
                limits: vec![budget(5_000_000, LimitWindow::Month)],
                ..Default::default()
            },
        )
        .build();
    let svc = AdminService::new(app);

    let g = svc.get_group("acme").await.expect("found");
    assert_eq!(g.name, "acme");
    assert_eq!(g.limits[0].amount, 5_000_000);

    let err = svc.get_group("ghost").await.unwrap_err();
    assert!(
        matches!(&err, AdminError::NotFound { what: msg, .. } if msg.contains("ghost")),
        "unknown group is not_found: {err:?}"
    );
}

/// A team ceiling with a per-user leaf beneath it — the base tree the mutation tests build on.
fn team_app() -> Arc<App> {
    TestApp::new()
        .group(
            "team",
            GroupCfg {
                limits: vec![budget(20_000, LimitWindow::Month)],
                ..Default::default()
            },
        )
        .build()
}

/// `build_with_group` creates a valid leaf, bumps the version, and rebuilds the cost model so the
/// new group's limits are live in the enforcement projection (the "raise a user's budget" path).
#[test]
fn build_with_group_creates_leaf_and_rebuilds_cost() {
    let app = team_app();
    let bob = GroupCfg {
        parent: Some("team".into()),
        limits: vec![budget(3_000, LimitWindow::Month)],
        ..Default::default()
    };
    let next = build_with_group(&app, "user:bob", bob).expect("valid leaf");
    assert_eq!(next.config_version, app.config_version.wrapping_add(1));
    assert!(next.groups_registry.contains_key("user:bob"));
    // The rebuilt cost model sees the new leaf AND its parent chain (parent index resolved).
    let leaf = next
        .cost
        .group_named("user:bob")
        .expect("leaf in cost model");
    assert!(leaf.parent.is_some(), "leaf's parent chain resolved");
    // The parent's own ceiling is still present (cost rebuilt the WHOLE tree, not just the leaf).
    assert!(next.cost.group_named("team").is_some());
}

/// A group whose `parent` names a nonexistent group is rejected at the door (validate_groups),
/// changing nothing — a 400 `invalid_request`.
#[test]
fn build_with_group_rejects_dangling_parent() {
    let app = team_app();
    let orphan = GroupCfg {
        parent: Some("nonexistent".into()),
        ..Default::default()
    };
    let Err(err) = build_with_group(&app, "orphan", orphan) else {
        panic!("dangling parent must be rejected");
    };
    assert!(
        matches!(&err, AdminError::Validation(m) if m.contains("orphan")),
        "dangling parent is a validation error: {err:?}"
    );
}

#[test]
fn build_with_group_rejects_empty_name() {
    let app = team_app();
    let Err(err) = build_with_group(&app, "   ", GroupCfg::default()) else {
        panic!("empty name must be rejected");
    };
    assert!(matches!(err, AdminError::Validation(_)));
}

/// Deleting a leaf removes it from the registry and the rebuilt cost model.
#[test]
fn build_without_group_removes_leaf() {
    // Build a tree that already contains the leaf.
    let app = TestApp::new()
        .group(
            "team",
            GroupCfg {
                limits: vec![budget(20_000, LimitWindow::Month)],
                ..Default::default()
            },
        )
        .group(
            "user:bob",
            GroupCfg {
                parent: Some("team".into()),
                limits: vec![budget(3_000, LimitWindow::Month)],
                ..Default::default()
            },
        )
        .build();
    let next = build_without_group(&app, "user:bob", 0).expect("leaf removable");
    assert!(!next.groups_registry.contains_key("user:bob"));
    assert!(next.cost.group_named("user:bob").is_none());
    assert!(next.cost.group_named("team").is_some());
}

/// Deleting a group that still PARENTS another is a 409 conflict — never silently orphan the child.
#[test]
fn build_without_group_conflict_when_still_a_parent() {
    let app = TestApp::new()
        .group(
            "team",
            GroupCfg {
                limits: vec![budget(20_000, LimitWindow::Month)],
                ..Default::default()
            },
        )
        .group(
            "user:bob",
            GroupCfg {
                parent: Some("team".into()),
                ..Default::default()
            },
        )
        .build();
    let Err(err) = build_without_group(&app, "team", 0) else {
        panic!("deleting a still-referenced parent must conflict");
    };
    assert!(
        matches!(&err, AdminError::Conflict(m) if m.contains("team")),
        "deleting a still-referenced parent is a conflict: {err:?}"
    );
}

#[test]
fn build_without_group_not_found() {
    let app = team_app();
    let Err(err) = build_without_group(&app, "ghost", 0) else {
        panic!("unknown group must be not_found");
    };
    assert!(matches!(&err, AdminError::NotFound { what: m, .. } if m.contains("ghost")));
}

/// Deleting a group that virtual keys still charge through is a 409 conflict — an
/// orphaned `key.group` would fail that key CLOSED at every admission, so the delete is blocked
/// (re-bind or delete the keys first) rather than silently orphaning them.
#[test]
fn build_without_group_conflict_when_keys_still_bound() {
    use crate::governance::{GovState, MemoryStore};
    use busbar_api::Store as _;
    let store = std::sync::Arc::new(MemoryStore::new());
    store
        .put_key(&crate::governance::VirtualKey {
            id: "vk_bound".to_string(),
            generation_hash: "h:vk_bound".to_string(),
            name: "bound".to_string(),
            allowed_scopes: None,
            enabled: true,
            created_at: 0,
            group: Some("team".to_string()),
            labels: Default::default(),
            expires_at: None,
            deleted_at: None,
            revision: 1,
        })
        .unwrap();
    let gov = Arc::new(GovState::new(store, None).unwrap());
    let app = TestApp::new()
        .group(
            "team",
            GroupCfg {
                limits: vec![budget(20_000, LimitWindow::Month)],
                ..Default::default()
            },
        )
        .governance(gov)
        .build();
    // The COUNT is the caller's job now (it is a blocking store read; see `count_keys_bound_to`,
    // executed on `spawn_blocking` inside the delete transaction). Drive the pure guard with the
    // count that helper would have produced for this fixture.
    let bound = count_keys_bound_to(&app, "team").expect("count readable");
    assert_eq!(bound, 1, "one key is bound to `team`");
    let Err(err) = build_without_group(&app, "team", bound) else {
        panic!("deleting a group with bound keys must conflict");
    };
    assert!(
        matches!(&err, AdminError::Conflict(m) if m.contains("team") && m.contains("bound")),
        "bound-key delete is a conflict naming the count: {err:?}"
    );
}

// ---- group usage read ----

use crate::governance::{GovState, MemoryStore, TierTokens, VirtualKey};

/// The fixture group: a group-wide requests cap (day), a group-wide budget (month), and a
/// POOL-SCOPED budget on `frontier` (month) — three distinct `(window, pool?)` enforcement
/// buckets from three limits.
fn usage_group_cfg() -> GroupCfg {
    let limit = |metric, amount, per, pool: Option<&str>| LimitCfg {
        metric,
        amount,
        per: Some(per),
        scope: pool.map(busbar_api::ScopeRef::pool),
        on_exhaust: None,
        downgrade_to: None,
    };
    GroupCfg {
        limits: vec![
            limit(LimitMetric::Requests, 5, LimitWindow::Day, None),
            limit(LimitMetric::Budget, 1_000, LimitWindow::Month, None),
            limit(
                LimitMetric::Budget,
                500,
                LimitWindow::Month,
                Some("frontier"),
            ),
        ],
        ..Default::default()
    }
}

/// A cost model carrying `groups` and a rate card pricing model `m` at 10 micro-units per
/// token (in and out) — 1 cent per 1_000 tokens, so the derived-spend assertions are round.
fn usage_cost(groups: &std::collections::BTreeMap<String, GroupCfg>) -> crate::cost::CostModel {
    let card = std::collections::BTreeMap::from([(
        "m".to_string(),
        crate::config::RateEntryCfg {
            input_utok: 10.0,
            output_utok: 10.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
        },
    )]);
    crate::cost::CostModel::resolve_parts(Some(&card), 0, groups)
}

fn usage_key(group: &str) -> VirtualKey {
    VirtualKey {
        id: "vk_usage_probe".to_string(),
        generation_hash: "h:vk_usage_probe".to_string(),
        name: "usage-probe".to_string(),
        allowed_scopes: None,
        enabled: true,
        created_at: 0,
        group: Some(group.to_string()),
        labels: Default::default(),
        expires_at: None,
        deleted_at: None,
        revision: 1,
    }
}

fn input_toks(n: u64) -> TierTokens {
    TierTokens {
        input: n,
        output: 0,
        cache_read: 0,
        cache_write: 0,
    }
}

/// `get_group_usage` returns ONE row per `(window, pool?)` enforcement bucket. Usage is
/// driven through the REAL admission/accrual seam (`try_admit` + `record_usage`, the same path
/// the proxy charges), so the read proves: the pool-scoped bucket accounts ONLY its pool's
/// traffic, the group-wide buckets account everything, caps are projected from the limits, and
/// `budget_remaining_cents = cap − derived spend` (ledger × the current rate card).
#[tokio::test]
async fn get_group_usage_splits_window_pool_buckets_and_derives_remaining() {
    let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
    let gov = Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).unwrap());
    let app = TestApp::new()
        .group("acme", usage_group_cfg())
        .cost(usage_cost(&groups))
        .governance(gov.clone())
        .build();

    // One request through `frontier` (100k tokens = 100 cents), one through `value` (50k =
    // 50 cents). The frontier bucket must see only the first; the group-wide buckets both.
    let k = usage_key("acme");
    let now = crate::store::now();
    gov.try_admit(&app.cost, &k, "frontier", now)
        .expect("frontier request admits");
    gov.record_usage(&app.cost, &k, "frontier", "m", &input_toks(100_000), now);
    gov.try_admit(&app.cost, &k, "value", now)
        .expect("value request admits");
    gov.record_usage(&app.cost, &k, "value", "m", &input_toks(50_000), now);

    let svc = AdminService::new(app);
    let view = svc.get_group_usage("acme").await.expect("usage read");
    assert_eq!(view.group, "acme");
    assert!(view.enabled);
    assert!(view.as_of >= now, "as_of is the read instant");
    assert_eq!(
        view.buckets.len(),
        3,
        "three (window, pool?) buckets: {:?}",
        view.buckets
    );
    let find = |window: &str, pool: Option<&str>| {
        view.buckets
            .iter()
            .find(|b| b.window == window && b.pool.as_deref() == pool)
            .unwrap_or_else(|| panic!("bucket ({window}, {pool:?}) missing: {:?}", view.buckets))
    };

    // (day, group-wide) — the requests cap's bucket: both admissions land; no budget cap ⇒
    // no remaining (never a fabricated 0).
    let day = find("day", None);
    assert_eq!(day.requests, 2);
    assert_eq!(day.tokens, 150_000);
    assert_eq!(day.requests_cap, Some(5));
    assert_eq!(day.budget_cap, None);
    assert_eq!(day.budget_remaining_cents, None);

    // (month, group-wide) — EVERY pool's traffic accounts here.
    let month = find("month", None);
    assert_eq!(month.requests, 2);
    assert_eq!(month.tokens, 150_000);
    assert_eq!(month.spend_cents, 150, "150k tokens at 1c/1k tokens");
    assert_eq!(month.budget_cap, Some(1_000));
    assert_eq!(month.budget_remaining_cents, Some(850));

    // (month, frontier) — ONLY the frontier-dispatched request accounts here.
    let frontier = find("month", Some("frontier"));
    assert_eq!(frontier.requests, 1);
    assert_eq!(frontier.tokens, 100_000);
    assert_eq!(frontier.spend_cents, 100);
    assert_eq!(frontier.budget_cap, Some(500));
    assert_eq!(frontier.budget_remaining_cents, Some(400));
}

/// An unknown group is `not_found` — the usage read resolves against the enforcement
/// projection (the cost model), the same truth `try_admit` walks.
#[tokio::test]
async fn get_group_usage_unknown_group_not_found() {
    let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
    let app = TestApp::new()
        .group("acme", usage_group_cfg())
        .cost(usage_cost(&groups))
        .build();
    let svc = AdminService::new(app);
    let err = svc.get_group_usage("ghost").await.unwrap_err();
    assert!(
        matches!(&err, AdminError::NotFound { what: m, .. } if m.contains("ghost")),
        "unknown group is not_found: {err:?}"
    );
}

/// Governance OFF: the read still serves the full bucket projection — every bucket present
/// with ZERO usage, caps projected, remaining = the whole cap. The definition exists even
/// when nothing enforces (the doc contract on `get_group_usage`).
#[tokio::test]
async fn get_group_usage_governance_off_zero_usage_caps_projected() {
    let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
    let app = TestApp::new()
        .group("acme", usage_group_cfg())
        .cost(usage_cost(&groups))
        .build(); // no .governance(..)
    let svc = AdminService::new(app);
    let view = svc.get_group_usage("acme").await.expect("usage read");
    assert_eq!(
        view.buckets.len(),
        3,
        "caps still projected: {:?}",
        view.buckets
    );
    for b in &view.buckets {
        assert_eq!(b.requests, 0, "governance off = zero usage ({b:?})");
        assert_eq!(b.tokens, 0);
        assert_eq!(b.spend_cents, 0);
        assert_eq!(
            b.budget_remaining_cents, b.budget_cap,
            "nothing spent ⇒ the whole cap remains ({b:?})"
        );
    }
    // The caps themselves survived the projection.
    assert!(view.buckets.iter().any(|b| b.requests_cap == Some(5)));
    assert!(view
        .buckets
        .iter()
        .any(|b| b.budget_cap == Some(500) && b.pool.as_deref() == Some("frontier")));
}

// ---- fleet-wide usage read: store-failure logging ----

/// A `Store` decorator whose `list_metering` always fails, everything else delegating to a
/// real `MemoryStore` — proves `get_usage`'s store-failure arm without needing a real broken
/// backend.
#[derive(Default)]
struct FailingMeteringStore {
    inner: MemoryStore,
}
impl busbar_api::Store for FailingMeteringStore {
    fn put_key(&self, key: &VirtualKey) -> busbar_api::StoreResult<()> {
        self.inner.put_key(key)
    }
    fn get_key(&self, id: &str) -> busbar_api::StoreResult<Option<VirtualKey>> {
        self.inner.get_key(id)
    }
    fn list_keys(&self) -> busbar_api::StoreResult<Vec<VirtualKey>> {
        self.inner.list_keys()
    }
    fn delete_key(&self, id: &str) -> busbar_api::StoreResult<()> {
        self.inner.delete_key(id)
    }
    fn get_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
    ) -> busbar_api::StoreResult<busbar_api::UsageLedger> {
        self.inner.get_usage(bucket_id, window_start)
    }
    fn put_usage(
        &self,
        bucket_id: &str,
        window_start: u64,
        ledger: &busbar_api::UsageLedger,
    ) -> busbar_api::StoreResult<()> {
        self.inner.put_usage(bucket_id, window_start, ledger)
    }
    fn add_metering(&self, delta: &busbar_api::MeteringDelta) -> busbar_api::StoreResult<()> {
        self.inner.add_metering(delta)
    }
    fn list_metering(&self, _bucket: u64) -> busbar_api::StoreResult<Vec<busbar_api::MeteringRow>> {
        Err(busbar_api::StoreError(
            "simulated metering store outage".to_string(),
        ))
    }
}

/// A store failure inside `get_usage`'s `spawn_blocking` must reach an `error!` log while the
/// wire contract stays unchanged (still `AdminError::Internal`). An earlier version destroyed
/// the error with `map_err(|_| ())` under a comment claiming "details logged upstream in the
/// store layer" — nothing logged them, so the cause of a 500 was unrecoverable.
#[test]
fn usage_read_store_failure_logs_the_real_error() {
    use tracing_subscriber::layer::SubscriberExt as _;
    let cap = crate::test_support::warn_capture::WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let gov =
                Arc::new(GovState::new(Arc::new(FailingMeteringStore::default()), None).unwrap());
            let app = TestApp::new().governance(gov).build();
            let svc = AdminService::new(app);
            let err = svc.get_usage(None).await.unwrap_err();
            assert!(
                matches!(err, AdminError::Internal),
                "wire contract is unchanged: still AdminError::Internal, {err:?}"
            );
        });
    });
    assert!(
        cap.contains("usage.metering") && cap.contains("simulated metering store outage"),
        "the real store error and which read failed must be logged: {:?}",
        cap.messages()
    );
}

// ── narrow-branch coverage ──────────────────────────────────────────────────────────────────

/// A MISSING plugins directory is `Ok` with the empty-entries fingerprint (see the function's own
/// doc comment) — not a propagated I/O error. A mutated guard (NotFound compared to `false`)
/// would route the NotFound case into `Err(e) => return Err(e)` instead.
#[test]
fn plugins_dir_fingerprint_treats_a_missing_dir_as_ok_empty() {
    let missing = tmp_plugins_dir("fingerprint-missing");
    std::fs::remove_dir_all(&missing).unwrap();
    assert!(
        !missing.exists(),
        "precondition: the directory must genuinely not exist"
    );
    let fp = plugins_dir_fingerprint(&missing).expect("a missing dir must not I/O-error");

    // A REAL empty (but existing) directory must produce the IDENTICAL fingerprint — proving
    // "empty" specifically, not just "any Ok(_) value" (which a mutant returning e.g. `Ok(0)`
    // unconditionally would also satisfy against the weaker `.is_ok()`-only assertion this
    // replaces).
    let empty = tmp_plugins_dir("fingerprint-really-empty");
    std::fs::create_dir_all(&empty).unwrap();
    let empty_fp =
        plugins_dir_fingerprint(&empty).expect("a real empty dir must not I/O-error either");
    assert_eq!(
        fp, empty_fp,
        "a missing dir's fingerprint must equal a real empty dir's fingerprint, not some \
             other Ok value"
    );

    // And a NON-empty directory must differ, so this isn't trivially "every case returns the
    // same constant".
    std::fs::write(empty.join("something"), b"x").unwrap();
    let nonempty_fp = plugins_dir_fingerprint(&empty).expect("a populated dir must not error");
    assert_ne!(
        fp, nonempty_fp,
        "a populated dir's fingerprint must differ from the empty one"
    );
}

/// Each of the three path-escape checks (`/`, `\`, `..`) independently rejects a filename.
/// SUBTLETY: `../evil.tar.gz` and `sub/evil.tar.gz` are ALSO caught by the belt-and-braces
/// single-normal-component check a few lines below regardless of `||` vs `&&` here —
/// `Path::components()` on either shape never yields exactly one `Normal` component, so those
/// two cases can't actually distinguish the mutant on their own. Only `sub\evil.tar.gz`
/// (backslash) does: on Unix, `\` is not a path
/// separator, so `Path::components()` treats the whole string as ONE normal component and the
/// belt-and-braces check passes it through — making `contains('\\')` the ONLY thing standing
/// between it and acceptance. (On Windows, `\` IS a separator, so the belt-and-braces check
/// would catch it too, making this specific mutant equivalent there — this test's real
/// discriminating power is platform-dependent, which is fine: CI runs on Linux.)
#[test]
fn validate_plugin_filename_rejects_each_escape_form_independently() {
    assert!(
        validate_plugin_filename("../evil.tar.gz").is_err(),
        "..  alone must reject"
    );
    assert!(
        validate_plugin_filename("sub/evil.tar.gz").is_err(),
        "/ alone must reject"
    );
    assert!(
        validate_plugin_filename("sub\\evil.tar.gz").is_err(),
        "\\ alone must reject"
    );
    assert!(
        validate_plugin_filename("plain.tar.gz").is_ok(),
        "a bare filename with none of the three must be accepted"
    );
}

/// The filename length boundary is exact: `MAX_PLUGIN_FILENAME_LEN` chars (with a valid
/// `.tar.gz` suffix) is accepted; one char over is rejected. A mutated `>` → `>=` would reject
/// the boundary length itself.
#[test]
fn validate_plugin_filename_length_boundary_is_exact() {
    let suffix = ".tar.gz";
    let at_cap = "a".repeat(MAX_PLUGIN_FILENAME_LEN - suffix.len()) + suffix;
    assert_eq!(at_cap.len(), MAX_PLUGIN_FILENAME_LEN);
    assert!(
        validate_plugin_filename(&at_cap).is_ok(),
        "exactly MAX_PLUGIN_FILENAME_LEN chars must be accepted"
    );
    let over_cap = format!("a{at_cap}");
    assert!(
        validate_plugin_filename(&over_cap).is_err(),
        "MAX_PLUGIN_FILENAME_LEN + 1 chars must be rejected"
    );
}

/// The settings byte cap is exactly 64 KiB, not some other magnitude a mutated `*` in its
/// definition could silently produce.
#[test]
fn max_settings_bytes_is_exactly_64_kibibytes() {
    assert_eq!(MAX_SETTINGS_BYTES, 65_536);
    assert_eq!(MAX_SETTINGS_BYTES, 64 * 1024);
}

/// The inspect-schema JSON byte cap is exactly 256 KiB, same rationale.
#[test]
fn max_inspect_schema_json_bytes_is_exactly_256_kibibytes() {
    assert_eq!(MAX_INSPECT_SCHEMA_JSON_BYTES, 262_144);
    assert_eq!(MAX_INSPECT_SCHEMA_JSON_BYTES, 256 * 1024);
}

/// `probe_transport` returns THREE distinguishable outcomes (resolves as hook / resolves as a
/// different kind / does not resolve at all), each with its own detail string — a mutant
/// collapsing the non-hook-kind or unresolved arms to a fixed placeholder string would still
/// return `Some(false)` and pass a loose "it's false" check, but the detail text would be wrong.
#[tokio::test]
async fn probe_transport_distinguishes_wrong_kind_from_unresolved() {
    let Some(env) =
        crate::test_support::test_hook_env_with_wrong_kind_plugin("test-hook", "test-wrong-kind")
    else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let hook_cfg = hook(HookKind::Tap, false);

    // Resolves and IS a hook: (Some(true), None).
    let mut wired = hook_cfg.clone();
    wired.plugin = "test-hook".to_string();
    let (reachable, detail) = probe_transport(&wired, &env).await;
    assert_eq!(reachable, Some(true));
    assert_eq!(detail, None);

    // Resolves, but to a DIFFERENT kind (secret, not hook): distinct detail text naming both
    // kinds, distinguishing this arm from a mutant that collapses it to a fixed placeholder.
    let mut wrong_kind = hook_cfg.clone();
    wrong_kind.plugin = "test-wrong-kind".to_string();
    let (reachable, detail) = probe_transport(&wrong_kind, &env).await;
    assert_eq!(reachable, Some(false));
    assert!(
        detail
            .as_deref()
            .is_some_and(|d| d.contains("test-wrong-kind")
                && d.contains("secret")
                && d.contains("hook")),
        "wrong-kind resolution must name both the resolved kind and the expected kind: {detail:?}"
    );

    // Does not resolve at all: distinct detail text naming "is not installed".
    let mut missing = hook_cfg.clone();
    missing.plugin = "totally-unregistered-plugin-name".to_string();
    let (reachable, detail) = probe_transport(&missing, &env).await;
    assert_eq!(reachable, Some(false));
    assert!(
        detail
            .as_deref()
            .is_some_and(|d| d.contains("is not installed")),
        "unresolved plugin must say so distinctly: {detail:?}"
    );
}

/// Re-registering the SAME name as a global hook a second time must NOT push a duplicate entry
/// into `global_hooks` — a mutated `n == name` (inside the `!...any(...)` idempotency guard)
/// would defeat the guard and double-push on every re-register.
#[test]
fn build_with_hook_reregistering_same_global_hook_does_not_duplicate() {
    let Some(env) = crate::test_support::test_hook_env(&["test-hook"], Default::default()) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = TestApp::new().hook_env(env).build();
    let once = build_with_hook(&app, "logger", hook(HookKind::Tap, true))
        .expect("first global registration");
    assert_eq!(
        once.global_hooks.iter().filter(|n| *n == "logger").count(),
        1
    );
    // Re-PUT the SAME grants (idempotent) a second time.
    let twice = build_with_hook(&once, "logger", hook(HookKind::Tap, true))
        .expect("idempotent re-register with identical grants");
    assert_eq!(
        twice.global_hooks.iter().filter(|n| *n == "logger").count(),
        1,
        "re-registering the same global hook must not duplicate its global_hooks entry"
    );
}

/// Removing one global hook must leave OTHER global hooks untouched — a mutated `!=` → `==` in
/// the `retain` predicate would invert which entries survive, wiping every OTHER hook instead of
/// just the target (with only one hook present the two directions are indistinguishable, so this
/// needs at least two).
#[test]
fn build_with_hook_demote_only_removes_the_target_hook() {
    let Some(env) =
        crate::test_support::test_hook_env(&["test-hook", "test-hook-2"], Default::default())
    else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = TestApp::new().hook_env(env).build();
    let mut other = hook(HookKind::Tap, true);
    other.plugin = "test-hook-2".to_string();
    let with_both = build_with_hook(&app, "logger", hook(HookKind::Tap, true))
        .and_then(|a| build_with_hook(&a, "other", other))
        .expect("two global taps register");
    assert_eq!(with_both.global_hooks.len(), 2);

    let demoted = build_with_hook(&with_both, "logger", hook(HookKind::Tap, false))
        .expect("demoting one of the two is a valid same-grant replace");
    assert!(
        !demoted.global_hooks.iter().any(|n| n == "logger"),
        "the demoted hook must be removed"
    );
    assert!(
        demoted.global_hooks.iter().any(|n| n == "other"),
        "the OTHER global hook must survive the demotion untouched"
    );
}

/// `build_without_hook`'s DELETE cleanup: removing one hook must leave a different hook's global
/// wiring untouched — same `!=`/`==` retain distinction as the demote case above.
#[test]
fn build_without_hook_only_removes_the_target_from_global_wiring() {
    let Some(env) =
        crate::test_support::test_hook_env(&["test-hook", "test-hook-2"], Default::default())
    else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = TestApp::new().hook_env(env).build();
    let mut other = hook(HookKind::Tap, true);
    other.plugin = "test-hook-2".to_string();
    let with_both = build_with_hook(&app, "logger", hook(HookKind::Tap, true))
        .and_then(|a| build_with_hook(&a, "other", other))
        .expect("two global taps register");

    let next = build_without_hook(&with_both, "logger").expect("delete an existing hook");
    assert!(!next.hook_registry.contains_key("logger"));
    assert!(
        !next.global_hooks.iter().any(|n| n == "logger"),
        "the deleted hook must be removed from global wiring"
    );
    assert!(
        next.global_hooks.iter().any(|n| n == "other"),
        "the OTHER global hook must survive the deletion untouched"
    );
}

/// The group name length boundary is exact: `MAX_GROUP_NAME_LEN` chars is accepted, one over is
/// rejected. A mutated `>` → `>=` would reject the boundary length itself.
#[test]
fn build_with_group_name_length_boundary_is_exact() {
    let app = team_app();
    let at_cap = "g".repeat(MAX_GROUP_NAME_LEN);
    let leaf = GroupCfg {
        parent: Some("team".into()),
        ..Default::default()
    };
    assert!(
        build_with_group(&app, &at_cap, leaf.clone()).is_ok(),
        "exactly MAX_GROUP_NAME_LEN chars must be accepted"
    );
    let over_cap = format!("g{at_cap}");
    assert!(
        build_with_group(&app, &over_cap, leaf).is_err(),
        "MAX_GROUP_NAME_LEN + 1 chars must be rejected"
    );
}

/// `build_with_registry` rejects a snapshot with MORE THAN ONE `default: true` hook, but exactly
/// one is fine — a mutated `> 1` boundary needs both sides tested to catch `==`/`>=` variants.
#[test]
fn build_with_registry_rejects_more_than_one_default_but_allows_exactly_one() {
    let Some(env) = crate::test_support::test_hook_env(&["test-hook"], Default::default()) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = TestApp::new().hook_env(env).build();
    let mut one_default = hook(HookKind::Tap, false);
    one_default.default = true;
    let mut registry = HashMap::new();
    registry.insert("a".to_string(), one_default.clone());
    assert!(
        build_with_registry(&app, registry.clone(), vec![]).is_ok(),
        "exactly one default: true hook must be accepted"
    );

    let mut second_default = hook(HookKind::Tap, false);
    second_default.default = true;
    registry.insert("b".to_string(), second_default);
    assert!(
        build_with_registry(&app, registry, vec![]).is_err(),
        "more than one default: true hook must be rejected"
    );
}

/// `build_with_registry` rejects a snapshot whose `global_hooks` names a hook that isn't actually
/// in the registry — a deleted `!` on the `contains_key` check would invert this into rejecting
/// every VALID global reference instead.
#[test]
fn build_with_registry_rejects_a_dangling_global_hook_reference() {
    let Some(env) = crate::test_support::test_hook_env(&["test-hook"], Default::default()) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = TestApp::new().hook_env(env).build();
    let mut registry = HashMap::new();
    registry.insert("logger".to_string(), hook(HookKind::Tap, true));

    // A valid reference (the named hook IS in the registry) must be accepted.
    assert!(
        build_with_registry(&app, registry.clone(), vec!["logger".to_string()]).is_ok(),
        "a global_hooks entry that IS in the registry must be accepted"
    );
    // A dangling reference (named hook is NOT in the registry) must be rejected.
    assert!(
        build_with_registry(&app, registry, vec!["ghost".to_string()]).is_err(),
        "a global_hooks entry naming an unregistered hook must be rejected"
    );
}

/// `healthz` returns a real, non-default `Response` (a mutated body → `Default::default()` would
/// still type-check but return a `200` with an EMPTY body/no status text, not either real health
/// payload). `TestApp::new().build()` deterministically has NO lanes (nothing in this test adds
/// one), so the readiness check always takes the unready branch — pinned to the SPECIFIC expected
/// outcome (503 "no usable lanes"), not "either of the two real branches", so an inverted
/// readiness condition (a mutant that flips which branch fires) is also caught, not just the
/// Default::default() case.
#[tokio::test]
async fn healthz_returns_a_real_response_not_the_default() {
    let app = TestApp::new().build();
    let resp = crate::endpoints::healthz(crate::state::CurrentApp(app)).await;
    use axum::body::to_bytes;
    let status = resp.status();
    let body = to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "a lane-less fixture must report unready (503), not Default::default()'s 200 nor an \
             inverted readiness condition"
    );
    assert_eq!(
        body,
        "no usable lanes".as_bytes(),
        "a real 503 healthz response must carry the real status text, not \
             Response::default()'s empty body: {body:?}"
    );
}

/// THE IR COMPUTE GATE FOLLOWS THE REGISTRY IT IS DERIVED FROM. `any_content_hook` is resolved at
/// config apply, and every snapshot builder that rewrites `hook_registry` must recompute it:
/// registering a `prompt: ro` hook opens the gate for the very next request, and deleting the last
/// granted hook closes it again. A builder that skipped the recompute would leave a live snapshot
/// whose gate disagrees with its own hook registry.
#[test]
fn hook_snapshot_builders_recompute_the_content_gate() {
    let Some(env) = crate::test_support::test_hook_env(&["test-hook"], Default::default()) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = TestApp::new().hook_env(env).build();
    assert!(
        !app.any_content_hook,
        "a fixture with no hooks grants no content"
    );

    let mut granted = hook(HookKind::Tap, true);
    granted.prompt = PromptAccess::Ro;
    let registered = build_with_hook(&app, "screener", granted.clone()).expect("registers");
    assert!(
        registered.any_content_hook,
        "registering a `prompt: ro` hook must open the gate"
    );

    let deleted = build_without_hook(&registered, "screener").expect("deletes");
    assert!(
        !deleted.any_content_hook,
        "deleting the last granted hook must close the gate"
    );

    let mut registry = HashMap::new();
    registry.insert("screener".to_string(), granted);
    let rolled_back =
        build_with_registry(&app, registry, vec!["screener".to_string()]).expect("rolls back");
    assert!(
        rolled_back.any_content_hook,
        "a rolled-back snapshot's gate must match the registry it installed"
    );
}
