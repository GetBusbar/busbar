// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-core/src/admin/v1/service.rs`.

use super::*;
use busbar_kernel::config::{HookCfg, HookKind, PromptAccess, UserAccess};

fn hook(kind: HookKind, global: bool) -> HookCfg {
    HookCfg {
        kind,
        plugin: "test-hook".to_string(),
        timeout_ms: 5,
        on_error: "weighted".to_string(),
        prompt: PromptAccess::No,
        user: UserAccess::No,
        priority: 0,
        settings: serde_json::Map::new(),
        at: None,
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
    let Some(env) = busbar_kernel::test_support::test_hook_env(&["test-hook"], Default::default())
    else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = crate::new_test_app().hook_env(env).build();
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
    let Some(env) = busbar_kernel::test_support::test_hook_env(&["test-hook"], Default::default())
    else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = crate::new_test_app().hook_env(env).build();
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

/// A hook registered through the ADMIN API must become live on every OTHER compiled-in plane too,
/// not only on the pool-scoped hooks.
///
/// The failure this pins is specific and silent: an operator writes an MCP server's `hooks: [screen]`
/// attach in the file and registers the `screen` DEFINITION later through the API. At boot the name
/// resolved to nothing (no definition yet), so the server's gate chain was empty — and without
/// `reresolve_plane_gates` the register would answer `200 OK` while that chain stayed empty
/// forever, leaving the operator believing a control is attached that is not. The pool-scoped hooks'
/// own three `resolve_*` calls exist for exactly this reason; this test exercises that same
/// fail-open for a plane-owned attach, using MCP as the concrete plane under test.
#[test]
fn build_with_hook_makes_an_mcp_attach_live() {
    let Some(env) = busbar_kernel::test_support::test_hook_env(&["test-hook"], Default::default())
    else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    // The ONLY thing this test reads of the `tools.fs` registration is its hook ATTACH
    // (`hooks: [screen]`), whose resolution lands in `App::mcp_server_gates`. Drive that through
    // core's NEUTRAL container-hook seam rather than the `busbar_mcp` `.mcp_server(McpServerDefCfg)`
    // builder, so this in-crate unit test names no plane config type across the crate boundary (the
    // full end-to-end `.mcp_server(...)` path is covered by `tests/plane_integration.rs`).
    let mut builder = crate::new_test_app().hook_env(env);
    builder.set_container_hooks(
        busbar_mcp::PLANE_DECL.key,
        vec![("fs".to_string(), vec!["screen".to_string()])],
        Vec::new(),
    );
    // The `reresolve_gates` seam re-reads the SERVER REGISTRY off the plane's runtime slot, so the
    // runtime this generation carries must actually hold the `fs` server (with its `hooks: [screen]`
    // attach) for the re-resolution under test to have anything to resolve. Install it through the MCP
    // test-kit's neutral runtime builder — an in-crate `#[cfg(test)]` reach across the dev-dep edge, the
    // same one `admin::tests` uses — so `build()`'s default empty runtime is not what gets read back.
    {
        let mut tools = busbar_mcp::mcp::config::ToolsCfg::default();
        tools.servers.insert(
            "fs".to_string(),
            serde_json::from_value(serde_json::json!({
                "url": "https://mcp.internal/fs",
                "pin": {"mechanism": "cert_spki", "key": "sha256/BASE="},
                "hooks": ["screen"]
            }))
            .unwrap(),
        );
        builder.install_plane_runtime(
            busbar_kernel::state::runtime_slot_key("mcp"),
            busbar_mcp::testkit::mcp_runtime_with_servers(tools),
        );
    }
    let app = builder.build();
    assert!(
        !app.plane_gates("mcp").is_some_and(|g| g.contains_key("fs")),
        "the attach names a hook no registry entry defines yet, so it resolves to nothing"
    );

    let next = build_with_hook(&app, "screen", hook(HookKind::Gate, false))
        .expect("a valid gate registers");
    assert_eq!(
        next.plane_gates("mcp")
            .and_then(|g| g.get("fs"))
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
    let app = crate::new_test_app().build();
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
    let app = crate::new_test_app().build();
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
    let app = crate::new_test_app().build();
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
    let app = crate::new_test_app().build();
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

use busbar_plugin_loader::sign::{sign, Manifest, SigningKey};

/// A unique temp plugins directory for one test (isolated so parallel tests never collide).
fn tmp_plugins_dir(tag: &str) -> std::path::PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // pid + counter alone is NOT unique over time: these dirs are never cleaned up, and under
    // process churn the OS reuses pids — observed as `plugins_dir_fingerprint_treats_a_missing_
    // dir_as_ok_empty` finding a PREVIOUS run's leftover file inside its "really empty" dir and
    // failing on two honest fingerprints of two different directories. A once-per-process clock
    // token makes the name unique across pid reuse; the counter keeps it unique within the
    // process (same idiom, same reasoning as `busbar_kernel::tests::tmp_plugin_dir`).
    static PROC_TOKEN: std::sync::OnceLock<u128> = std::sync::OnceLock::new();
    let token = PROC_TOKEN.get_or_init(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    });
    let d = std::env::temp_dir().join(format!(
        "busbar-plugin-admin-{}-{token:x}-{n}-{tag}",
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
fn svc_with(dir: std::path::PathBuf, cfg: busbar_kernel::config::PluginsCfg) -> AdminService {
    let app = crate::new_test_app()
        .plugins_dir(dir)
        .plugins_cfg(cfg)
        .build();
    AdminService::new(app)
}

/// The STRICT default posture: no publishers, no opt-ins.
fn strict_posture() -> busbar_kernel::config::PluginsCfg {
    busbar_kernel::config::PluginsCfg::default()
}

/// A permissive posture (allow_unsigned): an unsigned upload installs "unverified".
fn unsigned_ok_posture() -> busbar_kernel::config::PluginsCfg {
    let mut cfg = busbar_kernel::config::PluginsCfg::default();
    cfg.trust.allow_unsigned = true;
    cfg
}

/// A posture that allowlists one third-party publisher key.
fn publisher_posture(name: &str, key: &SigningKey) -> busbar_kernel::config::PluginsCfg {
    let mut cfg = busbar_kernel::config::PluginsCfg::default();
    cfg.trust.publishers = vec![busbar_kernel::config::PluginPublisher {
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
    m.sha256 = busbar_plugin_loader::sign::sha256_hex(b"lib bytes");
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
    m.sha256 = busbar_plugin_loader::sign::sha256_hex(b"lib bytes");
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
    m.sha256 = busbar_plugin_loader::sign::sha256_hex(b"lib bytes");
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
    m.sha256 = busbar_plugin_loader::sign::sha256_hex(lib);
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
    m.sha256 = busbar_plugin_loader::sign::sha256_hex(lib);
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
    m.sha256 = busbar_plugin_loader::sign::sha256_hex(lib);
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
    m2.sha256 = busbar_plugin_loader::sign::sha256_hex(lib2);
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
/// runtime. Mirrors `audit_ring`'s `valve_write_through_does_not_park_the_reactor` proof
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
    let app = crate::new_test_app()
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
    let app = crate::new_test_app()
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
    let app = crate::new_test_app()
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
    m.sha256 = busbar_plugin_loader::sign::sha256_hex(lib);
    let tarball = busbar_plugin_loader::tarball::package(&m, "lib.so", lib).unwrap();
    std::fs::write(dir.join("sf.tar.gz"), &tarball).unwrap();

    let app = crate::new_test_app()
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
        entry.inserted_at = busbar_kernel::store::now().saturating_sub(CATALOG_CACHE_TTL_SECS + 1);
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
        entry.inserted_at = busbar_kernel::store::now() + CATALOG_CACHE_TTL_SECS + 1;
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
    m.sha256 = busbar_plugin_loader::sign::sha256_hex(lib);
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
    m.sha256 = busbar_plugin_loader::sign::sha256_hex(lib);
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

use busbar_kernel::config::groups::{ChildDefault, LimitMetric, LimitWindow};
use busbar_kernel::config::{GroupCfg, LimitCfg};

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
    let app = crate::new_test_app()
        .group("team", team)
        .group("user:bob", bob)
        .build();
    let svc = AdminService::new(app);

    let page = svc
        .list_groups(0, busbar_kernel::admin::v1::contract::LIST_LIMIT_DEFAULT)
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
    let mut builder = crate::new_test_app();
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
    let start2 =
        busbar_kernel::admin::v1::contract::decode_offset_cursor(c1).expect("valid cursor");

    let p2 = svc.list_groups(start2, 2).await.expect("list ok");
    assert_eq!(p2.items.len(), 2);
    let names: Vec<&str> = p2.items.iter().map(|g| g.name.as_str()).collect();
    assert_eq!(names, vec!["g2", "g3"]);
    let c2 = p2.next_cursor.as_deref().expect("one row remains");
    let start3 =
        busbar_kernel::admin::v1::contract::decode_offset_cursor(c2).expect("valid cursor");

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
    let app = crate::new_test_app()
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
    crate::new_test_app()
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
        matches!(&err, busbar_kernel::config::transaction::TxnError::Validation(m) if m.contains("orphan")),
        "dangling parent is a validation error: {err:?}"
    );
}

#[test]
fn build_with_group_rejects_empty_name() {
    let app = team_app();
    let Err(err) = build_with_group(&app, "   ", GroupCfg::default()) else {
        panic!("empty name must be rejected");
    };
    assert!(matches!(
        err,
        busbar_kernel::config::transaction::TxnError::Validation(_)
    ));
}

/// Deleting a leaf removes it from the registry and the rebuilt cost model.
#[test]
fn build_without_group_removes_leaf() {
    // Build a tree that already contains the leaf.
    let app = crate::new_test_app()
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
    let app = crate::new_test_app()
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
    use busbar_api::Store as _;
    use busbar_kernel::governance::{GovState, MemoryStore};
    let store = std::sync::Arc::new(MemoryStore::new());
    store
        .put_key(&busbar_kernel::governance::VirtualKey {
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
            ..Default::default()
        })
        .unwrap();
    let gov = Arc::new(GovState::new(store, None).unwrap());
    let app = crate::new_test_app()
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

use busbar_kernel::governance::{GovState, MemoryStore, VirtualKey};

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
fn usage_cost(
    groups: &std::collections::BTreeMap<String, GroupCfg>,
) -> busbar_kernel::cost::CostModel {
    let card = std::collections::BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 10.0,
            output_utok: 10.0,
            cache_read_utok: 0.0,
            cache_write_utok: 0.0,
            ..Default::default()
        },
    )]);
    busbar_kernel::cost::CostModel::resolve_parts(Some(&card), 0, groups)
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
        ..Default::default()
    }
}

fn input_toks(n: u64) -> std::collections::BTreeMap<String, u64> {
    let mut m = std::collections::BTreeMap::new();
    if n != 0 {
        m.insert(busbar_api::UNIT_INPUT.to_string(), n);
    }
    m
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
    let app = crate::new_test_app()
        .group("acme", usage_group_cfg())
        .cost(usage_cost(&groups))
        .governance(gov.clone())
        .build();

    // One request through `frontier` (100k tokens = 100 cents), one through `value` (50k =
    // 50 cents). The frontier bucket must see only the first; the group-wide buckets both.
    let k = usage_key("acme");
    let now = busbar_kernel::store::now();
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
    let app = crate::new_test_app()
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

/// ADMIN-API BACK-COMPAT (M1b): the public GET-usage JSON still emits the FLAT
/// `tokens_input`/`tokens_output`/`tokens_cache_read`/`tokens_cache_creation` fields, BYTE-IDENTICAL
/// to pre-M1b for a token workload — the reserved-four dissolution into the name-keyed ledger changed
/// nothing on this wire (the `UsageBreakdown` contract is unchanged; the pricer adapter projects the
/// same counts). A downstream FinOps consumer's parser keeps working across the upgrade.
#[test]
fn admin_usage_breakdown_json_is_byte_identical_flat_token_aliases() {
    use busbar_kernel::admin::v1::contract::UsageBreakdown;
    let b = UsageBreakdown {
        tokens_input: 100,
        tokens_output: 40,
        tokens_cache_read: 7,
        tokens_cache_creation: 3,
        requests: 5,
        spend_micros: 12_345,
    };
    let json = serde_json::to_string(&b).unwrap();
    assert_eq!(
        json,
        r#"{"tokens_input":100,"tokens_output":40,"tokens_cache_read":7,"tokens_cache_creation":3,"requests":5,"spend_micros":12345}"#,
        "the admin usage JSON must keep the flat token aliases, byte-identical to pre-M1b"
    );
}

/// Governance OFF: the read still serves the full bucket projection — every bucket present
/// with ZERO usage, caps projected, remaining = the whole cap. The definition exists even
/// when nothing enforces (the doc contract on `get_group_usage`).
#[tokio::test]
async fn get_group_usage_governance_off_zero_usage_caps_projected() {
    let groups = std::collections::BTreeMap::from([("acme".to_string(), usage_group_cfg())]);
    let app = crate::new_test_app()
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
    let cap = busbar_kernel::test_support::warn_capture::WarnCapture::default();
    let subscriber = tracing_subscriber::registry().with(cap.clone());
    tracing::subscriber::with_default(subscriber, || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            let gov =
                Arc::new(GovState::new(Arc::new(FailingMeteringStore::default()), None).unwrap());
            let app = crate::new_test_app().governance(gov).build();
            let svc = AdminService::new(app);
            let err = svc.get_usage(None, None).await.unwrap_err();
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
    let Some(env) = busbar_kernel::test_support::test_hook_env_with_wrong_kind_plugin(
        "test-hook",
        "test-wrong-kind",
    ) else {
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
    let Some(env) = busbar_kernel::test_support::test_hook_env(&["test-hook"], Default::default())
    else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = crate::new_test_app().hook_env(env).build();
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
    let Some(env) = busbar_kernel::test_support::test_hook_env(
        &["test-hook", "test-hook-2"],
        Default::default(),
    ) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = crate::new_test_app().hook_env(env).build();
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
    let Some(env) = busbar_kernel::test_support::test_hook_env(
        &["test-hook", "test-hook-2"],
        Default::default(),
    ) else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = crate::new_test_app().hook_env(env).build();
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
    let Some(env) = busbar_kernel::test_support::test_hook_env(&["test-hook"], Default::default())
    else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = crate::new_test_app().hook_env(env).build();
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
    let Some(env) = busbar_kernel::test_support::test_hook_env(&["test-hook"], Default::default())
    else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = crate::new_test_app().hook_env(env).build();
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
/// payload). `crate::new_test_app().build()` deterministically has NO lanes (nothing in this test adds
/// one), so the readiness check always takes the unready branch — pinned to the SPECIFIC expected
/// outcome (503 "no usable lanes"), not "either of the two real branches", so an inverted
/// readiness condition (a mutant that flips which branch fires) is also caught, not just the
/// Default::default() case.
#[tokio::test]
async fn healthz_returns_a_real_response_not_the_default() {
    let app = crate::new_test_app().build();
    let resp = busbar_kernel::endpoints::healthz(busbar_kernel::state::CurrentApp(app)).await;
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
    let Some(env) = busbar_kernel::test_support::test_hook_env(&["test-hook"], Default::default())
    else {
        eprintln!("skip: hook cdylib not built (run under --workspace)");
        return;
    };
    let app = crate::new_test_app().hook_env(env).build();
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

/// THE CLOSED-SET CHECK: after EVERY snapshot builder that rewrites `hook_registry`, every field
/// DERIVED from that registry must equal what a fresh derivation from the installed registry would
/// produce. This is deliberately written as an INVARIANT over the derived set rather than as a
/// per-field assertion, because the defect it exists to catch is structural: `requested_signals`
/// was added to `main.rs`'s `App` construction beside `any_content_hook` and never wired into the
/// three builders, so a hook registered through `POST /api/v1/admin/hooks` declaring `signals:` got
/// a `200 OK` and then a candidate payload that silently lacked the signal it declared — the same
/// FAIL-OPEN shape as a register that leaves the gate chain empty.
///
/// WHEN A NEW DERIVED FIELD IS ADDED, EXTEND `assert_hook_derived` BELOW. `service::
/// rebuild_hook_derived` is now the single place the builders compute the set, so there is exactly
/// one production site to touch and this test is what fails if it is missed.
#[test]
fn hook_derived_fields_follow_the_registry() {
    // PANIC, never skip: a rig that skips when the cdylib is absent reports green over the code it
    // was written to cover. Build it (`cargo build -p busbar-hook-test-plugin`) or fail loudly.
    let env = busbar_kernel::test_support::test_hook_env(&["test-hook"], Default::default())
        .expect(
            "the hook-test plugin cdylib must be built for this test (cargo build -p \
         busbar-hook-test-plugin); refusing to skip the derived-field invariant",
        );

    /// Every `App` field that is a PURE FUNCTION of `hook_registry`, re-derived from the snapshot's
    /// own registry and compared against what the builder installed.
    fn assert_hook_derived(app: &busbar_kernel::state::App, ctx: &str) {
        assert_eq!(
            app.any_content_hook,
            busbar_kernel::hooks::any_content_hook(&app.hook_registry),
            "{ctx}: `any_content_hook` disagrees with the registry the snapshot installed"
        );
        assert_eq!(
            app.requested_signals,
            busbar_kernel::hooks::requested_signals(&app.hook_registry),
            "{ctx}: `requested_signals` disagrees with the registry the snapshot installed — a \
             hook's `signals:` declaration did not take effect on the snapshot that installed it"
        );
    }

    let app = crate::new_test_app().hook_env(env).build();
    assert_hook_derived(&app, "boot fixture");

    // A hook that exercises BOTH derived scalars at once: a content grant and a signal declaration.
    let mut declaring = hook(HookKind::Tap, true);
    declaring.prompt = PromptAccess::Ro;
    declaring.signals = vec![busbar_api::Signal::CandidateBreakerState];

    let registered = build_with_hook(&app, "declarer", declaring.clone()).expect("registers");
    assert_hook_derived(&registered, "after build_with_hook (POST/PUT /hooks)");
    assert!(
        registered
            .requested_signals
            .wants(busbar_api::Signal::CandidateBreakerState),
        "registering a hook that declares `candidate.breaker_state` must open the compute gate for \
         the very next request"
    );

    let deleted = build_without_hook(&registered, "declarer").expect("deletes");
    assert_hook_derived(&deleted, "after build_without_hook (DELETE /hooks/{name})");
    assert!(
        deleted.requested_signals.is_empty(),
        "deleting the last declaring hook must close the compute gate again"
    );

    let mut registry = HashMap::new();
    registry.insert("declarer".to_string(), declaring);
    let rolled_back =
        build_with_registry(&app, registry, vec!["declarer".to_string()]).expect("rolls back");
    assert_hook_derived(&rolled_back, "after build_with_registry (config rollback)");
}

/// SECURITY (R3-B): `POST /api/v1/admin/config/validate` must NOT scan a CALLER-SUPPLIED
/// `plugins.dir`. The pre-flight does `fs::read_dir` + a read of every tarball it finds on that
/// directory, so honoring the request's `plugins.dir` made the endpoint an arbitrary-path
/// readability + directory-enumeration oracle for any token that can reach it (`plugins.dir:
/// /root/.ssh` reports whether that path is readable and what tarballs it holds). The fix PINS the
/// scanned directory to the RUNNING install's plugins dir.
///
/// The request's `plugins.dir` points at a directory holding a GARBAGE `.tar.gz`. Because the scan is
/// pinned to the running (empty) dir, that caller-supplied directory is never read: the config
/// validates `ok: true`. Were the request's dir honored instead, the scan would choke on the garbage
/// tarball and return `ok: false` — the signal that the arbitrary directory had been probed.
#[tokio::test]
async fn validate_config_pins_the_scan_to_the_running_plugins_dir() {
    // The RUNNING install's plugins dir — empty, so a reference-free config lints clean.
    let running_dir = tmp_plugins_dir("validate-running");
    let svc = svc_with(running_dir, unsigned_ok_posture());

    // The CALLER's dir: a DIFFERENT directory holding a file any scan would reject. If the endpoint
    // scanned it, validation would fail on this garbage tarball.
    let evil_dir = tmp_plugins_dir("validate-evil");
    std::fs::write(evil_dir.join("probe.tar.gz"), b"not a real tarball at all").unwrap();

    let yaml = format!(
        r#"
listen: "0.0.0.0:8080"
providers:
  anthropic:
    api_key: {{ env: ANTHROPIC_API_KEY }}
models:
  claude:
    provider: anthropic
pools:
  main:
    members:
      - model: claude
store:
  module: memory
plugins:
  enabled: true
  dir: '{}'
"#,
        // Single-quoted YAML scalar: a Windows path's backslashes are literal here, whereas a
        // double-quoted scalar would read `\U`/`\v`/... as invalid escapes and fail to parse.
        evil_dir.display()
    );
    let deploy: busbar_kernel::config::DeployCfg =
        serde_yaml::from_str(&yaml).expect("test DeployCfg yaml must parse");
    let def: busbar_kernel::config::ProviderDef = serde_yaml::from_str(
        "protocol: anthropic\nbase_url: https://api.anthropic.com\nerror_map:\n  \"400\": client_error\n",
    )
    .unwrap();
    let defs = std::collections::HashMap::from([("anthropic".to_string(), def)]);

    let view = svc
        .validate_config(deploy, defs)
        .await
        .expect("validate returns a view");
    assert!(
        view.ok,
        "the caller's plugins.dir (holding a garbage tarball) must NOT be scanned — the scan is \
         pinned to the running install dir; got errors: {:?}",
        view.errors
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// DECISION #79 — RATE CARDS ARE A DATED HISTORY
//
// A metering row prices against the card in force AT THE ROW'S OWN INSTANT, never the newest card
// ever authored. The owner's worked example is the shape of the first proof: a customer signs PAYG
// at 10, later month-to-month at 5, later a yearly prepaid at 1, and the early windows keep pricing
// at 10 forever. The instant is `MeteringRow::priced_from_ms` — the `effective_from` of the entry
// in force when the counts were accrued — which is also what splits a UTC day at a mid-day edit.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod dated_rate_card_history {
    use super::*;
    use busbar_kernel::governance::{GovState, MemoryStore};
    use busbar_kernel_ledger::cost::{Author, CardEntryDraft, History, RateCard, TierRates};

    /// The one priced lane. It is a metering row's `model` and a card entry's lane, spelled once.
    const LANE: &str = "m-openai-chat";
    const PROVIDER: &str = "openai-chat";
    const KEY: &str = "vk_payg";
    /// One thousand input tokens per row, so a rate of N micro-units per token reads back as
    /// exactly `N * 1_000` micro-units and the cards separate arithmetically.
    const TOKENS: u64 = 1_000;
    const DAY: u64 = busbar_kernel::governance::METERING_BUCKET_SECS;

    /// A COMPLETE one-lane card at `micro_per_token` micro-units per input token, no flat fee.
    pub(super) fn card(micro_per_token: f64) -> RateCard {
        RateCard::from_config(
            Some([(
                LANE,
                TierRates {
                    input: micro_per_token,
                    ..Default::default()
                },
            )]),
            0,
        )
    }

    /// The CURRENT cost model — deliberately the NEWEST, cheapest card in every test below, so a
    /// read that fell back to it would answer `1 * 1_000` for every row and the assertions separate
    /// the lookup from the reprice arithmetically rather than by inspection.
    fn newest_cost() -> busbar_kernel::cost::CostModel {
        let rates = std::collections::BTreeMap::from([(
            LANE.to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: 1.0,
                output_utok: 0.0,
                cache_read_utok: 0.0,
                cache_write_utok: 0.0,
                ..Default::default()
            },
        )]);
        busbar_kernel::cost::CostModel::resolve_parts(
            Some(&rates),
            0,
            &std::collections::BTreeMap::new(),
        )
    }

    /// The test's dated-history source: one history, handed back whole.
    struct Recorded {
        history: Arc<History>,
    }

    impl UsageRateHistory for Recorded {
        fn history(&self) -> Option<Arc<History>> {
            Some(Arc::clone(&self.history))
        }
    }

    /// A source the service can hold for `'static`. Leaked on purpose: the production holder is a
    /// process-wide `OnceLock` and a test that raced it could only ever run once.
    pub(super) fn source(history: History) -> &'static dyn UsageRateHistory {
        Box::leak(Box::new(Recorded {
            history: Arc::new(history),
        }))
    }

    /// Governance holding one metering row per `(bucket, priced_from_ms)` — the store's own key,
    /// which is why a card edit inside a day is TWO rows rather than one. Written through the store
    /// seam because `record_metering` can only ever bucket at the wall clock, and these windows are
    /// in the past.
    pub(super) fn gov_with_rows(rows: &[(u64, u64)]) -> Arc<GovState> {
        let store = Arc::new(MemoryStore::new());
        for (bucket, priced_from_ms) in rows {
            busbar_api::Store::add_metering(
                store.as_ref(),
                &busbar_api::MeteringDelta {
                    usage_units: Default::default(),
                    key_id: KEY.to_string(),
                    bucket: *bucket,
                    model: LANE.to_string(),
                    provider: PROVIDER.to_string(),
                    tokens_input: TOKENS,
                    tokens_output: 0,
                    tokens_cache_read: 0,
                    tokens_cache_write: 0,
                    requests: 1,
                    billable_requests: 1,
                    key_group_at_use: String::new(),
                    pricing_version: String::new(),
                    priced_from_ms: *priced_from_ms,
                },
            )
            .expect("the memory store accepts a metering delta");
        }
        Arc::new(GovState::new(store, None).expect("governance builds"))
    }

    /// Read one bucket through the endpoint's own service method, resolving against `src`.
    async fn read(
        gov: Arc<GovState>,
        src: &'static dyn UsageRateHistory,
        bucket: u64,
    ) -> UsageView {
        let app = crate::new_test_app()
            .governance(gov)
            .cost(newest_cost())
            .build();
        AdminService::new(app)
            .with_rate_history(src)
            .get_usage(Some(bucket), None)
            .await
            .expect("usage read")
    }

    /// The same read, naming a rate-card history SNAPSHOT, and returning the `Result` so a
    /// refusal is a value the caller asserts on rather than a panic.
    pub(super) async fn read_as_of(
        gov: Arc<GovState>,
        src: &'static dyn UsageRateHistory,
        bucket: u64,
        as_of: Option<u64>,
    ) -> Result<UsageView, AdminError> {
        let app = crate::new_test_app()
            .governance(gov)
            .cost(newest_cost())
            .build();
        AdminService::new(app)
            .with_rate_history(src)
            .get_usage(Some(bucket), as_of)
            .await
    }

    /// A snapshot named against a service with NO dated-history source at all.
    pub(super) async fn read_no_source_as_of(
        gov: Arc<GovState>,
        bucket: u64,
        as_of: Option<u64>,
    ) -> Result<UsageView, AdminError> {
        let app = crate::new_test_app()
            .governance(gov)
            .cost(newest_cost())
            .build();
        AdminService::new(app).get_usage(Some(bucket), as_of).await
    }

    /// The three dated windows, day-aligned because a metering bucket is a UTC day. The owner's
    /// example spans months; the arithmetic of "an earlier window keeps its own card" is the same
    /// at any spacing, and a day apart keeps the fixture inside the memory store's retention.
    pub(super) fn windows() -> (u64, u64, u64) {
        let today = busbar_kernel::governance::metering_bucket(busbar_kernel::store::now());
        (today - 3 * DAY, today - 2 * DAY, today - DAY)
    }

    /// The 10 / 5 / 1 history: PAYG from instant zero, month-to-month from `monthly`, prepaid from
    /// `prepaid`.
    fn payg_then_monthly_then_prepaid(monthly: u64, prepaid: u64) -> History {
        let mut history = History::opening(card(10.0), 0);
        history.append(CardEntryDraft {
            effective_from: monthly * 1_000,
            effective_until: None,
            card: card(5.0),
            appended_at: monthly * 1_000,
            author: Author::Config { policy_epoch: 1 },
        });
        history.append(CardEntryDraft {
            effective_from: prepaid * 1_000,
            effective_until: None,
            card: card(1.0),
            appended_at: prepaid * 1_000,
            author: Author::Config { policy_epoch: 2 },
        });
        history
    }

    // ── PROOF 1: a row in each window prices at THAT window's rate ───────────────────────────

    /// PAYG at 10, then month-to-month at 5, then a yearly prepaid at 1 — the owner's worked
    /// example, end to end through `GET /api/v1/admin/usage`. The first window keeps pricing at 10
    /// forever, and it does so while the CURRENT card is 1.
    #[tokio::test]
    async fn each_window_prices_at_the_card_in_force_when_it_was_earned() {
        let (payg, monthly, prepaid) = windows();
        let src = source(payg_then_monthly_then_prepaid(monthly, prepaid));
        // Each day's row carries the instant its own era started — 0 for the opening entry.
        let gov = gov_with_rows(&[
            (payg, 0),
            (monthly, monthly * 1_000),
            (prepaid, prepaid * 1_000),
        ]);

        assert_eq!(
            read(gov.clone(), src, payg).await.total.spend_micros,
            10_000,
            "the PAYG window keeps the card it was earned under (10 x 1_000 tokens)"
        );
        assert_eq!(
            read(gov.clone(), src, monthly).await.total.spend_micros,
            5_000,
            "the month-to-month window prices at 5"
        );
        assert_eq!(
            read(gov, src, prepaid).await.total.spend_micros,
            1_000,
            "the prepaid window prices at 1"
        );
    }

    // ── PROOF 1b: a HOLE in the dated history REFUSES the read (#42, item 374) ───────────────

    /// A history whose only entry starts at `monthly` leaves the PAYG window in a HOLE: no entry
    /// covers the row's instant. That is `MoneyError::NoCardInForce`, a refusal like the other
    /// three — the read fails rather than pricing the row at the CURRENT card (1 x 1_000 = 1_000,
    /// the figure it served before), which is a card nobody put in force for that instant. The
    /// covered window alongside it still prices, so the refusal is the hole's and not the fixture's.
    #[tokio::test]
    async fn a_hole_in_the_dated_history_refuses_rather_than_pricing_at_the_current_card() {
        let (payg, monthly, _prepaid) = windows();
        let mut history = History::new();
        history.append(CardEntryDraft {
            effective_from: monthly * 1_000,
            effective_until: None,
            card: card(5.0),
            appended_at: monthly * 1_000,
            author: Author::Config { policy_epoch: 0 },
        });
        let src = source(history);
        let gov = gov_with_rows(&[(payg, 0), (monthly, monthly * 1_000)]);

        assert_eq!(
            read(gov.clone(), src, monthly).await.total.spend_micros,
            5_000,
            "the covered window prices at the entry in force (5 x 1_000 tokens)"
        );
        assert!(
            matches!(
                read_as_of(gov, src, payg, None).await,
                Err(AdminError::Internal)
            ),
            "a row no history entry covers must REFUSE the read, never price at the current card"
        );
    }

    // ── PROOF 2: publishing a forward-dated card leaves the earlier window BYTE-IDENTICAL ────

    /// The same window read before and after a card is published, compared as BYTES.
    ///
    /// `as_of` is the read instant and is the one field that legitimately moves between two reads,
    /// so it is normalised away; every other byte of the response — the window, the currency, the
    /// totals, every `by_model` and `by_key` row, the truncation flag and the `others` remainder —
    /// is compared verbatim.
    #[tokio::test]
    async fn publishing_a_card_leaves_the_window_before_it_byte_identical() {
        let (payg, _, _) = windows();
        let gov = gov_with_rows(&[(payg, 0)]);

        let before = source(History::opening(card(10.0), 0));

        // The publish: a card effective from NOW, long after the window being read.
        let mut published = History::opening(card(10.0), 0);
        let now_ms = busbar_kernel::store::now().saturating_mul(1_000);
        published.append(CardEntryDraft {
            effective_from: now_ms,
            effective_until: None,
            card: card(1.0),
            appended_at: now_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        let after = source(published);

        let bytes = |mut v: serde_json::Value| {
            v["as_of"] = serde_json::json!(0);
            serde_json::to_string(&v).expect("a usage view serializes")
        };
        let a =
            bytes(serde_json::to_value(read(gov.clone(), before, payg).await).expect("serializes"));
        let b = bytes(serde_json::to_value(read(gov, after, payg).await).expect("serializes"));
        assert_eq!(
            a, b,
            "a forward-dated publish must not touch the window before its effective_from"
        );
        assert!(
            a.contains("\"spend_micros\":10000"),
            "and the window is still priced at the card it was earned under: {a}"
        );
    }

    // ── PROOF 3: a signed back-dated correction reprices EXACTLY its window ──────────────────

    /// An `Author::Amend` entry over `[monthly, prepaid)`. The window it names moves; the window
    /// before it and the window after it do not — both halves asserted, because "reprices its
    /// window" and "reprices nothing else" are two claims and only one of them is the easy one.
    #[tokio::test]
    async fn a_back_dated_correction_reprices_its_window_and_nothing_outside_it() {
        let (payg, monthly, prepaid) = windows();
        // One opening entry, so every row is accrued under it and carries instant zero. The
        // correction lands LATER and still reaches them, which is the whole point of resolving by
        // instant rather than by a stamped version.
        let gov = gov_with_rows(&[(payg, 0), (monthly, 0), (prepaid, 0)]);

        let before = source(History::opening(card(10.0), 0));
        for w in [payg, monthly, prepaid] {
            assert_eq!(
                read(gov.clone(), before, w).await.total.spend_micros,
                10_000,
                "a single-entry history prices every window at the opening card"
            );
        }

        // The correction: the ratecard was wrong for the middle window only.
        let mut corrected = History::opening(card(10.0), 0);
        corrected.append(CardEntryDraft {
            effective_from: monthly * 1_000,
            effective_until: Some(prepaid * 1_000),
            card: card(5.0),
            appended_at: busbar_kernel::store::now().saturating_mul(1_000),
            author: Author::Amend {
                operator_fingerprint: "sha256:operator".to_string(),
                reason_hash: [7u8; 32],
            },
        });
        let after = source(corrected);

        assert_eq!(
            read(gov.clone(), after, payg).await.total.spend_micros,
            10_000,
            "OUTSIDE, before effective_from: unmoved"
        );
        assert_eq!(
            read(gov.clone(), after, monthly).await.total.spend_micros,
            5_000,
            "INSIDE [effective_from, effective_until): repriced"
        );
        assert_eq!(
            read(gov, after, prepaid).await.total.spend_micros,
            10_000,
            "OUTSIDE, at and after effective_until: unmoved"
        );
    }

    // ── PROOF 4: a card edit INSIDE one UTC day splits that day ──────────────────────────────

    /// **THE DEFECT `priced_from_ms` CLOSES.** One bucket, one key, one model — and a card edit at
    /// noon. Before the row carried an instant, the read had nothing between midnight and midnight
    /// to resolve at, so the whole day priced at one card whichever card that was. Now the accrual
    /// key carries the era, the day is TWO rows, and the bucket's total is the sum of two cards.
    ///
    /// The arithmetic separates all three hypotheses: 20,000 would be the whole day at the morning
    /// card, 2,000 the whole day at the afternoon card, and 11,000 — asserted — each half at the
    /// card it was actually earned under.
    #[tokio::test]
    async fn a_card_edit_inside_a_day_splits_the_day_and_each_half_keeps_its_own_card() {
        let (_, _, today) = windows();
        let noon = (today + DAY / 2) * 1_000;
        let mut history = History::opening(card(10.0), 0);
        history.append(CardEntryDraft {
            effective_from: noon,
            effective_until: None,
            card: card(1.0),
            appended_at: noon,
            author: Author::Config { policy_epoch: 1 },
        });
        let src = source(history);
        // Two rows in ONE bucket: the morning's counts under the opening entry, the afternoon's
        // under the noon entry.
        let gov = gov_with_rows(&[(today, 0), (today, noon)]);

        let view = read(gov, src, today).await;
        assert_eq!(
            view.total.spend_micros, 11_000,
            "the day is 10 x 1_000 earned before noon plus 1 x 1_000 earned after it — not \
             20_000 (all morning) and not 2_000 (all afternoon)"
        );
        assert_eq!(
            view.total.tokens_input, 2_000,
            "and the quantities still roll up whole: splitting the price never splits the counts"
        );
        assert_eq!(
            view.by_model.len(),
            1,
            "the split is a PRICING fact, not an attribution one: one model, one provider, one row \
             in the report"
        );
    }

    // ── PROOF 5: no pricing path reads `PostingStamp.rate_card_version` ──────────────────────

    /// The resolution key is an instant, and the version field is reporting provenance (#44) that
    /// must never become a pricing input. This scans the service's own CODE — comments excluded,
    /// since the rule is what the file *does*, not what it says about the rule — so that reading
    /// one back is a red test and not a review note.
    #[test]
    fn the_usage_service_names_no_rate_card_version_in_code() {
        let src = include_str!("../service.rs");
        let offenders: Vec<(usize, &str)> = src
            .lines()
            .enumerate()
            .filter(|(_, l)| {
                let t = l.trim_start();
                !(t.starts_with("//") || t.starts_with("*") || t.is_empty())
            })
            .filter(|(_, l)| l.contains("rate_card_version"))
            .map(|(i, l)| (i + 1, l.trim()))
            .collect();
        assert!(
            offenders.is_empty(),
            "a pricing path reads the posting's stamped rate-card version: {offenders:?}"
        );
    }

    // ── THE BYTE-SAFETY PIN: no source installed ⇒ the previous release's arithmetic ─────────

    /// The oracle cell `billing|rate-card|history-mid-window`'s exact shape (three responses of
    /// 11 in / 7 out inside ONE bucket) read by a service with NO dated history source — a build
    /// whose composition root installed none.
    ///
    /// It reads back 750,090,000: every row at the newest card. That is the published 1.5.5 figure
    /// to the byte, which is the point of pinning it — the resolution is ADDITIVE and a build that
    /// has wired no history answers exactly what it always did.
    #[tokio::test]
    async fn with_no_history_source_the_read_is_the_previous_release_to_the_byte() {
        let gov =
            Arc::new(GovState::new(Arc::new(MemoryStore::new()), None).expect("governance builds"));
        let now = busbar_kernel::store::now();
        let usage = busbar_kernel::billing::TokenUsage {
            input: 11,
            output: 7,
            ..Default::default()
        };
        for _ in 0..3 {
            gov.record_metering(KEY, LANE, PROVIDER, Some(&usage), now);
        }
        gov.flush_metering();

        let rates = std::collections::BTreeMap::from([(
            LANE.to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: 10_000_000.0,
                output_utok: 20_000_000.0,
                cache_read_utok: 0.0,
                cache_write_utok: 0.0,
                ..Default::default()
            },
        )]);
        let app = crate::new_test_app()
            .governance(gov)
            .cost(busbar_kernel::cost::CostModel::resolve_parts(
                Some(&rates),
                3,
                &std::collections::BTreeMap::new(),
            ))
            .build();
        let view = AdminService::new(app)
            .get_usage(None, None)
            .await
            .expect("usage read");
        assert_eq!(
            view.total.spend_micros, 750_090_000,
            "with no history installed the read is the published 1.5.5 figure"
        );
    }

    // ── ITEM 404 (OWNER RULING Q9): an `adjust` of a unit's COUNTS reaches the served figure ──

    /// **THE EXIT TEST FOR ITEM 404's USAGE HALF.** A unit of key `vk_adjust_404` metered 1,000
    /// input tokens at 2.5 micro-units each: `GET /api/v1/admin/usage` serves 2,500 micro-units
    /// (2,500,000 nano-units). A root `adjust` seals 800 on the node amendment journal — counts, no
    /// money — and the same read serves 800 tokens and 2,000 micro-units (2,000,000 nano-units): the
    /// read prices the counts AS CORRECTED. A correction for another key leaves the row alone.
    #[tokio::test]
    async fn an_adjust_of_a_units_counts_moves_the_served_usage_figure() {
        use busbar_kernel::audit::amend::{correct_counts, ClassCounts, CountCorrection};
        const ADJUSTED_KEY: &str = "vk_adjust_404";
        let (bucket, _, _) = windows();
        let store = Arc::new(MemoryStore::new());
        busbar_api::Store::add_metering(
            store.as_ref(),
            &busbar_api::MeteringDelta {
                key_id: ADJUSTED_KEY.to_string(),
                bucket,
                model: LANE.to_string(),
                provider: PROVIDER.to_string(),
                tokens_input: TOKENS,
                tokens_output: 0,
                tokens_cache_read: 0,
                tokens_cache_write: 0,
                requests: 1,
                billable_requests: 1,
                key_group_at_use: String::new(),
                pricing_version: String::new(),
                priced_from_ms: 0,
                usage_units: Default::default(),
            },
        )
        .expect("the memory store accepts a metering delta");
        let gov = Arc::new(GovState::new(store, None).expect("governance builds"));
        let src = source(History::opening(card(2.5), 0));

        let before = read(gov.clone(), src, bucket).await.total;
        assert_eq!((before.tokens_input, before.spend_micros), (1_000, 2_500));

        let count = |n: i128| busbar_contract::count::Count::from_integer(n).expect("whole");
        let was = ClassCounts::from([(busbar_api::UNIT_INPUT.to_string(), count(1_000))]);
        let correct = |principal: &'static str, amends: &'static str| {
            correct_counts(
                busbar_contract::authz::Scope::Full,
                &was,
                CountCorrection {
                    amends,
                    principal: Some(principal),
                    lane: LANE,
                    card_epoch_ms: bucket * 1_000 + 5,
                    now: ClassCounts::from([(busbar_api::UNIT_INPUT.to_string(), count(800))]),
                    authorised_by: "admin",
                    reason: "a retried request was metered twice",
                },
            )
            .expect("a root correction with a reason is sealed")
        };
        correct("vk_someone_else_404", "item-404-other-unit");
        assert_eq!(
            read(gov.clone(), src, bucket).await.total.spend_micros,
            2_500,
            "a correction for another key does not reach this row"
        );
        correct(ADJUSTED_KEY, "item-404-usage-unit");
        let after = read(gov, src, bucket).await.total;
        assert_eq!(
            (after.tokens_input, after.spend_micros),
            (800, 2_000),
            "the served figure prices the corrected counts: 800 x 2.5"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE MONEY-READ REGISTER
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// **EVERY PRODUCTION SITE IN THIS CRATE THAT TURNS A LEDGER FIGURE INTO MONEY**, named, with the
/// book it reads and whether it resolves through the dated rate-card history (#79).
///
/// One endpoint wired and the rest left flat is how two admin reads come to answer different money
/// for the same consumption, and a reviewer cannot see that by reading one file. So the set is
/// asserted instead: a conversion this crate performs anywhere outside this list is a RED test,
/// which is what makes "every money read follows one rule" a property of the crate rather than of
/// whoever reviewed the last diff.
///
/// `resolves` records the state of the world, not an aspiration. The two `false` rows read the
/// ENFORCEMENT ledger (`UsageLedger`/`ModelTokens`), whose rows carry no price instant at all, so
/// under the one rule they take the documented fallback and still derive from the current card.
/// That residual is a real, parked divergence from the metering read beside them — it is not this
/// test's job to hide it, it is this test's job to make it impossible to forget.
const MONEY_READS: &[(&str, &str, &str, bool)] = &[
    (
        "v1/service_operations.rs",
        "get_usage",
        "metering rows (MeteringRow, one UTC-day bucket)",
        true,
    ),
    (
        "v1/service_operations.rs",
        "get_group_usage",
        "enforcement ledger (UsageLedger, per limit window)",
        false,
    ),
    (
        "v1/service.rs",
        "derive_spend_micros_row / derive_spend_micros_row_at_card",
        "the two row pricers themselves — the definitions the reads above call, \
         the second of which is the dated-history one",
        true,
    ),
    (
        "keys.rs",
        "GET /keys/{id}/usage",
        "enforcement ledger (UsageLedger, WINDOW_TOTAL)",
        false,
    ),
];

/// The call shapes that CONVERT a ledger figure into money. `derived_bucket_usage` is on the list
/// because it is a conversion by delegation: it takes the `CostModel` and answers `spend_cents`, so
/// a caller of it is a money read whether or not the multiply is written at the call site.
const MONEY_CONVERSIONS: &[&str] = &[
    "derive_spend_cents",
    "derive_spend_micros",
    "derived_bucket_usage",
];

#[test]
fn every_money_read_in_this_crate_is_registered() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found: Vec<String> = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).expect("the crate's src tree is readable") {
            let path = entry.expect("a readable dir entry").path();
            if path.is_dir() {
                // Test trees are excluded: a fixture may price anything it likes, and this register
                // is about what the SHIPPED read paths do.
                if path.file_name().is_some_and(|n| n == "tests") {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if path.extension().is_none_or(|e| e != "rs") {
                continue;
            }
            let rel = path
                .strip_prefix(&root)
                .expect("every walked path is under src")
                .to_string_lossy()
                .to_string();
            let text = std::fs::read_to_string(&path).expect("a readable source file");
            for (n, line) in text.lines().enumerate() {
                let t = line.trim_start();
                // Prose is not a call. A doc comment naming a conversion is documentation of the
                // rule, which is the opposite of a violation of it.
                if t.starts_with("//") || t.starts_with('*') {
                    continue;
                }
                if MONEY_CONVERSIONS.iter().any(|c| line.contains(c)) {
                    found.push(format!("{rel}:{}", n + 1));
                }
            }
        }
    }
    assert!(
        !found.is_empty(),
        "the walk found no money conversion at all — the scan is broken, not the crate"
    );

    // The registered files, and the count of conversion sites each is allowed to carry. A read that
    // grew a second conversion, or a new file that converts at all, lands here as a diff.
    let registered: std::collections::BTreeSet<&str> =
        MONEY_READS.iter().map(|(file, ..)| *file).collect();
    // Matched by FILE rather than by an exact count, because no registered file carries a fixed
    // number of conversion lines: `v1/service.rs` holds the two row pricers' DEFINITIONS and
    // `v1/service_operations.rs` the two operations that CALL them — one subject, two files, since
    // the impl block was carved out under the oversized cap. An unregistered FILE is the signal.
    let strays: Vec<&String> = found
        .iter()
        .filter(|site| {
            let file = site.split(':').next().unwrap_or_default();
            !registered.contains(file)
        })
        .collect();
    assert!(
        strays.is_empty(),
        "an unregistered site in this crate turns a ledger figure into money. Either route it \
         through the dated rate-card history like `get_usage`, or add it to MONEY_READS with the \
         book it reads and whether it resolves. Strays: {strays:?}"
    );

    // And the register itself must stay honest about which of them resolve.
    assert!(
        MONEY_READS.iter().any(|(.., resolves)| *resolves),
        "no registered money read resolves through the dated history — #79 is unwired"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// `?as_of` — THE RATE-CARD HISTORY SNAPSHOT SELECTOR
//
// Honouring the recorded cell `ledger|rate-history|as-of`, which sends
// `GET /api/v1/admin/usage?as_of=1`. A recorded behaviour is the contract; the design prose that
// gave `?as_of` to the ledger endpoints ONLY was stale and has been corrected to match.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod usage_as_of {
    use super::dated_rate_card_history::{
        card, gov_with_rows, read_as_of, read_no_source_as_of, source, windows,
    };
    use busbar_kernel_ledger::cost::{Author, CardEntryDraft, History};

    /// An older snapshot prices at the older head, and the same URL asked twice answers the same
    /// thing forever — which is the whole of what a snapshot is for.
    ///
    /// The fixture is the recorded cell's shape: a window earned under the opening card, then a
    /// card published over it. At `as_of = 0` only the opening entry is visible, so the window
    /// reads what it always read; at the head both entries are, and — because the row was earned
    /// before the publish — it STILL reads the same. The second assertion is the one worth having:
    /// a snapshot selector that changed a window the publish never touched would be selecting the
    /// wrong thing.
    #[tokio::test]
    async fn an_older_snapshot_is_re_derivable_and_the_publish_moves_neither() {
        let (payg, _, _) = windows();
        let gov = gov_with_rows(&[(payg, 0)]);
        let mut history = History::opening(card(10.0), 0);
        let now_ms = busbar_kernel::store::now().saturating_mul(1_000);
        history.append(CardEntryDraft {
            effective_from: now_ms,
            effective_until: None,
            card: card(1.0),
            appended_at: now_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        let src = source(history);

        assert_eq!(
            read_as_of(gov.clone(), src, payg, Some(0))
                .await
                .expect("seq 0 exists")
                .total
                .spend_micros,
            10_000,
            "at the opening snapshot the window prices at the opening card"
        );
        assert_eq!(
            read_as_of(gov, src, payg, Some(1))
                .await
                .expect("seq 1 is the head")
                .total
                .spend_micros,
            10_000,
            "and at the head too — the publish is dated after the window it did not touch"
        );
    }

    /// A BACK-DATED correction is what makes two snapshots of one window differ, and the
    /// difference is exactly the correction.
    #[tokio::test]
    async fn a_snapshot_before_a_correction_still_answers_the_old_figure() {
        let (payg, _, _) = windows();
        let gov = gov_with_rows(&[(payg, 0)]);
        let mut history = History::opening(card(10.0), 0);
        history.append(CardEntryDraft {
            effective_from: payg.saturating_mul(1_000),
            effective_until: Some(payg.saturating_add(86_400).saturating_mul(1_000)),
            card: card(5.0),
            appended_at: busbar_kernel::store::now().saturating_mul(1_000),
            author: Author::Amend {
                operator_fingerprint: "sha256:operator".to_string(),
                reason_hash: [7u8; 32],
            },
        });
        let src = source(history);

        assert_eq!(
            read_as_of(gov.clone(), src, payg, Some(0))
                .await
                .expect("seq 0 exists")
                .total
                .spend_micros,
            10_000,
            "the snapshot taken before the correction re-derives the figure it was cut at"
        );
        assert_eq!(
            read_as_of(gov.clone(), src, payg, Some(1))
                .await
                .expect("seq 1 is the head")
                .total
                .spend_micros,
            5_000,
            "the snapshot that can see the correction reports the corrected figure"
        );
        assert_eq!(
            read_as_of(gov, src, payg, None)
                .await
                .expect("no snapshot named")
                .total
                .spend_micros,
            5_000,
            "and naming no snapshot is the history as it stands, which is the head"
        );
    }

    /// **A SEQ ABOVE THE HEAD IS REFUSED**, never clamped to the head and never an empty body.
    #[tokio::test]
    async fn a_snapshot_above_the_head_is_refused_rather_than_clamped() {
        let (payg, _, _) = windows();
        let gov = gov_with_rows(&[(payg, 0)]);
        let src = source(History::opening(card(10.0), 0));

        let err = read_as_of(gov, src, payg, Some(7))
            .await
            .expect_err("a snapshot that does not exist is a refusal");
        let busbar_kernel::admin::v1::contract::AdminError::Validation(msg) = &err else {
            panic!("expected a client-safe validation refusal, got {err:?}");
        };
        assert!(
            msg.contains("as_of 7") && msg.contains("head (0)"),
            "the refusal must name the seq asked for and the head that exists: {msg}"
        );
    }

    /// A node with NO dated history refuses a snapshot rather than serving the live figure under a
    /// snapshot's name.
    #[tokio::test]
    async fn a_snapshot_of_a_history_that_does_not_exist_is_refused() {
        let (payg, _, _) = windows();
        let gov = gov_with_rows(&[(payg, 0)]);
        let err = read_no_source_as_of(gov, payg, Some(0))
            .await
            .expect_err("there is no snapshot of a history that does not exist");
        let busbar_kernel::admin::v1::contract::AdminError::Validation(msg) = &err else {
            panic!("expected a client-safe validation refusal, got {err:?}");
        };
        assert!(
            msg.contains("no rate-card history"),
            "the refusal must say WHY there is nothing to snapshot: {msg}"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE BANK AUDITOR'S ONE QUESTION — ONE RECORDED USAGE, DRIVEN THROUGH EVERY SURFACE THAT
// REPORTS OR ENFORCES IT.
//
// "Show me that the number you billed is the number your own books say." A deployment that
// answers that question five ways has not answered it. This module records ONE consumption and
// asks every surface what it cost, in one unit, so the answers can be compared as integers
// rather than as prose.
//
// The governing lines, each quoted where it is applied below:
//   #79 `docs/design/BUSBAR-1.6.0.md:423` — rate cards are a DATED HISTORY; a posting prices at
//        the card in force at its own `arrived_ms`.
//   #42 `:367` — a card PRESENT and silent about a hit class is a REFUSAL; a silent zero is right
//        ONLY when the card is ABSENT.
//   #81 `:425` — counts are exact fixed-point decimals at scale 6; no `f32`/`f64` on any money path.
//   #71 `:409` — pricing is read-time, in the kernel.
// ─────────────────────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod one_recorded_usage_every_surface {
    use super::*;
    use busbar_kernel_ledger::cost::{
        self as ledger_cost, Author, CardEntryDraft, History, LedgerEntry, RateCard, TierRates,
    };

    /// The one lane the recorded usage was served on — a metering row's `model`, a card entry's
    /// lane, and a `LedgerEntry`'s `lane`, spelled once so no surface can be reading another name.
    const LANE: &str = "m-openai-chat";
    const PROVIDER: &str = "openai-chat";
    const KEY: &str = "vk_auditor";
    /// One thousand input tokens per posting, so a rate of N micro-units per token reads back as
    /// exactly `N * 1_000` micro-units and the two cards separate arithmetically.
    const TOKENS: u64 = 1_000;
    const DAY: u64 = busbar_kernel::governance::METERING_BUCKET_SECS;

    /// THE CARD THE FIRST POSTING WAS EARNED UNDER — 27 micro-units per input token.
    const RATE_EARNED: f64 = 27.0;
    /// THE CARD IN FORCE NOW — 12 micro-units per input token. Every flat surface prices the whole
    /// window at this one, whatever the postings were actually earned under.
    const RATE_CURRENT: f64 = 12.0;

    /// A COMPLETE one-lane card at `micro_per_token` micro-units per input token, no flat fee.
    ///
    /// No fee, deliberately: a flat fee is a second pricing dimension (#44) and this fixture is
    /// about the FIRST one. A fee here would add the same constant to every surface and hide the
    /// size of the disagreement rather than expose it.
    fn card(micro_per_token: f64) -> RateCard {
        RateCard::from_config(
            Some([(
                LANE,
                TierRates {
                    input: micro_per_token,
                    ..Default::default()
                },
            )]),
            0,
        )
    }

    /// The cost model every FLAT surface prices through: the card in force NOW, and only that one.
    /// This is what the composition root hands `GET /groups/{g}/usage`, `GET /keys/{id}/usage` and
    /// the budget gate.
    fn current_cost() -> busbar_kernel::cost::CostModel {
        let rates = std::collections::BTreeMap::from([(
            LANE.to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: RATE_CURRENT,
                output_utok: 0.0,
                cache_read_utok: 0.0,
                cache_write_utok: 0.0,
                ..Default::default()
            },
        )]);
        busbar_kernel::cost::CostModel::resolve_parts(
            Some(&rates),
            0,
            &std::collections::BTreeMap::new(),
        )
    }

    /// The dated history: the earned card from instant zero, the current card from `edit_ms`.
    fn history(edit_ms: u64) -> History {
        let mut history = History::opening(card(RATE_EARNED), 0);
        history.append(CardEntryDraft {
            effective_from: edit_ms,
            effective_until: None,
            card: card(RATE_CURRENT),
            appended_at: edit_ms,
            author: Author::Config { policy_epoch: 1 },
        });
        history
    }

    /// THE RECORDED USAGE, as the METERING book holds it: two rows in one UTC day, one per price
    /// era, because a card edit inside a day opens a second row at the edit.
    fn metering(bucket: u64, edit_ms: u64) -> Arc<busbar_kernel::governance::GovState> {
        let store = Arc::new(busbar_kernel::governance::MemoryStore::new());
        for priced_from_ms in [0, edit_ms] {
            busbar_api::Store::add_metering(
                store.as_ref(),
                &busbar_api::MeteringDelta {
                    usage_units: Default::default(),
                    key_id: KEY.to_string(),
                    bucket,
                    model: LANE.to_string(),
                    provider: PROVIDER.to_string(),
                    tokens_input: TOKENS,
                    tokens_output: 0,
                    tokens_cache_read: 0,
                    tokens_cache_write: 0,
                    requests: 1,
                    billable_requests: 1,
                    key_group_at_use: String::new(),
                    pricing_version: String::new(),
                    priced_from_ms,
                },
            )
            .expect("the memory store accepts a metering delta");
        }
        Arc::new(busbar_kernel::governance::GovState::new(store, None).expect("governance builds"))
    }

    /// THE SAME RECORDED USAGE, as the ENFORCEMENT book holds it: one cell per (bucket, window),
    /// carrying the summed counts and NO INSTANT AT ALL. That absence is the finding, not an
    /// omission in this fixture — see the module note on `UsageLedger` below.
    fn enforcement(now: u64) -> Arc<busbar_kernel::governance::GovState> {
        let store = Arc::new(busbar_kernel::governance::MemoryStore::new());
        let ledger = busbar_contract::records::UsageLedger {
            requests: 2,
            billable_requests: 2,
            models: vec![busbar_contract::records::ModelTokens {
                model: LANE.to_string(),
                usage_units: std::collections::BTreeMap::from([(
                    busbar_api::UNIT_INPUT.to_string(),
                    TOKENS * 2,
                )]),
            }],
        };
        for window in [
            busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_TOTAL, now),
            busbar_kernel::governance::budget_window(busbar_kernel::governance::WINDOW_DAY, now),
        ] {
            busbar_contract::records::RecordStore::put_usage(store.as_ref(), KEY, window, &ledger)
                .expect("the memory store accepts a usage ledger");
        }
        Arc::new(busbar_kernel::governance::GovState::new(store, None).expect("governance builds"))
    }

    /// The recorded usage as the ONE FUNCTION's input: one [`LedgerEntry`] per posting, each
    /// carrying the instant it arrived (#79's resolution key).
    fn one_function_slice(bucket: u64, edit_ms: u64) -> Vec<LedgerEntry> {
        [bucket.saturating_mul(1_000), edit_ms]
            .into_iter()
            .map(|arrived_ms| {
                LedgerEntry::new(LANE, arrived_ms).with_whole(busbar_api::UNIT_INPUT, TOKENS)
            })
            .collect()
    }

    /// One cent is ten thousand micro-units. Stated once so a cents surface and a micro surface
    /// can be compared as one integer rather than by eye.
    const MICROS_PER_CENT: i64 = 10_000;

    fn row(label: &str, figure: impl std::fmt::Display) {
        eprintln!("  {label:<56} {figure:>18}");
    }

    /// **THE AUDITOR'S QUESTION, ASKED.** One recorded usage; every surface that reports or
    /// enforces it; one unit.
    #[tokio::test]
    async fn one_recorded_usage_is_one_number_on_every_surface() {
        let now = busbar_kernel::store::now();
        let bucket = busbar_kernel::governance::metering_bucket(now) - DAY;
        // The card edit lands INSIDE the recorded day, which is the case every flat surface gets
        // wrong: half the day was earned under one card and half under another.
        let edit_ms = bucket.saturating_add(DAY / 2).saturating_mul(1_000);

        let hist = history(edit_ms);
        let cost = current_cost();

        // ── SURFACE 5: THE ONE FUNCTION — money = f(ledger_slice, card_history) (#79).
        let one = ledger_cost::price_ledger(&one_function_slice(bucket, edit_ms), &hist)
            .expect("both postings are priced by the card in force at their own instant");
        let one_micros = i64::try_from(one.micros()).expect("the figure fits");

        // ── SURFACE 1: GET /api/v1/admin/usage — the METERING book, through the real service.
        let admin = {
            let app = crate::new_test_app()
                .governance(metering(bucket, edit_ms))
                .cost(current_cost())
                .build();
            AdminService::new(app)
                .with_rate_history(super::dated_rate_card_history::source(history(edit_ms)))
                .get_usage(Some(bucket), None)
                .await
                .expect("usage read")
                .total
                .spend_micros
        };

        // ── SURFACES 2/3/4: the ENFORCEMENT book. Each is the real call the handler makes.
        let gov = enforcement(now);
        //    GET /api/v1/admin/groups/{name}/usage — service_operations.rs:371.
        let group_cents = gov
            .derived_bucket_usage(&cost, KEY, busbar_kernel::governance::WINDOW_DAY, true, now)
            .expect("the group bucket reads")
            .spend_cents;
        //    GET /api/v1/admin/keys/{id}/usage — keys.rs:1783, via `usage_for` -> WINDOW_TOTAL.
        let key_cents = gov
            .derived_bucket_usage(
                &cost,
                KEY,
                busbar_kernel::governance::WINDOW_TOTAL,
                true,
                now,
            )
            .expect("the key bucket reads")
            .spend_cents;
        //    THE BUDGET GATE — governance/state.rs:1970, the figure `try_admit` compares to a cap.
        let gate_cents = cost
            .derive_spend_cents(
                [(
                    LANE,
                    &std::collections::BTreeMap::from([(
                        busbar_api::UNIT_INPUT.to_string(),
                        TOKENS * 2,
                    )]),
                )]
                .into_iter(),
                2,
                true,
            )
            .expect("the one function prices");
        //    THE HOOK SEAM / budget_state — governance/state.rs:1691, the same fold in micro-units.
        let hook_micros = cost
            .derive_spend_micros(
                [(
                    LANE,
                    &std::collections::BTreeMap::from([(
                        busbar_api::UNIT_INPUT.to_string(),
                        TOKENS * 2,
                    )]),
                )]
                .into_iter(),
                2,
                true,
            )
            .expect("the one function prices");

        eprintln!("\n── ONE RECORDED USAGE: 2 x {TOKENS} input tokens on `{LANE}`, one posting");
        eprintln!("   under a {RATE_EARNED} card and one under a {RATE_CURRENT} card ────────────");
        row(
            "THE ONE FUNCTION   price(ledger, history)  [micro]",
            one_micros,
        );
        row("GET /admin/usage                           [micro]", admin);
        row(
            "GET /groups/{g}/usage                      [cents]",
            group_cents,
        );
        row(
            "GET /keys/{id}/usage                       [cents]",
            key_cents,
        );
        row(
            "the budget gate  try_admit                 [cents]",
            gate_cents,
        );
        row(
            "the hook seam    budget_state              [micro]",
            hook_micros,
        );
        eprintln!("   ─── the same five, in ONE unit (micro-units) ───");
        row("THE ONE FUNCTION", one_micros);
        row("GET /admin/usage", admin);
        row("GET /groups/{g}/usage", group_cents * MICROS_PER_CENT);
        row("GET /keys/{id}/usage", key_cents * MICROS_PER_CENT);
        row("the budget gate", gate_cents * MICROS_PER_CENT);
        row("the hook seam", hook_micros);

        // ── HALF ONE: THE DATED BOOK. PROVEN, AND PROVEN BY CONSTRUCTION ────────────────────
        //
        // `GET /admin/usage` prices through `busbar_kernel_ledger::cost::price_in_view` — it IS
        // the one function, not a second implementation that happens to agree. Before that it
        // carried its own call to the LEGACY projection `cost::derive_spend_micros`; the two
        // agreed on every input either answered, and that agreement was the hazard rather than
        // the reassurance (#71 `:409` — pricing is read-time and in the kernel; not in two).
        assert_eq!(
            i128::from(admin),
            one.micros(),
            "the dated admin read and the one function are the same function"
        );
        assert_eq!(
            one_micros,
            39_000,
            "one posting at the {RATE_EARNED} card it was earned under ({}) plus one at the \
             {RATE_CURRENT} card in force now ({}) — #79 `BUSBAR-1.6.0.md:423`",
            (RATE_EARNED as i64) * (TOKENS as i64),
            (RATE_CURRENT as i64) * (TOKENS as i64),
        );

        // ── HALF TWO: THE ENFORCEMENT BOOK. PARKED, AND PINNED SO IT CANNOT DRIFT ───────────
        //
        // THE ROOT CAUSE IS NOT ARITHMETIC. `LedgerEntry.arrived_ms` is #79's resolution key and
        // it is REQUIRED — the one function cannot price a row that does not carry the instant it
        // arrived. `MeteringRow` carries it (`busbar-contract/src/records.rs:885`, field
        // `priced_from_ms`), which is why half one above can adopt the one function at all.
        // `UsageLedger`/`ModelTokens` (`records.rs:678`/`:645`) carry NO INSTANT AT ALL: a cell is
        // keyed by (bucket, window) and holds `usage_units: BTreeMap<String, u64>` and nothing
        // else. So every surface that reads THAT book prices the whole window at whatever card is
        // configured at the moment of the read, and no amount of rewriting its arithmetic can
        // change that — adopting #79 there needs an instant COLUMN, which is a persisted-format
        // change and a money-byte change, and both are the owner's under #10 (`:328`) and #59
        // (`:391`).
        //
        // These three figures are therefore pinned, not asserted-as-correct. They are what a
        // 1.5.5 customer observes today and they are recorded in the shadow oracle
        // (`billing|group-usage|*`, `billing|key-usage|*`, `llm|*|over_budget*`). Moving one is
        // moving a golden, which no agent may do.
        let flat_micros = (RATE_CURRENT as i64) * (TOKENS as i64) * 2;
        assert_eq!(
            hook_micros, flat_micros,
            "the enforcement fold prices both postings at the card in force NOW"
        );
        assert_eq!(flat_micros, 24_000);
        for (surface, cents) in [
            ("GET /groups/{g}/usage", group_cents),
            ("GET /keys/{id}/usage", key_cents),
            ("the budget gate", gate_cents),
        ] {
            assert_eq!(
                cents, 2,
                "{surface} reads the enforcement book, which carries no instant, and then \
                 projects to WHOLE MINOR UNITS — so {flat_micros} micro-units is served as 2 \
                 cents and the remaining 4000 is dropped by the projection on top of the 15000 \
                 dropped by pricing flat. PARKED."
            );
        }

        // ── THE AUDITOR'S QUESTION, AS A NUMBER ────────────────────────────────────────────
        //
        // The gap between the book and the bill, pinned exactly. This is the figure the report
        // carries to the owner: 19,000 of 39,000 micro-units — 48.7% of this slice's bill — is
        // the distance between what the ledger says and what three of the five surfaces answer.
        let served = group_cents * MICROS_PER_CENT;
        assert_eq!(
            one_micros - served,
            19_000,
            "the dated book says {one_micros}; the enforcement surfaces say {served}"
        );
    }
}

/// Item 375: a doc comment in this directory that names a backticked file under the workspace's
/// scripts directory as the thing enforcing a rule must name a file that EXISTS. `service.rs` cited
/// the settings-leak shell lint as the guard on admin settings redaction after that script was
/// deleted (the rule lives on as `cargo xtask gate settings-leak`), so a reader looking for the
/// guard found nothing. A citation of another repository's script is not this tree's and is
/// skipped by the busbar-ui qualifier on the same line.
#[test]
fn every_scripts_path_cited_in_v1_exists() {
    fn walk(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("v1/ is readable") {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let workspace = manifest.join("../..");
    let mut files = Vec::new();
    walk(&manifest.join("src/v1"), &mut files);
    assert!(
        files.len() > 5,
        "the walk found the v1 sources ({})",
        files.len()
    );
    let mut stale = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a v1 source reads");
        for (n, line) in text.lines().enumerate() {
            if line.contains("busbar-ui") {
                continue;
            }
            for cited in line.split("`scripts/").skip(1) {
                let Some(end) = cited.find('`') else { continue };
                let path = cited[..end].split("::").next().unwrap_or_default();
                if !workspace.join("scripts").join(path).exists() {
                    stale.push(format!("{}:{}: scripts/{path}", file.display(), n + 1));
                }
            }
        }
    }
    assert!(
        stale.is_empty(),
        "v1/ cites scripts that do not exist: {stale:#?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// PER-PLANE FEES ON `GET /admin/usage` (#47, OWNER RULING Q32)
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// `GET /admin/usage` prices each metering row's requests at the fee of the plane the row belongs
/// to — the pools plane's flat `per_request_fee:` for a pools row, a plane's own
/// `fees.per_request` for that plane's row, and nothing for a plane that configured no fees — and so
/// answers the budget book's figure for the same traffic.
///
/// Before: a plane's metering row is keyed by its unqualified subject with the plane only in the
/// provider column, and the read priced its requests at the flat fee — 25 where the budget book
/// said 19, and 20 where a fee-less plane's book said 0.
mod plane_fees_on_admin_usage {
    use super::*;
    use busbar_api::Store as _;
    use busbar_kernel::plane::registry::{PlaneDecl, TestRegistryIsolation};
    use busbar_kernel_ledger::cost::{PlaneFees, PLANE_LANE_SEP};

    const KEY: &str = "vk_plane_fees";
    const LLM_MODEL: &str = "m";
    const LLM_PROVIDER: &str = "openai-chat";
    /// The plane with `fees.per_request: 3`.
    const FEE_PLANE: &str = "tp";
    /// A plane that configured no fees.
    const FREE_PLANE: &str = "np";
    /// The pools plane (the fallback) — a row naming ITS key is a pools row.
    const POOLS_PLANE: &str = "pools-test";
    /// One minor unit of fee, in the micro-units `spend_micros` is served in.
    const MICROS_PER_MINOR: i64 = 10_000;

    macro_rules! decl {
        ($key:expr, $fallback:expr, $section:expr) => {
            PlaneDecl {
                key: $key,
                fallback: $fallback,
                config_section: $section,
                scope_kinds: &[],
                subject_noun: $key,
                admin_noun: $key,
                audit_kind: $key,
                wire_format_names: || &[],
                claims: |_| Vec::new(),
                admission: |_| None,
                build: |_| None,
                routes: None,
                admin_routes: None,
                openapi: None,
                hydrate: None,
                start: None,
                config_validate: None,
                card_signing_domain: None,
                card_kid_prefix: None,
                named_def_list: None,
                named_def_get: None,
                registry_contains: None,
                reresolve_gates: None,
                #[cfg(feature = "openapi-schema")]
                openapi_schemas: None,
                on_swap: None,
                parse_section: None,
                parse_endpoint: None,
                lower_endpoint: None,
                build_runtime: None,
                viewer: None,
                retain_verify_gates: None,
                default_section: None,
                owned_config_sections: &[],
                billable_classes: &[],
                resolve_provider: None,
            }
        };
    }
    static POOLS: PlaneDecl = decl!(POOLS_PLANE, true, "pools");
    static FEE: PlaneDecl = decl!(FEE_PLANE, false, "tools");
    static FREE: PlaneDecl = decl!(FREE_PLANE, false, "streams");

    /// Flat fee 5 (the pools plane's), `tools.fees.per_request: 3`, no card (billing off for
    /// tokens) — the P2-fees before→after fixture.
    fn cost() -> busbar_kernel::cost::CostModel {
        let fees = busbar_kernel::config::PlaneFeesMap::from([(
            FEE_PLANE.to_string(),
            PlaneFees {
                per_request: 3,
                per_session: 0,
            },
        )]);
        busbar_kernel::cost::CostModel::resolve_parts(None, 5, &std::collections::BTreeMap::new())
            .with_plane_fees(&fees)
    }

    fn key() -> VirtualKey {
        VirtualKey {
            id: KEY.to_string(),
            generation_hash: format!("h:{KEY}"),
            name: "plane-fees".to_string(),
            enabled: true,
            revision: 1,
            ..Default::default()
        }
    }

    fn gov() -> Arc<GovState> {
        let store = Arc::new(MemoryStore::new());
        store.put_key(&key()).unwrap();
        Arc::new(GovState::new(store, None).unwrap())
    }

    /// Serve `llm` pools calls and `plane` calls on `plane` exactly as the host does: the admission
    /// (the budget book — the pools pool unqualified, the plane's pool qualified by its key) and
    /// the metering row (the plane's subject in `model`, its key in `provider`). Returns the budget
    /// book's spend (minor units) and `/admin/usage`'s total spend (micro-units).
    ///
    /// The app is built BEFORE the plane registry is seeded: building it registers the neutral test
    /// plane, which would re-lock the registry an isolation already holds on this thread.
    async fn serve(llm: usize, plane: &str, calls: usize) -> (i64, i64) {
        let gov = gov();
        let cost = cost();
        let app = crate::new_test_app()
            .governance(Arc::clone(&gov))
            .cost(self::cost())
            .build();
        let _planes = TestRegistryIsolation::seeded(&[&POOLS, &FEE, &FREE]);
        let now = busbar_kernel::store::now();
        let key = key();
        for _ in 0..llm {
            assert!(gov.try_admit(&cost, &key, "", now).is_ok(), "a pools call");
            gov.record_metering(KEY, LLM_MODEL, LLM_PROVIDER, None, now);
        }
        for _ in 0..calls {
            let pool = format!("{plane}{PLANE_LANE_SEP}srv.read");
            assert!(
                gov.try_admit(&cost, &key, &pool, now).is_ok(),
                "a plane call"
            );
            gov.record_metering(KEY, "srv.read", plane, None, now);
        }
        gov.flush_metering();
        let book = gov
            .usage_for(&cost, KEY, now)
            .unwrap()
            .expect("the key's usage")
            .spend_cents;
        let view = AdminService::new(app)
            .get_usage(None, None)
            .await
            .expect("usage read");
        (book, view.total.spend_micros)
    }

    #[tokio::test]
    async fn a_planes_rows_price_at_its_own_fee_and_admin_usage_agrees_with_the_budget_book() {
        let (book, admin) = serve(2, FEE_PLANE, 3).await;
        assert_eq!(book, 19, "the budget book: 2 pools × 5 + 3 tools × 3");
        assert_eq!(
            admin,
            19 * MICROS_PER_MINOR,
            "/admin/usage prices the tools rows at tools.fees.per_request, not the flat fee \
             (before: 25), and agrees with the budget book"
        );
        assert_eq!(admin, book * MICROS_PER_MINOR);
    }

    #[tokio::test]
    async fn a_plane_without_fees_reads_zero_fee_on_admin_usage() {
        let (book, admin) = serve(0, FREE_PLANE, 4).await;
        assert_eq!(book, 0, "the budget book: a fee-less plane bills no fee");
        assert_eq!(
            admin, 0,
            "/admin/usage: 4 calls on a fee-less plane (before: 20)"
        );
    }

    /// THE DATED PATH (#79) prices a plane's row the same way: its requests on the plane's fee
    /// lane at the plane's own fee, resolved through the history entry in force at the row's
    /// instant — 3 tools calls at 3, 2 pools calls at the flat 5, 4 fee-less plane calls at 0.
    #[test]
    fn the_dated_read_prices_a_planes_row_at_its_own_fee() {
        use busbar_kernel::admin::v1::contract::UsageBreakdown;
        let cost = cost();
        let history = busbar_kernel_ledger::cost::History::opening(cost.card().clone(), 0);
        let view = history.current();
        let (_, card) = view.card_at(0).expect("the opening card");
        let price = |lane: &str, requests: u64| {
            let b = UsageBreakdown {
                requests,
                ..Default::default()
            };
            crate::v1::service::derive_spend_micros_row_at_card(&view, 0, card, &cost, lane, &b)
                .expect("priced")
        };
        let tools = format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read");
        let free = format!("{FREE_PLANE}{PLANE_LANE_SEP}srv.read");
        assert_eq!(price(&tools, 3), 9 * MICROS_PER_MINOR, "3 × tools fee 3");
        assert_eq!(price(LLM_MODEL, 2), 10 * MICROS_PER_MINOR, "2 × flat fee 5");
        assert_eq!(price(&free, 4), 0, "a fee-less plane bills no fee");
        assert_eq!(
            crate::v1::service::derive_spend_micros_row(
                &cost,
                &tools,
                &UsageBreakdown {
                    requests: 3,
                    ..Default::default()
                }
            )
            .expect("priced"),
            9 * MICROS_PER_MINOR,
            "the no-history fallback agrees"
        );
    }

    /// A pools row — its provider an upstream provider, or the pools plane's own key — keeps the
    /// flat fee: byte-identical to the previous release.
    #[tokio::test]
    async fn a_pools_row_keeps_the_flat_fee() {
        let (book, admin) = serve(2, POOLS_PLANE, 0).await;
        assert_eq!((book, admin), (10, 10 * MICROS_PER_MINOR));
        let _planes = TestRegistryIsolation::seeded(&[&POOLS, &FEE, &FREE]);
        assert_eq!(
            crate::v1::service::row_lane(LLM_MODEL, POOLS_PLANE),
            LLM_MODEL,
            "the fallback plane's key is a pools row"
        );
        assert_eq!(
            crate::v1::service::row_lane(LLM_MODEL, LLM_PROVIDER),
            LLM_MODEL
        );
        assert_eq!(
            crate::v1::service::row_lane("srv.read", FEE_PLANE),
            format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read")
        );
    }

    /// The pools plane's model and provider, as the rows above name them.
    const POOLS_MODEL: &str = LLM_MODEL;
    const POOLS_PROVIDER: &str = LLM_PROVIDER;

    // ── THE CLASSES THE BUDGET BOOK HOLDS AND A METERING ROW DID NOT (P2-usagegaps) ──────────────
    //
    // Every count a plane ledgers through the budget book's accrual (`GovState::record_usage`, the
    // kernel side of `meter_ledger`) is a count `/admin/usage` must price too: a session opened (one
    // PER_SESSION on the plane's fee lane, `SessionAccount::count_open`), a tool call (a tools
    // plane's `tool_calls`), a rerank's search units. Each case drives the host's own calls and
    // asserts `/admin/usage` equals the budget book.

    /// A card pricing the fee plane's `srv.read` lane's `tool_calls` at `per_call_micros`, the fee
    /// plane at `per_request` / `per_session`, the pools plane's flat fee 5 and its model `m`
    /// priced per token (1 micro-unit per input token, 2 per output) and per search unit (3).
    fn carded_cost(
        per_call_micros: u64,
        per_request: i64,
        per_session: i64,
    ) -> busbar_kernel::cost::CostModel {
        let entry = |units: &[(&str, u64)]| -> busbar_kernel::config::RateEntryCfg {
            let units: serde_json::Map<String, serde_json::Value> = units
                .iter()
                .map(|(c, r)| (c.to_string(), serde_json::json!(r)))
                .collect();
            serde_json::from_value(serde_json::json!({ "units": units })).expect("a rate entry")
        };
        let mut pools = entry(&[("search_units", 3)]);
        pools.input_utok = 1.0;
        pools.output_utok = 2.0;
        let card = std::collections::BTreeMap::from([
            (POOLS_MODEL.to_string(), pools),
            (PLANE_LANE_SEP.to_string(), Default::default()),
            (format!("{FEE_PLANE}{PLANE_LANE_SEP}"), Default::default()),
            (
                format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read"),
                entry(&[("tool_calls", per_call_micros)]),
            ),
        ]);
        let fees = busbar_kernel::config::PlaneFeesMap::from([(
            FEE_PLANE.to_string(),
            PlaneFees {
                per_request,
                per_session,
            },
        )]);
        busbar_kernel::cost::CostModel::resolve_parts(
            Some(&card),
            5,
            &std::collections::BTreeMap::new(),
        )
        .with_plane_fees(&fees)
    }

    /// One served call as the host records it, in the budget book and on the metering series.
    enum Call {
        /// A pools call on `m`: its admission, its tokens ledgered, its metering row.
        Tokens { input: u64, output: u64 },
        /// A pools rerank on `m`: its admission, its search units ledgered, its metering row.
        Rerank { search_units: u64 },
        /// A session opened on the fee plane (`SessionAccount::count_open`).
        Session,
        /// A tool call on the fee plane (`charge_round` + `ledger_tool_call`).
        Tool,
    }

    /// Serve `calls` through the host's own calls; the budget book's spend (minor units) and
    /// `/admin/usage`'s total spend (micro-units).
    async fn serve_calls(
        cost: fn() -> busbar_kernel::cost::CostModel,
        calls: &[Call],
    ) -> (i64, i64) {
        use busbar_kernel_ledger::cost::{plane_fee_lane, PER_SESSION};
        let gov = gov();
        let app = crate::new_test_app()
            .governance(Arc::clone(&gov))
            .cost(cost())
            .build();
        let cost = cost();
        let _planes = TestRegistryIsolation::seeded(&[&POOLS, &FEE, &FREE]);
        let now = busbar_kernel::store::now();
        let key = key();
        let units = |pairs: &[(&str, u64)]| -> std::collections::BTreeMap<String, u64> {
            pairs.iter().map(|(c, n)| (c.to_string(), *n)).collect()
        };
        let tool_lane = format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read");
        for call in calls {
            match call {
                Call::Tokens { input, output } => {
                    assert!(gov.try_admit(&cost, &key, "", now).is_ok());
                    let t = busbar_kernel::billing::TokenUsage {
                        input: *input,
                        output: *output,
                        ..Default::default()
                    };
                    gov.record_usage(
                        &cost,
                        &key,
                        "",
                        POOLS_MODEL,
                        &units(&[("input", *input), ("output", *output)]),
                        now,
                    );
                    gov.record_metering(KEY, POOLS_MODEL, POOLS_PROVIDER, Some(&t), now);
                }
                Call::Rerank { search_units } => {
                    assert!(gov.try_admit(&cost, &key, "", now).is_ok());
                    gov.record_usage(
                        &cost,
                        &key,
                        "",
                        POOLS_MODEL,
                        &units(&[("search_units", *search_units)]),
                        now,
                    );
                    gov.record_metering(KEY, POOLS_MODEL, POOLS_PROVIDER, None, now);
                }
                Call::Session => {
                    gov.record_usage(
                        &cost,
                        &key,
                        "sessions",
                        &plane_fee_lane(FEE_PLANE),
                        &units(&[(PER_SESSION, 1)]),
                        now,
                    );
                }
                Call::Tool => {
                    assert!(gov.try_admit(&cost, &key, &tool_lane, now).is_ok());
                    gov.record_metering(KEY, "srv.read", FEE_PLANE, None, now);
                    gov.record_usage(
                        &cost,
                        &key,
                        "srv.read",
                        &tool_lane,
                        &units(&[("tool_calls", 1)]),
                        now,
                    );
                }
            }
        }
        gov.flush_metering();
        let book = gov
            .usage_for(&cost, KEY, now)
            .unwrap()
            .expect("the key's usage")
            .spend_cents;
        let view = AdminService::new(app)
            .get_usage(None, None)
            .await
            .expect("usage read");
        (book, view.total.spend_micros)
    }

    /// (a) Two sessions at `fees.per_session: 40`: the budget book charges 80, and so does
    /// `/admin/usage` (before: 0 — no metering row carried the session count).
    #[tokio::test]
    async fn two_sessions_price_their_session_fee_on_admin_usage() {
        let (book, admin) = serve_calls(
            || carded_cost(70_000, 0, 40),
            &[Call::Session, Call::Session],
        )
        .await;
        assert_eq!(book, 80, "the budget book: 2 sessions × 40");
        assert_eq!(
            admin,
            80 * MICROS_PER_MINOR,
            "/admin/usage agrees (before: 0)"
        );
    }

    /// (b) A tools card pricing `tool_calls` at 7 minor units, `tools.fees.per_request: 3`, three
    /// tool calls: 3 × 3 + 3 × 7 = 30 on the budget book and on `/admin/usage` (before: 9 — the
    /// fee alone; the `tool_calls` class never reached a metering row).
    #[tokio::test]
    async fn a_planes_ledgered_class_prices_on_admin_usage() {
        let calls = [Call::Tool, Call::Tool, Call::Tool];
        let (book, admin) = serve_calls(|| carded_cost(70_000, 3, 0), &calls).await;
        assert_eq!(book, 30, "the budget book: 3 × fee 3 + 3 × tool_calls 7");
        assert_eq!(
            admin,
            30 * MICROS_PER_MINOR,
            "/admin/usage agrees (before: 9)"
        );
    }

    /// A rerank's search units — the pools plane's own open class — price on `/admin/usage` as the
    /// budget book prices them: 2 reranks of 1,000,000 units at 3 micro-units = 6,000,000 micro-units
    /// plus 2 × the flat fee 5 (before: the fee alone).
    #[tokio::test]
    async fn a_pools_open_class_prices_on_admin_usage() {
        let calls = [
            Call::Rerank {
                search_units: 1_000_000,
            },
            Call::Rerank {
                search_units: 1_000_000,
            },
        ];
        let (book, admin) = serve_calls(|| carded_cost(70_000, 3, 0), &calls).await;
        assert_eq!(book, 610, "the budget book: 2 × 5 + 6,000,000 micro-units");
        assert_eq!(
            admin,
            610 * MICROS_PER_MINOR,
            "/admin/usage agrees (before: 10)"
        );
    }

    /// (c) Pools-only token traffic is unchanged: the tokens ride the row's token columns, the fee
    /// the flat `per_request_fee:`, and nothing is counted twice — 2 calls of 1,000,000 input and
    /// 500,000 output at 1 / 2 micro-units: 4,000,000 micro-units + 2 × 5 = 410 on both books, the
    /// figure this read served before the change.
    #[tokio::test]
    async fn pools_only_token_traffic_is_unchanged() {
        let t = || Call::Tokens {
            input: 1_000_000,
            output: 500_000,
        };
        let (book, admin) = serve_calls(|| carded_cost(70_000, 3, 0), &[t(), t()]).await;
        assert_eq!(book, 410);
        assert_eq!(admin, 410 * MICROS_PER_MINOR);
    }

    /// THE DATED PATH (#79) prices a row's ledgered classes as the fallback does: a plane's fee row
    /// carrying 2 sessions at 40, a tool row carrying 3 requests at fee 3 and 3 `tool_calls` at 7, a
    /// pools row carrying 1,000,000 search units at 3 micro-units and 1 request at the flat 5.
    #[test]
    fn the_dated_read_prices_a_rows_classes_as_the_fallback_does() {
        use busbar_kernel::admin::v1::contract::UsageBreakdown;
        use busbar_kernel_ledger::cost::PER_SESSION;
        let cost = carded_cost(70_000, 3, 40);
        let history = busbar_kernel_ledger::cost::History::opening(cost.card().clone(), 0);
        let view = history.current();
        let (_, card) = view.card_at(0).expect("the opening card");
        let classes = |pairs: &[(&str, u64)]| -> std::collections::BTreeMap<String, u64> {
            pairs.iter().map(|(c, n)| (c.to_string(), *n)).collect()
        };
        let fee_row = format!("{FEE_PLANE}{PLANE_LANE_SEP}");
        let tool_row = format!("{FEE_PLANE}{PLANE_LANE_SEP}srv.read");
        for (lane, requests, units, minor) in [
            (fee_row.as_str(), 0, classes(&[(PER_SESSION, 2)]), 80),
            (tool_row.as_str(), 3, classes(&[("tool_calls", 3)]), 30),
            (POOLS_MODEL, 1, classes(&[("search_units", 1_000_000)]), 305),
        ] {
            let b = UsageBreakdown {
                requests,
                ..Default::default()
            };
            let dated = crate::v1::service::derive_spend_micros_row_classes_at_card(
                &view, 0, card, &cost, lane, &b, &units,
            )
            .expect("priced");
            let fallback =
                crate::v1::service::derive_spend_micros_row_classes(&cost, lane, &b, &units)
                    .expect("priced");
            assert_eq!(
                (dated, fallback),
                (minor * MICROS_PER_MINOR, minor * MICROS_PER_MINOR)
            );
        }
    }

    /// Everything at once: every lane's counts on one `/admin/usage` total, equal to the budget book.
    #[tokio::test]
    async fn mixed_traffic_agrees_with_the_budget_book() {
        let calls = [
            Call::Tokens {
                input: 1_000_000,
                output: 500_000,
            },
            Call::Rerank {
                search_units: 1_000_000,
            },
            Call::Session,
            Call::Tool,
            Call::Tool,
        ];
        let (book, admin) = serve_calls(|| carded_cost(70_000, 3, 40), &calls).await;
        assert_eq!(book, 200 + 5 + 300 + 5 + 40 + 2 * (3 + 7));
        assert_eq!(admin, book * MICROS_PER_MINOR);
    }
}
