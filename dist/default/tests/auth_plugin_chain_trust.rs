// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! AN UNTRUSTED AUTH PLUGIN FAILS CLOSED, over the loader's scan: the kernel's `plugins_preflight`
//! and `AuthMiddleware::new` judge a `kind: auth` row the loader's trust policy SKIPPED, as boot
//! does, with the loader's registry build installed over the kernel's stand-in
//! (`common::root_install`).
//!
//! Moved here from busbar-kernel's `auth/tests/plugin_chain_tests.rs`: the kernel never names the
//! loader (THE DESIGN l.322), and the verdict pinned here — the unsigned row skipped, the refusal
//! carrying the trust opt-in in the loader's words — is the loader's. The kernel's own fail-closed
//! arms (a missing module, the plugin subsystem off, `keys` needing no plugin) stay in the kernel.

mod common;

use std::path::{Path, PathBuf};

use busbar_contract::plugin_rows::PluginRows;
use busbar_kernel::auth::AuthMiddleware;
use busbar_kernel::config::{AuthCfg, AuthChainEntry, PluginsCfg};
use busbar_plugin_loader::sign::Manifest;

/// A fresh, empty plugins directory for this process under `tag`.
fn tmp_plugin_dir(tag: &str) -> PathBuf {
    common::plugins::scratch(&format!("auth-chain-trust-{tag}"))
}

/// A `kind: auth` row's manifest for the given name/alias whose library bytes are not a library,
/// stating the newest auth payload schema the loader speaks so the scan admits its structure.
/// Nothing ever loads it: it is the row a trust refusal judges.
fn auth_row_manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
    let mut m = common::plugins::manifest("auth", name, publisher);
    m.alias = alias.into();
    m.version = "1.5.0".into();
    m
}

/// The bytes an auth row carries where a library would be.
const NOT_A_LIBRARY: &[u8] = b"an auth row whose library bytes are not a library";

/// An UNSIGNED (but structurally valid) tarball: sha256 set, signature empty.
fn unsigned_tarball(m: Manifest, lib: &[u8]) -> Vec<u8> {
    common::plugins::seal(m, lib)
}

/// An `auth.chain` naming exactly the given plugin module. Its settings are empty: the row is never
/// loaded, so nothing reads them.
fn chain_with(module: &str) -> AuthCfg {
    AuthCfg {
        chain: vec![AuthChainEntry::bare(module)],
        ..AuthCfg::default_none()
    }
}

/// FAIL-CLOSED: a configured auth plugin that is PRESENT but UNTRUSTED (unsigned under the default
/// strict policy) is SKIPPED by the scan; both `plugins_preflight` and `AuthMiddleware::new` must
/// fail LOUD — never silently drop the front-door module and admit everyone.
#[test]
fn untrusted_auth_plugin_fails_closed_not_open() {
    common::root_install::install();
    let dir = tmp_plugin_dir("auth-plugin-untrusted");
    let tarball = unsigned_tarball(
        auth_row_manifest("acme-idp", "test-idp-double", "acme"),
        NOT_A_LIBRARY,
    );
    std::fs::write(dir.join("idp.tar.gz"), tarball).unwrap();

    // STRICT default trust: the unsigned auth plugin is skipped.
    let strict = PluginsCfg {
        enabled: true,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cfg = chain_with("test-idp-double");
    // Preflight refuses (names the module + carries the trust opt-in to set).
    let err = busbar_kernel::plugins_preflight(
        None,
        Some(&cfg),
        &Default::default(),
        &Default::default(),
        &strict,
        &Default::default(),
    )
    .unwrap_err();
    assert!(
        err.contains("test-idp-double"),
        "names the auth module: {err}"
    );
    assert!(
        err.contains("allow_unsigned"),
        "carries the trust reason: {err}"
    );

    // And the middleware itself fail-closes on the skipped plugin (the runtime load-time gate):
    // the scan succeeds (skips are not fatal) but resolving the referenced module fails loud.
    let registry = busbar_plugin_loader::scan_and_validate(
        Path::new(&strict.dir),
        &common::root_install::trust_policy(&strict).unwrap(),
    )
    .expect("scan succeeds; the untrusted plugin is merely skipped");
    let registry: std::sync::Arc<dyn PluginRows> = std::sync::Arc::new(registry);
    let mw_err = AuthMiddleware::new(
        &cfg,
        &registry,
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .unwrap_err();
    assert!(
        mw_err.contains("test-idp-double"),
        "middleware names the module: {mw_err}"
    );
    assert!(
        mw_err.contains("not loaded") || mw_err.contains("was not loaded"),
        "middleware fail-closes with the trust reason: {mw_err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
