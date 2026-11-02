// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

mod common;

use std::path::{Path, PathBuf};

use busbar_contract::plugin_rows::PluginRows;
use busbar_kernel::auth::AuthMiddleware;
use busbar_kernel::config::{AuthCfg, AuthChainEntry, PluginsCfg};
use busbar_plugin_loader::sign::Manifest;

fn tmp_plugin_dir(tag: &str) -> PathBuf {
    common::plugins::scratch(&format!("auth-chain-trust-{tag}"))
}

fn auth_row_manifest(name: &str, alias: &str, publisher: &str) -> Manifest {
    let mut m = common::plugins::manifest("auth", name, publisher);
    m.alias = alias.into();
    m.version = "1.5.0".into();
    m
}

const NOT_A_LIBRARY: &[u8] = b"an auth row whose library bytes are not a library";

fn unsigned_tarball(m: Manifest, lib: &[u8]) -> Vec<u8> {
    common::plugins::seal(m, lib)
}

fn chain_with(module: &str) -> AuthCfg {
    AuthCfg {
        chain: vec![AuthChainEntry::bare(module)],
        ..AuthCfg::default_none()
    }
}

#[test]
fn untrusted_auth_plugin_fails_closed_not_open() {
    common::root_install::install();
    let dir = tmp_plugin_dir("auth-plugin-untrusted");
    let tarball = unsigned_tarball(
        auth_row_manifest("acme-idp", "test-idp-double", "acme"),
        NOT_A_LIBRARY,
    );
    std::fs::write(dir.join("idp.tar.gz"), tarball).unwrap();

    let strict = PluginsCfg {
        enabled: true,
        dir: dir.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cfg = chain_with("test-idp-double");

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
