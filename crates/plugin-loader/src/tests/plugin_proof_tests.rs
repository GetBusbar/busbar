// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! **`kind: secret` AND `kind: auth`, PROVEN BY REAL PLUGINS.** The owner deleted the in-tree
//! secret and auth fixtures ("these are trash … real plugins are the examples",
//! `docs/design/1.6.0-QUESTIONS.md` "FIXTURES"): the proofs of these two kinds are the real plugin
//! repos, `GetBusbar/hashicorp-vault` (secret) and `GetBusbar/auth-github` (auth).
//!
//! ci.yml's `plugin-proofs` job checks both repos out beside this one (their `../../busbar/crates/…`
//! path convention), builds their `cdylib`s, and runs these tests with `BUSBAR_PLUGIN_PROOF_DIR`
//! naming the directory the `cdylib`s were built into. Each test takes the REAL artifact through the
//! DROPPED-IN door ([`super::both_ways::dropped`]: signed first-party into a fresh `plugins/`,
//! found by [`crate::scan_and_validate`], opened by the registry's own `open_*`) and asserts:
//!
//! * the KIND HANDSHAKE — the row resolves, and the library opens as the kind it exports;
//! * ONE REAL OPERATION — the plugin's own code runs over the ABI and answers what only it would;
//! * the RED ARMS — the same bytes signed as the OTHER kind are refused at the handshake, naming both
//!   kinds, and an empty config is refused with the plugin's own words.
//!
//! The artifact names and the plugin-specific expectations are DATA
//! (`tests/fixtures/plugin_artifacts.txt`, `proof_*` rows): the loader names no plugin instance.
//!
//! `#[ignore]`d: a local `cargo test` has no plugin repos beside it. With `--ignored` and no
//! `BUSBAR_PLUGIN_PROOF_DIR`, each test FAILS naming the variable — a proof that was asked for never
//! passes by finding nothing.

use super::both_ways::{dropped, statement};
use crate::tests::artifact;
use busbar_contract::auth::{BeginLogin, LoginOutcome};

/// The environment variable naming the directory the real plugins' `cdylib`s were built into.
const PROOF_DIR: &str = "BUSBAR_PLUGIN_PROOF_DIR";

/// The REAL `cdylib` bytes for the `proof_<kind>_cdylib` row, from [`PROOF_DIR`].
fn real_cdylib(kind: &str) -> Vec<u8> {
    let dir = std::env::var_os(PROOF_DIR).unwrap_or_else(|| {
        panic!(
            "{PROOF_DIR} is not set: these proofs dlopen the REAL {kind} plugin's cdylib and must \
             be pointed at the directory it was built into (ci.yml `plugin-proofs`)"
        )
    });
    let path = std::path::Path::new(&dir).join(crate::plugin_library_filename(artifact(&format!(
        "proof_{kind}_cdylib"
    ))));
    std::fs::read(&path)
        .unwrap_or_else(|e| panic!("the real {kind} plugin is not at {}: {e}", path.display()))
}

/// The manifest the real `kind` plugin is signed under, at the newest payload schema this loader
/// speaks for `as_kind`.
fn manifest(as_kind: &str, name: &str) -> crate::sign::Manifest {
    let abi = *crate::supported_abi(as_kind)
        .iter()
        .max()
        .expect("a payload schema for the kind");
    statement(as_kind, name, name, abi)
}

/// `open`'s error, or a panic naming what opened when it must not have.
fn refused<T>(what: &str, r: Result<T, String>) -> String {
    match r {
        Ok(_) => panic!("{what} opened; it must be refused"),
        Err(e) => e,
    }
}

/// SECRET: the real secret plugin, dropped in, resolves a reference by doing its own work — it
/// addresses the backend it was configured with and reports that backend unreachable — and the RED
/// arms refuse it as the wrong kind and without config.
#[test]
#[ignore = "needs BUSBAR_PLUGIN_PROOF_DIR (ci.yml plugin-proofs builds the real plugin repos)"]
fn the_real_secret_plugin_resolves_through_the_dropped_in_door() {
    let lib = real_cdylib("secret");
    let registry = dropped("proof-secret", manifest("secret", "proof-secret"), &lib);

    // The kind handshake: the row resolves, and the library opens as the kind it exports.
    let module = registry
        .open_secret("proof-secret", artifact("proof_secret_config"))
        .expect("the real secret plugin opens as `secret`");

    // One real operation: the plugin parses the reference and goes to its backend.
    let mut settings = serde_json::Map::new();
    settings.insert(
        "path".into(),
        serde_json::Value::String(artifact("proof_secret_reference").into()),
    );
    let err = module
        .resolve(&settings)
        .expect_err("the configured backend is unreachable, so the reference cannot resolve");
    let want = artifact("proof_secret_resolve_error");
    assert!(
        err.to_string().contains(want),
        "the plugin's own resolve must address its configured backend (`{want}`): {err}"
    );

    // RED: an empty config is refused in the plugin's own words.
    let e = refused(
        "the secret plugin with no config",
        registry.open_secret("proof-secret", ""),
    );
    let want = artifact("proof_secret_refusal");
    assert!(e.contains(want), "want `{want}`: {e}");

    // RED: the same bytes signed as `auth` are refused at the kind handshake, naming both kinds.
    let wrong = dropped(
        "proof-secret-as-auth",
        manifest("auth", "proof-secret-as-auth"),
        &lib,
    );
    let e = refused(
        "a secret library signed as auth",
        wrong.open_auth("proof-secret-as-auth", artifact("proof_secret_config")),
    );
    assert!(
        e.contains(
            "plugin 'proof-secret-as-auth' exports kind 'secret' but is being loaded as 'auth'"
        ),
        "{e}"
    );
}

/// AUTH: the real auth plugin, dropped in, starts a browser login by building its IdP's authorize
/// URL from the core-minted state and PKCE challenge — and the RED arms refuse it as the wrong kind
/// and without config.
#[test]
#[ignore = "needs BUSBAR_PLUGIN_PROOF_DIR (ci.yml plugin-proofs builds the real plugin repos)"]
fn the_real_auth_plugin_begins_a_login_through_the_dropped_in_door() {
    let lib = real_cdylib("auth");
    let registry = dropped("proof-auth", manifest("auth", "proof-auth"), &lib);

    // The kind handshake: the row resolves, and the library opens as the kind it exports, at the
    // payload schema it was signed under.
    let (module, abi) = registry
        .open_login("proof-auth", artifact("proof_auth_config"))
        .expect("the real auth plugin opens as `auth`");
    assert_eq!(
        abi,
        *crate::supported_abi("auth").iter().max().unwrap(),
        "the row carries the schema it was signed under"
    );

    // One real operation: `begin_login` builds the IdP authorize URL from what the core minted.
    let outcome = module.begin_login(&BeginLogin {
        redirect_uri: artifact("proof_auth_redirect_uri").into(),
        state: "proof-state".into(),
        code_challenge: "proof-challenge".into(),
        nonce: None,
        scopes: Vec::new(),
    });
    let LoginOutcome::Authorize(url) = outcome else {
        panic!("a redirect login module must answer Authorize: {outcome:?}");
    };
    let want = artifact("proof_auth_authorize_prefix");
    assert!(url.starts_with(want), "want prefix `{want}`: {url}");
    assert!(
        url.contains(
            "&state=proof-state&code_challenge=proof-challenge&code_challenge_method=S256"
        ),
        "the core-minted state and PKCE challenge ride the URL: {url}"
    );

    // RED: an empty config is refused in the plugin's own words.
    let e = refused(
        "the auth plugin with no config",
        registry.open_login("proof-auth", "").map(|_| ()),
    );
    let want = artifact("proof_auth_refusal");
    assert!(e.contains(want), "want `{want}`: {e}");

    // RED: the same bytes signed as `secret` are refused at the kind handshake, naming both kinds.
    let wrong = dropped(
        "proof-auth-as-secret",
        manifest("secret", "proof-auth-as-secret"),
        &lib,
    );
    let e = refused(
        "an auth library signed as secret",
        wrong.open_secret("proof-auth-as-secret", artifact("proof_auth_config")),
    );
    assert!(
        e.contains(
            "plugin 'proof-auth-as-secret' exports kind 'auth' but is being loaded as 'secret'"
        ),
        "{e}"
    );
}
