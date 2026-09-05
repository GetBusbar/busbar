// THE THIN BINARY'S OWN TESTS — the boot/CLI helpers that live in main.rs and nowhere else:
// worker-thread sizing, --safe-mode detection, the shutdown/serve lifecycle, and the
// signing-key command's stdout-only-secret contract. Everything engine-shaped moved to
// busbar-core/src/tests/tests.rs with the core split (step 3.7); DELETING these instead was the
// named failure mode — validate_worker_threads_config and signing_key_command_output have no
// other coverage.
use super::*;
use busbar_core::test_support::EnvVarGuard;

/// `worker_threads_from_env`: an unset var returns None (the normal default path, no warning); a
/// valid positive integer returns Some(n); zero/negative/non-numeric returns None WITH a warning
/// printed (not silently ignored, see the function's own doc comment). Uses a
/// test-unique env var name so this can never collide with a concurrently-running test.
#[test]
fn worker_threads_from_env_parses_valid_rejects_invalid() {
    let unset_name = "BUSBAR_TEST_WORKER_THREADS_UNSET_MARKER_1";
    std::env::remove_var(unset_name);
    assert_eq!(
        worker_threads_from_env(unset_name),
        None,
        "an unset var must return None"
    );

    let valid_name = "BUSBAR_TEST_WORKER_THREADS_VALID_MARKER_1";
    std::env::set_var(valid_name, "7");
    assert_eq!(
        worker_threads_from_env(valid_name),
        Some(7),
        "a valid positive integer must round-trip exactly"
    );
    std::env::remove_var(valid_name);

    for bad in ["0", "-1", "not-a-number", ""] {
        let bad_name = "BUSBAR_TEST_WORKER_THREADS_BAD_MARKER_1";
        std::env::set_var(bad_name, bad);
        assert_eq!(
            worker_threads_from_env(bad_name),
            None,
            "a non-positive-integer value ({bad:?}) must return None, not panic or parse partially"
        );
        std::env::remove_var(bad_name);
    }
}

/// `validate_worker_threads_config`: a config-supplied `advanced.worker_threads: 0` is DIAGNOSED
/// (`Err`, so the caller warns) rather than silently dropped — matching `worker_threads_from_env`'s
/// treatment of an invalid env value. A positive count or an unset value passes through as `Ok`.
/// Pre-fix the config path used `.filter(|n| *n >= 1)`, which returned `None` for
/// `Some(0)` with NO diagnostic — reverting to that (removing this validation) fails the `Err` case.
#[test]
fn validate_worker_threads_config_diagnoses_zero() {
    assert!(
        validate_worker_threads_config(Some(0)).is_err(),
        "worker_threads: 0 must be diagnosed, not silently dropped"
    );
    assert_eq!(validate_worker_threads_config(Some(4)), Ok(Some(4)));
    assert_eq!(validate_worker_threads_config(None), Ok(None));
}

/// `worker_threads_from_config`: END-TO-END from a real config.yaml (not just a parse). A positive
/// `advanced.worker_threads` is read back from the file the `BUSBAR_CONFIG` env var names; a `0` is
/// diagnosed away to `None`. Deleting `worker_threads_from_config`'s parse (or its
/// call in `main()`) means `advanced.worker_threads` stops being read from config.yaml — the positive
/// assertion fails.
#[test]
fn worker_threads_from_config_reads_a_real_file() {
    // `BUSBAR_CONFIG` is read ONLY by `worker_threads_from_config` outside of `main()`, so setting it
    // here does not perturb other unit tests (they pass explicit config paths to `load_config_from_disk`).
    //
    // The restore MUST be panic-safe: a bare `assert_eq!` between the `set_var` and a manual restore
    // at the bottom of the function would, on failure, unwind straight past the restore and leak a
    // `BUSBAR_CONFIG` pointing at THIS test's (about-to-be-deleted) temp dir to every later test in
    // the same binary — a process-global env var is not per-test state, so that leak is silent and
    // order-dependent. `EnvVarGuard`'s `Drop` runs during unwind too, so the restore happens
    // regardless of whether the assertions below pass. See
    // `env_var_guard_restores_on_panic` for a direct proof of that unwind behavior.
    let _guard = EnvVarGuard::capture(ENV_CONFIG);
    let dir = std::env::temp_dir().join(format!(
        "busbar-wtcfg-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let config_path = dir.join("config.yaml");

    std::fs::write(
        &config_path,
        "providers: {}\nmodels: {}\nadvanced:\n  worker_threads: 5\n",
    )
    .unwrap();
    std::env::set_var(ENV_CONFIG, &config_path);
    assert_eq!(
        worker_threads_from_config(),
        Some(5),
        "a positive advanced.worker_threads must be read from config.yaml"
    );

    std::fs::write(
        &config_path,
        "providers: {}\nmodels: {}\nadvanced:\n  worker_threads: 0\n",
    )
    .unwrap();
    assert_eq!(
        worker_threads_from_config(),
        None,
        "advanced.worker_threads: 0 is invalid → None (diagnosed, not honored)"
    );

    // `_guard`'s `Drop` restores `BUSBAR_CONFIG` here (or on unwind above) — no manual restore needed.
    let _ = std::fs::remove_dir_all(&dir);
}

/// `safe_mode_requested`: true iff `--safe-mode` is literally present among the args; absent, a
/// near-miss, or an empty arg list must all return false.
#[test]
fn safe_mode_requested_matches_the_exact_flag_only() {
    assert!(safe_mode_requested(
        vec!["busbar".to_string(), "--safe-mode".to_string()].into_iter()
    ));
    assert!(!safe_mode_requested(
        vec!["busbar".to_string(), "--validate".to_string()].into_iter()
    ));
    assert!(!safe_mode_requested(
        vec!["busbar".to_string(), "--safe-mode=true".to_string()].into_iter()
    ));
    assert!(!safe_mode_requested(std::iter::empty()));
}

/// `value_flag`: extracts a value-taking flag in all accepted forms — `--long value`, `--long=value`,
/// and the short `-x value` — returning the LAST occurrence, and `None` when the flag is absent.
#[test]
fn value_flag_parses_all_accepted_forms() {
    let v = |a: &[&str], long: &str, short: Option<&str>| {
        value_flag(a.iter().map(|s| s.to_string()), long, short)
    };
    // `--config value`
    assert_eq!(
        v(&["--config", "/a/config.yaml"], "--config", Some("-c")),
        Some("/a/config.yaml".to_string())
    );
    // `--config=value`
    assert_eq!(
        v(&["--config=/b/config.yaml"], "--config", Some("-c")),
        Some("/b/config.yaml".to_string())
    );
    // `-c value` (short)
    assert_eq!(
        v(&["-c", "/c/config.yaml"], "--config", Some("-c")),
        Some("/c/config.yaml".to_string())
    );
    // LAST occurrence wins.
    assert_eq!(
        v(
            &["-c", "/first", "--config", "/second"],
            "--config",
            Some("-c")
        ),
        Some("/second".to_string())
    );
    // Absent ⇒ None. `--providers` has no short form.
    assert_eq!(v(&["--validate"], "--providers", None), None);
    assert_eq!(
        v(&["--providers", "/p/providers.yaml"], "--providers", None),
        Some("/p/providers.yaml".to_string())
    );
}

/// `resolve_config_path`: the flag, when passed, wins over everything (the env layer is only consulted
/// when the flag is `None`). The flag-present arm is deterministic (no env dependence), so it is the
/// safe half to unit-test without racing the process environment.
#[test]
fn resolve_config_path_flag_wins() {
    assert_eq!(
        resolve_config_path(Some("/flag/config.yaml")),
        "/flag/config.yaml".to_string()
    );
}

/// `config_override_notice`: fires ONLY when both the `--config` flag and `BUSBAR_CONFIG` are set to
/// DIFFERENT paths (a real override to explain) — never on a bare flag, a bare env, or equal values.
#[test]
fn config_override_notice_fires_only_on_a_real_override() {
    // Both set + differ ⇒ notice naming both.
    let n = config_override_notice(Some("/flag.yaml"), Some("/env.yaml")).expect("notice");
    assert!(
        n.contains("/flag.yaml") && n.contains("/env.yaml"),
        "got {n}"
    );
    // Equal ⇒ no notice.
    assert_eq!(
        config_override_notice(Some("/same.yaml"), Some("/same.yaml")),
        None
    );
    // Flag alone ⇒ no notice.
    assert_eq!(config_override_notice(Some("/flag.yaml"), None), None);
    // Env alone ⇒ no notice.
    assert_eq!(config_override_notice(None, Some("/env.yaml")), None);
}

/// `providers_override_notice`: fires when `--providers` is set AND config.yaml ALSO declares a
/// DIFFERENT `providers_file:` — naming both — and is silent for a bare flag or matching values.
#[test]
fn providers_override_notice_names_both_only_on_a_real_override() {
    // Flag set + providers_file set (and differ) ⇒ notice naming BOTH.
    let n = providers_override_notice(Some("/flag.yaml"), Some("catalog.yaml")).expect("notice");
    assert!(
        n.contains("/flag.yaml") && n.contains("catalog.yaml") && n.contains("providers_file"),
        "the notice must name both the flag and the config's providers_file: {n}"
    );
    // Flag alone (no providers_file in config) ⇒ no notice.
    assert_eq!(providers_override_notice(Some("/flag.yaml"), None), None);
    // Matching values ⇒ no notice.
    assert_eq!(
        providers_override_notice(Some("catalog.yaml"), Some("catalog.yaml")),
        None
    );
    // No flag ⇒ no notice regardless of providers_file.
    assert_eq!(providers_override_notice(None, Some("catalog.yaml")), None);
}

/// `recv_shutdown`: a `-> ()` mutant would resolve immediately regardless of the channel — the
/// real function must genuinely BLOCK until something is sent (or the sender is dropped), then
/// resolve promptly once it is.
#[tokio::test(start_paused = true)]
async fn recv_shutdown_blocks_until_a_send_then_resolves() {
    let (tx, rx) = tokio::sync::broadcast::channel(1);
    let handle = tokio::spawn(recv_shutdown(rx));

    // Give the spawned task every chance to (wrongly) resolve on its own if it were a no-op.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !handle.is_finished(),
        "recv_shutdown must still be waiting with nothing sent on the channel"
    );

    tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(1), handle)
        .await
        .expect("recv_shutdown must resolve promptly once the channel fires")
        .unwrap();
}

/// `shutdown_signal`: a `-> ()` mutant would resolve immediately — the real function must genuinely
/// block (nothing sends SIGINT/SIGTERM in this test), never completing within a bounded wait.
#[tokio::test]
async fn shutdown_signal_blocks_when_no_signal_is_delivered() {
    let result =
        tokio::time::timeout(std::time::Duration::from_millis(200), shutdown_signal()).await;
    assert!(
        result.is_err(),
        "shutdown_signal must still be pending with no real signal delivered, not resolve as a no-op"
    );
}

/// `serve_listener`: a `-> ()` mutant would never actually accept connections. Bind a real
/// listener, serve a trivial router through `serve_listener`, and confirm a real HTTP request
/// against it succeeds before the shutdown future fires.
#[tokio::test]
async fn serve_listener_actually_serves_real_http_traffic() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route("/probe", axum::routing::get(|| async { "ok" }));
    let secret_resolver = Arc::new(busbar_core::test_support::builtins_only_secret_resolver());
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel::<()>(1);

    let serve_handle = tokio::spawn(serve_listener(
        listener,
        router,
        None,
        secret_resolver,
        "test",
        recv_shutdown(shutdown_rx),
        None,
        true,
    ));

    let resp = reqwest::Client::new()
        .get(format!("http://{addr}/probe"))
        .send()
        .await
        .expect("serve_listener must actually accept and answer a real HTTP request");
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.text().await.unwrap(), "ok");

    shutdown_tx.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), serve_handle)
        .await
        .expect("serve_listener must actually stop once shutdown fires")
        .unwrap();
}

/// SECURITY (signing-key stdout-only contract): `--generate-signing-key` prints the secret ONLY on
/// stdout; the stderr guidance must be secret-free so a stderr capture (systemd journal, CI/build log,
/// terminal scrollback) can never leak the master signing key. Enforced here, not merely commented.
/// RED before the fix: the stderr guidance embedded `export BUSBAR_SIGNING_KEY={hex}`.
#[test]
fn signing_key_guidance_omits_secret() {
    // A real generated key (64 hex chars) through the boot doorway (the signer type stays
    // crate-private in core), so the assertion is against actual secret material.
    let hex = busbar_core::boot::generate_signing_key_hex().expect("generate a signing key");
    assert_eq!(hex.len(), 64, "sanity: an ed25519 secret is 64 hex chars");

    let (stdout, stderr) = signing_key_command_output(&hex);

    // STDOUT carries the secret verbatim (and ONLY the secret).
    assert_eq!(
        stdout, hex,
        "the secret must be printed verbatim on stdout for `> /run/secrets/...` capture"
    );
    // STDERR guidance must NOT contain the secret anywhere.
    assert!(
        !stderr.contains(&hex),
        "the stderr guidance must be secret-free — it must never embed the generated key"
    );
    // And it must point the operator at the stdout value with a non-secret placeholder.
    assert!(
        stderr.contains("export BUSBAR_SIGNING_KEY=<paste-the-64-hex-key-printed-above>"),
        "the guidance must use a non-secret placeholder pointing at the stdout key"
    );
}

/// THE BUILD-PROVENANCE STAMP FORMAT IS LOCKED. `scripts/build-provenance-gate.sh` parses this line
/// as space-separated `key=value` pairs to assert a release build's optimization posture (the guard
/// against the ~20% "regression" that was a mis-built binary). A refactor that renames a key or
/// changes the separator would silently blind that gate; this test fails first instead. It also pins
/// that a TEST build (which is a debug profile) self-reports `profile=debug` / `debug-assertions=true`
/// / `pgo=false` — the exact stamp the gate must be able to distinguish from an optimized release.
#[test]
fn build_info_line_format_is_locked() {
    let line = build_info_line();

    // Every field the gate reads must be present as a `key=` token.
    for key in [
        "profile=",
        "opt-level=",
        "lto=",
        "debug-assertions=",
        "pgo=",
        "target=",
        "target-cpu=",
        "target-features=",
    ] {
        assert!(
            line.contains(key),
            "build_info_line() must expose `{key}` — the build-provenance gate parses it. Got: {line}"
        );
    }

    // A `cargo test` binary is a DEBUG build, so the stamp must say so. If these ever read
    // `release`/`false`, the stamp is decoupled from the actual build and the gate is worthless.
    assert!(
        line.contains("profile=debug"),
        "a test build must self-report profile=debug; got: {line}"
    );
    assert!(
        line.contains("debug-assertions=true"),
        "a test (debug) build must self-report debug-assertions=true; got: {line}"
    );
    assert!(
        line.contains("pgo=false"),
        "a plain (non-pgo-build.sh) build must self-report pgo=false; got: {line}"
    );
}
