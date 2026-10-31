// THE THIN BINARY'S OWN TESTS — the boot and flag-surface helpers that live in this crate and
// nowhere else: worker-thread sizing, --safe-mode detection, the shutdown/serve lifecycle, and the
// signing-key command's stdout-only-secret contract. Everything engine-shaped moved out with the
// core split (step 3.7) and rode the busbar-core absorption on to
// busbar-kernel/src/tests/tests.rs, which is where it is today — `busbar-core` itself no longer
// exists. DELETING these instead was the named failure mode: validate_worker_threads_config and
// signing_key_command_output have no other coverage.
//
// They no longer live in ONE file, and the import below is why. main.rs was over the
// structure-lint cap and split at the flag/serve seam, so the half this file covers that ANSWERS
// AND EXITS is now `root::cli` while the half that BOOTS AND SERVES stayed in main.rs. `super::*`
// reaches the second half only; the first is named explicitly.
use super::*;
use crate::root::cli::{
    config_override_notice, providers_override_notice, resolve_config_path,
    signing_key_command_output, value_flag,
};
use busbar_kernel::test_support::EnvVarGuard;

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
/// listener (the connector's, as the root binds its own), serve a trivial router through
/// `serve_listener`, and confirm a real HTTP request against it succeeds before the shutdown
/// future fires.
#[cfg(unix)]
#[tokio::test]
async fn serve_listener_actually_serves_real_http_traffic() {
    let listener = Listening::bind_stream(None, "127.0.0.1:0", ROOT_BIND_LIMITS).unwrap();
    let addr = listener.local_addr();
    let router = Router::new().route("/probe", axum::routing::get(|| async { "ok" }));
    let secret_resolver = Arc::new(busbar_kernel::test_support::builtins_only_secret_resolver());
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
        None,
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
    let hex = busbar_kernel::boot::generate_signing_key_hex().expect("generate a signing key");
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

/// THE `pgo=` FIELD IS A FUNCTION OF THE FLAGS RUSTC WAS GIVEN, AND OF NOTHING ELSE.
///
/// `build.rs`'s header says the stamp exists so a build-config mismatch is impossible to
/// MISDIAGNOSE. That makes a stamp field which can be asserted rather than derived a defect by
/// construction, and `pgo=` was one: it read `BUSBAR_PGO=1 || -Cprofile-use present`, an OR whose
/// left arm no shipping path sets (`scripts/pgo-build.sh` stopped exporting it precisely so the
/// stamp would be an INDEPENDENT witness) and which nothing validated — so
/// `BUSBAR_PGO=1 cargo build --release` produced a binary self-reporting `pgo=true` with no profile
/// data anywhere near it. CI's own assertions were not fooled, but a hand-built, vendored or
/// customer-built binary could lie about the one field the stamp exists for.
///
/// This walks the derivation itself (`src/build_stamp.rs`, the same file `build.rs` `include!`s)
/// rather than the baked constant, because the constant is fixed at compile time and a test cannot
/// rebuild itself under a different environment. Against the pre-fix derivation the environment arm
/// is what decided the answer; here there is no environment arm to reach.
#[test]
fn the_pgo_stamp_is_derived_only_from_the_flags_that_reached_the_compiler() {
    use crate::build_stamp::{flag_value, pgo_from_flags};

    // A real PGO build's flag list, in both shapes cargo delivers `-C` options in.
    assert!(pgo_from_flags(&["-Cprofile-use=/tmp/merged.profdata"]));
    assert!(pgo_from_flags(&["-C", "profile-use=/tmp/merged.profdata"]));
    assert!(pgo_from_flags(&[
        "-Cprofile-use=/tmp/merged.profdata",
        "-Ctarget-cpu=native"
    ]));

    // A plain release build, and an INSTRUMENTED (profile-generate) build — which is emphatically
    // not a profile-USING one, and must not stamp itself as optimized.
    assert!(!pgo_from_flags(&[]));
    assert!(!pgo_from_flags(&["-Ctarget-cpu=native", "-Clto=fat"]));
    assert!(
        !pgo_from_flags(&["-Cprofile-generate=/tmp/prof"]),
        "the training build writes a profile, it does not consume one"
    );

    // THE REGRESSION ITSELF: no environment value, however spelled, can put PGO into the answer.
    // `pgo_from_flags` takes only the flag list, so the ONLY way to reintroduce the escape hatch is
    // to change its signature — and this line stops compiling if anyone does.
    let _: fn(&[&str]) -> bool = pgo_from_flags;
    for asserted in ["1", "true", "yes", "BUSBAR_PGO=1"] {
        assert!(
            !pgo_from_flags(&[asserted]),
            "an asserted value ({asserted}) is not a compiler flag and must not read as PGO"
        );
    }

    // The sibling fields the same file derives, pinned alongside so a refactor of one cannot
    // quietly change the others: present -> the value after `=`, absent -> None (the caller
    // supplies the honest "default" / "(profile-table)" fallback).
    let flags = ["-Cprofile-use=/tmp/m.profdata", "-Ctarget-feature=+lse"];
    assert_eq!(
        flag_value(&flags, "target-feature").as_deref(),
        Some("+lse")
    );
    assert_eq!(flag_value(&flags, "target-cpu"), None);
    assert_eq!(flag_value(&flags, "lto"), None);
}

/// THE STAMP REPORTS THE VALUE RUSTC USED (the stamp exists so a perf number is never pinned on the
/// wrong build, `src/build_stamp.rs`): a `-C` option's value is the one its exact name carries, and
/// when the option is passed twice rustc takes the last, so the stamp does too.
/// RED before the fix: the first element CONTAINING `<name>=` won, so `-Ctarget-cpu=native
/// -Ctarget-cpu=x86-64` stamped `native`, and `-Clinker-plugin-lto=<path>` stamped as `lto=<path>`.
#[test]
fn a_flag_value_is_the_last_one_passed_under_its_exact_name() {
    use crate::build_stamp::flag_value;
    assert_eq!(
        flag_value(
            &["-Ctarget-cpu=native", "-Ctarget-cpu=x86-64"],
            "target-cpu"
        )
        .as_deref(),
        Some("x86-64"),
        "rustc takes the last of a repeated option"
    );
    assert_eq!(
        flag_value(&["-Clinker-plugin-lto=/usr/lib/LLVMgold.so"], "lto"),
        None,
        "another option whose name ends in the one asked for is not it"
    );
    // The green twins: both shapes cargo hands a `-C` option in still read.
    assert_eq!(
        flag_value(&["-C", "lto=fat"], "lto").as_deref(),
        Some("fat")
    );
    assert_eq!(
        flag_value(&["-Ctarget-cpu=native"], "target-cpu").as_deref(),
        Some("native")
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A PLANE-GATED MODULE IS NAMED ONLY FROM CODE UNDER THE SAME GATE
// ─────────────────────────────────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE BOOT JOURNAL: IT REACHES THE CONFIGURED STORE
//
// `node_book()` hard-coded `data_dir: None` and a `NullShipper`, so a deployment that configured a
// data directory wrote its journal nowhere. The journal carries no money (MONEY-DESIGN §2c): no
// opening balance is sealed, because the ledger is the store's usage counts, read as they are.
//
// The three tests below are one proof in three parts, split by WHAT EACH CAN SEE:
//
//   * `the_boot_path_opens_the_configured_directory` drives the REAL path — a real `App` out of the
//     real `build_app_from_config`, then `root::boot::book`, the exact function `run()` calls. It can
//     see the directory and the chain, so it proves the data directory is honoured.
//   * `the_boot_book_ships_its_records_to_the_configured_store` drives `root::boot::compose_book`, the
//     seam `root::boot::book` calls, over a store whose record slots the TEST holds, so what the
//     store KEPT is observable: the boot's records, under this node's keys.
//   * `no_configured_directory_still_opens_nothing_and_writes_nothing` holds the other half of the
//     discipline: the fix gives a node WITH a directory somewhere to write, and must not make
//     writing unconditional.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// A scratch directory that removes itself, so a failing assertion never leaves a tree behind and
/// two runs of the same test never read each other's journal.
/// `BUSBAR_DATA_DIR` IS PROCESS-GLOBAL, and `cargo test` runs this binary's tests on parallel
/// threads: two boot-book tests that each set it would resolve one directory and write two chains
/// into one journal, whose replay then fails verification. Every test that sets it does so through
/// [`data_dir_env`], which holds this lock until the test ends. Its only callers are the
/// `linked_axis_body_ingress` boot-book cells, so it is gated with them.
#[cfg(linked_axis_body_ingress)]
static DATA_DIR_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Set `BUSBAR_DATA_DIR` to `dir` for the rest of the calling test, serialized against every other
/// test that sets it. The tuple drops in order: the variable is restored, then the lock released.
#[cfg(linked_axis_body_ingress)]
fn data_dir_env(dir: &std::path::Path) -> (EnvVarGuard, std::sync::MutexGuard<'static, ()>) {
    // A test that panicked while holding the lock still restored the variable on unwind.
    let held = DATA_DIR_ENV
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let guard = EnvVarGuard::capture("BUSBAR_DATA_DIR");
    std::env::set_var("BUSBAR_DATA_DIR", dir);
    (guard, held)
}

struct BookDir(std::path::PathBuf);

impl BookDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "busbar-boot-book-{tag}-{}-{}",
            std::process::id(),
            {
                static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
                format!(
                    "{}-{}-{}",
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_nanos()),
                    line!(),
                    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                )
            }
        ));
        std::fs::create_dir_all(&path).expect("the fixture directory is creatable");
        BookDir(path)
    }

    /// What is in it now, by name, sorted. The assertion is made of a LISTING rather than of a
    /// method's return value: "a file appeared" and "a file did not appear" are facts about a
    /// filesystem, and asking the code under test whether it wrote one is asking the defendant.
    fn entries(&self) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(&self.0)
            .into_iter()
            .flatten()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }
}

impl Drop for BookDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// THE REAL PATH, END TO END: a real `App`, then `root::boot::book` — the function `run()` calls at
/// the line that used to read `node_book()` — against a CONFIGURED data directory.
///
/// THE JOURNAL REACHES THE CONFIGURED STORE. With `BUSBAR_DATA_DIR` set, the node's own journal is
/// ON DISK and files appear IN THAT DIRECTORY. Under the old `node_book()` the directory was never
/// read — `data_dir: None` was a literal — so the journal was memory-buffered and this listing was
/// empty no matter what the operator configured. The one record on the chain when the boot hands
/// the journal over is the deployment keyset's `Bootstrap` (spec #82(a)): no money record.
// A PROVIDER NEEDS A WIRE CODEC. `cfg_with_provider_api_key` configures one provider on the
// registry's residual-default dialect, and a build that links no protocol (a single-plane build of a
// plane with no body-ingress codec) has none to name: the fixture refuses, and which test happened to
// register a dialect first decided the verdict. Gated on the linked axis that carries the codecs, as
// the root's other provider-configuring cells are.
#[cfg(linked_axis_body_ingress)]
#[test]
fn the_boot_path_opens_the_configured_directory() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    busbar_kernel::test_support::register_neutral_test_plane();
    use busbar_kernel_wal::RecordClass;

    // ORDER-INDEPENDENCE, not decoration. `cfg_with_provider_api_key` names the registry's
    // residual-default dialect, and in a test binary the protocol set is installed by whichever
    // test installs it first — so without this the test passes in a full run and fails run alone.
    // Every linked protocol declaration goes into the test registry, read off the linked table
    // the root registers from.
    for decls in crate::LINKED.protocols {
        busbar_kernel::test_support::protocols::register_test_protocols(decls);
    }
    busbar_kernel::snapshot::init();
    let dir = BookDir::new("real-path");
    assert!(
        dir.entries().is_empty(),
        "the fixture directory starts empty, or nothing below is evidence of anything"
    );

    // THE CONFIGURED DIRECTORY. `BUSBAR_DATA_DIR` is the one source `preflight::fleet_data_dir`
    // resolves today (there is no `data_dir:` config key yet — see that function's own comment), and
    // it is the SAME accessor the plugin anti-downgrade floor persists under, which is why the boot
    // book reads it through that function rather than probing for itself.
    let _env = data_dir_env(&dir.0);

    // A REAL APP, off the REAL construction path — `build_app_from_config`, the one boot and config
    // apply both run — so `app.governance` is the store this deployment actually resolved and
    // `app.cost` is the resolved cost model the read plan is derived from. Not a stand-in for one.
    let app = busbar_kernel::test_support::build_once(
        busbar_kernel::test_support::cfg_with_provider_api_key(
            busbar_kernel::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_BOOT_BOOK"),
        ),
        None,
    )
    .expect("the app builds over the default memory store");

    // THE FUNCTION `run()` CALLS. Not a re-implementation of it, not a recording double of it.
    let book = root::boot::book(&app, "test-store").expect("the boot book opens");

    let (on_disk, first_record) = {
        let durability = book
            .durability
            .lock()
            .expect("the book's lock is unpoisoned");
        let replayed = durability
            .journal
            .replay()
            .expect("the journal on the configured directory reads back")
            .expect("and verifies");
        (durability.on_disk(), replayed)
    };

    assert!(
        on_disk,
        "with a data directory configured the node's journal must be on this node's own disk; it \
         was memory-buffered, which is the `data_dir: None` literal the boot used to hard-code"
    );
    assert!(
        !dir.entries().is_empty(),
        "the configured data directory holds no file: the journal never reached it. The listing \
         is the assertion, not the mode flag above"
    );
    assert_eq!(
        first_record.iter().map(|r| r.class).collect::<Vec<_>>(),
        vec![RecordClass::Bootstrap],
        "the keyset's Bootstrap, and no money record, is on the chain when the boot hands the \
         journal over"
    );
}

/// **A STORE THAT DOES NOT OFFER THE RECORD SLOTS REFUSES THE BOOT**, naming the store and the slots
/// (ARCHITECT 2026-10-07 H3 open-question ruling): such a store cannot keep the node's journal, and
/// a boot over it would serve while keeping nothing. The governance state here holds the store's
/// 1.5.5 op set and no v3 calls — the store as a boot sees one that offers no record slots.
///
/// RED before the fix: the boot opened a book whose journal the adapter's shim "kept".
#[cfg(linked_axis_body_ingress)]
#[test]
fn a_store_without_the_record_slots_refuses_the_boot_by_name() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    busbar_kernel::test_support::register_neutral_test_plane();
    for decls in crate::LINKED.protocols {
        busbar_kernel::test_support::protocols::register_test_protocols(decls);
    }
    busbar_kernel::snapshot::init();
    let app = busbar_kernel::test_support::build_once(
        busbar_kernel::test_support::cfg_with_provider_api_key(
            busbar_kernel::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_NO_SLOTS"),
        ),
        None,
    )
    .expect("the app builds");
    let mut slotless = app.clone();
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(busbar_kernel::governance::MemoryStore::new());
    slotless.governance = Some(std::sync::Arc::new(
        busbar_kernel::governance::GovState::new(store, None).expect("the state opens"),
    ));
    let refused = match root::boot::book(&slotless, "no-slots-store") {
        Ok(_) => panic!("a store with no record slots must refuse the boot"),
        Err(refused) => refused,
    };
    assert_eq!(refused, root::boot::no_record_slots("no-slots-store"));
    assert!(
        refused.contains("`no-slots-store`")
            && refused.contains("record_put, record_get and record_scan"),
        "the refusal names the store and the slots: {refused}"
    );
}

/// THE STORE HALF, at the only vantage point it is visible from: `root::boot::compose_book`, the seam
/// `root::boot::book` calls, handed a store whose record slots the TEST holds.
///
/// What the store KEPT is read off the store: the boot's records under the journal schema, put
/// through its `record_put` slot by the journal's lane, keyed by this node's identity and the
/// record's sequence. The adapter's old shipper acknowledged a batch and kept a count, so this
/// reading was nothing whatever it said (ARCHITECT 2026-10-07 H3 ruling).
#[test]
fn the_boot_book_ships_its_records_to_the_configured_store() {
    use busbar_kernel_wal::RecordClass;

    let dir = BookDir::new("ships");
    let slots = crate::root::store_double::RecordSlots::new();
    let token = root::kernel::new_kernel().durability_token();

    let durability = root::boot::compose_book(
        journal_lane(&slots),
        Some(dir.0.clone()),
        0,
        1_700_000_000,
        &token,
    )
    .expect("the boot journal composes over the configured directory and an empty store");

    let replayed = durability
        .journal
        .replay()
        .expect("the journal reads back")
        .expect("and verifies");
    // The first boot with a data directory seals the deployment keyset's `Bootstrap` (spec #82(a);
    // BUSBAR-1.6.0.md THE DESIGN, §2), and no money record.
    assert_eq!(
        replayed.iter().map(|r| r.class).collect::<Vec<_>>(),
        vec![RecordClass::Bootstrap],
        "exactly the keyset's Bootstrap is on the chain"
    );

    // THE ASSERTION THIS TEST EXISTS FOR. The records reached the CONFIGURED store's record slots.
    let lane = durability
        .lane()
        .expect("a book over the store holds its lane")
        .clone();
    assert!(
        lane.drain(std::time::Duration::from_secs(5)),
        "the store takes the Bootstrap"
    );
    let seq = replayed[0].node_seq;
    let kept = futures::executor::block_on(slots.calls().record_get(
        root::durability::JOURNAL_SCHEMA,
        &root::durability::part_key(0, seq, 0),
    ))
    .expect("the store answers");
    assert!(
        kept.is_some(),
        "the store keeps the Bootstrap under THIS node's identity and the record's sequence"
    );
}

/// The journal's lane to `slots`, as `root::boot::book` opens one over the configured store.
fn journal_lane(slots: &crate::root::store_double::RecordSlots) -> root::durability::JournalLane {
    root::durability::JournalLane::start(slots.calls(), "test-store").expect("the lane starts")
}

/// THE OTHER HALF OF THE DISCIPLINE, and it is not a footnote: constructing an on-disk journal IS
/// the decision to write to a disk, so a node whose configuration names NO data directory must
/// still open nothing and leave nothing behind. The fix gives a node WITH a directory somewhere to
/// write; it must not make writing unconditional.
///
/// The shipping still happens — that is the store's business, not the disk's — so this also pins
/// that the two decisions are independent.
#[test]
fn no_configured_directory_still_opens_nothing_and_writes_nothing() {
    // A directory the node was never told about. Nothing may appear in it.
    let unnamed = BookDir::new("unnamed");
    let slots = crate::root::store_double::RecordSlots::new();
    let token = root::kernel::new_kernel().durability_token();

    let durability = root::boot::compose_book(journal_lane(&slots), None, 0, 1_700_000_000, &token)
        .expect("a memory-buffered journal composes");

    assert!(
        !durability.on_disk(),
        "a configuration that named no data directory must not put a journal on a disk"
    );
    assert_eq!(
        unnamed.entries(),
        Vec::<String>::new(),
        "a file appeared beside a configuration that asked for none"
    );
    assert!(
        durability
            .lane()
            .expect("a book over the store holds its lane")
            .drain(std::time::Duration::from_secs(5)),
        "the store takes the boot's records"
    );
    assert!(
        slots.rows_under(root::durability::JOURNAL_SCHEMA) >= 1,
        "without a directory the book's durability IS the store's, so the records must be kept \
         there"
    );
}

/// THE DEPLOYMENT KEYSET AT THE BOOT SEAM (spec #82(a); BUSBAR-1.6.0.md THE DESIGN, §2, PB-13; architect
/// ruling 2026-09-26): the audit chain `root::boot::compose_book` hands over SIGNS with the keyset it
/// bound — ephemeral without a directory, cached under it with one — and a restart over a directory
/// whose keyset file is gone refuses `KeysetMissing` in the refusal's own words, which `die` prints.
#[test]
fn the_boot_book_binds_its_keyset_and_refuses_keyset_missing_without_the_cache() {
    let token = root::kernel::new_kernel().durability_token();

    // No directory: ephemeral, and the chain signs with a key its own keyset holds.
    let memory = root::boot::compose_book(
        journal_lane(&crate::root::store_double::RecordSlots::new()),
        None,
        0,
        1_700_000_000,
        &token,
    )
    .expect("a memory-buffered journal composes");
    let key_id = memory
        .record
        .signing_key_id()
        .expect("the chain signs")
        .to_string();
    assert!(
        root::durability::keyset_of(&memory.record)
            .get(&key_id)
            .is_some(),
        "the node's own keyset holds the key its chain signs with"
    );

    // A directory: minted and cached; then the cache is lost and the restart refuses.
    let dir = BookDir::new("keyset");
    let first = root::boot::compose_book(
        journal_lane(&crate::root::store_double::RecordSlots::new()),
        Some(dir.0.clone()),
        0,
        1_700_000_000,
        &token,
    )
    .expect("the first boot mints the keyset");
    assert!(first.record.signing_key_id().is_some());
    drop(first);
    std::fs::remove_file(dir.0.join(root::keyset::KEYSET_FILE)).expect("the cache is removed");
    let refused = root::boot::compose_book(
        journal_lane(&crate::root::store_double::RecordSlots::new()),
        Some(dir.0.clone()),
        0,
        1_700_000_000,
        &token,
    )
    .expect_err("a bootstrapped directory with no keyset refuses");
    let prefix = format!(
        "KeysetMissing: the journal under {} holds a Bootstrap sealing keyset fingerprint ",
        dir.0.display()
    );
    let suffix = format!(
        ", and neither the keyset file {}/deployment-keyset nor the configured store yields that \
         fingerprint. Restore this node's data_dir (the keyset file beside its journal), or boot \
         against a store that holds the deployment keyset",
        dir.0.display()
    );
    assert!(
        refused.starts_with(&prefix) && refused.ends_with(&suffix),
        "the refusal is not KeysetMissing in its own words: {refused}"
    );
    assert_eq!(
        refused.len(),
        prefix.len() + 64 + suffix.len(),
        "the fingerprint is 64 hex characters: {refused}"
    );
}

/// STAGE 4 BOOK IS BOOT-ONLY — ONE SEAL AFTER TWO RELOADS (`BUSBAR-1.6.0.md` §3: "Reload runs
/// stages 1–3 and 5, never Book: the store carries over, and a changed `store:` applies on restart";
/// its *Proven by* names "RED arms for one seal after two reloads"). Boot opens the one book over
/// the store its generation resolved; two reloads then rebuild the generation the way
/// `config/reload` and `config/apply` do, each over the one before it.
///
/// Three facts, read off the things themselves: (a) the third generation still holds the SAME
/// store the boot opened — a reload that reopened it would hand the book's shipper a store no
/// generation serves; (b) the book's chain carries exactly ONE sealed opening; (c) Book is
/// reachable from the boot alone: the crate's one call of `root::boot::book` is `run()`'s, in
/// `main.rs`, so no reload path can seal a second opening onto the chain — which is what makes (b)
/// a claim about reloads and not true by construction. RED arms: a rebuild that drops the prior
/// generation's store (`build_app_from_config` ignoring `prior`) fails (a); a second call of
/// `root::boot::book` anywhere in the crate's code (a reload that reopens Book) fails (c).
#[cfg(linked_axis_body_ingress)]
#[test]
fn one_seal_after_two_reloads() {
    // The provider dialects a lane may name are DECLARED by a registered plane (ruling 2026-10-16 D).
    busbar_kernel::test_support::register_neutral_test_plane();
    use busbar_kernel_wal::RecordClass;

    for decls in crate::LINKED.protocols {
        busbar_kernel::test_support::protocols::register_test_protocols(decls);
    }
    busbar_kernel::snapshot::init();
    let dir = BookDir::new("two-reloads");
    let _env = data_dir_env(&dir.0);
    let cfg = || {
        busbar_kernel::test_support::cfg_with_provider_api_key(
            busbar_kernel::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_ONE_SEAL"),
        )
    };

    let boot = busbar_kernel::test_support::build_once(cfg(), None).expect("the boot builds");
    let book = root::boot::book(&boot, "test-store").expect("the boot book opens");
    let store = boot
        .governance
        .clone()
        .expect("a boot resolves the store its book opens over");
    let first = busbar_kernel::test_support::build_once(cfg(), Some(&boot)).expect("reload 1");
    let second = busbar_kernel::test_support::build_once(cfg(), Some(&first)).expect("reload 2");

    // (a) THE STORE CARRIES OVER.
    assert!(
        Arc::ptr_eq(
            second.governance.as_ref().expect("a reload keeps a store"),
            &store
        ),
        "a reload reopened the store: Book is boot-only, and the generation must carry the store \
         the boot opened"
    );

    // (b) ONE SEAL.
    let openings = book
        .durability
        .lock()
        .expect("the book's lock is unpoisoned")
        .journal
        .replay()
        .expect("the journal reads back")
        .expect("and verifies")
        .iter()
        .filter(|r| r.class == RecordClass::Migration)
        .count();
    assert_eq!(
        openings, 1,
        "two reloads must leave exactly the boot's one sealed opening on the book's chain"
    );

    // (c) BOOK IS BOOT-ONLY: every call of `root::boot::book` in the crate's code (comments and the
    // test modules skipped) is the boot's one, in `main.rs`.
    let calls = book_call_sites(&std::path::Path::new(env!("BUSBAR_CORE_DIR")).join("src"));
    assert_eq!(
        calls,
        vec!["main.rs".to_string()],
        "Book is boot-only: `root::boot::book` must be called once, by the boot in main.rs"
    );
}

/// The file (relative to `src`) of every call of the free function `book(` in the crate's non-test
/// code, however it is reached (`root::boot::book(`, `super::boot::book(`, or a bare `book(` inside
/// `boot.rs`), one entry per call. Not a call: a method (`.book(`), a longer name (`node_book(`)
/// and the definition (`fn book(`). A line comment is skipped, and so is every `tests` directory
/// and `tests.rs`. Read only by [`one_seal_after_two_reloads`], so gated with it.
#[cfg(linked_axis_body_ingress)]
fn book_call_sites(src: &std::path::Path) -> Vec<String> {
    fn walk(root: &std::path::Path, dir: &std::path::Path, out: &mut Vec<String>) {
        let mut entries: Vec<_> = std::fs::read_dir(dir)
            .expect("the crate's src reads")
            .map(|e| e.expect("an entry").path())
            .collect();
        entries.sort();
        for path in entries {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or_default();
            if path.is_dir() {
                if name != "tests" {
                    walk(root, &path, out);
                }
            } else if name.ends_with(".rs") && name != "tests.rs" {
                let text = std::fs::read_to_string(&path).expect("a source file reads");
                let rel = path
                    .strip_prefix(root)
                    .expect("under src")
                    .display()
                    .to_string();
                for line in text.lines() {
                    let code = line.split("//").next().unwrap_or_default();
                    for (at, _) in code.match_indices("book(") {
                        let before = &code[..at];
                        let prev = before.chars().next_back();
                        let ident = prev.is_some_and(|c| c.is_alphanumeric() || c == '_');
                        if !ident && prev != Some('.') && !before.ends_with("fn ") {
                            out.push(rel.clone());
                        }
                    }
                }
            }
        }
    }
    let mut out = Vec::new();
    walk(src, src, &mut out);
    out
}

/// THE IDLE PURGE NEVER WRITES A POSITIVE DECAY TO AN ARENA THAT RAN AT 0. The huge arena (where an
/// oversize allocation lands) runs at decay 0, and a positive decay written to it makes jemalloc start
/// a background thread for it — `not_reached()` on a build without background threads (a SIGTRAP on
/// macOS debug, undefined behaviour in a static-musl release). Restoring the global default to every
/// arena did exactly that on the first idle window after any oversize allocation, killing an idle
/// process that had staged a large plugin library or served a large body.
#[cfg(not(target_env = "msvc"))]
#[test]
fn the_idle_purge_puts_each_arena_back_to_its_own_decay() {
    use tikv_jemalloc_ctl::{Access, AsName};
    // An oversize allocation (well past jemalloc's 8 MiB default threshold) brings the huge arena up.
    let big = vec![1u8; 64 << 20];
    assert_eq!(big[big.len() - 1], 1);
    drop(big);
    let decays = || -> Vec<(u32, isize)> {
        let n: u32 = b"arenas.narenas\0".name().read().unwrap_or(0);
        (0..n)
            .filter_map(|i| {
                let key = format!("arena.{i}.dirty_decay_ms\0");
                Access::<isize>::read(key.as_bytes().name())
                    .ok()
                    .map(|v| (i, v))
            })
            .collect()
    };
    let before = decays();
    assert!(
        before.iter().any(|(_, v)| *v == 0),
        "the huge arena is initialized and runs at decay 0: {before:?}"
    );
    super::purge_idle_arenas();
    super::purge_idle_arenas();
    let after = decays();
    for (i, was) in &before {
        let now = after.iter().find(|(j, _)| j == i).map(|(_, v)| *v);
        assert_eq!(
            now,
            Some(*was),
            "arena {i}'s decay was not put back to its own value"
        );
    }
}

/// THE LINE-SERVE FLAG IS THE PLANE'S (audit busbar-src H1): the root serves a plane on the
/// process's own lines when a flag a linked plane declares is passed, read off the plane's `Flags:`
/// rows; it names no flag of its own. A planted plane's flag asks for it, and the same word no plane
/// declares does not.
#[test]
fn the_line_serve_flag_is_read_off_the_planes_declared_rows() {
    let planted: &[crate::root::linked::CliHelpRow] = &[(
        "flag",
        "    --planted-serve      serve the planted plane on stdin/stdout",
    )];
    let args = |a: &[&str]| {
        a.iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
            .into_iter()
    };
    assert!(line_serve_requested(
        &[planted],
        args(&["busbar", "--planted-serve"])
    ));
    assert!(!line_serve_requested(
        &[],
        args(&["busbar", "--planted-serve"])
    ));
    assert!(!line_serve_requested(&[planted], args(&["busbar"])));
}
