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
/// listener, serve a trivial router through `serve_listener`, and confirm a real HTTP request
/// against it succeeds before the shutdown future fires.
#[tokio::test]
async fn serve_listener_actually_serves_real_http_traffic() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
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

/// EVERY DIAGNOSTIC CODE IS UNIQUE ACROSS THE WHOLE CATALOG — the neutral half in
/// `busbar-substrate-values` AND every plane catalogue the composition root installs.
///
/// Each half is internally consistent on its own, and neither crate can see the other: a plane
/// numbers its codes without the neutral registry in scope, and the neutral registry is compiled
/// long before any plane is linked. THIS binary is the only place both halves exist at once, which
/// is why the check lives here. A collision is not cosmetic — `by_code` resolves a code to the FIRST
/// match, so a duplicate makes one diagnostic permanently unreachable and makes `busbar explain
/// <code>` and a rendered catalog describe the wrong failure.
///
/// `slug` is checked too, for the same reason: it is the other stable handle a catalog is keyed by.
#[test]
fn every_diagnostic_code_is_unique_across_the_neutral_and_plane_catalogues() {
    // The composition root's own registration, so `all()` returns the real runtime union rather
    // than the neutral half alone. This is the only installer in the test binary; a second call
    // would panic by design.
    register_diagnostics();

    let all = busbar_substrate_values::diagnostics::all();
    assert!(
        !all.is_empty(),
        "the catalog must not be empty — the walk would assert nothing"
    );

    let mut by_code: std::collections::HashMap<u16, Vec<&str>> = std::collections::HashMap::new();
    let mut by_slug: std::collections::HashMap<&str, Vec<u16>> = std::collections::HashMap::new();
    for d in &all {
        by_code.entry(d.code).or_default().push(d.slug);
        by_slug.entry(d.slug).or_default().push(d.code);
    }

    let dup_codes: Vec<_> = by_code.iter().filter(|(_, v)| v.len() > 1).collect();
    assert!(
        dup_codes.is_empty(),
        "diagnostic CODES collide across the neutral and plane catalogues: {dup_codes:?}"
    );

    let dup_slugs: Vec<_> = by_slug.iter().filter(|(_, v)| v.len() > 1).collect();
    assert!(
        dup_slugs.is_empty(),
        "diagnostic SLUGS collide across the neutral and plane catalogues: {dup_slugs:?}"
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// A PLANE-GATED MODULE IS NAMED ONLY FROM CODE UNDER THE SAME GATE
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// The features a `#[cfg(feature = "…")]` attribute names, or nothing if it is not a `cfg` gate.
///
/// `cfg_attr` is deliberately NOT a gate: it decorates code that compiles either way, so a feature
/// named inside one says nothing about whether the line it sits over is compiled.
fn cfg_gate_features(attr: &str) -> Vec<String> {
    if !attr.starts_with("#[cfg(") && !attr.starts_with("#![cfg(") {
        return Vec::new();
    }
    const KEY: &str = "feature = \"";
    let mut out = Vec::new();
    let mut rest = attr;
    while let Some(at) = rest.find(KEY) {
        rest = &rest[at + KEY.len()..];
        let Some(end) = rest.find('"') else { break };
        out.push(rest[..end].to_string());
        rest = &rest[end..];
    }
    out
}

/// The net `{`/`(`/`[` minus `}`/`)`/`]` of a line, ignoring what is inside a string literal.
fn bracket_delta(code: &str) -> i32 {
    let mut delta = 0;
    let mut in_str = false;
    let mut escaped = false;
    for c in code.chars() {
        if in_str {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' | '(' | '[' => delta += 1,
            '}' | ')' | ']' => delta -= 1,
            _ => {}
        }
    }
    delta
}

/// The gate every line of a source file is compiled under, as the features named by the `#[cfg(…)]`
/// attributes covering it. `base` is the file's OWN gate — the one its `pub mod` declaration
/// carries — which covers every line in it.
///
/// A LEXICAL READING, not a parse. Bracket depth is what closes a region: an attribute attaches to
/// the item that follows it, and that item ends at the first point where depth is back where it
/// started and the line closes with `;`, `,` or `}`. That covers the shapes the root actually
/// writes — a gated field, a gated parameter, a gated `fn`, a gated `use`, and a gated `if` inside
/// an ungated one — and anything it reads wrongly fails as a false ALARM, which someone reads,
/// rather than a false all-clear, which nobody does.
fn gate_by_line(src: &str, base: &[String]) -> Vec<Vec<String>> {
    let mut out: Vec<Vec<String>> = Vec::new();
    // Regions still open, as (the depth the region closes back to, the features gating it).
    let mut open: Vec<(i32, Vec<String>)> = Vec::new();
    // The attributes read since the last code line, waiting for the item they attach to.
    let mut pending: Vec<String> = Vec::new();
    // A `#[cfg(all(\n  feature = "…",\n))]` spread over lines, held until its brackets balance.
    let mut attr_buf = String::new();
    let mut depth: i32 = 0;
    for raw in src.lines() {
        let mut active: Vec<String> = base.to_vec();
        for (_, feats) in &open {
            active.extend(feats.iter().cloned());
        }
        let code = raw.split("//").next().unwrap_or("").trim().to_string();
        if !attr_buf.is_empty() {
            attr_buf.push_str(&code);
            if bracket_delta(&attr_buf) == 0 {
                pending.extend(cfg_gate_features(&attr_buf));
                attr_buf.clear();
            }
            active.extend(pending.iter().cloned());
            out.push(active);
            continue;
        }
        let attribute = code.starts_with("#[") || code.starts_with("#![");
        if attribute && bracket_delta(&code) != 0 {
            attr_buf = code;
            active.extend(pending.iter().cloned());
            out.push(active);
            continue;
        }
        if attribute && code.ends_with(']') {
            pending.extend(cfg_gate_features(&code));
            active.extend(pending.iter().cloned());
            out.push(active);
            continue;
        }
        if attribute {
            // `#[cfg(…)] field: Ty,` — the gate and the code it gates on one line.
            let head = code.find(']').map_or("", |at| &code[..=at]);
            pending.extend(cfg_gate_features(head));
        }
        active.extend(pending.iter().cloned());
        out.push(active);
        if code.is_empty() {
            continue;
        }
        // A code line: whatever was pending gates the item it opens, until that item ends.
        let start = depth;
        depth += bracket_delta(&code);
        let closes = code.ends_with(';') || code.ends_with(',') || code.ends_with('}');
        if !pending.is_empty() && !(depth <= start && closes) {
            open.push((start, std::mem::take(&mut pending)));
        }
        pending.clear();
        while let Some((closes_at, _)) = open.last() {
            if depth <= *closes_at && closes {
                open.pop();
            } else {
                break;
            }
        }
    }
    out
}

/// Every `.rs` file under `dir`, test files excluded — a test naming a plane's module is compiled
/// under its own `#[cfg(test)]` gate and is not the shipped path this invariant is about.
fn source_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("the crate's own source tree is readable") {
        let path = entry.expect("a readable directory entry").path();
        if path.is_dir() {
            if path.file_name().is_none_or(|n| n != "tests") {
                source_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "rs")
            && path.file_name().is_some_and(|n| n != "tests.rs")
        {
            out.push(path);
        }
    }
}

/// A ROOT MODULE GATED ON A PLANE'S FEATURE IS NAMED ONLY FROM CODE UNDER THE SAME FEATURE.
///
/// The point of gating `units_<plane>` on `root-<plane>` is that the plane is DELETABLE: a build
/// without the feature must still compile, boot and serve the remaining planes. One unconditional
/// call into a gated module takes that away, and takes it away SILENTLY — every default build is
/// green, and only the deletion gates, which are not what a change is usually run against, go red.
/// That is exactly how a root whose shared rate card was built through one plane's unit file
/// shipped: the card is the root's, every plane's exit prices against it, and no build without
/// that one plane could compile it.
///
/// So the rule is read off the source rather than trusted, and nothing here spells a plane: the
/// gated module names and their features come from `root/mod.rs` itself, and every line in this
/// crate that names one must be compiled under a `#[cfg]` carrying the same feature — from the
/// file's own declaration or from an attribute over the line.
#[test]
fn a_plane_gated_module_is_named_only_from_code_under_the_same_feature() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let root_mod = std::fs::read_to_string(src.join("root/mod.rs"))
        .expect("the composition root's own module file is where the gates are declared");

    // (module name, the single feature its declaration is gated on).
    let mut gated: Vec<(String, String)> = Vec::new();
    let lines: Vec<&str> = root_mod.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let feats = cfg_gate_features(line.trim());
        let [feature] = feats.as_slice() else {
            continue;
        };
        let Some(decl) = lines.get(i + 1).map(|l| l.trim()) else {
            continue;
        };
        let Some(name) = decl
            .strip_prefix("pub mod ")
            .or_else(|| decl.strip_prefix("mod "))
            .and_then(|rest| rest.strip_suffix(';'))
        else {
            continue;
        };
        gated.push((name.to_string(), feature.clone()));
    }
    assert!(
        gated.len() >= 4,
        "the root declares one feature-gated module per switched plane, or this test is reading \
         the wrong file: found {gated:?}"
    );

    let mut files = Vec::new();
    source_files(&src, &mut files);
    assert!(
        files.len() > 10,
        "the crate's source tree is more than {} files, or this test is walking the wrong one",
        files.len()
    );

    let mut escapes: Vec<String> = Vec::new();
    for file in &files {
        let text = std::fs::read_to_string(file).expect("a source file this test just listed");
        // The file's OWN gate: a gated module's whole body compiles under its feature, so a reach
        // between two files of the same plane is not an escape.
        let stem = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let parent = file
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        let base: Vec<String> = gated
            .iter()
            .filter(|(name, _)| name == stem || name == parent)
            .map(|(_, feature)| feature.clone())
            .collect();
        let gate = gate_by_line(&text, &base);
        for (i, line) in text.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("");
            for (name, feature) in &gated {
                if !code.contains(&format!("{name}::")) || gate[i].iter().any(|f| f == feature) {
                    continue;
                }
                let at = file.strip_prefix(&src).unwrap_or(file).display();
                escapes.push(format!(
                    "{at}:{}: names `{name}::` with no `{feature}` gate over it",
                    i + 1
                ));
            }
        }
    }
    assert!(
        escapes.is_empty(),
        "a plane's module is reached from code that compiles without that plane — the build \
         without the feature cannot compile, and only the deletion gates would say so:\n  {}",
        escapes.join("\n  ")
    );
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE BOOT BOOK: IT REACHES THE CONFIGURED STORE, AND ITS OPENING IS SEALED BEFORE ANYTHING SETTLES
//
// Two facts, and the previous shape failed both. `node_book()` hard-coded `data_dir: None` and a
// `NullShipper`, so a deployment that configured a data directory wrote its book nowhere; and
// `root::migration::run` had no caller outside its own tests, so no opening was ever sealed. Every
// settlement therefore measured its residual from a checkpoint that was never written.
//
// The three tests below are one proof in three parts, and they are deliberately split by WHAT EACH
// CAN SEE rather than by what each asserts:
//
//   * `the_boot_path_opens_the_configured_directory_and_seals_before_it_settles` drives the REAL
//     path — a real `App` out of the real `build_app_from_config`, then `open_boot_book`, the exact
//     function `run()` calls. It can see the directory and the chain, so it proves the data
//     directory is honoured and the ORDER holds.
//   * `the_boot_book_ships_its_opening_to_the_configured_store` drives `compose_boot_book`, the seam
//     `open_boot_book` calls, over a store adapter the TEST holds. The shipped count lives on the
//     adapter, so this is the only vantage point from which "the store's shipper, not the null one"
//     is observable at all.
//   * `no_configured_directory_still_opens_nothing_and_writes_nothing` holds the other half of the
//     discipline: the fix gives a node WITH a directory somewhere to write, and must not make
//     writing unconditional.
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// A scratch directory that removes itself, so a failing assertion never leaves a tree behind and
/// two runs of the same test never read each other's journal.
struct BookDir(std::path::PathBuf);

impl BookDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "busbar-boot-book-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("a clock after the epoch")
                .as_nanos()
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

/// The migration config a seam test opens over: a plan naming nothing, so an empty deployment seals
/// a ZERO opening rather than refusing, and the two facts under test are proved without seeding rows
/// the seal would then have to read back.
fn empty_opening_plan() -> root::migration::MigrationConfig {
    root::migration::MigrationConfig {
        node: 0,
        window: 0,
        group_buckets: Vec::new(),
        metering_days: Vec::new(),
        rate_card_version: 7,
    }
}

/// THE REAL PATH, END TO END: a real `App`, then `open_boot_book` — the function `run()` calls at
/// the line that used to read `node_book()` — against a CONFIGURED data directory.
///
/// Three assertions, in the order the defect broke them:
///
/// (a) THE BOOK REACHES THE CONFIGURED STORE. With `BUSBAR_DATA_DIR` set, the node's own journal is
///     ON DISK and files appear IN THAT DIRECTORY. Under the old `node_book()` the directory was
///     never read — `data_dir: None` was a literal — so the journal was memory-buffered and this
///     listing was empty no matter what the operator configured.
///
/// (b) THE OPENING IS SEALED. A migration marker is readable off the book's own chain. The old boot
///     never called the migration at all, so there was no marker anywhere and nothing had opened the
///     deployment's balances.
///
/// (c) THE SEAL COMES FIRST — which is the whole point, and the reason (b) alone would not be a
///     proof. The marker is the FIRST record on the chain; a settlement made afterwards lands
///     STRICTLY AFTER it. An opening sealed after traffic has begun is worse than useless, because
///     it looks authoritative while measuring from the wrong point.
#[test]
fn the_boot_path_opens_the_configured_directory_and_seals_before_it_settles() {
    use busbar_kernel_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey};
    use busbar_kernel_wal::RecordClass;

    // ORDER-INDEPENDENCE, not decoration. `cfg_with_provider_api_key` names the registry's
    // residual-default dialect, and in a test binary the protocol set is installed by whichever
    // test installs it first — so without this the test passes in a full run and fails run alone.
    // Every linked protocol declaration goes into the test registry, read off the linked table
    // the root registers from.
    for decls in crate::LINKED.protocols {
        busbar_kernel::proto::register_test_protocols(decls);
    }
    busbar_kernel::metrics::init();
    let dir = BookDir::new("real-path");
    assert!(
        dir.entries().is_empty(),
        "the fixture directory starts empty, or nothing below is evidence of anything"
    );

    // THE CONFIGURED DIRECTORY. `BUSBAR_DATA_DIR` is the one source `preflight::fleet_data_dir`
    // resolves today (there is no `data_dir:` config key yet — see that function's own comment), and
    // it is the SAME accessor the plugin anti-downgrade floor persists under, which is why the boot
    // book reads it through that function rather than probing for itself.
    let _guard = busbar_kernel::test_support::EnvVarGuard::capture("BUSBAR_DATA_DIR");
    std::env::set_var("BUSBAR_DATA_DIR", &dir.0);

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
    let book = open_boot_book(&app);

    let (on_disk, marker, first_record) = {
        let durability = book
            .durability
            .lock()
            .expect("the book's lock is unpoisoned");
        let replayed = durability
            .journal
            .replay()
            .expect("the journal on the configured directory reads back")
            .expect("and verifies");
        (
            durability.on_disk(),
            durability.migration_marker(),
            replayed,
        )
    };

    // (a) THE CONFIGURED DIRECTORY IS WHERE THE BOOK WENT.
    assert!(
        on_disk,
        "with a data directory configured the node's book must be on this node's own disk; it was \
         memory-buffered, which is the `data_dir: None` literal the boot used to hard-code"
    );
    assert!(
        !dir.entries().is_empty(),
        "the configured data directory holds no file: the book never reached it. The listing is \
         the assertion, not the mode flag above"
    );

    // (b) THE OPENING IS SEALED.
    assert!(
        marker.is_some(),
        "the boot must SEAL the opening balances; no migration marker is on the book's chain, which \
         is what a boot that never called the migration leaves behind"
    );

    // (c) AND IT WAS SEALED FIRST. Nothing else is on the chain yet — the book has not been handed
    //     to a listener, and this is the instant before the first connection could settle.
    assert_eq!(
        first_record.len(),
        1,
        "exactly the opening's marker is on the chain at the moment the boot hands the book over; \
         found {} records",
        first_record.len()
    );
    assert_eq!(
        first_record[0].class,
        RecordClass::Migration,
        "the FIRST record on the node's chain is the sealed opening's marker"
    );
    let opening_seq = first_record[0].node_seq;

    // Now settle, the way an exit arm does, and prove the ORDER rather than merely the presence: the
    // settlement's record is strictly after the opening's. This is the sentence the defect made
    // false — a settlement measured from a checkpoint that was not there when it happened.
    let kernel = root::kernel::new_kernel();
    let durability_token = kernel.durability_token();
    let key = TotalsKey::new(
        BucketId::new("vk_boot_order"),
        CapDimension::NanoUnits,
        BucketScope::All,
    );
    let settled = {
        let mut durability = book
            .durability
            .lock()
            .expect("the book's lock is unpoisoned");
        durability.ledger.record_hold_opened(&key, 86_400, 5_000);
        let hold = busbar_contract::caps::Hold::open(
            &kernel.admit_token(),
            busbar_contract::caps::PrincipalId::new("vk_boot_order"),
            5_000,
        );
        let usage = busbar_contract::caps::Usage::report(
            &kernel.usage_token(),
            vec![busbar_contract::caps::UsageLine {
                class: busbar_contract::caps::MeterClassId::new("nano_units"),
                quantity: 4_200,
                source: busbar_contract::caps::QuantitySource::Count,
                estimated: false,
            }],
        )
        .expect("one usage line");
        durability
            .settle(
                &root::durability::Settling {
                    key: &key,
                    window: 86_400,
                    durability: &durability_token,
                    step: busbar_contract::caps::StepName::Meter,
                    stamp: root::durability::PostingStamp {
                        rate_card_version: 3,
                        wall: 1_700_000_000,
                        mono: 42,
                    },
                },
                hold,
                4_200,
                &usage,
                &kernel.ledger_token(),
            )
            .expect("the configured store takes the settlement's batch")
    };
    assert_eq!(settled.settlement.posted.settled(), 4_200);

    let after = {
        let durability = book
            .durability
            .lock()
            .expect("the book's lock is unpoisoned");
        durability
            .journal
            .replay()
            .expect("the journal reads back")
            .expect("and verifies")
    };
    let posting = after
        .iter()
        .find(|r| r.class == RecordClass::Transaction)
        .expect("the settlement is on the same chain the opening is on");
    assert!(
        posting.node_seq > opening_seq,
        "the settlement (seq {}) must come AFTER the sealed opening (seq {}) on the one chain — an \
         opening sealed after traffic has begun looks authoritative and measures from the wrong \
         point",
        posting.node_seq,
        opening_seq
    );
}

/// THE STORE HALF, at the only vantage point it is visible from: `compose_boot_book`, the seam
/// `open_boot_book` calls, handed a `StoreAdapter` the TEST holds.
///
/// The shipped count and the acknowledged head live on the ADAPTER — `open_boot_book` builds its own
/// from `gov.store()`, so from outside the real path there is nothing to read them off. This drives
/// the same seam with an adapter in hand and asserts what that buys: the opening's batch was
/// OFFERED TO THE CONFIGURED STORE and acknowledged under this node's identity. A `NullShipper` —
/// the literal the old `node_book()` passed — would leave both readings at nothing, which is exactly
/// the difference between the two shapes.
///
/// The adapter is the real one over the real in-tree memory store: the store a config naming none
/// resolves to at boot. Not a recording double.
#[test]
fn the_boot_book_ships_its_opening_to_the_configured_store() {
    use busbar_kernel_wal::RecordClass;
    use busbar_plugin_loader::store_adapter::StoreAdapter;

    let dir = BookDir::new("ships");
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(busbar_kernel::governance::MemoryStore::new());
    let adapter = StoreAdapter::native(store);
    let mig = empty_opening_plan();
    let token = root::kernel::new_kernel().durability_token();

    let (durability, _rows, migration) =
        compose_boot_book(&adapter, Some(dir.0.clone()), &mig, 1_700_000_000, &token)
            .expect("the boot book composes over the configured directory and an empty store");

    assert!(
        migration.sealed_now(),
        "the composition must SEAL the opening at start-of-book, not hand back an unopened book"
    );
    let replayed = durability
        .journal
        .replay()
        .expect("the journal reads back")
        .expect("and verifies");
    assert_eq!(
        replayed.len(),
        1,
        "exactly the one opening marker is on the chain"
    );
    assert_eq!(
        replayed[0].class,
        RecordClass::Migration,
        "the sealed opening's marker is a Migration record"
    );

    // THE ASSERTION THIS TEST EXISTS FOR. The batch reached the CONFIGURED store's shipper.
    let shim = adapter.shim_state();
    assert!(
        shim.records_shipped >= 1,
        "the book must ship its batch to the configured store's shipper (shipped {}), which a \
         NullShipper would never receive — that literal is the defect",
        shim.records_shipped
    );
    assert_eq!(
        adapter.head(),
        Some((mig.node, replayed[0].node_seq)),
        "the store acknowledged the opening under THIS node's identity and the marker's sequence"
    );
}

/// THE OTHER HALF OF THE DISCIPLINE, and it is not a footnote: constructing an on-disk journal IS
/// the decision to write to a disk, so a node whose configuration names NO data directory must
/// still open nothing and leave nothing behind. The fix gives a node WITH a directory somewhere to
/// write; it must not make writing unconditional.
///
/// The seal and the shipping still happen — those are the store's business, not the disk's — so
/// this also pins that the two decisions are independent: no directory does not mean no opening.
#[test]
fn no_configured_directory_still_opens_nothing_and_writes_nothing() {
    use busbar_plugin_loader::store_adapter::StoreAdapter;

    // A directory the node was never told about. Nothing may appear in it.
    let unnamed = BookDir::new("unnamed");
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(busbar_kernel::governance::MemoryStore::new());
    let adapter = StoreAdapter::native(store);
    let token = root::kernel::new_kernel().durability_token();

    let (durability, _rows, migration) =
        compose_boot_book(&adapter, None, &empty_opening_plan(), 1_700_000_000, &token)
            .expect("a memory-buffered book composes");

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
        migration.sealed_now(),
        "no data directory is not no opening: the balances are still sealed, into the store"
    );
    assert!(
        adapter.shim_state().records_shipped >= 1,
        "without a directory the book's durability IS the store's, so the batch must still be \
         offered to it"
    );
}

/// ITEMS 244, 247, 259 — THREE DOC CLAIMS IN `main.rs` THAT THE CODE BESIDE THEM CONTRADICTED.
///
/// Read off the source, because each claim is prose and the code that falsifies it sits beside it:
/// `register_planes` registers every linked entry, and the manifest links the A2A plane's crate (so
/// "A2A is still built into core ... not pushed here yet" was false); `main()`/`run()` call into
/// `root::` throughout (so "Nothing in `main()` calls into it yet" was false); and exactly one root
/// unit binds the boot book — the LLM arm's — while the admin views share it (so "Every plane's exit
/// arm settles onto it" was false for mcp/a2a/voice).
#[test]
fn main_rs_doc_claims_match_the_code_beside_them() {
    const MAIN: &str = include_str!("../main.rs");
    const MANIFEST: &str = include_str!("../../Cargo.toml");

    // 244: the A2A plane IS registered — its crate is a linked row and `register_planes` registers
    // every linked entry — so its doc may not say otherwise.
    // The manifest's linked row for the plane the old doc said was not pushed — manifest data, kept
    // in a fixture so this test names no plane.
    const PUSHED_ROW: &str = include_str!("../../tests/fixtures/pushed_plane_linked_row.txt");
    assert!(MANIFEST.contains(PUSHED_ROW.trim_end()));
    let register_planes = &MAIN[MAIN
        .find("\nfn register_planes() {")
        .expect("register_planes")..];
    let register_planes = &register_planes[..register_planes.find("\n}\n").expect("it closes")];
    assert!(register_planes.contains("root::linked::register_planes(&LINKED, "));
    assert!(
        !MAIN.contains("is not pushed here yet"),
        "register_planes' doc says a plane is not pushed, and the function registers every linked plane"
    );

    // 247: `main()` calls into `root::`, so the `mod root;` doc may not say nothing does.
    let main_fn = &MAIN[MAIN.find("\nfn main() {").expect("main() is in main.rs")..];
    let main_body = &main_fn[..main_fn.find("\n}\n").expect("main() closes")];
    assert!(
        main_body.contains("root::"),
        "the control: main() reaches root::"
    );
    assert!(
        !MAIN.contains("Nothing in `main()` calls into it"),
        "the `mod root;` doc says main() does not call into the root, and it does"
    );

    // 259: exactly one root unit binds the boot book (the LLM arm), so the book's doc may not claim
    // every plane settles onto it.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/root");
    let binders = std::fs::read_dir(&root)
        .expect("the composition root")
        .map(|e| e.expect("a directory entry").path())
        .filter(|p| p.extension().is_some_and(|x| x == "rs"))
        .filter(|p| {
            std::fs::read_to_string(p)
                .expect("a readable unit")
                .contains("on_book: Some(|ctx| bind_book(")
        })
        .count();
    assert_eq!(binders, 1);
    assert!(MAIN.contains("ROOT_UNITS.iter().filter_map(|u| u.on_book)"));
    assert!(
        !MAIN.contains("Every plane's exit arm settles onto it"),
        "the boot book's doc claims every plane settles onto it; only one root unit's arm is bound here"
    );
}
