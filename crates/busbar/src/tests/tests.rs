// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::cli::{
    config_override_notice, providers_override_notice, resolve_config_path,
    signing_key_command_output, Argv,
};

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

#[test]
fn validate_worker_threads_config_diagnoses_zero() {
    assert!(
        validate_worker_threads_config(Some(0)).is_err(),
        "worker_threads: 0 must be diagnosed, not silently dropped"
    );
    assert_eq!(validate_worker_threads_config(Some(4)), Ok(Some(4)));
    assert_eq!(validate_worker_threads_config(None), Ok(None));
}

#[test]
fn worker_threads_from_config_reads_a_real_file() {
    const CHILD: &str = "BUSBAR_WORKER_CONFIG_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = concat!(
            module_path!(),
            "::worker_threads_from_config_reads_a_real_file"
        );
        let test_name = name.split_once("::").unwrap().1;
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name])
            .env(CHILD, "1")
            .env("BUSBAR_WORKER_THREADS", "19")
            .output()
            .expect("run the config environment case in a fresh process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(&format!("test {test_name} ... ok")),
            "{stdout}"
        );
        assert!(
            output.status.success(),
            "the config environment case passes: {stdout}"
        );
        return;
    }
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
    assert_eq!(
        resolve_worker_threads().0,
        5,
        "retired BUSBAR_WORKER_THREADS cannot override configured workers"
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

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn ignore_overlay_requested_matches_the_exact_flag_only() {
    for (arg, expected) in [
        ("--ignore-overlay", true),
        ("--safe-mode", false),
        ("--ignore-overlay=true", false),
        ("--validate", false),
    ] {
        assert_eq!(
            ignore_overlay_requested(vec!["busbar".to_string(), arg.to_string()].into_iter()),
            expected,
            "{arg}"
        );
    }
    assert!(!ignore_overlay_requested(std::iter::empty()));
}

#[test]
fn value_flag_parses_all_accepted_forms() {
    let config = |a: &[&str]| Argv::parse(a).config;
    let providers = |a: &[&str]| Argv::parse(a).providers;

    assert_eq!(
        config(&["--config", "/a/config.yaml"]),
        Some("/a/config.yaml".to_string())
    );

    assert_eq!(
        config(&["--config=/b/config.yaml"]),
        Some("/b/config.yaml".to_string())
    );

    assert_eq!(
        config(&["-c", "/c/config.yaml"]),
        Some("/c/config.yaml".to_string())
    );

    assert_eq!(
        config(&["-c", "/first", "--config", "/second"]),
        Some("/second".to_string())
    );

    assert_eq!(providers(&["--validate"]), None);
    assert_eq!(
        providers(&["--providers", "/p/providers.yaml"]),
        Some("/p/providers.yaml".to_string())
    );
}

#[test]
fn resolve_config_path_flag_wins() {
    assert_eq!(
        resolve_config_path(Some("/flag/config.yaml")),
        "/flag/config.yaml".to_string()
    );
}

#[test]
fn config_override_notice_fires_only_on_a_real_override() {
    let n = config_override_notice(Some("/flag.yaml"), Some("/env.yaml")).expect("notice");
    assert!(
        n.contains("/flag.yaml") && n.contains("/env.yaml"),
        "got {n}"
    );

    assert_eq!(
        config_override_notice(Some("/same.yaml"), Some("/same.yaml")),
        None
    );

    assert_eq!(config_override_notice(Some("/flag.yaml"), None), None);

    assert_eq!(config_override_notice(None, Some("/env.yaml")), None);
}

#[test]
fn providers_override_notice_names_both_only_on_a_real_override() {
    let n = providers_override_notice(Some("/flag.yaml"), Some("catalog.yaml")).expect("notice");
    assert!(
        n.contains("/flag.yaml") && n.contains("catalog.yaml") && n.contains("providers_file"),
        "the notice must name both the flag and the config's providers_file: {n}"
    );

    assert_eq!(providers_override_notice(Some("/flag.yaml"), None), None);

    assert_eq!(
        providers_override_notice(Some("catalog.yaml"), Some("catalog.yaml")),
        None
    );

    assert_eq!(providers_override_notice(None, Some("catalog.yaml")), None);
}

#[tokio::test(start_paused = true)]
async fn recv_shutdown_blocks_until_a_send_then_resolves() {
    let (tx, rx) = tokio::sync::broadcast::channel(1);
    let handle = tokio::spawn(recv_shutdown(rx));

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

#[tokio::test]
async fn shutdown_signal_blocks_when_no_signal_is_delivered() {
    let result =
        tokio::time::timeout(std::time::Duration::from_millis(200), shutdown_signal()).await;
    assert!(
        result.is_err(),
        "shutdown_signal must still be pending with no real signal delivered, not resolve as a no-op"
    );
}

#[cfg(unix)]
#[tokio::test]
async fn serve_listener_actually_serves_real_http_traffic() {
    let listener = Listening::bind_stream(None, "127.0.0.1:0", ROOT_BIND_LIMITS).unwrap();
    let addr = listener.local_addr();
    let router = Router::new().route("/probe", axum::routing::get(|| async { "ok" }));
    let secret_resolver = Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());
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

#[test]
fn signing_key_guidance_omits_secret() {
    let hex = busbar_kernel::boot::generate_signing_key_hex().expect("generate a signing key");
    assert_eq!(hex.len(), 64, "sanity: an ed25519 secret is 64 hex chars");

    let (stdout, stderr) = signing_key_command_output(&hex);

    assert_eq!(
        stdout, hex,
        "the secret must be printed verbatim on stdout for `> /run/secrets/...` capture"
    );

    assert!(
        !stderr.contains(&hex),
        "the stderr guidance must be secret-free — it must never embed the generated key"
    );

    assert!(
        stderr.contains("export BUSBAR_SIGNING_KEY=<paste-the-64-hex-key-printed-above>"),
        "the guidance must use a non-secret placeholder pointing at the stdout key"
    );
}

#[test]
fn build_info_line_format_is_locked() {
    let line = build_info_line();

    for key in [
        "profile=",
        "opt-level=",
        "lto=",
        "debug-assertions=",
        "pgo=",
        "target=",
        "target-cpu=",
        "target-features=",
        "codegen-units=",
        "receipt=",
        "package=",
        "manifest=",
        "source-commit=",
        "source-clean=",
    ] {
        assert!(
            line.contains(key),
            "build_info_line() must expose `{key}` — the build-provenance gate parses it. Got: {line}"
        );
    }

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

#[test]
fn the_pgo_stamp_is_derived_only_from_the_flags_that_reached_the_compiler() {
    use crate::build_stamp::{flag_value, pgo_from_flags};

    assert!(pgo_from_flags(&["-Cprofile-use=/tmp/merged.profdata"]));
    assert!(pgo_from_flags(&["-C", "profile-use=/tmp/merged.profdata"]));
    assert!(pgo_from_flags(&[
        "-Cprofile-use=/tmp/merged.profdata",
        "-Ctarget-cpu=native"
    ]));

    assert!(!pgo_from_flags(&[]));
    assert!(!pgo_from_flags(&["-Ctarget-cpu=native", "-Clto=fat"]));
    assert!(
        !pgo_from_flags(&["-Cprofile-generate=/tmp/prof"]),
        "the training build writes a profile, it does not consume one"
    );
    assert!(!pgo_from_flags(&[
        "-Cprofile-generate=/tmp/profile-use-training"
    ]));
    assert!(!pgo_from_flags(&["--cfg", "profile-use"]));

    let _: fn(&[&str]) -> bool = pgo_from_flags;
    for asserted in ["1", "true", "yes", "BUSBAR_PGO=1"] {
        assert!(
            !pgo_from_flags(&[asserted]),
            "an asserted value ({asserted}) is not a compiler flag and must not read as PGO"
        );
    }

    let flags = ["-Cprofile-use=/tmp/m.profdata", "-Ctarget-feature=+lse"];
    assert_eq!(
        flag_value(&flags, "target-feature").as_deref(),
        Some("+lse")
    );
    assert_eq!(flag_value(&flags, "target-cpu"), None);
    assert_eq!(flag_value(&flags, "lto"), None);
}

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

    assert_eq!(
        flag_value(&["-C", "lto=fat"], "lto").as_deref(),
        Some("fat")
    );
    assert_eq!(
        flag_value(&["-Ctarget-cpu=native"], "target-cpu").as_deref(),
        Some("native")
    );
    assert_eq!(flag_value(&["-Clto"], "lto").as_deref(), Some("fat"));
    assert_eq!(flag_value(&["-C", "lto"], "lto").as_deref(), Some("fat"));
    assert_eq!(
        flag_value(&["-Clto", "-Clto=thin"], "lto").as_deref(),
        Some("thin")
    );
    assert_eq!(
        flag_value(
            &["-Ctarget-feature=+sse2", "-C", "target-feature=+avx,-sse2"],
            "target-feature"
        )
        .as_deref(),
        Some("+sse2,+avx,-sse2"),
        "rustc combines target-feature options in order, with later entries overriding earlier ones"
    );
    assert_eq!(
        flag_value(&["--cfg", "target-cpu=native"], "target-cpu"),
        None
    );
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

#[cfg(distribution_root)]
#[tokio::test]
async fn the_boot_path_keeps_its_journal_in_the_store_with_a_configured_directory() {
    const CHILD: &str = "BUSBAR_JOURNAL_DIRECTORY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = concat!(
            module_path!(),
            "::the_boot_path_keeps_its_journal_in_the_store_with_a_configured_directory"
        );
        let test_name = name.split_once("::").unwrap().1;
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name])
            .env(CHILD, "1")
            .output()
            .expect("run the journal directory case in a fresh process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(&format!("test {test_name} ... ok")),
            "{stdout}"
        );
        assert!(
            output.status.success(),
            "the journal directory case passes: {stdout}"
        );
        return;
    }
    crate::dist_root_install::install();
    use busbar_kernel_wal::RecordClass;

    let dir = BookDir::new("real-path");
    assert!(
        dir.entries().is_empty(),
        "the fixture directory starts empty, or nothing below is evidence of anything"
    );

    std::env::set_var("BUSBAR_DATA_DIR", &dir.0);

    let store_module = crate::LINKED
        .stores
        .iter()
        .find(|store| store.1)
        .expect("the distribution links its real ephemeral product store")
        .0;
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {},
            "models": {},
            "store": { "module": store_module },
            "auth": { "chain": [], "admin_auth": [] },
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let rules =
        Arc::new(root::door_steps::Rules::default()) as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = crate::root::real_store::build_app(
        config,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the production root builds the app and opens its real store through the ABI");
    limits.stage_boot();
    let book = root::boot::book(&app, "test-store")
        .await
        .expect("the boot book opens");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }

    let (on_disk, journal) = {
        let durability = book
            .durability
            .lock()
            .expect("the book's lock is unpoisoned");
        (durability.on_disk(), durability.journal.clone())
    };
    let first_record = journal
        .read_records(root::durability::tests::BUDGET)
        .await
        .expect("the configured Store reads its verified journal");

    assert!(!on_disk, "the configured Store owns journal persistence");
    assert!(dir.entries().is_empty(), "boot created local state");
    assert!(book.durability.lock().unwrap().durable_in_store());
    assert_eq!(
        first_record.iter().map(|r| r.class).collect::<Vec<_>>(),
        vec![RecordClass::Bootstrap],
        "the keyset's Bootstrap, and no money record, is on the chain when the boot hands the \
         journal over"
    );
}

// Native Store admission requires every primitive before a CoreStore can exist.
// The retired optional-slot case is covered at that boundary by plugin-loader's
// dispatch_tests and store_v4_tests retired-table refusal witnesses.

#[tokio::test]
async fn the_boot_book_ships_its_records_to_the_configured_store() {
    use busbar_kernel_wal::RecordClass;
    let dir = BookDir::new("ships");
    let fixture = root::durability::tests::NativeFixture::new(7).await;
    root::kernel::ROOT_CARD
        .keep_in_store(fixture.core.clone(), 7)
        .expect("the price owner binds the journal's actual configured CoreStore");
    let token = root::kernel::new_kernel().durability_token();
    let durability = root::boot::compose_book(
        fixture.journal.clone(),
        &fixture.identity().await,
        7,
        1_700_000_000,
        &token,
    )
    .await
    .expect("the boot journal composes over its native Store");
    durability
        .journal
        .flush()
        .await
        .expect("the Store confirms Bootstrap");
    let replayed = fixture
        .journal
        .read_records(root::durability::tests::BUDGET)
        .await
        .expect("the actual native Store reads its confirmed records");
    assert_eq!(
        replayed.iter().map(|r| r.class).collect::<Vec<_>>(),
        vec![RecordClass::Bootstrap],
        "exactly the keyset's Bootstrap is on the chain"
    );
    assert_eq!(replayed[0].node, 7, "the Store keeps this node's Bootstrap");
    assert!(
        dir.entries().is_empty(),
        "Store persistence creates no local journal"
    );
}

#[tokio::test]
async fn no_configured_directory_still_opens_nothing_and_writes_nothing() {
    let unnamed = BookDir::new("unnamed");
    let fixture = root::durability::tests::NativeFixture::new(7).await;
    root::kernel::ROOT_CARD
        .keep_in_store(fixture.core.clone(), 7)
        .expect("the price owner binds the journal's actual configured CoreStore");
    let token = root::kernel::new_kernel().durability_token();
    let durability = root::boot::compose_book(
        fixture.journal.clone(),
        &fixture.identity().await,
        7,
        1_700_000_000,
        &token,
    )
    .await
    .expect("a Store-backed journal composes without a directory");
    assert!(
        !durability.on_disk(),
        "no data directory means no journal on disk"
    );
    assert_eq!(
        unnamed.entries(),
        Vec::<String>::new(),
        "no unrequested local state"
    );
    durability
        .journal
        .flush()
        .await
        .expect("the Store confirms the boot's records");
    assert!(
        !fixture
            .journal
            .read_records(root::durability::tests::BUDGET)
            .await
            .expect("read the Store's originals")
            .is_empty(),
        "without a directory the records remain durable in the configured Store"
    );
}

#[tokio::test]
async fn the_boot_book_binds_the_store_keyset_and_refuses_a_mismatched_store_key() {
    const CHILD: &str = "BUSBAR_NATIVE_KEYSET_FIXTURE_CHILD";
    const TEST: &str =
        "tests::the_boot_book_binds_the_store_keyset_and_refuses_a_mismatched_store_key";
    const WITNESS: &str = "native keyset fixture entered";
    if std::env::var_os(CHILD).is_none() {
        let output = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(CHILD, "1")
            .kill_on_drop(true)
            .output()
            .await
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains(WITNESS),
            "{stdout}\n{stderr}"
        );
        return;
    }
    println!("{WITNESS}");

    use busbar_kernel::persistence::{
        boot_identity::{BootIdentity, INSTANCE, KEYSET_SCHEMA},
        journal::{BufferBudget, RuntimeJournal},
        scoped::{Expected, Mutation, Outcome, Predicate, Request, ScopedStore},
    };
    let token = root::kernel::new_kernel().durability_token();
    let dir = BookDir::new("keyset");
    let core = crate::root::real_store::core().await;
    let identity = BootIdentity::new(core.clone()).unwrap();
    root::kernel::ROOT_CARD
        .keep_in_store(core.clone(), 7)
        .expect("native card owner");
    root::kernel::ROOT_CARD.card_applied(&Default::default(), "keyset fixture");
    let budget = BufferBudget {
        records: 65536,
        bytes: 64 * 1024 * 1024,
    };
    let first = root::boot::compose_book(
        RuntimeJournal::open(core.clone(), 7, budget).await.unwrap(),
        &identity,
        7,
        1_700_000_000,
        &token,
    )
    .await
    .unwrap();
    let key_id = first.record.signing_key_id().unwrap().to_string();
    assert!(root::durability::keyset_of(&first.record)
        .get(&key_id)
        .is_some());
    let seed = root::durability::stored_keyset(&identity)
        .await
        .unwrap()
        .unwrap();
    first.journal.flush().await.unwrap();
    drop(first);
    let restarted = root::boot::compose_book(
        RuntimeJournal::open(core.clone(), 7, budget).await.unwrap(),
        &identity,
        7,
        1_700_000_001,
        &token,
    )
    .await
    .unwrap();
    assert_eq!(restarted.record.signing_key_id(), Some(key_id.as_str()));
    assert!(restarted.keeps_chain());
    assert_eq!(
        restarted
            .chain()
            .await
            .unwrap()
            .unwrap()
            .iter()
            .filter(|r| r.class == busbar_kernel_wal::RecordClass::Bootstrap)
            .count(),
        1
    );
    assert!(dir.entries().is_empty());
    restarted.journal.flush().await.unwrap();
    drop(restarted);
    let legacy = dir.0.join("deployment-keyset");
    std::fs::write(&legacy, seed.as_bytes()).unwrap();
    let records =
        ScopedStore::host_private(core.clone(), INSTANCE, [KEYSET_SCHEMA.into()]).unwrap();
    let corrupt = Request {
        op_id: busbar_kernel::door::op_id().0,
        predicates: vec![Predicate {
            schema: KEYSET_SCHEMA.into(),
            key: b"deployment".to_vec(),
            expected: Expected::Exact(busbar_contract::Secret::new(seed.as_bytes().to_vec())),
        }],
        mutations: vec![Mutation::Put {
            schema: KEYSET_SCHEMA.into(),
            key: b"deployment".to_vec(),
            value: busbar_contract::Secret::new("11".repeat(32).into_bytes()),
        }],
    };
    assert!(matches!(
        records.conditional_native(&corrupt).await.unwrap(),
        Outcome::Applied
    ));
    let refused = root::boot::compose_book(
        RuntimeJournal::open(core, 7, budget).await.unwrap(),
        &identity,
        7,
        1_700_000_002,
        &token,
    )
    .await
    .unwrap_err();
    assert!(
        refused.starts_with("KeysetMissing: the journal the configured store keeps"),
        "{refused}"
    );
    assert_eq!(std::fs::read(&legacy).unwrap(), seed.as_bytes());
}

#[cfg(distribution_root)]
#[tokio::test]
async fn one_seal_after_two_reloads() {
    const CHILD: &str = "BUSBAR_JOURNAL_RELOAD_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = concat!(module_path!(), "::one_seal_after_two_reloads");
        let test_name = name.split_once("::").unwrap().1;
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", test_name])
            .env(CHILD, "1")
            .output()
            .expect("run the journal reload case in a fresh process");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains(&format!("test {test_name} ... ok")),
            "{stdout}"
        );
        assert!(
            output.status.success(),
            "the journal reload case passes: {stdout}"
        );
        return;
    }
    crate::dist_root_install::install();
    use busbar_kernel_wal::RecordClass;

    let dir = BookDir::new("two-reloads");
    std::env::set_var("BUSBAR_DATA_DIR", &dir.0);
    let store_module = crate::LINKED
        .stores
        .iter()
        .find(|store| store.1)
        .expect("the distribution links its real ephemeral product store")
        .0;
    let deploy = busbar_kernel::config::deploy_from_deserializer(
        serde_json::json!({
            "providers": {},
            "models": {},
            "store": { "module": store_module },
            "auth": { "chain": [], "admin_auth": [] },
        }),
        &crate::root::boot::axis_test_grammar(),
    )
    .expect("the product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the product deployment resolves");
    let rules =
        Arc::new(root::door_steps::Rules::default()) as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (boot, rotate, limits) = crate::root::real_store::build_app(
        config,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
    )
    .await
    .expect("the production root builds the app and opens its real store through the ABI");
    limits.stage_boot();
    let book = root::boot::book(&boot, "test-store")
        .await
        .expect("the boot book opens");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let store = boot
        .governance
        .clone()
        .expect("a boot resolves the store its book opens over");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the unchanged product deployment resolves for the first reload");
    let (first, rotate, limits) = crate::root::real_store::build_app(
        config,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(&boot),
        &rules,
    )
    .await
    .expect("the first product reload builds over the prior generation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the unchanged product deployment resolves for the second reload");
    let (second, rotate, limits) = crate::root::real_store::build_app(
        config,
        Default::default(),
        None,
        Default::default(),
        Default::default(),
        (None, None),
        Some(&first),
        &rules,
    )
    .await
    .expect("the second product reload builds over the prior generation");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }

    assert!(
        Arc::ptr_eq(
            second.governance.as_ref().expect("a reload keeps a store"),
            &store
        ),
        "a reload reopened the store: Book is boot-only, and the generation must carry the store \
         the boot opened"
    );

    let (signing_fingerprint, journal) = {
        let durability = book
            .durability
            .lock()
            .expect("the book's lock is unpoisoned");
        let keyset = root::durability::keyset_of(&durability.record);
        let key_id = durability.record.signing_key_id().expect("the book signs");
        let key = keyset
            .get(key_id)
            .expect("the keyset holds the signing key");
        (
            root::keyset::fingerprint_of(key),
            durability.journal.clone(),
        )
    };
    let records = journal
        .read_records(root::durability::tests::BUDGET)
        .await
        .expect("the configured Store reads its verified journal");
    let mut openings = records.iter().filter(|r| r.class == RecordClass::Bootstrap);
    let opening = openings.next().expect("the boot sealed its keyset");
    assert!(
        openings.next().is_none(),
        "two reloads must leave exactly the boot's one sealed opening on the book's chain"
    );
    assert_eq!(
        root::keyset::bootstrap_fingerprint(&opening.body),
        Some(signing_fingerprint),
        "the surviving Bootstrap seals the bound signing key"
    );
}

#[test]
fn the_line_serve_flag_is_read_off_the_planes_declared_rows() {
    let planted: &[crate::root::linked::CliHelpRow] = &[(
        "flag",
        "    --planted-serve      serve the planted plane on stdin/stdout",
    )];
    assert!(line_serve_requested(
        &[planted],
        &Argv::parse(["busbar", "--planted-serve"])
    ));
    assert!(!line_serve_requested(
        &[],
        &Argv::parse(["busbar", "--planted-serve"])
    ));
    assert!(!line_serve_requested(&[planted], &Argv::parse(["busbar"])));
}

/// The crate root denies `dead_code`, `unused_imports` and `unused_macros` outside tests. An
/// item-level `allow` or `expect` naming one of them would silence that, so every such escape in
/// this crate's source, build script and generators is listed here by file, and each listed one is
/// test-only. A new site fails this test; adding one to the list needs owner review.
#[test]
fn no_dead_code_escape_outside_the_listed_test_only_sites() {
    // No site is listed: LR-135 forbids every dead_code/unused escape, generated code included.
    const LISTED: &[(&str, usize)] = &[];
    let lints = ["dead_code", "unused_imports", "unused_macros"];
    let escapes = ["allow(", "expect("];
    let krate = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/busbar");
    let mut files = vec![krate.join("build.rs")];
    let mut dirs = vec![krate.join("src")];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(&dir).expect("read the busbar source tree") {
            let path = entry.expect("read a source entry").path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                files.push(path);
            }
        }
    }
    let mut found = Vec::new();
    for path in files {
        let text = std::fs::read_to_string(&path).expect("read a source file");
        let count = text
            .lines()
            .filter(|l| {
                escapes.iter().any(|e| l.contains(e)) && lints.iter().any(|n| l.contains(n))
            })
            .count();
        let rel = path
            .strip_prefix(&krate)
            .expect("under the crate")
            .to_string_lossy()
            .replace('\\', "/");
        let listed = LISTED
            .iter()
            .find(|(f, _)| *f == rel)
            .map_or(0, |(_, n)| *n);
        if count != listed {
            found.push(format!("{rel}: {count} escape lines, {listed} listed"));
        }
    }
    assert!(found.is_empty(), "dead-code escapes changed: {found:?}");
}

/// BOOT-130: the `store.module` plugin-preflight refusal, built once in
/// `busbar-kernel` preflight, as `prepare_config_store` returns it.
const STORE_MODULE_SQLITE_REFUSAL: &str = "store.module: 'sqlite' requires the plugin subsystem, \
     but plugins.enabled is false (the default). Set plugins.enabled: true and place the signed \
     'sqlite' store plugin tarball in the plugins directory ('plugins'). The published binary links no store of its own: store.module selects a plugin of kind store by name.";

#[test]
fn store_boot_refusal_passes_the_store_module_refusal_through() {
    assert_eq!(
        store_boot_refusal(false, STORE_MODULE_SQLITE_REFUSAL.to_owned()),
        STORE_MODULE_SQLITE_REFUSAL,
        "a plugin-preflight refusal is not a Store overlay anchor failure: an ordinary boot \
         prints the store.module instruction byte for byte"
    );
}

#[test]
fn store_boot_refusal_transition_does_not_leak_the_store_module_refusal() {
    let refusal = store_boot_refusal(true, STORE_MODULE_SQLITE_REFUSAL.to_owned());
    assert_eq!(refusal, "principal transition base Store opening refused");
    assert!(
        !refusal.contains(STORE_MODULE_SQLITE_REFUSAL),
        "a principal transition summary carries no inner detail"
    );
}

#[test]
fn admitted_min3_store_refusal_goes_through_store_boot_refusal() {
    let source: String = include_str!("../main.rs")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let call_site = concat!(
        "die(store_boot_refusal(",
        "principal_transition.is_some(),error))"
    );
    assert_eq!(
        source.matches(call_site).count(),
        1,
        "the admitted MIN-3 store boot refusal must be printed through store_boot_refusal"
    );
    let false_prefix: String = concat!("base Store overlay ", "anchor")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    assert_eq!(
        source.matches(false_prefix.as_str()).count(),
        0,
        "no boot refusal may carry the 'base Store overlay anchor' prefix: the inner error \
         already names its own subject"
    );
}

#[test]
fn main_runs_the_crypto_self_test_before_anything_else() {
    let source: String = include_str!("../main.rs")
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let head = concat!(
        "fnmain(){",
        "ifletErr(e)=busbar_contract::crypto::self_test(){",
        "die(e);"
    );
    assert!(
        source.contains(head),
        "main must run crypto::self_test() first, before anything touches crypto, and refuse \
         to boot on Err (#172: the FIPS backend's power-on self-test gates boot)"
    );
}

#[test]
fn store_boot_refusal_passes_the_inner_error_through_on_an_ordinary_boot() {
    let inner = "plugins.fetch failed:\n  - sha256 mismatch: expected 11, got 22 (not written)";
    assert_eq!(
        store_boot_refusal(false, inner.to_owned()),
        inner,
        "an ordinary boot prints the inner error unchanged: it already names its own subject, \
         and a plugin download is not a Store overlay anchor"
    );
}

#[test]
fn store_boot_refusal_prints_the_context_alone_under_a_principal_transition() {
    assert_eq!(
        store_boot_refusal(true, "plugins.fetch failed:\n  - secret detail".to_owned()),
        "principal transition base Store opening refused",
        "a principal transition summary carries no inner detail"
    );
}

/// #428: on dev no plane states a CLI row, so the stdio trigger was unreachable. Core's own
/// `--stdio` selects line serving through `main`'s CLI path on every build, and nothing else does
/// (WP1-GAP r3 §1.3).
#[test]
fn stdio_selects_line_serving_through_mains_cli_path() {
    assert!(line_serve_requested(
        &root::cli::help_rows(),
        &Argv::parse(["--stdio"])
    ));
    assert!(!line_serve_requested(
        &root::cli::help_rows(),
        &Argv::parse(Vec::<String>::new())
    ));
    assert!(!line_serve_requested(
        &root::cli::help_rows(),
        &Argv::parse(["--mcp-stdio"])
    ));
}
