use super::*;
use crate::root::cli::{
    config_override_notice, providers_override_notice, resolve_config_path,
    signing_key_command_output, value_flag,
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
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name.split_once("::").unwrap().1])
            .env(CHILD, "1")
            .status()
            .expect("run the config environment case in a fresh process");
        assert!(status.success(), "the config environment case passes");
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

#[test]
fn value_flag_parses_all_accepted_forms() {
    let v = |a: &[&str], long: &str, short: Option<&str>| {
        value_flag(a.iter().map(|s| s.to_string()), long, short)
    };

    assert_eq!(
        v(&["--config", "/a/config.yaml"], "--config", Some("-c")),
        Some("/a/config.yaml".to_string())
    );

    assert_eq!(
        v(&["--config=/b/config.yaml"], "--config", Some("-c")),
        Some("/b/config.yaml".to_string())
    );

    assert_eq!(
        v(&["-c", "/c/config.yaml"], "--config", Some("-c")),
        Some("/c/config.yaml".to_string())
    );

    assert_eq!(
        v(
            &["-c", "/first", "--config", "/second"],
            "--config",
            Some("-c")
        ),
        Some("/second".to_string())
    );

    assert_eq!(v(&["--validate"], "--providers", None), None);
    assert_eq!(
        v(&["--providers", "/p/providers.yaml"], "--providers", None),
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
        flag_value(&["-Ctarget-feature=+sse2", "-C", "target-feature=+avx,-sse2"], "target-feature").as_deref(),
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

#[cfg(linked_axis_body_ingress)]
#[test]
fn the_boot_path_keeps_its_journal_in_the_store_with_a_configured_directory() {
    const CHILD: &str = "BUSBAR_JOURNAL_DIRECTORY_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = concat!(
            module_path!(),
            "::the_boot_path_keeps_its_journal_in_the_store_with_a_configured_directory"
        );
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name.split_once("::").unwrap().1])
            .env(CHILD, "1")
            .status()
            .expect("run the journal directory case in a fresh process");
        assert!(status.success(), "the journal directory case passes");
        return;
    }
    busbar_kernel_testkit::test_support::register_neutral_test_plane();
    use busbar_kernel_wal::RecordClass;

    for decls in crate::LINKED.protocols {
        busbar_kernel_testkit::test_support::protocols::register_test_protocols(decls);
    }
    busbar_kernel_testkit::test_support::metrics::init();
    let dir = BookDir::new("real-path");
    assert!(
        dir.entries().is_empty(),
        "the fixture directory starts empty, or nothing below is evidence of anything"
    );

    std::env::set_var("BUSBAR_DATA_DIR", &dir.0);

    let app = busbar_kernel_testkit::app::build_once(
        busbar_kernel_testkit::test_support::cfg_with_provider_api_key(
            busbar_kernel::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_BOOT_BOOK"),
        ),
        None,
    )
    .expect("the app builds over the default memory store");

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

#[cfg(linked_axis_body_ingress)]
#[test]
fn a_store_without_the_record_slots_refuses_the_boot_by_name() {
    busbar_kernel_testkit::test_support::register_neutral_test_plane();
    for decls in crate::LINKED.protocols {
        busbar_kernel_testkit::test_support::protocols::register_test_protocols(decls);
    }
    busbar_kernel_testkit::test_support::metrics::init();
    let app = busbar_kernel_testkit::app::build_once(
        busbar_kernel_testkit::test_support::cfg_with_provider_api_key(
            busbar_kernel::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_NO_SLOTS"),
        ),
        None,
    )
    .expect("the app builds");
    let mut slotless = app.clone();
    let store: std::sync::Arc<dyn busbar_contract::records::RecordStore> =
        std::sync::Arc::new(busbar_kernel_testkit::test_support::store_double::MemoryStore::new());
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

    assert_eq!(
        replayed.iter().map(|r| r.class).collect::<Vec<_>>(),
        vec![RecordClass::Bootstrap],
        "exactly the keyset's Bootstrap is on the chain"
    );

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

fn journal_lane(slots: &crate::root::store_double::RecordSlots) -> root::durability::JournalLane {
    root::durability::JournalLane::start(slots.calls(), "test-store").expect("the lane starts")
}

#[test]
fn no_configured_directory_still_opens_nothing_and_writes_nothing() {
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

#[test]
fn the_boot_book_binds_the_store_keyset_and_refuses_a_mismatched_store_key() {
    let token = root::kernel::new_kernel().durability_token();
    let dir = BookDir::new("keyset");
    let slots = crate::root::store_double::RecordSlots::new();
    let first = root::boot::compose_book(
        journal_lane(&slots),
        Some(dir.0.clone()),
        7,
        1_700_000_000,
        &token,
    )
    .unwrap();
    let key_id = first.record.signing_key_id().unwrap().to_string();
    assert!(root::durability::keyset_of(&first.record)
        .get(&key_id)
        .is_some());
    let seed = root::durability::stored_keyset(slots.calls().as_ref())
        .unwrap()
        .unwrap();
    assert!(first
        .lane()
        .unwrap()
        .drain(std::time::Duration::from_secs(5)));
    drop(first);
    let restarted = root::boot::compose_book(
        journal_lane(&slots),
        Some(dir.0.clone()),
        7,
        1_700_000_001,
        &token,
    )
    .unwrap();
    assert_eq!(restarted.record.signing_key_id(), Some(key_id.as_str()));
    assert!(restarted.keeps_chain());
    assert_eq!(
        restarted
            .chain()
            .unwrap()
            .unwrap()
            .iter()
            .filter(|r| r.class == busbar_kernel_wal::RecordClass::Bootstrap)
            .count(),
        1
    );
    assert!(dir.entries().is_empty());
    drop(restarted);
    let legacy = dir.0.join("deployment-keyset");
    std::fs::write(&legacy, seed.as_bytes()).unwrap();
    slots.put_row(
        "busbar.keyset.v1",
        b"deployment",
        "11".repeat(32).as_bytes(),
    );
    let refused = root::boot::compose_book(
        journal_lane(&slots),
        Some(dir.0.clone()),
        7,
        1_700_000_002,
        &token,
    )
    .unwrap_err();
    assert!(
        refused.starts_with("KeysetMissing: the journal the configured store keeps"),
        "{refused}"
    );
    assert_eq!(std::fs::read(&legacy).unwrap(), seed.as_bytes());
}

#[cfg(linked_axis_body_ingress)]
#[test]
fn one_seal_after_two_reloads() {
    const CHILD: &str = "BUSBAR_JOURNAL_RELOAD_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let name = concat!(module_path!(), "::one_seal_after_two_reloads");
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name.split_once("::").unwrap().1])
            .env(CHILD, "1")
            .status()
            .expect("run the journal reload case in a fresh process");
        assert!(status.success(), "the journal reload case passes");
        return;
    }
    busbar_kernel_testkit::test_support::register_neutral_test_plane();
    use busbar_kernel_wal::RecordClass;

    for decls in crate::LINKED.protocols {
        busbar_kernel_testkit::test_support::protocols::register_test_protocols(decls);
    }
    busbar_kernel_testkit::test_support::metrics::init();
    let dir = BookDir::new("two-reloads");
    std::env::set_var("BUSBAR_DATA_DIR", &dir.0);
    let cfg = || {
        busbar_kernel_testkit::test_support::cfg_with_provider_api_key(
            busbar_kernel::config::SecretRef::env("BUSBAR_TEST_NO_SUCH_KEY_ONE_SEAL"),
        )
    };

    let boot = busbar_kernel_testkit::app::build_once(cfg(), None).expect("the boot builds");
    let book = root::boot::book(&boot, "test-store").expect("the boot book opens");
    let store = boot
        .governance
        .clone()
        .expect("a boot resolves the store its book opens over");
    let first = busbar_kernel_testkit::app::build_once(cfg(), Some(&boot)).expect("reload 1");
    let second = busbar_kernel_testkit::app::build_once(cfg(), Some(&first)).expect("reload 2");

    assert!(
        Arc::ptr_eq(
            second.governance.as_ref().expect("a reload keeps a store"),
            &store
        ),
        "a reload reopened the store: Book is boot-only, and the generation must carry the store \
         the boot opened"
    );

    let durability = book
        .durability
        .lock()
        .expect("the book's lock is unpoisoned");
    let keyset = root::durability::keyset_of(&durability.record);
    let key_id = durability.record.signing_key_id().expect("the book signs");
    let signing_key = keyset
        .get(key_id)
        .expect("the keyset holds the signing key");
    let records = durability
        .journal
        .replay()
        .expect("the journal reads back")
        .expect("and verifies");
    let mut openings = records.iter().filter(|r| r.class == RecordClass::Bootstrap);
    let opening = openings.next().expect("the boot sealed its keyset");
    assert!(
        openings.next().is_none(),
        "two reloads must leave exactly the boot's one sealed opening on the book's chain"
    );
    assert_eq!(
        root::keyset::bootstrap_fingerprint(&opening.body),
        Some(root::keyset::fingerprint_of(signing_key)),
        "the surviving Bootstrap seals the bound signing key"
    );
}

#[cfg(not(target_env = "msvc"))]
#[test]
fn the_idle_purge_puts_each_arena_back_to_its_own_decay() {
    use tikv_jemalloc_ctl::{Access, AsName};

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
