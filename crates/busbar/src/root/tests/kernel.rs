use super::*;

#[test]
fn an_apply_moves_the_head_and_leaves_a_pinned_reader_on_the_snapshot_it_took() {
    let holder = RootHistory::default();
    assert!(
        holder.pin().is_none(),
        "a holder that has heard no apply prices nothing"
    );

    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    let admitted = holder.pin().expect("the first apply put an entry in place");
    assert_eq!(
        fee_at(&admitted, 1_000),
        30_000_000,
        "the first apply's fee did not reach the entry a reader resolves to"
    );

    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);
    assert_eq!(
        fee_at(&admitted, 5_000),
        30_000_000,
        "a reader that pinned before the apply was repriced by it, at every instant of its life"
    );
    let next = holder
        .pin()
        .expect("the second apply put an entry in place");
    assert_eq!(
        fee_at(&next, 5_000),
        110_000_000,
        "the apply did not reach the next admission's snapshot"
    );
}

fn fee_at(pinned: &PinnedHistory, at: u64) -> u128 {
    pinned
        .view()
        .card_at(at)
        .expect("an entry covers the instant")
        .1
        .fee_unit_price_nanos()
}

#[test]
fn a_reload_appends_and_never_rewrites_the_entry_before_it() {
    let holder = RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(29), 3_000);

    assert_eq!(
        holder.len(),
        3,
        "three applies left fewer than three entries, so one of them overwrote another"
    );

    let head = holder.pin().expect("three applies put a head in place");
    let view = head.view();
    let entries = view.entries();
    assert_eq!(
        entries[0].card().fee_unit_price_nanos(),
        30_000_000,
        "the entry the first apply wrote was rewritten by a later one"
    );
    assert_eq!(
        entries[0].seq(),
        busbar_kernel_ledger::cost::HistorySeq(0),
        "the first entry was renumbered, which unmakes every invoice that named a snapshot"
    );
    assert_eq!(entries[1].card().fee_unit_price_nanos(), 110_000_000);
    assert_eq!(entries[2].card().fee_unit_price_nanos(), 290_000_000);
}

#[test]
fn an_instant_before_a_reload_resolves_to_the_entry_that_was_in_force_then() {
    let holder = RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);

    let head = holder.pin().expect("two applies put a head in place");
    assert_eq!(
        fee_at(&head, 1_500),
        30_000_000,
        "a unit that arrived before the reload was re-priced at the card that replaced it"
    );
    assert_eq!(
        fee_at(&head, 2_500),
        110_000_000,
        "a unit that arrived after the reload was priced at the card it superseded"
    );
}

#[test]
fn the_first_entry_covers_every_instant_before_the_boot_that_wrote_it() {
    let holder = RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 9_000_000);
    let head = holder.pin().expect("the apply put an entry in place");
    assert_eq!(
        fee_at(&head, 0),
        30_000_000,
        "instant zero fell in a hole, so a pre-boot row prices at nothing"
    );
    assert_eq!(fee_at(&head, 8_999_999), 30_000_000);
}

#[test]
fn every_config_apply_records_the_generation_that_wrote_it() {
    let holder = RootHistory::default();
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);
    let head = holder.pin().expect("two applies put a head in place");
    let view = head.view();
    let epochs: Vec<busbar_kernel_ledger::cost::Author> =
        view.entries().iter().map(|e| e.author().clone()).collect();
    assert_eq!(
        epochs,
        vec![
            busbar_kernel_ledger::cost::Author::Config { policy_epoch: 0 },
            busbar_kernel_ledger::cost::Author::Config { policy_epoch: 1 },
        ]
    );
}

#[test]
fn the_card_an_apply_builds_carries_its_configured_fee_at_the_one_scale() {
    let holder = RootHistory::default();
    holder.apply(
        super::card_from_config(
            std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
            7,
            true,
        ),
        1_000,
    );
    let head = holder.pin().expect("the apply put an entry in place");
    let view = head.view();
    let (_, card) = view.card_at(1_000).expect("an entry covers it");
    assert_eq!(card.fee(), 7, "the configured fee reached the card unmoved");
    assert_eq!(
        card.fee_unit_price_nanos(),
        7 * busbar_kernel_ledger::cost::NANOS_PER_CENT,
        "the fee lifts to nano-units at the one scale and no other"
    );
}

#[test]
fn a_card_edit_mid_window_prices_an_open_class_in_both_eras_and_refuses_neither() {
    let zero = busbar_contract::billing::RawTierRates {
        input: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
        output: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
        cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
        cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
    };
    let lanes = [("rerank".to_string(), zero)];
    let era = |nanos: u64| [("rerank".to_string(), "search_units".to_string(), nanos)];
    let (before, after) = (era(5_000), era(3_000));
    let no_fees = busbar_kernel::config::PlaneFeesMap::new();
    let raw = |units| busbar_kernel::rate_apply::RawRates {
        lanes: &lanes,
        units,
        flat_minor: 0,
        present: true,
        plane_fees: &no_fees,
    };

    let holder = RootHistory::default();
    holder.apply(super::card_from_raw(&raw(&before)), 1_000);
    holder.apply(super::card_from_raw(&raw(&after)), 2_000);
    let history = holder.history().expect("two applies are a history");
    let live = super::card_from_raw(&raw(&after));

    let earned_before = std::collections::BTreeMap::from([("search_units".to_string(), 1_000_000)]);
    let earned_after = std::collections::BTreeMap::from([("search_units".to_string(), 2_000_000)]);
    let priced = busbar_kernel_ledger::usage::price_dated(
        [
            ("rerank", 0, &earned_before),
            ("rerank", 2_000, &earned_after),
        ],
        [],
        0,
        &live,
        Some(busbar_kernel_ledger::usage::DatedHistory::of(
            &history, 3_000,
        )),
    )
    .expect("an open class the older era's card priced must price, not refuse");
    assert_eq!(
        priced.micros(),
        11_000_000,
        "each era at the open-class rate in force when it was earned"
    );
}

#[test]
fn a_fee_edit_mid_window_prices_each_era_at_the_plane_fee_in_force() {
    use busbar_kernel_ledger::cost::{plane_fee_lane, PlaneFees, PER_REQUEST};
    let fees = |per_request| {
        let f = PlaneFees {
            per_request,
            per_session: 0,
        };
        busbar_kernel::config::PlaneFeesMap::from([("tp".to_string(), f)])
    };
    let (before, after) = (fees(3), fees(7));
    let raw = |plane_fees| busbar_kernel::rate_apply::RawRates {
        lanes: &[],
        units: &[],
        flat_minor: 5,
        present: false,
        plane_fees,
    };
    let holder = RootHistory::default();
    holder.apply(super::card_from_raw(&raw(&before)), 1_000);
    holder.apply(super::card_from_raw(&raw(&after)), 2_000);
    let history = holder.history().expect("two applies are a history");
    let live = super::card_from_raw(&raw(&after));
    let lane = plane_fee_lane("tp");
    let two = std::collections::BTreeMap::from([(PER_REQUEST.to_string(), 2)]);
    let one = std::collections::BTreeMap::from([(PER_REQUEST.to_string(), 1)]);
    let priced = busbar_kernel_ledger::usage::price_dated(
        [(lane.as_str(), 0, &two), (lane.as_str(), 2_000, &one)],
        [],
        0,
        &live,
        Some(busbar_kernel_ledger::usage::DatedHistory::of(
            &history, 3_000,
        )),
    )
    .expect("a plane's fee units price");
    assert_eq!(priced.minor(), 13, "each era at the plane fee in force");
}

#[test]
fn the_arrival_door_opens_the_callers_hold() {
    let kernel = new_kernel();
    let door = AdmissionDoor;
    let hold = busbar_kernel::inflight::arrival_hold(
        &kernel,
        &door,
        PrincipalId::new("k-7"),
        kernel.next_call(),
    );
    assert_eq!(hold.principal(), &PrincipalId::new("k-7"));
}

#[test]
fn the_units_assemble_from_values_configuration_decided() {
    let durability = crate::root::durability::build(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("a memory-buffered journal cannot fail to open");

    let kernel = new_kernel();
    let units = ProductionUnits::new(
        &kernel,
        durability,
        #[cfg(feature = "root-admin")]
        crate::root::units_admin::AdminBinding::new(
            std::sync::Arc::new(crate::root::units_admin::RefusingDispatch),
            crate::root::units_admin::open_door(),
        ),
        None,
    );

    let durability = units.durability.lock().expect("durability lock");
    assert!(!durability.on_disk());
}

/// A store that writes down every primitive it is asked for, so a test can say WHICH store a call
/// landed on rather than inferring it from an `Ok`.
#[cfg(feature = "root-admin")]
#[derive(Default)]
struct ReachedStore(Mutex<Vec<String>>);

#[cfg(feature = "root-admin")]
impl ReachedStore {
    fn note(&self, line: String) {
        self.0.lock().expect("the log lock").push(line);
    }

    fn reached(&self) -> Vec<String> {
        self.0.lock().expect("the log lock").clone()
    }
}

#[cfg(feature = "root-admin")]
impl busbar_kernel_seams::verb_store::Store for ReachedStore {
    fn chain_break(
        &self,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
    ) -> Result<(), busbar_kernel_seams::verb_store::StoreError> {
        self.note("chain_break".to_string());
        Ok(())
    }

    fn store_restore(
        &self,
        _admin: &busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        backup_ref: &str,
    ) -> Result<(), busbar_kernel_seams::verb_store::StoreError> {
        self.note(format!("store_restore {backup_ref}"));
        Ok(())
    }
}

#[cfg(feature = "root-admin")]
#[test]
fn the_admin_units_over_a_book_reach_that_books_store_for_every_recovery_verb() {
    let configured = Arc::new(ReachedStore::default());
    let mut book = crate::root::durability::node_book();
    book.verb_store = Some(Arc::clone(&configured) as _);
    let units = ProductionUnits::admin_over_book(
        Arc::new(crate::root::units_admin::RefusingDispatch),
        crate::root::units_admin::open_door(),
        &book,
    );
    let store = units
        .store
        .as_ref()
        .expect("units over a book with a configured store hold a store");

    store
        .chain_break(&units.admin_token)
        .expect("chain_break applies");
    store
        .store_restore(&units.admin_token, "nightly")
        .expect("store_restore applies");

    assert_eq!(
        configured.reached(),
        vec![
            "chain_break".to_string(),
            "store_restore nightly".to_string(),
        ],
        "every recovery primitive landed on the book's configured store"
    );
}

#[test]
fn the_interner_leaks_a_repeated_key_once() {
    let mut registration = new_registration();
    let first = registration
        .key("lane-a")
        .expect("an unfrozen image interns a key");
    let second = registration
        .key("lane-a")
        .expect("a repeated key is the same key");
    assert!(std::ptr::eq(first, second));
    assert_eq!(registration.len(), 1);
}

#[test]
fn the_holder_hands_a_reader_the_whole_history_and_an_unresolved_node_none() {
    let holder = RootHistory::default();
    assert!(
        holder.history().is_none(),
        "a node that has resolved no configuration has no history to hand over"
    );

    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    holder.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);
    let history = holder.history().expect("two applies are a history");
    assert_eq!(
        history.len(),
        2,
        "the reader sees every entry, not just the head"
    );
    assert_eq!(
        history.head(),
        Some(busbar_kernel_ledger::cost::HistorySeq(1)),
        "and the numbers are the holder's own, so a snapshot names the same entry twice"
    );
}

#[test]
fn the_usage_read_answers_with_the_process_history() {
    use busbar_kernel::rate_apply::RateEpoch as _;
    const CHILD: &str = "BUSBAR_CARD_REPRICER_TEST_CHILD";
    const WITNESS: &str = "populated CardRepricer history witness completed";
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let module = module_path!()
            .split_once("::")
            .expect("a crate-qualified module")
            .1;
        let mut child = Child(
            std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg(format!(
                    "{module}::the_usage_read_answers_with_the_process_history"
                ))
                .arg("--nocapture")
                .env(CHILD, "1")
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("the isolated test process starts"),
        );
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = child.0.try_wait().expect("the test process status reads") {
                use std::io::Read as _;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the populated process-history witness failed: {status}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact child test did not complete its witness: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the isolated history test did not exit"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    assert!(
        ROOT_CARD.history().is_none(),
        "the child starts with no resolved history"
    );
    ROOT_CARD.apply(busbar_kernel_ledger::cost::RateCard::absent(3), 1_000);
    ROOT_CARD.apply(busbar_kernel_ledger::cost::RateCard::absent(11), 2_000);
    let held = CardRepricer
        .history()
        .expect("two actual applies are visible to the usage read");
    let process = ROOT_CARD
        .history()
        .expect("the process holds those applies");
    assert!(
        Arc::ptr_eq(&held, &process),
        "the read shares the actual process history"
    );
    assert_eq!(held.len(), 2);
    assert_eq!(
        held.head(),
        Some(busbar_kernel_ledger::cost::HistorySeq(1)),
        "the read names the second real entry"
    );
    ROOT_CARD.apply(busbar_kernel_ledger::cost::RateCard::absent(29), 3_000);
    let next = CardRepricer
        .history()
        .expect("the subsequent apply is visible");
    assert_eq!(next.len(), 3);
    assert!(Arc::ptr_eq(&next, &ROOT_CARD.history().unwrap()));
    assert_eq!(held.len(), 2, "the earlier reader keeps its own snapshot");
    println!("{WITNESS}");
}

#[test]
fn actual_card_store_and_root_rate_apply_gate_the_real_app_generation_commit() {
    use busbar_kernel::rate_apply::{RateApply, RateEpoch};
    const CHILD: &str = "BUSBAR_CONFIRMED_CARD_GENERATION_CHILD";
    const WITNESS: &str = "actual confirmed card generation witness completed";
    const BOOT_FEE: i64 = 3;
    const FIRST_FEE: i64 = 7;
    const SECOND_FEE: i64 = 11;
    if std::env::var_os(CHILD).is_none() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let module = module_path!().split_once("::").unwrap().1;
        let mut child = Child(std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!("{module}::actual_card_store_and_root_rate_apply_gate_the_real_app_generation_commit"))
            .arg("--nocapture").env(CHILD, "1")
            .stdout(std::process::Stdio::piped()).spawn().unwrap());
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                use std::io::Read as _;
                let mut output = String::new();
                child
                    .0
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut output)
                    .unwrap();
                assert!(
                    status.success(),
                    "the actual generation witness failed: {status}: {output}"
                );
                assert!(
                    output.contains(WITNESS),
                    "the exact witness did not finish: {output}"
                );
                return;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the actual generation witness timed out"
            );
            std::thread::park_timeout(std::time::Duration::from_millis(5));
        }
    }
    let release = crate::root::test_plugins::key(0x5a);
    std::env::set_var(
        "BUSBAR_TEST_HARNESS_FIRST_PARTY_KEY",
        hex::encode(release.verifying_key().as_bytes()),
    );
    let library_path = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN")
            .expect("BUSBAR_GOVERNANCE_TEST_STORE_PLUGIN names the actual built store"),
    );
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::loader::sign::FIRST_PARTY_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = crate::root::test_plugins::scratch("confirmed-card-generation");
    std::fs::write(
        directory.join("store.tar.gz"),
        crate::root::test_plugins::signed(&release, manifest, &library),
    )
    .expect("stage the actual store archive");
    let settings: serde_json::Value = serde_json::from_str(
        &std::env::var("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS").unwrap_or_else(|_| "{}".into()),
    )
    .expect("BUSBAR_GOVERNANCE_TEST_STORE_SETTINGS is JSON");
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the actual product deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the actual product deployment resolves");
    let judge = crate::root::connector::dest_judge(&config);
    let late = crate::root::serve::LateServices::new();
    let dispatcher = crate::root::dispatch::boot(1, &late);
    crate::root::doors::install_dispatcher(dispatcher);
    let (credentials, _handle) = crate::root::credentials::AppCredentials::late();
    crate::root::serve::compose(judge.clone(), &late, credentials);
    crate::register_protocols();
    crate::register_planes();
    crate::register_diagnostics();
    crate::root::doors::install_plugin_logs(crate::root::boot::plugin_logs());
    crate::root::connector::boot(
        crate::LINKED_TRANSPORT_DOORS,
        &crate::root::policy::client_settings(&config.limits),
        judge,
        &[],
    );
    let plugins = busbar_kernel::config::PluginsCfg {
        enabled: true,
        dir: directory.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let slots = crate::root::store_double::RecordSlots::new();
    let boot = busbar_kernel::config::card::CardFields {
        per_request_fee: BOOT_FEE,
        ..Default::default()
    };
    ROOT_CARD.keep_in_store(slots.calls(), 1);
    ROOT_CARD.card_applied(&boot, "actual boot");
    ROOT_CARD.boot_in_store(None).unwrap();
    let build = |fee, prior: Option<&busbar_kernel::state::App>| {
        let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
            .expect("the actual product deployment resolves for this generation");
        cfg.per_request_fee = fee;
        if let Some(prior) = prior {
            cfg.limits.request_body_max_bytes = prior
                .limits
                .as_ref()
                .unwrap()
                .request_body_max_bytes
                .saturating_add(1);
        }
        let (app, _, limits) = busbar_kernel::build_app_from_config(
            cfg,
            plugins.clone(),
            None,
            Default::default(),
            Default::default(),
            (None, None),
            prior,
            &(Arc::new(crate::root::door_steps::Rules::default())
                as Arc<dyn busbar_kernel::appbuild::RootRules>),
        )
        .unwrap();
        (Arc::new(app), limits)
    };
    let (boot_app, limits) = build(BOOT_FEE, None);
    limits.keep().unwrap();
    let handle = busbar_kernel::state::AppHandle::new(boot_app);
    let pinned = ROOT_CARD.pin().unwrap();
    for (fee, fail_activation) in [(FIRST_FEE, false), (SECOND_FEE, true)] {
        let before = handle.load();
        let before_limits = busbar_kernel::config::limits::installed();
        let before_era = CardRepricer.era_at(busbar_kernel::store::now_ms());
        let before_own = ROOT_CARD.card_store().unwrap().own();
        let card = busbar_kernel::config::card::CardFields {
            per_request_fee: fee,
            ..Default::default()
        };
        if fail_activation {
            drop(
                CardRepricer
                    .prepare(&card, &card.rates().raw(), "saved actual candidate")
                    .unwrap(),
            );
        }
        slots.refuse(true);
        let (next, limits) = build(fee, Some(&before));
        assert!(handle
            .commit_rates_and_swap(next, || Ok(()), limits, "actual generation refusal")
            .is_err());
        let store = ROOT_CARD.card_store().unwrap();
        let candidate = store.pending().unwrap();
        assert!(Arc::ptr_eq(&handle.load(), &before));
        assert_eq!(handle.load().config_version, before.config_version);
        assert_eq!(store.own(), before_own);
        assert_eq!(
            CardRepricer.era_at(busbar_kernel::store::now_ms()),
            before_era
        );
        assert_eq!(
            busbar_kernel::config::limits::installed().map(|limits| limits.request_body_max_bytes),
            before_limits.map(|limits| limits.request_body_max_bytes)
        );
        slots.refuse(false);
        let (next, limits) = build(fee, Some(&before));
        handle
            .reload_rates_and_swap(
                next.clone(),
                || Ok(()),
                limits,
                "explicit actual generation recovery",
            )
            .unwrap();
        assert!(Arc::ptr_eq(&handle.load(), &next));
        assert_eq!(handle.load().config_version, before.config_version + 1);
        assert_eq!(store.own(), Some((candidate, card)));
        assert_eq!(
            CardRepricer.era_at(busbar_kernel::store::now_ms()).entry_id,
            Some(candidate.id())
        );
        assert!(store.pending().is_none());
    }
    assert_eq!(ROOT_CARD.card_store().unwrap().entries().len(), 3);
    assert_eq!(
        pinned
            .view()
            .card_at(busbar_kernel::store::now_ms())
            .unwrap()
            .1
            .fee(),
        BOOT_FEE
    );
    println!("{WITNESS}");
}

fn root_unit_modules(manifest: &str) -> Vec<String> {
    let mut in_table = false;
    let mut modules = Vec::new();
    for line in manifest.lines() {
        let code = line.split('#').next().unwrap_or("").trim();
        if code.starts_with('[') {
            in_table = code == "[package.metadata.busbar.root-units]";
            continue;
        }
        if let (true, Some((_, module))) = (in_table, code.split_once('=')) {
            modules.push(module.trim().trim_matches('"').to_string());
        }
    }
    assert!(!modules.is_empty(), "the manifest lists no root unit");
    modules
}

const FLAT_LANE: &str = "gpt";

const PLANE: &str = "planex";

const PLANE_LANE: &str = "planex\u{1f}search";

const BOOT_A: u64 = 1_000;
const EARNED_A: u64 = 10_000;
const APPLIED_B: u64 = 20_000;
const EARNED_B: u64 = 30_000;
const REBOOT: u64 = 40_000;
const REBOOT_CHANGED: u64 = 50_000;

fn tiers(input: f64) -> busbar_contract::billing::RawTierRates {
    busbar_contract::billing::RawTierRates {
        input: busbar_kernel_ledger::cost::representable_nano_rate(input),
        output: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
        cache_read: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
        cache_write: busbar_kernel_ledger::cost::representable_nano_rate(0.0),
    }
}

fn lanes_at(price: f64) -> Vec<(String, busbar_contract::billing::RawTierRates)> {
    vec![
        (FLAT_LANE.to_string(), tiers(price)),
        (format!("{PLANE}\u{1f}"), tiers(0.0)),
        (PLANE_LANE.to_string(), tiers(2.0 * price)),
    ]
}

fn plane_fees() -> busbar_kernel::config::PlaneFeesMap {
    busbar_kernel::config::PlaneFeesMap::from([(
        PLANE.to_string(),
        busbar_kernel_ledger::cost::PlaneFees {
            per_request: 7,
            per_session: 11,
        },
    )])
}

fn apply_at(holder: &RootHistory, price: f64, at: u64) {
    let _ = try_apply_at(holder, price, at);
    let book = match &*holder.journal.lock().unwrap() {
        CardJournal::Bound { book, .. } => Some(book.clone()),
        _ => None,
    };
    if let Some(book) = book {
        drain_book(&book);
    }
}

fn try_apply_at(
    holder: &RootHistory,
    price: f64,
    at: u64,
) -> Result<busbar_kernel_ledger::cost::HistorySeq, CardRefused> {
    let lanes = lanes_at(price);
    let fees = plane_fees();
    holder.apply_rates(
        &busbar_kernel::rate_apply::RawRates {
            lanes: &lanes,
            units: &[("gpt".to_string(), "search_units".to_string(), 2_000)],
            flat_minor: 4,
            present: true,
            plane_fees: &fees,
        },
        at,
    )
}

#[cfg(feature = "root-admin")]
fn publish_unjournalled_at(holder: &RootHistory, price: f64, at: u64) {
    let lanes = lanes_at(price);
    let fees = plane_fees();
    holder.apply(
        super::card_from_raw(&busbar_kernel::rate_apply::RawRates {
            lanes: &lanes,
            units: &[("gpt".to_string(), "search_units".to_string(), 2_000)],
            flat_minor: 4,
            present: true,
            plane_fees: &fees,
        }),
        at,
    );
}

fn process_holder() -> &'static RootHistory {
    let holder: &'static RootHistory = Box::leak(Box::default());
    holder.arm_journal();
    holder
}

fn boot_book(
    holder: &'static RootHistory,
    store: &crate::root::store_double::RecordSlots,
) -> Arc<Mutex<crate::root::durability::Durability>> {
    let book = open_book(holder, store);
    holder.bind_journal(&book);
    book
}

fn open_book(
    holder: &'static RootHistory,
    store: &crate::root::store_double::RecordSlots,
) -> Arc<Mutex<crate::root::durability::Durability>> {
    let lane = crate::root::durability::JournalLane::start(store.calls(), "card-history-test")
        .expect("the Store lane starts");
    let book = crate::root::durability::build_on_store(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        7,
        lane,
        Some(holder),
    )
    .expect("the journal opens over the Store");
    let book = Arc::new(Mutex::new(book));
    drain_book(&book);
    book
}

fn drain_book(book: &Arc<Mutex<crate::root::durability::Durability>>) {
    let lane = book.lock().unwrap().lane().cloned();
    if let Some(lane) = lane {
        assert!(
            lane.drain(std::time::Duration::from_secs(10)),
            "Store acknowledges the chain"
        );
    }
}

fn earned(holder: &RootHistory, lane: &str, at: u64) -> u64 {
    let price = holder
        .history()
        .expect("a history")
        .current()
        .card_at(at)
        .and_then(|(_, card)| card.lane_rates(lane).map(|r| r.nanos_per_unit("input")))
        .expect("a card prices the lane");
    1_000_000 * price
}

fn figures(holder: &RootHistory) -> (u64, u64) {
    (
        earned(holder, FLAT_LANE, EARNED_A) + earned(holder, FLAT_LANE, EARNED_B),
        earned(holder, PLANE_LANE, EARNED_A) + earned(holder, PLANE_LANE, EARNED_B),
    )
}

fn cards_on_chain(book: &Arc<Mutex<crate::root::durability::Durability>>) -> usize {
    drain_book(book);
    book.lock()
        .expect("the book")
        .journal
        .replay()
        .expect("reads")
        .expect("verifies")
        .iter()
        .filter(|r| r.class == busbar_kernel_wal::RecordClass::Policy)
        .filter(|r| super::CardApplied::from_body(&r.body).is_some())
        .count()
}

fn usage_row_micros(holder: &RootHistory, priced_from_ms: u64, input: u64) -> i64 {
    let history = holder.history().expect("a resolved history");
    let live = history
        .current()
        .card_at(u64::MAX)
        .map(|(_, card)| card.clone())
        .expect("a head card");
    let cost = busbar_kernel::cost::CostModel::resolve_parts(
        Some(&std::collections::BTreeMap::from([(
            FLAT_LANE.to_string(),
            busbar_kernel::config::RateEntryCfg {
                input_utok: 1.0,
                ..Default::default()
            },
        )])),
        0,
        &std::collections::BTreeMap::new(),
    );
    use busbar_core_admin::v1::service::read_path_money as invoice;
    invoice::derive_spend_micros_row_at_card(
        &history.current(),
        priced_from_ms,
        &live,
        &cost,
        FLAT_LANE,
        &invoice::UsageBreakdown {
            tokens_input: input,
            tokens_output: 0,
            tokens_cache_read: 0,
            tokens_cache_creation: 0,
            requests: 0,
            spend_micros: 0,
            classes: Default::default(),
        },
    )
    .expect("the row prices")
}

#[test]
fn a_restart_prices_every_posting_at_the_card_in_force_when_it_arrived() {
    let store = crate::root::store_double::RecordSlots::new();

    let figures_before = {
        let holder = process_holder();
        apply_at(holder, 3.0, BOOT_A);
        let book = boot_book(holder, &store);
        apply_at(holder, 5.0, APPLIED_B);
        assert_eq!(cards_on_chain(&book), 2, "the boot card and the live apply");
        figures(holder)
    };
    assert_eq!(figures_before, (8_000_000_000, 16_000_000_000));

    let holder = process_holder();
    apply_at(holder, 5.0, REBOOT);
    let book = boot_book(holder, &store);
    assert_eq!(
        figures(holder),
        figures_before,
        "a restart repriced counts at a card that was not in force when they arrived"
    );
    assert!(book.lock().expect("the book").restart_findings.is_empty());
    assert_eq!(
        holder.len(),
        2,
        "a restart that changed no price appends no entry"
    );
    assert_eq!(cards_on_chain(&book), 2, "and journals none");
    assert_eq!(
        (
            usage_row_micros(holder, 0, 1_000_000),
            usage_row_micros(holder, APPLIED_B, 1_000_000),
        ),
        (3_000_000, 5_000_000),
        "the usage read prices each era at its own card after a restart"
    );
    drop(book);

    let holder = process_holder();
    apply_at(holder, 7.0, REBOOT_CHANGED);
    let book = boot_book(holder, &store);
    assert_eq!(figures(holder), figures_before);
    assert_eq!(holder.len(), 3);
    assert_eq!(cards_on_chain(&book), 3);
    let history = holder.history().expect("a history");
    let price_at = |lane: &str, at: u64| {
        history
            .current()
            .card_at(at)
            .and_then(|(_, card)| card.lane_rates(lane).map(|r| r.nanos_per_unit("input")))
    };
    assert_eq!(
        [EARNED_A, EARNED_B, REBOOT_CHANGED].map(|at| price_at(FLAT_LANE, at)),
        [Some(3_000), Some(5_000), Some(7_000)]
    );
    assert_eq!(
        [EARNED_A, EARNED_B, REBOOT_CHANGED].map(|at| price_at(PLANE_LANE, at)),
        [Some(6_000), Some(10_000), Some(14_000)],
        "the plane's own card is dated with the rest"
    );
    drop(book);
}

#[test]
fn a_restart_after_store_chunks_prices_every_posting_at_the_card_in_force_when_it_arrived() {
    let store = crate::root::store_double::RecordSlots::new();
    let holder = process_holder();
    apply_at(holder, 3.0, BOOT_A);
    let book = boot_book(holder, &store);
    book.lock()
        .unwrap()
        .journal
        .append(
            &new_kernel().durability_token(),
            busbar_contract::caps::StepName::Meter,
            &[busbar_kernel_wal::Entry::new(
                busbar_kernel_wal::RecordClass::Load,
                vec![7; 4096],
            )],
        )
        .expect("a payload crosses multiple Store records");
    apply_at(holder, 5.0, APPLIED_B);
    drain_book(&book);
    let figures_before = figures(holder);
    let restarted = process_holder();
    apply_at(restarted, 5.0, REBOOT);
    let restarted_book = boot_book(restarted, &store);
    assert_eq!(figures(restarted), figures_before);
    assert_eq!(
        cards_on_chain(&restarted_book),
        2,
        "both eras survive Store chunking"
    );
    assert!(restarted_book.lock().unwrap().restart_findings.is_empty());
}

struct RefusingShipper;

impl busbar_kernel_wal::Shipper<busbar_kernel_wal::Record> for RefusingShipper {
    fn ship(
        &mut self,
        _records: &[busbar_kernel_wal::Record],
    ) -> Result<(), busbar_kernel_wal::ShipError> {
        Err(busbar_kernel_wal::ShipError::Unavailable(
            "the store is not answering".into(),
        ))
    }
}

fn flat_price_at(holder: &RootHistory, at: u64) -> Option<u64> {
    holder
        .history()
        .expect("a history")
        .current()
        .card_at(at)
        .and_then(|(_, card)| {
            card.lane_rates(FLAT_LANE)
                .map(|r| r.nanos_per_unit("input"))
        })
}

#[test]
fn a_rate_apply_the_journal_refuses_leaves_the_card_in_force_unchanged() {
    let store = crate::root::store_double::RecordSlots::new();
    let holder = process_holder();
    apply_at(holder, 3.0, BOOT_A);
    let book = boot_book(holder, &store);
    assert_eq!(cards_on_chain(&book), 1, "the boot card is journalled");
    book.lock().expect("the book").journal = busbar_kernel_wal::Journal::memory_buffered_to(
        7,
        Box::new(RefusingShipper),
        busbar_kernel::store::now_ms,
    );
    apply_at(holder, 5.0, APPLIED_B);
    assert_eq!(
        holder.len(),
        1,
        "the refused card is not published, and nothing is WITHDRAWN behind it (MONEY-DESIGN section 3a)"
    );
    assert_eq!(
        flat_price_at(holder, EARNED_B),
        Some(3_000),
        "the card in force is the one the journal holds"
    );
    drop(book);
}

struct SwitchShipper(Arc<std::sync::atomic::AtomicBool>);

impl busbar_kernel_wal::Shipper<busbar_kernel_wal::Record> for SwitchShipper {
    fn ship(
        &mut self,
        _records: &[busbar_kernel_wal::Record],
    ) -> Result<(), busbar_kernel_wal::ShipError> {
        if self.0.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(busbar_kernel_wal::ShipError::Unavailable(
                "the store is not answering".into(),
            ));
        }
        Ok(())
    }
}

fn chain_records(
    book: &Arc<Mutex<crate::root::durability::Durability>>,
) -> Vec<busbar_kernel_wal::JournalRecord> {
    drain_book(book);
    book.lock()
        .expect("the book")
        .journal
        .replay()
        .expect("reads")
        .expect("verifies")
}

fn rebuilt_from(
    records: &[busbar_kernel_wal::JournalRecord],
) -> busbar_kernel_ledger::cost::History {
    RootHistory::restore(super::journalled_cards(records), Vec::new()).history
}

fn flat_price_on(history: &busbar_kernel_ledger::cost::History, at: u64) -> Option<u64> {
    history.current().card_at(at).and_then(|(_, card)| {
        card.lane_rates(FLAT_LANE)
            .map(|r| r.nanos_per_unit("input"))
    })
}

fn config_epochs(records: &[busbar_kernel_wal::JournalRecord]) -> Vec<u64> {
    super::journalled_cards(records)
        .into_iter()
        .filter_map(|card| match card {
            super::JournalledCard::Applied(applied) => Some(applied.policy_epoch),
            super::JournalledCard::Amended(_) | super::JournalledCard::Corrected(..) => None,
        })
        .collect()
}

struct BreakableDisk {
    failing: Arc<std::sync::atomic::AtomicBool>,
    highest: Option<u64>,
}

struct BreakableSegment {
    inner: busbar_kernel_wal::MemorySegment,
    failing: Arc<std::sync::atomic::AtomicBool>,
}

impl BreakableSegment {
    fn check(&self) -> std::io::Result<()> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::other("the disk is gone"));
        }
        Ok(())
    }
}

impl busbar_kernel_wal::SegmentBackend for BreakableSegment {
    fn write_all_at(&mut self, offset: u64, bytes: &[u8]) -> std::io::Result<()> {
        self.check()?;
        self.inner.write_all_at(offset, bytes)
    }
    fn sync(&mut self) -> std::io::Result<()> {
        self.check()?;
        self.inner.sync()
    }
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read_at(offset, buf)
    }
    fn len(&self) -> std::io::Result<u64> {
        self.inner.len()
    }
    fn set_len(&mut self, len: u64) -> std::io::Result<()> {
        self.check()?;
        self.inner.set_len(len)
    }
}

impl busbar_kernel_wal::SegmentFactory for BreakableDisk {
    fn open(&mut self, index: u64) -> std::io::Result<Box<dyn busbar_kernel_wal::SegmentBackend>> {
        if self.failing.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(std::io::Error::other("no segment opens on a gone disk"));
        }
        self.highest = Some(self.highest.map_or(index, |h| h.max(index)));
        Ok(Box::new(BreakableSegment {
            inner: busbar_kernel_wal::MemorySegment::new(),
            failing: Arc::clone(&self.failing),
        }))
    }
    fn highest_index(&self) -> std::io::Result<Option<u64>> {
        Ok(self.highest)
    }

    fn existing(
        &self,
        _index: u64,
    ) -> std::io::Result<Option<Box<dyn busbar_kernel_wal::SegmentBackend>>> {
        Ok(None)
    }
    fn is_durable(&self) -> bool {
        true
    }
    fn segment_file(&self, _index: u64) -> Option<std::path::PathBuf> {
        None
    }
    fn quarantine(
        &mut self,
        _index: u64,
        _offset: u64,
        _unix_ms: u64,
        _bytes: &[u8],
    ) -> std::io::Result<Option<std::path::PathBuf>> {
        Ok(None)
    }
}

#[test]
fn a_rate_card_the_log_owes_after_a_failed_roll_is_not_published_while_unconfirmed() {
    let store = crate::root::store_double::RecordSlots::new();
    let holder = process_holder();
    apply_at(holder, 3.0, BOOT_A);
    let book = boot_book(holder, &store);
    let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let log = busbar_kernel_wal::Wal::with_parts(
        Box::new(BreakableDisk {
            failing: Arc::clone(&failing),
            highest: None,
        }),
        Box::new(busbar_kernel_wal::NullShipper::new()),
        busbar_kernel_wal::Mode::OnDisk,
        busbar_kernel_wal::SEGMENT_BYTES,
        busbar_kernel::store::now_ms,
    )
    .expect("the log opens");
    book.lock().expect("the book").journal = busbar_kernel_wal::Journal::over(log, 7);
    failing.store(true, std::sync::atomic::Ordering::SeqCst);

    let token = new_kernel().durability_token();
    assert!(book
        .lock()
        .expect("the book")
        .journal
        .append(
            &token,
            busbar_contract::caps::StepName::Meter,
            &[busbar_kernel_wal::Entry::new(
                busbar_kernel_wal::RecordClass::Policy,
                b"in flight".to_vec(),
            )],
        )
        .is_err());
    assert!(
        matches!(
            try_apply_at(holder, 5.0, APPLIED_B),
            Err(CardRefused::Lost(_))
        ),
        "a card the log retained but could not write is answered as in doubt, not confirmed"
    );
    assert_eq!(
        flat_price_at(holder, APPLIED_B),
        Some(3_000),
        "the unconfirmed card is not in force from the instant it was applied at"
    );
    assert_eq!(
        flat_price_at(holder, EARNED_B),
        Some(3_000),
        "nor at any instant after it: the card in force prices on"
    );
    let owed_cards = book
        .lock()
        .expect("the book")
        .journal
        .log()
        .owed()
        .iter()
        .filter_map(|r| busbar_kernel_wal::JournalRecord::decode(&r.body).ok())
        .filter(|r| super::CardApplied::from_body(&r.body).is_some())
        .count();
    assert_eq!(
        owed_cards, 1,
        "the log owes the card for its retry, and no WITHDRAW is written behind it (MONEY-DESIGN \
         section 3a)"
    );
    drop(book);
}

#[test]
fn a_rate_apply_before_the_book_is_bound_is_refused() {
    let store = crate::root::store_double::RecordSlots::new();
    let holder = process_holder();
    apply_at(holder, 3.0, BOOT_A);
    let book = open_book(holder, &store);
    apply_at(holder, 5.0, APPLIED_B);
    assert_eq!(holder.len(), 1, "no journal bound, no card published");
    assert_eq!(flat_price_at(holder, EARNED_B), Some(3_000));
    holder.bind_journal(&book);
    apply_at(holder, 5.0, EARNED_B);
    assert_eq!(holder.len(), 2);
    assert_eq!(
        cards_on_chain(&book),
        2,
        "the boot card and the bound apply"
    );
    assert_eq!(flat_price_at(holder, REBOOT), Some(5_000));
    drop(book);
}

fn swap_to_switchable_store(
    book: &Arc<Mutex<crate::root::durability::Durability>>,
    refusing: bool,
) -> Arc<std::sync::atomic::AtomicBool> {
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(refusing));
    book.lock().expect("the book").journal = busbar_kernel_wal::Journal::memory_buffered_to(
        7,
        Box::new(SwitchShipper(Arc::clone(&flag))),
        busbar_kernel::store::now_ms,
    );
    flag
}

#[test]
fn no_data_dir_or_no_arming_keeps_the_boot_card_and_journals_nothing() {
    let holder = process_holder();
    apply_at(holder, 3.0, BOOT_A);
    let book = crate::root::durability::build_with_cards(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        7,
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Some(holder),
    )
    .expect("memory-buffered cannot fail");
    let book = Arc::new(Mutex::new(book));
    holder.bind_journal(&book);
    apply_at(holder, 5.0, APPLIED_B);
    assert_eq!(
        cards_on_chain(&book),
        0,
        "no data directory, no card journalled"
    );
    assert_eq!(holder.len(), 2);
    assert_eq!(
        holder
            .history()
            .expect("a history")
            .entries()
            .first()
            .map(busbar_kernel_ledger::cost::CardEntry::effective_from),
        Some(0),
        "the boot card opens the history from instant zero"
    );

    let unarmed: &'static RootHistory = Box::leak(Box::default());
    apply_at(unarmed, 3.0, BOOT_A);
    let store = crate::root::store_double::RecordSlots::new();
    let book = open_book(unarmed, &store);
    unarmed.bind_journal(&book);
    apply_at(unarmed, 5.0, APPLIED_B);
    assert_eq!(
        cards_on_chain(&book),
        0,
        "an unarmed holder journals nothing"
    );
    drop(book);
}

#[test]
fn an_applied_card_round_trips_the_journal_as_the_same_card_on_every_plane() {
    let lanes = lanes_at(3.0);
    let fees = plane_fees();
    let units = [("gpt".to_string(), "search_units".to_string(), 2_000)];
    let raw = busbar_kernel::rate_apply::RawRates {
        lanes: &lanes,
        units: &units,
        flat_minor: 4,
        present: true,
        plane_fees: &fees,
    };
    let card = super::card_from_raw(&raw);
    let applied = super::CardApplied {
        effective_from: APPLIED_B,
        appended_at: APPLIED_B,
        policy_epoch: 3,
        form: super::CardForm::of(&raw, &card),
    };
    let read = super::CardApplied::from_body(&applied.body()).expect("the body reads back");
    assert_eq!(read, applied);
    let rebuilt = read.form.card();
    let fee_lane = busbar_kernel_ledger::cost::plane_fee_lane(PLANE);
    for lane in [
        FLAT_LANE,
        PLANE_LANE,
        "other",
        "planex\u{1f}other",
        fee_lane.as_str(),
    ] {
        assert_eq!(
            rebuilt.lane_unpriced(lane),
            card.lane_unpriced(lane),
            "{lane}"
        );
        for class in [
            "input",
            "output",
            "cache_read",
            "cache_write",
            "search_units",
        ] {
            let of = |c: &busbar_kernel_ledger::cost::RateCard| {
                c.lane_rates(lane)
                    .map(|r| (r.nanos_per_unit(class), r.class_priced(class)))
            };
            assert_eq!(of(&rebuilt), of(&card), "{lane} {class}");
        }
        for class in ["per_request", "per_session"] {
            assert_eq!(
                rebuilt.plane_lane(lane).0.fee_of(class),
                card.plane_lane(lane).0.fee_of(class),
                "{lane} {class}"
            );
        }
    }
    assert_eq!(rebuilt.fee(), card.fee());
    assert_eq!(rebuilt.pricing_enabled(), card.pricing_enabled());
    assert!(
        super::CardApplied::from_body(b"not a card").is_none(),
        "another Policy record is not read as a card"
    );

    let absent = busbar_kernel::rate_apply::RawRates {
        lanes: &[],
        units: &[],
        flat_minor: 9,
        present: false,
        plane_fees: &fees,
    };
    let card = super::card_from_raw(&absent);
    let rebuilt = super::CardForm::of(&absent, &card).card();
    assert!(!rebuilt.pricing_enabled());
    assert_eq!(rebuilt.fee(), 9);
    assert_eq!(
        rebuilt.plane_lane(&fee_lane).0.fee_of("per_session"),
        Some(11)
    );
}

#[cfg(feature = "root-admin")]
#[test]
fn a_back_dated_correction_survives_a_restart() {
    const CORRECTED: (u64, u64) = (0, 86_400_000);

    const OUTSIDE: u64 = 86_400_000 + EARNED_B;
    const SIGNED_AT: u64 = 20_000;
    let store = crate::root::store_double::RecordSlots::new();
    {
        let holder = process_holder();
        apply_at(holder, 3.0, BOOT_A);
        let book = boot_book(holder, &store);

        let journal = crate::root::units_admin::AmendmentJournal::new(
            Arc::clone(&book),
            new_kernel().durability_token(),
        );
        holder
            .amend(
                &crate::root::kernel::Correction {
                    effective_from: CORRECTED.0,
                    effective_until: Some(CORRECTED.1),
                    appended_at: SIGNED_AT,
                    author: busbar_kernel_ledger::cost::Author::Amend {
                        reason_hash: [9; 32],
                    },
                    cells: vec![(
                        busbar_kernel_ledger::cost::LaneClass::new(FLAT_LANE, "input"),
                        4_000,
                    )],
                    fee: None,
                },
                |card, base| {
                    journal.record(
                        &crate::root::units_admin::AmendmentRecord {
                            version: crate::root::units_admin::AmendmentVersion::V4,
                            effective_from: CORRECTED.0,
                            effective_until: Some(CORRECTED.1),
                            amended_at_ms: SIGNED_AT,
                            sealed_over: Some(base),
                            sealed_fee: card.fee(),
                            rates: vec![(FLAT_LANE.to_string(), "input".to_string(), Some(4_000))],
                            operator_fingerprint: "op".to_string(),
                            reason_hash: [9; 32],
                            principal: "admin".to_string(),
                            dual_control: "single".to_string(),
                            signed_payload: b"signed".to_vec(),
                            signature: "00".to_string(),
                        },
                        SIGNED_AT / 1_000,
                    )
                },
            )
            .expect("a resolved history takes a correction");
        drain_book(&book);
    }

    let holder = process_holder();
    apply_at(holder, 3.0, REBOOT);
    let book = boot_book(holder, &store);
    assert_eq!(
        (
            earned(holder, FLAT_LANE, EARNED_A),
            earned(holder, FLAT_LANE, OUTSIDE)
        ),
        (4_000_000_000, 3_000_000_000),
        "the correction reprices exactly its window after a restart, and nothing outside it"
    );
    assert_eq!(holder.len(), 2, "the opening card and the correction");
    let history = holder.history().expect("a history");
    let view = history.current();
    let entry = view
        .entry_at(EARNED_A)
        .expect("the correction covers its window");
    assert_eq!(
        (entry.appended_at(), entry.effective_until()),
        (SIGNED_AT, Some(CORRECTED.1))
    );
    assert!(matches!(
        entry.author(),
        busbar_kernel_ledger::cost::Author::Amend { .. }
    ));
    drop(book);
}

#[cfg(feature = "root-admin")]
fn seal_correction(
    holder: &RootHistory,
    book: &Arc<Mutex<crate::root::durability::Durability>>,
    window: (u64, u64),
    signed_at: u64,
    nanos: u64,
    rebase: impl FnOnce(super::CorrectionBase) -> super::CorrectionBase,
) -> busbar_kernel_ledger::cost::HistorySeq {
    let journal = crate::root::units_admin::AmendmentJournal::new(
        Arc::clone(book),
        new_kernel().durability_token(),
    );
    let seq = holder
        .amend(
            &super::Correction {
                effective_from: window.0,
                effective_until: Some(window.1),
                appended_at: signed_at,
                author: busbar_kernel_ledger::cost::Author::Amend {
                    reason_hash: [9; 32],
                },
                cells: vec![(
                    busbar_kernel_ledger::cost::LaneClass::new(FLAT_LANE, "input"),
                    nanos,
                )],
                fee: None,
            },
            |card, base| {
                journal.record(
                    &crate::root::units_admin::AmendmentRecord {
                        version: crate::root::units_admin::AmendmentVersion::V4,
                        effective_from: window.0,
                        effective_until: Some(window.1),
                        amended_at_ms: signed_at,
                        sealed_over: Some(rebase(base)),
                        sealed_fee: card.fee(),
                        rates: vec![(FLAT_LANE.to_string(), "input".to_string(), Some(nanos))],
                        operator_fingerprint: "op".to_string(),
                        reason_hash: [9; 32],
                        principal: "admin".to_string(),
                        dual_control: "single".to_string(),
                        signed_payload: b"signed".to_vec(),
                        signature: "00".to_string(),
                    },
                    signed_at / 1_000,
                )
            },
        )
        .expect("a resolved history takes a correction");
    drain_book(book);
    seq
}

#[cfg(feature = "root-admin")]
fn refused_corrections(book: &Arc<Mutex<crate::root::durability::Durability>>) -> Vec<String> {
    book.lock().expect("the book").restart_findings.clone()
}

#[cfg(feature = "root-admin")]
fn holds_a_correction(holder: &RootHistory) -> bool {
    holder
        .history()
        .expect("a history")
        .entries()
        .iter()
        .any(|e| matches!(e.author(), busbar_kernel_ledger::cost::Author::Amend { .. }))
}

#[cfg(feature = "root-admin")]
#[test]
fn a_restore_whose_prefix_lacks_the_corrections_base_refuses_it() {
    const DAY: u64 = 86_400_000;
    const CARD_B: u64 = DAY;
    const CORRECTED: (u64, u64) = (DAY, 2 * DAY);
    const SIGNED_AT: u64 = 3 * DAY;
    let store = crate::root::store_double::RecordSlots::new();
    {
        let holder = process_holder();
        apply_at(holder, 3.0, BOOT_A);
        let book = boot_book(holder, &store);
        publish_unjournalled_at(holder, 5.0, CARD_B);
        assert_eq!(holder.len(), 2, "card B is entry 1 on the live history");
        let seq = seal_correction(holder, &book, CORRECTED, SIGNED_AT, 4_000, |base| base);
        assert_eq!(seq, busbar_kernel_ledger::cost::HistorySeq(2));
    }

    let holder = process_holder();
    apply_at(holder, 5.0, 4 * DAY);
    let book = boot_book(holder, &store);
    assert_eq!(
        refused_corrections(&book),
        vec![super::CorrectionRefused {
            effective_from: CORRECTED.0,
            effective_until: Some(CORRECTED.1),
            appended_at: SIGNED_AT,
            sealed_over: super::CorrectionBase::Key {
                key: busbar_kernel_ledger::cost::EntryKey::new(CARD_B, [0; 8], 1),
                card_digest: holder
                    .history()
                    .expect("a history")
                    .entries()
                    .get(1)
                    .expect("card B is rebuilt as entry 1")
                    .card()
                    .digest(),
            },
            cause: super::BaseMismatch::MissingBase,
        }
        .to_string()],
        "the correction is refused by name, not dropped with a log line or rebuilt over card A"
    );
    assert!(
        !holds_a_correction(holder),
        "a refused correction is not rebuilt over another card"
    );
    drop(book);
}

#[cfg(feature = "root-admin")]
#[test]
fn a_restore_whose_base_digest_differs_refuses_the_correction() {
    const CORRECTED: (u64, u64) = (0, 86_400_000);
    const SIGNED_AT: u64 = 20_000;
    let store = crate::root::store_double::RecordSlots::new();
    let sealed_over = {
        let holder = process_holder();
        apply_at(holder, 3.0, BOOT_A);
        let book = boot_book(holder, &store);
        let mut sealed_over = None;
        seal_correction(holder, &book, CORRECTED, SIGNED_AT, 4_000, |mut base| {
            match &mut base {
                super::CorrectionBase::Key { card_digest, .. }
                | super::CorrectionBase::LegacyOrdinal { card_digest, .. } => {
                    card_digest[0] ^= 0xff
                }
            }
            sealed_over = Some(base);
            base
        });
        sealed_over.expect("the seal ran")
    };
    assert!(
        matches!(sealed_over, super::CorrectionBase::Key { key, .. } if key == busbar_kernel_ledger::cost::EntryKey::new(BOOT_A, [0; 8], 0))
    );

    let holder = process_holder();
    apply_at(holder, 3.0, REBOOT);
    let book = boot_book(holder, &store);
    assert_eq!(
        refused_corrections(&book),
        vec![super::CorrectionRefused {
            effective_from: CORRECTED.0,
            effective_until: Some(CORRECTED.1),
            appended_at: SIGNED_AT,
            sealed_over,
            cause: super::BaseMismatch::BaseDigest,
        }
        .to_string()]
    );
    assert!(!holds_a_correction(holder));
    assert_eq!(holder.len(), 1, "the opening card alone");
    drop(book);
}

#[cfg(feature = "root-admin")]
#[test]
fn a_restore_over_the_sealed_base_rebuilds_the_identical_card() {
    const CORRECTED: (u64, u64) = (0, 86_400_000);
    const SIGNED_AT: u64 = 20_000;
    let store = crate::root::store_double::RecordSlots::new();
    let (live_seq, live_card) = {
        let holder = process_holder();
        apply_at(holder, 3.0, BOOT_A);
        let book = boot_book(holder, &store);
        let seq = seal_correction(holder, &book, CORRECTED, SIGNED_AT, 4_000, |base| base);
        let history = holder.history().expect("a history");
        let card = history
            .entries()
            .get(usize::try_from(seq.get()).expect("a small seq"))
            .expect("the correction is on the live history")
            .card()
            .clone();
        (seq, card)
    };

    let holder = process_holder();
    apply_at(holder, 3.0, REBOOT);
    let book = boot_book(holder, &store);
    assert!(
        book.lock().expect("the book").restart_findings.is_empty(),
        "{:?}",
        book.lock().expect("the book").restart_findings
    );
    let history = holder.history().expect("a history");
    let rebuilt = history
        .entries()
        .get(usize::try_from(live_seq.get()).expect("a small seq"))
        .expect("the correction is rebuilt at the number it had");
    assert!(matches!(
        rebuilt.author(),
        busbar_kernel_ledger::cost::Author::Amend { .. }
    ));
    assert_eq!(rebuilt.card().digest(), live_card.digest());
    assert_eq!(
        format!("{:?}", rebuilt.card()),
        format!("{live_card:?}"),
        "the rebuilt correction is the card the live node priced"
    );
    assert_eq!(
        rebuilt
            .card()
            .lane_rates(FLAT_LANE)
            .map(|r| r.nanos_per_unit("input")),
        Some(4_000)
    );
    drop(book);
}

#[test]
fn applying_rates_registers_the_classes_a_unit_may_report() {
    let fees = plane_fees();
    let lanes = lanes_at(1.0);
    let _ = process_holder().apply_rates(
        &busbar_kernel::rate_apply::RawRates {
            lanes: &lanes,
            units: &[(
                "gpt".to_string(),
                "configured_open_units".to_string(),
                2_000,
            )],
            flat_minor: 0,
            present: false,
            plane_fees: &fees,
        },
        0,
    );
    for class in busbar_contract::records::RESERVED_UNITS {
        assert!(
            busbar_kernel::Registration::resolve(class).is_some(),
            "{class}"
        );
    }
    assert!(busbar_kernel::Registration::resolve("configured_open_units").is_some());
    assert_eq!(
        busbar_kernel::Registration::resolve("a_class_nobody_declared_or_configured"),
        None
    );
}

fn boot_book_on_store(
    holder: &'static RootHistory,
    slots: &crate::root::store_double::RecordSlots,
) -> Arc<Mutex<crate::root::durability::Durability>> {
    let lane = crate::root::durability::JournalLane::start(slots.calls(), "test-store")
        .expect("the lane starts");
    let book = Arc::new(Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig { data_dir: None },
            7,
            lane,
            Some(holder),
        )
        .expect("the store reads back"),
    ));
    holder.bind_journal(&book);
    book
}

#[cfg(feature = "root-admin")]
#[test]
fn a_back_dated_correction_survives_a_restart_over_the_store() {
    const CORRECTED: (u64, u64) = (0, 86_400_000);
    const SIGNED_AT: u64 = 20_000;
    let slots = crate::root::store_double::RecordSlots::new();
    {
        let holder = process_holder();
        apply_at(holder, 3.0, BOOT_A);
        let book = boot_book_on_store(holder, &slots);
        let journal = crate::root::units_admin::AmendmentJournal::new(
            Arc::clone(&book),
            new_kernel().durability_token(),
        );
        holder
            .amend(
                &crate::root::kernel::Correction {
                    effective_from: CORRECTED.0,
                    effective_until: Some(CORRECTED.1),
                    appended_at: SIGNED_AT,
                    author: busbar_kernel_ledger::cost::Author::Amend {
                        reason_hash: [9; 32],
                    },
                    cells: vec![(
                        busbar_kernel_ledger::cost::LaneClass::new(FLAT_LANE, "input"),
                        4_000,
                    )],
                    fee: None,
                },
                |card, base| {
                    journal.record(
                        &crate::root::units_admin::AmendmentRecord {
                            version: crate::root::units_admin::AmendmentVersion::V4,
                            effective_from: CORRECTED.0,
                            effective_until: Some(CORRECTED.1),
                            amended_at_ms: SIGNED_AT,
                            sealed_over: Some(base),
                            sealed_fee: card.fee(),
                            rates: vec![(FLAT_LANE.to_string(), "input".to_string(), Some(4_000))],
                            operator_fingerprint: "op".to_string(),
                            reason_hash: [9; 32],
                            principal: "admin".to_string(),
                            dual_control: "single".to_string(),
                            signed_payload: b"signed".to_vec(),
                            signature: "00".to_string(),
                        },
                        SIGNED_AT / 1_000,
                    )
                },
            )
            .expect("a resolved history takes a correction");
        assert!(
            book.lock()
                .expect("the book")
                .lane()
                .expect("a lane")
                .drain(std::time::Duration::from_secs(5)),
            "the store takes the chain"
        );
    }

    let holder = process_holder();
    apply_at(holder, 3.0, REBOOT);
    let _book = boot_book_on_store(holder, &slots);
    assert_eq!(
        earned(holder, FLAT_LANE, EARNED_A),
        4_000_000_000,
        "the correction reprices its window after a restart over the store"
    );
    assert_eq!(holder.len(), 2, "the opening card and the correction");
}

#[test]
fn a_stored_chain_that_does_not_verify_never_disarms_the_card_journal() {
    let slots = crate::root::store_double::RecordSlots::new();
    {
        let holder = process_holder();
        apply_at(holder, 3.0, BOOT_A);
        let book = boot_book_on_store(holder, &slots);
        assert!(
            book.lock()
                .expect("the book")
                .lane()
                .expect("a lane")
                .drain(std::time::Duration::from_secs(5)),
            "the store takes the chain"
        );
    }
    slots.corrupt(
        crate::root::durability::JOURNAL_SCHEMA,
        &crate::root::durability::part_key(7, 1, 0),
    );

    let holder = process_holder();
    apply_at(holder, 3.0, REBOOT);
    let lane = crate::root::durability::JournalLane::start(slots.calls(), "test-store")
        .expect("the lane starts");
    let refused = crate::root::durability::build_on_store(
        &crate::root::durability::DurabilityConfig { data_dir: None },
        7,
        lane,
        Some(holder),
    )
    .err()
    .map(|e| e.to_string());
    assert!(
        refused
            .as_deref()
            .is_some_and(|why| why.contains("does not verify")),
        "a stored chain that does not verify must refuse the boot, naming the break; the build \
         answered {refused:?}"
    );
    assert!(
        matches!(
            *holder.journal.lock().unwrap_or_else(|p| p.into_inner()),
            CardJournal::Armed(_)
        ),
        "the card journal is left armed, never disarmed by a chain the boot could not verify"
    );
}

#[test]
fn store_card_history_ignores_absent_and_unusable_data_directories_without_writing_files() {
    let scratch = std::env::temp_dir().join(format!(
        "busbar-store-card-config-{}-{}",
        std::process::id(),
        hex::encode(crate::root::card_store::boot_rand())
    ));
    std::fs::create_dir(&scratch).unwrap();
    let blocked = scratch.join("a-file-not-a-directory");
    std::fs::write(&blocked, b"unchanged fixture").unwrap();
    let slots = crate::root::store_double::RecordSlots::new();
    let boot = busbar_kernel::config::card::CardFields {
        per_request_fee: 3,
        ..Default::default()
    };
    let mut edited = boot.clone();
    edited.per_request_fee = 7;
    let mut changed_key = None;
    for data_dir in [None, Some(blocked.join("cannot-open"))] {
        let holder: &'static RootHistory = Box::leak(Box::default());
        holder.keep_in_store(slots.calls(), 7);
        holder.card_applied(&boot, "boot fixture");
        let lane = crate::root::durability::JournalLane::start(slots.calls(), "test-store")
            .expect("Store lane");
        let book = crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig { data_dir },
            7,
            lane,
            Some(holder),
        )
        .expect("Store owns persistence independently of dataDir");
        holder.card_applied(&edited, "config/apply by admin");
        let own = holder.card_store().unwrap().own().unwrap();
        assert_eq!(own.1, edited);
        if let Some(key) = changed_key {
            assert!(holder
                .card_store()
                .unwrap()
                .entries()
                .iter()
                .any(|entry| entry.key == key));
        }
        changed_key = Some(own.0);
        assert!(holder.pending_refusal().is_none());
        drop(book);
        assert_eq!(std::fs::read(&blocked).unwrap(), b"unchanged fixture");
        assert_eq!(
            std::fs::read_dir(&scratch).unwrap().count(),
            1,
            "the host wrote no card files, journals or sidecars"
        );
    }
    std::fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn a_store_amendment_keeps_its_pinned_base_and_calls_the_store_outside_the_global_money_lock() {
    let slots = crate::root::store_double::RecordSlots::new();
    let holder: &'static RootHistory = Box::leak(Box::default());
    let boot = busbar_kernel::config::card::CardFields {
        per_request_fee: 3,
        ..Default::default()
    };
    holder.keep_in_store(slots.calls(), 7);
    holder.card_applied(&boot, "boot");
    holder.boot_in_store(None).unwrap();
    let store = holder.card_store().unwrap();
    let base = store.own().unwrap().0;
    slots.on_put(move || {
        assert!(
            holder.applying.try_lock().is_ok(),
            "no global money lock crosses StoreCalls"
        );
        None
    });
    let mut changed = boot.clone();
    changed.per_request_fee = 5;
    holder
        .amend_by(
            &Correction {
                effective_from: 0,
                effective_until: Some(86_400_000),
                appended_at: 20_000,
                author: busbar_kernel_ledger::cost::Author::Amend {
                    reason_hash: [9; 32],
                },
                cells: Vec::new(),
                fee: Some(7),
            },
            "admin correcting pinned opening",
            |_, _| {
                assert!(
                    holder.applying.try_lock().is_ok(),
                    "seal callback is outside the global lock"
                );
                holder.card_applied(&changed, "config changed during seal");
                Ok::<(), ()>(())
            },
        )
        .expect("the immutable correction can be sealed over its original base");
    let amendment = store
        .entries()
        .into_iter()
        .find(|entry| {
            matches!(
                entry.author,
                crate::root::card_store::EntryAuthor::Amend { .. }
            )
        })
        .unwrap();
    assert_eq!(amendment.base, Some(base));
    assert_eq!(amendment.card.per_request_fee, 7);
    assert_eq!(
        store.own().unwrap().1,
        changed,
        "amend never replaces config own-selection"
    );
}

fn keyed_correction_fixture() -> (
    busbar_kernel_ledger::cost::History,
    super::Correction,
    busbar_kernel_ledger::cost::EntryKey,
) {
    use busbar_kernel_ledger::cost::{Author, CardEntryDraft, EntryKey, History, RateCard};
    let key = EntryKey::new(100, [9; 8], 0);
    let mut history = History::new();
    history.insert(
        key,
        CardEntryDraft {
            effective_from: 0,
            effective_until: None,
            card: RateCard::absent(3),
            appended_at: 100,
            author: Author::Opening,
        },
    );
    let correction = super::Correction {
        effective_from: 0,
        effective_until: Some(100),
        appended_at: 300,
        author: Author::Amend {
            reason_hash: [7; 32],
        },
        cells: Vec::new(),
        fee: Some(9),
    };
    (history, correction, key)
}

#[test]
fn correction_keys_and_pinned_boundaries_survive_a_late_lower_peer_key() {
    use busbar_kernel_ledger::cost::{Author, CardEntryDraft, EntryKey, RateCard};
    let (mut history, correction, key) = keyed_correction_fixture();
    let (sealed, expected) = correction
        .draft_over(history.current())
        .expect("a sole base");
    let peer = EntryKey::new(100, [1; 8], 0);
    history.insert(
        peer,
        CardEntryDraft {
            effective_from: 0,
            effective_until: None,
            card: RateCard::absent(77),
            appended_at: 100,
            author: Author::Opening,
        },
    );
    assert_eq!(
        history.entry(&key).unwrap().seq(),
        busbar_kernel_ledger::cost::HistorySeq(1)
    );
    assert_eq!(
        correction
            .rebuild_over(&history, sealed)
            .unwrap()
            .card
            .digest(),
        expected.card.digest()
    );
    let pin = PinnedHistory {
        history: Arc::new(history),
        at: key,
    };
    assert_eq!(pin.seq(), key);
    assert_eq!(pin.view().card_at(1).unwrap().0, key);
    assert_eq!(pin.view_at(EntryKey::new(999, [9; 8], 9)).seq(), Some(key));
}

#[test]
fn correction_rebuild_refuses_unknown_keys_digest_mismatches_and_ordinary_legacy_lookup() {
    use busbar_kernel_ledger::cost::{EntryKey, HistorySeq};
    let (history, correction, key) = keyed_correction_fixture();
    let digest = history.entry(&key).unwrap().card().digest();
    for missing in [EntryKey([0; 20]), EntryKey::new(999, [9; 8], 9)] {
        assert!(matches!(
            correction.rebuild_over(
                &history,
                super::CorrectionBase::Key {
                    key: missing,
                    card_digest: digest
                }
            ),
            Err(super::BaseMismatch::MissingBase)
        ));
    }
    assert!(matches!(
        correction.rebuild_over(
            &history,
            super::CorrectionBase::Key {
                key,
                card_digest: [5; 32]
            }
        ),
        Err(super::BaseMismatch::BaseDigest)
    ));
    let legacy = super::CorrectionBase::LegacyOrdinal {
        seq: HistorySeq(0),
        card_digest: digest,
    };
    assert!(matches!(
        correction.rebuild_over(&history, legacy),
        Err(super::BaseMismatch::MissingBase)
    ));
    assert!(correction
        .rebuild_from_original_chain(&history, legacy, &[Some(key)])
        .is_ok());
    assert!(matches!(
        correction.rebuild_from_original_chain(&history, legacy, &[None, Some(key)]),
        Err(super::BaseMismatch::MissingBase)
    ));
}

#[test]
fn legacy_correction_replay_uses_original_identity_and_checks_the_original_sole_base() {
    use busbar_kernel_ledger::cost::{Author, CardEntryDraft, EntryKey, HistorySeq, RateCard};
    let (mut history, correction, key) = keyed_correction_fixture();
    let legacy = super::CorrectionBase::LegacyOrdinal {
        seq: HistorySeq(0),
        card_digest: history.entry(&key).unwrap().card().digest(),
    };
    let draft = |fee| CardEntryDraft {
        effective_from: 0,
        effective_until: None,
        card: RateCard::absent(fee),
        appended_at: 100,
        author: Author::Opening,
    };
    history.insert(EntryKey::new(100, [1; 8], 0), draft(77));
    assert_eq!(
        correction
            .rebuild_from_original_chain(&history, legacy, &[Some(key)])
            .unwrap()
            .0,
        key
    );
    let higher = EntryKey::new(200, [3; 8], 0);
    history.insert(higher, draft(88));
    assert!(
        matches!(correction.rebuild_from_original_chain(&history, legacy, &[Some(key)]), Err(super::BaseMismatch::OtherBase(Some(found))) if found == higher)
    );
}

#[test]
fn an_actual_known_zero_opening_key_is_not_an_unattached_card_sentinel() {
    use busbar_kernel_ledger::cost::{Author, CardEntryDraft, EntryKey, History, RateCard};
    let (_, correction, _) = keyed_correction_fixture();
    let mut history = History::new();
    history.append(CardEntryDraft {
        effective_from: 0,
        effective_until: None,
        card: RateCard::absent(3),
        appended_at: 0,
        author: Author::Opening,
    });
    let (sealed, _) = correction.draft_over(history.current()).unwrap();
    assert!(matches!(sealed, super::CorrectionBase::Key { key, .. } if key == EntryKey([0; 20])));
    assert!(correction.rebuild_over(&history, sealed).is_ok());
}
