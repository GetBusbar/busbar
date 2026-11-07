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

#[tokio::test]
async fn the_units_assemble_from_values_configuration_decided() {
    let fixture = crate::root::durability::tests::NativeFixture::new(7).await;
    let durability = fixture.book().await;

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
impl busbar_kernel::persistence::recovery_api::Store for ReachedStore {
    fn chain_break<'a>(
        &'a self,
        _admin: &'a busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
    ) -> busbar_kernel::persistence::recovery_api::StoreCall<'a> {
        Box::pin(async move {
            self.note("chain_break".to_string());
            Ok(())
        })
    }

    fn store_restore<'a>(
        &'a self,
        _admin: &'a busbar_contract::caps::Grant<busbar_contract::caps::AdminVerb>,
        backup_ref: &'a str,
    ) -> busbar_kernel::persistence::recovery_api::StoreCall<'a> {
        Box::pin(async move {
            self.note(format!("store_restore {backup_ref}"));
            Ok(())
        })
    }
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn the_admin_units_over_a_book_reach_that_books_store_for_every_recovery_verb() {
    let configured = Arc::new(ReachedStore::default());
    let core = crate::root::real_store::core().await;
    let budget = busbar_kernel::persistence::journal::BufferBudget {
        records: 128,
        bytes: 1024 * 1024,
    };
    let journal = busbar_kernel::persistence::journal::RuntimeJournal::open(core, 37, budget)
        .await
        .expect("native journal");
    let mut book = crate::root::durability::node_book(journal, budget)
        .await
        .expect("native book");
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
        .await
        .expect("chain_break applies");
    store
        .store_restore(&units.admin_token, "nightly")
        .await
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

#[tokio::test]
async fn actual_card_store_and_root_rate_apply_gate_the_real_app_generation_commit() {
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
    let library_path = crate::root::test_plugins::application_store_library();
    let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
        .expect("the actual store statement reads")
        .expect("the actual store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the actual store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(library_path).expect("the actual store library reads");
    let directory = crate::root::test_plugins::scratch("confirmed-card-generation");
    std::fs::write(
        directory.join("store.tar.gz"),
        crate::root::test_plugins::signed(&release, manifest, &library),
    )
    .expect("stage the actual store archive");
    let settings = crate::root::test_plugins::application_store_settings(&directory);
    let late = crate::root::serve::LateServices::new();
    let dispatcher = crate::root::dispatch::boot(1, &late);
    crate::root::doors::install_dispatcher(dispatcher);

    crate::register_protocols();
    crate::register_planes();
    crate::register_diagnostics();
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
    let (credentials, _handle) = crate::root::credentials::AppCredentials::late();
    crate::root::serve::compose(judge.clone(), &late, credentials);
    crate::root::doors::install_plugin_logs(crate::root::boot::plugin_logs());
    crate::root::connector::boot(
        crate::LINKED_TRANSPORT_DOORS,
        &crate::root::policy::client_settings(&config.limits),
        judge,
        &[],
    );
    let plugins = crate::root::test_plugins::trusted_config_with_key(
        &directory,
        &crate::root::test_plugins::key(0x5a),
    );
    let (core, faults) = native_price_backend().await;
    let boot = busbar_kernel::config::card::CardFields {
        per_request_fee: BOOT_FEE,
        ..Default::default()
    };
    ROOT_CARD.keep_in_store(core, 1).unwrap();
    ROOT_CARD.card_applied(&boot, "actual boot");
    ROOT_CARD.boot_in_store(None).await.unwrap();
    let build = async |fee, prior: Option<&busbar_kernel::state::App>| {
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
        let (app, _, limits) = crate::root::real_store::build_app(
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
        .await
        .unwrap();
        (Arc::new(app), limits)
    };
    let (boot_app, limits) = build(BOOT_FEE, None).await;
    limits.keep().await.unwrap();
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
                    .await
                    .unwrap(),
            );
        }
        faults
            .refuse
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let (next, limits) = build(fee, Some(&before)).await;
        assert!(handle
            .commit_rates_and_swap(next, || Ok(()), limits, "actual generation refusal")
            .await
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
        faults
            .refuse
            .store(false, std::sync::atomic::Ordering::SeqCst);
        let (next, limits) = build(fee, Some(&before)).await;
        handle
            .reload_rates_and_swap(
                next.clone(),
                || Ok(()),
                limits,
                "explicit actual generation recovery",
            )
            .await
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

fn fields_at(price: f64) -> busbar_kernel::config::card::CardFields {
    let lanes = lanes_at(price);
    let fees = plane_fees();
    let units = [("gpt".to_string(), "search_units".to_string(), 2_000)];
    let raw = busbar_kernel::rate_apply::RawRates {
        lanes: &lanes,
        units: &units,
        flat_minor: 4,
        present: true,
        plane_fees: &fees,
    };
    super::CardForm::of(&raw, &super::card_from_raw(&raw)).to_fields()
}
async fn seed_price(
    core: &busbar_kernel::persistence::facade::CoreStore,
    card: busbar_kernel::config::card::CardFields,
    at: u64,
) {
    use busbar_kernel::governance::persistence::prices::{
        Activation, EntryAuthor, Outcome, StoredEntry,
    };
    use busbar_kernel_ledger::cost::EntryKey;
    let prices = core.prices();
    let snapshot = prices.snapshot().await.unwrap();
    let opening = snapshot.entries.is_empty();
    let entry = StoredEntry {
        key: EntryKey::new(at, 7u64.to_be_bytes(), snapshot.entries.len() as u32),
        effective_from: if opening { 0 } else { at },
        effective_until: None,
        appended_at: at,
        author: if opening {
            EntryAuthor::Opening {}
        } else {
            EntryAuthor::Change
        },
        actor: "native fixture".into(),
        base: snapshot.head,
        writer: 7,
        set_fields: Vec::new(),
        card,
        correction: None,
    };
    let key = entry.key;
    let mut prepare = prices.prepare(entry, true).await.unwrap();
    assert_eq!(prices.submit(&mut prepare).await.unwrap(), Outcome::Applied);
    let mut authorize = prices
        .authorize_activation(
            key,
            Activation {
                effective_from: if opening { 0 } else { at },
            },
        )
        .await
        .unwrap();
    assert_eq!(
        prices.submit(&mut authorize).await.unwrap(),
        Outcome::Applied
    );
    let mut activate = prices.activate(key).await.unwrap();
    assert_eq!(
        prices.submit(&mut activate).await.unwrap(),
        Outcome::Applied
    );
}
async fn price_holder(
    core: Arc<busbar_kernel::persistence::facade::CoreStore>,
    card: &busbar_kernel::config::card::CardFields,
) -> &'static RootHistory {
    let holder: &'static RootHistory = Box::leak(Box::default());
    holder.keep_in_store(core, 7).unwrap();
    holder.card_applied(card, "fixture boot");
    holder.boot_in_store(None).await.unwrap();
    holder
        .card_store()
        .unwrap()
        .stop_background()
        .await
        .unwrap();
    holder
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
            tokens_input: input.into(),
            tokens_output: 0.into(),
            tokens_cache_read: 0.into(),
            tokens_cache_creation: 0.into(),
            requests: 0,
            spend_micros: 0,
            classes: Default::default(),
        },
    )
    .expect("the row prices")
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

#[tokio::test]
async fn a_restart_prices_every_posting_at_the_card_in_force_when_it_arrived() {
    let core = crate::root::real_store::core().await;
    seed_price(&core, fields_at(3.0), BOOT_A).await;
    seed_price(&core, fields_at(5.0), APPLIED_B).await;
    let holder = price_holder(core.clone(), &fields_at(5.0)).await;
    let before = figures(holder);
    assert_eq!(before, (8_000_000_000, 16_000_000_000));
    let restarted = price_holder(core.clone(), &fields_at(5.0)).await;
    assert_eq!(figures(restarted), before);
    assert_eq!(restarted.len(), 2, "unchanged restart appends no price");
    assert_eq!(
        (
            usage_row_micros(restarted, 0, 1_000_000),
            usage_row_micros(restarted, APPLIED_B, 1_000_000)
        ),
        (3_000_000, 5_000_000)
    );
    seed_price(&core, fields_at(7.0), REBOOT_CHANGED).await;
    let changed = price_holder(core, &fields_at(7.0)).await;
    assert_eq!(
        figures(changed),
        before,
        "historical earnings stay dated after a new configuration"
    );
    assert_eq!(changed.len(), 3);
    assert_eq!(earned(changed, FLAT_LANE, REBOOT_CHANGED), 7_000_000_000);
    assert_eq!(earned(changed, PLANE_LANE, REBOOT_CHANGED), 14_000_000_000);
}
#[tokio::test]
async fn a_restart_after_store_chunks_prices_every_posting_at_the_card_in_force_when_it_arrived() {
    let core = crate::root::real_store::core().await;
    let mut large = fields_at(3.0);
    let rates = large.rate_card.as_mut().unwrap();
    let entry = rates[FLAT_LANE].clone();
    for n in 0..64 {
        rates.insert(format!("large-card-lane-{n}"), entry.clone());
    }
    assert!(
        large.to_bytes().len() > 4096,
        "accepted price payload crosses the retired fixed record limit"
    );
    seed_price(&core, large.clone(), BOOT_A).await;
    seed_price(&core, fields_at(5.0), APPLIED_B).await;
    let holder = price_holder(core.clone(), &fields_at(5.0)).await;
    let restarted = price_holder(core, &fields_at(5.0)).await;
    assert_eq!(figures(restarted), figures(holder));
    assert_eq!(restarted.card_store().unwrap().entries()[0].card, large);
    assert_eq!(restarted.len(), 2, "both eras survive native persistence");
}
#[tokio::test]
async fn a_rate_apply_the_journal_refuses_leaves_the_card_in_force_unchanged() {
    let (core, faults) = native_price_backend().await;
    let holder = price_holder(core, &fields_at(3.0)).await;
    faults
        .refuse
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let store = holder.card_store().unwrap();
    assert!(store
        .prepare(&fields_at(5.0), "refused change")
        .await
        .is_err());
    assert_eq!(holder.len(), 1);
    assert_eq!(flat_price_at(holder, EARNED_B), Some(3_000));
    assert!(
        store.pending().is_some(),
        "the original refuses publication while retaining its owner"
    );
}
#[tokio::test]
async fn a_rate_card_the_log_owes_after_a_failed_roll_is_not_published_while_unconfirmed() {
    let (core, faults) = native_price_backend().await;
    let holder = price_holder(core, &fields_at(3.0)).await;
    faults
        .unknown_after
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let store = holder.card_store().unwrap();
    assert!(store
        .prepare(&fields_at(5.0), "lost native reply")
        .await
        .is_err());
    let original = store.pending().unwrap();
    assert_eq!(holder.len(), 1);
    assert_eq!(flat_price_at(holder, EARNED_B), Some(3_000));
    let prepared = store
        .prepare_recovery(&fields_at(5.0), "exact recovery")
        .await
        .unwrap();
    let key = prepared.confirm_activation().await.unwrap().commit();
    assert_eq!(key, original, "recovery publishes the retained candidate");
    assert_eq!(holder.len(), 2);
    assert!(store.pending().is_none());
}
#[tokio::test]
async fn a_rate_apply_before_the_book_is_bound_is_refused() {
    let holder = RootHistory::default();
    let card = fields_at(3.0);
    let rates = card.rates();
    assert!(matches!(
        holder.apply_rates(&rates.raw(), BOOT_A),
        Err(CardRefused::Unbound)
    ));
    assert_eq!(holder.len(), 0);
    holder
        .keep_in_store(crate::root::real_store::core().await, 7)
        .unwrap();
    holder.card_applied(&card, "boot");
    holder.boot_in_store(None).await.unwrap();
    holder
        .card_store()
        .unwrap()
        .prepare(&fields_at(5.0), "bound change")
        .await
        .unwrap()
        .confirm_activation()
        .await
        .unwrap()
        .commit();
    assert_eq!(holder.len(), 2);
    holder
        .card_store()
        .unwrap()
        .stop_background()
        .await
        .unwrap();
}
#[tokio::test]
async fn no_data_dir_or_no_arming_keeps_the_boot_card_and_journals_nothing() {
    let holder = price_holder(crate::root::real_store::core().await, &fields_at(3.0)).await;
    assert_eq!(holder.len(), 1);
    assert_eq!(
        holder.card_store().unwrap().entries().len(),
        1,
        "canonical prices require no disk or separate node journal"
    );
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
async fn correct_opening(holder: &RootHistory) {
    holder
        .amend(
            &super::Correction {
                effective_from: 0,
                effective_until: Some(86_400_000),
                appended_at: 20_000,
                author: busbar_kernel_ledger::cost::Author::Amend {
                    reason_hash: [9; 32],
                },
                cells: vec![(
                    busbar_kernel_ledger::cost::LaneClass::new(FLAT_LANE, "input"),
                    4_000,
                )],
                fee: None,
            },
            |_, _| Ok::<(), ()>(()),
        )
        .await
        .unwrap();
}
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_back_dated_correction_survives_a_restart() {
    native_correction_restart().await;
}
#[cfg(feature = "root-admin")]
async fn native_correction_restart() {
    let core = crate::root::real_store::core().await;
    seed_price(&core, fields_at(3.0), BOOT_A).await;
    let holder = price_holder(core.clone(), &fields_at(3.0)).await;
    correct_opening(holder).await;
    let live = holder.history().unwrap();
    let restarted = price_holder(core, &fields_at(3.0)).await;
    assert_eq!(earned(restarted, FLAT_LANE, EARNED_A), 4_000_000_000);
    assert_eq!(
        earned(restarted, FLAT_LANE, 86_400_000 + EARNED_B),
        3_000_000_000
    );
    assert_eq!(restarted.len(), 2);
    let entry = restarted.history().unwrap();
    let current = entry.current();
    let amended = current.entry_at(EARNED_A).unwrap();
    assert_eq!(amended.effective_until(), Some(86_400_000));
    assert_eq!(
        amended.card().digest(),
        live.current().entry_at(EARNED_A).unwrap().card().digest()
    );
}
#[cfg(feature = "root-admin")]
#[test]
fn a_restore_whose_prefix_lacks_the_corrections_base_refuses_it() {
    let (history, correction, _) = keyed_correction_fixture();
    assert!(matches!(
        correction.rebuild_over(
            &history,
            super::CorrectionBase::Key {
                key: busbar_kernel_ledger::cost::EntryKey::new(999, [8; 8], 0),
                card_digest: [0; 32]
            }
        ),
        Err(super::BaseMismatch::MissingBase)
    ));
}
#[cfg(feature = "root-admin")]
#[test]
fn a_restore_whose_base_digest_differs_refuses_the_correction() {
    let (history, correction, key) = keyed_correction_fixture();
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
}
#[cfg(feature = "root-admin")]
#[test]
fn a_restore_over_the_sealed_base_rebuilds_the_identical_card() {
    let (history, correction, key) = keyed_correction_fixture();
    let (base, draft) = correction.draft_over(history.current()).unwrap();
    assert_eq!(
        correction
            .rebuild_over(&history, base)
            .unwrap()
            .card
            .digest(),
        draft.card.digest()
    );
    assert_eq!(history.entry(&key).unwrap().key(), key);
}
#[test]
fn applying_rates_registers_the_classes_a_unit_may_report() {
    let fees = plane_fees();
    let lanes = lanes_at(1.0);
    let _ = RootHistory::default().apply_rates(
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

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_back_dated_correction_survives_a_restart_over_the_store() {
    native_correction_restart().await;
}
#[tokio::test]
async fn a_stored_chain_that_does_not_verify_never_disarms_the_card_journal() {
    let (core, faults) = native_price_backend().await;
    let holder = price_holder(core.clone(), &fields_at(3.0)).await;
    assert_eq!(holder.len(), 1);
    faults
        .corrupt_read
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let restarted = RootHistory::default();
    restarted.keep_in_store(core, 7).unwrap();
    restarted.card_applied(&fields_at(3.0), "restart");
    assert!(
        restarted.boot_in_store(None).await.is_err(),
        "malformed canonical price facts must refuse boot"
    );
    assert!(restarted.keeps_store());
    assert!(
        restarted.card_store().is_none(),
        "unverified canonical history is not published"
    );
}
#[tokio::test]
async fn store_card_history_ignores_absent_and_unusable_data_directories_without_writing_files() {
    let scratch = std::path::PathBuf::from("/Users/matthew/Developer/tmp/corefix-implementation")
        .join(format!(
            "native-price-files-{}",
            busbar_kernel::door::op_id().counter()
        ));
    std::fs::create_dir(&scratch).unwrap();
    let blocked = scratch.join("a-file-not-a-directory");
    std::fs::write(&blocked, b"unchanged fixture").unwrap();
    let core = crate::root::real_store::core().await;
    for _ in 0..2 {
        let holder = price_holder(core.clone(), &fields_at(3.0)).await;
        holder
            .card_store()
            .unwrap()
            .prepare(&fields_at(5.0), "configuration change")
            .await
            .unwrap()
            .confirm_activation()
            .await
            .unwrap()
            .commit();
        assert_eq!(std::fs::read(&blocked).unwrap(), b"unchanged fixture");
        assert_eq!(
            std::fs::read_dir(&scratch).unwrap().count(),
            1,
            "canonical price persistence creates no local files"
        );
    }
    std::fs::remove_dir_all(scratch).unwrap();
}
#[cfg(feature = "root-admin")]
#[tokio::test]
async fn a_store_amendment_keeps_its_pinned_base_and_calls_the_store_outside_the_global_money_lock()
{
    let (core, faults) = native_price_backend().await;
    let boot = fields_at(3.0);
    let holder = price_holder(core, &boot).await;
    let store = holder.card_store().unwrap();
    let base = store.own().unwrap().0;
    let mut changed = boot.clone();
    changed.per_request_fee = 5;
    let confirmed = store
        .prepare(&changed, "configuration changes during seal")
        .await
        .unwrap()
        .confirm_activation()
        .await
        .unwrap();
    *faults.on_commit.lock().unwrap() = Some(Box::new(move || {
        assert!(
            holder.applying.try_lock().is_ok(),
            "no global money lock crosses native persistence"
        )
    }));
    holder
        .amend_by(
            &super::Correction {
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
                assert!(holder.applying.try_lock().is_ok());
                confirmed.commit();
                Ok::<(), ()>(())
            },
        )
        .await
        .unwrap();
    let amendment = store
        .entries()
        .into_iter()
        .find(|entry| {
            matches!(
                entry.author,
                busbar_kernel::governance::persistence::prices::EntryAuthor::Amend { .. }
            )
        })
        .unwrap();
    assert_eq!(amendment.base, Some(base));
    assert_eq!(amendment.card.per_request_fee, 7);
    assert_eq!(store.own().unwrap().1, changed);
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

struct NativePriceFaults {
    inner: Arc<dyn busbar_contract::persistence::PersistenceBackend>,
    refuse: std::sync::atomic::AtomicBool,
    unknown_after: std::sync::atomic::AtomicBool,
    corrupt_read: std::sync::atomic::AtomicBool,
    on_commit: Mutex<Option<Box<dyn FnOnce() + Send>>>,
}
impl busbar_contract::persistence::PersistenceBackend for NativePriceFaults {
    fn info(&self) -> busbar_contract::persistence::BackendInfo {
        self.inner.info()
    }
    fn read(
        &self,
        request: Arc<busbar_contract::persistence::Read>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult> {
        Box::pin(async move {
            let corrupt = self.corrupt_read.load(std::sync::atomic::Ordering::SeqCst);
            let indexes: Vec<_> = request
                .addresses
                .iter()
                .enumerate()
                .filter(|(_, a)| {
                    a.namespace == busbar_kernel::governance::persistence::prices::PRICES.0
                        && a.key.first() == Some(&b'E')
                })
                .map(|(i, _)| i)
                .collect();
            let mut result = self.inner.read(request).await?;
            if corrupt {
                if let busbar_contract::persistence::ReadResult::Values { values, .. } = &mut result
                {
                    for i in indexes {
                        if values[i].is_some() {
                            values[i] = Some(busbar_contract::Secret::new(
                                b"malformed native price entry".to_vec(),
                            ));
                        }
                    }
                }
            }
            Ok(result)
        })
    }
    fn scan(
        &self,
        request: Arc<busbar_contract::persistence::Scan>,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
        Box::pin(async move {
            let mut page = self.inner.scan(request).await?;
            if self.corrupt_read.load(std::sync::atomic::Ordering::SeqCst) {
                for (address, value) in &mut page.rows {
                    if address.namespace == busbar_kernel::governance::persistence::prices::PRICES.0
                        && address.key.first() == Some(&b'E')
                    {
                        *value =
                            busbar_contract::Secret::new(b"malformed native price entry".to_vec());
                    }
                }
            }
            Ok(page)
        })
    }
    fn clock(
        &self,
        dataset: busbar_contract::persistence::DatasetId,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
    {
        self.inner.clock(dataset)
    }
    fn commit(
        &self,
        candidate: busbar_contract::persistence::PreparedCandidate,
    ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision> {
        Box::pin(async move {
            let price = candidate.candidate().mutations.iter().any(|m| matches!(m, busbar_contract::persistence::Mutation::Put {address,..} if address.namespace == busbar_kernel::governance::persistence::prices::PRICES.0));
            if price {
                let callback = self.on_commit.lock().unwrap().take();
                if let Some(callback) = callback {
                    callback();
                }
                if self.refuse.load(std::sync::atomic::Ordering::SeqCst) {
                    return Err(busbar_contract::persistence::Failure::Refused);
                }
            }
            let result = self.inner.commit(candidate).await;
            if price
                && result.is_ok()
                && self
                    .unknown_after
                    .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(busbar_contract::persistence::Failure::Unknown);
            }
            result
        })
    }
}
async fn native_price_backend() -> (
    Arc<busbar_kernel::persistence::facade::CoreStore>,
    Arc<NativePriceFaults>,
) {
    let backend = Arc::new(NativePriceFaults {
        inner: crate::root::real_store::native_backend().await,
        refuse: false.into(),
        unknown_after: false.into(),
        corrupt_read: false.into(),
        on_commit: Mutex::new(None),
    });
    (
        crate::root::real_store::core_over(backend.clone()).await,
        backend,
    )
}
