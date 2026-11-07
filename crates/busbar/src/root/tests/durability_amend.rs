// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::audit::amend::{NodeAmendments, Reader};
use busbar_kernel::persistence::{
    facade::CoreStore,
    journal::runtime::{BufferBudget, RuntimeJournal},
};

const PHASE: &str = "BUSBAR_TEST_AMEND_RESTART_PHASE";
const DIR: &str = "BUSBAR_TEST_AMEND_RESTART_DIR";

const HOOK: &str = "compressor";
const LATE_HOOK: &str = "summarizer";

#[tokio::test]
async fn malformed_amendments_are_counted_without_changing_the_accepted_run() {
    let core = crate::root::real_store::core().await;
    let book = native_book(core, 7).await;
    let mut chain = amend::AmendChain::default();
    let valid = chain.append(
        amend::content_access(
            Reader::Hook,
            "kept",
            busbar_kernel_audit::Subject::PrincipalId("principal".to_string()),
            OpClassId::new("chat"),
            Vec::new(),
            1,
        ),
        &busbar_kernel::teller::verb_audit_pass(&crate::root::kernel::new_kernel()),
    );
    let mut truncated = BodyWriter::new();
    truncated.text(AMENDMENT);
    let unrelated = Entry::new(RecordClass::Load, Vec::new());
    let malformed = Entry::new(RecordClass::Access, truncated.finish());
    let wrong_class = Entry::new(RecordClass::Load, body(&valid));
    let staged = book
        .stage_entries(&[unrelated, entry(&valid), malformed, wrong_class])
        .expect("records staged");
    book.journal
        .confirm(&staged)
        .await
        .expect("records journalled");
    let records = book
        .chain()
        .await
        .expect("read chain")
        .expect("verified journal");
    let (run, set_aside) = linked_run(&records);
    assert_eq!(run, vec![valid]);
    assert_eq!(
        set_aside, 2,
        "both recognized malformed amendment records are reported"
    );
}

async fn access(app: &Arc<busbar_kernel::state::App>, hook: &str) {
    busbar_kernel::plane_driver::engine_host(app)
        .hook_read(hook, Some("pseudonym-1"), "chat", false)
        .await
        .expect("content access is durably recorded");
}

fn accessed(journal: &NodeAmendments) -> Vec<String> {
    journal
        .recent()
        .into_iter()
        .filter_map(|a| match a.body {
            AmendBody::Access(x) if x.reader == Reader::Hook => Some(x.name),
            _ => None,
        })
        .collect()
}

async fn application(core: Arc<CoreStore>) -> Arc<busbar_kernel::state::App> {
    crate::dist_root_install::install();
    let path = crate::root::test_plugins::application_store_library();
    let statement = crate::root::loader::dispatch::rendering_of_library(&path)
        .expect("the product store statement reads")
        .expect("the product store exports its statement");
    let module = busbar_contract::abi::mechanism::rendering::read(&statement)
        .expect("the product store statement is valid")
        .name;
    let mut manifest = crate::root::test_plugins::manifest(
        "store",
        &module,
        crate::root::test_plugins::FIXTURE_PUBLISHER,
    );
    manifest.statement = Some(hex::encode(statement));
    let library = std::fs::read(path).expect("the product store library reads");
    let directory = crate::root::durability::Scratch::new("amend-app-plugins");
    let archive = crate::root::test_plugins::signed(
        &crate::dist_root_install::release_key(),
        manifest,
        &library,
    );
    std::fs::write(directory.0.join("store.tar.gz"), archive)
        .expect("the actual store archive is staged");
    let settings = crate::root::test_plugins::application_store_settings(&directory.0);
    let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
        "providers": {},
        "models": {},
        "auth": { "chain": [], "admin_auth": [] },
        "store": { "module": module, "settings": settings },
        "advanced": { "allow_destinations": ["127.0.0.1"] },
    }))
    .expect("the amendment deployment parses");
    let config = busbar_kernel::config::resolve(&deploy, &Default::default())
        .expect("the amendment deployment resolves");
    let plugins = crate::root::test_plugins::trusted_config(&directory.0);
    let rules = Arc::new(crate::root::door_steps::Rules::default())
        as Arc<dyn busbar_kernel::appbuild::RootRules>;
    let (app, rotate, limits) = busbar_kernel::appbuild::build_app_from_config_with_store(
        config,
        plugins,
        None,
        Default::default(),
        Default::default(),
        (None, None),
        None,
        &rules,
        Some(core.clone()),
        false,
    )
    .await
    .expect("the product builds the amendment deployment over its actual store");
    limits.stage_boot();
    crate::root::kernel::ROOT_CARD
        .keep_in_store(core, STORE_NODE)
        .expect("native price authority");
    crate::root::kernel::ROOT_CARD
        .boot_in_store(None)
        .await
        .expect("the amendment Store boots its rate-card history");
    limits.keep().await.expect("the product limits commit");
    if let Some(rotate) = rotate {
        rotate.await;
    }
    Arc::new(app)
}

fn budget() -> BufferBudget {
    BufferBudget {
        records: 65_536,
        bytes: 256 * 1024 * 1024,
    }
}

async fn native_book(core: Arc<CoreStore>, node: u64) -> Durability {
    let journal = RuntimeJournal::open(core, node, budget())
        .await
        .expect("native journal opens");
    build_on_store(
        &DurabilityConfig { data_dir: None },
        node,
        journal,
        None,
        budget(),
    )
    .await
    .expect("the native journal reads back")
}

async fn boot(
    core: Arc<CoreStore>,
    dir: &std::path::Path,
) -> (Arc<Mutex<Durability>>, Arc<busbar_kernel::state::App>) {
    assert_eq!(
        busbar_kernel::preflight::fleet_data_dir().as_deref(),
        Some(dir),
        "the child process boots over the directory its phase names"
    );
    let app = application(core.clone()).await;
    let book = store_boot(core, &app.amendments).await;
    (book, app)
}

async fn child_phase() -> bool {
    let (Ok(phase), Ok(dir)) = (std::env::var(PHASE), std::env::var(DIR)) else {
        return false;
    };
    restart_phase(&phase, &dir).await;
    true
}

async fn restart_phase(phase: &str, dir: &str) {
    if phase == "store" {
        store_phase().await;
        return;
    }
    let core = crate::root::real_store::core().await;
    let (book, app) = boot(core.clone(), std::path::Path::new(dir)).await;

    let journal = Arc::clone(&app.amendments);
    match phase {
        "restart" => {
            access(&app, HOOK).await;
            store_drained(&book).await;
            let mut next_app = (*app).clone();
            next_app.amendments = Arc::new(NodeAmendments::new());
            drop(journal);
            drop(app);
            drop(book);
            let app = Arc::new(next_app);
            let restarted = store_boot(core, &app.amendments).await;
            let durability = restarted.lock().unwrap_or_else(|p| p.into_inner());
            assert!(
                durability.restart_findings.is_empty(),
                "{:?}",
                durability.restart_findings
            );
            assert_eq!(
                accessed(&app.amendments),
                vec![HOOK.to_string()],
                "the content access survived the restart through Store records"
            );
            assert_eq!(
                std::fs::read_dir(dir).unwrap().count(),
                0,
                "boot created local state"
            );
            return;
        }

        #[cfg(feature = "root-admin")]
        "tamper" => {
            access(&app, HOOK).await;
            let findings = |answer: crate::root::units_admin::AdminAnswer| -> String {
                String::from_utf8(answer.body).expect("utf-8")
            };
            let clean = crate::root::units_admin::bound::verify_effect(
                &crate::root::units_admin::UnopenedLedger,
                None,
                Some(&journal),
            )
            .await
            .expect("verify answers");
            let clean = findings(clean);
            assert!(!clean.contains("amendment chain"), "{clean}");
            journal.tamper_for_test();
            let tampered = findings(
                crate::root::units_admin::bound::verify_effect(
                    &crate::root::units_admin::UnopenedLedger,
                    None,
                    Some(&journal),
                )
                .await
                .expect("verify answers"),
            );
            assert!(
                tampered.contains("amendment chain") && tampered.contains(r#""ok":false"#),
                "an edit to the held amendment run must be a /verify finding: {tampered}"
            );
        }
        other => panic!("unknown phase {other}"),
    }
    drop(book);
}

const STORE_NODE: u64 = 31;

const PAD_BODY: usize = 100_000;

async fn store_boot(core: Arc<CoreStore>, journal: &NodeAmendments) -> Arc<Mutex<Durability>> {
    let mut durability = native_book(core, STORE_NODE).await;
    let token = crate::root::kernel::new_kernel().durability_token();
    durability
        .restore_amendments(journal, &token)
        .await
        .expect("the chain reads back");
    let book = Arc::new(Mutex::new(durability));
    bind_amendments(&book, journal)
        .await
        .expect("native amendment sink binds");
    book
}

async fn store_drained(book: &Arc<Mutex<Durability>>) {
    let journal = book
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .runtime_journal();
    journal
        .flush()
        .await
        .expect("the store takes the journal's records");
    assert_eq!(journal.pending_records(), 0);
}

async fn store_phase() {
    let core = crate::root::real_store::core().await;
    {
        let app = application(core.clone()).await;
        let book = store_boot(core.clone(), &app.amendments).await;
        access(&app, HOOK).await;
        let pads = usize::try_from(busbar_kernel_wal::SEGMENT_BYTES).expect("fits") / PAD_BODY + 1;
        let runtime = book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .runtime_journal();
        for _ in 0..pads {
            let staged = runtime
                .stage_run(&[
                    Entry::new(RecordClass::Load, vec![0x5a; PAD_BODY]).at(1_700_000_000, 0)
                ])
                .expect("padding staged");
            runtime.confirm(&staged).await.expect("padding persisted");
        }
        access(&app, LATE_HOOK).await;
        store_drained(&book).await;
        let records = runtime
            .read_records(budget())
            .await
            .expect("complete native history");
        let bytes: usize = records.iter().map(|record| record.body.len()).sum();
        assert!(
            bytes > busbar_kernel_wal::SEGMENT_BYTES as usize,
            "native history exceeds the old memory-segment boundary"
        );
    }

    let journal = NodeAmendments::new();
    let restarted = store_boot(core, &journal).await;
    let durability = restarted.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(
        accessed(&journal),
        vec![HOOK.to_string(), LATE_HOOK.to_string()],
        "the accesses sealed before and after the roll survived the restart"
    );
    assert!(
        durability.restart_findings.is_empty(),
        "{:?}",
        durability.restart_findings
    );
}

#[tokio::test]
async fn a_chain_past_one_memory_segment_keeps_its_amendments_over_the_store() {
    if child_phase().await {
        return;
    }
    let dir = crate::root::durability::Scratch::new("amend-store");
    run_phase(
        "a_chain_past_one_memory_segment_keeps_its_amendments_over_the_store",
        "store",
        &dir.0,
    );
}

fn run_phase(test: &str, phase: &str, dir: &std::path::Path) {
    let out = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args([
            "--exact",
            &format!("root::durability::amend::tests::{test}"),
        ])
        .args(["--test-threads", "1", "--nocapture"])
        .env(PHASE, phase)
        .env(DIR, dir)
        .env("BUSBAR_DATA_DIR", dir)
        .output()
        .expect("the test binary runs");
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "the {phase} phase failed:\n{text}");
    assert!(
        text.contains("1 passed"),
        "the {phase} phase ran nothing:\n{text}"
    );
}

#[cfg(feature = "root-admin")]
#[tokio::test]
async fn verify_reports_an_edit_to_the_held_amendment_run() {
    if child_phase().await {
        return;
    }
    let dir = crate::root::durability::Scratch::new("amend-verify");
    run_phase(
        "verify_reports_an_edit_to_the_held_amendment_run",
        "tamper",
        &dir.0,
    );
}

#[tokio::test]
async fn a_content_access_survives_a_restart() {
    if child_phase().await {
        return;
    }
    let dir = crate::root::durability::Scratch::new("amend-restart");
    let test = "a_content_access_survives_a_restart";
    run_phase(test, "restart", &dir.0);
}

#[tokio::test]
async fn without_a_store_the_amendment_journal_is_neither_rebuilt_nor_bound() {
    let journal = NodeAmendments::new();
    let token = crate::root::kernel::new_kernel().durability_token();
    journal
        .bind(None, 0, &token)
        .await
        .expect("no sink is bound");
    assert!(
        journal.recent().is_empty(),
        "no history is invented without a Store"
    );
    journal
        .verify()
        .expect("the untouched empty amendment chain verifies");
}
