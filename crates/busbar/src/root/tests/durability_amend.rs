// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::audit::amend::{NodeAmendments, Reader};

const PHASE: &str = "BUSBAR_TEST_AMEND_RESTART_PHASE";
const DIR: &str = "BUSBAR_TEST_AMEND_RESTART_DIR";

const HOOK: &str = "compressor";
const LATE_HOOK: &str = "summarizer";

#[test]
fn malformed_amendments_are_counted_without_changing_the_accepted_run() {
    let scratch = crate::root::durability::audit::tests::Scratch::new("amend-decode");
    let mut book = build_for_node(
        &DurabilityConfig {
            data_dir: Some(scratch.0.clone()),
        },
        7,
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .unwrap();
    let token = busbar_kernel_testkit::test_support::tokens::grant::<DurableWrite>();
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
        &busbar_kernel_testkit::test_support::tokens::pass(),
    );
    let mut truncated = BodyWriter::new();
    truncated.text(AMENDMENT);
    let unrelated = Entry::new(RecordClass::Load, Vec::new());
    let malformed = Entry::new(RecordClass::Access, truncated.finish());
    let wrong_class = Entry::new(RecordClass::Load, body(&valid));
    book.journal
        .append(
            &token,
            StepName::Audit,
            &[unrelated, entry(&valid), malformed, wrong_class],
        )
        .expect("records journalled");
    let records = book.chain().expect("read chain").expect("verified journal");
    let (run, set_aside) = linked_run(&records);
    assert_eq!(run, vec![valid]);
    assert_eq!(
        set_aside, 2,
        "both recognized malformed amendment records are reported"
    );
}

fn access(app: &Arc<busbar_kernel::state::App>, hook: &str) {
    busbar_kernel::plane_driver::engine_host(app).hook_read(
        hook,
        Some("pseudonym-1"),
        "chat",
        false,
    );
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

fn boot(
    slots: &crate::root::store_double::RecordSlots,
    dir: &std::path::Path,
) -> (Arc<Mutex<Durability>>, Arc<busbar_kernel::state::App>) {
    assert_eq!(
        busbar_kernel::preflight::fleet_data_dir().as_deref(),
        Some(dir),
        "the child process boots over the directory its phase names"
    );
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new(
            Arc::new(busbar_kernel_testkit::test_support::store_double::MemoryStore::new()),
            None,
        )
        .expect("a governance over the memory store"),
    );
    gov.attach_store_calls(slots.calls());
    let app = busbar_kernel_testkit::test_support::TestApp::new()
        .governance(gov)
        .build();
    let book = crate::root::boot::book(&app, "test-store").expect("the boot book opens");
    (book.durability, app)
}

fn child_phase() -> bool {
    let (Ok(phase), Ok(dir)) = (std::env::var(PHASE), std::env::var(DIR)) else {
        return false;
    };
    restart_phase(&phase, &dir);
    true
}

fn restart_phase(phase: &str, dir: &str) {
    if phase == "store" {
        store_phase();
        return;
    }
    let slots = crate::root::store_double::RecordSlots::new();
    let (book, app) = boot(&slots, std::path::Path::new(dir));

    let journal = Arc::clone(&app.amendments);
    match phase {
        "restart" => {
            access(&app, HOOK);
            store_drained(&book);
            let lane = book
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .lane()
                .unwrap()
                .clone();
            lane.release_held_lease();
            drop(lane);
            drop(journal);
            drop(app);
            drop(book);
            let (restarted, app) = boot(&slots, std::path::Path::new(dir));
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
            access(&app, HOOK);
            let findings = |answer: crate::root::units_admin::AdminAnswer| -> String {
                String::from_utf8(answer.body).expect("utf-8")
            };
            let clean = crate::root::units_admin::bound::verify_effect(
                &crate::root::units_admin::UnopenedLedger,
                None,
                Some(&journal),
            )
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

fn store_boot(
    slots: &crate::root::store_double::RecordSlots,
    journal: &NodeAmendments,
) -> Arc<Mutex<Durability>> {
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    let mut durability =
        build_on_store(&DurabilityConfig { data_dir: None }, STORE_NODE, lane, None)
            .expect("the store reads back");
    let token = busbar_kernel_testkit::test_support::tokens::grant::<DurableWrite>();
    durability
        .restore_amendments(journal, &token)
        .expect("the chain reads back");
    let book = Arc::new(Mutex::new(durability));
    bind_amendments(&book, journal);
    book
}

fn store_drained(book: &Arc<Mutex<Durability>>) {
    let lane = book
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .lane()
        .expect("Store lane")
        .clone();
    assert!(
        lane.drain(std::time::Duration::from_secs(120)),
        "the store takes the journal's records"
    );
}

fn store_phase() {
    let slots = crate::root::store_double::RecordSlots::new();
    let token = busbar_kernel_testkit::test_support::tokens::grant::<DurableWrite>();
    {
        let app = busbar_kernel_testkit::test_support::TestApp::new().build();
        let book = store_boot(&slots, &app.amendments);
        access(&app, HOOK);
        let pads = usize::try_from(busbar_kernel_wal::SEGMENT_BYTES).expect("fits") / PAD_BODY + 1;
        for _ in 0..pads {
            book.lock()
                .unwrap_or_else(|p| p.into_inner())
                .journal
                .append(
                    &token,
                    StepName::Meter,
                    &[Entry::new(RecordClass::Load, vec![0x5a; PAD_BODY]).at(1_700_000_000, 0)],
                )
                .expect("the padding goes on the chain");
        }
        access(&app, LATE_HOOK);
        store_drained(&book);
        assert!(
            book.lock()
                .unwrap_or_else(|p| p.into_inner())
                .journal
                .log()
                .segments_used()
                >= 2,
            "the memory journal rolled past one segment"
        );
    }

    let journal = NodeAmendments::new();
    let restarted = store_boot(&slots, &journal);
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

#[test]
fn a_chain_past_one_memory_segment_keeps_its_amendments_over_the_store() {
    if child_phase() {
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
#[test]
fn verify_reports_an_edit_to_the_held_amendment_run() {
    if child_phase() {
        return;
    }
    let dir = crate::root::durability::Scratch::new("amend-verify");
    run_phase(
        "verify_reports_an_edit_to_the_held_amendment_run",
        "tamper",
        &dir.0,
    );
}

#[test]
fn a_content_access_survives_a_restart() {
    if child_phase() {
        return;
    }
    let dir = crate::root::durability::Scratch::new("amend-restart");
    let test = "a_content_access_survives_a_restart";
    run_phase(test, "restart", &dir.0);
}

#[test]
fn without_a_store_the_amendment_journal_is_neither_rebuilt_nor_bound() {
    let mut durability = build_with_cards(
        &DurabilityConfig { data_dir: None },
        0,
        Box::new(busbar_kernel_wal::NullShipper::new()),
        None,
    )
    .expect("a memory-buffered journal cannot fail to open");
    let journal = NodeAmendments::new();
    let token = busbar_kernel_testkit::test_support::tokens::grant::<DurableWrite>();
    durability
        .restore_amendments(&journal, &token)
        .expect("nothing is read back");
    assert_eq!(durability.amendments_through, None);
    assert!(durability.restart_findings.is_empty());
}
