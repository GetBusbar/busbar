// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `durability/amend.rs`: the node amendment journal survives a restart.
//!
//! A restart is proven with two real processes over one data directory, as a node restarts: the
//! parent test runs this same test binary twice, filtered to itself — first to seal a content access
//! on the booted node's journal, then, in a fresh process, to read it back off the one its boot
//! rebuilt. Each phase boots through [`crate::root::boot::book`] itself, over an `App` whose
//! governance owns the journal (item 404: an instance the node owns, never a process static).

use super::*;
use busbar_kernel::audit::amend::{NodeAmendments, Reader};

/// Which half of the restart the child process runs, and where.
const PHASE: &str = "BUSBAR_TEST_AMEND_RESTART_PHASE";
const DIR: &str = "BUSBAR_TEST_AMEND_RESTART_DIR";

/// The hooks that read content.
const HOOK: &str = "compressor";
const LATE_HOOK: &str = "summarizer";

/// A hook named `hook` was handed one unit's content: one access on the journal `app` carries,
/// recorded by the node's host as a served unit's is.
fn access(app: &Arc<busbar_kernel::state::App>, hook: &str) {
    busbar_kernel::plane_driver::engine_host(app).hook_read(
        hook,
        Some("pseudonym-1"),
        "chat",
        false,
    );
}

/// The hooks `journal` holds an access of, oldest first.
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

/// THE NODE'S BOOT, BY THE BOOT'S OWN FUNCTION: an `App` whose governance holds the stand-in
/// store's record slots, then [`crate::root::boot::book`] over it — which rebuilds the App's own
/// amendment journal from the chain and binds it to the book. The data directory is
/// `BUSBAR_DATA_DIR`, which [`run_phase`] sets for the child process to `dir`. Answers the book and
/// the booted App, whose `amendments` is the journal every phase seals on and reads back.
fn boot(dir: &std::path::Path) -> (Arc<Mutex<Durability>>, Arc<busbar_kernel::state::App>) {
    assert_eq!(
        busbar_kernel::preflight::fleet_data_dir().as_deref(),
        Some(dir),
        "the child process boots over the directory its phase names"
    );
    let gov = Arc::new(
        busbar_kernel::governance::GovState::new(
            Arc::new(busbar_kernel::governance::MemoryStore::new()),
            None,
        )
        .expect("a governance over the memory store"),
    );
    gov.attach_store_calls(crate::root::store_double::RecordSlots::new().calls());
    let app = busbar_kernel::test_support::TestApp::new()
        .governance(gov)
        .build();
    let book = crate::root::boot::book(&app, "test-store").expect("the boot book opens");
    (book.durability, app)
}

/// In a child process [`run_phase`] started: run its phase and answer `true`. In the test's own
/// process: `false`, and the test goes on to start its phases.
fn child_phase() -> bool {
    let (Ok(phase), Ok(dir)) = (std::env::var(PHASE), std::env::var(DIR)) else {
        return false;
    };
    restart_phase(&phase, &dir);
    true
}

/// ONE HALF OF THE RESTART, run in a child process of the test that names it.
fn restart_phase(phase: &str, dir: &str) {
    if phase == "store" {
        store_phase();
        return;
    }
    let (book, app) = boot(std::path::Path::new(dir));
    // The journal the boot rebuilt and bound: the one the booted App carries.
    let journal = Arc::clone(&app.amendments);
    match phase {
        "seal" => access(&app, HOOK),
        "read" => {
            let durability = book.lock().unwrap_or_else(|p| p.into_inner());
            assert!(
                durability.restart_findings.is_empty(),
                "{:?}",
                durability.restart_findings
            );
            assert_eq!(
                accessed(&journal),
                vec![HOOK.to_string()],
                "the content access survived the restart"
            );
        }
        // U15: the on-demand verify sees an edit to the HELD amendment run. One access is sealed
        // and `/verify` reports nothing; the held run is then edited in place, and `/verify` names
        // the amendment chain.
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

/// The node the store-kept chain is written under in the `store` phase.
const STORE_NODE: u64 = 31;

/// How long one padding record's body is: big enough that a few hundred of them roll the memory
/// log past one segment, small enough that 256 of them (one block of the store's scan) stay inside
/// one scan.
const PAD_BODY: usize = 100_000;

/// The node's boot with NO DATA DIRECTORY over the configured store, as `root::boot` runs it: build
/// over the store (resuming the chain it kept), rebuild the node amendment journal `journal`, share
/// the book, bind it.
fn store_boot(
    slots: &crate::root::store_double::RecordSlots,
    journal: &NodeAmendments,
) -> Arc<Mutex<Durability>> {
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    let mut durability =
        build_on_store(&DurabilityConfig { data_dir: None }, STORE_NODE, lane, None)
            .expect("the store reads back");
    let token = busbar_kernel::test_support::tokens::grant::<DurableWrite>();
    durability
        .restore_amendments(journal, &token)
        .expect("the chain reads back");
    let book = Arc::new(Mutex::new(durability));
    bind_amendments(&book, journal);
    book
}

/// Wait until the store took everything the book's lane holds.
fn store_drained(book: &Arc<Mutex<Durability>>) {
    let durability = book.lock().unwrap_or_else(|p| p.into_inner());
    assert!(
        durability
            .lane()
            .expect("a book over the store")
            .drain(std::time::Duration::from_secs(120)),
        "the store takes the journal's records"
    );
}

/// THE `store` PHASE (audit R1#1): a node with no data directory whose chain outgrows one memory
/// segment. The first boot seals an access, pads the journal past one segment, seals a second
/// access, and stops; the second boot over the same store must see both, with no restart finding.
fn store_phase() {
    let slots = crate::root::store_double::RecordSlots::new();
    let token = busbar_kernel::test_support::tokens::grant::<DurableWrite>();
    {
        let app = busbar_kernel::test_support::TestApp::new().build();
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

    // The restarted node's journal starts empty: what it holds is what the boot rebuilt.
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

/// A NODE WITH NO DATA DIRECTORY WHOSE CHAIN OUTGREW ONE MEMORY SEGMENT keeps its amendments across a
/// restart (audit R1#1). The memory log keeps only its newest segment resident; the store keeps the
/// rest, and every chain read after boot reads the whole of it. See the `store` phase.
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

/// Run `phase` in a fresh process of this test binary: the test `test` again, which runs the phase
/// ([`child_phase`]).
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

/// U15: `GET /admin/verify` VERIFIES THE HELD AMENDMENT RUN ON DEMAND. See the `tamper` phase.
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

/// A CONTENT ACCESS SURVIVES A RESTART. The first process boots through `root::boot::book` and seals
/// a hook's content access on its App's journal; the second boots the same way over the same data
/// directory and finds it on the journal its own boot rebuilt. With the
/// amendments held in memory only, the second process found no access.
#[test]
fn a_content_access_survives_a_restart() {
    if child_phase() {
        return;
    }
    let dir = crate::root::durability::Scratch::new("amend-restart");
    let test = "a_content_access_survives_a_restart";
    run_phase(test, "seal", &dir.0);
    run_phase(test, "read", &dir.0);
}

/// A NODE WITH NO DATA DIRECTORY rebuilds nothing, so it binds nothing: the node journal stays
/// memory-only, the previous release's shape, and no amendment reaches its memory-buffered journal.
#[test]
fn without_a_data_dir_the_amendment_journal_is_neither_rebuilt_nor_bound() {
    let mut durability = build_with_cards(
        &DurabilityConfig { data_dir: None },
        0,
        Box::new(busbar_kernel_wal::NullShipper::new()),
        None,
    )
    .expect("a memory-buffered journal cannot fail to open");
    let journal = NodeAmendments::new();
    let token = busbar_kernel::test_support::tokens::grant::<DurableWrite>();
    durability
        .restore_amendments(&journal, &token)
        .expect("nothing is read back");
    assert_eq!(durability.amendments_through, None);
    assert!(durability.restart_findings.is_empty());
}
