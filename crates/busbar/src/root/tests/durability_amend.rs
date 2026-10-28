// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `durability/amend.rs`: the node amendment journal survives a restart.
//!
//! The node journal is ONE per process, so a restart is proven with two real processes rather than
//! by resetting it under the other tests of this binary: the parent test runs this same test binary
//! twice over one data directory, filtered to [`restart_phase`] — first to seal content accesses,
//! then, in a fresh process whose node journal starts empty, to read them back.

use super::*;
use busbar_kernel::audit::amend::{node_recent, Reader};

/// Which half of the restart the child process runs, and where.
const PHASE: &str = "BUSBAR_TEST_AMEND_RESTART_PHASE";
const DIR: &str = "BUSBAR_TEST_AMEND_RESTART_DIR";

/// The hooks that read content.
const HOOK: &str = "compressor";
const LATE_HOOK: &str = "summarizer";

/// A hook named `hook` was handed one unit's content: one access on the node journal.
fn access(hook: &str) {
    let app = busbar_kernel::test_support::TestApp::new().build();
    busbar_kernel::plane_driver::engine_host(&app).hook_read(
        hook,
        Some("pseudonym-1"),
        "chat",
        false,
    );
}

/// The hooks the node journal holds an access of, oldest first.
fn accessed() -> Vec<String> {
    node_recent()
        .into_iter()
        .filter_map(|a| match a.body {
            AmendBody::Access(x) if x.reader == Reader::Hook => Some(x.name),
            _ => None,
        })
        .collect()
}

/// The node's boot, as `root::boot::compose_book` and `root::boot::book` run it: build over the data
/// directory, rebuild the node amendment journal, share the book, bind it.
fn boot(dir: &std::path::Path) -> Arc<Mutex<Durability>> {
    let mut durability = build_for_node(
        &DurabilityConfig {
            data_dir: Some(dir.to_path_buf()),
        },
        4,
        Box::new(busbar_kernel_wal::NullShipper::new()),
    )
    .expect("the directory is writable");
    durability
        .restore_amendments()
        .expect("the chain reads back");
    let book = Arc::new(Mutex::new(durability));
    bind_amendments(&book);
    book
}

/// ONE HALF OF THE RESTART, run only in a child process the restart tests below start
/// ([`run_phase`], `--ignored`). Ignored so the default run never counts it as a pass: alone it
/// proves nothing, and run without its phase it fails (status row 114).
#[test]
#[ignore = "child process of the restart tests: run_phase runs it with --ignored"]
fn restart_phase() {
    let (Ok(phase), Ok(dir)) = (std::env::var(PHASE), std::env::var(DIR)) else {
        panic!("restart_phase is the child half of the restart tests: run them, not this");
    };
    if phase == "store" {
        store_phase();
        return;
    }
    let book = boot(std::path::Path::new(&dir));
    match phase.as_str() {
        "seal" => access(HOOK),
        "read" => {
            let durability = book.lock().unwrap_or_else(|p| p.into_inner());
            assert!(
                durability.restart_findings.is_empty(),
                "{:?}",
                durability.restart_findings
            );
            assert_eq!(
                accessed(),
                vec![HOOK.to_string()],
                "the content access survived the restart"
            );
        }
        // U15: the on-demand verify sees an edit to the HELD amendment run. One access is sealed
        // and `/verify` reports nothing; the held run is then edited in place, and `/verify` names
        // the amendment chain. A process of its own, because the node journal is the process's one.
        #[cfg(feature = "root-admin")]
        "tamper" => {
            access(HOOK);
            let findings = |answer: crate::root::units_admin::AdminAnswer| -> String {
                String::from_utf8(answer.body).expect("utf-8")
            };
            let clean = crate::root::units_admin::bound::verify_effect(
                &crate::root::units_admin::UnopenedLedger,
                None,
            )
            .expect("verify answers");
            let clean = findings(clean);
            assert!(!clean.contains("amendment chain"), "{clean}");
            tamper_node_for_test();
            let tampered = findings(
                crate::root::units_admin::bound::verify_effect(
                    &crate::root::units_admin::UnopenedLedger,
                    None,
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
}

/// The node the store-kept chain is written under in the `store` phase.
const STORE_NODE: u64 = 31;

/// How long one padding record's body is: big enough that a few hundred of them roll the memory
/// log past one segment, small enough that 256 of them (one block of the store's scan) stay inside
/// one scan.
const PAD_BODY: usize = 100_000;

/// The node's boot with NO DATA DIRECTORY over the configured store, as `root::boot` runs it: build
/// over the store (resuming the chain it kept), rebuild the node amendment journal, share the
/// book, bind it.
fn store_boot(slots: &crate::root::store_double::RecordSlots) -> Arc<Mutex<Durability>> {
    let lane = JournalLane::start(slots.calls(), "test-store").expect("the lane starts");
    let mut durability =
        build_on_store(&DurabilityConfig { data_dir: None }, STORE_NODE, lane, None)
            .expect("the store reads back");
    durability
        .restore_amendments()
        .expect("the chain reads back");
    let book = Arc::new(Mutex::new(durability));
    bind_amendments(&book);
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
        let book = store_boot(&slots);
        access(HOOK);
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
        access(LATE_HOOK);
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

    let restarted = store_boot(&slots);
    let durability = restarted.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(
        accessed(),
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
    let dir = crate::root::durability::Scratch::new("amend-store");
    run_phase("store", &dir.0);
}

/// Run [`restart_phase`] in a fresh process of this test binary.
fn run_phase(phase: &str, dir: &std::path::Path) {
    let out = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args(["--exact", "root::durability::amend::tests::restart_phase"])
        .args(["--ignored", "--test-threads", "1", "--nocapture"])
        .env(PHASE, phase)
        .env(DIR, dir)
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
    let dir = crate::root::durability::Scratch::new("amend-verify");
    run_phase("tamper", &dir.0);
}

/// A CONTENT ACCESS SURVIVES A RESTART. The first process seals a hook's content access; the second,
/// whose node journal starts empty, boots over the same data directory and finds it. With the
/// amendments held in memory only, the second process found no access.
#[test]
fn a_content_access_survives_a_restart() {
    let dir = crate::root::durability::Scratch::new("amend-restart");
    run_phase("seal", &dir.0);
    run_phase("read", &dir.0);
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
    durability
        .restore_amendments()
        .expect("nothing is read back");
    assert_eq!(durability.amendments_through, None);
    assert!(durability.restart_findings.is_empty());
}
