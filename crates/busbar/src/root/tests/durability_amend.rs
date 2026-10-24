// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `durability/amend.rs`: the node amendment journal survives a restart.
//!
//! The node journal is ONE per process, so a restart is proven with two real processes rather than
//! by resetting it under the other tests of this binary: the parent test runs this same test binary
//! twice over one data directory, filtered to [`restart_phase`] — first to seal a correction and an
//! access, then, in a fresh process whose node journal starts empty, to read them back.

use super::*;
use busbar_kernel::audit::amend::{
    correct_counts, counts_now, node_recent, CountCorrection, Reader,
};
use busbar_kernel_ledger::cost::{
    nanos_of_exact, whole, Count, LaneClass, RateCard, Tally, STANDARD_TIER_BP,
};

/// Which half of the restart the child process runs, and where.
const PHASE: &str = "BUSBAR_TEST_AMEND_RESTART_PHASE";
const DIR: &str = "BUSBAR_TEST_AMEND_RESTART_DIR";

/// The entry the correction amends, the lane its counts price on, and the hook that reads content.
const ENTRY: &str = "the-entry-a-root-correction-amends";
const LANE_M: &str = "m";
const HOOK: &str = "compressor";
/// A second recorded unit, corrected with a POOL named (Q64/Q67).
const POOLED_ENTRY: &str = "the-entry-a-pooled-correction-amends";

/// 2,500 nano-units per `input` unit on [`LANE_M`].
fn card() -> RateCard {
    RateCard::from_nano_rates([(LaneClass::new(LANE_M, "input"), 2_500)], 0)
}

fn counts(n: u64) -> ClassCounts {
    ClassCounts::from([("input".to_string(), whole(n))])
}

/// What `c` costs on [`LANE_M`] at [`card`], in nano-units, through the one function.
fn priced(c: &ClassCounts) -> u128 {
    let card = card();
    let mut tally = Tally::at_card(&card);
    tally
        .row(
            LANE_M,
            0,
            STANDARD_TIER_BP,
            c.iter().map(|(class, n)| (class.as_str(), *n)),
            Count::ZERO,
        )
        .expect("every class is priced");
    nanos_of_exact(tally.exact().expect("in range")).expect("in range")
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
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
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
    let recorded = counts(1_000);
    match phase.as_str() {
        "seal" => {
            correct_counts(
                busbar_contract::authz::Scope::Full,
                &recorded,
                CountCorrection {
                    amends: ENTRY,
                    principal: Some("pseudonym-1"),
                    lane: LANE_M,
                    card_epoch_ms: 1_700_000_000_000,
                    now: counts(800),
                    authorised_by: "root",
                    reason: "duplicate charge on a retried request",
                    pool: None,
                },
            )
            .expect("a root correction to a non-negative count lands");
            correct_counts(
                busbar_contract::authz::Scope::Full,
                &recorded,
                CountCorrection {
                    amends: POOLED_ENTRY,
                    principal: Some("pseudonym-1"),
                    lane: LANE_M,
                    card_epoch_ms: 1_700_000_000_000,
                    now: counts(800),
                    authorised_by: "root",
                    reason: "duplicate charge on a retried request",
                    pool: Some("pool-a"),
                },
            )
            .expect("a pooled root correction lands");
            let app = busbar_kernel::test_support::TestApp::new().build();
            busbar_kernel::plane_driver::engine_host(&app).hook_read(
                HOOK,
                Some("pseudonym-1"),
                "chat",
                false,
            );
        }
        "read" => {
            let durability = book.lock().unwrap_or_else(|p| p.into_inner());
            assert!(
                durability.restart_findings.is_empty(),
                "{:?}",
                durability.restart_findings
            );
            let now = counts_now(ENTRY, &recorded);
            assert_eq!(now, counts(800), "the correction survived the restart");
            assert_eq!(
                priced(&now),
                2_000_000,
                "and its money with it: 800 x 2,500 nano-units, not the recorded 2,500,000"
            );
            let accesses: Vec<_> = node_recent()
                .into_iter()
                .filter_map(|a| match a.body {
                    AmendBody::Access(x) if x.reader == Reader::Hook && x.name == HOOK => Some(x),
                    _ => None,
                })
                .collect();
            assert_eq!(accesses.len(), 1, "the content access survived the restart");
            // Q64/Q67: the pool rides the journal record; the unscoped one reads back unscoped.
            let pools: Vec<_> = (busbar_kernel::audit::amend::node_corrections().into_iter())
                .filter_map(|a| match a.body {
                    AmendBody::Adjust(x) => Some((x.amends_hash, x.pool)),
                    AmendBody::Access(_) => None,
                })
                .collect();
            assert_eq!(
                pools,
                vec![
                    (ENTRY.to_string(), None),
                    (POOLED_ENTRY.to_string(), Some("pool-a".to_string()))
                ],
                "the pool survived the restart, and the unscoped correction stayed unscoped"
            );
            assert_eq!(accesses[0].fields, vec!["content".to_string()]);
        }
        // U15: the on-demand verify sees an edit to the HELD amendment run. One correction is
        // sealed and `/verify` reports nothing; the held run is then edited in place, and `/verify`
        // names the amendment chain. A process of its own, because the node journal is the
        // process's one journal.
        #[cfg(feature = "root-admin")]
        "tamper" => {
            correct_counts(
                busbar_contract::authz::Scope::Full,
                &recorded,
                CountCorrection {
                    amends: ENTRY,
                    principal: Some("pseudonym-1"),
                    lane: LANE_M,
                    card_epoch_ms: 1_700_000_000_000,
                    now: counts(800),
                    authorised_by: "root",
                    reason: "duplicate charge on a retried request",
                    pool: None,
                },
            )
            .expect("a root correction lands");
            let findings = |answer: crate::root::units_admin::AdminAnswer| -> String {
                String::from_utf8(answer.body).expect("utf-8")
            };
            let clean = crate::root::units_admin::bound::verify_effect(
                &crate::root::units_admin::UnopenedLedger,
            )
            .expect("verify answers");
            let clean = findings(clean);
            assert!(!clean.contains("amendment chain"), "{clean}");
            tamper_node_for_test();
            let tampered = findings(
                crate::root::units_admin::bound::verify_effect(
                    &crate::root::units_admin::UnopenedLedger,
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
    let mut durability = build_on_store(
        &DurabilityConfig { data_dir: None },
        STORE_NODE,
        lane,
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        Box::new(|| None),
        None,
    )
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

/// A root correction of the entry `amends` from 1,000 input units to 800.
fn correct(amends: &str) {
    correct_counts(
        busbar_contract::authz::Scope::Full,
        &counts(1_000),
        CountCorrection {
            amends,
            principal: Some("pseudonym-1"),
            lane: LANE_M,
            card_epoch_ms: 1_700_000_000_000,
            now: counts(800),
            authorised_by: "root",
            reason: "duplicate charge on a retried request",
            pool: None,
        },
    )
    .expect("a root correction to a non-negative count lands");
}

/// THE `store` PHASE (audit R1#1): a node with no data directory whose chain outgrows one memory
/// segment. The first boot seals the migration marker and a correction, pads the journal past one
/// segment, seals a second correction, and stops; the second boot over the same store must see
/// both corrections and the marker, with no restart finding.
fn store_phase() {
    let slots = crate::root::store_double::RecordSlots::new();
    let token = busbar_kernel::test_support::tokens::grant::<DurableWrite>();
    let sealed = MigrationMarker {
        checkpoint_seq: 0,
        node: STORE_NODE,
        sealed_at: 1_700_000_000,
        body_hash: [7u8; 32],
        balances: 3,
        cells_read: 11,
        rate_card_version: 5,
    };
    {
        let book = store_boot(&slots);
        book.lock()
            .unwrap_or_else(|p| p.into_inner())
            .migration_records(&token, StepName::Meter)
            .write_marker(&sealed)
            .expect("the marker goes on the chain");
        correct(ENTRY);
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
        correct(POOLED_ENTRY);
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
    let mut durability = restarted.lock().unwrap_or_else(|p| p.into_inner());
    assert_eq!(
        durability.migration_marker(),
        Some(sealed.clone()),
        "the restarted node reads the marker its first boot sealed"
    );
    assert_eq!(
        durability
            .migration_records(&token, StepName::Meter)
            .read_marker()
            .expect("readable"),
        Some(sealed),
        "the migration step reads the marker, so it does not seal a second opening"
    );
    assert_eq!(
        counts_now(ENTRY, &counts(1_000)),
        counts(800),
        "the correction sealed before the roll survived the restart"
    );
    assert_eq!(
        counts_now(POOLED_ENTRY, &counts(1_000)),
        counts(800),
        "the correction sealed after the roll survived the restart"
    );
    assert!(
        durability.restart_findings.is_empty(),
        "{:?}",
        durability.restart_findings
    );
}

/// A NODE WITH NO DATA DIRECTORY WHOSE CHAIN OUTGREW ONE MEMORY SEGMENT keeps its corrections and its
/// migration marker across a restart (audit R1#1). The memory log keeps only its newest segment
/// resident; the store keeps the rest, and every chain read after boot reads the whole of it. With
/// the reads on the resident segment only, the restart read the marker as absent and the corrections
/// as never made (the money reverted). See the `store` phase.
#[test]
fn a_chain_past_one_memory_segment_keeps_its_corrections_and_marker_over_the_store() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-amend-store-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    run_phase("store", &dir);
    let _ = std::fs::remove_dir_all(&dir);
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
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-amend-verify-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    run_phase("tamper", &dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A CORRECTED COUNT AND A CONTENT ACCESS SURVIVE A RESTART. The first process seals a root
/// correction (1,000 input units corrected to 800) and a hook's content access; the second, whose
/// node journal starts empty, boots over the same data directory and reads the count as 800 — and
/// the money view as 800 × the card — and finds the access. With the amendments held in memory
/// only, the second process read the count as recorded and found no access.
#[test]
fn a_corrected_count_and_a_content_access_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!(
        "busbar-root-amend-restart-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch directory");
    run_phase("seal", &dir);
    run_phase("read", &dir);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A NODE WITH NO DATA DIRECTORY rebuilds nothing, so it binds nothing: the node journal stays
/// memory-only, the previous release's shape, and no amendment reaches its memory-buffered journal.
#[test]
fn without_a_data_dir_the_amendment_journal_is_neither_rebuilt_nor_bound() {
    let mut durability = build_priced(
        &DurabilityConfig { data_dir: None },
        0,
        Box::new(busbar_kernel_wal::NullShipper::new()),
        Box::new(busbar_kernel_ledger::legacy::RecordingRows::new()),
        Box::new(|| None),
    )
    .expect("a memory-buffered journal cannot fail to open");
    durability
        .restore_amendments()
        .expect("nothing is read back");
    assert_eq!(durability.amendments_through, None);
    assert!(durability.restart_findings.is_empty());
}
