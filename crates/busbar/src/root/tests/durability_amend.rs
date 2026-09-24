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

/// The node's boot, as `compose_boot_book` and `open_boot_book` run it: build over the data
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
    durability.restore_amendments();
    let book = Arc::new(Mutex::new(durability));
    bind_amendments(&book);
    book
}

/// ONE HALF OF THE RESTART, run only in a child process the restart test below starts; a no-op
/// anywhere else.
#[test]
fn restart_phase() {
    let (Ok(phase), Ok(dir)) = (std::env::var(PHASE), std::env::var(DIR)) else {
        return;
    };
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
                },
            )
            .expect("a root correction to a non-negative count lands");
            let app = busbar_kernel::test_support::TestApp::new().build();
            busbar_kernel::plane_host::engine_host(&app).hook_read(
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
            assert_eq!(accesses[0].fields, vec!["content".to_string()]);
        }
        other => panic!("unknown phase {other}"),
    }
}

/// Run [`restart_phase`] in a fresh process of this test binary.
fn run_phase(phase: &str, dir: &std::path::Path) {
    let out = std::process::Command::new(std::env::current_exe().expect("the test binary"))
        .args(["--exact", "root::durability::amend::tests::restart_phase"])
        .args(["--test-threads", "1", "--nocapture"])
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
    durability.restore_amendments();
    assert_eq!(durability.amendments_through, None);
    assert!(durability.restart_findings.is_empty());
}
