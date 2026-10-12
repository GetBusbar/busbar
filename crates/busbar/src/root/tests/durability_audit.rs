// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fixed audit chain across a restart: the head read and the anchors answer as they did before.

use super::*;
use busbar_kernel_audit::expose;
use busbar_kernel_ledger::legacy::RecordingRows;
use busbar_kernel_wal::NullShipper;

/// A directory nobody else writes to, removed when the test ends.
pub(super) struct Scratch(pub(super) std::path::PathBuf);

impl Scratch {
    pub(super) fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "busbar-root-durability-audit-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        Scratch(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A book journalling into `dir`, as node 7.
pub(super) fn open(dir: &std::path::Path) -> Durability {
    build_for_node(
        &DurabilityConfig {
            data_dir: Some(dir.to_path_buf()),
        },
        7,
        Box::new(NullShipper::new()),
        Box::new(RecordingRows::new()),
    )
    .expect("the directory is writable")
}

/// A unit's facts for the audit step, an hour apart per unit so each one is its own head sample.
pub(super) fn inputs(unit: u64) -> AuditInputs {
    use busbar_contract::caps::{OriginKind, Outcome, UnitKey};
    use busbar_kernel_audit::{
        Controls, FinishClass, OpClassId, OutcomeFacts, Subject, Usage, What,
    };
    AuditInputs {
        subject: Subject::PrincipalId(format!("key-{unit}")),
        what: What {
            unit_key: UnitKey::new(unit),
            incarnation: 0,
            op_class: OpClassId::new("chat.completion"),
            destination: None,
            parent: None,
            pre_hook_head: None,
            post_hook_head: None,
        },
        wall: 1_700_000_000 + unit * 3_600,
        mono: unit,
        origin: busbar_kernel::test_support::tokens::origin(OriginKind::Client),
        outcome: OutcomeFacts {
            unit_end: Outcome::Completed,
            step: None,
            finish: FinishClass::Complete,
            hook_failed: false,
            emission_delta: 0,
            stale_policy: false,
        },
        usage: Usage {
            lines: Vec::new(),
            tier_bp: 10_000,
            fee_count: 1,
            rate_card_version: 1,
            bucket_chain_ref: String::new(),
        },
        controls: Controls::default(),
        correlation_label: None,
    }
}

/// Seal `n` units onto `book`'s chain, returning what was sealed.
pub(super) fn seal(
    book: &mut Durability,
    units: std::ops::RangeInclusive<u64>,
) -> Vec<AuditRecord> {
    let token = busbar_kernel::test_support::tokens::grant::<DurableWrite>();
    units
        .map(|unit| {
            book.seal_unit(
                inputs(unit),
                busbar_kernel::test_support::tokens::pass(),
                &token,
            )
            .expect("the record goes on the journal")
        })
        .collect()
}

/// AFTER A RESTART THE HEAD READ ANSWERS WITH THE CHAIN'S TIP, and every anchor survives.
///
/// The restarted book continues the chain at position four. Its head read used to answer
/// `"head":null` beside `"next_seq":4` — "this chain has no records" while it holds three — and the
/// range read's `anchor` was null for every window sealed before the restart, because the chain
/// was resumed from its tail and its head history started empty.
#[test]
fn after_a_restart_the_head_read_answers_with_the_tip_and_the_anchors_survive() {
    let scratch = Scratch::new("head-after-restart");
    let (sealed, head_before, anchors_before, range_before) = {
        let mut book = open(&scratch.0);
        let sealed = seal(&mut book, 1..=3);
        (
            sealed.clone(),
            expose::head_body(&book.record),
            book.record.heads().anchors(),
            expose::range_body(&book.record, &sealed, 1, 2),
        )
    };
    assert!(!head_before.contains("\"head\":null"), "{head_before}");

    let restarted = open(&scratch.0);
    assert_eq!(restarted.record.next_seq(), 4);
    let head = expose::head_body(&restarted.record);
    assert!(
        !head.contains("\"head\":null"),
        "a restarted non-empty chain answered a null head: {head}"
    );
    assert_eq!(head, head_before, "the head read moved across the restart");
    let tip = restarted
        .record
        .heads()
        .tip()
        .expect("a restarted non-empty chain has a tip");
    assert_eq!((tip.seq, tip.hash.as_str()), (3, sealed[2].hash.as_str()));
    assert_eq!(
        restarted.record.heads().anchors(),
        anchors_before,
        "an anchor was lost across the restart"
    );
    assert_eq!(
        expose::range_body(&restarted.record, &sealed, 1, 2),
        range_before,
        "a window's anchor moved across the restart"
    );
}
