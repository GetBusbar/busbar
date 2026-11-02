// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fixed audit chain across a restart: the head read and the anchors answer as they did before.

use super::*;
use crate::root::store_double::RecordSlots;
use busbar_kernel_audit::expose;

/// A directory nobody else writes to, removed when the test ends.
pub(crate) struct Scratch(pub(crate) std::path::PathBuf);

impl Scratch {
    pub(crate) fn new(tag: &str) -> Self {
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

/// A book over the Store as node 7, supplied a legacy directory.
pub(super) fn open(dir: &std::path::Path, slots: &RecordSlots) -> Durability {
    let lane = JournalLane::start(slots.calls(), "test-store").unwrap();
    build_on_store(
        &DurabilityConfig {
            data_dir: Some(dir.to_path_buf()),
        },
        7,
        lane,
        None,
    )
    .expect("the Store reads back")
}

/// A unit's facts for the audit step, an hour apart per unit so each one is its own head sample.
pub(crate) fn inputs(unit: u64) -> AuditInputs {
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
        origin: busbar_kernel_testkit::test_support::tokens::origin(OriginKind::Client),
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
    let token = busbar_kernel_testkit::test_support::tokens::grant::<DurableWrite>();
    units
        .map(|unit| {
            book.seal_unit(
                inputs(unit),
                busbar_kernel_testkit::test_support::tokens::pass(),
                &token,
            )
            .expect("the record goes on the journal")
        })
        .collect()
}

#[test]
fn an_undecodable_audit_record_refuses_the_chain_window_without_reclassifying_the_journal() {
    let slots = RecordSlots::new();
    use tracing_subscriber::layer::SubscriberExt as _;
    let scratch = Scratch::new("undecodable-window");
    let mut book = open(&scratch.0, &slots);
    let sealed = seal(&mut book, 1..=1);
    assert_eq!(book.chain_at().audit_window(1, 2), Some(sealed));

    let mut next = inputs(2);
    next.usage.lines.push(busbar_kernel_audit::UsageLine {
        class: busbar_contract::MeterClassId::new("unregistered-window-class"),
        quantity: 3,
        source: busbar_contract::caps::QuantitySource::Count,
        estimated: false,
    });
    book.seal_unit(
        next,
        busbar_kernel_testkit::test_support::tokens::pass(),
        &busbar_kernel_testkit::test_support::tokens::grant::<DurableWrite>(),
    )
    .expect("the complete record is journalled");
    assert!(
        book.chain().expect("read chain").is_ok(),
        "the journal still verifies"
    );
    let captured = busbar_kernel_testkit::test_support::warn_capture::WarnCapture::default();
    let window = tracing::subscriber::with_default(
        tracing_subscriber::registry().with(captured.clone()),
        || book.chain_at().audit_window(1, 2),
    );
    assert!(
        window.is_none(),
        "an unreadable audit record must not produce a partial successful window"
    );
    assert!(captured.contains("does not decode"));
    assert!(!captured.contains("unregistered-window-class"));
}

/// AFTER A RESTART THE HEAD READ ANSWERS WITH THE CHAIN'S TIP, and every anchor survives.
///
/// The restarted book continues the chain at position four. Its head read used to answer
/// `"head":null` beside `"next_seq":4` — "this chain has no records" while it holds three — and the
/// range read's `anchor` was null for every window sealed before the restart, because the chain
/// was resumed from its tail and its head history started empty.
#[test]
fn after_a_restart_the_head_read_answers_with_the_tip_and_the_anchors_survive() {
    let slots = RecordSlots::new();
    let scratch = Scratch::new("head-after-restart");
    let (sealed, head_before, anchors_before, range_before) = {
        let mut book = open(&scratch.0, &slots);
        let sealed = seal(&mut book, 1..=3);
        assert!(book
            .lane()
            .unwrap()
            .drain(std::time::Duration::from_secs(5)));
        (
            sealed.clone(),
            expose::head_body(&book.record),
            book.record.heads().anchors(),
            expose::range_body(&book.record, &sealed, 1, 2),
        )
    };
    assert!(!head_before.contains("\"head\":null"), "{head_before}");

    let restarted = open(&scratch.0, &slots);
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
