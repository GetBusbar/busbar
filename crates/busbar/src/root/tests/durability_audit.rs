// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors
use super::super::tests::{audit_pass, token, NativeFixture, BUDGET};
use super::*;
use busbar_kernel_audit::expose;

pub(crate) struct Scratch(pub(crate) std::path::PathBuf);

impl Scratch {
    pub(crate) fn new(tag: &str) -> Self {
        let path = std::path::PathBuf::from("/Users/matthew/Developer/tmp/corefix-implementation")
            .join(format!(
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
        origin: crate::root::kernel::new_kernel().origin(OriginKind::Client),
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
            rate_card_version: Some([1; 20]),
            bucket_chain_ref: String::new(),
        },
        controls: Controls::default(),
        correlation_label: None,
    }
}

pub(super) async fn seal(
    book: &std::sync::Arc<std::sync::Mutex<Durability>>,
    units: std::ops::RangeInclusive<u64>,
) -> Vec<AuditRecord> {
    let mut sealed = Vec::new();
    for unit in units {
        sealed.push(
            Durability::seal_unit(book, inputs(unit), audit_pass(), &token())
                .await
                .unwrap(),
        );
    }
    sealed
}

#[tokio::test]
async fn an_undecodable_audit_record_refuses_window_without_reclassifying_journal() {
    let fixture = NativeFixture::new(7).await;
    let book = std::sync::Arc::new(std::sync::Mutex::new(fixture.book().await));
    let sealed = seal(&book, 1..=1).await;
    let chain = book.lock().unwrap().chain_at();
    assert_eq!(chain.audit_window(1, 2).await, Some(sealed));
    let mut next = inputs(2);
    next.usage.lines.push(busbar_kernel_audit::UsageLine {
        class: busbar_contract::MeterClassId::new("unregistered-window-class"),
        quantity: 3.into(),
        source: busbar_contract::caps::QuantitySource::Count,
        estimated: false,
    });
    Durability::seal_unit(&book, next, audit_pass(), &token())
        .await
        .unwrap();
    assert!(
        fixture.journal.read_records(BUDGET).await.is_ok(),
        "original frames still verify"
    );
    let chain = book.lock().unwrap().chain_at();
    use tracing::instrument::WithSubscriber;
    use tracing_subscriber::layer::SubscriberExt;
    let captured = super::super::tests::Warnings::default();
    let window = chain
        .audit_window(1, 2)
        .with_subscriber(tracing_subscriber::registry().with(captured.clone()))
        .await;
    assert!(window.is_none(), "no partial successful audit window");
    assert!(captured.contains("does not decode"));
    assert!(!captured.contains("unregistered-window-class"));
    let reopened = fixture.reopen().await;
    assert!(reopened
        .restart_findings
        .iter()
        .any(|finding| finding.contains("audit chain")));
}

#[tokio::test]
async fn after_restart_head_tip_and_every_anchor_survive() {
    let fixture = NativeFixture::new(7).await;
    let book = std::sync::Arc::new(std::sync::Mutex::new(fixture.book().await));
    let sealed = seal(&book, 1..=3).await;
    let (head_before, anchors_before, range_before) = {
        let held = book.lock().unwrap();
        (
            expose::head_body(&held.record),
            held.record.heads().anchors(),
            expose::range_body(&held.record, &sealed, 1, 2),
        )
    };
    assert!(!head_before.contains("\"head\":null"));
    let reopened = fixture.reopen().await;
    assert_eq!(reopened.record.next_seq(), 4);
    assert_eq!(expose::head_body(&reopened.record), head_before);
    let tip = reopened.record.heads().tip().unwrap();
    assert_eq!((tip.seq, tip.hash.as_str()), (3, sealed[2].hash.as_str()));
    assert_eq!(reopened.record.heads().anchors(), anchors_before);
    assert_eq!(
        expose::range_body(&reopened.record, &sealed, 1, 2),
        range_before
    );
}
