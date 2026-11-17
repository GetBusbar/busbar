// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::tests::inputs;
use super::*;
use crate::root::durability::tests::{audit_pass, token, NativeFixture, BUDGET};
use std::sync::{atomic::Ordering, Mutex};

#[tokio::test]
async fn native_staged_audit_retains_original_after_cancel_and_lost_ack() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let frozen = FrozenNativeAudit::new(inputs(1), &book);
    let mut slot = None;
    Durability::stage_native(&book, &frozen, &audit_pass(), &token(), &mut slot).unwrap();
    let staged = slot.as_ref().unwrap();
    let original = staged.run.clone();
    let line = staged.line();
    fixture.faults.pause(true);
    {
        let confirmation = staged.confirm_journal();
        tokio::pin!(confirmation);
        assert!(futures::poll!(&mut confirmation).is_pending());
    }
    assert!(Arc::ptr_eq(&slot.as_ref().unwrap().run, &original));
    assert_eq!(fixture.journal.pending_records(), 1);
    fixture.faults.pause(false);
    fixture.faults.clear_observations();
    fixture.faults.lose_acks.store(true, Ordering::Release);
    assert!(staged.confirm_journal().await.is_err());
    assert!(Arc::ptr_eq(&slot.as_ref().unwrap().run, &original));
    fixture.faults.lose_acks.store(false, Ordering::Release);
    staged.confirm_journal().await.unwrap();
    {
        let sent = fixture.faults.requests.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].candidate().id, sent[1].candidate().id);
        assert_eq!(sent[0].fingerprint(), sent[1].fingerprint());
    }
    assert_eq!(staged.line(), line);
    assert_eq!(fixture.journal.pending_records(), 0);
    let restarted = fixture.reopen().await;
    assert_eq!(restarted.audit_records().len(), 1);
    assert_eq!(restarted.audit_records()[0].hash, line.fp.to_string());
}

#[tokio::test]
async fn native_stage_refusal_keeps_frozen_input_and_does_not_advance_chain() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let frozen = FrozenNativeAudit::new(inputs(1), &book);
    let before = book.lock().unwrap().record.next_seq();
    fixture.journal.stop_staging().unwrap();
    let mut slot = None;
    assert!(Durability::stage_native(&book, &frozen, &audit_pass(), &token(), &mut slot).is_err());
    assert!(slot.is_none());
    assert_eq!(book.lock().unwrap().record.next_seq(), before);
    assert_eq!(frozen.inputs.what.unit_key.get(), 1);
    assert_eq!(frozen.inputs.subject, inputs(1).subject);
    assert!(fixture
        .journal
        .read_records(BUDGET)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn native_stage_never_replaces_an_installed_original_or_foreign_book() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let frozen = FrozenNativeAudit::new(inputs(1), &book);
    let mut slot = None;
    Durability::stage_native(&book, &frozen, &audit_pass(), &token(), &mut slot).unwrap();
    let original = slot.as_ref().unwrap().run.clone();
    let next = book.lock().unwrap().record.next_seq();
    assert!(Durability::stage_native(&book, &frozen, &audit_pass(), &token(), &mut slot).is_err());
    assert!(Arc::ptr_eq(&slot.as_ref().unwrap().run, &original));
    assert_eq!(book.lock().unwrap().record.next_seq(), next);
    // Equal numeric node/incarnation is not ownership of the original journal.
    let other = NativeFixture::new(7).await;
    let other_book = Arc::new(Mutex::new(other.book().await));
    let mut foreign_slot = None;
    assert!(Durability::stage_native(
        &other_book,
        &frozen,
        &audit_pass(),
        &token(),
        &mut foreign_slot
    )
    .is_err());
    assert!(foreign_slot.is_none());
    assert_eq!(other.journal.pending_records(), 0);
}

#[tokio::test]
async fn native_stage_retries_same_frozen_facts_after_journal_budget_is_released() {
    let fixture = NativeFixture::new(7).await;
    let journal = RuntimeJournal::open(
        fixture.core.clone(),
        7,
        BufferBudget {
            records: 1,
            bytes: 64 * 1024,
        },
    )
    .await
    .unwrap();
    let book = Arc::new(Mutex::new(
        crate::root::durability::build_on_store(
            &crate::root::durability::DurabilityConfig::default(),
            7,
            journal.clone(),
            None,
            BUDGET,
        )
        .await
        .unwrap(),
    ));
    let frozen = FrozenNativeAudit::new(inputs(1), &book);
    let occupied = journal
        .stage_run(&[Entry::new(RecordClass::Load, vec![1])])
        .unwrap();
    let mut slot = None;
    assert!(Durability::stage_native(&book, &frozen, &audit_pass(), &token(), &mut slot).is_err());
    assert!(slot.is_none());
    assert_eq!(book.lock().unwrap().record.next_seq(), 1);
    journal.confirm(&occupied).await.unwrap();
    Durability::stage_native(&book, &frozen, &audit_pass(), &token(), &mut slot).unwrap();
    let staged = slot.as_ref().unwrap();
    staged.confirm_journal().await.unwrap();
    assert_eq!(staged.line().chain_seq, 1);
    assert_eq!(staged.line().node_seq, 2);
    let held = book.lock().unwrap();
    let record = held.audit_records().last().unwrap();
    assert_eq!(record.subject, frozen.inputs.subject);
    assert_eq!(record.what, frozen.inputs.what);
    assert_eq!(record.usage, frozen.inputs.usage);
}

/// The terminal facts a native caller still owns when it asks for a frozen audit (r2: the
/// preparation returns this original bundle on any refusal).
#[derive(Debug, PartialEq, Eq)]
struct TerminalSource {
    user: String,
    billing: busbar_kernel_audit::record::billing::PartitionedBillingV1,
}

fn terminal_source(user: String) -> TerminalSource {
    use busbar_kernel_audit::record::billing as signed;
    use std::collections::BTreeMap;
    let era = signed::BillingEra {
        effective_from: 17,
        entry_id: Some([1; 12]),
    };
    let selected = signed::SelectedQuantity {
        count: 12u64.into(),
        source: signed::UsageSource::Reported,
    };
    let billing = signed::PartitionedBillingV1::new(signed::BillingFacts {
        revision: 9,
        request_pool: "p\u{1f}original".into(),
        routing_generation: 3,
        era,
        session_origin: signed::SessionOrigin {
            instance: "p".into(),
            lane: "p\u{1f}".into(),
            provider: None,
        },
        logical_request: signed::LogicalRequest::DeliveredPreparation(1),
        fee: signed::LogicalFee {
            state: signed::FeeState::Charged,
            lane: Some("p\u{1f}".into()),
            era,
        },
        disposition: signed::BillingDisposition::End,
        far_end_answered: true,
        caller_bytes_committed: true,
        final_target: Some(1),
        partitions: vec![signed::BillingPartition {
            scope: signed::PartitionScope::Attempt {
                preparation: 1,
                dispatch: Some(1),
            },
            kind: signed::TargetKind::Model,
            instance: "p".into(),
            lane: "p\u{1f}model".into(),
            provider: Some("configured".into()),
            selected_pool: Some("p\u{1f}selected".into()),
            resource: None,
            transport: Some(signed::Transport::Committed),
            finality: signed::Finality::Complete,
            classes: BTreeMap::from([(
                "tokens".into(),
                signed::BillingClass {
                    reported: Some(selected.count),
                    floor: Some(3u64.into()),
                    estimated: Some(50u64.into()),
                    selected: Some(selected),
                    billed: Some(selected),
                    rate_high_water: selected.count,
                },
            )]),
        }],
    })
    .unwrap();
    TerminalSource { user, billing }
}

/// The canonical inputs the caller's existing input building produces from its source.
fn build_from(source: &TerminalSource) -> Result<AuditInputs, std::convert::Infallible> {
    let mut built = inputs(1);
    built.usage.fee_count = source.billing.fee_count();
    built.unit.billing = Some(source.billing.clone());
    built.unit.records.user = Some(source.user.clone());
    Ok(built)
}

/// DOES: (native DATA audit r2, frozen input boundary) a terminal whose canonical line no journal
/// body can carry (a V9 `records.user` past its bound) is refused at preparation, before any entry
/// owns it.
/// Nothing is staged, the chain does not move and the journal holds nothing. Freezing it instead
/// would leave an entry whose every stage retry refuses for the rest of the process.
#[tokio::test]
async fn native_prepare_refuses_an_unencodable_line_before_any_entry() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let source = terminal_source("u".repeat(4097));
    let before = book.lock().unwrap().record.next_seq();
    let Err(refused) = FrozenNativeAudit::prepare(source, &book, &audit_pass(), build_from) else {
        panic!("a line no journal body can carry was frozen into the native entry");
    };
    assert!(!matches!(refused.why, NativeFreezeRefusal::Build(_)));
    assert_eq!(book.lock().unwrap().record.next_seq(), before);
    assert_eq!(fixture.journal.pending_records(), 0);
    assert!(fixture
        .journal
        .read_records(BUDGET)
        .await
        .unwrap()
        .is_empty());
}

/// DOES: a refusal by the caller's own input building freezes nothing.
#[tokio::test]
async fn native_prepare_build_refusal_freezes_nothing() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let source = terminal_source("user".into());
    let Err(refused) =
        FrozenNativeAudit::prepare(source, &book, &audit_pass(), |_: &TerminalSource| {
            Err::<AuditInputs, _>("selected terminal differs from its original audit identity")
        })
    else {
        panic!("a refused build froze an entry");
    };
    assert_eq!(
        refused.why,
        NativeFreezeRefusal::Build("selected terminal differs from its original audit identity")
    );
    assert_eq!(fixture.journal.pending_records(), 0);
}

/// DOES: an encodable V9 terminal freezes with this book's identity, hands the caller back its
/// untouched source to drop after install, and the frozen facts stage as exactly that line.
#[tokio::test]
async fn native_prepare_freezes_an_encodable_line_and_stages_those_exact_facts() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let source = terminal_source("user".into());
    let original = source.user.as_ptr();
    let (frozen, source) =
        FrozenNativeAudit::prepare(source, &book, &audit_pass(), build_from).unwrap();
    assert_eq!(source.user.as_ptr(), original);
    assert_eq!(frozen.identity, book.lock().unwrap().line_identity());
    assert_eq!(
        frozen.inputs.unit.billing.as_ref(),
        Some(&source.billing),
        "the frozen copy is the source's billing"
    );
    let mut slot = None;
    Durability::stage_native(&book, &frozen, &audit_pass(), &token(), &mut slot).unwrap();
    slot.as_ref().unwrap().confirm_journal().await.unwrap();
    let held = book.lock().unwrap();
    let record = held.audit_records().last().unwrap();
    assert_eq!(record.unit.records.user.as_deref(), Some("user"));
    assert_eq!(record.unit.billing.as_ref(), Some(&source.billing));
}
