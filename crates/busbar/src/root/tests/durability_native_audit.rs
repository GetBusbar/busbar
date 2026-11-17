// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use super::tests::inputs;
use crate::root::durability::tests::{audit_pass, token, NativeFixture, BUDGET};
use std::sync::{atomic::Ordering, Mutex};

#[tokio::test]
async fn native_staged_audit_retains_original_after_cancel_and_lost_ack() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let frozen = FrozenNativeAudit::new(inputs(1), book.lock().unwrap().line_identity());
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
    let sent = fixture.faults.requests.lock().unwrap();
    assert_eq!(sent.len(), 2);
    assert_eq!(sent[0].candidate().id, sent[1].candidate().id);
    assert_eq!(sent[0].fingerprint(), sent[1].fingerprint());
    drop(sent);
    assert_eq!(staged.line(), line);
    assert_eq!(fixture.journal.pending_records(), 0);
    let restarted = fixture.reopen().await;
    assert_eq!(restarted.audit_records().len(), 1);
    assert_eq!(restarted.audit_records()[0].hash, line.fp.to_hex());
}

#[tokio::test]
async fn native_stage_refusal_keeps_frozen_input_and_does_not_advance_chain() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let frozen = FrozenNativeAudit::new(inputs(1), book.lock().unwrap().line_identity());
    let before = book.lock().unwrap().record.next_seq();
    fixture.journal.stop_staging().unwrap();
    let mut slot = None;
    assert!(Durability::stage_native(&book, &frozen, &audit_pass(), &token(), &mut slot).is_err());
    assert!(slot.is_none());
    assert_eq!(book.lock().unwrap().record.next_seq(), before);
    assert_eq!(frozen.inputs.what.unit_key.get(), 1);
    assert_eq!(frozen.inputs.subject, inputs(1).subject);
    assert!(fixture.journal.read_records(BUDGET).await.unwrap().is_empty());
}

#[tokio::test]
async fn native_stage_never_replaces_an_installed_original_or_foreign_book() {
    let fixture = NativeFixture::new(7).await;
    let book = Arc::new(Mutex::new(fixture.book().await));
    let frozen = FrozenNativeAudit::new(inputs(1), book.lock().unwrap().line_identity());
    let mut slot = None;
    Durability::stage_native(&book, &frozen, &audit_pass(), &token(), &mut slot).unwrap();
    let original = slot.as_ref().unwrap().run.clone();
    let next = book.lock().unwrap().record.next_seq();
    assert!(Durability::stage_native(&book, &frozen, &audit_pass(), &token(), &mut slot).is_err());
    assert!(Arc::ptr_eq(&slot.as_ref().unwrap().run, &original));
    assert_eq!(book.lock().unwrap().record.next_seq(), next);
    let other = NativeFixture::new(8).await;
    let other_book = Arc::new(Mutex::new(other.book().await));
    let mut foreign_slot = None;
    assert!(Durability::stage_native(&other_book, &frozen, &audit_pass(), &token(), &mut foreign_slot).is_err());
    assert!(foreign_slot.is_none());
    assert_eq!(other.journal.pending_records(), 0);
}
