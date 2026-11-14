// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::durability::tests::{audit_inputs, audit_pass};
use busbar_kernel_audit::{Audit, AuditChain};

fn sealed(count: usize) -> Vec<AuditRecord> {
    let mut chain = AuditChain::new().sealing_as(1);
    let pass = audit_pass();
    (0..count)
        .map(|unit| chain.seal(audit_inputs(unit as u64 + 1), &pass))
        .collect()
}

#[test]
fn audit_ring_evicts_in_batches_not_per_push() {
    let pushes = 10 * AUDIT_RING;
    let mut ring = AuditRing::new();
    for record in sealed(pushes) {
        ring.push(record);
    }
    assert_eq!(ring.as_slice().len(), AUDIT_RING);
    let limit = (pushes / AUDIT_SLACK) as u64;
    assert!(
        ring.compactions() <= limit,
        "{} compactions for {pushes} pushes; at most {limit} (one per {AUDIT_SLACK})",
        ring.compactions()
    );
    println!(
        "size_of::<AuditRecord>() = {} bytes",
        std::mem::size_of::<AuditRecord>()
    );
}

#[test]
fn audit_ring_view_is_the_contract() {
    let total = 3 * (AUDIT_RING + AUDIT_SLACK);
    let records = sealed(total);
    let mut ring = AuditRing::new();
    assert!(ring.as_slice().is_empty());
    for (n, record) in records.iter().enumerate() {
        ring.push(record.clone());
        let pushed = n + 1;
        let view = ring.as_slice();
        assert_eq!(view.len(), pushed.min(AUDIT_RING), "length at {pushed}");
        assert_eq!(view.last().map(|r| r.seq), Some(record.seq));
        assert_eq!(
            view.first().map(|r| r.seq),
            Some(records[pushed - view.len()].seq),
            "oldest at {pushed}"
        );
        assert!(
            view.windows(2).all(|w| w[1].seq == w[0].seq + 1),
            "contiguous seqs at {pushed}"
        );
        assert!(
            AuditChain::verify_window(view).is_ok(),
            "window verifies at {pushed}"
        );
        let seqs: Vec<u64> = view.iter().map(|r| r.seq).collect();
        let window = ring.window_mut_for_tamper_test();
        assert_eq!(window.len(), seqs.len(), "tamper window length at {pushed}");
        assert!(
            window.iter().map(|r| r.seq).eq(seqs.iter().copied()),
            "tamper window is the view at {pushed}"
        );
    }

    // A write through the tamper hook is a write to the visible window.
    let mut tampered = AuditRing::from_sealed(records.clone());
    tampered.window_mut_for_tamper_test()[1].usage.fee_count += 1;
    assert!(AuditChain::verify_window(tampered.as_slice()).is_err());

    // Resume keeps the newest AUDIT_RING sealed records.
    let resumed = AuditRing::from_sealed(records.clone());
    assert_eq!(resumed.as_slice(), &records[total - AUDIT_RING..]);
    let short = AuditRing::from_sealed(records[..5].to_vec());
    assert_eq!(short.as_slice(), &records[..5]);

    // push_unique dedupes inside the view and re-admits what has left it.
    let mut ring = AuditRing::new();
    for record in &records[..AUDIT_RING + 1] {
        assert!(ring.push_unique(record.clone()));
    }
    assert!(!ring.push_unique(records[AUDIT_RING].clone()), "in view");
    assert!(
        ring.push_unique(records[0].clone()),
        "an evicted record is no longer in the view"
    );

    // retain over the window equals Vec::retain on the ring.
    let mut ring = AuditRing::new();
    for record in &records[..AUDIT_RING + AUDIT_SLACK] {
        ring.push(record.clone());
    }
    let mut want = ring.as_slice().to_vec();
    let drop = want[3].seq;
    want.retain(|r| r.seq != drop);
    ring.retain_for_tamper_test(|r| r.seq != drop);
    assert_eq!(ring.as_slice(), want.as_slice());
}
