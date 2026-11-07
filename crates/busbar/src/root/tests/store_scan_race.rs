// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::root::store_double::NativeFaults;

#[tokio::test]
async fn native_replay_pins_the_complete_selected_prefix_across_an_atomic_append() {
    let faults = NativeFaults::open().await;
    let core = crate::root::real_store::core_over(faults.clone()).await;
    let journal = RuntimeJournal::open(core, busbar_kernel::door::op_id().counter(), BUDGET)
        .await
        .unwrap();
    let initial: Vec<_> = (0..300)
        .map(|n| Entry::new(RecordClass::Load, vec![n as u8; 8192]))
        .collect();
    for entry in &initial {
        let run = journal.stage_run(std::slice::from_ref(entry)).unwrap();
        journal.confirm(&run).await.unwrap();
    }
    let next = journal
        .stage_run(&[
            Entry::new(RecordClass::Load, vec![1; 8192]),
            Entry::new(RecordClass::Load, vec![2; 8192]),
        ])
        .unwrap();
    let appended = Arc::new(AtomicBool::new(false));
    let seen = appended.clone();
    let writer = journal.clone();
    *faults.on_read.lock().unwrap() = Some(Arc::new(move |request| {
        let writer = writer.clone();
        let next = next.clone();
        let seen = seen.clone();
        Box::pin(async move {
            if request
                .addresses
                .iter()
                .any(|at| at.key.get(24) == Some(&b'R'))
                && !seen.swap(true, Ordering::SeqCst)
            {
                writer
                    .confirm(&next)
                    .await
                    .map_err(|_| Failure::Unavailable)?;
            }
            Ok(())
        })
    }));
    let old = journal.read_records(BUDGET).await.unwrap();
    *faults.on_read.lock().unwrap() = None;
    assert!(appended.load(Ordering::SeqCst));
    assert_eq!(
        old.len(),
        300,
        "an append after head selection cannot extend the selected proof"
    );
    for (record, entry) in old.iter().zip(&initial) {
        assert_eq!(record.body, entry.body);
    }
    busbar_kernel_wal::verify_journal(&old).unwrap();
    let fresh = journal.read_records(BUDGET).await.unwrap();
    assert_eq!(
        fresh.len(),
        302,
        "a new proof sees both records of the actual atomic append"
    );
    assert_eq!(fresh[..300], old);
    assert_eq!(fresh[300].node_seq, 301);
    assert_eq!(fresh[301].node_seq, 302);
    busbar_kernel_wal::verify_journal(&fresh).unwrap();
}
