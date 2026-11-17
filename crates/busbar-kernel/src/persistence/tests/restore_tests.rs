// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-331 part B §B5.1, §B10.4: the restore quarantine gate and the pending marker.

use super::*;
use crate::persistence::startup::{classify, Format};
use crate::persistence::test_backend::{attach, Backend};
use busbar_contract::Secret;

fn row(epoch: u64, state: RestoreState) -> Restore {
    Restore {
        epoch,
        state,
        declared_at: if epoch == 0 { 0 } else { 1_800_000_000 },
        declaration_digest: if epoch == 0 { [0; 32] } else { [9; 32] },
    }
}

#[test]
fn a_flag_or_a_pending_row_quarantines_at_boot() {
    let gate = Gate::new();
    assert_eq!(gate.boot(None, false), None);
    assert!(!gate.quarantined());
    let gate = Gate::new();
    assert_eq!(gate.boot(None, true), Some(Reason::Flag));
    let gate = Gate::new();
    assert_eq!(
        gate.boot(Some(row(0, RestoreState::Pending)), false),
        Some(Reason::PendingRow)
    );
    let gate = Gate::new();
    assert_eq!(gate.boot(Some(row(1, RestoreState::Declared)), false), None);
    assert_eq!(gate.booted_epoch(), 1);
}

#[test]
fn a_refresh_that_sees_pending_or_another_epoch_quarantines_for_good() {
    let gate = Gate::new();
    gate.boot(Some(row(1, RestoreState::Declared)), false);
    assert_eq!(gate.observe(Some(row(1, RestoreState::Declared))), None);
    assert_eq!(
        gate.observe(Some(row(1, RestoreState::Pending))),
        Some(Reason::PendingRow)
    );
    // The first reason stays; quarantine is one-way inside a process.
    assert_eq!(
        gate.observe(Some(row(1, RestoreState::Declared))),
        Some(Reason::PendingRow)
    );
    let gate = Gate::new();
    gate.boot(Some(row(1, RestoreState::Declared)), false);
    assert_eq!(
        gate.observe(Some(row(2, RestoreState::Declared))),
        Some(Reason::EpochChanged)
    );
    // A store rewound to a never-restored dataset is an epoch change too.
    let gate = Gate::new();
    gate.boot(Some(row(1, RestoreState::Declared)), false);
    assert_eq!(gate.observe(None), Some(Reason::EpochChanged));
}

fn manifest_one(core: &CoreStore) -> Vec<u8> {
    let authority = core.authority().unwrap();
    Manifest {
        dataset: core.info().dataset,
        registrar: authority,
        format: RECORD_FORMAT,
    }
    .encode()
    .to_vec()
}

#[tokio::test]
async fn the_pending_marker_raises_the_manifest_to_the_restored_format_once() {
    let backend = Arc::new(Backend::default());
    let core = attach(backend.clone()).await;
    let before = manifest_one(&core);
    backend
        .state
        .lock()
        .unwrap()
        .rows
        .insert(manifest_address(), Secret::new(before.clone()));
    assert_eq!(read(backend.as_ref()).await.unwrap(), None);

    let marked = mark_pending(&core).await.unwrap();
    assert_eq!(marked, row(0, RestoreState::Pending));
    assert_eq!(read(backend.as_ref()).await.unwrap(), Some(marked));
    let after = backend.state.lock().unwrap().rows[&manifest_address()]
        .expose(&crate::seal::lend())
        .clone();
    assert_eq!(classify(&after, |_| false), Format::Current);
    assert_eq!(
        u32::from_le_bytes(after[8..12].try_into().unwrap()),
        RESTORED_FORMAT
    );
    assert_eq!(after[24..], before[24..]);

    // Already pending: answered as is, nothing more is sent.
    let sent = backend.state.lock().unwrap().sent.len();
    assert_eq!(mark_pending(&core).await.unwrap(), marked);
    assert_eq!(backend.state.lock().unwrap().sent.len(), sent);
}

#[tokio::test]
async fn a_declared_row_goes_back_to_pending_at_its_own_epoch() {
    let backend = Arc::new(Backend::default());
    let core = attach(backend.clone()).await;
    let declared = row(1, RestoreState::Declared);
    {
        let mut state = backend.state.lock().unwrap();
        state
            .rows
            .insert(manifest_address(), Secret::new(manifest_one(&core)));
        state
            .rows
            .insert(address(), Secret::new(declared.encode().to_vec()));
    }
    let marked = mark_pending(&core).await.unwrap();
    assert_eq!(
        marked,
        Restore {
            state: RestoreState::Pending,
            ..declared
        }
    );
}
