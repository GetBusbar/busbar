// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-331 part B §B5.1, §B10.4: the restore quarantine gate and the pending marker.

use super::*;
use crate::persistence::startup::{classify, Format};
use crate::persistence::test_backend::{attach, Backend};
use busbar_contract::json::JsonValueTrait as _;
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

/// DES-331 §B5.2, §B10.8: in quarantine every read and only the allow-listed writes pass.
#[test]
fn quarantine_admits_reads_and_the_allow_listed_writes_only() {
    for (method, rel) in [
        ("GET", "/keys"),
        ("HEAD", "/config"),
        ("POST", "/store-restore"),
        ("POST", "/store-restore/verify"),
        ("PUT", "/store-restore/tail/abc/0"),
        ("POST", "/trust/revoke"),
        ("POST", "/keys/vk_1/revoke"),
        ("DELETE", "/keys/vk_1"),
        ("DELETE", "/groups/g"),
        ("DELETE", "/hooks/h"),
        ("DELETE", "/hooks/h/attachments/t"),
        ("DELETE", "/overlay/limits"),
        ("DELETE", "/plugins/p.so"),
    ] {
        assert!(admits_in_quarantine(method, rel), "{method} {rel}");
    }
    for (method, rel) in [
        ("POST", "/keys"),
        ("PATCH", "/keys/vk_1"),
        ("POST", "/keys/vk_1/rotate"),
        ("PUT", "/hooks/h"),
        ("POST", "/config/apply"),
        ("POST", "/trust/approve"),
        ("DELETE", "/keys/vk_1/extra"),
        ("POST", "/store-restore/other"),
    ] {
        assert!(!admits_in_quarantine(method, rel), "{method} {rel}");
    }
}

/// DES-331 §B10.8: the refusal is 503 `unavailable`, reason `restore_quarantine`, with the epoch
/// and the allow-list in `details`, and no `Retry-After`.
#[tokio::test]
async fn the_quarantine_refusal_names_its_reason_epoch_and_allow_list() {
    let response = crate::admin::gate::restore_quarantine_response(3);
    assert_eq!(
        response.status(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(response
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .is_none());
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let body = busbar_contract::json::parse_value(&body).unwrap();
    let error = &body["error"];
    assert_eq!(error["code"].as_str(), Some("unavailable"));
    assert_eq!(error["reason"].as_str(), Some("restore_quarantine"));
    assert_eq!(error["details"]["restore_epoch"].as_u64(), Some(3));
    let allowed = error["details"]["allowed"].as_array().unwrap();
    assert_eq!(allowed.len(), QUARANTINE_ALLOWED.len());
    assert!(allowed
        .iter()
        .any(|a| a.as_str() == Some("POST /api/v1/admin/store-restore")));
}
