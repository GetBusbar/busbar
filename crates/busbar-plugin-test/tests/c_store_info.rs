// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-STORE-INFO (ABI-MIN3-INTERFACE §14): `info` once after INSTANCE equals `PersistenceBackend::info()`;
//! READ_DONE/COMMITTED authority equals `clock_authority`.
//!
//! WBS rule 10: each arm is ignored for the task that lands the last piece it needs; that task writes
//! the arm's body and un-ignores it in its own MR (red first, then green).
//!
//! The core arm runs over the `plugin!` store fixture (`fixtures/min3_store.rs`, the inline image) opened through
//! `Registry::open_store`. store-memory's own half (it reports DUR_EPHEMERAL and the kernel's in-memory warning
//! fires) is its repo's suite; here core's side of it is pinned: an FB_EPHEMERAL image is one of
//! `Registry::ephemeral_stores` (what that warning reads) and an `info` durability that disagrees with the fact
//! refuses the open before any read or write.

use busbar_contract::persistence::{
    BackendInfo, DatasetId, Decision, Durability, Failure, PersistenceBackend, ReadResult,
};
use busbar_plugin_abi::fail::refused::R_INVALID;
use busbar_plugin_loader::instance::OpenError;
use busbar_plugin_test::fake_needs::FakeNeeds;

use crate::min3_store::{
    booted, counts, initialization, inline, read_one, AUTHORITY, DATASET, DOMAIN, OBSERVED_AT,
    PHYSICAL_VERSION,
};

#[test]
fn info_once_after_instance() {
    let h = booted(inline::PLUGIN.plugin(), FakeNeeds::new());
    let want = BackendInfo {
        dataset: DatasetId(DATASET),
        atomic_domain: DOMAIN,
        clock_authority: AUTHORITY,
        physical_version: PHYSICAL_VERSION,
        durability: Durability::Ephemeral,
    };

    // `info` is called exactly once, right after INSTANCE, and `PersistenceBackend::info()` is its answer.
    let id = "c-store-info";
    let store = h
        .open_store("info", format!(r#"{{"id":"{id}"}}"#).as_bytes())
        .unwrap_or_else(|e| panic!("open failed: {e:?}"));
    let b: &dyn PersistenceBackend = &*store.backend;
    assert_eq!(counts(id).info, 1, "info is called once after INSTANCE");
    assert_eq!(b.info(), want);

    // READ_DONE's authority is the one `info` stated.
    match h.block_on(read_one(b)) {
        Ok(ReadResult::Values {
            observed_at,
            values,
        }) => {
            assert_eq!(observed_at.authority, want.clock_authority, "READ_DONE");
            assert_eq!(observed_at.unix_seconds, OBSERVED_AT);
            assert!(values.len() == 1 && values[0].is_none());
        }
        Ok(ReadResult::TimeGuardFailed { .. }) => panic!("an unguarded read failed its guard"),
        Err(e) => panic!("read failed: {e:?}"),
    }

    // COMMITTED's authority (a time-guard verdict carries it) is the one `info` stated.
    let tg = "c-store-info-tg";
    let guarded = h
        .open_store(
            "info-tg",
            format!(r#"{{"id":"{tg}","commit_code":"time_guard_failed"}}"#).as_bytes(),
        )
        .unwrap_or_else(|e| panic!("open failed: {e:?}"));
    let (init, key) = initialization(&*guarded.backend);
    match h.block_on(guarded.backend.commit(init, key)) {
        Ok(Decision::TimeGuardFailed { observed_at }) => {
            assert_eq!(observed_at.authority, want.clock_authority, "COMMITTED");
        }
        Ok(_) => panic!("COMMITTED answered another decision"),
        Err(e) => panic!("commit failed: {e:?}"),
    }
    assert_eq!(counts(tg).commits, 1);

    // Nothing after the open calls `info` again: the cached answer serves.
    assert_eq!(b.info(), want);
    assert_eq!((counts(id).info, counts(tg).info), (1, 1));

    // An authority `info` did not state is refused: a read is Corrupt, a commit Unknown.
    let wrong = h
        .open_store(
            "info-wrong",
            br#"{"authority":"wrong","commit_code":"time_guard_failed"}"#,
        )
        .unwrap_or_else(|e| panic!("open failed: {e:?}"));
    assert_eq!(
        h.block_on(read_one(&*wrong.backend)).err(),
        Some(Failure::Corrupt)
    );
    let (init, key) = initialization(&*wrong.backend);
    assert_eq!(
        h.block_on(wrong.backend.commit(init, key)).err(),
        Some(Failure::Unknown)
    );

    // FB_EPHEMERAL: the image is an ephemeral store, and an `info` answering DUR_LOCAL refuses the open.
    assert!(h.registry().ephemeral_stores().contains(&h.identity()));
    let dur = "c-store-info-dur";
    match h.open_store(
        "info-dur",
        format!(r#"{{"id":"{dur}","durability":"local"}}"#).as_bytes(),
    ) {
        Err(OpenError::Config { code, .. }) => assert_eq!(code, R_INVALID),
        Err(e) => panic!("not the durability refusal: {e:?}"),
        Ok(_) => panic!("an info durability that disagrees with FB_EPHEMERAL opened"),
    }
    assert_eq!(counts(dur).info, 1);
}
