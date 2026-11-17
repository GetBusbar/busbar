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

#[cfg(feature = "test-seal")]
#[test]
fn typed_store_conversion_settles_an_unchanged_bag_and_retains_settled_config() {
    use busbar_plugin_test::store::{StoreCase, StoreHarness};
    use busbar_plugin_test::suites::harness::OpenPurpose;

    let h = StoreHarness::admit(inline::PLUGIN.plugin(), FakeNeeds::new()).expect("admit");
    let current = StoreCase::new("current", b"{}".to_vec());
    drop(h.open(&current).expect("canonical open needs no CONFIG"));
    let absent = StoreCase::new("missing-config", b"{}".to_vec());
    // #432: a converting open with no CONFIG answer is "unchanged"; core settles the bag as bound.
    drop(
        h.open_converting(&absent)
            .expect("a converting open with no CONFIG is unchanged"),
    );
    let unchanged = h
        .harness()
        .settled("missing-config")
        .expect("core settles the unchanged bag");
    assert_eq!(unchanged.config_json.as_slice(), b"{}");
    let converting = StoreCase::new("converted", br#"{"settle":true}"#.to_vec());
    drop(
        h.open_converting(&converting)
            .expect("conversion with CONFIG"),
    );
    let settled = h.harness().settled("converted").expect("settled CONFIG");
    assert_eq!(settled.config_json.as_slice(), br#"{"canonical":true}"#);

    let mut spec = h.harness().spec("generic-conversion", &converting.config);
    spec.purpose = OpenPurpose::ConvertUnstamped;
    spec.limits = converting.limits;
    drop(h.harness().open_spec(&spec).expect("generic conversion"));
    assert!(h.harness().settled("generic-conversion").is_some());
}

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

/// The public plugin-test facade installs its test-only store authority internally: a plugin's live test
/// opens and reads a typed store without importing busbar-contract or minting a KernelSeal itself.
#[test]
fn public_store_host_opens_and_reads_without_a_caller_seal() {
    use busbar_plugin_test::store::{Address, Read, ReadResult, StoreCase, StoreHarness};
    let host =
        StoreHarness::admit(inline::PLUGIN.plugin(), FakeNeeds::new()).expect("store admission");
    let case = StoreCase::new(
        "valid_schema_8_1",
        br#"{"id":"public-store-host"}"#.to_vec(),
    );
    host.check(&case).expect("check");
    let store = host
        .open(&case)
        .expect("test authority is installed by the facade");
    let info = store.backend.info();
    let answer = host
        .block_on(store.backend.read(std::sync::Arc::new(Read {
            dataset: info.dataset,
            addresses: vec![Address {
                namespace: [7; 16],
                key: b"absent".to_vec(),
            }],
            time: None,
        })))
        .expect("typed store read");
    match answer {
        ReadResult::Values {
            observed_at,
            values,
        } => {
            assert_eq!(observed_at.authority, info.clock_authority);
            assert_eq!(values.len(), 1);
            assert!(values[0].is_none());
        }
        ReadResult::TimeGuardFailed { .. } => panic!("unguarded read failed"),
    }
    drop(store);
    host.finish()
        .expect("live target completion is part of facade finish");
}

#[test]
fn typed_store_check_keeps_endpoints_and_check_open_keep_refusals() {
    use busbar_plugin_test::fake_needs::ConnScript;
    use busbar_plugin_test::store::{StoreCase, StoreHarness};

    let mut needs = FakeNeeds::new();
    needs.conn(observation_fixture::DEST, ConnScript::new().eof());
    let host = StoreHarness::admit(observation_fixture::PLUGIN.plugin(), needs)
        .expect("endpoint store admission");
    let case = StoreCase::new(
        "store_observation",
        br#"{"id":"store-observation"}"#.to_vec(),
    );
    host.check(&case).expect("declares the connection endpoint");
    let store = host.open(&case).expect("opens the scripted connection");
    assert_eq!(
        host.harness().declared().len(),
        1,
        "typed check keeps ENDPOINT"
    );
    assert_eq!(
        host.harness().seen().len(),
        1,
        "the store really issued OPEN"
    );
    host.harness()
        .assert_needs_declared("typed-store-observation");
    assert!(host.harness().refusals().is_empty());
    drop(store);
    host.finish().expect("all store connections released");

    // Intentional negative operations have their own host, preserving the successful suite's accounting.
    let refused = StoreHarness::admit(inline::PLUGIN.plugin(), FakeNeeds::new())
        .expect("refusal store admission");
    let invalid = StoreCase::new("invalid_store", b"null".to_vec());
    assert!(refused.check(&invalid).is_err());
    assert_eq!(
        refused.harness().refusals().len(),
        1,
        "check refusal recorded"
    );
    assert!(refused.open(&invalid).is_err());
    assert_eq!(
        refused.harness().refusals().len(),
        2,
        "open refusal recorded"
    );
    refused
        .finish()
        .expect("no live operations on refused host");
}

mod observation_fixture {
    use busbar_plugin_abi::fail::Fail;
    use busbar_plugin_abi::host::Host;
    use busbar_plugin_abi::need::{egress, need, need_flag, ChainBytes, TrustHandle};
    use busbar_plugin_abi::plugin::{Describe, Endpoints, Open};
    use busbar_plugin_abi::records::{Out, Reply};
    use busbar_plugin_abi::Store;

    use crate::min3_store::Fixture;

    pub const DEST: &str = "store.example:5432";
    pub struct ObservedStore(Fixture<0>);

    impl Open for ObservedStore {
        async fn open(h: &'static Host, config: ChainBytes) -> Result<Self, Fail> {
            let store = Fixture::<0>::open(h, config).await?;
            let opened = need::open(
                DEST,
                need::Tls::Required {
                    sni: "store.example",
                    alpn: &[],
                    trust: TrustHandle(0),
                },
                egress::OPERATOR_INFRASTRUCTURE,
            )
            .await?;
            need::close(opened.conn, false).await?;
            Ok(Self(store))
        }

        fn check(h: &Host, config: &[u8], ends: &mut Endpoints<'_>) -> Result<(), Fail> {
            Fixture::<0>::check(h, config, ends)?;
            ends.open(
                DEST,
                need_flag::TLS_REQUIRED,
                egress::OPERATOR_INFRASTRUCTURE,
            );
            Ok(())
        }

        fn describe(d: &mut Describe<'_>) {
            Fixture::<0>::describe(d);
        }
    }

    impl Store for ObservedStore {
        async fn read(&self, _h: &'static Host, _req: ChainBytes) -> Result<Reply, Fail> {
            Err(Fail::unsupported())
        }
        async fn scan(&self, _h: &'static Host, _req: ChainBytes) -> Result<Reply, Fail> {
            Err(Fail::unsupported())
        }
        async fn commit(&self, _h: &'static Host, _req: ChainBytes) -> Result<Reply, Fail> {
            Err(Fail::unsupported())
        }
        async fn clock(&self, _h: &'static Host, _req: ChainBytes) -> Result<Reply, Fail> {
            Err(Fail::unsupported())
        }
        fn info(&self, h: &Host, out: &mut Out<'_>) -> Result<(), Fail> {
            self.0.info(h, out)
        }
    }

    busbar_plugin_abi::plugin!(Store, ObservedStore, name: "fixture-observed-store");
}
