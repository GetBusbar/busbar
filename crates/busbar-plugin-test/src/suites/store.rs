// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store suite body (IF §14: C-STORE-INFO, C-STORE-COMMIT's SDK store cases). It admits the store image
//! through [`Harness`], opens it through `Registry::open_store` (the real adapter, so encode, decode, the entry
//! guard and zeroize run as in production) and drives the resulting `PersistenceBackend` with raw candidates.
//!
//! The slot-row cases come from `busbar_contract::abi::sdk::store::v4::conformance` (STORE-TRANSACTIONS §8
//! item 18: 8.1, 8.2, 8.2b, 8.2c, 8.3, 8.4); the cases written here are C13 and C20 plus the C-STORE-INFO
//! checks. Every case runs on its own instance, so the `config` must open an empty dataset on every open
//! (store-memory does; for a file-backed store write the instance name into the path with the literal token
//! `{instance}`, which the suite replaces in `config` before each open).
//!
//! The conformance module and the slot seal exist only under the `test-seal` feature (a plugin crate's
//! dev-dependency opt-in, STH-ROWS D-7); without it the suite panics with that instruction.

use crate::fake_needs::FakeNeeds;
use busbar_plugin_abi::plugin::Plugin;

#[cfg(feature = "test-seal")]
pub(crate) fn run_parameterized(
    host: &crate::store::StoreHarness,
    case: impl FnMut(&str) -> crate::store::StoreCase,
) {
    cases::run_parameterized(host, case);
}

pub(super) fn run(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds) {
    #[cfg(feature = "test-seal")]
    cases::run(plugin, config, needs);
    #[cfg(not(feature = "test-seal"))]
    {
        let _ = (plugin, config, needs);
        panic!(
            "suites::store needs busbar-plugin-test's `test-seal` feature (dev-dependency only): \
             the store adapter's kernel seal and the slot keys are minted by it"
        );
    }
}

#[cfg(feature = "test-seal")]
mod cases {
    use std::sync::Arc;

    use busbar_contract::abi::sdk::store::v4::conformance::{self as sdk, Subject};
    use busbar_contract::persistence::{
        control, Address, AttemptId, Candidate, CommitKey, Decision, Durability, ExpectedValue,
        Mutation, PersistenceBackend, Predicate, PreparedCandidate, Read, ReadResult, SelfFenced,
        CANDIDATE_VERSION,
    };
    use busbar_contract::plugin::TestKernelSeal;
    use busbar_contract::Secret;
    use busbar_plugin_abi::plugin::Plugin;
    use busbar_ports::store::StoreHandle;

    use crate::fake_needs::FakeNeeds;
    use crate::store::{StoreCase, StoreHarness};

    const NS: [u8; 16] = *b"suite.store.v1\0\0";
    const WRITER: [u8; 16] = [0xA1; 16];

    /// The opened store as the SDK cases' `Subject`. The plugin keeps its rows to itself, so the cases that
    /// count slot rows natively (8.10 no growth, counter wrap, 8.11) are the store crate's own native test.
    struct Live(StoreHandle);

    impl Subject for Live {
        fn backend(&self) -> &dyn PersistenceBackend {
            &*self.0.backend
        }
        fn slot_rows(&self, _writer: [u8; 16]) -> usize {
            unreachable!("the suite runs no case that counts slot rows")
        }
        fn jump_clock(&self, _seconds: u64) -> bool {
            false
        }
    }

    pub(super) fn run(plugin: &'static Plugin, config: &[u8], needs: FakeNeeds) {
        let host =
            StoreHarness::admit(plugin, needs).unwrap_or_else(|r| panic!("admit refused: {r:?}"));
        crate::store::run_suite(&host, |case| {
            let name = format!("store-{case}");
            StoreCase::new(name.clone(), config_for(config, &name))
        });
    }

    pub(super) fn run_parameterized(
        host: &StoreHarness,
        mut case_config: impl FnMut(&str) -> StoreCase,
    ) {
        let h = host.harness();

        // DRY_RUN open (`--validate`): bind and check, keep nothing.
        host.check(&case_config("check"))
            .unwrap_or_else(|e| panic!("check of the operator config failed: {e:?}"));

        let mut open = |case: &str| -> Live {
            Live(
                host.open(&case_config(case))
                    .unwrap_or_else(|e| panic!("open for {case} failed: {e:?}")),
            )
        };

        // C-STORE-INFO: the cached `info` is stable, names a dataset and clock authority, and the authority
        // that stamps a read is the one `info` declared.
        {
            let live = open("info");
            let b = live.backend();
            let info = b.info();
            assert_eq!(info, b.info(), "info is cached at open and never changes");
            assert!(
                matches!(
                    info.durability,
                    Durability::Ephemeral | Durability::Local | Durability::Quorum
                ),
                "durability"
            );
            match h.block_on(read(b, &at(b"absent"))) {
                ReadResult::Values {
                    observed_at,
                    values,
                } => {
                    assert_eq!(
                        observed_at.authority, info.clock_authority,
                        "READ_DONE authority"
                    );
                    assert!(values[0].is_none(), "an empty dataset holds nothing");
                }
                ReadResult::TimeGuardFailed { .. } => panic!("an unguarded read failed its guard"),
            }
        }

        // Slot mechanic (item 18): each case on a fresh instance.
        let live = open("8.1");
        h.block_on(sdk::detached_original_after_reuse(&live));
        drop(live);
        let live = open("8.2");
        h.block_on(sdk::initialize_lost_reply(&live));
        drop(live);
        let live = open("8.2b");
        h.block_on(sdk::initialize_race_lost_reply(&live));
        drop(live);
        let live = open("8.2c");
        h.block_on(sdk::register_race(&live));
        drop(live);
        let live = open("8.3");
        h.block_on(sdk::duplicate_and_conflict_replay(&live));
        drop(live);
        let live = open("8.4");
        h.block_on(sdk::zombie_fenced_in_doubt(&live));
        drop(live);

        // C13 and C20.
        let live = open("c13");
        h.block_on(c13_two_absent_puts(live.backend()));
        drop(live);
        let live = open("c20");
        h.block_on(c20_put_then_delete(live.backend()));
        drop(live);

        // Nothing the suite did may have been refused unnoticed.
        assert!(
            h.refusals().is_empty(),
            "an open or check was refused: {:?}",
            h.refusals()
        );
        h.assert_needs_declared("store");
        host.finish().expect("store socket target finished cleanly");
    }

    /// The operator config for instance `name`: `{instance}` becomes the name.
    fn config_for(config: &[u8], name: &str) -> Vec<u8> {
        const TOKEN: &[u8] = b"{instance}";
        let mut out = Vec::with_capacity(config.len());
        let mut i = 0;
        while i < config.len() {
            if config[i..].starts_with(TOKEN) {
                out.extend_from_slice(name.as_bytes());
                i += TOKEN.len();
            } else {
                out.push(config[i]);
                i += 1;
            }
        }
        out
    }

    fn at(key: &[u8]) -> Address {
        Address {
            namespace: NS,
            key: key.to_vec(),
        }
    }

    fn writer_at(writer: [u8; 16]) -> Address {
        Address {
            namespace: control::NAMESPACE.0,
            key: control::writer_key(writer).to_vec(),
        }
    }

    fn op(n: u64) -> [u8; 16] {
        let mut id = [0; 16];
        id[..8].copy_from_slice(&n.to_le_bytes());
        id[15] = 0x5D;
        id
    }

    fn candidate(
        b: &dyn PersistenceBackend,
        operation: [u8; 16],
        predicates: Vec<Predicate>,
        mutations: Vec<Mutation>,
    ) -> PreparedCandidate {
        PreparedCandidate::new(Candidate {
            id: AttemptId {
                dataset: b.info().dataset,
                writer_epoch: 1,
                writer: WRITER,
                execution_epoch: 1,
                operation,
            },
            codec: CANDIDATE_VERSION,
            predicates,
            mutations,
            time: None,
            result: Secret::new(Vec::new()),
        })
        .expect("valid suite candidate")
    }

    fn put(key: &[u8], value: &[u8]) -> Mutation {
        Mutation::Put {
            address: at(key),
            value: Secret::new(value.to_vec()),
        }
    }

    fn absent(key: &[u8]) -> Predicate {
        Predicate {
            address: at(key),
            expected: ExpectedValue::Absent,
        }
    }

    async fn commit(b: &dyn PersistenceBackend, c: &PreparedCandidate, key: CommitKey) -> Decision {
        b.commit(c.clone(), key)
            .await
            .expect("a definitive suite answer")
    }

    async fn read(b: &dyn PersistenceBackend, address: &Address) -> ReadResult {
        b.read(Arc::new(Read {
            dataset: b.info().dataset,
            addresses: vec![address.clone()],
            time: None,
        }))
        .await
        .expect("suite read")
    }

    async fn value(b: &dyn PersistenceBackend, address: Address) -> Option<Vec<u8>> {
        let ReadResult::Values { mut values, .. } = read(b, &address).await else {
            panic!("an unguarded read failed its guard");
        };
        values
            .pop()
            .flatten()
            .map(|secret| secret.expose(&TestKernelSeal).clone())
    }

    /// Initialize an empty dataset, registering [`WRITER`].
    async fn bootstrap(b: &dyn PersistenceBackend) {
        let init = sdk::initialization(b, WRITER, 1);
        let key =
            CommitKey::self_fenced(&SelfFenced::check(&init).expect("self-fenced initialization"));
        assert!(
            matches!(commit(b, &init, key).await, Decision::Applied(_)),
            "an empty dataset accepts its initialization"
        );
        assert!(value(b, writer_at(WRITER)).await.is_some(), "writer row");
    }

    /// C13: two `Absent(x), Put x` candidates: one APPLIED, one CONDITION_CONFLICT, and x holds the winner's value.
    async fn c13_two_absent_puts(b: &dyn PersistenceBackend) {
        bootstrap(b).await;
        let first = candidate(b, op(10), vec![absent(b"x")], vec![put(b"x", b"one")]);
        let second = candidate(b, op(11), vec![absent(b"x")], vec![put(b"x", b"two")]);
        assert!(matches!(
            commit(b, &first, sdk::slot(0, 1)).await,
            Decision::Applied(_)
        ));
        assert!(matches!(
            commit(b, &second, sdk::slot(1, 1)).await,
            Decision::ConditionConflict
        ));
        assert_eq!(value(b, at(b"x")).await.as_deref(), Some(&b"one"[..]));
    }

    /// C20: a Put then a Delete leaves no key.
    async fn c20_put_then_delete(b: &dyn PersistenceBackend) {
        bootstrap(b).await;
        let write = candidate(b, op(20), vec![], vec![put(b"gone", b"v")]);
        assert!(matches!(
            commit(b, &write, sdk::slot(0, 1)).await,
            Decision::Applied(_)
        ));
        assert_eq!(value(b, at(b"gone")).await.as_deref(), Some(&b"v"[..]));
        let delete = candidate(b, op(21), vec![], vec![Mutation::Delete(at(b"gone"))]);
        assert!(matches!(
            commit(b, &delete, sdk::slot(0, 2)).await,
            Decision::Applied(_)
        ));
        assert_eq!(value(b, at(b"gone")).await, None);
    }
}
