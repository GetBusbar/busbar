// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINT-RULES R9 `commit-outside-slot-facade`: a store commit crosses only through custody. Every
//! `PersistenceBackend::commit` takes a `CommitKey` by value, and a key is minted only as a slotted
//! key under the kernel's `SlotSeal` or as a self-fenced key from a checked `SelfFenced` proof
//! (`src/persistence/commit_key.rs`, STORE-TRANSACTIONS), so a raw commit elsewhere does not compile.

use busbar_contract::persistence::{
    Call, CommitKey, Decision, PersistenceBackend, PreparedCandidate,
};

/// The commit signature names the key: a call without one is a type error.
#[test]
fn a_commit_takes_a_key_by_value() {
    fn commit<'a>(
        backend: &'a dyn PersistenceBackend,
        candidate: PreparedCandidate,
        key: CommitKey,
    ) -> Call<'a, Decision> {
        backend.commit(candidate, key)
    }
    let _: for<'a> fn(
        &'a dyn PersistenceBackend,
        PreparedCandidate,
        CommitKey,
    ) -> Call<'a, Decision> = commit;
}
