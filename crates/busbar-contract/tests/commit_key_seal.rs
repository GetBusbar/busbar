// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! LINT-RULES R9 `commit-outside-slot-facade`: a store commit crosses only through custody. Every
//! `PersistenceBackend::commit` takes a `CommitKey` by value, and only the kernel's commit root
//! (`busbar-kernel` `persistence::commit`) and the migration library's grant mint one, so a raw
//! commit anywhere else does not compile. The constructor and `Clone` refusals are the
//! `compile_fail` examples on `CommitKey` and `CommitRoot` (`src/persistence.rs`).

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
