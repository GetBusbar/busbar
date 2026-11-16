// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-POOL-KEY (ABI-MIN3-INTERFACE §14): Conn pool keys (rounds 4 and 11; C1's suite).
//!
//! Every arm runs in busbar-core-connector, beside the MIN-3 pool key it pins (`need::key::NeedKey`, the IF's
//! `PoolKey`, and `NeedPool`, generic over its hasher). That crate is not a dependency of this one, and no
//! production item is widened for a test (SDK-SAFE-TEST-HOST), so the arms moved there (WBS rule 10: the
//! owner's crate):
//!
//! - TEST-VALUE `sni_cert_or_trust_alone_never_share_a_conn` (round 4):
//!   `busbar_core_connector::need::key::tests::keys_differing_in_one_part_never_share_a_conn` (keys differing
//!   only in SNI, ALPN, client cert digest, trust digest, class, TLS state or dest never take another's conn).
//! - TEST-VALUE `a_constant_hasher_never_reuses_another_dests_conn` (round 11): the same test, over a
//!   `BuildHasher` that hashes every key alike (`One`): `db:5433`, another SNI and another ALPN are never
//!   lent the `db:5432` conn, which is lent again to its own key. On a miss `HostNeeds::open` judges and dials
//!   afresh (need.rs; the judge is `need::judge::tests`).
//! - TEST-VALUE `pool_key_has_no_u64_hash_and_production_uses_random_state` (round 11):
//!   `busbar_core_connector::need::key::tests::pool_key_has_no_u64_hash_and_production_uses_random_state`.
