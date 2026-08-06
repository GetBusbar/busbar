// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The shared [`busbar_api::Store`] contract conformance suite (`busbar-plugin-testkit`).
//!
//! Core's own reference backend runs it alongside every plugin backend on purpose: these checks
//! exist because the fleet had silently disagreed with itself about all four behaviours, and a suite
//! the reference implementation is exempt from is a suite nobody has to agree with.
//!
//! `append_audit` is not covered here — `MemoryStore` deliberately takes the trait's defaulted no-op
//! (memory = ephemeral audit, see the trait doc), so there is no durable behaviour to conform to.
//!
//! Its own file rather than a second inline `mod` in `src/lib.rs`, per the repo's test-locality rule
//! (at most one inline test body per file; see `docs/code-layout.md`).

use busbar_plugin_testkit::store_conformance as conf;
use busbar_store_memory::MemoryStore;

// A fresh MemoryStore per check is already an empty namespace, so `ns` only has to be stable.

#[test]
fn put_key_does_not_resurrect_a_tombstone() {
    conf::assert_put_key_does_not_resurrect_a_tombstone(&MemoryStore::new(), "conf");
}

#[test]
fn delete_key_unknown_id_is_an_error() {
    conf::assert_delete_key_unknown_id_is_an_error(&MemoryStore::new(), "conf");
}

#[test]
fn revoke_credential_unknown_id_is_an_error() {
    conf::assert_revoke_credential_unknown_id_is_an_error(&MemoryStore::new(), "conf");
}
