// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The strings an `Access` journal entry records for each purpose.
//!
//! `AccessPurpose::as_str` exists so the journal records a name that outlives this crate's enum:
//! an audit trail is read by things that never linked against this build, and "why was this secret
//! read" is the half of an access entry that makes it evidence rather than a counter. Every test
//! that asserts on journal contents compares `AccessPurpose` values, so all of them hold with
//! `as_str` returning the empty string for every purpose — an audit trail where the private key
//! read and the public CA bundle read are the same, indistinguishable entry.

use busbar_unit_transport_key::AccessPurpose;

/// Each purpose has its own stable, non-empty name, and no two share one.
#[test]
fn each_access_purpose_records_its_own_stable_name() {
    assert_eq!(AccessPurpose::Cert.as_str(), "cert");
    assert_eq!(AccessPurpose::Key.as_str(), "key");
    assert_eq!(AccessPurpose::ClientCa.as_str(), "client_ca");

    let all = [
        AccessPurpose::Cert,
        AccessPurpose::Key,
        AccessPurpose::ClientCa,
    ];
    for p in all {
        assert!(!p.as_str().is_empty(), "{p:?} records an empty name");
    }
    for (i, a) in all.iter().enumerate() {
        for b in &all[i + 1..] {
            assert_ne!(
                a.as_str(),
                b.as_str(),
                "{a:?} and {b:?} are indistinguishable in the journal"
            );
        }
    }
}
