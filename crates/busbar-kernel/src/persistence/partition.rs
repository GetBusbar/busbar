// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Deterministic opaque namespace assignment by core, independent of backend names.
//! Full partition identity remains in record keys/metadata: a hash collision can
//! cause extra contention, never alias two business records or grant authority.

use busbar_contract::persistence::NamespaceId;
use sha2::{Digest, Sha256};

pub(crate) fn namespace(owner: NamespaceId, parts: &[&[u8]]) -> NamespaceId {
    let mut hash = Sha256::new();
    hash.update(b"busbar.persistence.partition/1\0");
    hash.update(owner.0);
    hash.update((parts.len() as u64).to_be_bytes());
    for part in parts {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    let digest = hash.finalize();
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest[..16]);
    // Reserved adapter-control and fixed core namespaces are ASCII. Derived
    // namespaces cannot collide with those privileged addresses.
    bytes[0] |= 0x80;
    NamespaceId(bytes)
}
