// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`crate::host_outbound`]'s enrollment verbs: publishing (or re-publishing) a user's outbound
//! credential and recording a revocation tombstone. Each runs once per consent or revocation, never
//! per governed request; the per-request bind only looks the stored row up and copies nothing.

use std::sync::{Arc, Mutex};

use busbar_contract::services::OutboundAuthorization;
use busbar_contract::Secret;

use crate::host_outbound::{Entry, Key, KeyRef};

/// The host's own copy of a published credential, kept until revocation or replacement.
pub(crate) fn credential(credential: &[u8]) -> Secret<Vec<u8>> {
    Secret::new(credential.to_vec())
}

/// The stored identity of a newly enrolled (or tombstoned) connection.
fn key_of(key: &KeyRef<'_>) -> Key {
    Key {
        instance: key.instance.clone(),
        owner: key.owner.to_owned(),
        connection: key.connection.to_owned(),
    }
}

/// A newly enrolled connection's row at revision 1.
pub(crate) fn enrolled(
    key: &KeyRef<'_>,
    ask: &OutboundAuthorization<'_>,
    body: bool,
) -> (Key, Arc<Mutex<Entry>>) {
    (
        key_of(key),
        Arc::new(Mutex::new(Entry {
            body,
            revision: 1,
            expires: ask.expires_at_unix,
            need: ask.need,
            member: ask.member.to_owned(),
            resource: ask.resource.to_owned(),
            field_name: ask.field_name.to_owned(),
            credential: Some(credential(ask.credential)),
        })),
    )
}

/// A revocation tombstone for a connection never enrolled here: it can never be re-enrolled.
pub(crate) fn tombstone(
    key: &KeyRef<'_>,
    ask: &OutboundAuthorization<'_>,
) -> (Key, Arc<Mutex<Entry>>) {
    (
        key_of(key),
        Arc::new(Mutex::new(Entry {
            body: false,
            revision: 1,
            expires: 0,
            need: ask.need,
            member: ask.member.to_owned(),
            resource: ask.resource.to_owned(),
            field_name: String::new(),
            credential: None,
        })),
    )
}
