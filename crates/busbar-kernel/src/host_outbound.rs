// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host custody for user-owned outbound authorizations. The plane supplies a public connection
//! identity once it has completed its protocol; the authenticated owner comes only from the live
//! unit. A bound request retains this host cell, never a credential or credential handle on the
//! plane wire. Revocation and replacement invalidate every earlier binding.
//!
//! This custody is process-local: restart requires enrollment again. No plaintext secret is
//! serialized into a plane record, and no restart can resurrect revoked credentials.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_contract::abi::host::service::{
    OUTBOUND_BIND, OUTBOUND_PUBLISH, OUTBOUND_PUBLISH_BODY, OUTBOUND_REVOKE,
};
use busbar_contract::auth_calls::AuthField;
use busbar_contract::services::{Caller, Incarnation, OutboundAuthorization};
use busbar_contract::Secret;

pub const REFUSED: &str = "outbound authorization is unavailable for this request";
const MAX_CONNECTIONS: usize = 4096;

/// One protected request body handed to the host exactly once, for a governed exchange.
/// It is consumed even if its destination check fails, and never enters an ordinary plane record.
pub struct Prepared {
    need: u32,
    member: String,
    resource: String,
    expires: u64,
    body: Secret<Vec<u8>>,
}

impl Prepared {
    pub fn new(ask: &OutboundAuthorization<'_>, now: u64) -> Option<Self> {
        if ask.expected_revision != 0
            || !ask.field_name.is_empty()
            || ask.expires_at_unix <= now
            || ask.credential.is_empty()
            || ask.credential.len() > 16_384
            || ask.member.is_empty()
            || ask.member.len() > 4096
            || ask.resource.is_empty()
            || ask.resource.len() > 4096
        {
            return None;
        }
        Some(Self {
            need: ask.need,
            member: ask.member.to_owned(),
            resource: ask.resource.to_owned(),
            expires: ask.expires_at_unix,
            body: Secret::new(ask.credential.to_vec()),
        })
    }

    pub fn take(
        self,
        need: u32,
        member: &str,
        resource: &str,
        now: u64,
    ) -> Option<Secret<Vec<u8>>> {
        (self.need == need
            && self.member == member
            && self.resource == resource
            && self.expires > now)
            .then_some(self.body)
    }
}

/// Bytes clones retain the zeroizing allocation until the connector releases its final borrow.
pub(crate) struct Body(pub Secret<Vec<u8>>);
impl AsRef<[u8]> for Body {
    fn as_ref(&self) -> &[u8] {
        self.0.expose(&crate::seal::lend())
    }
}

#[derive(Hash, PartialEq, Eq)]
struct Key {
    instance: Incarnation,
    owner: String,
    connection: String,
}

struct Entry {
    body: bool,
    revision: u64,
    expires: u64,
    need: u32,
    member: String,
    resource: String,
    field_name: String,
    credential: Option<Secret<Vec<u8>>>,
}

/// One request's host-retained binding. Its debug representation discloses no account metadata.
#[derive(Clone)]
pub struct Bound {
    entry: Arc<Mutex<Entry>>,
    revision: u64,
}

impl std::fmt::Debug for Bound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OutboundBinding").finish_non_exhaustive()
    }
}

/// Material delivered only to the governed host dispatcher, never the plane.
pub enum Presentation {
    Field(AuthField),
    Body(Secret<Vec<u8>>),
}

impl Bound {
    pub fn field(&self, need: u32, member: &str, resource: &str, now: u64) -> Option<AuthField> {
        match self.present(need, member, resource, now)? {
            Presentation::Field(field) => Some(field),
            Presentation::Body(_) => None,
        }
    }

    /// Linearize authorization for this dispatch against replacement/revocation. Already begun
    /// dispatches cannot be recalled, but every later attempt must take this lock again.
    pub fn present(
        &self,
        need: u32,
        member: &str,
        resource: &str,
        now: u64,
    ) -> Option<Presentation> {
        let row = self
            .entry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if row.revision != self.revision
            || row.expires <= now
            || row.need != need
            || row.member != member
            || row.resource != resource
        {
            return None;
        }
        if row.body {
            return Some(Presentation::Body(row.credential.clone()?));
        }
        Some(Presentation::Field(AuthField {
            name: row.field_name.as_bytes().to_vec(),
            value: row.credential.clone()?,
            sensitive: true,
            query: false,
            require_secure: true,
        }))
    }
}

#[derive(Default)]
pub struct Custody {
    entries: Mutex<HashMap<Key, Arc<Mutex<Entry>>>>,
}

impl Custody {
    /// Mutate only the authenticated owner's connection. `expected_revision` is a compare-and-swap
    /// fence, not authority. Tombstones remain bounded in this instance and cannot be re-enrolled:
    /// a new consent requires a new public connection identity.
    pub fn authorize(
        &self,
        caller: &Caller,
        owner: &str,
        ask: &OutboundAuthorization<'_>,
        now: u64,
    ) -> Result<(u64, Option<Bound>), &'static str> {
        if owner.is_empty()
            || ask.connection.is_empty()
            || ask.member.is_empty()
            || ask.resource.is_empty()
            || ask.connection.len() > 4096
            || ask.member.len() > 4096
            || ask.resource.len() > 4096
        {
            return Err(REFUSED);
        }
        let key = Key {
            instance: caller.incarnation().clone(),
            owner: owner.to_owned(),
            connection: ask.connection.to_owned(),
        };
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(ask.action, OUTBOUND_PUBLISH | OUTBOUND_PUBLISH_BODY) {
            let body = ask.action == OUTBOUND_PUBLISH_BODY;
            let valid = if body {
                ask.field_name.is_empty()
                    && !ask.credential.is_empty()
                    && ask.credential.len() <= 16_384
            } else {
                valid_field(ask.field_name, ask.credential)
            };
            if ask.expires_at_unix <= now || !valid {
                return Err(REFUSED);
            }
            if let Some(cell) = entries.get(&key) {
                let mut row = cell
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if row.revision != ask.expected_revision
                    || row.credential.is_none()
                    || row.body != body
                    || row.need != ask.need
                    || row.member != ask.member
                    || row.resource != ask.resource
                {
                    return Err(REFUSED);
                }
                let next = row.revision.checked_add(1).ok_or(REFUSED)?;
                row.revision = next;
                row.expires = ask.expires_at_unix;
                row.field_name = ask.field_name.to_owned();
                row.credential = Some(Secret::new(ask.credential.to_vec()));
                return Ok((next, None));
            }
            if ask.expected_revision != 0 || entries.len() >= MAX_CONNECTIONS {
                return Err(REFUSED);
            }
            entries.insert(
                key,
                Arc::new(Mutex::new(Entry {
                    body,
                    revision: 1,
                    expires: ask.expires_at_unix,
                    need: ask.need,
                    member: ask.member.to_owned(),
                    resource: ask.resource.to_owned(),
                    field_name: ask.field_name.to_owned(),
                    credential: Some(Secret::new(ask.credential.to_vec())),
                })),
            );
            return Ok((1, None));
        }
        if !ask.credential.is_empty() || !ask.field_name.is_empty() || ask.expires_at_unix != 0 {
            return Err(REFUSED);
        }
        if ask.action == OUTBOUND_REVOKE
            && ask.expected_revision == 0
            && !entries.contains_key(&key)
        {
            if entries.len() >= MAX_CONNECTIONS {
                return Err(REFUSED);
            }
            entries.insert(
                key,
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
            );
            return Ok((1, None));
        }
        let cell = entries.get(&key).ok_or(REFUSED)?;
        let mut row = cell
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if row.revision != ask.expected_revision
            || row.need != ask.need
            || row.member != ask.member
            || row.resource != ask.resource
            || row.credential.is_none()
        {
            return Err(REFUSED);
        }
        match ask.action {
            OUTBOUND_BIND if row.expires > now => Ok((
                row.revision,
                Some(Bound {
                    entry: Arc::clone(cell),
                    revision: row.revision,
                }),
            )),
            OUTBOUND_REVOKE => {
                row.revision = row.revision.checked_add(1).ok_or(REFUSED)?;
                row.credential = None;
                row.expires = 0;
                Ok((row.revision, None))
            }
            _ => Err(REFUSED),
        }
    }
}

fn valid_field(name: &str, value: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && busbar_contract::header::is_header_name_token(name.as_bytes())
        && ![
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "trailer",
            "upgrade",
        ]
        .iter()
        .any(|forbidden| name.eq_ignore_ascii_case(forbidden))
        && !busbar_contract::conn::is_sealed_fields_field(name.as_bytes())
        && !busbar_contract::conn::is_sealed_query_field(name.as_bytes())
        && !value.is_empty()
        && value.len() <= 16_384
        && value
            .iter()
            .all(|b| *b == b'\t' || (*b >= 0x20 && *b != 0x7f))
}

#[cfg(test)]
#[path = "host_outbound_tests.rs"]
mod tests;
