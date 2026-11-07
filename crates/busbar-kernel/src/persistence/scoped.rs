// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-only scoped persistence. Construct from trusted instance/schema declarations,
//! never from a plugin's claimed authority. Confidential values remain inline under
//! secret custody; this API does not encode the bounded plane transaction carrier.

use super::{
    facade::{CoreStore, PendingId},
    host_records::HostRecords,
};
use busbar_contract::{
    persistence::{
        ExpectedValue, Mutation as NativeMutation, NamespaceId, Predicate as NativePredicate,
    },
    Secret,
};
use std::{collections::BTreeSet, sync::Arc};

pub use super::claims::{Error as ClaimError, Outcome as ClaimOutcome, PendingClaim};
pub use super::host_records::{Error, Outcome};

/// Canonical destination identity for a fenced host-owned migration. The caller
/// supplies the authenticated legacy instance and unscoped logical suffix; this
/// pure helper grants no live backend access or schema authorization.
pub fn migration_address(
    private: bool,
    instance: &str,
    schema: &str,
    logical_key: &[u8],
) -> Result<busbar_contract::persistence::Address, Error> {
    u16::try_from(instance.len()).map_err(|_| Error::Invalid)?;
    let scope = crate::host_records::record_key(instance, &[]);
    let key = crate::host_records::record_key(instance, logical_key);
    let namespace = if private {
        super::host_records::HOST_RECORDS
    } else {
        super::host_records::RECORDS
    };
    super::host_records::scoped_address(namespace, &scope, schema, &key)
}

/// Validate a migration row against one compiled instance/schema binding.
pub fn migration_authorizes(
    private: bool,
    instance: &str,
    schema: &str,
    address: &busbar_contract::persistence::Address,
) -> bool {
    if u16::try_from(instance.len()).is_err() {
        return false;
    }
    let namespace = if private {
        super::host_records::HOST_RECORDS
    } else {
        super::host_records::RECORDS
    };
    let Ok(frame) = super::keys::framed(b'R', &[&namespace.0, schema.as_bytes()]) else {
        return false;
    };
    let scope = crate::host_records::record_key(instance, &[]);
    let Some(logical_key) = address
        .key
        .strip_prefix(frame.as_slice())
        .and_then(|key| key.strip_prefix(scope.as_slice()))
    else {
        return false;
    };
    migration_address(private, instance, schema, logical_key)
        .is_ok_and(|expected| expected == *address)
}

/// Native rows produced by the trusted historical claim codec.
pub type MigrationRows = Vec<(busbar_contract::persistence::Address, Secret<Vec<u8>>)>;

/// Preserve a historically consumed claim with its original absolute expiry.
pub fn migration_claim_rows(
    instance: &str,
    kind: &str,
    token: &str,
    expires_at: u64,
) -> Result<MigrationRows, ClaimError> {
    super::claims::migration_rows(instance, kind, token, expires_at)
}
pub fn migration_claim_authorizes(
    instance: &str,
    kind: &str,
    address: &busbar_contract::persistence::Address,
) -> bool {
    super::claims::migration_authorizes(instance, kind, address)
}

/// Owned form of the existing bounded claim maintenance cursor.
pub type ClaimSweep = super::claims::Sweep<'static>;
pub use super::claims::SweepOutcome as ClaimSweepOutcome;

#[derive(Debug)]
pub enum Expected {
    Absent,
    Exact(Secret<Vec<u8>>),
}
#[derive(Debug)]
pub struct Predicate {
    pub schema: String,
    pub key: Vec<u8>,
    pub expected: Expected,
}
#[derive(Debug)]
pub enum Mutation {
    Put {
        schema: String,
        key: Vec<u8>,
        value: Secret<Vec<u8>>,
    },
    Delete {
        schema: String,
        key: Vec<u8>,
    },
    DeleteRange {
        schema: String,
        prefix: Vec<u8>,
        exact_key_length: u64,
    },
}
#[derive(Debug)]
pub struct Request {
    pub op_id: [u8; 16],
    pub predicates: Vec<Predicate>,
    pub mutations: Vec<Mutation>,
}

/// Continuations are bound to their original schema, prefix and generation.
#[derive(Debug, Clone)]
pub struct Cursor {
    dataset: busbar_contract::persistence::DatasetId,
    instance: String,
    private: bool,
    schema: String,
    prefix: Vec<u8>,
    inner: super::host_records::Cursor,
}
#[derive(Debug)]
pub struct Page {
    pub generation: u64,
    pub rows: Vec<(Vec<u8>, Secret<Vec<u8>>)>,
    pub next: Option<Cursor>,
}

#[derive(Clone)]
pub struct ScopedStore {
    store: Arc<CoreStore>,
    instance: String,
    schemas: BTreeSet<String>,
    private: bool,
}
impl ScopedStore {
    /// The host has already authenticated this instance and authorized its schemas.
    pub fn host_private(
        store: Arc<CoreStore>,
        instance: &str,
        schemas: impl IntoIterator<Item = String>,
    ) -> Result<Self, Error> {
        Self::new(store, instance, schemas, true)
    }
    /// Bind the normal instance record namespace after host authorization.
    pub fn authorized(
        store: Arc<CoreStore>,
        instance: &str,
        schemas: impl IntoIterator<Item = String>,
    ) -> Result<Self, Error> {
        Self::new(store, instance, schemas, false)
    }
    fn new(
        store: Arc<CoreStore>,
        instance: &str,
        schemas: impl IntoIterator<Item = String>,
        private: bool,
    ) -> Result<Self, Error> {
        let result = Self {
            store,
            instance: instance.into(),
            schemas: schemas.into_iter().collect(),
            private,
        };
        result.owner()?;
        Ok(result)
    }
    fn owner(&self) -> Result<HostRecords<'_>, Error> {
        if self.private {
            HostRecords::host_private(
                &self.store,
                &self.instance,
                self.schemas.iter().map(String::as_str),
            )
        } else {
            HostRecords::authorized(
                &self.store,
                &self.instance,
                self.schemas.iter().map(String::as_str),
            )
        }
    }
    fn key(&self, key: &[u8]) -> Vec<u8> {
        crate::host_records::record_key(&self.instance, key)
    }
    pub async fn get(&self, schema: &str, key: &[u8]) -> Result<Option<Secret<Vec<u8>>>, Error> {
        self.owner()?.get(schema, &self.key(key)).await
    }
    pub async fn read(
        &self,
        keys: &[(&str, &[u8])],
    ) -> Result<Vec<Option<Secret<Vec<u8>>>>, Error> {
        let scoped: Vec<_> = keys
            .iter()
            .map(|(schema, key)| (*schema, self.key(key)))
            .collect();
        self.owner()?
            .read(
                &scoped
                    .iter()
                    .map(|(s, k)| (*s, k.as_slice()))
                    .collect::<Vec<_>>(),
            )
            .await
    }
    pub async fn put(
        &self,
        schema: &str,
        key: &[u8],
        value: Secret<Vec<u8>>,
    ) -> Result<Outcome, Error> {
        self.owner()?.put(schema, &self.key(key), value).await
    }
    pub async fn delete(&self, schema: &str, key: &[u8]) -> Result<Outcome, Error> {
        self.owner()?.delete(schema, &self.key(key)).await
    }
    /// Prepare a guarded deletion before awaiting; retain this request across
    /// cancellation and resubmit it to rediscover the original pending attempt.
    pub fn prepare_delete_exact(
        &self,
        schema: &str,
        key: &[u8],
        expected: Secret<Vec<u8>>,
    ) -> Result<Request, Error> {
        // Authorization is checked before returning an operation capability.
        self.owner()?.address(schema, &self.key(key))?;
        Ok(Request {
            op_id: self.store.next_id()?.operation,
            predicates: vec![Predicate {
                schema: schema.into(),
                key: key.into(),
                expected: Expected::Exact(expected),
            }],
            mutations: vec![Mutation::Delete {
                schema: schema.into(),
                key: key.into(),
            }],
        })
    }
    pub async fn page(
        &self,
        schema: &str,
        prefix: &[u8],
        after: Option<&Cursor>,
    ) -> Result<Page, Error> {
        if after.is_some_and(|c| {
            c.dataset != self.store.info().dataset
                || c.instance != self.instance
                || c.private != self.private
                || c.schema != schema
                || c.prefix != prefix
        }) {
            return Err(Error::Unauthorized);
        }
        let page = self
            .owner()?
            .scan(schema, &self.key(prefix), after.map(|c| &c.inner))
            .await?;
        let skip = self.key(&[]).len();
        Ok(Page {
            generation: page.generation,
            rows: page
                .rows
                .into_iter()
                .map(|(key, value)| (key[skip..].to_vec(), value))
                .collect(),
            next: page.next.map(|inner| Cursor {
                dataset: self.store.info().dataset,
                instance: self.instance.clone(),
                private: self.private,
                schema: schema.into(),
                prefix: prefix.into(),
                inner,
            }),
        })
    }
    pub async fn retry(&self, id: PendingId) -> Result<Outcome, Error> {
        self.owner()?.retry(id).await
    }
    /// Native predicates and mutations have storage carrier bounds, independently
    /// of the 512-byte plane record and 16-MiB plane transaction transport.
    pub async fn conditional_native(&self, request: &Request) -> Result<Outcome, Error> {
        self.conditional_native_timed(request, None).await
    }
    /// Host-owned temporal conditions enter the immutable logical fingerprint.
    /// Matching receipts remain replayable after the original interval closes.
    pub async fn conditional_native_timed(
        &self,
        request: &Request,
        time: Option<busbar_contract::persistence::TimeGuard>,
    ) -> Result<Outcome, Error> {
        let owner = self.owner()?;
        let predicates = request
            .predicates
            .iter()
            .map(|p| {
                Ok(NativePredicate {
                    address: owner.address(&p.schema, &self.key(&p.key))?,
                    expected: match &p.expected {
                        Expected::Absent => ExpectedValue::Absent,
                        Expected::Exact(v) => ExpectedValue::Exact(v.clone()),
                    },
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mutations = request
            .mutations
            .iter()
            .map(|m| {
                Ok(match m {
                    Mutation::Put { schema, key, value } => NativeMutation::Put {
                        address: owner.address(schema, &self.key(key))?,
                        value: value.clone(),
                    },
                    Mutation::Delete { schema, key } => {
                        NativeMutation::Delete(owner.address(schema, &self.key(key))?)
                    }
                    Mutation::DeleteRange {
                        schema,
                        prefix,
                        exact_key_length,
                    } => {
                        let address = owner.address(schema, &self.key(prefix))?;
                        let overhead = address
                            .key
                            .len()
                            .checked_sub(prefix.len())
                            .ok_or(Error::Invalid)?;
                        NativeMutation::DeleteRange {
                            namespace: NamespaceId(address.namespace),
                            prefix: address.key,
                            exact_key_length: exact_key_length
                                .checked_add(u64::try_from(overhead).map_err(|_| Error::Invalid)?)
                                .ok_or(Error::Invalid)?,
                        }
                    }
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        owner
            .conditional_native_timed(request.op_id, predicates, mutations, time)
            .await
    }
    /// Register this host scope with the attachment's shared maintenance owner.
    pub fn register_claims(&self, kind: &str) -> Result<(), ClaimError> {
        self.store.register_claim_scope(&self.instance, kind)
    }
    /// Advance one registered claim scope, retaining its cursor on cancellation.
    pub async fn sweep_claims(&self) -> Result<Option<ClaimSweepOutcome>, ClaimError> {
        self.store.sweep_claim_scope().await
    }

    /// Retain this cursor across maintenance ticks and caller cancellation.
    pub fn claim_sweeper(&self, kind: &str) -> Result<ClaimSweep, ClaimError> {
        super::claims::owned_sweep(Arc::clone(&self.store), &self.instance, kind)
    }

    pub async fn redeem(
        &self,
        kind: &str,
        token: &str,
        expires_at: u64,
    ) -> Result<ClaimOutcome, ClaimError> {
        super::claims::Claims::authorized(&self.store, &self.instance, kind)
            .redeem(token, expires_at)
            .await
    }
    pub async fn retry_claim(
        &self,
        kind: &str,
        claim: PendingClaim,
    ) -> Result<ClaimOutcome, ClaimError> {
        super::claims::Claims::authorized(&self.store, &self.instance, kind)
            .retry(claim)
            .await
    }
}
