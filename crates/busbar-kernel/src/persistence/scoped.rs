// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-only scoped persistence. Construct from trusted instance/schema declarations,
//! never from a plugin's claimed authority. Confidential values remain inline under
//! secret custody; this API does not encode the bounded plane transaction carrier.

use super::{
    facade::{CoreStore, DomainCall, DomainOwner, PendingId},
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
pub use super::record_ops::{HeldOp, Op};

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
    /// The receipt identity: a held class-M op, or the class-D principal-transition op.
    pub op: Op,
    pub predicates: Vec<Predicate>,
    pub mutations: Vec<Mutation>,
}

/// Non-submittable rows authorized by one trusted host-private scope. The
/// eventual submit owner must use the original attachment and writer authority.
/// No Record maintenance domain owns or collects these rows.
pub struct PreparedRows {
    store: Arc<CoreStore>,
    authority: super::facade::WriterAuthority,
    predicates: Vec<NativePredicate>,
    mutations: Vec<NativeMutation>,
}

impl PreparedRows {
    pub(crate) fn into_parts(
        self,
        store: &CoreStore,
    ) -> Result<(Vec<NativePredicate>, Vec<NativeMutation>), Error> {
        // The same attachment fixes dataset, atomic domain and native backend,
        // in addition to the independently checked current writer authority.
        if !std::ptr::eq(self.store.as_ref(), store) || self.authority != store.authority()? {
            return Err(Error::Unauthorized);
        }
        Ok((self.predicates, self.mutations))
    }
}

/// What a lent predicate expects at its address: the bytes stay with the caller.
#[derive(Clone, Copy)]
pub enum ExpectedRow<'a> {
    Absent,
    Exact(&'a [u8]),
}

/// One predicate of a conditional request, lent: the caller keeps the schema, the key and the
/// expected bytes, and the scope reads them once, as it forms the store's row. A caller that
/// holds its request as facts (a ticket, its expiry) lends rows over them and copies nothing.
/// No `Debug`: the expected bytes are record bytes.
#[derive(Clone, Copy)]
pub struct PredicateRow<'a> {
    pub schema: &'a str,
    pub key: &'a [u8],
    pub expected: ExpectedRow<'a>,
}

/// One mutation of a conditional request, lent as [`PredicateRow`] is.
#[derive(Clone, Copy)]
pub enum MutationRow<'a> {
    Put {
        schema: &'a str,
        key: &'a [u8],
        value: &'a [u8],
    },
    Delete {
        schema: &'a str,
        key: &'a [u8],
    },
    DeleteRange {
        schema: &'a str,
        prefix: &'a [u8],
        exact_key_length: u64,
    },
}

impl Predicate {
    /// This predicate, lent: its expected bytes are read under `seal`.
    fn row<'a>(
        &'a self,
        seal: &busbar_contract::caps::Grant<busbar_contract::caps::Sign>,
    ) -> PredicateRow<'a> {
        PredicateRow {
            schema: &self.schema,
            key: &self.key,
            expected: match &self.expected {
                Expected::Absent => ExpectedRow::Absent,
                Expected::Exact(value) => ExpectedRow::Exact(value.expose(seal)),
            },
        }
    }
}

impl Mutation {
    /// This mutation, lent: a put's value is read under `seal`.
    fn row<'a>(
        &'a self,
        seal: &busbar_contract::caps::Grant<busbar_contract::caps::Sign>,
    ) -> MutationRow<'a> {
        match self {
            Mutation::Put { schema, key, value } => MutationRow::Put {
                schema,
                key,
                value: value.expose(seal),
            },
            Mutation::Delete { schema, key } => MutationRow::Delete { schema, key },
            Mutation::DeleteRange {
                schema,
                prefix,
                exact_key_length,
            } => MutationRow::DeleteRange {
                schema,
                prefix,
                exact_key_length: *exact_key_length,
            },
        }
    }
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
    domain: Option<DomainCall>,
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
            domain: None,
        };
        result.owner()?;
        Ok(result)
    }
    fn owner(&self) -> Result<HostRecords<'_>, Error> {
        let owner = if self.private {
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
        }?;
        owner.in_domain(self.domain.as_ref())
    }

    /// Bind one operation's foreground reservation to the exact durable owner.
    pub(crate) fn in_domain(mut self, owner: &DomainOwner) -> Result<Self, Error> {
        if !owner.owns(&self.store) {
            return Err(Error::Unauthorized);
        }
        self.domain = Some(owner.call());
        Ok(self)
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
    pub async fn prepare_delete_exact(
        &self,
        schema: &str,
        key: &[u8],
        expected: Secret<Vec<u8>>,
    ) -> Result<Request, Error> {
        // Authorization is checked before returning an operation capability.
        self.owner()?.address(schema, &self.key(key))?;
        Ok(Request {
            op: self.store.record_op().await?.into(),
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
    /// A class-M receipt identity for one request of this scope (DES-264): the request holds it.
    pub async fn record_op(&self) -> Result<Op, Error> {
        Ok(self.store.record_op().await?.into())
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
        let (predicates, mutations) = {
            let seal = crate::seal::lend();
            self.native_rows(
                request.predicates.iter().map(|p| p.row(&seal)),
                request.mutations.iter().map(|m| m.row(&seal)),
                None,
            )?
        };
        self.owner()?
            .conditional_native_timed(&request.op, predicates, mutations, time)
            .await
    }
    /// [`Self::conditional_native_timed`] for a caller that keeps its request as facts and lends
    /// the rows over them: the same submit under the same receipt identity `op`. The rows are
    /// read once, before the first wait; the store's own rows are formed from them as they are
    /// from an owned [`Request`].
    pub async fn conditional_rows_timed(
        &self,
        op: &Op,
        predicates: &[PredicateRow<'_>],
        mutations: &[MutationRow<'_>],
        time: Option<busbar_contract::persistence::TimeGuard>,
    ) -> Result<Outcome, Error> {
        let (predicates, mutations) =
            self.native_rows(predicates.iter().copied(), mutations.iter().copied(), None)?;
        self.owner()?
            .conditional_native_timed(op, predicates, mutations, time)
            .await
    }

    /// Validate addresses without claiming or submitting an operation. The
    /// composition owner supplies its own exact attempt and durable receipt.
    /// The rows carry no operation identity; the composition owner's attempt is the receipt.
    /// `max_bytes` bounds retained row structs/keys/values incrementally; it is
    /// caller-owned memory backpressure, not a native permanent capacity verdict.
    pub fn prepare_participant(
        &self,
        predicates: &[Predicate],
        mutations: &[Mutation],
        max_bytes: usize,
    ) -> Result<PreparedRows, Error> {
        if !self.private || self.domain.is_some() {
            return Err(Error::Unauthorized);
        }
        let authority = self.store.authority()?;
        let seal = crate::seal::lend();
        let (predicates, mutations) = self.native_rows(
            predicates.iter().map(|p| p.row(&seal)),
            mutations.iter().map(|m| m.row(&seal)),
            Some(max_bytes),
        )?;
        Ok(PreparedRows {
            store: self.store.clone(),
            authority,
            predicates,
            mutations,
        })
    }

    /// The store's own rows for the lent rows, in their order: each address is formed under
    /// this scope, and each expected or put value is copied once, into the row the store keeps.
    fn native_rows<'r>(
        &self,
        predicates: impl Iterator<Item = PredicateRow<'r>>,
        mutations: impl Iterator<Item = MutationRow<'r>>,
        max_bytes: Option<usize>,
    ) -> Result<(Vec<NativePredicate>, Vec<NativeMutation>), Error> {
        let owner = self.owner()?;
        let mut remaining = max_bytes.unwrap_or(usize::MAX);
        let mut charge = |bytes: usize| {
            remaining = remaining
                .checked_sub(bytes)
                .ok_or(Error::Access(super::facade::AccessError::Overloaded))?;
            Ok::<(), Error>(())
        };
        let predicates = predicates
            .map(|p| {
                charge(std::mem::size_of::<NativePredicate>())?;
                charge(p.key.len())?;
                if let ExpectedRow::Exact(value) = p.expected {
                    charge(value.len())?;
                }
                let address = owner.address(p.schema, &self.key(p.key))?;
                charge(
                    address
                        .key
                        .len()
                        .checked_sub(p.key.len())
                        .ok_or(Error::Invalid)?,
                )?;
                Ok(NativePredicate {
                    address,
                    expected: match p.expected {
                        ExpectedRow::Absent => ExpectedValue::Absent,
                        ExpectedRow::Exact(value) => {
                            ExpectedValue::Exact(Secret::new(value.to_vec()))
                        }
                    },
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let mutations = mutations
            .map(|m| {
                charge(std::mem::size_of::<NativeMutation>())?;
                Ok(match m {
                    MutationRow::Put { schema, key, value } => {
                        charge(key.len())?;
                        charge(value.len())?;
                        let address = owner.address(schema, &self.key(key))?;
                        charge(
                            address
                                .key
                                .len()
                                .checked_sub(key.len())
                                .ok_or(Error::Invalid)?,
                        )?;
                        NativeMutation::Put {
                            address,
                            value: Secret::new(value.to_vec()),
                        }
                    }
                    MutationRow::Delete { schema, key } => {
                        charge(key.len())?;
                        let address = owner.address(schema, &self.key(key))?;
                        charge(
                            address
                                .key
                                .len()
                                .checked_sub(key.len())
                                .ok_or(Error::Invalid)?,
                        )?;
                        NativeMutation::Delete(address)
                    }
                    MutationRow::DeleteRange {
                        schema,
                        prefix,
                        exact_key_length,
                    } => {
                        charge(prefix.len())?;
                        let address = owner.address(schema, &self.key(prefix))?;
                        let overhead = address
                            .key
                            .len()
                            .checked_sub(prefix.len())
                            .ok_or(Error::Invalid)?;
                        charge(overhead)?;
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
        Ok((predicates, mutations))
    }
    /// Register this host scope with the attachment's shared maintenance owner.
    pub fn register_claims(&self, kind: &str) -> Result<(), ClaimError> {
        self.store.register_claim_scope(&self.instance, kind)
    }
    /// Advance one registered claim scope, retaining its cursor on cancellation.
    pub async fn sweep_claims(&self) -> Result<Option<ClaimSweepOutcome>, ClaimError> {
        self.store.sweep_claim_scope().await
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
