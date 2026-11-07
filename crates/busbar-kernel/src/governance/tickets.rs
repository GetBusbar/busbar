// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::host_services::VerifiedTicketIdentity;
use crate::persistence::{
    facade::CoreStore,
    scoped::{Expected, Mutation, Outcome, Predicate, Request, ScopedStore},
};
use busbar_contract::{
    persistence::{Read, ReadResult, TimeGuard},
    Secret,
};
use std::sync::atomic::{AtomicBool, Ordering};

pub const TICKET_RECORD_KIND: &str = "ticket";
pub const TICKET_SPENT_KIND: &str = "ticket-spent";
const OWNER: &str = "@kernel.tickets";
const EXPIRY_SCHEMA: &str = "ticket-expiry";
fn expiry_key(id: &str, expiry: u64) -> Vec<u8> {
    let mut key = expiry.to_be_bytes().to_vec();
    key.extend_from_slice(id.as_bytes());
    key
}

/// Why a ticket was not minted. Each answer is the refusal's reason, never secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketRefusal {
    /// This node holds no signing key.
    NoSigner,
    /// The principal's key does not stand (unknown, disabled or revoked).
    NoStanding,
    /// The lifetime left after the ceilings is zero.
    NoLifetime,
    /// The store did not keep the record.
    NotKept,
    /// The OS randomness source failed.
    NoRandomness,
}

impl TicketRefusal {
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Self::NoSigner => "no ticket is minted: this node holds no signing key",
            Self::NoStanding => "no ticket is minted: the principal's key does not stand",
            Self::NoLifetime => "no ticket is minted: no lifetime is left under the ceilings",
            Self::NotKept => "no ticket is minted: the store did not keep its record",
            Self::NoRandomness => "no ticket is minted: the randomness source failed",
        }
    }
}

fn ticket_id() -> Result<String, TicketRefusal> {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).map_err(|_| TicketRefusal::NoRandomness)?;
    Ok(raw.iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyTicketError;
fn valid_ticket_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
/// Source plane_records.kind="ticket", id=original random hex, ts=exact expiry.
/// The source opaque consumer body is copied unchanged behind the new envelope.
pub(crate) fn legacy_ticket_record(
    id: &str,
    expires_at: u64,
    body: &[u8],
) -> Result<(busbar_contract::persistence::Address, Secret<Vec<u8>>), LegacyTicketError> {
    if !valid_ticket_id(id) {
        return Err(LegacyTicketError);
    }
    let address = crate::persistence::scoped::migration_address(
        true,
        OWNER,
        TICKET_RECORD_KIND,
        id.as_bytes(),
    )
    .map_err(|_| LegacyTicketError)?;
    Ok((address, encoded_record(expires_at, body)))
}
/// Source plane_tokens.kind="ticket-spent", token=original hex, expires_at=exact expiry.
pub(crate) fn legacy_ticket_token(
    kind: &str,
    id: &str,
    expires_at: u64,
) -> Result<(busbar_contract::persistence::Address, Secret<Vec<u8>>), LegacyTicketError> {
    if kind != TICKET_SPENT_KIND || !valid_ticket_id(id) {
        return Err(LegacyTicketError);
    }
    let address = crate::persistence::scoped::migration_address(
        true,
        OWNER,
        TICKET_SPENT_KIND,
        id.as_bytes(),
    )
    .map_err(|_| LegacyTicketError)?;
    let mut bytes = vec![1];
    bytes.extend_from_slice(&expires_at.to_be_bytes());
    Ok((address, Secret::new(bytes)))
}
pub(crate) fn legacy_ticket_expiry(
    id: &str,
    expires_at: u64,
) -> Result<(busbar_contract::persistence::Address, Secret<Vec<u8>>), LegacyTicketError> {
    if !valid_ticket_id(id) {
        return Err(LegacyTicketError);
    }
    Ok((
        crate::persistence::scoped::migration_address(
            true,
            OWNER,
            EXPIRY_SCHEMA,
            &expiry_key(id, expires_at),
        )
        .map_err(|_| LegacyTicketError)?,
        Secret::new(vec![1]),
    ))
}
pub(crate) fn legacy_ticket_authorizes(address: &busbar_contract::persistence::Address) -> bool {
    let Some(id) = address
        .key
        .get(address.key.len().saturating_sub(32)..)
        .and_then(|id| std::str::from_utf8(id).ok())
        .filter(|id| valid_ticket_id(id))
    else {
        return false;
    };
    if let Some(suffix) = address.key.get(address.key.len().saturating_sub(40)..) {
        if suffix.len() == 40 && suffix[8..] == *id.as_bytes() {
            let expiry = u64::from_be_bytes(suffix[..8].try_into().expect("eight byte expiry"));
            if legacy_ticket_expiry(id, expiry).is_ok_and(|(expected, _)| expected == *address) {
                return true;
            }
        }
    }
    [TICKET_RECORD_KIND, TICKET_SPENT_KIND]
        .iter()
        .any(|schema| {
            crate::persistence::scoped::migration_address(true, OWNER, schema, id.as_bytes())
                .is_ok_and(|expected| expected == *address)
        })
}

#[derive(Default)]
pub(super) struct TicketOperations {
    pending: std::sync::Mutex<std::collections::BTreeMap<String, Arc<TicketOperation>>>,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum OperationKind {
    Mint,
    Spend,
    Cleanup,
}
struct TicketOperation {
    core: Arc<CoreStore>,
    kind: OperationKind,
    request: Request,
    time: Option<TimeGuard>,
    principal: Arc<VirtualKey>,
    expires_at: u64,
    record: Secret<Vec<u8>>,
    delivered: AtomicBool,
    runner: super::BudgetFlushRunner,
}
fn request_id(core: &CoreStore) -> Option<[u8; 16]> {
    // Preserve the scoped logical receipt's node8/counter8 partitioning while
    // checking current admission before staging new retained work.
    core.next_id().ok()?;
    Some(crate::door::op_id().0)
}
fn scope(core: Arc<CoreStore>) -> Option<ScopedStore> {
    ScopedStore::host_private(
        core,
        OWNER,
        [
            TICKET_RECORD_KIND.into(),
            TICKET_SPENT_KIND.into(),
            EXPIRY_SCHEMA.into(),
        ],
    )
    .ok()
}
fn encoded_record(expires_at: u64, record: &[u8]) -> Secret<Vec<u8>> {
    let mut bytes = Vec::with_capacity(9 + record.len());
    bytes.push(1);
    bytes.extend_from_slice(&expires_at.to_be_bytes());
    bytes.extend_from_slice(record);
    Secret::new(bytes)
}
fn record_body(bytes: &Secret<Vec<u8>>, expires_at: u64) -> Option<&[u8]> {
    let bytes = bytes.expose(&crate::seal::lend());
    (bytes.len() >= 9 && bytes[0] == 1 && bytes[1..9] == expires_at.to_be_bytes())
        .then(|| &bytes[9..])
}
async fn native_record(
    core: &CoreStore,
    id: &str,
    expires_at: u64,
) -> RecordStoreResult<Option<Secret<Vec<u8>>>> {
    if !valid_ticket_id(id) {
        return Err(RecordStoreError("invalid native ticket identity".into()));
    }
    let address = |kind| {
        crate::persistence::scoped::migration_address(true, OWNER, kind, id.as_bytes())
            .map_err(|_| RecordStoreError("invalid native ticket scope".into()))
    };
    let time = TimeGuard {
        not_before: None,
        before: expires_at.checked_add(1),
    };
    let observed = core
        .backend()
        .read(Arc::new(Read {
            dataset: core.info().dataset,
            addresses: vec![
                address(TICKET_RECORD_KIND)?,
                address(TICKET_SPENT_KIND)?,
                crate::persistence::scoped::migration_address(
                    true,
                    OWNER,
                    EXPIRY_SCHEMA,
                    &expiry_key(id, expires_at),
                )
                .map_err(|_| RecordStoreError("invalid native ticket index scope".into()))?,
            ],
            time: Some(time),
        }))
        .await
        .map_err(|_| RecordStoreError("native ticket observation unavailable".into()))?;
    let (observed_at, mut values) = match observed {
        ReadResult::TimeGuardFailed { observed_at } => {
            if observed_at.authority != core.info().clock_authority
                || time.permits(observed_at.unix_seconds)
            {
                return Err(RecordStoreError(
                    "invalid native ticket time observation".into(),
                ));
            }
            return Ok(None);
        }
        ReadResult::Values {
            observed_at,
            values,
        } => (observed_at, values),
    };
    if observed_at.authority != core.info().clock_authority
        || !time.permits(observed_at.unix_seconds)
        || values.len() != 3
    {
        return Err(RecordStoreError("invalid native ticket observation".into()));
    }
    let index = values.pop().expect("validated count");
    let spent = values.pop().expect("validated count");
    let active = values.pop().expect("validated count");
    if index
        .as_ref()
        .is_some_and(|value| value.expose(&crate::seal::lend()) != &[1])
        || spent
            .as_ref()
            .is_some_and(|value| record_body(value, expires_at) != Some(&[][..]))
    {
        return Err(RecordStoreError("invalid native ticket metadata".into()));
    }
    let Some(record) = active else {
        return Ok(None);
    };
    if record_body(&record, expires_at).is_none() || index.is_none() {
        return Err(RecordStoreError("invalid native ticket record".into()));
    }
    if spent.is_some() {
        return Ok(None);
    }
    Ok(Some(record))
}

/// A truthful native reservation observation for host custody maintenance.
/// Read failure is distinct from expiry/absence/consumption and retains custody.
pub async fn ticket_record_live(
    core: Arc<CoreStore>,
    id: &str,
    expected_expiry: u64,
) -> RecordStoreResult<bool> {
    native_record(&core, id, expected_expiry)
        .await
        .map(|record| record.is_some())
}

impl GovState {
    pub(super) fn has_unsettled_ticket_operations(&self) -> bool {
        self.ticket_operations
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .values()
            .any(|operation| {
                !operation.delivered.load(Ordering::Acquire) || operation.runner.is_running()
            })
    }
    fn ticket_operation(&self, id: &str) -> Option<Arc<TicketOperation>> {
        self.ticket_operations.pending.lock().ok()?.get(id).cloned()
    }
    fn forget_ticket_operation(&self, id: &str, operation: &Arc<TicketOperation>) {
        let mut pending = self
            .ticket_operations
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if pending
            .get(id)
            .is_some_and(|current| Arc::ptr_eq(current, operation))
        {
            pending.remove(id);
        }
    }
    async fn ticket_attempt(&self, operation: &TicketOperation) -> Option<Outcome> {
        scope(operation.core.clone())?
            .conditional_native_timed(&operation.request, operation.time)
            .await
            .ok()
    }
    async fn purge_expired_ticket_records(&self, principal: &Arc<VirtualKey>) -> Option<()> {
        let core = self.core_store_handle().ok()?;
        let records = scope(core.clone())?;
        let observed = core.backend().clock(core.info().dataset).await.ok()?;
        if observed.authority != core.info().clock_authority {
            return None;
        }
        let page = records.page(EXPIRY_SCHEMA, b"", None).await.ok()?;
        for (key, index) in page.rows {
            if key.len() != 40 || index.expose(&crate::seal::lend()) != &[1] {
                return None;
            }
            let expiry = u64::from_be_bytes(key[..8].try_into().ok()?);
            if expiry >= observed.unix_seconds {
                break;
            }
            let id = std::str::from_utf8(&key[8..]).ok()?.to_owned();
            if !valid_ticket_id(&id) {
                return None;
            }
            let mut values = records
                .read(&[
                    (TICKET_RECORD_KIND, id.as_bytes()),
                    (TICKET_SPENT_KIND, id.as_bytes()),
                ])
                .await
                .ok()?;
            let spent = values.pop()?;
            let active = values.pop()?;
            if active
                .as_ref()
                .is_some_and(|bytes| record_body(bytes, expiry).is_none())
                || spent.as_ref().is_some_and(|bytes| {
                    bytes.expose(&crate::seal::lend())
                        != encoded_record(expiry, b"").expose(&crate::seal::lend())
                })
            {
                return None;
            }
            let operation = Arc::new(TicketOperation {
                core: core.clone(),
                kind: OperationKind::Cleanup,
                request: Request {
                    op_id: request_id(&core)?,
                    predicates: vec![
                        Predicate {
                            schema: TICKET_RECORD_KIND.into(),
                            key: id.as_bytes().into(),
                            expected: active.map_or(Expected::Absent, Expected::Exact),
                        },
                        Predicate {
                            schema: TICKET_SPENT_KIND.into(),
                            key: id.as_bytes().into(),
                            expected: spent.map_or(Expected::Absent, Expected::Exact),
                        },
                        Predicate {
                            schema: EXPIRY_SCHEMA.into(),
                            key: key.clone(),
                            expected: Expected::Exact(index),
                        },
                    ],
                    mutations: vec![
                        Mutation::Delete {
                            schema: TICKET_RECORD_KIND.into(),
                            key: id.as_bytes().into(),
                        },
                        Mutation::Delete {
                            schema: TICKET_SPENT_KIND.into(),
                            key: id.as_bytes().into(),
                        },
                        Mutation::Delete {
                            schema: EXPIRY_SCHEMA.into(),
                            key,
                        },
                    ],
                },
                time: Some(TimeGuard {
                    not_before: expiry.checked_add(1),
                    before: None,
                }),
                principal: principal.clone(),
                expires_at: expiry,
                record: Secret::default(),
                delivered: AtomicBool::new(false),
                runner: Default::default(),
            });
            let cleanup_id = format!("expiry:{id}");
            let operation = self
                .ticket_operations
                .pending
                .lock()
                .ok()?
                .entry(cleanup_id.clone())
                .or_insert(operation)
                .clone();
            let Ok(_running) = operation.runner.enter(false).await else {
                continue;
            };
            if matches!(
                self.ticket_attempt(&operation).await,
                Some(
                    Outcome::Applied
                        | Outcome::ConditionConflict
                        | Outcome::OpIdConflict
                        | Outcome::NoEffect(_)
                )
            ) {
                self.forget_ticket_operation(&cleanup_id, &operation);
            }
        }
        Some(())
    }

    /// Drive retained immutable ticket attempts without admitting a credential.
    /// Root may call this during maintenance/drain, including after expiry.
    pub async fn settle_ticket_operations(&self) -> usize {
        let pending = self
            .ticket_operations
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(id, op)| (id.clone(), op.clone()))
            .collect::<Vec<_>>();
        let mut settled = 0;
        for (id, operation) in pending {
            let Ok(_running) = operation.runner.enter(false).await else {
                continue;
            };
            if matches!(
                self.ticket_attempt(&operation).await,
                Some(
                    Outcome::Applied
                        | Outcome::ConditionConflict
                        | Outcome::OpIdConflict
                        | Outcome::NoEffect(_)
                )
            ) {
                operation.delivered.store(true, Ordering::Release);
                self.forget_ticket_operation(&id, &operation);
                settled += 1;
            }
        }
        settled
    }
    pub(crate) async fn admit_ticket_async(
        self: &Arc<Self>,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<(Arc<VirtualKey>, Vec<u8>)> {
        let identity = self
            .prepare_ticket_redemption_async(prefix, credential, now)
            .await?;
        self.redeem_verified_ticket_async(identity, now).await
    }
    pub async fn prepare_ticket_redemption_async(
        self: &Arc<Self>,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<VerifiedTicketIdentity> {
        let (principal, id, expires_at) = self.checked_ticket(prefix, credential, now)?;
        let core = self.core_store_handle().ok()?;
        let operation = if let Some(operation) = self.ticket_operation(&id) {
            operation
        } else {
            let original = native_record(&core, &id, expires_at).await.ok()??;
            let record = Secret::new(record_body(&original, expires_at)?.to_vec());
            let op_id = request_id(&core)?;
            let mut spent = vec![1];
            spent.extend_from_slice(&expires_at.to_be_bytes());
            let candidate = Arc::new(TicketOperation {
                core: core.clone(),
                kind: OperationKind::Spend,
                request: Request {
                    op_id,
                    predicates: vec![
                        Predicate {
                            schema: TICKET_RECORD_KIND.into(),
                            key: id.as_bytes().into(),
                            expected: Expected::Exact(original),
                        },
                        Predicate {
                            schema: TICKET_SPENT_KIND.into(),
                            key: id.as_bytes().into(),
                            expected: Expected::Absent,
                        },
                        Predicate {
                            schema: EXPIRY_SCHEMA.into(),
                            key: expiry_key(&id, expires_at),
                            expected: Expected::Exact(Secret::new(vec![1])),
                        },
                    ],
                    mutations: vec![
                        Mutation::Delete {
                            schema: TICKET_RECORD_KIND.into(),
                            key: id.as_bytes().into(),
                        },
                        Mutation::Put {
                            schema: TICKET_SPENT_KIND.into(),
                            key: id.as_bytes().into(),
                            value: Secret::new(spent),
                        },
                    ],
                },
                time: Some(TimeGuard {
                    not_before: None,
                    before: expires_at.checked_add(1),
                }),
                principal: principal.clone(),
                expires_at,
                record,
                delivered: AtomicBool::new(false),
                runner: Default::default(),
            });
            self.ticket_operations
                .pending
                .lock()
                .ok()?
                .entry(id.clone())
                .or_insert(candidate)
                .clone()
        };
        if operation.kind != OperationKind::Spend
            || operation.delivered.load(Ordering::Acquire)
            || !Arc::ptr_eq(&operation.core, &core)
            || operation.expires_at != expires_at
            || operation.principal.id != principal.id
            || operation.principal.generation_hash != principal.generation_hash
        {
            return None;
        }
        Some(VerifiedTicketIdentity {
            id,
            principal,
            expires_at,
            store: core,
            prefix: prefix.into(),
            credential: zeroize::Zeroizing::new(credential.into()),
        })
    }
    pub async fn redeem_verified_ticket_async(
        self: &Arc<Self>,
        identity: VerifiedTicketIdentity,
        now: u64,
    ) -> Option<(Arc<VirtualKey>, Vec<u8>)> {
        let core = self.core_store_handle().ok()?;
        if !Arc::ptr_eq(&core, &identity.store) {
            return None;
        }
        let (key, id, exp) = self.checked_ticket(&identity.prefix, &identity.credential, now)?;
        if id != identity.id
            || exp != identity.expires_at
            || key.id != identity.principal.id
            || key.generation_hash != identity.principal.generation_hash
        {
            return None;
        }
        let operation = self.ticket_operation(&id)?;
        let _running = operation.runner.enter(false).await.ok()?;
        if operation.delivered.load(Ordering::Acquire)
            || operation.kind != OperationKind::Spend
            || !Arc::ptr_eq(&operation.core, &core)
        {
            return None;
        }
        match self.ticket_attempt(&operation).await? {
            Outcome::Applied => {
                if operation.delivered.swap(true, Ordering::AcqRel) {
                    return None;
                }
                self.forget_ticket_operation(&id, &operation);
                let current = self
                    .checked_ticket(&identity.prefix, &identity.credential, now)?
                    .0;
                if current.id != key.id || current.generation_hash != key.generation_hash {
                    return None;
                }
                Some((
                    current,
                    operation.record.expose(&crate::seal::lend()).clone(),
                ))
            }
            Outcome::ConditionConflict | Outcome::OpIdConflict | Outcome::NoEffect(_) => {
                operation.delivered.store(true, Ordering::Release);
                self.forget_ticket_operation(&id, &operation);
                None
            }
            Outcome::Pending(_) | Outcome::Reconcile(_) | Outcome::Busy(_) => None,
        }
    }
    pub(crate) async fn peek_ticket_async(
        self: &Arc<Self>,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<Arc<VirtualKey>> {
        let (key, id, expires_at) = self.checked_ticket(prefix, credential, now)?;
        native_record(self.core_store().ok()?, &id, expires_at)
            .await
            .ok()??;
        let (current, current_id, current_expiry) = self.checked_ticket(prefix, credential, now)?;
        if current.id != key.id
            || current.generation_hash != key.generation_hash
            || current_id != id
            || current_expiry != expires_at
        {
            return None;
        }
        Some(current)
    }
    pub async fn mint_ticket(
        &self,
        key_id: &str,
        prefix: &str,
        ttl_secs: u64,
        ceiling_secs: Option<u64>,
        record: &[u8],
        now: u64,
    ) -> Result<(String, u64), TicketRefusal> {
        self.mint_ticket_bound(key_id, prefix, ttl_secs, ceiling_secs, record, now, |_| {
            Ok(())
        })
        .await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn mint_ticket_bound(
        &self,
        key_id: &str,
        prefix: &str,
        ttl_secs: u64,
        ceiling_secs: Option<u64>,
        record: &[u8],
        now: u64,
        bind: impl FnOnce(&VerifiedTicketIdentity) -> Result<(), TicketRefusal> + Send,
    ) -> Result<(String, u64), TicketRefusal> {
        let material = self.signing_material().ok_or(TicketRefusal::NoSigner)?;
        let key = self
            .lookup_by_sub(key_id)
            .filter(|key| key.enabled && !self.is_revoked(&key.id))
            .ok_or(TicketRefusal::NoStanding)?;
        let ttl =
            mint_policy::apply_mint_ttl_ceiling(ttl_secs, false, ceiling_secs).unwrap_or(ttl_secs);
        let mut exp = now.saturating_add(ttl);
        if let Some(key_exp) = key.expires_at {
            exp = exp.min(key_exp)
        }
        if exp <= now {
            return Err(TicketRefusal::NoLifetime);
        }
        let _ = self.purge_expired_ticket_records(&key).await;
        let id = ticket_id()?;
        let core = self
            .core_store_handle()
            .map_err(|_| TicketRefusal::NotKept)?;
        let original = encoded_record(exp, record);
        let operation = Arc::new(TicketOperation {
            core: core.clone(),
            kind: OperationKind::Mint,
            request: Request {
                op_id: request_id(&core).ok_or(TicketRefusal::NotKept)?,
                predicates: vec![
                    Predicate {
                        schema: TICKET_RECORD_KIND.into(),
                        key: id.as_bytes().into(),
                        expected: Expected::Absent,
                    },
                    Predicate {
                        schema: TICKET_SPENT_KIND.into(),
                        key: id.as_bytes().into(),
                        expected: Expected::Absent,
                    },
                    Predicate {
                        schema: EXPIRY_SCHEMA.into(),
                        key: expiry_key(&id, exp),
                        expected: Expected::Absent,
                    },
                ],
                mutations: vec![
                    Mutation::Put {
                        schema: TICKET_RECORD_KIND.into(),
                        key: id.as_bytes().into(),
                        value: original.clone(),
                    },
                    Mutation::Put {
                        schema: EXPIRY_SCHEMA.into(),
                        key: expiry_key(&id, exp),
                        value: Secret::new(vec![1]),
                    },
                ],
            },
            time: Some(TimeGuard {
                not_before: None,
                before: exp.checked_add(1),
            }),
            principal: key.clone(),
            expires_at: exp,
            record: Secret::default(),
            delivered: AtomicBool::new(false),
            runner: Default::default(),
        });
        self.ticket_operations
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(id.clone(), operation.clone());
        let _running = operation
            .runner
            .enter(false)
            .await
            .map_err(|_| TicketRefusal::NotKept)?;
        if !matches!(
            self.ticket_attempt(&operation).await,
            Some(Outcome::Applied)
        ) {
            return Err(TicketRefusal::NotKept);
        }
        operation.delivered.store(true, Ordering::Release);
        self.forget_ticket_operation(&id, &operation);
        let body = material.signer.mint_ticket_body(
            &key.id,
            exp,
            binding_generation(&key.generation_hash),
            &id,
            prefix,
        );
        let mut identity = VerifiedTicketIdentity {
            id,
            principal: key,
            expires_at: exp,
            store: core.clone(),
            prefix: prefix.into(),
            credential: zeroize::Zeroizing::new(format!("{prefix}{body}")),
        };
        if let Err(why) = bind(&identity) {
            let cleanup = Request {
                op_id: request_id(&core).ok_or(TicketRefusal::NotKept)?,
                predicates: vec![
                    Predicate {
                        schema: TICKET_RECORD_KIND.into(),
                        key: identity.id.as_bytes().into(),
                        expected: Expected::Exact(original),
                    },
                    Predicate {
                        schema: EXPIRY_SCHEMA.into(),
                        key: expiry_key(&identity.id, exp),
                        expected: Expected::Exact(Secret::new(vec![1])),
                    },
                ],
                mutations: vec![
                    Mutation::Delete {
                        schema: TICKET_RECORD_KIND.into(),
                        key: identity.id.as_bytes().into(),
                    },
                    Mutation::Delete {
                        schema: EXPIRY_SCHEMA.into(),
                        key: expiry_key(&identity.id, exp),
                    },
                ],
            };
            let cleanup = Arc::new(TicketOperation {
                core: core.clone(),
                kind: OperationKind::Cleanup,
                request: cleanup,
                time: None,
                principal: identity.principal.clone(),
                expires_at: exp,
                record: Secret::default(),
                delivered: AtomicBool::new(false),
                runner: Default::default(),
            });
            self.ticket_operations
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(identity.id.clone(), cleanup.clone());
            if matches!(
                self.ticket_attempt(&cleanup).await,
                Some(
                    Outcome::Applied
                        | Outcome::ConditionConflict
                        | Outcome::OpIdConflict
                        | Outcome::NoEffect(_)
                )
            ) {
                self.forget_ticket_operation(&identity.id, &cleanup);
            }
            return Err(why);
        }
        Ok((std::mem::take(&mut *identity.credential), exp))
    }
    fn checked_ticket(
        &self,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<(Arc<VirtualKey>, String, u64)> {
        if prefix.is_empty() {
            return None;
        }
        let body = credential.strip_prefix(prefix)?;
        let material = self.signing_material()?;
        let claims = match material.verifier.verify_ticket_body(body, prefix) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(reason = %e, "ticket verify rejected");
                return None;
            }
        };
        let id = claims.ticket.clone()?;
        let key = self.standing_key(&claims, now)?;
        Some((key, id, claims.exp))
    }
}

#[cfg(test)]
#[path = "tests/tickets_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/tickets_native_tests.rs"]
mod native_tests;
