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
    stage_probe::{tick, Derive},
    Secret,
};
use std::sync::atomic::{AtomicBool, Ordering};

pub const TICKET_RECORD_KIND: &str = "ticket";
pub const TICKET_SPENT_KIND: &str = "ticket-spent";
const OWNER: &str = "@kernel.tickets";
const EXPIRY_SCHEMA: &str = "ticket-expiry";
fn expiry_key(id: &str, expiry: u64) -> Vec<u8> {
    crate::cold::governance::state::tickets_expiry_key(id, expiry)
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
    /// The principal's key holds its maximum of unredeemed tickets on this node.
    KeySaturated {
        /// The seconds until that key's earliest ticket expires, plus one sweep cycle.
        retry_after_secs: u32,
    },
    /// This node holds its maximum of unredeemed tickets.
    NodeSaturated {
        /// One sweep cycle: an estimate, since any key's redemption frees a slot sooner.
        retry_after_secs: u32,
    },
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
            Self::KeySaturated { .. } => {
                "no ticket is minted: this key holds its maximum of unredeemed tickets; \
                 redeem or let them expire"
            }
            Self::NodeSaturated { .. } => {
                "no ticket is minted: this node holds its maximum of unredeemed tickets; \
                 retry shortly"
            }
        }
    }

    /// The refusal's `ticket.mint` code, as the plane reads it from the answer's value.
    #[must_use]
    pub const fn code(self) -> u32 {
        use busbar_contract::abi::host::service as svc;
        match self {
            Self::NoSigner
            | Self::NoStanding
            | Self::NoLifetime
            | Self::NotKept
            | Self::NoRandomness => svc::TICKET_REFUSED_OTHER,
            Self::KeySaturated { .. } => svc::KEY_SATURATED,
            Self::NodeSaturated { .. } => svc::NODE_SATURATED,
        }
    }

    /// The seconds after which a retry may find a free slot; `0` = none stated.
    #[must_use]
    pub const fn retry_after_secs(self) -> u32 {
        match self {
            Self::KeySaturated { retry_after_secs } | Self::NodeSaturated { retry_after_secs } => {
                retry_after_secs
            }
            Self::NoSigner
            | Self::NoStanding
            | Self::NoLifetime
            | Self::NotKept
            | Self::NoRandomness => 0,
        }
    }
}

fn ticket_id() -> Result<String, TicketRefusal> {
    let mut raw = [0u8; 16];
    busbar_contract::crypto::fill(&mut raw).map_err(|_| TicketRefusal::NoRandomness)?;
    Ok(hex::encode(raw))
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
/// The request's receipt identity, held by the retained `TicketOperation` until it drops.
async fn request_id(core: &CoreStore) -> Option<crate::persistence::scoped::Op> {
    // Check current admission before staging new retained work.
    core.next_id().ok()?;
    core.record_op().await.ok().map(Into::into)
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
    crate::cold::governance::state::tickets_encoded_record(expires_at, record)
}
/// The audited refusal of a ticket whose signing key changed between its verification and a
/// later standing re-check.
const TICKET_SIGNING_ROTATED: &str = "ticket_signing_rotated";

/// A door ticket whose signature was verified and whose claims were parsed once (SP-AU3), with
/// the signing material it was verified under and, once the inbound auth point read it, its
/// native record. Prepare and redeem take it by reference and never verify it again.
pub(crate) struct VerifiedTicket {
    prefix: String,
    credential: busbar_contract::secure::SecureString,
    id: String,
    claims: super::signing::TokenClaims,
    material: Arc<SigningMaterial>,
    record: Option<Secret<Vec<u8>>>,
}

impl VerifiedTicket {
    /// Whether this is the ticket `credential` presents on a `prefix` route.
    pub(crate) fn presented_as(&self, prefix: &str, credential: &str) -> bool {
        self.prefix == prefix && self.credential.as_str() == credential
    }
}

/// Whether two signing materials verify the same tickets: the same key id and verifying key.
fn same_signing_key(a: &SigningMaterial, b: &SigningMaterial) -> bool {
    a.signer.kid() == b.signer.kid() && a.signer.verifying_key() == b.signer.verifying_key()
}

fn record_body_len(bytes: &Secret<Vec<u8>>, expires_at: u64) -> Option<usize> {
    let bytes = bytes.expose(&crate::seal::lend());
    (bytes.len() >= 9 && bytes[0] == 1 && bytes[1..9] == expires_at.to_be_bytes())
        .then(|| bytes.len() - 9)
}
/// The three native addresses one ticket is observed through: its record, its spent marker and
/// its expiry index row.
pub(crate) fn ticket_addresses(
    id: &str,
    expires_at: u64,
) -> RecordStoreResult<[busbar_contract::persistence::Address; 3]> {
    if !valid_ticket_id(id) {
        return Err(RecordStoreError("invalid native ticket identity".into()));
    }
    tick(Derive::TicketRead);
    let address = |kind| {
        crate::persistence::scoped::migration_address(true, OWNER, kind, id.as_bytes())
            .map_err(|_| RecordStoreError("invalid native ticket scope".into()))
    };
    Ok([
        address(TICKET_RECORD_KIND)?,
        address(TICKET_SPENT_KIND)?,
        crate::persistence::scoped::migration_address(
            true,
            OWNER,
            EXPIRY_SCHEMA,
            &expiry_key(id, expires_at),
        )
        .map_err(|_| RecordStoreError("invalid native ticket index scope".into()))?,
    ])
}

/// Judge one ticket's three observed values (record, spent, index), already known to be within
/// its expiry at the store's clock.
pub(crate) fn judge_ticket(
    expires_at: u64,
    active: Option<Secret<Vec<u8>>>,
    spent: Option<&Secret<Vec<u8>>>,
    index: Option<&Secret<Vec<u8>>>,
) -> RecordStoreResult<Option<Secret<Vec<u8>>>> {
    if index.is_some_and(|value| value.expose(&crate::seal::lend()) != &[1])
        || spent.is_some_and(|value| record_body_len(value, expires_at) != Some(0))
    {
        return Err(RecordStoreError("invalid native ticket metadata".into()));
    }
    let Some(record) = active else {
        return Ok(None);
    };
    if record_body_len(&record, expires_at).is_none() || index.is_none() {
        return Err(RecordStoreError("invalid native ticket record".into()));
    }
    if spent.is_some() {
        return Ok(None);
    }
    Ok(Some(record))
}

async fn native_record(
    core: &CoreStore,
    id: &str,
    expires_at: u64,
) -> RecordStoreResult<Option<Secret<Vec<u8>>>> {
    let addresses = ticket_addresses(id, expires_at)?;
    let time = TimeGuard {
        not_before: None,
        before: expires_at.checked_add(1),
    };
    let observed = core
        .backend()
        .read(Arc::new(Read {
            dataset: core.info().dataset,
            addresses: crate::cold::governance::state::tickets_read_addresses(&addresses),
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
    judge_ticket(expires_at, active, spent.as_ref(), index.as_ref())
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

/// Tickets observed per batched `Read` (three addresses each), bounded by the store's page budget.
pub(crate) fn tickets_per_read(core: &CoreStore) -> usize {
    (core.limits().scan_items / 3).max(1)
}

/// [`ticket_record_live`] for many tickets of one store, with one `Read` per chunk instead of one
/// per ticket (WASTE-CORE-LIFECYCLE W4). The `Read` carries no `TimeGuard` (one guard cannot fit
/// distinct expiries); each ticket is judged by the store's own observation instead:
/// `observed_at > expires_at` is expired, exactly where the single-ticket guard
/// `before: expires_at + 1` fails. A chunk is accepted only as well-formed `Values` with this
/// store's clock authority and three values per ticket; anything else is the outer `Err`, which
/// releases nothing. Inside an accepted chunk a malformed ticket is an `Err` for that ticket only.
pub async fn ticket_records_live(
    core: Arc<CoreStore>,
    items: &[(String, u64)],
) -> RecordStoreResult<Vec<RecordStoreResult<bool>>> {
    crate::off_path::governance::state::tickets_records_live(core, items).await
}

impl GovState {
    pub(super) fn has_unsettled_ticket_operations(&self) -> bool {
        let pending = self
            .ticket_operations
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        crate::off_path::governance::state::tickets_any_unsettled(&*pending, |operation| {
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
            // The cleanup's map key carries the id; the id is borrowed from it, not copied out.
            let cleanup_id = crate::cold::governance::state::tickets_cleanup_id(
                std::str::from_utf8(&key[8..]).ok()?,
            );
            let id = &cleanup_id["expiry:".len()..];
            if !valid_ticket_id(id) {
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
                .is_some_and(|bytes| record_body_len(bytes, expiry).is_none())
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
                    op: request_id(&core).await?,
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
            let operation = {
                let mut pending = self.ticket_operations.pending.lock().ok()?;
                match pending.get(&cleanup_id) {
                    Some(retained) => retained.clone(),
                    None => crate::cold::governance::state::tickets_keep_first(
                        &mut *pending,
                        &cleanup_id,
                        operation,
                    ),
                }
            };
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
        let pending = crate::off_path::governance::state::tickets_pending_snapshot(
            &*self
                .ticket_operations
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner()),
        );
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
    /// Verify, prepare and redeem one ticket in a single call (tests only; a request carries
    /// its auth point's verified ticket to the final gate instead).
    #[cfg(test)]
    pub(crate) async fn admit_ticket_async(
        self: &Arc<Self>,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<(Arc<VirtualKey>, Vec<u8>)> {
        let (ticket, _) = self.verify_ticket(prefix, credential, now)?;
        let identity = self.prepare_verified_ticket(&ticket, now).await?;
        self.redeem_prepared_ticket(identity, &ticket, now).await
    }
    pub async fn prepare_ticket_redemption_async(
        self: &Arc<Self>,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<VerifiedTicketIdentity> {
        let (ticket, _) = self.verify_ticket(prefix, credential, now)?;
        self.prepare_verified_ticket(&ticket, now).await
    }
    /// Stage the single-use spend of a verified ticket. The record the auth point read is the
    /// spend's condition, so a ticket spent since then fails the condition and is refused; a
    /// ticket verified without an auth point reads its record here. Standing is re-checked after
    /// that, so the identity carries the key as it stands now.
    pub(crate) async fn prepare_verified_ticket(
        self: &Arc<Self>,
        ticket: &VerifiedTicket,
        now: u64,
    ) -> Option<VerifiedTicketIdentity> {
        let (id, expires_at) = (ticket.id.clone(), ticket.claims.exp);
        let core = self.core_store_handle().ok()?;
        let pending = self.ticket_operation(&id);
        let original = match (&pending, &ticket.record) {
            (Some(_), _) => None,
            (None, Some(record)) => Some(record.clone()),
            (None, None) => Some(native_record(&core, &id, expires_at).await.ok()??),
        };
        let principal = self.standing_of(ticket, now)?;
        let operation = if let Some(operation) = pending {
            operation
        } else {
            let original = original?;
            record_body_len(&original, expires_at)?;
            let record = crate::cold::governance::state::tickets_record_body(
                &original.expose(&crate::seal::lend())[9..],
            );
            let op = request_id(&core).await?;
            let mut spent = vec![1];
            spent.extend_from_slice(&expires_at.to_be_bytes());
            let candidate = Arc::new(TicketOperation {
                core: core.clone(),
                kind: OperationKind::Spend,
                request: Request {
                    op,
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
            prefix: ticket.prefix.clone(),
            credential: ticket.credential.clone(),
        })
    }
    pub async fn redeem_verified_ticket_async(
        self: &Arc<Self>,
        identity: VerifiedTicketIdentity,
        now: u64,
    ) -> Option<(Arc<VirtualKey>, Vec<u8>)> {
        let (ticket, key) = self.verify_ticket(&identity.prefix, &identity.credential, now)?;
        if key.id != identity.principal.id
            || key.generation_hash != identity.principal.generation_hash
        {
            return None;
        }
        self.redeem_prepared_ticket(identity, &ticket, now).await
    }
    /// Spend a prepared ticket. The caller prepared `identity` from `ticket` with no `.await`
    /// since, so its principal is the standing checked then; standing is re-checked once more
    /// after the spend's own waits.
    pub(crate) async fn redeem_prepared_ticket(
        self: &Arc<Self>,
        identity: VerifiedTicketIdentity,
        ticket: &VerifiedTicket,
        now: u64,
    ) -> Option<(Arc<VirtualKey>, Vec<u8>)> {
        let core = self.core_store_handle().ok()?;
        if !Arc::ptr_eq(&core, &identity.store)
            || identity.id != ticket.id
            || identity.expires_at != ticket.claims.exp
        {
            return None;
        }
        let operation = self.ticket_operation(&identity.id)?;
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
                self.forget_ticket_operation(&identity.id, &operation);
                let current = self.standing_of(ticket, now)?;
                if current.id != identity.principal.id
                    || current.generation_hash != identity.principal.generation_hash
                {
                    return None;
                }
                Some((
                    current,
                    operation.record.expose(&crate::seal::lend()).clone(),
                ))
            }
            Outcome::ConditionConflict | Outcome::OpIdConflict | Outcome::NoEffect(_) => {
                operation.delivered.store(true, Ordering::Release);
                self.forget_ticket_operation(&identity.id, &operation);
                None
            }
            Outcome::Pending(_) | Outcome::Reconcile(_) | Outcome::Busy(_) => None,
        }
    }
    /// The inbound auth point's ticket check: verify the ticket once, read its native record once
    /// and re-check standing after that read. The verified ticket, with the record it read, is
    /// carried to the final gate (SP-AU3).
    pub(crate) async fn peek_door_ticket_async(
        self: &Arc<Self>,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<(Arc<VirtualKey>, VerifiedTicket)> {
        let (mut ticket, key) = self.verify_ticket(prefix, credential, now)?;
        let record = native_record(self.core_store().ok()?, &ticket.id, ticket.claims.exp)
            .await
            .ok()??;
        let current = self.standing_of(&ticket, now)?;
        if current.id != key.id || current.generation_hash != key.generation_hash {
            return None;
        }
        ticket.record = Some(record);
        Some((current, ticket))
    }
    #[cfg(test)]
    pub(crate) async fn peek_ticket_async(
        self: &Arc<Self>,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<Arc<VirtualKey>> {
        self.peek_door_ticket_async(prefix, credential, now)
            .await
            .map(|(key, _)| key)
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
    #[expect(
        clippy::too_many_arguments,
        reason = "config: the mint's inputs are its contract"
    )]
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
                op: request_id(&core).await.ok_or(TicketRefusal::NotKept)?,
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
        let identity = VerifiedTicketIdentity {
            id,
            principal: key,
            expires_at: exp,
            store: core.clone(),
            prefix: prefix.into(),
            credential: busbar_contract::secure::SecureString::from_args(format_args!(
                "{prefix}{body}"
            )),
        };
        if let Err(why) = bind(&identity) {
            let cleanup = Request {
                op: request_id(&core).await.ok_or(TicketRefusal::NotKept)?,
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
        Ok((identity.credential.into_string(), exp))
    }
    /// Verify a door ticket's signature and parse its claims: the one place a ticket is verified
    /// (SP-AU3). The key it names must stand now. Every later check reads the result through
    /// `standing_of`.
    pub(crate) fn verify_ticket(
        &self,
        prefix: &str,
        credential: &str,
        now: u64,
    ) -> Option<(VerifiedTicket, Arc<VirtualKey>)> {
        if prefix.is_empty() {
            return None;
        }
        let body = credential.strip_prefix(prefix)?;
        let material = self.signing_material()?;
        tick(Derive::TicketSig);
        let claims = match material.verifier.verify_ticket_body(body, prefix) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(reason = %e, "ticket verify rejected");
                return None;
            }
        };
        let id = claims.ticket.clone()?;
        let key = self.standing_key(&claims, now)?;
        Some((
            VerifiedTicket {
                prefix: prefix.into(),
                credential: busbar_contract::secure::SecureString::from(credential),
                id,
                claims,
                material,
                record: None,
            },
            key,
        ))
    }
    /// Re-check a verified ticket's standing after an `.await`, without verifying its signature
    /// again. The signing material it verified under must still be this node's: a key rotated to
    /// another one, or removed, refuses `ticket_signing_rotated`, audited. A reload that keeps the
    /// same key is not a rotation.
    fn standing_of(&self, ticket: &VerifiedTicket, now: u64) -> Option<Arc<VirtualKey>> {
        tick(Derive::TicketStanding);
        let unchanged = self.signing_material().is_some_and(|current| {
            Arc::ptr_eq(&current, &ticket.material) || same_signing_key(&current, &ticket.material)
        });
        if !unchanged {
            tracing::warn!(
                sub = %ticket.claims.sub,
                "door ticket refused: its signing key was rotated or removed mid-redemption"
            );
            crate::audit_ring::AUDIT.record_by(
                TICKET_SIGNING_ROTATED,
                &crate::cold::governance::state::tickets_rotated_resource(&ticket.claims.sub),
                crate::audit_ring::OUTCOME_REJECTED,
                &ticket.claims.sub,
            );
            return None;
        }
        self.standing_key(&ticket.claims, now)
    }
}

#[cfg(test)]
#[path = "tests/tickets_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "tests/tickets_native_tests.rs"]
mod native_tests;
