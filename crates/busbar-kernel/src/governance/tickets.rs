// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::host_services::VerifiedTicketIdentity;
use crate::persistence::{
    facade::CoreStore,
    scoped::{ExpectedRow, MutationRow, Outcome, PredicateRow, ScopedStore},
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
        use busbar_contract::services::codes::service as svc;
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
    // A spent marker is the record encoding with no body: the one encoder builds it.
    Ok((address, encoded_record(expires_at, b"")))
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

/// A ticket's identity: its 32 lowercase hex digits, held inline.
type TicketId = [u8; 32];

/// `id` as a ticket's inline identity: `None` when it is not 32 bytes long (no ticket is).
fn ticket_bytes(id: &str) -> Option<TicketId> {
    id.as_bytes().try_into().ok()
}

/// The map key of one retained ticket operation: the ticket, and whether the operation is the
/// purge of its expired rows. Held inline, so retaining or finding an operation copies no text.
/// Ordered exactly as the keys were when they were text (`<id>`, and `expiry:<id>` for a
/// purge), so maintenance settles the retained operations in the same order.
#[derive(Clone, Copy, PartialEq, Eq)]
struct OperationKey {
    purge: bool,
    id: TicketId,
}

impl OperationKey {
    /// The key of the mint, spend or unbind operation of the ticket `id`.
    fn of(id: &str) -> Option<Self> {
        Some(Self {
            purge: false,
            id: ticket_bytes(id)?,
        })
    }

    /// The key's bytes as its text form had them.
    fn text(&self) -> impl Iterator<Item = u8> + '_ {
        let prefix: &[u8] = if self.purge { b"expiry:" } else { b"" };
        prefix.iter().chain(self.id.iter()).copied()
    }
}

impl Ord for OperationKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.text().cmp(other.text())
    }
}

impl PartialOrd for OperationKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Default)]
pub(super) struct TicketOperations {
    pending: std::sync::Mutex<std::collections::BTreeMap<OperationKey, Arc<TicketOperation>>>,
}

/// What a retained ticket operation checks and writes, kept as the facts it was staged with.
/// Its rows are lent over these facts at each attempt ([`GovState::ticket_attempt`]): the same
/// facts give the same rows, so a resubmit finds the original attempt. Nothing is copied into a
/// request ahead of time.
enum Rows {
    /// A new ticket: nothing is there; its record and its expiry index row are put.
    Mint { original: Secret<Vec<u8>> },
    /// A single-use spend: the record is as it was read, unspent and indexed; the record goes
    /// and the spent marker is put.
    Spend { original: Secret<Vec<u8>> },
    /// An expired ticket's rows, each as the purge observed it: all three go.
    Purge {
        active: Option<Secret<Vec<u8>>>,
        spent: Option<Secret<Vec<u8>>>,
        index: Secret<Vec<u8>>,
    },
    /// A minted ticket whose host binding failed: its record and its index row go.
    Unbind { original: Secret<Vec<u8>> },
}

struct TicketOperation {
    core: Arc<CoreStore>,
    /// The ticket.
    id: TicketId,
    /// The receipt identity, held until the operation drops.
    op: crate::persistence::scoped::Op,
    rows: Rows,
    time: Option<TimeGuard>,
    principal: Arc<VirtualKey>,
    expires_at: u64,
    delivered: AtomicBool,
    runner: super::BudgetFlushRunner,
}

impl TicketOperation {
    /// Where the retained operations keep this one.
    fn key(&self) -> OperationKey {
        OperationKey {
            purge: matches!(self.rows, Rows::Purge { .. }),
            id: self.id,
        }
    }
}

/// The value of a ticket's expiry index row.
const INDEX_VALUE: &[u8] = &[1];

/// A ticket's expiry index key: the big-endian expiry, then the id. Formed on the stack.
fn index_key(id: &TicketId, expires_at: u64) -> [u8; 40] {
    let mut key = [0u8; 40];
    key[..8].copy_from_slice(&expires_at.to_be_bytes());
    key[8..].copy_from_slice(id);
    key
}

/// The value of a spent ticket's marker: the record's version byte and its expiry, with no body.
/// Formed on the stack.
fn spent_marker(expires_at: u64) -> [u8; 9] {
    let mut marker = [0u8; 9];
    marker[0] = 1;
    marker[1..].copy_from_slice(&expires_at.to_be_bytes());
    marker
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
        [TICKET_RECORD_KIND, TICKET_SPENT_KIND, EXPIRY_SCHEMA],
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
            // The store's read request owns its address list: the three addresses are moved
            // into it, not copied.
            addresses: Vec::from(addresses),
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
        let key = OperationKey::of(id)?;
        self.ticket_operations
            .pending
            .lock()
            .ok()?
            .get(&key)
            .cloned()
    }
    /// Let go of `operation`, if it is still the one retained under its key.
    fn forget_ticket_operation(&self, operation: &Arc<TicketOperation>) {
        let key = operation.key();
        let mut pending = self
            .ticket_operations
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        if pending
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, operation))
        {
            pending.remove(&key);
        }
    }
    /// One attempt of a retained operation: its rows are lent over the facts it keeps (the
    /// ticket id, the expiry, the record bytes it read or wrote), so every attempt submits the
    /// same rows under the same receipt identity and nothing is copied to form them.
    async fn ticket_attempt(&self, operation: &TicketOperation) -> Option<Outcome> {
        let store = scope(operation.core.clone())?;
        let id = &operation.id[..];
        let index = index_key(&operation.id, operation.expires_at);
        let record = |expected| PredicateRow {
            schema: TICKET_RECORD_KIND,
            key: id,
            expected,
        };
        let spent = |expected| PredicateRow {
            schema: TICKET_SPENT_KIND,
            key: id,
            expected,
        };
        let indexed = |expected| PredicateRow {
            schema: EXPIRY_SCHEMA,
            key: &index,
            expected,
        };
        let delete = |schema, key| MutationRow::Delete { schema, key };
        let outcome = match &operation.rows {
            Rows::Mint { original } => {
                let original = original.expose(&crate::seal::lend()).as_slice();
                store
                    .conditional_rows_timed(
                        &operation.op,
                        &[
                            record(ExpectedRow::Absent),
                            spent(ExpectedRow::Absent),
                            indexed(ExpectedRow::Absent),
                        ],
                        &[
                            MutationRow::Put {
                                schema: TICKET_RECORD_KIND,
                                key: id,
                                value: original,
                            },
                            MutationRow::Put {
                                schema: EXPIRY_SCHEMA,
                                key: &index,
                                value: INDEX_VALUE,
                            },
                        ],
                        operation.time,
                    )
                    .await
            }
            Rows::Spend { original } => {
                let original = original.expose(&crate::seal::lend()).as_slice();
                let marker = spent_marker(operation.expires_at);
                store
                    .conditional_rows_timed(
                        &operation.op,
                        &[
                            record(ExpectedRow::Exact(original)),
                            spent(ExpectedRow::Absent),
                            indexed(ExpectedRow::Exact(INDEX_VALUE)),
                        ],
                        &[
                            delete(TICKET_RECORD_KIND, id),
                            MutationRow::Put {
                                schema: TICKET_SPENT_KIND,
                                key: id,
                                value: &marker,
                            },
                        ],
                        operation.time,
                    )
                    .await
            }
            Rows::Purge {
                active,
                spent: marker,
                index: observed,
            } => {
                // The three observed values are read under one seal, before the submit waits.
                let (active, marker, observed) = {
                    let seal = crate::seal::lend();
                    (
                        active.as_ref().map_or(ExpectedRow::Absent, |bytes| {
                            ExpectedRow::Exact(bytes.expose(&seal))
                        }),
                        marker.as_ref().map_or(ExpectedRow::Absent, |bytes| {
                            ExpectedRow::Exact(bytes.expose(&seal))
                        }),
                        ExpectedRow::Exact(observed.expose(&seal)),
                    )
                };
                store
                    .conditional_rows_timed(
                        &operation.op,
                        &[record(active), spent(marker), indexed(observed)],
                        &[
                            delete(TICKET_RECORD_KIND, id),
                            delete(TICKET_SPENT_KIND, id),
                            delete(EXPIRY_SCHEMA, &index),
                        ],
                        operation.time,
                    )
                    .await
            }
            Rows::Unbind { original } => {
                let original = original.expose(&crate::seal::lend()).as_slice();
                store
                    .conditional_rows_timed(
                        &operation.op,
                        &[
                            record(ExpectedRow::Exact(original)),
                            indexed(ExpectedRow::Exact(INDEX_VALUE)),
                        ],
                        &[
                            delete(TICKET_RECORD_KIND, id),
                            delete(EXPIRY_SCHEMA, &index),
                        ],
                        operation.time,
                    )
                    .await
            }
        };
        outcome.ok()
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
            // The index key is the expiry, then the ticket's id: the id is read off it in place.
            let id = std::str::from_utf8(&key[8..]).ok()?;
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
            // A spent marker is the record encoding with no body: judged in place, as the
            // single read judges it (`judge_ticket`), with no second copy built to compare.
            if active
                .as_ref()
                .is_some_and(|bytes| record_body_len(bytes, expiry).is_none())
                || spent
                    .as_ref()
                    .is_some_and(|bytes| record_body_len(bytes, expiry) != Some(0))
            {
                return None;
            }
            let operation = Arc::new(TicketOperation {
                core: core.clone(),
                id: ticket_bytes(id)?,
                op: request_id(&core).await?,
                rows: Rows::Purge {
                    active,
                    spent,
                    index,
                },
                time: Some(TimeGuard {
                    not_before: expiry.checked_add(1),
                    before: None,
                }),
                principal: principal.clone(),
                expires_at: expiry,
                delivered: AtomicBool::new(false),
                runner: Default::default(),
            });
            let operation = {
                let mut pending = self.ticket_operations.pending.lock().ok()?;
                let cleanup = operation.key();
                match pending.get(&cleanup) {
                    Some(retained) => retained.clone(),
                    None => {
                        pending.insert(cleanup, operation.clone());
                        operation
                    }
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
                self.forget_ticket_operation(&operation);
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
        for (_, operation) in pending {
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
                self.forget_ticket_operation(&operation);
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
            // The record carries its nine-byte head (version, expiry): the spend's condition is
            // the whole record, and the body it hands back is read off it at redemption.
            record_body_len(&original, expires_at)?;
            let candidate = Arc::new(TicketOperation {
                core: core.clone(),
                id: ticket_bytes(&id)?,
                op: request_id(&core).await?,
                rows: Rows::Spend { original },
                time: Some(TimeGuard {
                    not_before: None,
                    before: expires_at.checked_add(1),
                }),
                principal: principal.clone(),
                expires_at,
                delivered: AtomicBool::new(false),
                runner: Default::default(),
            });
            let key = candidate.key();
            self.ticket_operations
                .pending
                .lock()
                .ok()?
                .entry(key)
                .or_insert(candidate)
                .clone()
        };
        if !matches!(operation.rows, Rows::Spend { .. })
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
        let Rows::Spend { original } = &operation.rows else {
            return None;
        };
        if operation.delivered.load(Ordering::Acquire) || !Arc::ptr_eq(&operation.core, &core) {
            return None;
        }
        match self.ticket_attempt(&operation).await? {
            Outcome::Applied => {
                if operation.delivered.swap(true, Ordering::AcqRel) {
                    return None;
                }
                self.forget_ticket_operation(&operation);
                let current = self.standing_of(ticket, now)?;
                if current.id != identity.principal.id
                    || current.generation_hash != identity.principal.generation_hash
                {
                    return None;
                }
                // The caller owns the body it is handed: the one copy of it, made here, off the
                // record the spend kept (its head is nine bytes: checked when the spend was staged).
                Some((
                    current,
                    crate::cold::governance::state::tickets_record_body(
                        &original.expose(&crate::seal::lend())[9..],
                    ),
                ))
            }
            Outcome::ConditionConflict | Outcome::OpIdConflict | Outcome::NoEffect(_) => {
                operation.delivered.store(true, Ordering::Release);
                self.forget_ticket_operation(&operation);
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
        // A minted id is always 32 hex digits (`ticket_id`), so it always has its inline form.
        let ticket = ticket_bytes(&id).ok_or(TicketRefusal::NotKept)?;
        let operation = Arc::new(TicketOperation {
            core: core.clone(),
            id: ticket,
            op: request_id(&core).await.ok_or(TicketRefusal::NotKept)?,
            // The record is encoded once and kept here: it is the value the mint puts.
            rows: Rows::Mint {
                original: encoded_record(exp, record),
            },
            time: Some(TimeGuard {
                not_before: None,
                before: exp.checked_add(1),
            }),
            principal: key.clone(),
            expires_at: exp,
            delivered: AtomicBool::new(false),
            runner: Default::default(),
        });
        self.ticket_operations
            .pending
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(operation.key(), operation.clone());
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
        self.forget_ticket_operation(&operation);
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
            // The unbind is retained on its own and may outlive the mint's operation, so it
            // keeps its own copy of the record it expects: made only here, when a binding fails.
            let Rows::Mint { original } = &operation.rows else {
                return Err(why);
            };
            let cleanup = Arc::new(TicketOperation {
                core: core.clone(),
                id: ticket,
                op: request_id(&core).await.ok_or(TicketRefusal::NotKept)?,
                rows: Rows::Unbind {
                    original: original.clone(),
                },
                time: None,
                principal: identity.principal.clone(),
                expires_at: exp,
                delivered: AtomicBool::new(false),
                runner: Default::default(),
            });
            self.ticket_operations
                .pending
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .insert(cleanup.key(), cleanup.clone());
            if matches!(
                self.ticket_attempt(&cleanup).await,
                Some(
                    Outcome::Applied
                        | Outcome::ConditionConflict
                        | Outcome::OpIdConflict
                        | Outcome::NoEffect(_)
                )
            ) {
                self.forget_ticket_operation(&cleanup);
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
