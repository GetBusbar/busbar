// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::persistence::{
    facade::{CoreStore, PendingId},
    scoped::{self, ScopedStore},
};
use crate::trust::book::RulingRow;
use busbar_contract::Secret;
use std::sync::{Arc, Mutex};

const SCHEMA: &str = "busbar.trust.v1";

/// The durable quarantine fact. The historical `server` member stays unchanged.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DemotionRow {
    #[serde(rename = "server")]
    pub upstream: String,
    pub reason: String,
    pub recorded_at: u64,
}

pub struct Snapshot {
    pub demotions: Vec<DemotionRow>,
    pub decisions: Vec<RulingRow>,
}

/// Why a decision write did not definitely apply (TRUST-ADMIN-PRODUCER-DESIGN r3 §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteFailure {
    /// An earlier unsettled write for the same key could not be settled first: this call submitted
    /// nothing.
    Earlier(String),
    /// The store decided this write did not apply.
    NotApplied(String),
    /// The write was submitted and its outcome is unknown. Its exact attempt (`op_id`) stays
    /// retained and may still land through the record's own settlement.
    Unknown { op_id: [u8; 16] },
}

/// What the record can prove about one decision attempt (r3 §4.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The store applied it.
    Landed,
    /// The store proved it never applied and never can (`OpIdConflict`: the attempt's sequence is
    /// bound to other bytes).
    NotApplied,
    /// Nothing proves either.
    Unknown,
}

/// How many settled attempt verdicts the record keeps for replay resolution. An evicted verdict
/// reads as [`Verdict::Unknown`], never as a guess.
const VERDICTS_KEPT: usize = 4_096;

struct Attachment {
    core: Arc<CoreStore>,
    records: ScopedStore,
}
struct Write {
    owner: Arc<Attachment>,
    request: Arc<scoped::Request>,
    state: tokio::sync::Mutex<WriteState>,
}
#[derive(Default)]
struct WriteState {
    pending: Option<PendingId>,
    decided: Option<scoped::Outcome>,
}

/// Trust owns opaque host-private records. Each immutable attempt serializes its
/// own waiters; unrelated trust keys can continue while another crossing waits.
#[derive(Default)]
pub struct DemotionRecord {
    owner: Mutex<Option<Arc<Attachment>>>,
    pending: Mutex<Vec<Arc<Write>>>,
    /// Settled decision attempts by `op_id`, oldest first, capped at [`VERDICTS_KEPT`].
    verdicts: Mutex<std::collections::VecDeque<([u8; 16], Verdict)>>,
}

fn error(error: impl std::fmt::Debug) -> String {
    format!("trust persistence: {error:?}")
}
fn demotion_key(upstream: &str) -> Vec<u8> {
    let mut key = vec![b'D'];
    key.extend_from_slice(upstream.as_bytes());
    key
}
fn decision_key(row: &RulingRow) -> Result<Vec<u8>, String> {
    let mut fields = vec![row.instance.as_bytes(), row.counterparty.as_bytes()];
    if let Some(item) = &row.item {
        fields.push(item.as_bytes());
    }
    crate::persistence::keys::framed(b'R', &fields).map_err(error)
}

impl DemotionRecord {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Attachment is immutable: retained attempts cannot follow a replacement backend.
    pub fn set_store(&self, core: Arc<CoreStore>) -> Result<(), String> {
        let mut owner = self.owner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(owner) = &*owner {
            return if Arc::ptr_eq(&owner.core, &core) {
                Ok(())
            } else {
                Err("trust persistence: attachment changed".into())
            };
        }
        let records = ScopedStore::host_private(core.clone(), "trust", [SCHEMA.to_string()])
            .map_err(error)?;
        *owner = Some(Arc::new(Attachment { core, records }));
        Ok(())
    }

    fn owner(&self) -> Option<Arc<Attachment>> {
        self.owner.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Whether a Store is attached: decisions are kept durably only when it is (r3 §6).
    #[must_use]
    pub fn bound(&self) -> bool {
        self.owner().is_some()
    }

    fn remember(&self, op_id: [u8; 16], verdict: Verdict) {
        let mut verdicts = self.verdicts.lock().unwrap_or_else(|e| e.into_inner());
        if verdicts.len() == VERDICTS_KEPT {
            verdicts.pop_front();
        }
        verdicts.push_back((op_id, verdict));
    }

    /// What can be proven about the decision attempt `op_id`, through the record's own
    /// settlement only (r3 §4.6). A still-pending attempt is re-driven as the same attempt (it may
    /// land now: that is the original decision completing, never a new one); a settled one is read
    /// from the verdict table. Anything else is [`Verdict::Unknown`].
    pub async fn attempt_verdict(&self, op_id: [u8; 16]) -> Verdict {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|write| write.request.op.bytes() == op_id)
            .cloned();
        if let Some(write) = pending {
            let _ = self.settle_write(write).await;
        }
        self.verdicts
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .rev()
            .find(|(id, _)| *id == op_id)
            .map_or(Verdict::Unknown, |(_, verdict)| *verdict)
    }

    async fn settle_write(&self, write: Arc<Write>) -> Result<(), String> {
        let mut state = write.state.lock().await;
        if let Some(decided) = state.decided {
            return if decided == scoped::Outcome::Applied {
                Ok(())
            } else {
                Err(error(decided))
            };
        }
        let outcome = match state.pending {
            Some(id) => write.owner.records.retry(id).await,
            None => write.owner.records.conditional_native(&write.request).await,
        }
        .map_err(error)?;
        match outcome {
            scoped::Outcome::Pending(id)
            | scoped::Outcome::Reconcile(id)
            | scoped::Outcome::Busy(Some(id)) => {
                state.pending = Some(id);
                Err(error(outcome))
            }
            scoped::Outcome::Busy(None) => Err(error(outcome)),
            decided => {
                state.decided = Some(decided);
                self.pending
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .retain(|pending| !Arc::ptr_eq(pending, &write));
                match decided {
                    scoped::Outcome::Applied => {
                        self.remember(write.request.op.bytes(), Verdict::Landed)
                    }
                    scoped::Outcome::OpIdConflict => {
                        self.remember(write.request.op.bytes(), Verdict::NotApplied);
                    }
                    _ => {}
                }
                if decided == scoped::Outcome::Applied {
                    Ok(())
                } else {
                    Err(error(decided))
                }
            }
        }
    }

    async fn settle_pending(&self, keys: Option<&[Vec<u8>]>) -> Result<(), String> {
        let pending: Vec<_> = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|write| {
                keys.is_none_or(|keys| {
                    write
                        .request
                        .mutations
                        .iter()
                        .any(|mutation| match mutation {
                            scoped::Mutation::Put { key, .. }
                            | scoped::Mutation::Delete { key, .. } => keys.contains(key),
                            scoped::Mutation::DeleteRange { prefix, .. } => {
                                keys.iter().any(|key| key.starts_with(prefix))
                            }
                        })
                })
            })
            .cloned()
            .collect();
        for write in pending {
            self.settle_write(write).await?;
        }
        Ok(())
    }

    async fn write(&self, mutations: Vec<scoped::Mutation>) -> Result<(), String> {
        self.write_classified(mutations)
            .await
            .map_err(|failure| match failure {
                WriteFailure::Earlier(why) | WriteFailure::NotApplied(why) => why,
                WriteFailure::Unknown { .. } => {
                    error("the outcome is unknown; the attempt is retained")
                }
            })
    }

    /// [`Self::write`] with its failure classified (r3 §4.4): an earlier write that could not be
    /// settled, a decided non-apply, or an unknown outcome whose attempt stays retained.
    async fn write_classified(&self, mutations: Vec<scoped::Mutation>) -> Result<(), WriteFailure> {
        let keys: Vec<_> = mutations
            .iter()
            .map(|mutation| match mutation {
                scoped::Mutation::Put { key, .. } | scoped::Mutation::Delete { key, .. } => {
                    key.clone()
                }
                scoped::Mutation::DeleteRange { prefix, .. } => prefix.clone(),
            })
            .collect();
        self.settle_pending(Some(&keys))
            .await
            .map_err(WriteFailure::Earlier)?;
        let Some(owner) = self.owner() else {
            return Ok(());
        };
        let op = owner
            .records
            .record_op()
            .await
            .map_err(|e| WriteFailure::NotApplied(error(e)))?;
        let write = Arc::new(Write {
            owner,
            request: Arc::new(scoped::Request {
                op,
                predicates: vec![],
                mutations,
            }),
            state: tokio::sync::Mutex::new(WriteState::default()),
        });
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(write.clone());
        let op_id = write.request.op.bytes();
        match self.settle_write(write.clone()).await {
            Ok(()) => Ok(()),
            // A decided outcome other than `Applied` is definite. Anything else leaves the exact
            // attempt retained in `pending`, where it may still land: unknown, never "not applied".
            Err(why) if write.state.lock().await.decided.is_some() => {
                Err(WriteFailure::NotApplied(why))
            }
            Err(_) => Err(WriteFailure::Unknown { op_id }),
        }
    }

    pub async fn record(&self, upstream: &str, reason: &str, now: u64) -> Result<(), String> {
        let row = DemotionRow {
            upstream: upstream.into(),
            reason: reason.into(),
            recorded_at: now,
        };
        self.write(vec![put(demotion_key(upstream), &row)?]).await
    }

    pub(crate) async fn clear(&self, upstream: &str) -> Result<(), String> {
        self.write(vec![scoped::Mutation::Delete {
            schema: SCHEMA.into(),
            key: demotion_key(upstream),
        }])
        .await
    }

    /// A ruling and the quarantine rows it supersedes publish in one native commit.
    pub async fn keep_decision(&self, row: &RulingRow, _now: u64) -> Result<(), String> {
        self.keep_decision_clearing(row, &[]).await
    }

    /// Keep one decision and clear the quarantines it supersedes, in one native commit, with the
    /// failure classified (r3 §4.4).
    pub(crate) async fn keep_decision_attempt(
        &self,
        row: &RulingRow,
        clear: &[String],
    ) -> Result<(), WriteFailure> {
        let mut mutations = vec![
            put(decision_key(row).map_err(WriteFailure::NotApplied)?, row)
                .map_err(WriteFailure::NotApplied)?,
        ];
        for upstream in clear {
            mutations.push(scoped::Mutation::Delete {
                schema: SCHEMA.into(),
                key: demotion_key(upstream),
            });
        }
        self.write_classified(mutations).await
    }

    pub(crate) async fn keep_decision_clearing(
        &self,
        row: &RulingRow,
        clear: &[String],
    ) -> Result<(), String> {
        let mut mutations = vec![put(decision_key(row)?, row)?];
        for upstream in clear {
            mutations.push(scoped::Mutation::Delete {
                schema: SCHEMA.into(),
                key: demotion_key(upstream),
            });
        }
        self.write(mutations).await
    }

    /// Both families share a schema generation, so admission cannot combine
    /// quarantine and ruling pages from different observed histories.
    pub async fn snapshot(&self) -> Result<Snapshot, String> {
        self.settle_pending(None).await?;
        let mut snapshot = Snapshot {
            demotions: vec![],
            decisions: vec![],
        };
        let Some(owner) = self.owner() else {
            return Ok(snapshot);
        };
        let mut after = None;
        loop {
            let page = owner
                .records
                .page(SCHEMA, b"", after.as_ref())
                .await
                .map_err(error)?;
            for (key, value) in page.rows {
                let seal = crate::seal::lend();
                let value = value.expose(&seal);
                match key.first() {
                    Some(b'D') => {
                        let row: DemotionRow =
                            busbar_contract::json::parse(value).map_err(error)?;
                        if key != demotion_key(&row.upstream) {
                            return Err("trust persistence: demotion identity mismatch".into());
                        }
                        snapshot.demotions.push(row);
                    }
                    Some(b'R') => {
                        let row: RulingRow = busbar_contract::json::parse(value).map_err(error)?;
                        if key != decision_key(&row)? {
                            return Err("trust persistence: ruling identity mismatch".into());
                        }
                        snapshot.decisions.push(row);
                    }
                    _ => return Err("trust persistence: unknown record".into()),
                }
            }
            after = page.next;
            if after.is_none() {
                return Ok(snapshot);
            }
        }
    }

    /// Every kept row, read straight from the Store **without** settling pending writes, so a
    /// read-scope admin GET never drives a write (r3 §3.5). `Err` when no Store is attached.
    pub async fn kept(&self) -> Result<Snapshot, String> {
        let owner = self
            .owner()
            .ok_or_else(|| "trust persistence: no store is attached".to_string())?;
        let mut snapshot = Snapshot {
            demotions: vec![],
            decisions: vec![],
        };
        let mut after = None;
        loop {
            let page = owner
                .records
                .page(SCHEMA, b"", after.as_ref())
                .await
                .map_err(error)?;
            for (key, value) in page.rows {
                let seal = crate::seal::lend();
                let value = value.expose(&seal);
                match key.first() {
                    Some(b'D') => {
                        snapshot
                            .demotions
                            .push(busbar_contract::json::parse(value).map_err(error)?);
                    }
                    Some(b'R') => {
                        snapshot
                            .decisions
                            .push(busbar_contract::json::parse(value).map_err(error)?);
                    }
                    _ => return Err("trust persistence: unknown record".into()),
                }
            }
            after = page.next;
            if after.is_none() {
                return Ok(snapshot);
            }
        }
    }

    pub async fn read(&self) -> Result<Vec<DemotionRow>, String> {
        Ok(self.snapshot().await?.demotions)
    }
    pub async fn decisions(&self) -> Result<Vec<RulingRow>, String> {
        Ok(self.snapshot().await?.decisions)
    }
    #[cfg(test)]
    pub async fn list(&self) -> Vec<DemotionRow> {
        self.read().await.expect("the test store answers")
    }
}

fn put(key: Vec<u8>, value: &impl serde::Serialize) -> Result<scoped::Mutation, String> {
    Ok(scoped::Mutation::Put {
        schema: SCHEMA.into(),
        key,
        value: Secret::new(busbar_contract::json::to_vec(value).map_err(error)?),
    })
}
pub(crate) async fn settle(
    demotions: &DemotionRecord,
    upstream: &str,
    state: crate::trust::TrustState,
) -> Result<(), String> {
    match state {
        crate::trust::TrustState::Quarantined => {
            demotions
                .record(upstream, state.word(), crate::store::now())
                .await
        }
        crate::trust::TrustState::Approved => demotions.clear(upstream).await,
        _ => Ok(()),
    }
}

#[cfg(test)]
#[path = "tests/demotion_tests.rs"]
mod demotion_tests;

/// Canonical destination for one fenced historical trust row. Body bytes stay
/// exact; parsing establishes identity only and never rewrites signed/history data.
pub fn migration_trust_rows(
    kind: &str,
    id: &str,
    body: &[u8],
) -> Result<(busbar_contract::persistence::Address, Secret<Vec<u8>>), String> {
    let key = match kind {
        "demotion" => {
            let row: DemotionRow = busbar_contract::json::parse(body).map_err(error)?;
            if row.upstream.is_empty() || row.upstream != id {
                return Err("trust migration: demotion identity mismatch".into());
            }
            demotion_key(&row.upstream)
        }
        "trust_decision" => {
            let row: RulingRow = busbar_contract::json::parse(body).map_err(error)?;
            if row.instance.is_empty()
                || row.counterparty.is_empty()
                || row.item.as_ref().is_some_and(String::is_empty)
            {
                return Err("trust migration: invalid ruling identity".into());
            }
            let sep = crate::host_services::DEMOTION_SEP;
            let mut legacy = format!("{}{sep}{}", row.instance, row.counterparty);
            if let Some(item) = &row.item {
                legacy.push(sep);
                legacy.push_str(item);
            }
            if legacy != id {
                return Err("trust migration: ruling identity mismatch".into());
            }
            decision_key(&row)?
        }
        _ => return Err("trust migration: unknown row family".into()),
    };
    let address = scoped::migration_address(true, "trust", SCHEMA, &key).map_err(error)?;
    Ok((address, Secret::new(body.to_vec())))
}

/// Authority remains confined to the compiled trust owner/schema.
pub fn migration_trust_authorizes(address: &busbar_contract::persistence::Address) -> bool {
    scoped::migration_authorizes(true, "trust", SCHEMA, address)
}
