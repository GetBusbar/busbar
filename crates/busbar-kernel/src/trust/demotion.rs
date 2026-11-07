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
        let keys: Vec<_> = mutations
            .iter()
            .map(|mutation| match mutation {
                scoped::Mutation::Put { key, .. } | scoped::Mutation::Delete { key, .. } => {
                    key.clone()
                }
                scoped::Mutation::DeleteRange { prefix, .. } => prefix.clone(),
            })
            .collect();
        self.settle_pending(Some(&keys)).await?;
        let Some(owner) = self.owner() else {
            return Ok(());
        };
        let write = Arc::new(Write {
            owner,
            request: Arc::new(scoped::Request {
                op_id: crate::door::op_id().0,
                predicates: vec![],
                mutations,
            }),
            state: tokio::sync::Mutex::new(WriteState::default()),
        });
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(write.clone());
        self.settle_write(write).await
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
                        let row: DemotionRow = serde_json::from_slice(value).map_err(error)?;
                        if key != demotion_key(&row.upstream) {
                            return Err("trust persistence: demotion identity mismatch".into());
                        }
                        snapshot.demotions.push(row);
                    }
                    Some(b'R') => {
                        let row: RulingRow = serde_json::from_slice(value).map_err(error)?;
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
        value: Secret::new(serde_json::to_vec(value).map_err(error)?),
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
            let row: DemotionRow = serde_json::from_slice(body).map_err(error)?;
            if row.upstream.is_empty() || row.upstream != id {
                return Err("trust migration: demotion identity mismatch".into());
            }
            demotion_key(&row.upstream)
        }
        "trust_decision" => {
            let row: RulingRow = serde_json::from_slice(body).map_err(error)?;
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
