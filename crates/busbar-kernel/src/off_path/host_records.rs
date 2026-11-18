// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! [`crate::host_records`]' write-behind flusher and [`crate::host_records_async::AsyncHistory`]'s
//! admission-time constructors.
//!
//! The flusher drains the write-behind queue in batches of up to [`BATCH_CAP`] on the offload pool
//! (started by a queued write or by `flush_tick`), after each writer's request has already returned:
//! it never runs on a request, and each writer hears its answer through its `Owed`. A history's
//! collection declarations are bound once, when its owner is admitted or first opened.

use std::sync::Arc;

use busbar_contract::host_records::conditional;
use busbar_contract::records::Retention;

use crate::host_records::{
    record_key, AsyncBatch, ConditionalFailure, ConditionalResult, ConditionalWrite, NativeWrite,
    PendingRecords, QueuedWrite, RecordRows, WriteBehind, BATCH_CAP, WRITE_FAILED,
};
use crate::host_records_async::{AsyncHistory, Declaration, HistoryCollection, HistoryError};
use crate::persistence::history;

impl NativeWrite {
    pub(crate) async fn attempt(
        &mut self,
        store: &Arc<crate::persistence::facade::CoreStore>,
        book: &crate::host_chains::ChainBook,
    ) -> Option<Result<(), &'static str>> {
        use crate::persistence::scoped::{Mutation, Outcome, Predicate, Request, ScopedStore};
        // The two schemas by their own fixed names: named, never copied.
        let schemas = [
            self.write.schema.as_str(),
            crate::host_chains::CHAIN_LIFE_SCHEMA.as_str(),
        ];
        let scoped = match if self.private {
            ScopedStore::host_private(Arc::clone(store), &self.write.instance, schemas)
        } else {
            ScopedStore::authorized(Arc::clone(store), &self.write.instance, schemas)
        } {
            Ok(scoped) => scoped,
            Err(_) => return Some(Err(WRITE_FAILED)),
        };
        if self.request.is_none() {
            let held = match store.record_op().await {
                Ok(held) => held,
                Err(_) => return Some(Err(WRITE_FAILED)),
            };
            if let Some(framing) = self.write.chain {
                let rows = match crate::host_records_async::AsyncRecords::authorized(
                    Arc::clone(store),
                    &self.write.instance,
                    schemas,
                ) {
                    Ok(rows) => rows,
                    Err(_) => return Some(Err(WRITE_FAILED)),
                };
                let scope = match std::str::from_utf8(&self.write.key) {
                    Ok(scope) => scope,
                    Err(_) => return Some(Err(crate::host_chains::CHAIN_SCOPE_UNFIT)),
                };
                let input = crate::host_chains::OrdinaryChain {
                    instance: &self.write.instance,
                    schema: self.write.schema,
                    scope,
                    content: self.write.value.as_slice(),
                    framing,
                };
                let (request, position) =
                    match book.prepare_ordinary_async(&rows, input, &held).await {
                        Ok(prepared) => prepared,
                        Err(why) => return Some(Err(why)),
                    };
                match native_request(&self.write.instance, &request, held) {
                    Ok(request) => self.request = Some(request),
                    Err(why) => return Some(Err(why)),
                };
                self.positions.push(position);
            } else {
                let request = Request {
                    op: held.into(),
                    predicates: Vec::<Predicate>::new(),
                    mutations: vec![if self.write.value.as_slice().is_empty() {
                        Mutation::Delete {
                            schema: self.write.schema.as_str().into(),
                            key: self.write.key.clone(),
                        }
                    } else {
                        Mutation::Put {
                            schema: self.write.schema.as_str().into(),
                            key: self.write.key.clone(),
                            value: busbar_contract::Secret::new(
                                self.write.value.as_slice().to_vec(),
                            ),
                        }
                    }],
                };
                self.request = Some(request);
            }
        }
        let result = match self.pending {
            Some(id) => scoped.retry(id).await,
            None => scoped.conditional_native(self.request.as_ref()?).await,
        };
        match result {
            Ok(Outcome::Applied) => {
                for position in &self.positions {
                    book.conditional_settled(position, conditional::Decision::Applied);
                }
                Some(Ok(()))
            }
            Ok(Outcome::ConditionConflict) if self.write.chain.is_some() => {
                for position in &self.positions {
                    book.conditional_settled(position, conditional::Decision::ConditionConflict);
                }
                self.request = None;
                self.pending = None;
                self.positions.clear();
                self.conflicts += 1;
                if self.conflicts >= crate::host_chains::CLAIM_ATTEMPTS {
                    Some(Err(WRITE_FAILED))
                } else {
                    None
                }
            }
            Ok(Outcome::ConditionConflict | Outcome::OpIdConflict | Outcome::NoEffect(_)) => {
                Some(Err(WRITE_FAILED))
            }
            Ok(Outcome::Pending(id) | Outcome::Reconcile(id) | Outcome::Busy(Some(id))) => {
                self.pending = Some(id);
                None
            }
            Ok(Outcome::Busy(None)) => None,
            Err(_) if self.pending.is_some() => None,
            Err(_) => Some(Err(WRITE_FAILED)),
        }
    }
}

fn native_request(
    instance: &str,
    request: &conditional::Request,
    held: crate::persistence::record_ops::HeldOp,
) -> Result<crate::persistence::scoped::Request, &'static str> {
    use crate::persistence::scoped::{Expected, Mutation, Predicate, Request};
    if request.op_id != held.op_id() {
        return Err(WRITE_FAILED);
    }
    let scope = record_key(instance, &[]);
    let key = |key: &[u8]| {
        key.strip_prefix(scope.as_slice())
            .map(<[u8]>::to_vec)
            .ok_or(WRITE_FAILED)
    };
    Ok(Request {
        op: held.into(),
        predicates: request
            .predicates
            .iter()
            .map(|predicate| {
                Ok(Predicate {
                    schema: predicate.schema.clone(),
                    key: key(&predicate.key)?,
                    expected: match &predicate.expected {
                        conditional::Expected::Absent => Expected::Absent,
                        conditional::Expected::Bytes(bytes) => {
                            Expected::Exact(busbar_contract::Secret::new(bytes.clone()))
                        }
                    },
                })
            })
            .collect::<Result<_, &'static str>>()?,
        mutations: request
            .mutations
            .iter()
            .map(|mutation| {
                Ok(match mutation {
                    conditional::Mutation::Put {
                        schema,
                        key: at,
                        value,
                    } => Mutation::Put {
                        schema: schema.clone(),
                        key: key(at)?,
                        value: busbar_contract::Secret::new(value.clone()),
                    },
                    conditional::Mutation::Delete { schema, key: at } => Mutation::Delete {
                        schema: schema.clone(),
                        key: key(at)?,
                    },
                    conditional::Mutation::DeleteRange {
                        schema,
                        prefix,
                        exact_key_length,
                    } => Mutation::DeleteRange {
                        schema: schema.clone(),
                        prefix: key(prefix)?,
                        exact_key_length: exact_key_length
                            .checked_sub(scope.len() as u64)
                            .ok_or(WRITE_FAILED)?,
                    },
                })
            })
            .collect::<Result<_, &'static str>>()?,
    })
}

impl ConditionalWrite {
    pub(crate) async fn attempt_native(
        &mut self,
        store: &Arc<crate::persistence::facade::CoreStore>,
        book: &crate::host_chains::ChainBook,
    ) -> Option<Result<conditional::Decision, ConditionalFailure>> {
        use crate::persistence::scoped::Outcome;
        let schemas: std::collections::BTreeSet<String> = self
            .request
            .predicates
            .iter()
            .map(|p| p.schema.clone())
            .chain(
                self.request
                    .mutations
                    .iter()
                    .map(|m| m.address().0.to_string()),
            )
            .chain(
                self.chains
                    .iter()
                    .map(|chain| chain.schema.as_str().to_string()),
            )
            .chain(std::iter::once(
                crate::host_chains::CHAIN_LIFE_SCHEMA.as_str().to_string(),
            ))
            .collect();
        let rows = match crate::host_records_async::AsyncRecords::authorized(
            Arc::clone(store),
            &self.instance,
            schemas,
        ) {
            Ok(rows) => rows,
            Err(_) => return Some(Err(ConditionalFailure::Refused(WRITE_FAILED))),
        };
        if !self.prepared {
            // Discovery may await between chains. Publish the complete plan to
            // retained queue custody only after every chain has been prepared;
            // cancellation cannot append a second copy to a partial request.
            let mut request = self.request.clone();
            let mut positions = Vec::new();
            for chain in self.chains.iter() {
                match chain
                    .prepare_async(&rows, &self.instance, &mut request, book)
                    .await
                {
                    Ok(position) => positions.push(position),
                    Err(why) => return Some(Err(ConditionalFailure::Refused(why))),
                }
            }
            if request.encode_held().is_err() {
                return Some(Err(ConditionalFailure::Refused(
                    "invalid record transaction",
                )));
            }
            self.request = request;
            self.positions = positions;
            self.prepared = true;
        }
        let result = match (self.native_pending, self.held.as_ref()) {
            (Some(id), _) => rows.retry(id).await,
            (None, Some(held)) => rows.conditional(held, &self.request).await,
            // Admitted for CoreStore without its held identity: never submitted.
            (None, None) => return Some(Err(ConditionalFailure::Refused(WRITE_FAILED))),
        };
        let decision = match result {
            Ok(Outcome::Applied) => conditional::Decision::Applied,
            Ok(Outcome::ConditionConflict) => conditional::Decision::ConditionConflict,
            Ok(Outcome::OpIdConflict) => return Some(Err(ConditionalFailure::OpIdConflict)),
            Ok(Outcome::Pending(id) | Outcome::Busy(Some(id))) => {
                self.native_pending = Some(id);
                return None;
            }
            Ok(Outcome::Reconcile(id)) => {
                self.native_pending = Some(id);
                if let Some(acked) = self.owed.acked.take() {
                    acked(ConditionalResult {
                        correlation: self.owed.correlation,
                        decision: Err(ConditionalFailure::Indeterminate),
                    })
                };
                return None;
            }
            Ok(Outcome::Busy(None)) => return None,
            Ok(Outcome::NoEffect(_)) => {
                return Some(Err(ConditionalFailure::Refused(WRITE_FAILED)))
            }
            Err(_) if self.native_pending.is_some() => return None,
            Err(_) => return Some(Err(ConditionalFailure::Refused(WRITE_FAILED))),
        };
        for position in &self.positions {
            book.conditional_settled(position, decision);
        }
        Some(Ok(decision))
    }
}

impl WriteBehind {
    pub(crate) async fn flush_native(
        self: &Arc<Self>,
        pending: &PendingRecords,
        store: &Arc<crate::persistence::facade::CoreStore>,
        chains: &crate::host_chains::ChainBook,
    ) {
        loop {
            let batch = {
                let mut queue = self.lock();
                let count = queue.writes.len().min(BATCH_CAP);
                let batch: std::collections::VecDeque<_> = queue.writes.drain(..count).collect();
                queue.in_flight += count;
                if count == 0 {
                    queue.flushing = false;
                    return;
                }
                batch
            };
            let mut held = AsyncBatch {
                owner: Arc::clone(self),
                count: batch.len(),
                batch,
                unresolved: Vec::new(),
            };
            while !held.batch.is_empty() {
                if matches!(held.batch.front(), Some(QueuedWrite::Ordinary(_))) {
                    if let Some(QueuedWrite::Ordinary(write)) = held.batch.pop_front() {
                        held.batch.push_front(QueuedWrite::Native(NativeWrite {
                            write,
                            request: None,
                            pending: None,
                            positions: Vec::new(),
                            private: false,
                            conflicts: 0,
                        }));
                    }
                }
                match held.batch.front_mut() {
                    Some(QueuedWrite::Native(write)) => {
                        let result = write.attempt(store, chains).await;
                        if let Some(result) = result {
                            if let Some(QueuedWrite::Native(write)) = held.batch.pop_front() {
                                pending.acked(
                                    &write.write.instance,
                                    write.write.schema.as_str(),
                                    &write.write.key,
                                    write.write.seq,
                                );
                                write.write.owed.answer(result);
                            }
                        } else if let Some(write) = held.batch.pop_front() {
                            held.unresolved.push(write);
                            held.unresolved.extend(held.batch.drain(..));
                            break;
                        }
                    }
                    Some(QueuedWrite::Conditional(write)) => {
                        let result = write.attempt_native(store, chains).await;
                        if let Some(result) = result {
                            if let Some(QueuedWrite::Conditional(write)) = held.batch.pop_front() {
                                write.owed.answer(result);
                            }
                        } else if let Some(write) = held.batch.pop_front() {
                            held.unresolved.push(write);
                            held.unresolved.extend(held.batch.drain(..));
                            break;
                        }
                    }
                    _ => unreachable!("ordinary writes converted before crossing"),
                }
            }
            let retry = !held.unresolved.is_empty();
            {
                let mut queue = self.lock();
                queue.in_flight -= held.count;
                if retry {
                    let mut retained = std::mem::take(&mut held.unresolved);
                    retained.append(&mut queue.writes);
                    queue.writes = retained;
                    queue.flushing = false;
                }
            }
            held.count = 0;
            if retry {
                return;
            }
        }
    }

    pub fn flush(
        &self,
        pending: &PendingRecords,
        rows: &dyn RecordRows,
        chains: &crate::host_chains::ChainBook,
    ) {
        loop {
            let mut unresolved = Vec::new();
            let batch = {
                let mut q = self.lock();
                let n = q.writes.len().min(BATCH_CAP);
                let batch: Vec<QueuedWrite> = q.writes.drain(..n).collect();
                q.in_flight += batch.len();
                if batch.is_empty() {
                    q.flushing = false;
                    return;
                }
                batch
            };
            let batch_len = batch.len();
            for queued in batch {
                let w = match queued {
                    QueuedWrite::Ordinary(w) => w,
                    QueuedWrite::Native(w) => {
                        unresolved.push(QueuedWrite::Native(w));
                        continue;
                    }
                    QueuedWrite::Conditional(w) => {
                        if let Some(write) = w.attempt(rows, chains) {
                            unresolved.push(QueuedWrite::Conditional(write));
                        }
                        continue;
                    }
                };
                if let Some(framing) = w.chain {
                    let scope = String::from_utf8_lossy(&w.key);
                    let took = if w.value.as_slice().is_empty() {
                        chains.drop_chain(rows, &w.instance, w.schema, &scope)
                    } else {
                        chains.append(
                            rows,
                            &w.instance,
                            w.schema,
                            &scope,
                            w.value.as_slice(),
                            framing,
                        )
                    };
                    w.owed.answer(took);
                    continue;
                }
                let key = record_key(&w.instance, &w.key);
                let took = rows.record_put(w.schema, &key, &w.value);
                pending.acked(&w.instance, w.schema.as_str(), &w.key, w.seq);
                w.owed.answer(took.map_err(|_| WRITE_FAILED));
            }
            let mut q = self.lock();
            q.in_flight -= batch_len;
            if !unresolved.is_empty() {
                q.writes.append(&mut unresolved);
                q.flushing = false;
                return;
            }
        }
    }
}

impl AsyncHistory {
    /// Bind explicit host-owned collection declarations without plugin facts.
    pub fn authorized<'a>(
        store: Arc<crate::persistence::facade::CoreStore>,
        instance: &str,
        declarations: impl IntoIterator<Item = HistoryCollection<'a>>,
    ) -> Result<Self, HistoryError> {
        let result = Self {
            store,
            instance: instance.into(),
            declarations: declarations
                .into_iter()
                .map(|declaration| Declaration {
                    kind: declaration.kind.into(),
                    mode: declaration.mode,
                    retention: declaration.retention,
                    parent: declaration.parent.map(str::to_string),
                })
                .collect(),
        };
        result.owner()?;
        Ok(result)
    }

    /// Core envelope sinks use independently authorized upsert collections.
    /// An opaque envelope parent field does not declare a collection graph.
    pub fn authorized_upserts(
        store: Arc<crate::persistence::facade::CoreStore>,
        instance: &str,
        kinds: impl IntoIterator<Item = String>,
    ) -> Result<Self, HistoryError> {
        let result = Self {
            store,
            instance: instance.into(),
            declarations: kinds
                .into_iter()
                .map(|kind| Declaration {
                    kind,
                    mode: history::Mode::Upsert,
                    retention: Retention::Age,
                    parent: None,
                })
                .collect(),
        };
        result.owner()?;
        Ok(result)
    }

    pub fn admitted(
        store: Arc<crate::persistence::facade::CoreStore>,
        instance: &str,
        facts: &crate::host_services::InstanceFacts,
    ) -> Result<Self, history::Error> {
        let declarations = facts
            .record_collections
            .iter()
            .map(|d| {
                let kind = facts
                    .record_kinds
                    .get(d.kind as usize)
                    .ok_or(history::Error::Unauthorized)?
                    .as_str()
                    .to_string();
                let parent = d
                    .parent
                    .map(|index| {
                        facts
                            .record_kinds
                            .get(index as usize)
                            .map(|k| k.as_str().to_string())
                            .ok_or(history::Error::Unauthorized)
                    })
                    .transpose()?;
                let retention = facts
                    .record_retentions
                    .iter()
                    .find(|r| r.kind == d.kind)
                    .map(|r| Retention::from_code(r.rule).ok_or(history::Error::Invalid))
                    .transpose()?
                    .unwrap_or_default();
                let mode = match d.mode {
                    busbar_contract::abi::plane::CollectionMode::Upsert => history::Mode::Upsert,
                    busbar_contract::abi::plane::CollectionMode::Append => history::Mode::Append,
                };
                Ok(Declaration {
                    kind,
                    mode,
                    retention,
                    parent,
                })
            })
            .collect::<Result<Vec<_>, history::Error>>()?;
        let result = Self {
            store,
            instance: instance.into(),
            declarations,
        };
        result.owner()?;
        Ok(result)
    }
}
