// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store-backed [`DurableWork`] (IF §12.24): durable paid work over `host_work/` rows, the recovery binding the
//! governance standing captures (`host_recovery.rs`), for the WORK intents of the MIN-3 plane instances.
//!
//! A WORK_OPEN writes one `kernel-work` row under the instance's private namespace before it answers, carrying the
//! opt-in poll record of the ROUTE_RECOVERY target and the [`RecoveryBinding`] of the verified principal: the id,
//! generation and expiry the recovery scheduler re-resolves standing from, so a deleted, disabled or expired
//! principal is never recovered. The reference is the row's key. Rows are scoped to the principal that opened them
//! (`owner_of`): another principal's reference answers `R_DENIED`.
//!
//! Core refuses (`R_UNSUPPORTED`, the IF's fail-closed answer, so the plane sends no paid create) while the
//! recovery scheduler is stopped or governance holds no live standing for the principal. The store and
//! generation-scoped governance policy are complete constructor inputs, before any plane opens.
//!
//! The MIN-3 instances are not admitted in `KernelServices` (no `InstanceFacts`), so this custody does not go
//! through its unit-bound `work_*` services: it opens the instance's private [`ScopedStore`] itself, over the same
//! row format, so a row written here reads back through `Work::read` and the recovery scan alike.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use busbar_plugin_abi::fail::refused::{
    R_DENIED, R_INVALID, R_NOT_FOUND, R_RATE_LIMITED, R_UNSUPPORTED,
};
use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};
use busbar_plugin_abi::plane::{WORK_LIVE, WORK_SETTLED};
use busbar_plugin_abi::records::{tag as g, Records};

use super::port_intents::DurableWork;
use crate::host_services::{ActiveSet, RecoveryWork, WallMs};
use crate::host_work::{
    owner_of, parse_reference, reference_text, refusal, RecoveryBinding, Reference, Work, WorkBook,
    WorkBounds, WORK_SCHEMA,
};
use crate::persistence::facade::CoreStore;
use crate::persistence::scoped::{Cursor, Outcome, ScopedStore};

/// The kind a plane's WORK row is kept under (the row's own `kind` field; the schema is [`WORK_SCHEMA`]).
const KIND: &str = "plane";

/// Recovered work items handed back per scan (the admitted instances' scheduler batch).
const RECOVERY_BATCH: usize = 8;

/// What governance captures for a principal at open: the recovery binding of the live principal `subject` at
/// `now_s`, or why it has none (no live principal, no current standing, an external role with no expiry).
pub type Binder = dyn Fn(&str, u64) -> Result<RecoveryBinding, &'static str> + Send + Sync;

/// The generation's complete governance policy. The live governance book still decides standing
/// on each operation; retaining a generation never freezes revocation or expiry.
#[must_use]
pub fn governed_binder(
    governance: Option<Arc<crate::governance::GovState>>,
    role_bindings: crate::config::RoleBindings,
) -> Arc<Binder> {
    let standing = super::host::policy_standing(governance.clone(), role_bindings);
    Arc::new(move |subject, now| {
        let key = governance
            .as_deref()
            .and_then(|gov| gov.lookup_by_sub(subject))
            .ok_or("recovery requires an authenticated principal")?;
        crate::host_services::recovery_binding_of(&key, now, Some(&standing))
    })
}

/// [`DurableWork`] over the core store.
pub struct StoreWork {
    store: Arc<CoreStore>,
    binder: Arc<Binder>,
    book: Arc<WorkBook>,
    bounds: WorkBounds,
    wall_ms: WallMs,
    /// The recovery scheduler is running (`supports_work_recovery`'s gate): without it no paid work is opened.
    ready: AtomicBool,
    /// Each instance's recovery scan: its cursor and the rows of the page not yet handed out.
    scans: tokio::sync::Mutex<foldhash::HashMap<Arc<str>, Scan>>,
    /// The rows a recovery session holds in this process.
    active: ActiveSet,
}

/// One instance's recovery scan state, kept across scheduler ticks so slow polls never restart it from the first
/// row.
#[derive(Default)]
struct Scan {
    cursor: Option<Cursor>,
    pending: VecDeque<(Vec<u8>, busbar_contract::Secret<Vec<u8>>)>,
}

impl StoreWork {
    #[must_use]
    pub fn new(store: Arc<CoreStore>, binder: Arc<Binder>, wall_ms: WallMs) -> Self {
        Self {
            store,
            binder,
            book: Arc::new(WorkBook::default()),
            bounds: WorkBounds::DEFAULT,
            wall_ms,
            ready: AtomicBool::new(false),
            scans: tokio::sync::Mutex::default(),
            active: ActiveSet::default(),
        }
    }

    /// The instance's bounds (`work.max_live`, `work.retain_s`).
    #[must_use]
    pub fn with_bounds(mut self, bounds: WorkBounds) -> Self {
        self.bounds = bounds;
        self
    }

    /// Composition-root scheduler lifetime: true while the recovery scheduler runs.
    pub fn set_recovery_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }

    /// The instance's private work rows, with its book loaded from them (once).
    async fn rows(&self, plane: &Caller<'_>) -> Result<(ScopedStore, Arc<str>), u32> {
        let store = &self.store;
        let instance: Arc<str> = Arc::from(plane.name);
        let rows = ScopedStore::host_private(Arc::clone(store), &instance, [WORK_SCHEMA.as_str()])
            .map_err(|_| R_UNSUPPORTED)?;
        self.book
            .load_native(&rows, &instance)
            .await
            .map_err(|_| R_UNSUPPORTED)?;
        Ok((rows, instance))
    }

    /// The row a reference names, from the book or (one this process has not seen) the store.
    async fn held(
        &self,
        rows: &ScopedStore,
        instance: &Arc<str>,
        reference: &str,
    ) -> Result<(u64, Work), u32> {
        let key = parse_reference(reference.as_bytes()).ok_or(R_NOT_FOUND)?;
        if let Some(held) = self.book.by_reference(instance, &key) {
            return Ok(held);
        }
        let row = rows
            .get(WORK_SCHEMA.as_str(), &key)
            .await
            .map_err(|_| R_UNSUPPORTED)?
            .ok_or(R_NOT_FOUND)?;
        let work =
            Work::read(instance, key, row.expose(&crate::seal::lend())).ok_or(R_NOT_FOUND)?;
        Ok((self.book.adopt(work.clone()), work))
    }

    /// `work` is the verified subject's, and still retained (live, or settled within `retain_ms`).
    fn visible(&self, work: &Work, owner: &crate::host_work::Owner) -> Result<(), u32> {
        if work.owner != *owner {
            return Err(R_DENIED);
        }
        if work.live || work.settled_ms.saturating_add(self.bounds.retain_ms) > (self.wall_ms)() {
            Ok(())
        } else {
            Err(R_NOT_FOUND)
        }
    }
}

/// The ID_SUBJECT text of the request's identity records: the principal a WORK row binds to.
pub(crate) fn subject_of(identity: &[u8]) -> Option<&str> {
    let mut records = Records::new(identity);
    while let Some(Ok(rec)) = records.next_rec() {
        if rec.tag == g::ID_SUBJECT {
            return rec.text().ok().filter(|s| !s.is_empty());
        }
    }
    None
}

impl DurableWork for StoreWork {
    fn open<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        principal: &'a [u8],
        target: &'a str,
    ) -> BoxFut<'a, Result<Box<str>, u32>> {
        Box::pin(async move {
            let subject = subject_of(principal).ok_or(R_DENIED)?;
            let record =
                busbar_contract::abi::sdk::recovery::poll_record(target).map_err(|_| R_INVALID)?;
            if !self.ready.load(Ordering::Acquire) {
                return Err(R_UNSUPPORTED);
            }
            let binder = &self.binder;
            let now_ms = (self.wall_ms)();
            let recovery = binder(subject, now_ms / 1000).map_err(|_| R_UNSUPPORTED)?;
            let (rows, instance) = self.rows(plane).await?;
            for gone in self.book.sweep(&instance, now_ms, self.bounds.retain_ms) {
                // A swept row that is not deleted now is swept again by the next open.
                let _ = rows.delete(WORK_SCHEMA.as_str(), &gone).await;
            }
            let mut key: Reference = [0; 16];
            busbar_contract::crypto::fill(&mut key).map_err(|_| R_UNSUPPORTED)?;
            let work = Work {
                instance: Arc::clone(&instance),
                reference: key,
                kind: busbar_contract::kept::Text::fixed(KIND),
                owner: owner_of(Some(subject)),
                live: true,
                opened_ms: now_ms,
                settled_ms: 0,
                record,
                bound: None,
                // Opened by this process: the book counts it against `max_live`. No unit is in flight for it.
                opened_by: Some(0),
                recovery: Some(recovery),
            };
            let row = work.row().ok_or(R_INVALID)?;
            let handle = self
                .book
                .reserve(work, self.bounds.max_live)
                .ok_or(R_RATE_LIMITED)?;
            let put = rows
                .put(
                    WORK_SCHEMA.as_str(),
                    &key,
                    busbar_contract::Secret::new(row.into_vec()),
                )
                .await;
            if matches!(put, Ok(Outcome::Applied)) {
                Ok(reference_text(&key).into())
            } else {
                // Unconfirmed custody never authorises the paid create.
                self.book.unreserve(handle);
                Err(R_UNSUPPORTED)
            }
        })
    }

    fn find<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        principal: &'a [u8],
        reference: &'a str,
    ) -> BoxFut<'a, Result<(u32, Box<str>), u32>> {
        Box::pin(async move {
            let subject = subject_of(principal).ok_or(R_DENIED)?;
            let (rows, instance) = self.rows(plane).await?;
            let (_, work) = self.held(&rows, &instance, reference).await?;
            self.visible(&work, &owner_of(Some(subject)))?;
            if !work.live {
                return Ok((WORK_SETTLED, Box::from("")));
            }
            let target = busbar_contract::abi::sdk::recovery::poll_target(&work.record)
                .ok()
                .flatten()
                .unwrap_or_default();
            Ok((WORK_LIVE, target.into()))
        })
    }

    fn settle<'a>(
        &'a self,
        plane: &'a Caller<'_>,
        principal: &'a [u8],
        reference: &'a str,
    ) -> BoxFut<'a, Result<(), u32>> {
        Box::pin(async move {
            let subject = subject_of(principal).ok_or(R_DENIED)?;
            let owner = owner_of(Some(subject));
            let (rows, instance) = self.rows(plane).await?;
            let (handle, work) = self.held(&rows, &instance, reference).await?;
            self.visible(&work, &owner)?;
            let settled = match self.book.settle(
                &instance,
                handle,
                Some(&owner),
                // No unit outlives the request that opened it, and a plane's WORK is not unit-bound.
                &|_| false,
                Vec::new(),
                (self.wall_ms)(),
            ) {
                Ok(settled) => settled,
                // Settling twice answers the same (idempotent).
                Err(refusal::SETTLED) => return Ok(()),
                Err(_) => return Err(R_NOT_FOUND),
            };
            let Some(row) = settled.row() else {
                self.book.cancel_settle(handle);
                return Err(R_INVALID);
            };
            let put = rows
                .put(
                    WORK_SCHEMA.as_str(),
                    &settled.reference,
                    busbar_contract::Secret::new(row.into_vec()),
                )
                .await;
            if matches!(put, Ok(Outcome::Applied)) {
                self.book.commit_settle(handle, settled);
                Ok(())
            } else {
                self.book.cancel_settle(handle);
                Err(R_UNSUPPORTED)
            }
        })
    }

    /// One bounded batch of the instance's live, recovery-bound rows with a poll target, from a scan kept across
    /// calls (today's `KernelServices::recovery_work` over the same rows). A row a recovery session holds is skipped
    /// until its `RecoveryWork` drops. No store yet = nothing to recover.
    fn recoverable<'a>(
        &'a self,
        plane: &'a Caller<'_>,
    ) -> BoxFut<'a, Result<Vec<RecoveryWork>, &'static str>> {
        Box::pin(async move {
            let (rows, instance) = self
                .rows(plane)
                .await
                .map_err(|_| "recovery namespace unavailable")?;
            let mut scans = self.scans.lock().await;
            let scan = scans.entry(Arc::clone(&instance)).or_default();
            if scan.pending.is_empty() {
                let page = match rows
                    .page(WORK_SCHEMA.as_str(), &[], scan.cursor.as_ref())
                    .await
                {
                    Ok(page) => page,
                    Err(_) => {
                        scan.cursor = None;
                        return Err("recovery scan failed");
                    }
                };
                scan.cursor = page.next;
                scan.pending.extend(page.rows);
            }
            let active = &self.active;
            Ok(crate::off_path::host_services::recovery_batch(
                &instance,
                &mut scan.pending,
                RECOVERY_BATCH,
                |reference| active.claim(&instance, reference),
                |reference, binding, target| {
                    active.item(Arc::clone(&instance), reference, binding, target)
                },
            ))
        })
    }
}

#[cfg(test)]
#[path = "tests/port_work_tests.rs"]
mod tests;
