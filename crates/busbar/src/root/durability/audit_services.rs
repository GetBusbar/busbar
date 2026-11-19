// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE NODE BOOK'S AUDIT SERVICES (SEALING-FIX r20 §3.3, §5.3): the two signer threads, their
//! handles until their owners take them, the notary once serving starts, and the 1 s watch that
//! raises the notary's stall and panic alerts.
//!
//! Built at boot, right after the keyset is bound and split into its grants; the notary is started
//! from `main` once serving begins (on the control runtime) and stopped by the shutdown drain's
//! seal phase. Nothing here is reachable from the request path: the book itself holds only the
//! head feed and the bound public key.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use busbar_kernel::governance::drain::DrainClock;
use busbar_kernel::persistence::journal::runtime::RuntimeJournal;
use busbar_kernel_audit::{BootstrapSigner, Notary};

use super::notary::{self, FloorHints, HeadFeed, NotaryConfig, NotaryStart, NotaryTask};
use super::signer::{self, Checkpoint, Live, Seal, SignerHandle, SignerThreads};

/// The handles and threads before their owners take them.
struct Unstarted {
    live: SignerHandle<Live>,
    threads: SignerThreads,
    pending: Vec<super::boot_jobs::PendingBootJob>,
    delegated: Option<busbar_contract::crypto::PublicKey>,
}

/// THE BOOK'S AUDIT SERVICES.
pub(crate) struct AuditServices {
    node: u64,
    journal: Arc<RuntimeJournal>,
    feed: Arc<HeadFeed>,
    start: NotaryStart,
    original_start: OnceLock<NotaryStart>,
    notary_key_id: String,
    bootstrap_key_id: String,
    clock: Arc<OnceLock<Arc<DrainClock>>>,
    unstarted: Mutex<Option<Unstarted>>,
    boot: Mutex<Option<SignerHandle<Seal>>>,
    sealer: Mutex<Option<SignerHandle<Seal>>>,
    notary: Mutex<Option<NotaryTask>>,
    predecessor: Mutex<Option<super::predecessor::PredecessorInputs>>,
    stopping: Arc<AtomicBool>,
}

impl std::fmt::Debug for AuditServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditServices")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

/// What [`AuditServices::spawn`] returns beside the services: the checkpoint adapter's handle.
pub(crate) type CheckpointHandle = SignerHandle<Checkpoint>;

impl AuditServices {
    #[cfg(test)]
    pub(crate) fn cut_retained(&self) -> bool {
        self.notary
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .as_ref()
            .is_some_and(|task| task.progress().journal_cut_retained.load(Ordering::Acquire))
    }
    /// START THE SIGNER THREADS from the bound key's capabilities. `start` is the resumed head the
    /// notary will begin after (read before recovery appends anything).
    pub(crate) fn spawn(
        notary: Notary,
        bootstrap: BootstrapSigner,
        node: u64,
        journal: Arc<RuntimeJournal>,
        feed: Arc<HeadFeed>,
        start: NotaryStart,
    ) -> std::io::Result<(Self, CheckpointHandle)> {
        let clock = Arc::new(OnceLock::new());
        let delegated =
            (notary.public_key() != bootstrap.public_key()).then(|| notary.public_key().clone());
        let notary_key_id = notary.key_id().to_owned();
        let bootstrap_key_id = bootstrap.key_id().to_owned();
        let signers = signer::spawn(notary, bootstrap, Arc::clone(&clock))?;
        let services = AuditServices {
            node,
            journal,
            feed,
            start,
            original_start: OnceLock::new(),
            notary_key_id,
            bootstrap_key_id,
            clock,
            unstarted: Mutex::new(Some(Unstarted {
                live: signers.live,
                threads: signers.threads,
                pending: Vec::new(),
                delegated,
            })),
            boot: Mutex::new(Some(signers.boot)),
            sealer: Mutex::new(Some(signers.sealer)),
            notary: Mutex::new(None),
            predecessor: Mutex::new(None),
            stopping: Arc::new(AtomicBool::new(false)),
        };
        Ok((services, signers.checkpoint))
    }

    /// START THE NOTARY (once; later calls do nothing) on the current runtime, with
    /// `audit.seal_every` and SHUTDOWN-HANG's drain clock, and its 1 s watch. Returns whether this
    /// call started it. `floor` is the Ephemeral journal cut's floor (b) source (SEALING-FIX §3.9):
    /// the oldest audit line a checkpoint in custody names.
    pub(crate) fn start_notary(
        &self,
        every_ms: u64,
        clock: Arc<DrainClock>,
        floor: Option<FloorHints>,
        book: Arc<Mutex<super::Durability>>,
    ) -> bool {
        let _ = self.clock.set(Arc::clone(&clock));
        let host = super::host_identity();
        let template = busbar_kernel_audit::Stamp {
            node: self.node,
            from: 0,
            to: 0,
            fingerprint: busbar_kernel_audit::Fingerprint::ZERO,
            kind: busbar_kernel_audit::StampKind::Live,
            sealer: self.node,
            host: host.clone(),
            every: every_ms.clamp(1, 1_000),
            stamped_ms: 0,
            down_from_ms: 0,
            down_to_ms: 0,
            crypto: busbar_contract::crypto::BACKEND.into(),
            sig_alg: busbar_kernel_audit::SIGNATURE_ALGORITHM.into(),
            key_id: self.notary_key_id.clone(),
            key_cert: 0,
            signature: vec![0; 64],
        };
        if let Err(error) = self.feed.configure_original(&template) {
            tracing::error!(reason = error, "original notary storage bound unavailable");
            return false;
        }
        let Some(Unstarted {
            live,
            threads,
            pending,
            delegated,
        }) = self
            .unstarted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        else {
            return false;
        };
        let boot = self.boot.lock().unwrap_or_else(|p| p.into_inner()).take();
        let needs_boot = !pending.is_empty() || delegated.is_some();
        if needs_boot && boot.is_none() {
            busbar_kernel::diag_error!(
                busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                node = self.node,
                reason = "bootstrap_signer_panic",
                "audit live signing refused: pending boot work has no Bootstrap handle"
            );
            return false;
        }
        let boot = boot
            .map(|handle| super::boot_jobs::BootPreparation::new(handle, book, pending, delegated));
        let task = notary::spawn_with_boot(
            NotaryConfig {
                node: self.node,
                host,
                every_ms,
                key_cert: 0,
            },
            self.original_start.get().copied().unwrap_or(self.start),
            Arc::clone(&self.journal),
            Arc::clone(&self.feed),
            live,
            notary::NotaryRuntime {
                floor_hints: floor,
                drain_clock: Some(clock),
                boot,
            },
        );
        let progress = Arc::clone(task.progress());
        let stall_after_ms = task.stall_after_ms();
        let exited = task.exited();
        *self.notary.lock().unwrap_or_else(|p| p.into_inner()) = Some(task);
        tokio::spawn(watch(
            self.node,
            progress,
            exited,
            threads,
            stall_after_ms,
            Arc::clone(&self.stopping),
        ));
        true
    }

    /// Bind only the genuinely verified Bootstrap public half, after all boot recovery.
    /// No key-set cardinality, active-key fallback, or recovered tuple establishes authority.
    pub(crate) fn bind_original_bootstrap(
        &self,
        book: &super::Durability,
        trusted_key: busbar_kernel_audit::AuditVerifyingKey,
    ) -> Result<(), &'static str> {
        if self.original_start.get().is_some()
            || !Arc::ptr_eq(&self.journal, &book.journal)
            || !Arc::ptr_eq(&self.feed, &book.head)
            || self.node != book.record.node()
            || trusted_key.key_id() != self.bootstrap_key_id
            || trusted_key.key_id() != self.notary_key_id
            || self
                .unstarted
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .is_none()
        {
            return Err("original notary does not match its verified Bootstrap and book");
        }
        self.feed.bind_original(self.journal.clone(), trusted_key)?;
        self.original_start
            .set(book.notary_start())
            .map_err(|_| "original notary baseline already bound")
    }

    /// TAKE THE NOTARY for the shutdown drain's seal phase. The watch stops alerting once it is
    /// taken.
    pub(crate) fn take_notary(&self) -> Option<NotaryTask> {
        self.stopping.store(true, Ordering::Release);
        self.feed.stop_original();
        self.notary.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    /// The own-node boot phase's Bootstrap handle (taken once).
    pub(crate) fn take_boot_handle(&self) -> Option<SignerHandle<Seal>> {
        self.boot.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    /// Return the own-node phase's handle, retaining a failed sign or uncertain original ahead
    /// of this boot's certificate. Called before start_notary consumes the cold ownership.
    pub(crate) fn defer_boot(
        &self,
        handle: SignerHandle<Seal>,
        pending: Option<super::boot_jobs::PendingBootJob>,
    ) {
        if let Some(job) = pending {
            if let Some(unstarted) = self
                .unstarted
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .as_mut()
            {
                unstarted.pending.push(job);
            }
        }
        *self.boot.lock().unwrap_or_else(|p| p.into_inner()) = Some(handle);
    }

    /// The predecessor sealer's Bootstrap handle (taken once).
    pub(crate) fn take_sealer_handle(&self) -> Option<SignerHandle<Seal>> {
        self.sealer.lock().unwrap_or_else(|p| p.into_inner()).take()
    }

    /// What the boot book knows that the predecessor sealer needs (this node, its take time and
    /// the bound key), set once at boot.
    pub(crate) fn set_predecessor_inputs(&self, inputs: super::predecessor::PredecessorInputs) {
        *self.predecessor.lock().unwrap_or_else(|p| p.into_inner()) = Some(inputs);
    }

    /// THE PREDECESSOR SEALER'S INPUTS and its Bootstrap handle, taken once by `main` after
    /// `Ready`.
    pub(crate) fn take_predecessor(
        &self,
    ) -> Option<(super::predecessor::PredecessorInputs, SignerHandle<Seal>)> {
        let inputs = self
            .predecessor
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .take()?;
        Some((inputs, self.take_sealer_handle()?))
    }
}

/// THE 1 s WATCH (SEALING-FIX §3.3 "No restart", §5.1): raises `AUDIT_STAMP_FAILED{panic}` once
/// when the notary task ends before the drain takes it, `AUDIT_STAMP_FAILED{signer_panic |
/// bootstrap_signer_panic}` once per signer thread that exits, and `AUDIT_NOTARY_STALLED` once per
/// transition when the oldest unstamped line is older than the stall threshold.
async fn watch(
    node: u64,
    progress: Arc<notary::NotaryProgress>,
    exited: Arc<AtomicBool>,
    threads: SignerThreads,
    stall_after_ms: u64,
    stopping: Arc<AtomicBool>,
) {
    let mut tick = tokio::time::interval(busbar_kernel::host_records::FLUSH_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let (mut panic_seen, mut live_seen, mut boot_seen, mut stalled) = (false, false, false, false);
    loop {
        tick.tick().await;
        if stopping.load(Ordering::Acquire) {
            return;
        }
        if !panic_seen && exited.load(Ordering::Acquire) {
            panic_seen = true;
            busbar_kernel::diag_error!(
                busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                node,
                reason = "panic",
                "the audit notary ended unexpectedly; lines stay durable and linked, unstamped"
            );
            busbar_kernel::diag_error!(
                busbar_kernel::diagnostics::AUDIT_NOTARY_STALLED,
                node,
                "the audit notary is down for the rest of this process"
            );
        }
        if !live_seen && threads.live_finished() {
            live_seen = true;
            busbar_kernel::diag_error!(
                busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                node,
                reason = "signer_panic",
                "the audit notary signer thread exited"
            );
        }
        if !boot_seen && threads.bootstrap_finished() {
            boot_seen = true;
            busbar_kernel::diag_error!(
                busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                node,
                reason = "bootstrap_signer_panic",
                "the audit Bootstrap signer thread exited; checkpoints and restart pages go unsigned"
            );
        }
        let oldest = progress.oldest_unstamped_ms.load(Ordering::Relaxed);
        let age = if oldest == 0 {
            0
        } else {
            busbar_kernel::store::now_ms().saturating_sub(oldest)
        };
        if age > stall_after_ms && !stalled {
            stalled = true;
            busbar_kernel::diag_error!(
                busbar_kernel::diagnostics::AUDIT_NOTARY_STALLED,
                node,
                age_ms = age,
                unstamped_from = progress
                    .stamped_through
                    .load(Ordering::Relaxed)
                    .saturating_add(1),
                "audit lines have gone unstamped for too long"
            );
        } else if age <= stall_after_ms && stalled {
            stalled = false;
            tracing::info!(node, "audit lines are being stamped again");
        }
    }
}
