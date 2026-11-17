// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Ordered own-node boot work. Restart/break confirmation precedes certificate signing, and
//! the certificate's original run is confirmed before the notary may sign any live page.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use busbar_contract::crypto::PublicKey;
use busbar_kernel::persistence::journal::runtime::StagedRun;
use busbar_kernel_audit::{AuditChain, BreakNotice, Fingerprint, Stamp};
use busbar_kernel_wal::{Entry, RecordClass};

use super::signer::{Seal, SignFailure, SignerHandle, JOB_DEADLINE};
use super::Durability;

const FIRST_RETRY: Duration = Duration::from_millis(1);
const MAX_RETRY: Duration = Duration::from_secs(1);
const ALERT_AFTER: u32 = 3;

/// Work retained by the own-node phase. An uncertain staged run stays exactly that run;
/// retrying its signature would append a duplicate terminal record.
#[derive(Clone)]
pub(crate) enum PendingBootJob {
    Restart(Stamp),
    Break(BreakNotice),
    Staged(Arc<StagedRun>),
}

impl std::fmt::Debug for PendingBootJob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Restart(stamp) => f.debug_tuple("Restart").field(stamp).finish(),
            Self::Break(notice) => f.debug_tuple("Break").field(notice).finish(),
            Self::Staged(run) => f
                .debug_struct("Staged")
                .field(
                    "first_node_seq",
                    &run.records().first().map(|row| row.node_seq),
                )
                .finish_non_exhaustive(),
        }
    }
}

/// Owned by the notary task during its boot gate; never stored in the request-path book.
pub(crate) struct BootPreparation {
    handle: SignerHandle<Seal>,
    book: Arc<Mutex<Durability>>,
    pending: VecDeque<PendingBootJob>,
    delegated: Option<PublicKey>,
    certificate_run: Option<Arc<StagedRun>>,
    key_cert: u64,
    complete: bool,
    failures: u32,
    backoff: Duration,
}

impl BootPreparation {
    pub(crate) fn new(
        handle: SignerHandle<Seal>,
        book: Arc<Mutex<Durability>>,
        pending: Vec<PendingBootJob>,
        delegated: Option<PublicKey>,
    ) -> Self {
        Self {
            handle,
            book,
            pending: pending.into(),
            delegated,
            certificate_run: None,
            key_cert: 0,
            complete: false,
            failures: 0,
            backoff: FIRST_RETRY,
        }
    }

    /// Run until every original is confirmed. The owning task concurrently watches shutdown;
    /// cancellation leaves staged originals in journal custody and never enables live signing.
    pub(crate) async fn run(&mut self) -> Result<u64, String> {
        while !self.complete {
            match self.step().await {
                Ok(()) => {
                    self.backoff = FIRST_RETRY;
                    self.failures = 0;
                }
                Err(BootFailure::SignerGone) => return Err("bootstrap_signer_panic".into()),
                Err(BootFailure::Retry(reason)) => {
                    self.failures = self.failures.saturating_add(1);
                    if self.failures == ALERT_AFTER {
                        busbar_kernel::diag_error!(busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                            reason = %reason, "audit boot signing or confirmation failed; live pages remain blocked");
                    }
                    tokio::time::sleep(self.backoff).await;
                    self.backoff = (self.backoff * 2).min(MAX_RETRY);
                }
            }
        }
        Ok(self.key_cert)
    }

    async fn confirm(&self, run: &Arc<StagedRun>) -> Result<(), BootFailure> {
        let journal = self
            .book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .journal
            .clone();
        tokio::time::timeout(JOB_DEADLINE, journal.confirm(run))
            .await
            .map_err(|_| BootFailure::Retry("boot original confirmation deadline".into()))?
            .map_err(|error| BootFailure::Retry(format!("boot original confirmation: {error:?}")))
    }

    async fn step(&mut self) -> Result<(), BootFailure> {
        if let Some(job) = self.pending.front().cloned() {
            let body = match job {
                PendingBootJob::Staged(run) => {
                    self.confirm(&run).await?;
                    self.pending.pop_front();
                    return Ok(());
                }
                PendingBootJob::Restart(stamp) => {
                    let signed = self
                        .handle
                        .submit_restart(stamp)
                        .await
                        .map_err(BootFailure::from)?;
                    busbar_kernel_audit::stamp_body(&signed)
                }
                PendingBootJob::Break(notice) => {
                    let signed = self
                        .handle
                        .submit_break(notice)
                        .await
                        .map_err(BootFailure::from)?;
                    busbar_kernel_audit::break_body(&signed)
                }
            }
            .map_err(|error| BootFailure::Retry(error.to_string()))?;
            let journal = self
                .book
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .journal
                .clone();
            let run = journal
                .stage_run(&[Entry::new(RecordClass::Transaction, body)])
                .map_err(|error| BootFailure::Retry(format!("boot original stage: {error:?}")))?;
            if let Some(first) = self.pending.front_mut() {
                *first = PendingBootJob::Staged(run);
            }
            return Ok(());
        }
        let Some(key) = self.delegated.as_ref() else {
            self.complete = true;
            return Ok(());
        };
        if let Some(run) = &self.certificate_run {
            self.confirm(run).await?;
            self.key_cert = run.records().first().map_or(0, |row| row.node_seq);
            if self.key_cert == 0 {
                return Err(BootFailure::Retry(
                    "certificate stage has no WAL identity".into(),
                ));
            }
            self.complete = true;
            return Ok(());
        }
        let (node, seq, prev) = {
            let book = self.book.lock().unwrap_or_else(|p| p.into_inner());
            (
                book.record.node(),
                book.record.next_seq(),
                Fingerprint::from_hex(book.record.head()).ok_or_else(|| {
                    BootFailure::Retry("certificate predecessor is malformed".into())
                })?,
            )
        };
        let certificate = self
            .handle
            .submit_certificate(node, seq, prev, key.clone())
            .await
            .map_err(BootFailure::from)?;
        let prepared = AuditChain::prepare_notary_key(node, seq, prev, certificate);
        let kernel = crate::root::kernel::new_kernel();
        let pass = busbar_kernel::teller::verb_audit_pass(&kernel);
        let token = kernel.durability_token();
        let (_, run) = self
            .book
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .stage_notary_key(prepared, &pass, &token)
            .map_err(|_| {
                BootFailure::Retry("certificate staging position changed or stage refused".into())
            })?;
        self.certificate_run = Some(run);
        Ok(())
    }
}

enum BootFailure {
    SignerGone,
    Retry(String),
}

impl From<SignFailure> for BootFailure {
    fn from(error: SignFailure) -> Self {
        match error {
            SignFailure::Gone => Self::SignerGone,
            other => Self::Retry(other.to_string()),
        }
    }
}
