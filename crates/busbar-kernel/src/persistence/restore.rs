// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DES-331 part B: the declared-restore row and this process's restore quarantine (§B2, §B5).
//!
//! The row lives in the control namespace (`control::RESTORE_KEY`), judged by `control::admit`.
//! It is read at the backend level at boot, before any writer registration commit, and again at
//! every node-lease refresh, so a node that was never stopped quarantines within one refresh of
//! another node writing `pending` (§B5.1). Quarantine is one-way inside a process: only a
//! declaration lifts it.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{Arc, OnceLock};

use busbar_contract::persistence::control::{self, Restore, RestoreState};
use busbar_contract::persistence::{Address, PersistenceBackend, Read, ReadResult};

use super::commit::SubmitResult;
use super::facade::CoreStore;
use super::startup::{manifest_address, Manifest, RECORD_FORMAT, RESTORED_FORMAT};

/// The restore row's address.
#[must_use]
pub fn address() -> Address {
    Address {
        namespace: control::NAMESPACE.0,
        key: control::RESTORE_KEY.to_vec(),
    }
}

/// Decode an observed restore row; a present row that does not decode is corrupt.
pub fn decode(value: Option<&[u8]>) -> Result<Option<Restore>, String> {
    value
        .map(|bytes| Restore::decode(bytes).ok_or_else(|| "the restore row is malformed".into()))
        .transpose()
}

/// The restore epoch a row names: 0 when the dataset was never restored.
#[must_use]
pub fn epoch_of(row: Option<Restore>) -> u64 {
    row.map_or(0, |row| row.epoch)
}

/// Why this process is in restore quarantine (`STORE_RESTORED.reason`, DES-331 §B10.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// Launched with `--restore-quarantine`.
    Flag,
    /// The restore row was `pending` (at boot or at a lease refresh).
    PendingRow,
    /// A lease refresh saw a restore epoch other than the one this process booted with.
    EpochChanged,
}

impl Reason {
    /// The diagnostic and NodeView spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Flag => "flag",
            Self::PendingRow => "pending_row",
            Self::EpochChanged => "epoch_changed",
        }
    }
    fn code(self) -> u8 {
        match self {
            Self::Flag => 1,
            Self::PendingRow => 2,
            Self::EpochChanged => 3,
        }
    }
    fn of(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Flag),
            2 => Some(Self::PendingRow),
            3 => Some(Self::EpochChanged),
            _ => None,
        }
    }
}

/// One process's restore quarantine. The serving process uses [`gate`]; tests own their own.
#[derive(Debug, Default)]
pub struct Gate {
    booted: OnceLock<u64>,
    reason: AtomicU8,
}

static GATE: Gate = Gate::new();

/// The serving process's gate.
#[must_use]
pub fn gate() -> &'static Gate {
    &GATE
}

impl Gate {
    /// A gate that has not booted and is not quarantined.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            booted: OnceLock::new(),
            reason: AtomicU8::new(0),
        }
    }

    /// Boot: record the restore epoch read before registration, and enter quarantine when
    /// launched with `--restore-quarantine` or when the row is `pending` (§B5.1).
    pub fn boot(&self, row: Option<Restore>, flagged: bool) -> Option<Reason> {
        let _ = self.booted.set(epoch_of(row));
        if flagged {
            self.enter(Reason::Flag);
        } else if row.is_some_and(|row| row.state == RestoreState::Pending) {
            self.enter(Reason::PendingRow);
        }
        self.reason()
    }

    /// A lease refresh's observation: `pending`, or an epoch other than the booted one,
    /// quarantines this process at once (§B5.1).
    pub fn observe(&self, row: Option<Restore>) -> Option<Reason> {
        if row.is_some_and(|row| row.state == RestoreState::Pending) {
            self.enter(Reason::PendingRow);
        } else if self
            .booted
            .get()
            .is_some_and(|booted| *booted != epoch_of(row))
        {
            self.enter(Reason::EpochChanged);
        }
        self.reason()
    }

    /// The first reason this process entered quarantine; `None` while it serves normally.
    #[must_use]
    pub fn reason(&self) -> Option<Reason> {
        Reason::of(self.reason.load(Ordering::Acquire))
    }

    /// Whether this process is in restore quarantine.
    #[must_use]
    pub fn quarantined(&self) -> bool {
        self.reason().is_some()
    }

    /// The restore epoch this process booted with (0 before boot).
    #[must_use]
    pub fn booted_epoch(&self) -> u64 {
        self.booted.get().copied().unwrap_or(0)
    }

    fn enter(&self, reason: Reason) {
        let _ = self
            .reason
            .compare_exchange(0, reason.code(), Ordering::AcqRel, Ordering::Acquire);
    }
}

/// Read the restore row straight from the backend, before any writer registration commit
/// (§B5.2).
pub async fn read(backend: &dyn PersistenceBackend) -> Result<Option<Restore>, String> {
    let info = backend.info();
    let result = backend
        .read(Arc::new(Read {
            dataset: info.dataset,
            addresses: vec![address()],
            time: None,
        }))
        .await
        .map_err(|failure| format!("the restore row read failed: {failure:?}"))?;
    let ReadResult::Values {
        observed_at,
        values,
    } = result
    else {
        return Err("the restore row observation was not coherent".into());
    };
    if observed_at.authority != info.clock_authority || values.len() != 1 {
        return Err("the restore row observation authority changed".into());
    }
    let seal = crate::seal::lend();
    decode(
        values[0]
            .as_ref()
            .map(|value| value.expose(&seal).as_slice()),
    )
}

/// Most conflict re-reads of one pending-marker write before giving up.
const MARK_ATTEMPTS: usize = 8;

/// The pending marker (§B5.1, §B10.4): move the restore row to `pending` at its current epoch and
/// raise the Store manifest to [`RESTORED_FORMAT`] in the same candidate, so a build that
/// predates the restore row refuses this dataset from now on. Idempotent: a row already pending
/// is answered as is. Committed by this process's own writer, in quarantine, after registration.
pub async fn mark_pending(core: &CoreStore) -> Result<Restore, String> {
    let error = |cause: &dyn std::fmt::Debug| format!("the restore pending marker: {cause:?}");
    for _ in 0..MARK_ATTEMPTS {
        let info = core.info();
        let result = core
            .backend()
            .read(Arc::new(Read {
                dataset: info.dataset,
                addresses: vec![address(), manifest_address()],
                time: None,
            }))
            .await
            .map_err(|failure| error(&failure))?;
        let ReadResult::Values {
            observed_at,
            values,
        } = result
        else {
            return Err("the restore pending observation was not coherent".into());
        };
        if observed_at.authority != info.clock_authority || values.len() != 2 {
            return Err("the restore pending observation authority changed".into());
        }
        let seal = crate::seal::lend();
        let previous = decode(values[0].as_ref().map(|v| v.expose(&seal).as_slice()))?;
        if let Some(row) = previous.filter(|row| row.state == RestoreState::Pending) {
            return Ok(row);
        }
        let manifest_before = values[1]
            .as_ref()
            .ok_or("the restore pending marker found no manifest")?
            .expose(&seal)
            .clone();
        let manifest = Manifest::decode(&manifest_before).map_err(|cause| error(&cause))?;
        let manifest_after = if manifest.format == RECORD_FORMAT {
            Manifest {
                format: RESTORED_FORMAT,
                ..manifest
            }
            .encode()
            .to_vec()
        } else {
            manifest_before.clone()
        };
        let next = match previous {
            None => Restore {
                epoch: 0,
                state: RestoreState::Pending,
                declared_at: 0,
                declaration_digest: [0; 32],
            },
            Some(row) => Restore {
                state: RestoreState::Pending,
                ..row
            },
        };
        let candidate = super::fences::restore_pending(
            core.next_id().map_err(|cause| error(&cause))?,
            previous,
            next,
            (manifest_address(), manifest_before, manifest_after),
        )
        .map_err(|cause| error(&cause))?;
        let submission = core
            .submit(candidate)
            .await
            .map_err(|cause| error(&cause))?;
        match submission.result {
            SubmitResult::Decided(decision)
                if matches!(
                    *decision,
                    busbar_contract::persistence::Decision::Applied(_)
                ) =>
            {
                return Ok(next);
            }
            // A conflict, an uncertain or busy send: the next read shows what holds.
            SubmitResult::Decided(_) | SubmitResult::Uncertain | SubmitResult::Busy => {}
            SubmitResult::NoEffect(failure) => return Err(error(&failure)),
            SubmitResult::Reconcile => {
                return Err("the restore pending marker needs reconciliation".into())
            }
        }
    }
    Err("the restore pending marker did not settle".into())
}

#[cfg(test)]
#[path = "tests/restore_tests.rs"]
mod tests;
