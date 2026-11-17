// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE READ-ONLY TRUST HANDLE the admin read surface holds (TRUST-ADMIN-PRODUCER-DESIGN r3 §2.1).
//!
//! A concrete struct over the serving kernel, never a trait: it exposes the trust book's rows, the
//! counterparties' facts, the standing attachment, the kept decisions (already redacted) and the
//! custody state. It cannot decide, admit or sight, so holding an `AppHandle` grants no trust
//! mutation authority.

use std::sync::Arc;

use super::book::{CounterpartyFacts, DecidedBy, KeyRow};
use super::demotion::DemotionRow;
use crate::host_services::KernelServices;

/// Whether trust decisions can be kept durably (r3 §6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Custody {
    /// A decision record bound to a Store.
    Bound,
    /// No decision record, or one with no Store attached.
    Unbound,
}

/// Why kept decisions could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable(pub String);

/// A declared pin as the admin API may show it: never the operator's material (`DeclaredPin.key`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinFacts {
    pub mechanism: String,
    pub root: bool,
    pub peer_key: bool,
    pub fingerprint: Option<String>,
}

impl PinFacts {
    fn of(pin: &super::section::DeclaredPin) -> Self {
        Self {
            mechanism: pin.mechanism.clone(),
            root: pin.root,
            peer_key: pin.peer_key,
            fingerprint: pin.fingerprint.clone(),
        }
    }
}

/// One kept durable decision, redacted (r3 §2.1): pin material never leaves the kernel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptDecision {
    pub instance: String,
    pub counterparty: String,
    pub item: Option<String>,
    pub approved: Option<String>,
    pub demoted: bool,
    pub pin: Option<PinFacts>,
    pub decided_by: Option<DecidedBy>,
    pub decided_at: Option<u64>,
    pub operation: Option<String>,
}

/// Every kept trust row the `decisions` view lists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kept {
    pub decisions: Vec<KeptDecision>,
    pub quarantines: Vec<DemotionRow>,
}

/// One counterparty's facts with its pin redacted, for `subjects`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectFacts {
    pub row: KeyRow,
    pub pin: Option<PinFacts>,
    pub policy: super::reverify::Policy,
    pub ledger: super::reverify::Ledger,
    pub pending: bool,
    pub quarantined: bool,
    pub revoked: bool,
    pub confirmed: bool,
    pub demoted: Vec<String>,
}

impl SubjectFacts {
    fn of(facts: CounterpartyFacts) -> Self {
        Self {
            row: facts.row,
            pin: facts.pin.as_ref().map(PinFacts::of),
            policy: facts.policy,
            ledger: facts.ledger,
            pending: facts.pending,
            quarantined: facts.quarantined,
            revoked: facts.revoked,
            confirmed: facts.confirmed,
            demoted: facts.demoted,
        }
    }
}

/// The read-only handle over the serving kernel's trust state.
#[derive(Clone)]
pub struct TrustReadout {
    kernel: Arc<KernelServices>,
}

impl std::fmt::Debug for TrustReadout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustReadout").finish_non_exhaustive()
    }
}

impl TrustReadout {
    /// The readout over `kernel`. Only the composition root builds one, beside the decide-capable
    /// handle it gives the admin governance (r3 §2.2).
    #[must_use]
    pub fn over(kernel: Arc<KernelServices>) -> Self {
        Self { kernel }
    }

    /// Every trust key, counterparty rows before their items.
    #[must_use]
    pub fn rows(&self) -> Vec<KeyRow> {
        self.kernel.trust_rows()
    }

    /// Every admitted counterparty's facts, pins redacted.
    #[must_use]
    pub fn subjects(&self) -> Vec<SubjectFacts> {
        self.kernel
            .trust_counterparties()
            .into_iter()
            .map(SubjectFacts::of)
            .collect()
    }

    /// Whether the live standing re-check is attached.
    #[must_use]
    pub fn standing_attached(&self) -> bool {
        self.kernel.standing_attached()
    }

    /// Whether decisions can be kept durably.
    #[must_use]
    pub fn custody(&self) -> Custody {
        if self.kernel.trust_decision_record().is_some() {
            Custody::Bound
        } else {
            Custody::Unbound
        }
    }

    /// Every kept decision and quarantine, read without settling pending writes (r3 §3.5).
    pub async fn kept_decisions(&self) -> Result<Kept, Unavailable> {
        let record = self.kernel.trust_decision_record().ok_or_else(|| {
            Unavailable("trust decisions cannot be kept: no bound decision record".into())
        })?;
        let snapshot = record.kept().await.map_err(Unavailable)?;
        Ok(Kept {
            decisions: snapshot
                .decisions
                .into_iter()
                .map(|row| KeptDecision {
                    pin: row.declared.as_ref().map(PinFacts::of),
                    instance: row.instance,
                    counterparty: row.counterparty,
                    item: row.item,
                    approved: row.approved,
                    demoted: row.demoted,
                    decided_by: row.decided_by,
                    decided_at: row.decided_at,
                    operation: row.operation,
                })
                .collect(),
            quarantines: snapshot.demotions,
        })
    }

    /// Whether this readout reads `kernel` (r3 §2.2, test G2).
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn same_kernel(&self, kernel: &Arc<KernelServices>) -> bool {
        Arc::ptr_eq(&self.kernel, kernel)
    }
}
