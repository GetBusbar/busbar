// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The settlement table: how a unit ended, and which evidence survived, decide the amount.
//!
//! One table, every end. Where two things could be charged, the lower is charged and the posting
//! is flagged for a verdict. Where nothing can be charged honestly, nothing is charged — and the
//! evidence is kept internally so the disputes report still sees it.

use std::collections::BTreeSet;

use busbar_caps::{Usage, UsageLine};

/// How a unit ended, as far as the settlement is concerned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitEndKind {
    /// The unit ran to completion.
    Completed,
    /// The unit ended some other way while it was still live — refused under the hold, failed,
    /// aborted, timed out.
    LiveNonCompleted {
        /// Whether the end carried a terminal error signal from the destination. A stream that
        /// dies with one bills nothing, and the located figure becomes internal evidence.
        terminal_error: bool,
    },
    /// The unit was found after a crash rather than ended.
    CrashRecovered {
        /// Whether a dispatch record survived. Without one nothing was ever sent.
        dispatched: bool,
    },
    /// An accrual whose parent had already exited, so it posts on its own.
    LateAccrual {
        /// Whether the slice it drew against was empty, which posts anyway and says so.
        slice_empty: bool,
    },
    /// Value was delivered but the settle record did not survive. The posting is retained and
    /// appended again.
    DurabilityLost,
}

/// What a settlement is marked with. Flags travel onto the posting and onto the reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SettleFlag {
    /// The amount is the kernel's own floor rather than a figure anybody reported.
    Estimated,
    /// Two sources disagreed, or a check that should have been possible was not. Awaiting a
    /// verdict.
    MeterDisputed,
    /// Reconstructed from a checkpoint after a crash.
    Recovered,
    /// Nothing was ever dispatched, so nothing is owed.
    Voided,
    /// Posted after its parent had already exited.
    LateAccrual,
    /// Posted against an empty slice.
    Overdraft,
    /// Delivered but not durably posted; retained for re-appending.
    Unposted,
}

impl SettleFlag {
    /// The posting flag this settlement mark becomes.
    ///
    /// The table's flags and the posting's flags are one vocabulary read twice: this unit decides
    /// which marks a settlement carries, and the capability crate carries them onto the posting.
    /// A mark with no posting flag behind it would be a settlement nobody downstream could see.
    #[must_use]
    pub fn posting_flag(self) -> busbar_caps::PostingFlags {
        use busbar_caps::PostingFlags as P;
        match self {
            SettleFlag::Estimated => P::ESTIMATED,
            SettleFlag::MeterDisputed => P::METER_DISPUTED,
            SettleFlag::Recovered => P::RECOVERED,
            SettleFlag::Voided => P::VOIDED,
            SettleFlag::LateAccrual => P::LATE_ACCRUAL,
            SettleFlag::Overdraft => P::OVERDRAFT,
            SettleFlag::Unposted => P::UNPOSTED,
        }
    }
}

/// Every mark a settlement carries, as one set of posting flags.
#[must_use]
pub fn posting_flags<'a>(
    flags: impl IntoIterator<Item = &'a SettleFlag>,
) -> busbar_caps::PostingFlags {
    flags
        .into_iter()
        .fold(busbar_caps::PostingFlags::NONE, |acc, f| {
            acc.with(f.posting_flag())
        })
}

/// The evidence available at settlement.
// contract: the hold's dispatch and checkpoint records, as the journal holds them
#[derive(Debug, Clone, Default)]
pub struct Evidence<'a> {
    /// What the locators produced, if anything arrived.
    pub located: Option<&'a Usage>,
    /// The kernel's own floor for the unit.
    pub kernel_floor: &'a [UsageLine],
    /// The last accrual checkpointed before a crash.
    pub checkpointed_accrual: &'a [UsageLine],
    /// A late accrual's own figure.
    pub child_posting: &'a [UsageLine],
    /// Whether a locator was REQUIRED — that is, whether a card is present and prices this class.
    /// With no card nothing is required and nothing is flagged.
    pub locator_required: bool,
}

/// What one unit settles at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Settlement {
    /// The lines that actually bill.
    pub lines: Vec<UsageLine>,
    /// Everything the posting is marked with.
    pub flags: BTreeSet<SettleFlag>,
    /// Evidence that is kept but never billed: it reaches the disputes report and nothing else.
    pub internal_evidence: Vec<UsageLine>,
}

impl Settlement {
    /// Whether this settlement bills nothing at all.
    pub fn is_zero(&self) -> bool {
        self.lines.iter().all(|l| l.quantity == 0)
    }
}

/// Settle one unit: pick the row, take the amount, carry the flags.
pub fn settle(end: UnitEndKind, evidence: &Evidence<'_>) -> Settlement {
    let mut flags = BTreeSet::new();
    let mut internal_evidence = Vec::new();

    let lines = match end {
        UnitEndKind::Completed => match evidence.located {
            Some(usage) => {
                if usage.is_estimated() {
                    flags.insert(SettleFlag::Estimated);
                }
                usage.lines().to_vec()
            }
            None => {
                // NOTHING IS BILLED when the destination reported no usage. The kernel's floor is
                // kept as internal evidence — it reaches the disputes report and no invoice.
                if evidence.locator_required {
                    flags.insert(SettleFlag::Estimated);
                    flags.insert(SettleFlag::MeterDisputed);
                }
                internal_evidence = evidence.kernel_floor.to_vec();
                Vec::new()
            }
        },
        UnitEndKind::LiveNonCompleted { terminal_error } => match evidence.located {
            Some(usage) if !terminal_error => {
                if usage.is_estimated() {
                    flags.insert(SettleFlag::Estimated);
                }
                usage.lines().to_vec()
            }
            Some(usage) => {
                // A stream whose end carries a terminal error bills nothing, whatever the locator
                // found: the located figure becomes evidence rather than an amount.
                internal_evidence = usage.lines().to_vec();
                Vec::new()
            }
            None => {
                flags.insert(SettleFlag::Estimated);
                evidence.kernel_floor.to_vec()
            }
        },
        UnitEndKind::CrashRecovered { dispatched: true } => {
            flags.insert(SettleFlag::Recovered);
            evidence.checkpointed_accrual.to_vec()
        }
        UnitEndKind::CrashRecovered { dispatched: false } => {
            flags.insert(SettleFlag::Voided);
            Vec::new()
        }
        UnitEndKind::LateAccrual { slice_empty } => {
            flags.insert(SettleFlag::LateAccrual);
            if slice_empty {
                flags.insert(SettleFlag::Overdraft);
            }
            evidence.child_posting.to_vec()
        }
        UnitEndKind::DurabilityLost => {
            flags.insert(SettleFlag::Unposted);
            match evidence.located {
                Some(usage) => usage.lines().to_vec(),
                None => evidence.kernel_floor.to_vec(),
            }
        }
    };

    Settlement {
        lines,
        flags,
        internal_evidence,
    }
}

/// What the requests dimension settles at.
///
/// The slot is drawn at the door and is NEVER released. A unit that was admitted and then failed
/// still consumed its slot, which is what stops failures from escaping a cap by failing.
pub fn requests_settled(drawn: u64, reached_admitted: bool) -> u64 {
    if reached_admitted {
        drawn
    } else {
        0
    }
}
