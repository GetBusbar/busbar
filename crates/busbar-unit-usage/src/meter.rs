// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fold: retained locator values plus kernel counts become the one usage report the ledger
//! settles against.

use busbar_caps::step::MeterClassId;
use busbar_caps::{Usage, UsageError, UsageLine, UsageToken};

use crate::evidence::{KernelCounts, MeterPolicy, RetainedLocatorValues};
use crate::lane::{cross_check_lane, LaneCheck, LegDeclaration};
use crate::source::QuantitySource;
use crate::WHOLE_BP;

/// Why a line ended up on the disputes report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisputeReason {
    /// A reported quantity and its kernel companion disagreed beyond the tolerance. The lower
    /// figure is what posts.
    BeyondTolerance,
    /// A located figure came in below the kernel floor divided by the sanity ratio. The located
    /// figure still posts — it is the lower of the two, and the floor is never a charge.
    BelowFloorBand,
    /// A located figure came in above the kernel floor multiplied by the sanity ratio. The located
    /// figure still posts; the bound is a flag, not a cap.
    AboveFloorBand,
    /// A reported cardinality had no kernel-derived companion in the same unit to be checked
    /// against, so it posts as an estimate.
    NoCompanion,
    /// The three lane legs disagreed, or a declared leg never arrived.
    LaneMismatch,
}

/// One line the disputes report carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispute {
    /// Which class the disagreement was about; empty for a whole-unit dispute such as the lane.
    pub class: String,
    /// What went wrong.
    pub reason: DisputeReason,
    /// The figure that was reported.
    pub reported: u64,
    /// The kernel's own figure, where there was one.
    pub companion: Option<u64>,
}

/// The fold's whole answer: the report, the lane it prices against, and everything that has to
/// reach the disputes report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metered {
    /// The report the ledger settles against.
    pub usage: Usage,
    /// The lane the posting prices against, and whether the legs agreed about it.
    pub lane: LaneCheck,
    /// Every line that needs a verdict.
    pub disputes: Vec<Dispute>,
}

impl Metered {
    /// Whether anything about this unit is disputed.
    pub fn disputed(&self) -> bool {
        !self.disputes.is_empty()
    }
}

/// Building the report the ledger settles against, from the evidence a unit left behind.
///
/// This sits on the report type as a trait rather than as an inherent method because the report
/// itself belongs to the capability crate, which depends on nothing. The call reads the same way.
pub trait UsageMeter: Sized {
    /// Fold the retained locator values against the kernel's own counts into one report.
    fn meter(
        retained: &RetainedLocatorValues,
        kernel: &KernelCounts,
        token: &UsageToken,
    ) -> Result<Self, UsageError>;
}

impl UsageMeter for Usage {
    fn meter(
        retained: &RetainedLocatorValues,
        kernel: &KernelCounts,
        token: &UsageToken,
    ) -> Result<Usage, UsageError> {
        meter(
            retained,
            kernel,
            &MeterPolicy::default(),
            &LegDeclaration::default(),
            token,
        )
        .map(|m| m.usage)
    }
}

/// The fold, with everything it decided.
///
/// Line by line: a located figure is the charge, always, with the kernel floor as a tripwire either
/// side of it. Any other reported figure is compared against its kernel companion, and beyond the
/// tolerance the LOWER of the two posts. A reported cardinality with no companion at all posts as
/// an estimate, checked only against a proxy under the same one-sided bound.
///
/// The report is marked as an estimate as a whole when any line in it is one, because that mark
/// travels onto the posting and a posting is one thing.
pub fn meter(
    retained: &RetainedLocatorValues,
    kernel: &KernelCounts,
    policy: &MeterPolicy,
    declared: &LegDeclaration,
    token: &UsageToken,
) -> Result<Metered, UsageError> {
    let mut lines: Vec<UsageLine> = Vec::with_capacity(retained.values().len());
    let mut disputes: Vec<Dispute> = Vec::new();
    let mut estimated = false;

    for value in retained.values() {
        let class = value.class.as_str();
        let companion = kernel.companion(class);
        let reported = value.quantity;

        let charge = match &value.source {
            // THE FLOOR IS EVIDENCE, NEVER A CHARGE. The located figure bills in every case; the
            // floor only decides whether somebody has to look at it.
            QuantitySource::Locator { .. } => {
                if let Some(floor) = companion {
                    let ratio = policy.locator_floor_ratio.max(1);
                    if reported < floor / ratio {
                        disputes.push(Dispute {
                            class: class.to_string(),
                            reason: DisputeReason::BelowFloorBand,
                            reported,
                            companion,
                        });
                    } else if reported > floor.saturating_mul(ratio) {
                        disputes.push(Dispute {
                            class: class.to_string(),
                            reason: DisputeReason::AboveFloorBand,
                            reported,
                            companion,
                        });
                    }
                }
                reported
            }
            // A figure somebody else reported, with a kernel companion to check it against.
            source if source.is_reported() => match companion {
                Some(k) => {
                    if beyond_tolerance(reported, k, policy.tolerance_bp(class)) {
                        disputes.push(Dispute {
                            class: class.to_string(),
                            reason: DisputeReason::BeyondTolerance,
                            reported,
                            companion,
                        });
                        reported.min(k)
                    } else {
                        reported
                    }
                }
                None => {
                    // No companion in this unit: the line posts as an estimate, and the only check
                    // available is the one-sided bound against a proxy.
                    estimated = true;
                    disputes.push(Dispute {
                        class: class.to_string(),
                        reason: DisputeReason::NoCompanion,
                        reported,
                        companion: None,
                    });
                    if let Some(proxy) = kernel.proxy(class) {
                        let ratio = policy.locator_floor_ratio.max(1);
                        if reported > proxy.saturating_mul(ratio) {
                            disputes.push(Dispute {
                                class: class.to_string(),
                                reason: DisputeReason::AboveFloorBand,
                                reported,
                                companion: Some(proxy),
                            });
                        }
                    }
                    reported
                }
            },
            // A kernel-derived line the unit retained directly. A byte division floors, and a floor
            // is an estimate.
            source => {
                if source.is_floor() {
                    estimated = true;
                }
                reported
            }
        };

        lines.push(UsageLine {
            class: MeterClassId::new(class),
            quantity: charge,
        });
    }

    let lane = cross_check_lane(retained.lane_legs(), declared, policy);
    if lane.disputed {
        disputes.push(Dispute {
            class: String::new(),
            reason: DisputeReason::LaneMismatch,
            reported: 0,
            companion: None,
        });
    }

    let usage = if estimated {
        Usage::estimate(token, lines)?
    } else {
        Usage::report(token, lines)?
    };

    Ok(Metered {
        usage,
        lane,
        disputes,
    })
}

/// Whether two figures for the same class differ by more than the tolerance allows.
///
/// The comparison is a cross-multiplication on the basis-point scale, so no division and no decimal
/// is involved: the difference against the LARGER of the two, which makes the test symmetric —
/// whichever figure happens to be the bigger, the same pair either agrees or does not.
fn beyond_tolerance(a: u64, b: u64, tolerance_bp: u32) -> bool {
    let hi = a.max(b);
    let lo = a.min(b);
    if hi == 0 {
        return false; // two nothings agree
    }
    let difference = u128::from(hi - lo);
    let allowed = u128::from(hi).saturating_mul(u128::from(tolerance_bp));
    difference.saturating_mul(u128::from(WHOLE_BP)) > allowed
}
