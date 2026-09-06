// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fold: the closed sources, the variance rule, and the floor that is a tripwire and never a
//! charge.

use super::*;
use crate::{
    meter, Direction, DisputeReason, KernelCounts, LegDeclaration, MeterPolicy, QuantitySource,
    DEFAULT_LOCATOR_FLOOR_RATIO, DEFAULT_VARIANCE_TOLERANCE_BP,
};
use std::collections::BTreeMap;

fn fold(
    values: Vec<crate::LocatedValue>,
    kernel: KernelCounts,
    policy: &MeterPolicy,
) -> crate::Metered {
    meter(
        &retained(values),
        &kernel,
        policy,
        &LegDeclaration {
            admit_locator: false,
            verified: false,
            response: false,
        },
        &token(),
    )
    .expect("within the line bound")
}

/// The plain case: what the destination reported is what the ledger settles against, line for line.
#[test]
fn a_located_report_settles_at_what_the_destination_said() {
    let m = fold(
        vec![
            located(INPUT, 11, Direction::Input),
            located(OUTPUT, 7, Direction::Response),
        ],
        counts(vec![]),
        &MeterPolicy::default(),
    );
    assert_eq!(pairs(m.usage.lines()), vec![(INPUT, 11), (OUTPUT, 7)]);
    assert_eq!(m.usage.total(), 18);
    assert!(!m.usage.is_estimated());
    assert!(!m.disputed());
}

/// THE FLOOR IS EVIDENCE, NEVER A CHARGE. A located figure well below the kernel's floor still
/// bills at the located figure — it is the lower of the two — and the gap raises a dispute so
/// somebody looks at the plane that reported it.
#[test]
fn a_located_figure_far_below_the_floor_still_bills_and_raises_a_dispute() {
    let policy = MeterPolicy::default();
    let m = fold(
        vec![located(INPUT, 10, Direction::Input)],
        counts(vec![kernel_count(INPUT, 1_000)]),
        &policy,
    );
    assert_eq!(
        pairs(m.usage.lines()),
        vec![(INPUT, 10)],
        "the located figure is the charge"
    );
    assert_eq!(m.disputes.len(), 1);
    assert_eq!(m.disputes[0].reason, DisputeReason::BelowFloorBand);
    assert_eq!(m.disputes[0].companion, Some(1_000));
}

/// The bound is one-sided in each direction but exists on BOTH sides: a located figure far ABOVE
/// the floor is flagged too, so a locator pointed at the wrong field is caught whichever way it is
/// wrong. It still bills the located figure — the bound flags, it does not cap.
#[test]
fn a_located_figure_far_above_the_floor_bills_and_raises_a_dispute_too() {
    let m = fold(
        vec![located(INPUT, 1_000, Direction::Input)],
        counts(vec![kernel_count(INPUT, 10)]),
        &MeterPolicy::default(),
    );
    assert_eq!(pairs(m.usage.lines()), vec![(INPUT, 1_000)]);
    assert_eq!(m.disputes[0].reason, DisputeReason::AboveFloorBand);
}

/// Inside the band, nothing is disputed. The ratio is four, so a located figure between a quarter
/// of the floor and four times it is unremarkable.
#[test]
fn a_located_figure_inside_the_band_is_not_disputed() {
    let policy = MeterPolicy::default();
    assert_eq!(policy.locator_floor_ratio, DEFAULT_LOCATOR_FLOOR_RATIO);
    for located_quantity in [25u64, 100, 400] {
        let m = fold(
            vec![located(INPUT, located_quantity, Direction::Input)],
            counts(vec![kernel_count(INPUT, 100)]),
            &policy,
        );
        assert!(
            !m.disputed(),
            "{located_quantity} against a floor of 100 is inside the band"
        );
    }
}

/// THE VARIANCE RULE. A cardinality a plane reported is compared against the kernel's own count of
/// the same class; beyond the tolerance the LOWER of the two posts and the unit is disputed. An
/// under-reporting plane therefore gains nothing, and an over-reporting one is capped at the
/// kernel's figure.
#[test]
fn two_reported_sources_beyond_tolerance_post_the_lower() {
    let policy = MeterPolicy::default();
    assert_eq!(policy.variance_tolerance_bp, DEFAULT_VARIANCE_TOLERANCE_BP);

    // The plane claims more than the kernel counted: the kernel's figure is the lower and posts.
    let over = fold(
        vec![plane_count("calls", 500, "calls")],
        counts(vec![kernel_count("calls", 100)]),
        &policy,
    );
    assert_eq!(pairs(over.usage.lines()), vec![("calls", 100)]);
    assert_eq!(over.disputes[0].reason, DisputeReason::BeyondTolerance);

    // The plane claims less: its own figure is the lower and posts, still disputed.
    let under = fold(
        vec![plane_count("calls", 1, "calls")],
        counts(vec![kernel_count("calls", 100)]),
        &policy,
    );
    assert_eq!(pairs(under.usage.lines()), vec![("calls", 1)]);
    assert_eq!(under.disputes[0].reason, DisputeReason::BeyondTolerance);
}

/// Within the tolerance the reported figure stands unflagged. One per cent of a thousand is ten, so
/// nine hundred and ninety agrees and nine hundred and eighty does not.
#[test]
fn a_disagreement_within_tolerance_posts_the_reported_figure() {
    let policy = MeterPolicy::default();
    let inside = fold(
        vec![plane_count("calls", 990, "calls")],
        counts(vec![kernel_count("calls", 1_000)]),
        &policy,
    );
    assert_eq!(pairs(inside.usage.lines()), vec![("calls", 990)]);
    assert!(!inside.disputed());

    let outside = fold(
        vec![plane_count("calls", 980, "calls")],
        counts(vec![kernel_count("calls", 1_000)]),
        &policy,
    );
    assert_eq!(pairs(outside.usage.lines()), vec![("calls", 980)]);
    assert!(outside.disputed());
}

/// A card may TIGHTEN the tolerance for one class and may never widen it. A per-class entry looser
/// than the general figure is ignored.
#[test]
fn a_per_class_tolerance_may_tighten_and_never_widen() {
    let mut policy = MeterPolicy::default();
    policy.class_tolerance_bp.insert("calls".to_string(), 10); // a tenth of a per cent
    policy.class_tolerance_bp.insert("rows".to_string(), 5_000); // fifty per cent — an attempt to widen
    assert_eq!(policy.tolerance_bp("calls"), 10);
    assert_eq!(
        policy.tolerance_bp("rows"),
        DEFAULT_VARIANCE_TOLERANCE_BP,
        "a looser per-class figure is ignored"
    );

    // Half a per cent passes the general tolerance and fails the tightened one.
    let m = fold(
        vec![plane_count("calls", 995, "calls")],
        counts(vec![kernel_count("calls", 1_000)]),
        &policy,
    );
    assert!(m.disputed());
}

/// A reported cardinality with NO kernel companion in the same unit — objects, rows, queries —
/// posts as an estimate and reaches the disputes report, because there is nothing to check it
/// against. Where the kernel can offer a proxy, the one-sided bound applies against that instead.
#[test]
fn a_cardinality_with_no_companion_posts_estimated_and_is_bounded_against_a_proxy() {
    let policy = MeterPolicy::default();
    let bare = fold(
        vec![plane_count("objects", 42, "objects")],
        counts(vec![]),
        &policy,
    );
    assert_eq!(pairs(bare.usage.lines()), vec![("objects", 42)]);
    assert!(bare.usage.is_estimated());
    assert_eq!(bare.disputes[0].reason, DisputeReason::NoCompanion);

    // With a proxy, an implausible figure is flagged as well — an over-reporting plane is caught by
    // the bound where it cannot be caught by a pair.
    let proxied =
        KernelCounts::with_proxies(vec![], BTreeMap::from([("objects".to_string(), 10u64)]));
    let m = fold(
        vec![plane_count("objects", 1_000, "objects")],
        proxied,
        &policy,
    );
    let reasons: Vec<DisputeReason> = m.disputes.iter().map(|d| d.reason).collect();
    assert!(reasons.contains(&DisputeReason::NoCompanion));
    assert!(reasons.contains(&DisputeReason::AboveFloorBand));
}

/// A kernel byte count divided by its divisor FLOORS, so the line is an estimate and the whole
/// report says so. A frame count times its factor is exact and says nothing.
#[test]
fn a_byte_derived_line_is_an_estimate_and_a_frame_derived_one_is_not() {
    let bytes = crate::LocatedValue {
        class: MeterClassId::new("audio"),
        quantity: 7,
        source: QuantitySource::KernelBytes { divisor: 4 },
    };
    let frames = crate::LocatedValue {
        class: MeterClassId::new("frames"),
        quantity: 3,
        source: QuantitySource::KernelFrames { factor: 2 },
    };
    let floored = fold(vec![bytes], counts(vec![]), &MeterPolicy::default());
    assert!(floored.usage.is_estimated());
    let exact = fold(vec![frames], counts(vec![]), &MeterPolicy::default());
    assert!(!exact.usage.is_estimated());
}

/// THE PROVENANCE TRAVELS WITH THE LINE. The fold matches on the source to decide what to charge,
/// so it knows exactly what evidence each figure rests on; the line it posts must carry that same
/// source, and its own estimate mark, rather than a uniform `Count`/not-estimated pair.
///
/// The audit record seals `line.source` into its digest and the ledger settles against it, so a
/// posted line claiming the kernel counted a figure the destination actually reported is a claim
/// about evidence that a billing dispute turns on.
#[test]
fn each_posted_line_carries_the_source_the_fold_matched_and_its_own_estimate_mark() {
    let m = fold(
        vec![
            located(OUTPUT, 7, Direction::Response),
            crate::LocatedValue {
                class: MeterClassId::new(INPUT),
                quantity: 9,
                source: QuantitySource::KernelBytes { divisor: 4 },
            },
        ],
        counts(vec![]),
        &MeterPolicy::default(),
    );
    let lines = m.usage.lines();
    assert_eq!(lines.len(), 2);

    assert_eq!(lines[0].class.as_str(), OUTPUT);
    assert_eq!(
        lines[0].source,
        QuantitySource::Locator {
            direction: Direction::Response,
            ptr: LocatorPtr::new("/usage"),
        },
        "a located figure must post as located, not as a kernel count"
    );
    assert!(
        !lines[0].estimated,
        "a figure the destination reported is not the node's floor"
    );

    assert_eq!(lines[1].class.as_str(), INPUT);
    assert_eq!(
        lines[1].source,
        QuantitySource::KernelBytes { divisor: 4 },
        "a byte-derived figure must post as byte-derived"
    );
    assert!(
        lines[1].estimated,
        "a byte division floors, and a floor is an estimate"
    );
}

/// The conversion from a raw measurement to the class's own quantity: bytes floor, frames multiply,
/// and a class declared with no divisor converts nothing rather than dividing by zero.
#[test]
fn the_source_conversions_floor_multiply_and_refuse_to_divide_by_nothing() {
    assert_eq!(
        crate::source::quantity_from_raw(&QuantitySource::KernelBytes { divisor: 4 }, 7),
        1
    );
    assert_eq!(
        crate::source::quantity_from_raw(&QuantitySource::KernelBytes { divisor: 0 }, 7),
        0
    );
    assert_eq!(
        crate::source::quantity_from_raw(&QuantitySource::KernelFrames { factor: 2 }, 3),
        6
    );
    assert_eq!(
        crate::source::quantity_from_raw(
            &QuantitySource::KernelFrames { factor: u64::MAX },
            u64::MAX
        ),
        u64::MAX,
        "the frame factor saturates rather than wrapping"
    );
    assert_eq!(
        crate::source::quantity_from_raw(&QuantitySource::Count, 9),
        9
    );
}

/// Which sources the kernel derived itself, and which came from somebody else. The split is what
/// decides whether a line wants a companion at all.
#[test]
fn the_closed_sources_split_into_kernel_derived_and_reported() {
    let kernel = [
        QuantitySource::KernelBytes { divisor: 1 },
        QuantitySource::KernelFrames { factor: 1 },
        QuantitySource::KernelElapsedMono,
        QuantitySource::Count,
    ];
    for s in kernel {
        assert!(s.is_kernel_derived(), "{s:?} is the kernel's own");
        assert!(!s.is_reported());
    }
    let reported = [
        QuantitySource::Locator {
            direction: Direction::Response,
            ptr: LocatorPtr::new("/usage/output_tokens"),
        },
        QuantitySource::TransportUnits,
        QuantitySource::PlaneCount {
            content_fact_key: "calls".to_string(),
        },
    ];
    for s in reported {
        assert!(s.is_reported(), "{s:?} came from somebody else");
    }
}

/// The short form on the report type folds with the default tolerances and no lane evidence — the
/// The fold takes its policy and its legs, and there is no second way in.
///
/// There used to be a shorter form that took neither: it priced at default tolerances with no lane
/// alias map and discarded the disputes, which is not what the metering step does. Its absence is
/// the point of this cell — the policy and the legs are arguments the caller has to supply, so a
/// fold cannot happen without somebody deciding what it is folding against.
#[test]
fn the_fold_takes_its_policy_and_its_legs() {
    let values = vec![located(INPUT, 11, Direction::Input)];
    let folded = meter(
        &retained(values),
        &counts(vec![]),
        &MeterPolicy::default(),
        &LegDeclaration::default(),
        &token(),
    )
    .expect("within the line bound");
    assert_eq!(pairs(folded.usage.lines()), vec![(INPUT, 11)]);
    // The disputes come back with the report rather than being dropped — and WHICH dispute is the
    // whole of what the caller is being handed, so the assertion names it. The legs here are the
    // default declaration, which says all three legs are produced, against retained values that
    // carry no lane evidence at all: three declared legs that never arrived, which is one
    // whole-unit lane dispute and nothing else. Asserting only that something was disputed would
    // pass just as happily if the fold started reporting a different disagreement entirely.
    let reasons: Vec<DisputeReason> = folded.disputes.iter().map(|d| d.reason).collect();
    assert_eq!(reasons, vec![DisputeReason::LaneMismatch]);
    assert_eq!(
        folded.disputes[0].class, "",
        "the lane is a whole-unit dispute, not a dispute about one class"
    );

    // And the legs are an argument, not a constant: the same fold with no leg declared at all has
    // no lane to disagree about, so the only dispute left is the one the LINE earns — a reported
    // cardinality with no kernel companion in this unit to be checked against.
    let reported = meter(
        &retained(vec![plane_count("objects", 42, "objects")]),
        &counts(vec![]),
        &MeterPolicy::default(),
        &LegDeclaration {
            admit_locator: false,
            verified: false,
            response: false,
        },
        &token(),
    )
    .expect("within the line bound");
    let reasons: Vec<DisputeReason> = reported.disputes.iter().map(|d| d.reason).collect();
    assert_eq!(reasons, vec![DisputeReason::NoCompanion]);
    assert_eq!(reported.disputes[0].class, "objects");
    assert_eq!(reported.disputes[0].reported, 42);
    assert_eq!(
        reported.disputes[0].companion, None,
        "there was no companion — that is the dispute"
    );
    assert!(
        reported.usage.is_estimated(),
        "an unchecked reported figure posts as an estimate"
    );
}
