// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The masking forms the location grammar declares for a credential in the
//! read cursor.
//!
//! Masking is decided by the location grammar rather than per plane, so every form is asked here
//! what it does — including the one that does nothing, because it was never in the bytes.

use busbar_kernel::grammar::{ArrivalLocation, MaskKind, SignedOver, Span};
use busbar_kernel::inflight::MAX_SESSION_UPSTREAMS;

/// The ceilings the kernel enforces are the ceilings the contract told the plugin about.
///
/// Three of these were declared twice, once here and once on the plugin surface, with nothing
/// checking that the two agreed. A plugin allocates, declares legs and names usage lines against
/// the contract's numbers; the kernel sizes buffers, admits pairings and settles reports against
/// these. Two independently-maintained constants that happen to agree today are a plugin refused
/// at a limit it was never told about the first time one of them moves.
#[test]
fn the_kernels_ceilings_are_the_contracts_own() {
    assert_eq!(
        MAX_SESSION_UPSTREAMS,
        busbar_contract::MAX_SESSION_UPSTREAMS
    );
    assert_eq!(
        busbar_contract::caps::usage::MAX_USAGE_LINES,
        busbar_contract::MAX_USAGE_LINES
    );
}

#[test]
fn every_location_form_says_how_it_is_masked() {
    assert_eq!(
        ArrivalLocation::Header("authorization").mask(),
        MaskKind::SameLengthFill
    );
    assert_eq!(ArrivalLocation::ClientCert.mask(), MaskKind::Nothing);
    assert_eq!(
        ArrivalLocation::Signed {
            over: SignedOver::Body
        }
        .mask(),
        MaskKind::SignatureSpan
    );
    assert_eq!(
        ArrivalLocation::HandshakeFrames {
            max_frames: 4,
            max_bytes: 256,
        }
        .mask(),
        MaskKind::BoundedPrefix
    );
    // A body signature has to see every byte it signs, so the unit does not open until the body has.
    assert!(ArrivalLocation::Signed {
        over: SignedOver::Both
    }
    .needs_whole_body());
    // A path segment is bytes in the read cursor exactly as a header is, so it hides the same way:
    // same-length fill, which leaves every offset already computed over the target where it was.
    assert_eq!(
        ArrivalLocation::PathSegment(0).mask(),
        MaskKind::SameLengthFill
    );
    assert!(!ArrivalLocation::PathSegment(0).needs_whole_body());
    assert!(!ArrivalLocation::Header("x").needs_whole_body());
}

/// The mask kinds are a closed set, and the set says so out loud.
///
/// Every other closed set in the contract carries the same anchor: the list IS the enum, so a kind
/// added without being named here changes the count and this fails. Without it the set was closed
/// only by whoever happened to be reading the enum that day.
#[test]
fn the_mask_kinds_are_a_closed_set() {
    assert_eq!(MaskKind::ALL.len(), 4, "the list is the whole enum");
    let mut seen = MaskKind::ALL.to_vec();
    seen.sort_by_key(|kind| format!("{kind:?}"));
    seen.dedup();
    assert_eq!(seen.len(), MaskKind::ALL.len(), "no kind is listed twice");
    // Exhaustive, with no catch-all: a new kind stops compiling here rather than being masked by
    // whatever arm happened to be last.
    for kind in MaskKind::ALL {
        match kind {
            MaskKind::SameLengthFill
            | MaskKind::Nothing
            | MaskKind::SignatureSpan
            | MaskKind::BoundedPrefix => {}
        }
    }
}

/// Every location form is masked by the kind it is masked by.
///
/// Asserting only that the answer is a member of the closed set is an assertion no answer could
/// fail — the previous test already pins that the set is the whole enum, so `ALL.contains(..)` was
/// true of every value `mask()` can return. The kind is what decides whether a credential is still
/// in the bytes a plane reads, so the expectation is a decision per form: `Query` masking `Nothing`
/// would leave an API key in the read cursor with nothing to say so.
#[test]
fn every_location_form_masks_by_a_kind_the_closed_set_names() {
    let forms = [
        ArrivalLocation::Header("authorization"),
        ArrivalLocation::Query("key"),
        ArrivalLocation::PathSegment(0),
        ArrivalLocation::FirstFrameJsonPointer("/token"),
        ArrivalLocation::ClientCert,
        ArrivalLocation::Signed {
            over: SignedOver::Url,
        },
        ArrivalLocation::HandshakeFrames {
            max_frames: 2,
            max_bytes: 64,
        },
    ];
    for form in forms {
        // Exhaustive, with no catch-all: a location form added to the grammar stops compiling here
        // until somebody decides how its span is hidden.
        let expected = match form {
            ArrivalLocation::Header(_)
            | ArrivalLocation::Query(_)
            | ArrivalLocation::PathSegment(_)
            | ArrivalLocation::FirstFrameJsonPointer(_) => MaskKind::SameLengthFill,
            ArrivalLocation::ClientCert => MaskKind::Nothing,
            ArrivalLocation::Signed { .. } => MaskKind::SignatureSpan,
            ArrivalLocation::HandshakeFrames { .. } => MaskKind::BoundedPrefix,
        };
        assert_eq!(
            form.mask(),
            expected,
            "{form:?} is hidden by a different kind than the one it declares"
        );
        assert!(
            MaskKind::ALL.contains(&form.mask()),
            "{form:?} masks by a kind the closed set does not name"
        );
    }
}
