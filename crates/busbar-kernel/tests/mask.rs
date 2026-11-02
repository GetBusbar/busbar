// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::grammar::{ArrivalLocation, MaskKind, SignedOver};

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

    assert!(ArrivalLocation::Signed {
        over: SignedOver::Both
    }
    .needs_whole_body());

    assert_eq!(
        ArrivalLocation::PathSegment(0).mask(),
        MaskKind::SameLengthFill
    );
    assert!(!ArrivalLocation::PathSegment(0).needs_whole_body());
    assert!(!ArrivalLocation::Header("x").needs_whole_body());
}

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
