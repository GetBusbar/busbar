// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_plugin_abi::fallback_usage::{
    self as wire, Completeness, Estimate, EstimateValue, SelectedResource, UsageSource,
};
use busbar_ports::codec::fallback_usage::Declaration;

fn declared() -> PlaneDescribe {
    let mut reply = Reply::new();
    reply
        .put_pod_tail(
            t::D_USAGE_CLASS,
            &p::UsageClassRec {
                unit: p::UNIT_TOKENS,
                _r: 0,
                expected_units: f64::NAN,
            },
            b"tokens.in",
        )
        .unwrap();
    wire::write_attempt_class(&mut reply, "tokens.in").unwrap();
    decode_describe(
        Records::new(reply.as_bytes()),
        p::M_UPSTREAM,
        p::FB_ATTEMPT_USAGE | p::FB_PREPARED_ESTIMATES,
    )
    .unwrap()
}

#[test]
fn actual_describe_preserves_the_attempt_subset() {
    let declaration = declared();
    assert_eq!(&*declaration.attempt_classes[0], "tokens.in");
    assert_eq!(declaration.usage_classes[0].unit, p::UNIT_TOKENS);
}

#[test]
fn malformed_late_attempt_record_reaches_no_callback() {
    let described = declared();
    let declaration = Declaration::new(
        p::FB_ATTEMPT_USAGE,
        &described.usage_classes,
        &described.attempt_classes,
    )
    .unwrap();
    let mut reply = Reply::new();
    wire::write_attempt_usage(
        &mut reply,
        wire::AttemptUsage {
            attempt: 1,
            class: "tokens.in",
            amount: 0,
            scale: 0,
            source: UsageSource::Reported,
        },
    )
    .unwrap();
    wire::write_attempt_end(
        &mut reply,
        wire::AttemptEnd {
            attempt: 1,
            completeness: Completeness::Complete,
        },
    )
    .unwrap();
    reply.put(t::ATTEMPT_USAGE_END, b"broken").unwrap();
    let mut callbacks = 0;
    assert!(decode_answer(
        Call::Piece(p::FROM_UPSTREAM),
        false,
        declaration,
        None,
        Some(0),
        Records::new(reply.as_bytes()),
        &mut |_| callbacks += 1
    )
    .is_err());
    assert_eq!(callbacks, 0);
}

#[test]
fn selected_mismatch_and_duplicate_estimates_publish_nothing() {
    let described = declared();
    let declaration =
        Declaration::new(p::FB_PREPARED_ESTIMATES, &described.usage_classes, &[]).unwrap();
    let selected = SelectedResource {
        attempt: 1,
        exchange: 0,
        resource: "sol",
    };
    for duplicate in [false, true] {
        let mut reply = Reply::new();
        wire::write_selected(&mut reply, selected).unwrap();
        let entries = [Estimate {
            class: "tokens.in",
            value: EstimateValue::Unknown,
        }];
        wire::write_prepared_estimates(&mut reply, selected, &entries).unwrap();
        if duplicate {
            wire::write_prepared_estimates(&mut reply, selected, &entries).unwrap();
        }
        let expected = if duplicate {
            selected
        } else {
            SelectedResource {
                resource: "opus",
                ..selected
            }
        };
        let mut callbacks = 0;
        assert!(decode_answer(
            Call::Upstream,
            false,
            declaration,
            Some(expected),
            None,
            Records::new(reply.as_bytes()),
            &mut |_| callbacks += 1
        )
        .is_err());
        assert_eq!(callbacks, 0);
    }
}

#[test]
fn undeclared_features_and_nonzero_exchange_reject_attempt_reports() {
    let described = declared();
    let declared = Declaration::new(
        p::FB_ATTEMPT_USAGE,
        &described.usage_classes,
        &described.attempt_classes,
    )
    .unwrap();
    let mut reply = Reply::new();
    wire::write_attempt_usage(
        &mut reply,
        wire::AttemptUsage {
            attempt: 1,
            class: "tokens.in",
            amount: 0,
            scale: 0,
            source: UsageSource::Reported,
        },
    )
    .unwrap();
    for (declaration, exchange) in [(Declaration::legacy(), 0), (declared, 1)] {
        let mut callbacks = 0;
        assert!(decode_answer(
            Call::Piece(p::FROM_UPSTREAM),
            false,
            declaration,
            None,
            Some(exchange),
            Records::new(reply.as_bytes()),
            &mut |_| callbacks += 1
        )
        .is_err());
        assert_eq!(callbacks, 0);
    }
}

#[test]
fn complete_preparation_publishes_typed_unknown_after_validation() {
    let described = declared();
    let declaration =
        Declaration::new(p::FB_PREPARED_ESTIMATES, &described.usage_classes, &[]).unwrap();
    let selected = SelectedResource {
        attempt: 3,
        exchange: 0,
        resource: "sol",
    };
    let mut reply = Reply::new();
    wire::write_selected(&mut reply, selected).unwrap();
    wire::write_prepared_estimates(
        &mut reply,
        selected,
        &[Estimate {
            class: "tokens.in",
            value: EstimateValue::Unknown,
        }],
    )
    .unwrap();
    let mut values = Vec::new();
    let mut selected_count = 0;
    decode_answer(
        Call::Upstream,
        false,
        declaration,
        Some(selected),
        None,
        Records::new(reply.as_bytes()),
        &mut |out| match out {
            PlaneOut::SelectedResource(found) => {
                assert_eq!(found, selected);
                selected_count += 1;
            }
            PlaneOut::PreparedEstimates(found) => {
                values.extend(found.entries().map(|entry| entry.unwrap().value))
            }
            _ => panic!("unexpected preparation item"),
        },
    )
    .unwrap();
    assert_eq!(selected_count, 1);
    assert_eq!(values, [EstimateValue::Unknown]);
}

#[test]
fn decline_has_no_prepared_view_and_wrong_record_order_is_atomic() {
    let described = declared();
    let declaration = Declaration::new(
        p::FB_ATTEMPT_USAGE | p::FB_PREPARED_ESTIMATES,
        &described.usage_classes,
        &described.attempt_classes,
    )
    .unwrap();
    let mut reply = Reply::new();
    reply
        .put_pod_tail(
            t::ATTEMPT,
            &p::AttemptRec {
                verdict: p::ATT_DECLINE,
                class: 0,
                retry_after_s: 0,
            },
            b"declined",
        )
        .unwrap();
    let mut callbacks = 0;
    decode_answer(
        Call::Upstream,
        false,
        declaration,
        None,
        None,
        Records::new(reply.as_bytes()),
        &mut |_| callbacks += 1,
    )
    .unwrap();
    assert_eq!(callbacks, 1);
    let mut reply = Reply::new();
    wire::write_attempt_end(
        &mut reply,
        wire::AttemptEnd {
            attempt: 1,
            completeness: Completeness::Unknown,
        },
    )
    .unwrap();
    wire::write_attempt_usage(
        &mut reply,
        wire::AttemptUsage {
            attempt: 1,
            class: "tokens.in",
            amount: 0,
            scale: 0,
            source: UsageSource::Reported,
        },
    )
    .unwrap();
    let mut callbacks = 0;
    assert!(decode_answer(
        Call::Piece(p::FROM_UPSTREAM),
        false,
        declaration,
        None,
        Some(0),
        Records::new(reply.as_bytes()),
        &mut |_| callbacks += 1
    )
    .is_err());
    assert_eq!(callbacks, 0);
}
