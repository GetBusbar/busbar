// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_plugin_abi::fallback_usage::{
    self as wire, Completeness, Estimate, EstimateValue, SelectedResource, UsageSource,
};
use busbar_plugin_abi::plane::{self as p, tag};
use busbar_plugin_abi::records::{Records, Reply, Writer};
use busbar_ports::codec::fallback_usage::{AttemptState, Declaration};
use busbar_ports::plane::UsageClass;

fn classes() -> Vec<UsageClass> {
    vec![
        UsageClass {
            class: "tokens.in".into(),
            unit: p::UNIT_TOKENS,
            expected_units: Some(20.0),
        },
        UsageClass {
            class: "request".into(),
            unit: p::UNIT_COUNT,
            expected_units: Some(1.0),
        },
    ]
}

fn selected() -> SelectedResource<'static> {
    SelectedResource {
        attempt: 2,
        exchange: 0,
        resource: "sol",
    }
}

fn estimates() -> [Estimate<'static>; 2] {
    [
        Estimate {
            class: "tokens.in",
            value: EstimateValue::Unknown,
        },
        Estimate {
            class: "request",
            value: EstimateValue::Known {
                amount: 0,
                scale: 0,
            },
        },
    ]
}

#[test]
fn prepared_replacement_preserves_unknown_and_explicit_zero() {
    let classes = classes();
    let declaration = Declaration::new(p::FB_PREPARED_ESTIMATES, &classes, &[]).unwrap();
    let mut reply = Reply::new();
    wire::write_selected(&mut reply, selected()).unwrap();
    wire::write_prepared_estimates(&mut reply, selected(), &estimates()).unwrap();
    let view = declaration
        .validate_preparation(Some(selected()), Records::new(reply.as_bytes()))
        .unwrap()
        .unwrap();
    let entries = view.entries().collect::<Result<Vec<_>, _>>().unwrap();
    assert_eq!(entries, estimates());
    assert_eq!(entries[0].value, EstimateValue::Unknown);
    assert_eq!(
        entries[1].value,
        EstimateValue::Known {
            amount: 0,
            scale: 0
        }
    );
}

#[test]
fn wrong_resource_attempt_or_exchange_cannot_publish_prepared_values() {
    let classes = classes();
    let declaration = Declaration::new(p::FB_PREPARED_ESTIMATES, &classes, &[]).unwrap();
    let mut reply = Reply::new();
    wire::write_selected(&mut reply, selected()).unwrap();
    wire::write_prepared_estimates(&mut reply, selected(), &estimates()).unwrap();
    for expected in [
        SelectedResource {
            resource: "opus",
            ..selected()
        },
        SelectedResource {
            attempt: 1,
            ..selected()
        },
        SelectedResource {
            exchange: 1,
            ..selected()
        },
    ] {
        assert!(declaration
            .validate_preparation(Some(expected), Records::new(reply.as_bytes()))
            .is_err());
    }
}

#[test]
fn incomplete_duplicate_and_undeclared_estimates_refuse() {
    let classes = classes();
    let declaration = Declaration::new(p::FB_PREPARED_ESTIMATES, &classes, &[]).unwrap();
    for names in [
        vec!["request"],
        vec!["request", "request"],
        vec!["request", "other"],
    ] {
        let mut tail = Reply::new();
        for name in names {
            tail.put_pod_tail(
                tag::PREPARED_ESTIMATE,
                &p::PreparedEstimateRec {
                    amount: 0,
                    scale: 0,
                    knowledge: 2,
                },
                name.as_bytes(),
            )
            .unwrap();
        }
        let mut reply = Reply::new();
        wire::write_selected(&mut reply, selected()).unwrap();
        reply
            .put_pod_tail(
                tag::PREPARED_ESTIMATES,
                &p::PreparedEstimatesRec {
                    attempt: 2,
                    exchange: 0,
                },
                tail.as_bytes(),
            )
            .unwrap();
        assert!(declaration
            .validate_preparation(Some(selected()), Records::new(reply.as_bytes()))
            .is_err());
    }
}

#[test]
fn declaration_and_current_attempt_are_frozen_without_name_inference() {
    let classes = classes();
    let attempts = vec![Box::<str>::from("tokens.in")];
    assert!(Declaration::new(p::FB_ATTEMPT_USAGE, &classes, &[]).is_err());
    assert!(Declaration::new(0, &classes, &attempts).is_err());
    let declaration = Declaration::new(p::FB_ATTEMPT_USAGE, &classes, &attempts).unwrap();
    let usage = wire::AttemptUsage {
        attempt: 2,
        class: "tokens.in",
        amount: 0,
        scale: 0,
        source: UsageSource::Reported,
    };
    let state = AttemptState {
        attempt: 2,
        exchange: 0,
        sealed: false,
    };
    declaration.validate_attempt_usage(state, usage).unwrap();
    for bad in [
        AttemptState {
            attempt: 1,
            ..state
        },
        AttemptState {
            exchange: 1,
            ..state
        },
        AttemptState {
            sealed: true,
            ..state
        },
    ] {
        assert!(declaration.validate_attempt_usage(bad, usage).is_err());
    }
    assert!(declaration
        .validate_attempt_usage(
            state,
            wire::AttemptUsage {
                class: "request",
                ..usage
            }
        )
        .is_err());
    assert!(declaration.validate_session_class("tokens.in").is_err());
    declaration.validate_session_class("request").unwrap();
}

#[test]
fn complete_requires_authoritative_presence_even_for_zero() {
    let classes = classes();
    let attempts = vec![Box::<str>::from("tokens.in")];
    let declaration = Declaration::new(p::FB_ATTEMPT_USAGE, &classes, &attempts).unwrap();
    let state = AttemptState {
        attempt: 2,
        exchange: 0,
        sealed: false,
    };
    let end = wire::AttemptEnd {
        attempt: 2,
        completeness: Completeness::Complete,
    };
    assert!(declaration.validate_attempt_end(state, end, &[]).is_err());
    declaration
        .validate_attempt_end(state, end, &["tokens.in"])
        .unwrap();
    declaration
        .validate_attempt_end(
            state,
            wire::AttemptEnd {
                completeness: Completeness::Unknown,
                ..end
            },
            &[],
        )
        .unwrap();
}

#[test]
fn observation_counts_cannot_rebill_attempt_owned_classes() {
    let classes = classes();
    let attempts = vec![Box::<str>::from("tokens.in")];
    let declaration = Declaration::new(p::FB_ATTEMPT_USAGE, &classes, &attempts).unwrap();
    for names in [["request", "tokens.in"], ["tokens.in", "request"]] {
        let mut counts = Reply::new();
        for name in names {
            counts
                .put_pod_tail(
                    tag::OBS_COUNT,
                    &p::UsageRec {
                        amount: 1,
                        scale: 0,
                        source: p::SRC_REPORTED,
                    },
                    name.as_bytes(),
                )
                .unwrap();
        }
        assert!(declaration
            .validate_observation_counts(Records::new(counts.as_bytes()))
            .is_err());
    }
    // Reusing the immutable declaration on a later answer cannot open another billing path.
    assert!(declaration.validate_session_class("tokens.in").is_err());
    Declaration::legacy()
        .validate_session_class("tokens.in")
        .unwrap();
}
