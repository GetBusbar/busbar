// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fixed audit record: one shape, no content, and a chain that catches an edit.

use busbar_contract::caps::{Outcome, ReasonCode, StepName, UnitKey};

use crate::record::{FinishClass, QuantitySource, Subject};

/// THE ON-DISK TAG VOCABULARY, AS LITERALS — the test the frozen table actually needed.
#[test]
fn the_on_disk_tag_vocabulary_is_the_literal_text_and_not_a_rendering_of_a_type() {
    use crate::record::{
        abort_tag, direction_tag, finish_tag, outcome_tag, quantity_source_tag, reason_tag,
        step_tag, subject_tag,
    };
    use busbar_contract::caps::{Abort, LocatorPtr};
    use busbar_contract::ClassDirection;

    for (step, frozen) in [
        (StepName::Arrival, "Arrival"),
        (StepName::Decode, "Decode"),
        (StepName::Authenticate, "Authenticate"),
        (StepName::Verify, "Verify"),
        (StepName::Approve, "Approve"),
        (StepName::Admit, "Admit"),
        (StepName::Route, "Route"),
        (StepName::Meter, "Meter"),
        (StepName::Audit, "Audit"),
        (StepName::Encode, "Encode"),
    ] {
        assert_eq!(step_tag(step), frozen, "step name on disk");
    }

    for (finish, frozen) in [
        (FinishClass::Complete, "Complete"),
        (FinishClass::TurnComplete, "TurnComplete"),
        (FinishClass::Partial, "Partial"),
        (FinishClass::Error, "Error"),
    ] {
        assert_eq!(finish_tag(finish), frozen, "finish class on disk");
    }

    for (direction, frozen) in [
        (ClassDirection::Input, "Input"),
        (ClassDirection::Response, "Response"),
        (ClassDirection::CacheRead, "CacheRead"),
        (ClassDirection::CacheWrite, "CacheWrite"),
        (ClassDirection::Kernel, "Kernel"),
    ] {
        assert_eq!(direction_tag(direction), frozen, "class direction on disk");
    }

    for (reason, frozen) in [
        (ReasonCode::Drain, "Drain"),
        (ReasonCode::ClientGone, "ClientGone"),
        (ReasonCode::OverBudget, "OverBudget"),
        (ReasonCode::ScopeDenied, "ScopeDenied"),
        (ReasonCode::NoRate, "NoRate"),
        (ReasonCode::DestinationUnreachable, "DestinationUnreachable"),
    ] {
        assert_eq!(reason_tag(reason), frozen, "reason code on disk");
    }

    for (abort, frozen) in [
        (
            Abort::Kernel {
                reason: ReasonCode::ClientGone,
            },
            "Kernel { reason: ClientGone }",
        ),
        (
            Abort::Kernel {
                reason: ReasonCode::OverBudget,
            },
            "Kernel { reason: OverBudget }",
        ),
        (
            Abort::Kernel {
                reason: ReasonCode::Drain,
            },
            "Kernel { reason: Drain }",
        ),
        (
            Abort::Superseded {
                by: UnitKey::new(77),
            },
            "Superseded { by: UnitKey(77) }",
        ),
    ] {
        assert_eq!(abort_tag(abort), frozen, "abort on disk");
    }

    for (outcome, frozen) in [
        (Outcome::Completed, "Completed"),
        (
            Outcome::Refused(StepName::Admit, ReasonCode::OverBudget),
            "Refused(Admit, OverBudget)",
        ),
        (
            Outcome::Failed(StepName::Route, ReasonCode::DestinationUnreachable),
            "Failed(Route, DestinationUnreachable)",
        ),
        (
            Outcome::Aborted(Abort::Kernel {
                reason: ReasonCode::Drain,
            }),
            "Aborted(Kernel { reason: Drain })",
        ),
        (
            Outcome::Aborted(Abort::Superseded {
                by: UnitKey::new(9),
            }),
            "Aborted(Superseded { by: UnitKey(9) })",
        ),
        (Outcome::TimedOut(StepName::Meter), "TimedOut(Meter)"),
    ] {
        assert_eq!(outcome_tag(outcome), frozen, "outcome on disk");
    }

    for (source, frozen) in [
        (
            QuantitySource::Locator {
                direction: ClassDirection::Response,

                ptr: LocatorPtr::new("/usage/\"odd\\name\""),
            },
            r#"Locator { direction: Response, ptr: LocatorPtr("/usage/\"odd\\name\"") }"#,
        ),
        (
            QuantitySource::Locator {
                direction: ClassDirection::Input,
                ptr: LocatorPtr::new("/usage/prompt_tokens"),
            },
            r#"Locator { direction: Input, ptr: LocatorPtr("/usage/prompt_tokens") }"#,
        ),
        (
            QuantitySource::KernelBytes { divisor: 4 },
            "KernelBytes { divisor: 4 }",
        ),
        (
            QuantitySource::KernelFrames { factor: 2 },
            "KernelFrames { factor: 2 }",
        ),
        (QuantitySource::TransportUnits, "TransportUnits"),
        (QuantitySource::KernelElapsedMono, "KernelElapsedMono"),
        (QuantitySource::Count, "Count"),
        (
            QuantitySource::PlaneCount {
                content_fact_key: "messages".into(),
            },
            r#"PlaneCount { content_fact_key: "messages" }"#,
        ),
    ] {
        assert_eq!(
            quantity_source_tag(&source),
            frozen,
            "quantity source on disk"
        );
    }

    for (subject, frozen) in [
        (Subject::PrincipalId("pseudonym-1".into()), "principal"),
        (Subject::Arrival, "arrival"),
        (Subject::Node(7), "node"),
        (Subject::Aggregate, "aggregate"),
    ] {
        assert_eq!(subject_tag(&subject), frozen, "subject on disk");
    }
}

/// A SECRET DERIVED FROM THE DEPLOYMENT KEY is one value per key and label: the same key gives the
#[test]
fn a_derived_secret_is_one_per_key_and_label_and_never_the_seed() {
    use crate::sign::AuditSigningKey;
    let seed = [3u8; 32];
    let (a, again) = (
        AuditSigningKey::from_seed(&seed),
        AuditSigningKey::from_seed(&seed),
    );
    let label = b"busbar deployment keyset: caller-ref material v1";
    assert_eq!(a.derived_secret(label), again.derived_secret(label));
    assert_ne!(a.derived_secret(label), a.derived_secret(b"another label"));
    assert_ne!(
        a.derived_secret(label),
        AuditSigningKey::from_seed(&[4u8; 32]).derived_secret(label)
    );
    assert_ne!(a.derived_secret(label), seed);
    let chain = crate::record::AuditChain::default();
    assert_eq!(chain.derived_secret(label), None);
    assert_eq!(
        chain.signing_with(again).derived_secret(label),
        Some(a.derived_secret(label))
    );
}
