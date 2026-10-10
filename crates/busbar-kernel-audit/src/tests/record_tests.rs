// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The fixed audit record: one shape, no content, and a chain that catches an edit.

use busbar_contract::caps::{Outcome, ReasonCode, StepName, UnitKey};

use crate::record::{FinishClass, QuantitySource, Subject};

/// EVERY FROZEN TAG STILL SPELLS WHAT THE CHAIN FROZE.
///
/// The digested text for these enumerations used to be whatever the derived `Debug` printed, so a
/// rename moved the sealed hash and every stored record would have reported itself tampered. The
/// text is written out in the production file now; this checks each spelling against today's derive
/// output, so a rename shows up here — as a difference somebody has to look at — instead of in the
/// hash. If this test fails, the tag is the thing to keep and the rename is the thing to reconsider.
#[test]
fn the_frozen_tags_match_the_text_the_chain_was_sealed_with() {
    use crate::record::{
        abort_tag, direction_tag, finish_tag, outcome_tag, quantity_source_tag, reason_tag,
        step_tag,
    };
    use busbar_contract::caps::{Abort, LocatorPtr};

    for step in [
        StepName::Arrival,
        StepName::Decode,
        StepName::Authenticate,
        StepName::Verify,
        StepName::Approve,
        StepName::Admit,
        StepName::Route,
        StepName::Meter,
        StepName::Audit,
        StepName::Encode,
    ] {
        assert_eq!(step_tag(step), format!("{step:?}"), "step name");
    }

    // The reason list is open, so the tag is a RULE rather than a table: the wire name in upper
    // camel case. Checked against every reason declared today, which is what makes the rule safe to
    // apply to one declared tomorrow.
    for reason in ReasonCode::ALL {
        assert_eq!(
            reason_tag(*reason),
            format!("{reason:?}"),
            "reason `{}`",
            reason.as_str()
        );
    }

    for finish in [
        FinishClass::Complete,
        FinishClass::TurnComplete,
        FinishClass::Partial,
        FinishClass::Error,
    ] {
        assert_eq!(finish_tag(finish), format!("{finish:?}"), "finish class");
    }

    for abort in [
        Abort::Kernel {
            reason: ReasonCode::ClientGone,
        },
        Abort::Kernel {
            reason: ReasonCode::OverBudget,
        },
        Abort::Kernel {
            reason: ReasonCode::Drain,
        },
        Abort::Superseded {
            by: UnitKey::new(77),
        },
    ] {
        assert_eq!(abort_tag(abort), format!("{abort:?}"), "abort");
    }

    for outcome in [
        Outcome::Completed,
        Outcome::Refused(StepName::Admit, ReasonCode::OverBudget),
        Outcome::Failed(StepName::Route, ReasonCode::DestinationUnreachable),
        Outcome::Aborted(Abort::Kernel {
            reason: ReasonCode::Drain,
        }),
        Outcome::Aborted(Abort::Superseded {
            by: UnitKey::new(9),
        }),
        Outcome::TimedOut(StepName::Meter),
    ] {
        assert_eq!(outcome_tag(outcome), format!("{outcome:?}"), "outcome");
    }

    for direction in [
        busbar_contract::ClassDirection::Input,
        busbar_contract::ClassDirection::Response,
        busbar_contract::ClassDirection::CacheRead,
        busbar_contract::ClassDirection::CacheWrite,
        busbar_contract::ClassDirection::Kernel,
    ] {
        assert_eq!(
            direction_tag(direction),
            format!("{direction:?}"),
            "class direction"
        );
    }

    for source in [
        QuantitySource::Locator {
            direction: busbar_contract::ClassDirection::Response,
            // A pointer with a quote and a backslash in it, because the frozen text quotes and
            // escapes the pointer and an unescaped one would digest differently.
            ptr: LocatorPtr::new("/usage/\"odd\\name\""),
        },
        QuantitySource::KernelBytes { divisor: 4 },
        QuantitySource::KernelFrames { factor: 2 },
        QuantitySource::TransportUnits,
        QuantitySource::KernelElapsedMono,
        QuantitySource::Count,
        QuantitySource::PlaneCount {
            content_fact_key: "messages".into(),
        },
    ] {
        assert_eq!(
            quantity_source_tag(&source),
            format!("{source:?}"),
            "quantity source"
        );
    }
}

/// THE ON-DISK TAG VOCABULARY, AS LITERALS — the test the frozen table actually needed.
///
/// The test above compares every tag against today's derived `Debug`. That is a useful relation to
/// hold, but on its own it cannot do the job the table exists for, because BOTH SIDES MOVE
/// TOGETHER. Rename `FinishClass::Partial` to `PartialDelivery`: the compiler forces the tag arm to
/// be touched, the obvious edit returns `"PartialDelivery"`, `format!("{finish:?}")` now also says
/// `"PartialDelivery"`, and the suite stays green — while every audit record already on disk whose
/// finish class was `Partial` hashes differently at the next boot and reports itself as
/// `DigestMismatch`, which the operator reads as "EDITED". A tamper alarm that fires on a rename is
/// worse than no alarm, because the one time it does fire nobody will believe it.
///
/// So the spellings are written out here as string literals, with no `Debug` anywhere in the file's
/// path to them. This is the wire vocabulary: it is what is on disk in every chain already sealed,
/// and it is not a rendering of any type. A rename that must not move the hash keeps the literal and
/// this test stays green; a rename that people INTEND to move the hash comes here, goes red, and the
/// migration conversation happens before the records are unreadable rather than after.
///
/// The reason tags are the one open list (`ReasonCode` is `#[non_exhaustive]`, so no exhaustive
/// table could exist here) and are pinned as a representative spread of shapes — single word, two
/// words, an acronym-ish one — which pins the RULE the open list is generated by against fixed text.
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
                // The quote and the backslash are here because the frozen text quotes and escapes
                // the pointer, and an unescaped one would digest differently.
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

    // The subject tags were never derived from `Debug` at all — they are lowercase wire words — but
    // they are digested alongside the rest, so they belong to the same frozen vocabulary and are
    // pinned in the same place rather than left as the one part of it nobody wrote down.
    for (subject, frozen) in [
        (Subject::PrincipalId("pseudonym-1".into()), "principal"),
        (Subject::Arrival, "arrival"),
        (Subject::Node(7), "node"),
        (Subject::Aggregate, "aggregate"),
    ] {
        assert_eq!(subject_tag(&subject), frozen, "subject on disk");
    }
}
