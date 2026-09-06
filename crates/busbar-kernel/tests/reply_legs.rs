// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Which answer wakes which unit waiting on a reply leg.
//!
//! Two tool calls open at once is the ordinary shape of a turn that asks for two tools. What the
//! cells here fix is that the second one exists at all as far as reply matching is concerned — a
//! leg that waits on a constant, or on a sixty-four-bit fold of an identifier, is free to pay one
//! call's hold out against the other call's answer.

use busbar_contract::dest::ClientMode;
use busbar_contract::ids::{CorrelationRef, CorrelationValue, UnitKey};
use busbar_kernel::reply::{AwaitingReplies, NotWaiting, OwnedCorrelation};

/// The fact key the voice plane declares its tool-call correlation under.
const CALL_ID: &str = "call_id";

/// A leg as the plane plans one: it names the key and nothing else.
const LEG: ClientMode = ClientMode::AwaitReply {
    correlation_key: CALL_ID,
    deadline_secs: 30,
};

/// The correlation a unit's draft mints for answers to carry, borrowed from the unit's arena.
fn minted(id: &str) -> Option<CorrelationRef<'_>> {
    Some(CorrelationRef {
        fact_key: CALL_ID,
        value: CorrelationValue::Str(id),
    })
}

/// The correlation a reply carries, as the plane read it off the bytes.
fn carried<'u>(key: &'static str, id: &'u str) -> CorrelationRef<'u> {
    CorrelationRef {
        fact_key: key,
        value: CorrelationValue::Str(id),
    }
}

/// Two concurrent tool calls: each reply wakes ONLY the call it answers.
///
/// The two legs are identical apart from the identifier their units minted — same declared key,
/// same selector, same deadline — which is precisely the pair a constant or a digest is free to
/// confuse. The replies come back in the opposite order to the calls, so "whichever is found
/// first" cannot pass either.
#[test]
fn two_concurrent_tool_calls_each_wake_only_their_own_draft() {
    let (weather, tide) = (UnitKey::new(11), UnitKey::new(22));
    let mut awaiting = AwaitingReplies::new();
    awaiting.enter(weather, LEG, minted("call_aaa"), 0).unwrap();
    awaiting.enter(tide, LEG, minted("call_bbb"), 0).unwrap();
    assert_eq!(awaiting.len(), 2, "two calls are open, not one");

    // The SECOND call answers first.
    assert_eq!(
        awaiting.wake(carried(CALL_ID, "call_bbb")),
        Some(tide),
        "the reply wakes the call whose identifier it carries"
    );
    assert_eq!(
        awaiting.waiting(weather).map(|w| w.value.clone()),
        Some(OwnedCorrelation::Str("call_aaa".to_owned())),
        "and leaves the other call waiting on its own identifier, untouched"
    );

    assert_eq!(
        awaiting.wake(carried(CALL_ID, "call_ccc")),
        None,
        "an unmatched reply is not paid out against the last call left standing"
    );
    assert_eq!(
        awaiting.wake(carried(CALL_ID, "call_aaa")),
        Some(weather),
        "the first call is still there for its own answer"
    );
    assert!(awaiting.is_empty(), "and both calls are settled");
}

/// The key is half the correlation, and a draft that mints under another key is not a wait.
#[test]
fn a_reply_leg_matches_on_the_declared_key_as_well_as_the_value() {
    let mut awaiting = AwaitingReplies::new();
    awaiting
        .enter(UnitKey::new(7), LEG, minted("call_aaa"), 0)
        .unwrap();

    assert_eq!(
        awaiting.wake(carried("request_id", "call_aaa")),
        None,
        "the same bytes under another plane's key are another plane's correlation"
    );
    assert_eq!(
        awaiting.wake(CorrelationRef {
            fact_key: CALL_ID,
            value: CorrelationValue::Num(0),
        }),
        None,
        "and the constant the leg used to wait on matches nothing at all now"
    );

    assert_eq!(
        awaiting.enter(
            UnitKey::new(8),
            LEG,
            Some(carried("request_id", "call_bbb")),
            0
        ),
        Err(NotWaiting::KeyMismatch),
        "a draft correlating under a key its leg never named is a disagreement, not a wait"
    );
    assert_eq!(
        awaiting.enter(UnitKey::new(9), LEG, None, 0),
        Err(NotWaiting::NoCorrelationOut),
        "and a wait with no identity is refused rather than entered as a wildcard"
    );
    assert_eq!(
        awaiting.enter(UnitKey::new(10), ClientMode::Deliver, None, 0),
        Err(NotWaiting::Delivers),
        "a delivering leg waits for nothing"
    );
}

/// A wait that is never answered expires, so the hold behind it is settled rather than held open.
#[test]
fn an_unanswered_reply_leg_expires_at_its_own_deadline() {
    let mut awaiting = AwaitingReplies::new();
    for (unit, id, secs) in [
        (UnitKey::new(1), "call_aaa", 5_u32),
        (UnitKey::new(2), "call_bbb", 30),
    ] {
        awaiting
            .enter(
                unit,
                ClientMode::AwaitReply {
                    correlation_key: CALL_ID,
                    deadline_secs: secs,
                },
                minted(id),
                1_000,
            )
            .unwrap();
    }

    assert!(awaiting.expired(5_000).is_empty(), "neither deadline is up");
    assert_eq!(
        awaiting.expired(6_000),
        vec![UnitKey::new(1)],
        "the five-second wait ends at six seconds; the thirty-second one does not"
    );
    assert_eq!(awaiting.len(), 1, "the other call is still open");
}
