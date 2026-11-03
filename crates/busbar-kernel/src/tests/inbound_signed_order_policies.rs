// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn a_connection_refusal_preempts_both_signed_and_ticket_key_presteps() {
    for refusal in [Judged::Denied, Judged::Overloaded] {
        for position in [0, 1, 2] {
            let mut answers = [Some(Judged::Pass), None, Some(Judged::Identity)];
            answers[position] = Some(refusal);
            assert!(
                !connection_allows_key_prestep(&answers),
                "no later ticket or signed identity may override position {position}"
            );
        }
    }
    for answers in [
        vec![],
        vec![None],
        vec![Some(Judged::Pass)],
        vec![Some(Judged::Identity)],
        vec![Some(Judged::Pass), None, Some(Judged::Identity)],
    ] {
        assert!(connection_allows_key_prestep(&answers));
    }
}

#[test]
fn only_an_unfaulted_signed_pass_can_continue_to_the_ticket_and_token_path() {
    let strips = vec![Strip::field("authorization"), Strip::query("ticket")];
    let answer = VerifyAnswer {
        strips: strips.clone(),
        ..VerifyAnswer::from(Verified::Pass)
    };
    let SignedReaderStep::Pass(retained) = signed_reader_step(Some(answer.clone()), false) else {
        panic!("an unfaulted Pass reaches the next key pre-step");
    };
    assert_eq!(
        retained, strips,
        "the declared removals remain attached to the same unit"
    );
    let SignedReaderStep::Final(Some(retained)) = signed_reader_step(Some(answer), true) else {
        panic!("a faulted Pass is terminal and cannot reach a ticket");
    };
    assert_eq!(
        retained.verified,
        Verified::Pass,
        "the caller retains the faulted bit and original answer for fail-closed classification"
    );
    assert_eq!(retained.strips, strips);
    assert!(matches!(
        signed_reader_step(None, false),
        SignedReaderStep::Final(None)
    ));
    assert!(matches!(
        signed_reader_step(None, true),
        SignedReaderStep::Final(None)
    ));
}

#[test]
fn every_nonpass_signed_answer_remains_terminal_with_identity_and_replay_intact() {
    let identity = VerifiedIdentity {
        subject: "verified-public-credential".into(),
        replay: Some(Box::new(busbar_contract::auth_calls::Replay {
            key: "actual-signed-message".into(),
            ttl_secs: 60,
        })),
        ..Default::default()
    };
    for verified in [
        Verified::Identity(identity),
        Verified::Reject,
        Verified::Failed,
        Verified::Overloaded,
    ] {
        for faulted in [false, true] {
            let strips = vec![Strip::field("authorization")];
            let answer = VerifyAnswer {
                strips: strips.clone(),
                ..VerifyAnswer::from(verified.clone())
            };
            let SignedReaderStep::Final(Some(retained)) = signed_reader_step(Some(answer), faulted)
            else {
                panic!("a non-Pass never reaches tickets or another verifier");
            };
            assert_eq!(retained.verified, verified);
            assert_eq!(retained.strips, strips);
        }
    }
}
