// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The node journal's on-demand verify covers BOTH copies it holds: the window of recent amendments
//! and the corrections copy the money read uses.
//!
//! A child of `amend`, so it can edit the held copies the way only an in-process edit could.

use super::{
    content_access, AmendBody, AmendChain, AmendJournal, Amendment, ClassCounts, OpClassId, Reader,
    AMENDMENTS_RETAINED,
};
use crate::record::{AuditBreakKind, Subject};
use busbar_contract::count::Count;

fn counts(n: i128) -> ClassCounts {
    ClassCounts::from([(
        "input_tokens".to_string(),
        Count::from_integer(n).expect("a small count"),
    )])
}

/// Seal `body` at the end of `run` by hand, exactly as the chain would: the next position, linked
/// to the last digest, hashed by the one digest function.
fn push(run: &mut Vec<Amendment>, body: AmendBody) {
    let (prev_hash, seq) = run
        .last()
        .map_or((String::new(), 1), |a| (a.hash.clone(), a.seq + 1));
    let mut amendment = Amendment {
        seq,
        body,
        prev_hash,
        hash: String::new(),
    };
    amendment.hash = AmendChain::digest_of(&amendment);
    run.push(amendment);
}

fn a_correction() -> AmendBody {
    super::correction(
        "the-entry-being-amended",
        Subject::PrincipalId("key-1".into()),
        "lane-a",
        1_700_000_000_000,
        counts(100),
        counts(40),
        "root",
        "a duplicate charge",
        1_700_000_100,
    )
    .expect("a valid correction")
}

fn an_access(i: u64) -> AmendBody {
    content_access(
        Reader::Hook,
        "screen",
        Subject::Arrival,
        OpClassId::new("chat"),
        vec!["content".to_string()],
        1_700_000_200 + i,
    )
}

/// A journal whose one correction has been RELEASED from the window by the accesses after it: the
/// correction now exists only in the corrections copy, which is what the money read uses.
fn released_correction() -> AmendJournal {
    let mut run = Vec::new();
    push(&mut run, a_correction());
    for i in 0..AMENDMENTS_RETAINED as u64 + 5 {
        push(&mut run, an_access(i));
    }
    let journal = AmendJournal::restore(run).expect("a whole run rebuilds");
    assert!(
        journal.released() > 0,
        "the correction is still in the window"
    );
    assert!(journal
        .recent()
        .all(|a| !matches!(a.body, AmendBody::Adjust(_))));
    assert_eq!(journal.corrections().len(), 1);
    journal
}

/// AN EDIT TO A RELEASED CORRECTION IS A FINDING, not a figure. `counts_now` prices from the
/// corrections copy, so a held correction edited in memory after it left the window would move
/// money while `GET /admin/verify` said the journal "verified as it is held now".
#[test]
fn an_edit_to_a_correction_the_window_released_is_caught_by_the_on_demand_verify() {
    let mut journal = released_correction();
    assert_eq!(journal.verify(), Ok(()));
    assert_eq!(
        journal.counts_now("the-entry-being-amended", &counts(100)),
        counts(40)
    );

    if let AmendBody::Adjust(adj) = &mut journal.corrections[0].body {
        adj.now = counts(0);
    }
    assert_eq!(
        journal.counts_now("the-entry-being-amended", &counts(100)),
        counts(0),
        "the edit reached the money read"
    );
    let broken = journal
        .verify()
        .expect_err("an edited correction verified as held");
    assert_eq!(broken.kind, AuditBreakKind::DigestMismatch);
    assert_eq!(broken.at_index, 1);
}

/// A CORRECTION DROPPED FROM THE COPY, or one the copy holds at a position the window disagrees
/// with, is a finding too: the copy is judged against the window wherever the window still holds
/// the position.
#[test]
fn a_corrections_copy_that_disagrees_with_the_window_is_caught() {
    let mut run = Vec::new();
    push(&mut run, an_access(0));
    push(&mut run, a_correction());
    push(&mut run, an_access(1));
    let whole = AmendJournal::restore(run.clone()).expect("a whole run rebuilds");
    assert_eq!(whole.verify(), Ok(()));

    let mut dropped = AmendJournal::restore(run.clone()).expect("a whole run rebuilds");
    dropped.corrections.clear();
    assert!(
        dropped.verify().is_err(),
        "a correction missing from the money read's copy verified"
    );

    let mut moved = AmendJournal::restore(run).expect("a whole run rebuilds");
    let mut other = moved.corrections[0].clone();
    other.seq = 3;
    moved.corrections[0] = other;
    assert!(
        moved.verify().is_err(),
        "a correction copied at a position the window holds something else at verified"
    );
}
