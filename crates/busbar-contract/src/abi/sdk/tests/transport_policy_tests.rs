// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::sdk::test_support::zeroed;

fn policy(generation: u64) -> Vec<u8> {
    let value = guest_policy::encode(7, generation, &[]).unwrap();
    extensions::encode(&[(EXT_GUEST_POLICY, &value)])
}

fn ticket(slot: u32) -> Ticket {
    Ticket {
        slot,
        generation: 1,
    }
}

fn open(
    loans: &mut Loans,
    ticket: Ticket,
    stream: u64,
    reply: &[u8],
    leases: &Leases,
) -> Result<Option<Arc<Policy>>, &'static str> {
    let mut raw: FramerOut = zeroed();
    let result = loans.open(ticket, stream, reply, &mut Out::new(&mut raw), leases);
    if matches!(result, Ok(None)) {
        assert_ne!(raw.head.lease, 0, "the opening request must be leased");
        assert_eq!(raw.yielded.flags & YIELD_MORE, YIELD_MORE);
        assert_eq!((raw.yielded.frame_len, raw.yielded.pieces_len), (0, 0));
    }
    result
}

#[test]
fn a_consumed_reply_does_not_prevent_the_next_stream_on_a_resumed_operation() {
    let leases = Leases::default();
    let mut loans = Loans::from_initial(&policy(3)).unwrap().unwrap();
    assert!(open(&mut loans, ticket(1), 11, &[], &leases)
        .unwrap()
        .is_none());
    let reply = policy(4);
    let first = open(&mut loans, ticket(1), 11, &reply, &leases)
        .unwrap()
        .unwrap();
    assert_eq!(first.generation, 4);
    // The host retains this input reply while stream 11's auth is PENDING. Its resume may
    // discover stream 12, which must request its own selection rather than reuse/refuse it.
    assert!(open(&mut loans, ticket(1), 12, &reply, &leases)
        .unwrap()
        .is_none());
    let second = open(&mut loans, ticket(1), 12, &policy(5), &leases)
        .unwrap()
        .unwrap();
    assert_eq!(second.generation, 5);
    assert_eq!(
        first.generation, 4,
        "the first stream keeps its immutable loan"
    );
}

#[test]
fn an_acknowledgement_uses_the_policy_cached_when_that_stream_requested_it() {
    let leases = Leases::default();
    let mut loans = Loans::from_initial(&policy(3)).unwrap().unwrap();
    assert!(open(&mut loans, ticket(1), 11, &[], &leases)
        .unwrap()
        .is_none());
    assert!(open(&mut loans, ticket(2), 12, &[], &leases)
        .unwrap()
        .is_none());
    let newer = open(&mut loans, ticket(2), 12, &policy(4), &leases)
        .unwrap()
        .unwrap();
    let ack = Identity {
        listener: 7,
        generation: 3,
    }
    .encode()
    .unwrap();
    let ack = extensions::encode(&[(EXT_GUEST_CURRENT, &ack)]);
    let older = open(&mut loans, ticket(1), 11, &ack, &leases)
        .unwrap()
        .unwrap();
    assert_eq!((older.generation, newer.generation), (3, 4));
}

#[test]
fn cancelling_an_opening_forgets_only_that_operations_policy_loan() {
    let leases = Leases::default();
    let mut loans = Loans::from_initial(&policy(3)).unwrap().unwrap();
    assert!(open(&mut loans, ticket(1), 11, &[], &leases)
        .unwrap()
        .is_none());
    assert!(open(&mut loans, ticket(2), 12, &[], &leases)
        .unwrap()
        .is_none());
    assert_eq!(loans.pending_stream(ticket(1)), Some(11));
    assert_eq!(loans.cancel(ticket(1)), Some(11));
    assert_eq!(loans.pending_stream(ticket(1)), None);
    assert_eq!(loans.pending_stream(ticket(2)), Some(12));
    assert_eq!(loans.cancel(ticket(1)), None);
    let kept = open(&mut loans, ticket(2), 12, &policy(4), &leases)
        .unwrap()
        .unwrap();
    assert_eq!(kept.generation, 4);
}
