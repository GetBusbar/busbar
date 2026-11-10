// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Owned usage observations cross only an admitted plane invocation. The kernel owns
//! scope authority, pending receipts and durable settlement; no plugin pointer survives.

use super::ticket::{InstanceWake, Waking};
use busbar_contract::abi::{
    host::access::{self, Extension},
    mechanism::{
        call::{Blob, InHead, OutHead, Outcome, BLOB_OCTETS, BLOB_SECRET},
        check::HARD_MAX_BYTES,
        extensions,
        lifecycle::slot,
        ticket::Ticket,
        KindCode,
    },
    plane::{self, OnPieceOut},
    sdk::plane::observation as wire,
};
use std::sync::atomic::Ordering;

const KEYS: &[&str] = &[
    wire::CAPABILITY,
    wire::SCOPE,
    wire::INTENT,
    wire::SCOPE_INTENT,
    wire::RESULT,
];

pub(crate) struct Input {
    input: *mut InHead,
    original: Blob,
    _bytes: zeroize::Zeroizing<Vec<u8>>,
}

impl Drop for Input {
    fn drop(&mut self) {
        // SAFETY: this loan is dropped before the crossing's host input frame.
        unsafe { (*self.input).extensions = self.original };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AnswerError {
    Malformed,
    Authority,
}

impl AnswerError {
    pub(crate) fn outcome(self) -> Outcome {
        match self {
            Self::Malformed => Outcome::Fault,
            Self::Authority => Outcome::Refused,
        }
    }
}

/// Compose host-owned input without letting a previous extension impersonate its scope.
fn compose(prior: &[u8], supplied: &[u8]) -> Result<Vec<u8>, ()> {
    if supplied.len() > wire::MAX_BYTES {
        return Err(());
    }
    let capability = extensions::unique(supplied, wire::CAPABILITY).map_err(|_| ())?;
    wire::scope(supplied).map_err(|_| ())?;
    wire::result(supplied).map_err(|_| ())?;
    if capability != Some(&b"1"[..])
        || extensions::unique(supplied, wire::INTENT)
            .map_err(|_| ())?
            .is_some()
        || extensions::unique(supplied, wire::SCOPE_INTENT)
            .map_err(|_| ())?
            .is_some()
    {
        return Err(());
    }
    for key in KEYS {
        extensions::unique(supplied, key).map_err(|_| ())?;
        if extensions::unique(prior, key).map_err(|_| ())?.is_some() {
            return Err(());
        }
    }
    if extensions::entries(supplied).any(|(key, _)| !KEYS.iter().any(|name| key == name.as_bytes()))
    {
        return Err(());
    }
    let length = prior
        .len()
        .checked_add(supplied.len())
        .filter(|n| *n <= HARD_MAX_BYTES as usize)
        .ok_or(())?;
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(prior);
    bytes.extend_from_slice(supplied);
    Ok(bytes)
}

/// # Safety
/// The host owns `input` and its extension bytes for this entire crossing.
pub(crate) unsafe fn prepare(
    wake: &'static InstanceWake,
    operation: u32,
    input: *mut InHead,
    unit: Option<u64>,
) -> Result<Option<Input>, ()> {
    if operation != plane::slot::ON_PIECE || unit.is_none() {
        return Ok(None);
    }
    let policy = access::extension(Extension::UsageObservation);
    if super::access::admit(wake, Some(&policy), Some(operation)).is_err() {
        return Ok(None);
    }
    // SAFETY: this crossing owns the input frame.
    let head = unsafe { &mut *input };
    if head.ticket.is_none() {
        return Ok(None);
    }
    let Some(caller) = wake.caller.get() else {
        return Ok(None);
    };
    let Some(route) = Waking::of(wake).and_then(|w| w.route.upgrade()) else {
        return Ok(None);
    };
    let Some(served) = route.services() else {
        return Ok(None);
    };
    // None means the configured durable runtime or admitted accounting scope is unavailable.
    let Some(supplied) = served
        .provider
        .usage_observation_input(caller, head.ticket, unit)
    else {
        return Ok(None);
    };
    let supplied = zeroize::Zeroizing::new(supplied);
    let original = head.extensions;
    if original.len > HARD_MAX_BYTES as usize || (original.len != 0 && original.fmt != BLOB_OCTETS)
    {
        return Err(());
    }
    // SAFETY: the host-owned original loan is bounded before forming this slice.
    let prior = unsafe { super::validate::lent(original.ptr, original.len) }.ok_or(())?;
    let bytes = zeroize::Zeroizing::new(compose(prior, &supplied)?);
    head.extensions = Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: original.flags | BLOB_SECRET,
    };
    Ok(Some(Input {
        input,
        original,
        _bytes: bytes,
    }))
}

fn isolated(out: &OnPieceOut) -> bool {
    out.emitted == 0
        && out.more == 0
        && out.flags == 0
        && out.reply_status == 0
        && out.fields_written == 0
        && out.fields_needed == 0
        && out.units_written == 0
        && out.units_needed == 0
        && out.records_written == 0
        && out.records_needed == 0
        && out.arena_written == 0
        && out.arena_needed == 0
        && out.verb.len == 0
        && out.target.len == 0
        && out.need == 0
        && out.verdict == 0
        && out.fault == 0
        && out.tap_fault == 0
        && out.lane.len == 0
        && out.final_status == 0
        && out.final_message.len == 0
        && out.final_details.len == 0
        && out.metric_pool.len == 0
        && out.metric_lane.len == 0
        && out.wait_member.len == 0
        && out.fault_reason.len == 0
}

#[derive(Debug, PartialEq, Eq)]
enum Intent {
    Observe(wire::Observation),
    Scope(wire::ScopeRequest),
}

fn decode(bytes: &[u8]) -> Result<Option<Intent>, AnswerError> {
    if !extensions::present(bytes, KEYS) {
        return Ok(None);
    }
    for key in [wire::CAPABILITY, wire::SCOPE, wire::RESULT] {
        if extensions::unique(bytes, key)
            .map_err(|_| AnswerError::Malformed)?
            .is_some()
        {
            return Err(AnswerError::Malformed);
        }
    }
    // An accounting intent is an isolated effect. Conditional/inspection or other output
    // extensions cannot commit first and leave this crossing's accounting refused afterwards.
    if extensions::entries(bytes)
        .any(|(key, _)| key != wire::INTENT.as_bytes() && key != wire::SCOPE_INTENT.as_bytes())
    {
        return Err(AnswerError::Malformed);
    }
    let observation =
        wire::Observation::from_extensions(bytes).map_err(|_| AnswerError::Malformed)?;
    let scope = wire::ScopeRequest::from_extensions(bytes).map_err(|_| AnswerError::Malformed)?;
    match (observation, scope) {
        (Some(observation), None) => Ok(Some(Intent::Observe(observation))),
        (None, Some(scope)) => Ok(Some(Intent::Scope(scope))),
        _ => Err(AnswerError::Malformed),
    }
}

/// # Safety
/// The validated answer and all output extension bytes remain under their lease.
pub(crate) unsafe fn answer(
    wake: &'static InstanceWake,
    kind: KindCode,
    ticket: Ticket,
    unit: Option<u64>,
    head: &OutHead,
    answer: &super::Answer,
) -> Result<(), AnswerError> {
    if head.extensions.len > HARD_MAX_BYTES as usize {
        return Err(AnswerError::Malformed);
    }
    // SAFETY: the length is bounded and the plugin's answer lease is still held.
    let bytes = unsafe { super::validate::lent(head.extensions.ptr, head.extensions.len) }
        .ok_or(AnswerError::Malformed)?;
    let intent = decode(bytes)?;
    let waking = Waking::of(wake);
    let route = waking.as_ref().and_then(|w| w.route.upgrade());
    let served = route.as_ref().and_then(|r| r.services());
    let caller = wake.caller.get();
    let Some(intent) = intent else {
        if kind == KindCode::Plane {
            if let (Some(served), Some(caller)) = (served, caller) {
                if answer.slot == plane::slot::ON_PIECE
                    && !served
                        .provider
                        .usage_observation_output_allowed(caller, ticket, unit)
                    && (answer.outcome == Outcome::Ready
                        || !isolated(
                            answer
                                .out::<OnPieceOut>()
                                .map_err(|_| AnswerError::Malformed)?,
                        ))
                {
                    return Err(AnswerError::Authority);
                }
                if answer.slot == slot::CANCEL
                    || (answer.slot == plane::slot::ON_PIECE && answer.outcome != Outcome::Pending)
                {
                    served
                        .provider
                        .usage_observation_retire(caller, ticket, unit);
                }
            }
        }
        return Ok(());
    };
    if kind != KindCode::Plane || unit.is_none() || ticket.is_none() {
        return Err(AnswerError::Authority);
    }
    let policy = access::extension(Extension::UsageObservation);
    super::access::admit(wake, Some(&policy), Some(answer.slot))
        .map_err(|_| AnswerError::Authority)?;
    if answer.slot != plane::slot::ON_PIECE
        || answer.outcome != Outcome::Pending
        || head.extensions.fmt != BLOB_OCTETS
        || head.extensions.flags & !BLOB_SECRET != 0
        || !isolated(
            answer
                .out::<OnPieceOut>()
                .map_err(|_| AnswerError::Malformed)?,
        )
    {
        return Err(AnswerError::Malformed);
    }
    let caller = caller.ok_or(AnswerError::Authority)?;
    let waking = waking.ok_or(AnswerError::Authority)?;
    let served = served.ok_or(AnswerError::Authority)?;
    // The host stores the receipt before calling done. Cancellation may retire the ticket;
    // durable obligations survive, and generation-checked wake routing discards stale wakes.
    let done = Box::new(move |_| {
        if !wake.revoked.load(Ordering::Acquire) {
            waking.wake(ticket);
        }
    });
    match intent {
        Intent::Observe(observation) => {
            served
                .provider
                .usage_observation_submit(caller, ticket, unit, observation, done)
        }
        Intent::Scope(scope) => served
            .provider
            .usage_observation_scope(caller, ticket, unit, scope, done),
    }
    .map_err(|_| AnswerError::Authority)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_input_cannot_override_custody_or_hide_malformed_framing() {
        let supplied = extensions::encode(&[(wire::CAPABILITY, b"1"), (wire::SCOPE, &[1; 32])]);
        let unrelated = extensions::encode(&[("unrelated", b"preserved")]);
        let combined = compose(&unrelated, &supplied).unwrap();
        assert_eq!(
            extensions::unique(&combined, "unrelated").unwrap(),
            Some(&b"preserved"[..])
        );
        assert!(compose(&supplied, &supplied).is_err());
        assert!(compose(&[0], &supplied).is_err());
        let forged = extensions::encode(&[(wire::CAPABILITY, b"1"), (wire::INTENT, b"{}")]);
        assert!(compose(&[], &forged).is_err());
        assert!(compose(&[], &vec![0; wire::MAX_BYTES + 1]).is_err());
    }

    #[test]
    fn observation_output_refuses_duplicates_host_authority_and_other_effects() {
        let observation = wire::Observation::new([1; 32], vec![2], vec![3])
            .count(0, busbar_contract::Count::ZERO)
            .unwrap()
            .final_totals();
        let encoded = observation.extension().unwrap();
        assert_eq!(
            decode(&encoded).unwrap(),
            Some(Intent::Observe(observation))
        );
        let mut duplicate = encoded.clone();
        duplicate.extend_from_slice(&encoded);
        assert_eq!(decode(&duplicate), Err(AnswerError::Malformed));
        let mut mixed = encoded.clone();
        mixed.extend_from_slice(&extensions::encode(&[("other-effect", b"opaque")]));
        assert_eq!(decode(&mixed), Err(AnswerError::Malformed));
        assert_eq!(
            decode(&extensions::encode(&[(wire::SCOPE, &[1; 32])])),
            Err(AnswerError::Malformed)
        );
        let mut truncated = encoded;
        truncated.pop();
        assert_eq!(decode(&truncated), Err(AnswerError::Malformed));
        assert_eq!(
            decode(&extensions::encode(&[("unrelated", b"opaque")])),
            Ok(None)
        );
        let scope = wire::ScopeRequest::create();
        assert_eq!(
            decode(&scope.extension().unwrap()),
            Ok(Some(Intent::Scope(scope)))
        );
        let mut combined = wire::Observation::new([1; 32], vec![2], vec![3])
            .extension()
            .unwrap();
        combined.extend_from_slice(&wire::ScopeRequest::attach([1; 32]).extension().unwrap());
        assert_eq!(decode(&combined), Err(AnswerError::Malformed));
    }

    #[test]
    fn observation_isolated_output_refuses_ordinary_counts_and_response_publication() {
        // SAFETY: OnPieceOut contains only integer fields and pointers, all valid at zero.
        let mut out: OnPieceOut = unsafe { std::mem::zeroed() };
        assert!(isolated(&out));
        out.units_written = 1;
        assert!(!isolated(&out));
        out.units_written = 0;
        out.emitted = 1;
        assert!(!isolated(&out));
    }

    #[test]
    fn observation_crossing_bounds_pointer_before_read_and_refuses_wrong_kind() {
        let wake = Box::leak(Box::new(InstanceWake::default()));
        let input = super::super::in_head();
        let ticket = Ticket {
            slot: 1,
            generation: 1,
        };
        // SAFETY: OnPieceOut is an ABI aggregate of zero-valid scalars and pointers.
        let mut out: OnPieceOut = unsafe { std::mem::zeroed() };
        out.head = super::super::out_head();
        out.head.extensions = Blob {
            ptr: std::ptr::dangling(),
            len: HARD_MAX_BYTES as usize + 1,
            fmt: BLOB_OCTETS,
            flags: 0,
        };
        // SAFETY: both host frames are live. The invalid extension pointer must never be read;
        // its over-limit length is rejected before any slice construction.
        let result = unsafe {
            let frame = super::super::Answer::new(
                plane::slot::ON_PIECE,
                Outcome::Pending,
                &input,
                std::mem::size_of_val(&input),
                &out.head,
                std::mem::size_of_val(&out),
            );
            answer(wake, KindCode::Plane, ticket, Some(7), &out.head, &frame)
        };
        assert_eq!(result, Err(AnswerError::Malformed));
        let bytes = wire::Observation::new([1; 32], vec![2], vec![3])
            .extension()
            .unwrap();
        out.head.extensions.ptr = bytes.as_ptr();
        out.head.extensions.len = bytes.len();
        // SAFETY: both frames and encoded bytes remain alive for every crossing.
        unsafe {
            let frame = super::super::Answer::new(
                plane::slot::ON_PIECE,
                Outcome::Pending,
                &input,
                std::mem::size_of_val(&input),
                &out.head,
                std::mem::size_of_val(&out),
            );
            assert_eq!(
                answer(wake, KindCode::Hook, ticket, Some(7), &out.head, &frame),
                Err(AnswerError::Authority)
            );
            assert_eq!(
                answer(wake, KindCode::Plane, ticket, None, &out.head, &frame),
                Err(AnswerError::Authority)
            );
            assert_eq!(
                answer(
                    wake,
                    KindCode::Plane,
                    Ticket::NONE,
                    Some(7),
                    &out.head,
                    &frame
                ),
                Err(AnswerError::Authority)
            );
            // No root-issued Caller incarnation can authorize an otherwise valid intent.
            assert_eq!(
                answer(wake, KindCode::Plane, ticket, Some(7), &out.head, &frame),
                Err(AnswerError::Authority)
            );
        }
    }
}
