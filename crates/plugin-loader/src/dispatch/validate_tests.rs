// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::call::{Blob, RawOutcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::check::HARD_MAX_BYTES;
use busbar_contract::abi::mechanism::ticket::Ticket;

fn head(outcome: Outcome, extensions: Blob) -> OutHead {
    OutHead {
        size: size_of::<OutHead>() as u32,
        outcome: RawOutcome::of(outcome),
        _reserved: [0; 3],
        wake_at_ns: 0,
        lease: 0,
        error: AbiStr::ZERO,
        envelope: Envelope::ZERO,
        extensions,
    }
}

#[test]
fn every_outcome_refuses_oversized_extensions_before_any_pointer_read() {
    for outcome in [
        Outcome::Ready,
        Outcome::Pending,
        Outcome::Failed,
        Outcome::Refused,
    ] {
        // This pointer has no readable payload. The pure head checks must reject the length
        // before any generic extension consumer can form a slice or search for a known key.
        let head = head(
            outcome,
            Blob {
                ptr: std::ptr::NonNull::<u8>::dangling().as_ptr(),
                len: HARD_MAX_BYTES as usize + 1,
                fmt: BLOB_OCTETS,
                flags: 0,
            },
        );
        assert!(out_head(&head, head.size).is_err(), "{outcome:?}");
        assert_eq!(
            super::super::plugin::judge(
                head.outcome,
                &head,
                Ticket {
                    slot: 1,
                    generation: 1
                },
                head.size
            ),
            Outcome::Fault,
            "{outcome:?}",
        );
    }
}

#[test]
fn a_nonempty_extension_requires_a_pointer_before_any_consumer_runs() {
    let head = head(
        Outcome::Ready,
        Blob {
            ptr: std::ptr::null(),
            len: 1,
            fmt: BLOB_OCTETS,
            flags: 0,
        },
    );
    assert!(out_head(&head, head.size).is_err());
}

#[test]
fn empty_and_exactly_maximum_extensions_remain_valid_heads() {
    let bytes = vec![0; HARD_MAX_BYTES as usize];
    for extensions in [
        Blob::ZERO,
        Blob {
            ptr: bytes.as_ptr(),
            len: bytes.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        },
    ] {
        let head = head(Outcome::Ready, extensions);
        assert_eq!(out_head(&head, head.size), Ok(()));
    }
}
