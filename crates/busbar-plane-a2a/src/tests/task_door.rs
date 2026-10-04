// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's half of the task verbs: the once-a-second sweep claim and the record kind indices.

use super::*;

/// The first caller of each second runs the sweep, and no other caller of that second does.
#[test]
fn the_sweep_runs_once_a_second() {
    let swept = Keyed::new();
    assert!(claim_sweep(&swept, 10));
    assert!(!claim_sweep(&swept, 10));
    assert!(!claim_sweep(&swept, 9), "time read late never sweeps again");
    assert!(claim_sweep(&swept, 11));
}

/// A record write names its kind by its index in the tail's record kinds.
#[test]
fn a_write_names_its_kind_by_the_tails_index() {
    use crate::records::{KIND_PUSH_CONFIG, KIND_TASK, KIND_TASK_EVENT};
    assert_eq!(
        [KIND_TASK, KIND_TASK_EVENT, KIND_PUSH_CONFIG].map(kind_index),
        [0, 1, 2]
    );
    assert_eq!(
        kind_index("pin"),
        u32::MAX,
        "a kind the tail does not state"
    );
}

// ── the host records, through the SDK wrappers ───────────────────────────────────────────────────

use busbar_contract::abi::host::service::HostSlots;
use busbar_contract::abi::mechanism::ticket::{HostCtx, HostTables};

/// Tables naming a services table this file never calls through: [`Via::issue`] hands the
/// crossing to the closure the test writes, so the table is only ever stored.
fn tables() -> HostTables {
    HostTables {
        size: std::mem::size_of::<HostTables>() as u32,
        _reserved: 0,
        ctx: HostCtx {
            ptr: std::ptr::null_mut(),
        },
        wake: None,
        conns: std::ptr::null(),
        services: std::ptr::NonNull::<HostSlots>::dangling().as_ptr(),
    }
}

const TICKET: Ticket = Ticket {
    slot: 3,
    generation: 7,
};

/// The size a long record needs: past the first read's room.
const LONG: u64 = RECORD_BYTES as u64 + 1;

/// A host that holds one long record: a buffer short of it is answered short at its size, one that
/// holds it is answered with it. Every issue is logged as `(handle sequence, bytes offered)`.
fn long_record(
    log: &mut Vec<(u32, usize)>,
    handle: CompletionHandle,
    buf: &[u8],
) -> Poll<Result<usize, ServiceError>> {
    log.push((handle.seq, buf.len()));
    if (buf.len() as u64) < LONG {
        Poll::Ready(Err(ServiceError::Short {
            bytes: LONG,
            items: 1,
        }))
    } else {
        Poll::Ready(Ok(buf.len()))
    }
}

/// A short answer is re-called ONCE, on the same handle, at the size it named.
#[test]
fn a_short_records_answer_is_re_called_once_on_its_handle_at_the_named_size() {
    let t = tables();
    let host = Host::of(&t);
    let grown = Keyed::new();
    let mut via = Via::new(&host, Services::of(&t), TICKET, 0, &grown);
    let mut log = Vec::new();
    let got = via.issue((RECORD_BYTES, 1), |_, h, buf, _| {
        long_record(&mut log, h, buf)
    });
    assert!(matches!(got, Ok(n) if n as u64 == LONG));
    assert_eq!(log, vec![(0, RECORD_BYTES), (0, LONG as usize)]);
    assert_eq!(via.issued(), 1, "one handle, issued twice");
}

/// A piece that answers PENDING runs again from the top: the handle a short answer already sized is
/// re-issued at that size, so the host never answers it short a second time (that is FAULT).
#[test]
fn a_piece_run_again_issues_a_short_handle_at_the_size_already_named() {
    let t = tables();
    let host = Host::of(&t);
    let grown = Keyed::new();
    let mut log = Vec::new();
    // First entry: the long read is sized, then the next call pends.
    {
        let mut via = Via::new(&host, Services::of(&t), TICKET, 0, &grown);
        assert!(via
            .issue((RECORD_BYTES, 1), |_, h, buf, _| long_record(
                &mut log, h, buf
            ))
            .is_ok());
        let pends: Result<(), Halt> = via.issue((RECORD_BYTES, 1), |_, h, buf, _| {
            log.push((h.seq, buf.len()));
            Poll::Pending
        });
        assert!(matches!(pends, Err(Halt::Pending)));
    }
    log.clear();
    // The same piece again, from the same count: the sized handle goes out at its size at once.
    let mut via = Via::new(&host, Services::of(&t), TICKET, 0, &grown);
    assert!(via
        .issue((RECORD_BYTES, 1), |_, h, buf, _| long_record(
            &mut log, h, buf
        ))
        .is_ok());
    assert_eq!(log, vec![(0, LONG as usize)]);
}

/// A host that names a size and then answers short at it broke its own rule.
#[test]
fn a_second_short_answer_on_one_handle_is_a_broken_host() {
    let t = tables();
    let host = Host::of(&t);
    let grown = Keyed::new();
    let mut via = Via::new(&host, Services::of(&t), TICKET, 0, &grown);
    let got: Result<(), Halt> = via.issue((RECORD_BYTES, 1), |_, _, _, _| {
        Poll::Ready(Err(ServiceError::Short {
            bytes: LONG,
            items: 1,
        }))
    });
    assert!(matches!(got, Err(Halt::Failed(w)) if w == "Broken"));
}

/// No host services: every records call fails, and nothing is crossed.
#[test]
fn a_door_opened_with_no_services_reads_no_record() {
    let t = tables();
    let host = Host::of(&t);
    let grown = Keyed::new();
    let mut via = Via::new(&host, None, TICKET, 0, &grown);
    assert!(matches!(via.get("task", "k"), Err(Halt::Failed(w)) if w == "Unserved"));
    assert!(matches!(via.list("task", ""), Err(Halt::Failed(w)) if w == "Unserved"));
    assert!(matches!(via.claim("task", "k", 1), Err(Halt::Failed(w)) if w == "Unserved"));
}

/// The sizes book is bounded: at its cap it is cleared before the next entry.
#[test]
fn the_sizes_book_is_bounded() {
    let t = tables();
    let host = Host::of(&t);
    let grown = Keyed::new();
    let via = Via::new(&host, Services::of(&t), TICKET, 0, &grown);
    for seq in 0..GROWN_MAX as u32 {
        via.grow(
            CompletionHandle {
                ticket: TICKET,
                seq,
                _reserved: 0,
            },
            1,
            1,
        );
    }
    assert_eq!(grown.len(), GROWN_MAX);
    via.grow(
        CompletionHandle {
            ticket: TICKET,
            seq: u32::MAX,
            _reserved: 0,
        },
        1,
        1,
    );
    assert_eq!(grown.len(), 1);
}
