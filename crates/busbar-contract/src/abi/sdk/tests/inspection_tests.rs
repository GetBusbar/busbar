// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use crate::abi::mechanism::call::{Blob, InHead, OutHead, BLOB_OCTETS, FLAG_RESUME};
use crate::abi::mechanism::inspection::*;
use crate::abi::sdk::life::Leases;
use crate::abi::sdk::{Lent, Out};

struct On(Ticket);
impl Parks for On {
    fn ticket(&self) -> Ticket {
        self.0
    }
    fn park(&self, _: Exchange) {
        panic!("inspection must not park over an exchange")
    }
    fn resume(&self) -> Option<Box<Exchange>> {
        panic!("inspection must not take an exchange")
    }
}
fn blank<T: super::super::door::AbiIn>() -> T {
    // SAFETY: AbiIn explicitly admits all-zero initialized bits.
    unsafe { std::mem::zeroed() }
}
fn output() -> OutHead {
    // SAFETY: the ABI head is plain integer and raw-pointer data.
    unsafe { std::mem::zeroed() }
}
fn input(ticket: Ticket, flags: u32, ext: &[u8]) -> InHead {
    InHead {
        ticket,
        flags,
        extensions: Blob {
            ptr: ext.as_ptr(),
            len: ext.len(),
            fmt: BLOB_OCTETS,
            flags: 0,
        },
        ..blank()
    }
}
fn bytes(blob: Blob) -> Vec<u8> {
    if blob.len == 0 {
        return Vec::new();
    }
    // SAFETY: these tests read SDK-leased output while its Leases owner remains alive.
    unsafe { std::slice::from_raw_parts(blob.ptr, blob.len) }.to_vec()
}
fn run(
    on: &On,
    input: &InHead,
    out: &mut OutHead,
    leases: &Leases,
    state: &mut Inspection,
    id: u64,
    query: &InspectionQuery,
) -> Poll<InspectionResult> {
    let op = Op { on, host: None };
    // SAFETY: the test's complete input and extension bytes live through this call.
    op.inspect(
        unsafe { Lent::new(input) },
        &mut Out::new(out),
        leases,
        state,
        id,
        query,
    )
}
fn query() -> InspectionQuery {
    InspectionQuery::Work {
        reference: b"work-ref".to_vec(),
    }
}
fn observed() -> InspectionObservation {
    InspectionObservation::Work(WorkObservation {
        observed_ms: 90,
        opened_ms: 1,
        retain_ms: 60,
        settled_ms: Some(30),
    })
}

#[test]
fn old_host_is_immediately_unsupported_and_never_leases_or_pends() {
    let on = On(Ticket {
        slot: 3,
        generation: 9,
    });
    let leases = Leases::default();
    let mut out = output();
    let mut state = Inspection::default();
    assert_eq!(
        run(
            &on,
            &input(on.0, 0, &[]),
            &mut out,
            &leases,
            &mut state,
            1,
            &query()
        ),
        Poll::Ready(Err(InspectionError::Unsupported))
    );
    assert_eq!(out.lease, 0);
    assert_eq!(out.extensions.len, 0);
    assert!(state.pending.is_none());
}

#[test]
fn ordinary_pending_resume_and_driver_tick_drive_return_copied_receipts() {
    for next_flags in [FLAG_RESUME, 0] {
        let on = On(Ticket {
            slot: 3,
            generation: 9,
        });
        let leases = Leases::default();
        let capability = append_capability(&[], 72).unwrap();
        let mut out = output();
        let mut state = Inspection::default();
        assert_eq!(
            run(
                &on,
                &input(on.0, 0, &capability),
                &mut out,
                &leases,
                &mut state,
                1,
                &query()
            ),
            Poll::Pending
        );
        let request = read_request(&bytes(out.extensions)).unwrap().unwrap();
        assert_eq!(request.epoch, 72);
        assert_eq!(request.ticket, on.0);
        let receipt = InspectionReceipt {
            request,
            result: Ok(observed()),
        };
        let mut incoming = append_receipt(&capability, &receipt).unwrap();
        let result = run(
            &on,
            &input(on.0, next_flags, &incoming),
            &mut output(),
            &leases,
            &mut state,
            1,
            &query(),
        );
        incoming.fill(0);
        assert_eq!(result, Poll::Ready(Ok(observed())));
        assert!(state.pending.is_none());
    }
}

#[test]
fn another_helper_preserves_first_request_and_unrelated_extensions() {
    let on = On(Ticket {
        slot: 3,
        generation: 9,
    });
    let leases = Leases::default();
    let capability = append_capability(&[], 72).unwrap();
    let frame = input(on.0, 0, &capability);
    let mut out = output();
    let original = crate::abi::mechanism::extensions::encode(&[("other", b"preserved")]);
    Out::new(&mut out).lease_secret(|o| &o.extensions, &leases, original.clone(), BLOB_OCTETS);
    let mut first = Inspection::default();
    let mut second = Inspection::default();
    assert_eq!(
        run(&on, &frame, &mut out, &leases, &mut first, 1, &query()),
        Poll::Pending
    );
    let held = bytes(out.extensions);
    let lease = out.lease;
    assert_eq!(
        out.extensions.flags,
        crate::abi::mechanism::call::BLOB_SECRET
    );
    let other = InspectionQuery::CarrierSessions {
        sessions: vec![7, 8],
    };
    assert_eq!(
        run(&on, &frame, &mut out, &leases, &mut second, 2, &other),
        Poll::Ready(Err(InspectionError::Busy))
    );
    assert_eq!(bytes(out.extensions), held);
    assert_eq!(out.lease, lease);
    assert!(held.starts_with(&original));
    assert!(second.pending.is_none());
}

#[test]
fn changed_query_ticket_epoch_and_missing_receipt_are_refused_without_false_ready() {
    for change in 0..4 {
        let on = On(Ticket {
            slot: 3,
            generation: 9,
        });
        let leases = Leases::default();
        let capability = append_capability(&[], 72).unwrap();
        let mut state = Inspection::default();
        let mut out = output();
        assert_eq!(
            run(
                &on,
                &input(on.0, 0, &capability),
                &mut out,
                &leases,
                &mut state,
                1,
                &query()
            ),
            Poll::Pending
        );
        let mut request = read_request(&bytes(out.extensions)).unwrap().unwrap();
        match change {
            0 => request.id = 2,
            1 => request.ticket.generation += 1,
            2 => request.epoch += 1,
            _ => {}
        }
        let ext = if change == 3 {
            capability.clone()
        } else {
            append_receipt(
                &capability,
                &InspectionReceipt {
                    request,
                    result: Ok(observed()),
                },
            )
            .unwrap()
        };
        let result = run(
            &on,
            &input(on.0, FLAG_RESUME, &ext),
            &mut output(),
            &leases,
            &mut state,
            1,
            &query(),
        );
        assert_eq!(
            result,
            Poll::Ready(Err(if change == 3 {
                InspectionError::MissingReceipt
            } else {
                InspectionError::Correlation
            }))
        );
    }
}

#[test]
fn first_inspection_during_unrelated_resume_can_start_and_ids_cannot_wrap() {
    let on = On(Ticket {
        slot: 3,
        generation: 9,
    });
    let leases = Leases::default();
    let cap = append_capability(&[], 72).unwrap();
    let mut state = Inspection::default();
    let mut out = output();
    assert_eq!(
        run(
            &on,
            &input(on.0, FLAG_RESUME, &cap),
            &mut out,
            &leases,
            &mut state,
            u64::MAX,
            &query()
        ),
        Poll::Pending
    );
    let request = read_request(&bytes(out.extensions)).unwrap().unwrap();
    let ext = append_receipt(
        &cap,
        &InspectionReceipt {
            request,
            result: Err(InspectionError::NotFound),
        },
    )
    .unwrap();
    assert_eq!(
        run(
            &on,
            &input(on.0, FLAG_RESUME, &ext),
            &mut output(),
            &leases,
            &mut state,
            u64::MAX,
            &query()
        ),
        Poll::Ready(Err(InspectionError::NotFound))
    );
    assert_eq!(
        run(
            &on,
            &input(on.0, FLAG_RESUME, &ext),
            &mut output(),
            &leases,
            &mut state,
            1,
            &query()
        ),
        Poll::Ready(Err(InspectionError::Invalid))
    );
}

#[test]
fn a_large_matching_receipt_is_consumed_before_budgeting_the_next_request() {
    let on = On(Ticket {
        slot: 3,
        generation: 9,
    });
    let leases = Leases::default();
    let cap = append_capability(&[], 72).unwrap();
    let query = InspectionQuery::Work {
        reference: vec![b'r'; MAX_BYTES / 2 + 256],
    };
    let mut state = Inspection::default();
    let mut out = output();
    assert_eq!(
        run(
            &on,
            &input(on.0, 0, &cap),
            &mut out,
            &leases,
            &mut state,
            1,
            &query
        ),
        Poll::Pending
    );
    let request = read_request(&bytes(out.extensions)).unwrap().unwrap();
    let receipt = InspectionReceipt {
        request,
        result: Ok(observed()),
    };
    let ext = append_receipt(&cap, &receipt).unwrap();
    assert_eq!(
        run(
            &on,
            &input(on.0, FLAG_RESUME, &ext),
            &mut output(),
            &leases,
            &mut state,
            1,
            &query
        ),
        Poll::Ready(Ok(observed()))
    );
    assert_eq!(
        run(
            &on,
            &input(on.0, FLAG_RESUME, &ext),
            &mut output(),
            &leases,
            &mut state,
            2,
            &query
        ),
        Poll::Pending
    );
}

#[test]
fn a_short_recall_replays_the_same_owned_receipt_without_reissuing_a_query() {
    let on = On(Ticket {
        slot: 3,
        generation: 9,
    });
    let leases = Leases::default();
    let cap = append_capability(&[], 72).unwrap();
    let mut state = Inspection::default();
    let mut out = output();
    assert_eq!(
        run(
            &on,
            &input(on.0, 0, &cap),
            &mut out,
            &leases,
            &mut state,
            1,
            &query()
        ),
        Poll::Pending
    );
    let request = read_request(&bytes(out.extensions)).unwrap().unwrap();
    let ext = append_receipt(
        &cap,
        &InspectionReceipt {
            request,
            result: Ok(observed()),
        },
    )
    .unwrap();
    assert_eq!(
        run(
            &on,
            &input(on.0, FLAG_RESUME, &ext),
            &mut output(),
            &leases,
            &mut state,
            1,
            &query()
        ),
        Poll::Ready(Ok(observed()))
    );
    let mut recalled = output();
    assert_eq!(
        run(
            &on,
            &input(on.0, 0, &cap),
            &mut recalled,
            &leases,
            &mut state,
            1,
            &query()
        ),
        Poll::Ready(Ok(observed()))
    );
    assert_eq!(recalled.lease, 0);
    assert_eq!(recalled.extensions.len, 0);
    assert_eq!(
        run(
            &on,
            &input(on.0, 0, &cap),
            &mut output(),
            &leases,
            &mut state,
            1,
            &InspectionQuery::Work {
                reference: b"changed".to_vec()
            }
        ),
        Poll::Ready(Err(InspectionError::Correlation))
    );
}
