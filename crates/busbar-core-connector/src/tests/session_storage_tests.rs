// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};

// `ProcessAdmission::used()` is (retained total, retained Data payload): Data storage counts in both
// (the kernel's meaning since d6069a4294 and 85e1aaad6c, pinned by its process_admission_tests).

// ---- the session's one output buffer ----

#[test]
fn output_allocates_nothing_until_its_first_byte_and_charges_its_whole_capacity_before_holding_it()
{
    let account = ProcessAdmission::with_limits(2, 1 << 20, 512);
    let source = account.connection_storage(AdmissionClass::Data);
    let mut out = Output::new(&source).expect("owner");
    assert!(out.allocation().is_none(), "no buffer before output");
    assert_eq!(account.used(), (0, 0));
    let empty = out.append(b"").expect("an empty WRITE");
    assert!(empty.is_empty() && out.allocation().is_none());
    let head = out.append(b"HTTP/1.1 200 OK\r\n").expect("head");
    assert_eq!(out.unwritten(head), b"HTTP/1.1 200 OK\r\n");
    let capacity = out.allocation().expect("made on first need").len();
    assert_eq!(capacity, OUTPUT_MIN, "the smallest block");
    assert_eq!(account.used().1, capacity, "the whole block is charged");
    // Within the capacity nothing is allocated or charged again.
    let (body, allocations) =
        crate::support::allocations_during(|| out.append(&[b'b'; 512]).expect("body"));
    assert_eq!(allocations, 0);
    assert_eq!(account.used().1, capacity);
    assert_eq!(out.unwritten(body), &[b'b'; 512]);
    drop(out);
    assert_eq!(account.used(), (0, 0));
}

#[test]
fn output_growth_keeps_every_span_and_is_charged_before_it_happens() {
    let account = ProcessAdmission::with_limits(2, 1 << 20, 512);
    let source = account.connection_storage(AdmissionClass::Data);
    let mut out = Output::new(&source).expect("owner");
    let first = out.append(&[1; 1000]).expect("first");
    let before = out.allocation().expect("block").as_ptr();
    let second = out.append(&[2; 3000]).expect("grows");
    assert_ne!(
        out.allocation().expect("block").as_ptr(),
        before,
        "a new block"
    );
    assert_eq!(out.unwritten(first), &[1; 1000], "offsets survive growth");
    assert_eq!(out.unwritten(second), &[2; 3000]);
    assert_eq!(account.used().1, out.allocation().expect("block").len());
}

#[test]
fn output_growth_refused_by_the_account_leaves_what_is_held_unchanged() {
    // 2,048 bytes of Data storage: the 1,024-byte first block fits, a 2,048-byte one beside it does not.
    let account = ProcessAdmission::with_limits(2, 4096, 2048);
    let source = account.connection_storage(AdmissionClass::Data);
    let mut out = Output::new(&source).expect("owner");
    let held = out.append(b"held").expect("first");
    let used = account.used();
    assert_eq!(out.append(&[9; 1500]), Err(StorageDenied));
    assert_eq!(out.unwritten(held), b"held");
    assert_eq!(account.used(), used, "no charge escaped the refusal");
    let next = out.append(b"+").expect("room remains");
    assert_eq!(out.unwritten(next), b"+");
}

#[test]
fn output_taken_one_byte_at_a_time_resumes_at_the_first_untaken_byte_and_wipes_what_was_taken() {
    let source = test_source();
    let mut out = Output::new(&source).expect("owner");
    let a = out.append(b"abc").expect("a");
    let b = out.append(b"defg").expect("b");
    let mut wire = Vec::new();
    for span in [a, b] {
        loop {
            let unwritten = out.unwritten(span);
            let Some(&byte) = unwritten.first() else {
                break;
            };
            wire.push(byte);
            out.take(1);
            let block = out.allocation().expect("block");
            assert!(
                block[..wire.len()].iter().all(|byte| *byte == 0),
                "taken bytes are wiped"
            );
        }
    }
    assert_eq!(wire, b"abcdefg");
    assert!(out.unwritten(a).is_empty() && out.unwritten(b).is_empty());
    out.clear();
    assert!(out
        .allocation()
        .expect("kept")
        .iter()
        .all(|byte| *byte == 0));
}

#[test]
fn output_that_takes_nothing_then_everything_writes_the_same_bytes_in_order() {
    let source = test_source();
    let mut out = Output::new(&source).expect("owner");
    let a = out.append(b"head|").expect("a");
    let b = out.append(b"body").expect("b");
    out.take(0);
    assert_eq!(
        out.unwritten(a),
        b"head|",
        "a write that took nothing changes nothing"
    );
    let mut wire = Vec::new();
    for span in [a, b] {
        wire.extend_from_slice(out.unwritten(span));
        out.take(span.len());
    }
    assert_eq!(wire, b"head|body");
    // After a clear, offsets start again from the front of the same block.
    let block = out.allocation().expect("block").as_ptr();
    out.clear();
    let c = out.append(b"next").expect("c");
    assert_eq!(out.unwritten(c), b"next");
    assert_eq!(out.allocation().expect("same block").as_ptr(), block);
}

#[test]
fn output_grown_past_the_kept_bound_is_released_when_it_empties() {
    let account = ProcessAdmission::with_limits(2, 1 << 20, 1 << 19);
    let source = account.connection_storage(AdmissionClass::Data);
    let mut out = Output::new(&source).expect("owner");
    let small = out.append(&[3; 4096]).expect("small");
    out.take(small.len());
    out.clear();
    assert!(
        out.allocation().is_some(),
        "a small block stays for the next answer"
    );
    let large = out.append(&vec![4; OUTPUT_KEPT + 1]).expect("large");
    assert!(out.allocation().expect("block").len() > OUTPUT_KEPT);
    out.take(large.len());
    out.clear();
    assert!(
        out.allocation().is_none(),
        "the large block is let go once empty"
    );
    assert_eq!(account.used(), (0, 0), "and its charge with it");
}

#[test]
fn output_dropped_with_unwritten_bytes_wipes_them_before_the_free_and_returns_the_charge() {
    let account = ProcessAdmission::with_limits(2, 1 << 20, 512);
    let source = account.connection_storage(AdmissionClass::Data);
    let mut out = Output::new(&source).expect("owner");
    let secret = out.append(b"authorization: bearer s3cr3t").expect("head");
    out.take(5);
    assert_eq!(out.unwritten(secret), b"rization: bearer s3cr3t");
    let block = out.allocation().expect("block");
    let (pointer, len) = (block.as_ptr(), block.len());
    let ((), wiped, _) = crate::support::observe_wipe(pointer, len, || drop(out));
    assert_eq!(wiped, Some(true), "the freed block was all zero");
    assert_eq!(account.used(), (0, 0));
}

#[test]
fn callback_arrays_and_payloads_keep_credit_when_moved_to_the_consumer() {
    let account = ProcessAdmission::with_limits(2, 4096, 512);
    let source = account.connection_storage(AdmissionClass::Data);
    let mut answer = Items::new(&source).expect("empty owner");
    answer
        .push(Payload::copy(&source, b"body").expect("payload"))
        .expect("array");
    let array_bytes = answer.capacity() * std::mem::size_of::<Payload>();
    assert_eq!(account.used().1, array_bytes + 4);
    let mut consumer = answer.into_iter();
    let body = consumer.next().expect("one action");
    assert_eq!(account.used().1, array_bytes + 4);
    drop(consumer);
    assert_eq!(
        account.used().1,
        4,
        "payload owns its independent retained backing"
    );
    drop(body);
    assert_eq!(account.used(), (0, 0));
}

#[test]
fn denied_replacement_retains_original_payload_and_releases_no_live_credit() {
    let account = ProcessAdmission::with_limits(2, 32, 4);
    let source = account.connection_storage(AdmissionClass::Data);
    let mut payload = Payload::copy(&source, &[7; 16]).expect("original");
    assert!(
        payload.append(&[8; 8]).is_err(),
        "old plus replacement exceed data capacity"
    );
    assert_eq!(payload.as_slice(), &[7; 16]);
    assert_eq!(account.used(), (16, 16));
    assert!(Payload::copy(&source, &[9; 13]).is_err());
    assert_eq!(account.used(), (16, 16));
    drop(payload);
    assert_eq!(account.used(), (0, 0));
}

#[test]
fn upgrade_name_and_leftover_remain_funded_after_callback_returns() {
    let account = ProcessAdmission::with_limits(2, 4096, 512);
    let source = account.connection_storage(AdmissionClass::Data);
    let name = Name::copy(&source, "websocket").expect("name");
    let bytes = Payload::copy(&source, b"leftover").expect("leftover");
    assert_eq!(&*name, "websocket");
    assert_eq!(account.used(), (17, 17));
    drop(source);
    drop(name);
    assert_eq!(account.used(), (8, 8));
    drop(bytes);
    assert_eq!(account.used(), (0, 0));
}
