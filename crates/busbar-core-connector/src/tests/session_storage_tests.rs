// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_kernel::limits::process_admission::{AdmissionClass, ProcessAdmission};

// `ProcessAdmission::used()` is (retained total, retained Data payload): Data storage counts in both
// (the kernel's meaning since d6069a4294 and 85e1aaad6c, pinned by its process_admission_tests).

#[test]
fn consumed_payload_keeps_full_backing_charge_until_final_drop() {
    let account = ProcessAdmission::with_limits(2, 4096, 512);
    let source = account.connection_storage(AdmissionClass::Data);
    let mut payload = Payload::copy(&source, b"sensitive payload").expect("capacity");
    assert_eq!(account.used(), (17, 17));
    payload.consume(10);
    assert_eq!(payload.as_slice(), b"payload");
    assert_eq!(
        account.used(),
        (17, 17),
        "logical consumption is not backing retirement"
    );
    assert!(!format!("{payload:?}").contains("payload"));
    drop(payload);
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
