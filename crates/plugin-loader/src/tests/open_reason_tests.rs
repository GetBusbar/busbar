// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::cell::RefCell;
use std::sync::OnceLock;

use busbar_contract::abi::mechanism::call::{Blob, OutHead, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::lifecycle::{slot, OpenIn, OpenOut, ValidateIn};
use busbar_contract::abi::sdk::capture::{CaptureHome, CaptureRetention, CaptureSlot};
use busbar_contract::abi::sdk::door::{blank_in, blank_out, kind_op, Lifecycle};
use busbar_contract::abi::sdk::life::{self, Life, Refusal};
use busbar_contract::abi::sdk::Safe;

use super::{Called, OPEN_REASON_CAP};

// Individual SDK callbacks need capture storage even when their bodies emit no diagnostics.
// This supplies that storage without building a plugin door, kind table or registry.
struct CallbackCapture;
impl CaptureHome for CallbackCapture {
    fn with<R>(f: impl FnOnce(&mut CaptureSlot) -> R) -> R {
        thread_local! {
            static SLOT: RefCell<CaptureSlot> = RefCell::new(CaptureSlot::new());
        }
        SLOT.with(|slot| f(&mut slot.borrow_mut()))
    }
    fn retention() -> &'static CaptureRetention {
        static RETENTION: OnceLock<CaptureRetention> = OnceLock::new();
        RETENTION.get_or_init(CaptureRetention::default)
    }
}

// Failure text is test input. Neither callback can create a successful instance or operate a
// product; their owned Strings must be copied into the caller's reason loans before returning.
struct FailureOnly;
impl Life for FailureOnly {
    const CANCEL: u32 = 0;

    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        Err(Refusal::failed(format!(
            "invalid: {}",
            String::from_utf8_lossy(settings)
        )))
    }
    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Err(Refusal::failed(
            String::from_utf8_lossy(settings).into_owned(),
        ))
    }
}

fn called(outcome: Outcome, error: Option<Vec<u8>>) -> Called {
    Called {
        outcome,
        error,
        lease: 0,
        recall: None,
    }
}

fn octets(bytes: &[u8]) -> Blob {
    Blob {
        ptr: bytes.as_ptr(),
        len: bytes.len(),
        fmt: BLOB_OCTETS,
        flags: 0,
    }
}

fn failed_open(reason: &[u8], buffer: &mut [u8]) -> (Outcome, OpenOut) {
    let mut input: OpenIn = blank_in();
    input.head.op = slot::OPEN;
    input.settings = octets(reason);
    input.err_buf = buffer.as_mut_ptr();
    input.err_cap = buffer.len();
    let mut out: OpenOut = blank_out();
    let callback =
        kind_op::<Lifecycle, Safe<life::Open<FailureOnly>>, CallbackCapture, { slot::OPEN }>()
            .expect("the SDK provides this lifecycle callback");
    // SAFETY: this is the SDK OPEN callback for these exact initialized ABI frames. NULL is
    // the initial instance; reason and the exclusive nonoverlapping output loan remain live
    // through the complete call. FailureOnly always fails, so no instance can escape it.
    let outcome = unsafe {
        callback(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut out).cast(),
        )
    }
    .outcome();
    (outcome, out)
}

// The compatibility label is a formatter input. Fictional Store behavior and linked/dropped
// settings-echo parity are retired; these tests make no public-loader admission claim.
#[test]
fn a_store_whose_open_fails_reads_as_1_5_5_did() {
    assert_eq!(
        called(Outcome::Failed, Some(b"boom: x".to_vec())).open_failure("open-reason-store"),
        "plugin 'open-reason-store' open failed: boom: x"
    );
}

#[test]
fn an_over_long_reason_is_cut_on_a_char_boundary() {
    assert_eq!(OPEN_REASON_CAP % 2, 0, "the input assumes an even capacity");
    let long = format!("a{}", "é".repeat(OPEN_REASON_CAP));
    let kept = format!("a{}", "é".repeat((OPEN_REASON_CAP - 2) / 2));
    assert_eq!(kept.len(), OPEN_REASON_CAP - 1);
    let mut buffer = vec![0xa5; OPEN_REASON_CAP + 1];
    let (outcome, out) = failed_open(long.as_bytes(), &mut buffer[..OPEN_REASON_CAP]);
    assert_eq!(outcome, Outcome::Failed);
    assert_eq!(out.head.outcome.outcome(), Outcome::Failed);
    assert!(out.instance.is_null());
    assert_eq!(out.err_len, kept.len());
    assert_eq!(out.head.error.ptr, buffer.as_ptr());
    assert_eq!(out.head.error.len, out.err_len);
    assert_eq!(out.head.lease, 0);
    assert!(buffer[out.err_len..].iter().all(|b| *b == 0xa5));
    let text =
        called(outcome, Some(buffer[..out.err_len].to_vec())).open_failure("open-reason-store");
    let reason = text
        .split_once(" open failed: ")
        .map(|(_, r)| r)
        .expect("the 1.5.5 shape");
    assert!(!reason.contains('\u{FFFD}'), "cut inside a char: {reason}");
    assert_eq!(reason, kept);
}

#[test]
fn a_plugin_that_writes_no_reason_reads_as_a_stable_text() {
    for error in [None, Some(Vec::new())] {
        assert_eq!(
            called(Outcome::Failed, error).open_failure("open-reason-store"),
            "plugin 'open-reason-store' open failed: status 1"
        );
    }
    assert_eq!(
        called(Outcome::Fault, None).open_failure("open-reason-store"),
        "plugin 'open-reason-store' open failed: status 3"
    );
    assert_eq!(
        called(Outcome::Fault, Some(b"boom: x".to_vec())).open_failure("open-reason-store"),
        "plugin 'open-reason-store' open failed: boom: x"
    );
}

#[test]
fn an_sdk_validate_and_open_say_their_own_owned_words_through_the_lent_buffers() {
    let mut validation = [0xa5; 65];
    let mut input: ValidateIn = blank_in();
    input.head.op = slot::VALIDATE;
    input.settings = octets(b"no port");
    input.err_buf = validation.as_mut_ptr();
    input.err_cap = validation.len() - 1;
    let mut out: OutHead = blank_out();
    let callback = kind_op::<
        Lifecycle,
        Safe<life::Validate<FailureOnly>>,
        CallbackCapture,
        { slot::VALIDATE },
    >()
    .expect("the SDK provides this lifecycle callback");
    // SAFETY: this is the SDK VALIDATE callback for these exact initialized ABI frames; its
    // initial instance is NULL, and the settings and exclusive output reason loan remain live
    // and nonoverlapping for the call. The owned failure String dies inside this callback.
    let outcome = unsafe {
        callback(
            std::ptr::null_mut(),
            std::ptr::from_ref(&input).cast(),
            std::ptr::from_mut(&mut out).cast(),
        )
    }
    .outcome();
    assert_eq!(outcome, Outcome::Failed);
    assert_eq!(out.outcome.outcome(), Outcome::Failed);
    assert_eq!(out.error.ptr, validation.as_ptr());
    assert_eq!(out.error.len, b"invalid: no port".len());
    assert_eq!(&validation[..out.error.len], b"invalid: no port");
    assert!(validation[out.error.len..].iter().all(|b| *b == 0xa5));
    assert_eq!(out.lease, 0);
    let validated = called(outcome, Some(validation[..out.error.len].to_vec()));
    validation.fill(0);
    assert_eq!(validated.error.as_deref(), Some(&b"invalid: no port"[..]));

    let mut opening = [0xa5; 65];
    let (outcome, out) = failed_open(b"boom: x", &mut opening[..64]);
    assert_eq!(outcome, Outcome::Failed);
    assert_eq!(out.head.outcome.outcome(), Outcome::Failed);
    assert!(out.instance.is_null());
    assert_eq!(out.head.error.ptr, opening.as_ptr());
    assert_eq!(out.err_len, b"boom: x".len());
    assert_eq!(out.head.error.len, out.err_len);
    assert_eq!(&opening[..out.err_len], b"boom: x");
    assert!(opening[out.err_len..].iter().all(|b| *b == 0xa5));
    assert_eq!(out.head.lease, 0);
    let opened = called(outcome, Some(opening[..out.err_len].to_vec()));
    opening.fill(0);
    assert_eq!(
        opened.open_failure("open-reason-life"),
        "plugin 'open-reason-life' open failed: boom: x"
    );
}
