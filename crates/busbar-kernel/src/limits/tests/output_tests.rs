// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::limits::output::{CaptureScope, OutputBuffer, OutputError};
use crate::limits::process_admission::{AdmissionClass, ProcessAdmission};
use std::io::Write;

#[test]
fn retained_output_uses_the_same_operator_floor_as_input() {
    let process = ProcessAdmission::with_limits(4, 4096, 1024);
    let data = process.try_enter(AdmissionClass::Data).unwrap();
    let operator = process.try_enter(AdmissionClass::Operator).unwrap();
    let input = data.try_reserve(3072).unwrap();
    assert!(OutputBuffer::with_capacity(&data, 1).is_err());
    let output = OutputBuffer::with_capacity(&operator, 1024).unwrap();
    assert_eq!(process.used(), (4096, 3072));
    assert!(operator.try_reserve(1).is_err());
    drop(output);
    assert_eq!(process.used(), (3072, 3072));
    drop(input);
    assert_eq!(process.used(), (0, 0));
}

#[test]
fn nonempty_body_alias_keeps_capacity_and_request_count() {
    let process = ProcessAdmission::with_limits(2, 4096, 1024);
    let request = process.try_enter(AdmissionClass::Data).unwrap();
    let mut output = OutputBuffer::with_capacity(&request, 128).unwrap();
    output.write_all(b"retained").unwrap();
    let body = output.into_bytes().unwrap();
    let alias = body.slice(1..3);
    drop(request);
    drop(body);
    assert_eq!(&alias[..], b"et");
    assert_eq!(process.used(), (128, 128));
    assert!(process.try_enter(AdmissionClass::Data).is_err());
    drop(alias);
    assert_eq!(process.used(), (0, 0));
    assert!(process.try_enter(AdmissionClass::Data).is_ok());
}

#[test]
fn explicit_growth_reserves_old_and_new_backing_before_copy() {
    let process = ProcessAdmission::with_limits(0, 300, 0);
    let request = process.try_enter(AdmissionClass::Data).unwrap();
    let mut output = OutputBuffer::with_capacity(&request, 128).unwrap();
    output.write_all(&[9; 128]).unwrap();
    // New geometric capacity is 256; the old 128 is still live during allocation/copy.
    assert!(output.write_all(&[1]).is_err());
    assert_eq!(output.as_ref(), &[9; 128]);
    assert_eq!(process.used(), (128, 128));
    assert_eq!(output.failure(), Some(OutputError::Capacity));
    assert!(output.into_bytes().is_err());
    assert_eq!(process.used(), (0, 0));
}

#[test]
fn successful_growth_retires_old_capacity_only_after_copy() {
    let process = ProcessAdmission::with_limits(0, 4096, 0);
    let request = process.try_enter(AdmissionClass::Data).unwrap();
    let mut output = OutputBuffer::with_capacity(&request, 128).unwrap();
    output.write_all(&[3; 129]).unwrap();
    assert_eq!(output.as_ref(), &[3; 129]);
    assert_eq!(process.used(), (256, 256));
    drop(output);
    assert_eq!(process.used(), (0, 0));
}

#[test]
fn capture_result_and_next_capture_have_independent_custody() {
    let process = ProcessAdmission::with_limits(0, 20, 0);
    let request = process.try_enter(AdmissionClass::Data).unwrap();
    let mut first = CaptureScope::new(&request).unwrap();
    let value = first.copy_str("a retained result").unwrap();
    let captured = first.finish(value);
    let mut second = CaptureScope::new(&request).unwrap();
    assert_eq!(second.copy_str("another"), Err(OutputError::Capacity));
    assert_eq!(captured.value(), "a retained result");
    assert_eq!(process.used(), (17, 17));
    drop(captured);
    assert_eq!(second.copy_str("another").unwrap(), "another");
    drop(second);
    assert_eq!(process.used(), (0, 0));
}

#[test]
fn capture_storage_destructs_before_credit_retires() {
    struct Probe(std::sync::Arc<ProcessAdmission>);
    impl Drop for Probe {
        fn drop(&mut self) {
            assert_eq!(self.0.used(), (42, 42));
        }
    }
    let process = ProcessAdmission::with_limits(0, 128, 0);
    let request = process.try_enter(AdmissionClass::Data).unwrap();
    let mut scope = CaptureScope::new(&request).unwrap();
    scope.reserve_requested(42).unwrap();
    let captured = scope.finish(Probe(process.clone()));
    drop(captured);
    assert_eq!(process.used(), (0, 0));
}

#[test]
fn overflow_does_not_allocate_or_change_accounting() {
    let process = ProcessAdmission::with_limits(0, 4096, 0);
    let request = process.try_enter(AdmissionClass::Data).unwrap();
    let mut scope = CaptureScope::new(&request).unwrap();
    assert_eq!(
        scope.reserve_requested(usize::MAX),
        Err(OutputError::Capacity)
    );
    assert!(scope.vector::<u64>(usize::MAX).is_err());
    assert_eq!(process.used(), (0, 0));
}

#[tokio::test]
async fn cancelling_capture_future_drops_retained_projection() {
    let process = ProcessAdmission::with_limits(2, 4096, 1024);
    let request = process.try_enter(AdmissionClass::Data).unwrap();
    let mut scope = CaptureScope::new(&request).unwrap();
    let text = scope.copy_str("owned projection").unwrap();
    let captured = scope.finish(text);
    let task = tokio::spawn(async move {
        std::future::pending::<()>().await;
        drop(captured);
    });
    drop(request);
    assert_eq!(process.used(), (16, 16));
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(process.used(), (0, 0));
    assert!(process.try_enter(AdmissionClass::Data).is_ok());
}

#[cfg(not(target_env = "msvc"))]
#[test]
fn real_json_facade_escape_scratch_fits_the_preflight_credit() {
    #[derive(serde::Serialize)]
    struct Document<'a> {
        text: &'a str,
    }
    let text = "\\\"\n".repeat(4096);
    let scratch = 6 * (6 * text.len() + 35) + 4096;
    let process = ProcessAdmission::with_limits(0, 2 * 1024 * 1024, 0);
    let request = process.try_enter(AdmissionClass::Operator).unwrap();
    let mut scope = CaptureScope::new(&request).unwrap();
    scope.reserve_requested(scratch).unwrap();
    let mut body = OutputBuffer::with_capacity(&request, 6 * text.len() + 64).unwrap();
    crate::ThreadAllocated::reset();
    busbar_contract::json::to_writer(&mut body, &Document { text: &text }).unwrap();
    let allocated = crate::ThreadAllocated::bytes();
    assert!(
        allocated > 0,
        "the real facade owns an escape buffer before forwarding"
    );
    assert!(allocated <= u64::try_from(scratch).unwrap());
    let encoded = body.into_bytes().unwrap();
    assert!(encoded.len() > text.len());
    drop(scope);
    assert!(
        process.used().0 > 0,
        "the body has independent backing credit"
    );
    drop(encoded);
    assert_eq!(process.used(), (0, 0));
}
