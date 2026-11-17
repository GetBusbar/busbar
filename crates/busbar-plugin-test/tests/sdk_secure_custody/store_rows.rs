// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Q24 observation of the shared row helper, using the existing target's allocator and safe scanner.

use super::{payload, SecureVec, WipeProof};
use busbar_plugin_abi::kinds::store::plumbing::{write_row, RowErr};
use busbar_plugin_abi::records::{Full, Nested, Pod, Writer};

#[derive(Clone, Copy)]
enum Outcome {
    Success,
    Full,
    Panic,
}

/// Observe the borrowed tail without making another payload copy or retaining a response buffer.
struct RowObserver(Outcome);
impl Writer for RowObserver {
    fn put_parts(&mut self, _: u16, _: &[&[u8]]) -> Result<(), Full> {
        unreachable!()
    }
    fn put_pod_nested<T: Pod>(
        &mut self,
        _: u16,
        _: &T,
        _: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        unreachable!()
    }
    fn put_u32s(
        &mut self,
        _: u16,
        _: impl FnOnce(&mut busbar_plugin_abi::records::U32s<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        unreachable!()
    }
    fn put(&mut self, _: u16, _: &[u8]) -> Result<(), Full> {
        unreachable!()
    }
    fn put_u32s(
        &mut self,
        _: u16,
        _: impl FnOnce(&mut busbar_plugin_abi::records::U32s<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        unreachable!()
    }
    fn put_pod<T: Pod>(&mut self, _: u16, _: &T) -> Result<(), Full> {
        unreachable!()
    }
    fn put_pod_tail<T: Pod>(&mut self, _: u16, _: &T, tail: &[u8]) -> Result<(), Full> {
        std::hint::black_box(tail);
        match self.0 {
            Outcome::Success => Ok(()),
            Outcome::Full => Err(Full),
            Outcome::Panic => panic!("row writer interrupted after observing its borrowed tail"),
        }
    }
    fn put_text(&mut self, _: u16, _: &str) -> Result<(), Full> {
        unreachable!()
    }
    fn put_pair(&mut self, _: u16, _: &str, _: &[u8]) -> Result<(), Full> {
        unreachable!()
    }
    fn put_fact(&mut self, _: u32, _: u64) -> Result<(), Full> {
        unreachable!()
    }
    fn put_fact_text(&mut self, _: u32, _: &str) -> Result<(), Full> {
        unreachable!()
    }
    fn put_metric(&mut self, _: u32, _: u32, _: f64, _: &[&str]) -> Result<(), Full> {
        unreachable!()
    }
    fn put_nested(
        &mut self,
        _: u16,
        _: impl FnOnce(&mut Nested<'_>) -> Result<(), Full>,
    ) -> Result<(), Full> {
        unreachable!()
    }
}

#[test]
fn store_row_reusable_scratch_wipes_keys_and_values_on_every_exit() {
    for outcome in [Outcome::Success, Outcome::Full, Outcome::Panic] {
        for in_key in [false, true] {
            let proof = WipeProof::new();
            let input = payload(&proof);
            let mut scratch = SecureVec::new();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let (key, value) = if in_key {
                    (input.as_slice(), b"".as_slice())
                } else {
                    (b"key".as_slice(), input.as_slice())
                };
                write_row(&mut RowObserver(outcome), &mut scratch, key, value)
            }));
            match outcome {
                Outcome::Success => assert!(matches!(result, Ok(Ok(())))),
                Outcome::Full => assert!(matches!(result, Ok(Err(RowErr::Full(_))))),
                Outcome::Panic => assert!(result.is_err()),
            }
            drop(input);
            // Keep the allocation alive across the scan: a later SecureVec drop must not mask missing
            // row-exit cleanup. Each scan checks its live sentinel and freed-unwiped positive control.
            proof.assert_absent("Store row scratch after success, Full or caught panic");
            assert!(scratch.is_empty());
            std::hint::black_box(&scratch);
            write_row(
                &mut RowObserver(Outcome::Success),
                &mut scratch,
                b"next",
                b"row",
            )
            .unwrap();
            assert!(scratch.is_empty());
        }
    }
}

#[test]
fn store_row_dirty_input_is_wiped_before_replacement_frees_its_allocation() {
    let proof = WipeProof::new();
    let mut scratch = payload(&proof);
    write_row(
        &mut RowObserver(Outcome::Success),
        &mut scratch,
        b"key",
        &[0; 4096],
    )
    .unwrap();
    proof.assert_absent("Store row dirty scratch before exact-sized replacement");
    assert!(scratch.is_empty());
    std::hint::black_box(&scratch);
}

#[test]
fn store_row_operation_unwind_wipes_the_abandoned_input_and_scratch() {
    let proof = WipeProof::new();
    let interrupted = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let input = payload(&proof);
        let mut scratch = SecureVec::new();
        let _ = write_row(
            &mut RowObserver(Outcome::Panic),
            &mut scratch,
            b"key",
            &input,
        );
    }));
    assert!(interrupted.is_err());
    proof.assert_absent("Store row operation unwind");
}
