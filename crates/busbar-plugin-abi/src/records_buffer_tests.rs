// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn fixed_writer_never_grows_and_rolls_back_failed_nested_records() {
    let mut bytes = [0u8; 48];
    let mut fixed = Fixed::new(&mut bytes);
    fixed.put_text(tag::TEXT, "kept").unwrap();
    assert_eq!(fixed.len(), record_size(4).unwrap());
    let before = fixed.len();
    assert!(
        fixed
            .put_nested(tag::TEXT, |nested| {
                nested.put_text(tag::TEXT, "inside")?;
                nested.put_text(tag::TEXT, "cannot fit")
            })
            .is_err()
    );
    assert_eq!(fixed.len(), before);
    assert_eq!(
        Records::new(fixed.as_bytes())
            .next()
            .unwrap()
            .unwrap()
            .text()
            .unwrap(),
        "kept"
    );
    assert!(fixed.bytes[before..].iter().all(|byte| *byte == 0));
    assert!(fixed.put_text(tag::TEXT, &"x".repeat(48)).is_err());
    assert_eq!(fixed.capacity(), 48);
    assert_eq!(fixed.len(), before);
}

#[test]
fn fixed_record_quote_checks_overflow_and_exact_padding() {
    assert_eq!(record_size(0), Some(8));
    assert_eq!(record_size(4), Some(16));
    assert_eq!(record_size(8), Some(16));
    assert_eq!(record_size(usize::MAX), None);
    let mut bytes = [0; 16];
    let mut fixed = Fixed::new(&mut bytes);
    fixed
        .put_pod(tag::H_STATUS, &U32Rec { value: 200, _r: 0 })
        .unwrap();
    assert_eq!(fixed.len(), 16);
    assert!(fixed.put_text(tag::TEXT, "").is_err());
}

struct Sink {
    bytes: [u8; 64],
    len: usize,
    cap: usize,
}

impl Sink {
    fn new(cap: usize) -> Self {
        let mut bytes = [0; 64];
        bytes[..8].copy_from_slice(b"retained");
        Self { bytes, len: 8, cap }
    }

    fn rolled_back(&self) {
        assert_eq!(self.len, 8);
        assert_eq!(&self.bytes[..8], b"retained");
        assert!(self.bytes[8..].iter().all(|&byte| byte == 0));
    }
}

impl RawWrite for Sink {
    fn written(&self) -> usize {
        self.len
    }
    fn room(&mut self, need: usize) -> Result<(), Full> {
        self.len
            .checked_add(need)
            .filter(|&end| end <= self.cap)
            .map(|_| ())
            .ok_or(Full)
    }
    fn append(&mut self, bytes: &[u8]) {
        let end = self.len + bytes.len();
        self.bytes[self.len..end].copy_from_slice(bytes);
        self.len = end;
    }
    fn patch(&mut self, at: usize, bytes: &[u8]) {
        self.bytes[at..at + bytes.len()].copy_from_slice(bytes);
    }
    fn truncate(&mut self, len: usize) {
        self.bytes[len..self.len].zeroize();
        self.len = len;
    }
}

#[test]
fn flat_word_failure_restores_prefix_at_header_body_and_padding() {
    for cap in [8, 16, 20] {
        let mut sink = Sink::new(cap);
        assert!(put_u32s_in(&mut sink, 0x101, |words| words.push(u32::MAX)).is_err());
        sink.rolled_back();
    }
    let mut sink = Sink::new(24);
    assert!(put_u32s_in(&mut sink, 0x101, |words| words.push(u32::MAX)).is_ok());
    assert_eq!(sink.len, 24);
    assert_eq!(&sink.bytes[16..20], &[255; 4]);
    assert_eq!(&sink.bytes[20..24], &[0; 4]);
}

#[test]
fn swallowed_push_error_poison_cannot_publish_a_short_order() {
    let mut sink = Sink::new(20);
    assert!(
        put_u32s_in(&mut sink, 0x101, |words| {
            words.push(7)?;
            assert!(words.push(8).is_err());
            assert!(words.push(9).is_err());
            Ok(())
        })
        .is_err()
    );
    sink.rolled_back();
}

#[test]
fn caller_error_and_unwind_roll_back_flat_words() {
    let mut sink = Sink::new(64);
    assert!(
        put_u32s_in(&mut sink, 0x101, |words| {
            words.push(7)?;
            Err(Full)
        })
        .is_err()
    );
    sink.rolled_back();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = put_u32s_in(&mut sink, 0x101, |words| {
            words.push(8)?;
            std::panic::panic_any(())
        });
    }));
    assert!(result.is_err());
    sink.rolled_back();
}

#[test]
fn body_length_overflow_poison_is_sticky_without_a_large_allocation() {
    for initial in [usize::MAX, u32::MAX as usize - 3] {
        let mut sink = Sink::new(64);
        let mut body = initial;
        let mut failed = false;
        let mut words = U32s {
            w: &mut sink,
            body: &mut body,
            failed: &mut failed,
        };
        assert!(words.push(1).is_err());
        assert!(words.push(2).is_err());
        assert!(failed);
        assert_eq!(body, initial);
        sink.rolled_back();
    }
}

#[test]
fn scratch_finish_reuses_capacity_and_restores_terminal_limit() {
    let mut scratch = Reply::with_capacity(512).into_scratch(3).unwrap();
    scratch.put(b"abc").unwrap();
    let cap = scratch.reply.buf.capacity();
    assert!(scratch.put(b"d").is_err());
    assert_eq!(scratch.as_bytes(), b"abc");
    let mut reply = scratch.finish();
    assert_eq!(reply.len(), 0);
    assert_eq!(reply.buf.capacity(), cap);
    // Spare capacity is uninitialized to safe Rust; do not read it or claim this proves erasure.
    reply.put(0x101, &[9; 300]).unwrap();
    assert_eq!(reply.buf.capacity(), cap);
    assert_eq!(
        Records::new(reply.as_bytes()).next().unwrap().unwrap().body,
        &[9; 300]
    );
    let before = reply.as_bytes().to_vec();
    assert!(reply.room(REPLY_CAP).is_err());
    assert_eq!(reply.as_bytes(), before);
}

#[test]
fn scratch_refuses_nonempty_reply_and_invalid_limits() {
    let mut reply = Reply::new();
    reply.put_text(tag::TEXT, "record").unwrap();
    assert!(reply.into_scratch(100).is_err());
    assert!(Reply::new().into_scratch(REPLY_CAP + 1).is_err());
    let mut zero = Reply::new().into_scratch(0).unwrap();
    zero.put(b"").unwrap();
    assert!(zero.put(b"x").is_err());
    assert!(zero.finish().as_bytes().is_empty());
}

#[test]
fn scratch_grows_and_returns_the_exact_bytes_before_finish() {
    let mut scratch = Reply::with_capacity(1).into_scratch(300).unwrap();
    scratch.put(b"a").unwrap();
    scratch.put(&[b'b'; 299]).unwrap();
    assert_eq!(scratch.as_bytes().len(), 300);
    assert_eq!(scratch.as_bytes()[0], b'a');
    assert!(scratch.as_bytes()[1..].iter().all(|&b| b == b'b'));
    assert!(scratch.put(b"c").is_err());
    let reply = scratch.finish();
    assert_eq!(reply.len(), 0);
    assert!(reply.buf.capacity() >= 300);
}
