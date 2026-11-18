// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Request frames: `take`, `fill`, `share` and the reset by the last holder.

use busbar_ports::frame::{FramePool, Reset};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Default)]
struct Buf {
    bytes: Vec<u8>,
    resets: usize,
}

impl Reset for Buf {
    fn reset(&mut self) {
        // Wipe what was written, keep the capacity.
        self.bytes.iter_mut().for_each(|b| *b = 0);
        self.bytes.clear();
        self.resets += 1;
    }
}

#[test]
fn a_taken_frame_can_be_filled() {
    let pool = FramePool::<Buf>::build(2);
    let mut frame = pool.take();
    assert!(frame.fill().is_some());
}

#[test]
fn a_shared_frame_cannot_be_filled_until_the_share_drops() {
    let pool = FramePool::<Buf>::build(1);
    let mut first = pool.take();
    first.fill().unwrap().bytes.extend_from_slice(b"hello");
    let mut second = first.share();
    assert!(first.fill().is_none());
    assert!(second.fill().is_none());
    assert_eq!(&second.bytes[..], b"hello");
    drop(second);
    assert!(first.fill().is_some());
    assert_eq!(&first.bytes[..], b"hello");
}

#[test]
fn the_last_holder_resets_and_the_next_take_gets_the_same_allocation() {
    let pool = FramePool::<Buf>::build(1);
    let mut frame = pool.take();
    frame.fill().unwrap().bytes.extend_from_slice(&[7; 64]);
    let at = std::ptr::from_ref::<Buf>(&frame);
    let capacity = frame.bytes.capacity();
    let other = frame.share();
    drop(frame);
    // One holder is left: nothing is reset or returned yet.
    assert_eq!(pool.resting(), 0);
    assert_eq!(other.resets, 0);
    drop(other);
    assert_eq!(pool.resting(), 1);
    let again = pool.take();
    assert_eq!(std::ptr::from_ref::<Buf>(&again), at);
    assert_eq!(again.resets, 1);
    assert!(again.bytes.is_empty());
    assert_eq!(again.bytes.capacity(), capacity);
}

#[test]
fn demand_past_the_peak_makes_a_frame_and_the_pool_keeps_it() {
    let pool = FramePool::<Buf>::build(1);
    let a = pool.take();
    let b = pool.take();
    assert_eq!(pool.resting(), 0);
    drop(a);
    drop(b);
    assert_eq!(pool.resting(), 2);
}

#[test]
fn eight_threads_share_and_drop_without_losing_or_making_a_frame() {
    const FRAMES: usize = 8;
    const ROUNDS: usize = 100_000;
    let pool = FramePool::<Buf>::build(FRAMES);
    let unwritable = AtomicUsize::new(0);
    std::thread::scope(|scope| {
        for _ in 0..FRAMES {
            scope.spawn(|| {
                for round in 0..ROUNDS {
                    let mut frame = pool.take();
                    if let Some(buf) = frame.fill() {
                        buf.bytes.push(round as u8);
                    } else {
                        unwritable.fetch_add(1, Ordering::Relaxed);
                    }
                    let held = frame.share();
                    let seen = std::thread::scope(|inner| {
                        inner
                            .spawn(move || {
                                let seen = held.bytes.len();
                                drop(held);
                                seen
                            })
                            .join()
                            .unwrap()
                    });
                    assert_eq!(seen, 1);
                    drop(frame);
                }
            });
        }
    });
    // A frame taken was always writable at once, and every frame is back: none lost, none made
    // (8 takers over 8 frames).
    assert_eq!(unwritable.load(Ordering::Relaxed), 0);
    assert_eq!(pool.resting(), FRAMES);
}
