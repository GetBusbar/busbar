// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The generic call builder: typed arguments into the one call record (`Call`: `head`, `texts`, `blobs`).
//!
//! A method's arguments are of three sorts and each has one home:
//! - its numbers: one plain `#[repr(C)]` record, the method's `head`, read by prefix on the other side;
//! - its borrowed UTF-8 fields: `texts`, by position;
//! - its borrowed byte fields: `blobs`, by position.
//!
//! A `Frame` holds the head by value and the two position arrays inline, so it lives wholly on the
//! caller's stack: no heap call. The arrays hold `(pointer, length)` pairs that name the caller's own
//! memory: no lent byte is copied. `Frame::call` borrows the frame and returns the `Call` to pass by
//! address; the borrow keeps the frame, and so everything the `Call` points at, alive for the crossing.
//!
//! Appending is the only growth (C.3): a later field goes at the end of a head record, a later text or
//! blob takes the next position. `since`-gated positions are cut with [`Frame::known`] for an image whose
//! second number is older than the position, so an older image is never sent what it does not know.

use busbar_plugin_abi::types::{Bytes, Pair, Str};
use zerocopy::{Immutable, IntoBytes};

use super::ffi::{self, Call};

/// The operation's one clock reading, in monotonic nanoseconds, handed to the plugin in `Call::mono_ns`.
/// `NONE` (0) says no reading was handed in; the plugin then has none for this call.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mono(pub u64);

impl Mono {
    pub const NONE: Mono = Mono(0);
}

/// A method's numbers. Any plain record whose bytes may be lent as they stand: no padding, no pointer,
/// no interior mutability (zerocopy proves the three at compile time). `()` is the head of a method
/// with no numbers.
pub trait Head: IntoBytes + Immutable {}
impl<T: IntoBytes + Immutable> Head for T {}

/// One call's arguments, laid out for the crossing. `T` texts and `B` blobs, both fixed by the method.
pub struct Frame<'a, H: Head, const T: usize, const B: usize> {
    head: H,
    texts: [Str<'a>; T],
    blobs: [Bytes<'a>; B],
    /// How many leading positions the image knows (`since`); the rest are not sent.
    texts_known: usize,
    blobs_known: usize,
    head_known: usize,
}

impl<'a, H: Head, const T: usize, const B: usize> Frame<'a, H, T, B> {
    /// Every position sent, the whole head sent.
    pub fn new(head: H, texts: [&'a str; T], blobs: [&'a [u8]; B]) -> Self {
        Frame {
            head,
            texts: texts.map(Str::new),
            blobs: blobs.map(Bytes::new),
            texts_known: T,
            blobs_known: B,
            head_known: size_of::<H>(),
        }
    }

    /// The same from values already in crossing form (a view's own `Str` and `Bytes` fields).
    pub fn raw(head: H, texts: [Str<'a>; T], blobs: [Bytes<'a>; B]) -> Self {
        Frame {
            head,
            texts,
            blobs,
            texts_known: T,
            blobs_known: B,
            head_known: size_of::<H>(),
        }
    }

    /// Cut the frame to what an older image knows: `head` bytes, `texts` and `blobs` positions. Values
    /// past the frame's own sizes are clamped, so a table row for a newer image changes nothing here.
    #[must_use]
    pub fn known(mut self, head: usize, texts: usize, blobs: usize) -> Self {
        self.head_known = head.min(size_of::<H>());
        self.texts_known = texts.min(T);
        self.blobs_known = blobs.min(B);
        self
    }

    /// The call record over this frame. The session is not chosen here: the boundary crate's session and
    /// chain handles set it when the call is made on them.
    pub fn call(&self, at: Mono) -> Call<'_> {
        let head = self.head.as_bytes();
        ffi::call(
            at.0,
            head.get(..self.head_known).unwrap_or(head),
            self.texts.get(..self.texts_known).unwrap_or(&self.texts),
            self.blobs.get(..self.blobs_known).unwrap_or(&self.blobs),
        )
    }
}

/// A borrowed list of name and value pairs (request headers, upstream parameters) as one blob position.
/// The list is lent as it stands in the caller's memory: nothing is rebuilt and nothing is copied.
pub fn pairs<'a>(list: &'a [Pair<'a>]) -> Bytes<'a> {
    ffi::lend_pairs(list)
}

/// The count of a pair list as a head field.
pub fn count(list: &[Pair<'_>]) -> u32 {
    u32::try_from(list.len()).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zerocopy::{FromBytes, KnownLayout};

    #[repr(C)]
    #[derive(Clone, Copy, IntoBytes, Immutable, FromBytes, KnownLayout)]
    struct TwoNumbers {
        first: u32,
        second: u32,
        third: u64,
    }

    #[test]
    fn the_call_points_at_the_callers_own_memory() {
        let body = vec![7u8; 4096];
        let path = String::from("/v1/messages");
        let frame = Frame::new(
            TwoNumbers {
                first: 1,
                second: 2,
                third: 3,
            },
            [path.as_str()],
            [body.as_slice()],
        );
        let call = frame.call(Mono(11));
        assert_eq!((call.session(), call.mono_ns()), (0, 11));
        assert_eq!(call.head().len(), 16);
        assert!(core::ptr::eq(
            call.texts()[0].get().as_ptr(),
            path.as_ptr()
        ));
        assert!(core::ptr::eq(
            call.blobs()[0].get().as_ptr(),
            body.as_ptr()
        ));
        assert_eq!(call.blobs()[0].len(), 4096);
    }

    #[test]
    fn an_older_image_is_sent_the_prefix_it_knows() {
        let frame = Frame::new(
            TwoNumbers {
                first: 1,
                second: 2,
                third: 3,
            },
            ["a", "b"],
            [b"x".as_slice(), b"y".as_slice(), b"z".as_slice()],
        )
        .known(8, 1, 2);
        let call = frame.call(Mono::NONE);
        assert_eq!(call.head().len(), 8);
        assert_eq!(call.texts().len(), 1);
        assert_eq!(call.blobs().len(), 2);
    }

    #[test]
    fn a_method_with_no_arguments_is_an_empty_call() {
        let frame = Frame::new((), [], []);
        let call = frame.call(Mono::NONE);
        assert!(call.head().is_empty() && call.texts().is_empty() && call.blobs().is_empty());
    }

    #[test]
    fn known_never_widens_a_frame() {
        let frame = Frame::new((), ["a"], []).known(64, 9, 9);
        let call = frame.call(Mono::NONE);
        assert_eq!((call.head().len(), call.texts().len(), call.blobs().len()), (0, 1, 0));
    }
}
