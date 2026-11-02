// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Drive the actual SDK framer sink over exclusive, initialized host buffers.

use crate::abi::mechanism::call::{Outcome, RawOutcome};
use crate::abi::sdk::transport::sink::{self, Owed};
use crate::abi::sdk::{Lent, Out};
use crate::abi::transport::{FramePiece, FramerOut, FramerSink, HeadSlots};

/// Fill the caller's real buffers from `owed` using the SDK's unchanged sink implementation.
/// The returned counts and flags can be consumed by the caller's normal framing reader; the
/// buffers remain owned by the caller. No raw sink or pointer-taking constructor is exposed.
///
/// The SDK fill reads no sink timestamps, so both timestamp fields are zero here. Deadlines
/// returned by `owed` are preserved by the SDK itself.
pub fn fill<B: AsRef<[u8]>, F: Owed<B>>(
    owed: &mut F,
    wire: &mut [u8],
    frame: &mut [u8],
    pieces: &mut [FramePiece],
    heads: &mut [HeadSlots],
    class_of: impl Fn(u16) -> u8,
    fault_of: impl Fn(u16) -> u8,
) -> FramerOut {
    let sink = FramerSink {
        wire: wire.as_mut_ptr(),
        wire_cap: wire.len(),
        frame: frame.as_mut_ptr(),
        frame_cap: frame.len(),
        pieces: pieces.as_mut_ptr(),
        pieces_cap: pieces.len(),
        heads: heads.as_mut_ptr(),
        heads_cap: heads.len(),
        now_monotonic_ns: 0,
        now_unix_ns: 0,
    };
    let mut out: FramerOut = super::zeroed();
    out.head.size = std::mem::size_of::<FramerOut>() as u32;
    out.head.outcome = RawOutcome::of(Outcome::Ready);
    // SAFETY: each exact pointer/capacity pair names its exclusively borrowed, initialized
    // slice for this synchronous call. Rust's borrows keep all four buffers live and disjoint;
    // sink itself stays initialized here and the SDK retains none of these ranges.
    let sink = unsafe { Lent::new(&sink) };
    // Use the normal custody constructor, also present under the test-support feature. Fill
    // writes only scalar yield fields and the caller's buffers, so no holder escapes this call.
    let holders = crate::abi::sdk::out::Holders::default();
    sink::fill(
        owed,
        sink,
        &mut Out::lent(&mut out, None, &holders),
        class_of,
        fault_of,
    );
    out
}
