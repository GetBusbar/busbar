// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host I/O slots' reading of a caller's ranges (THE DESIGN §11.13 M1).

use super::*;

/// RED (THE DESIGN §11.13 M1, "Every slice built from a plugin-reported length is capped and
/// validated before it is formed"; audit PL1 #1): an I/O slot's list or buffer stated over the hard
/// byte maximum (`u32::MAX`) is refused before any slice is formed over it, as NULL with a count is.
#[test]
fn red_an_io_range_over_the_byte_cap_is_refused_before_any_slice() {
    let b = [0_u8; 8];
    let over = u32::MAX as usize + 1;
    // SAFETY: the range is refused before any slice is formed; nothing reads it.
    let formed = unsafe { list(b.as_ptr(), over) }.map(<[u8]>::len);
    assert_eq!(
        formed, None,
        "a range stated over the byte cap was formed into a slice"
    );
    // SAFETY: the test's own eight bytes.
    let within = unsafe { list(b.as_ptr(), b.len()) }.map(<[u8]>::len);
    assert_eq!(within, Some(8), "a range within the cap is the caller's");
    // SAFETY: NULL with a count is refused before anything is formed.
    assert!(unsafe { list::<u8>(std::ptr::null(), 1) }.is_none());
}

/// A caller's `out` lent in 96 bytes, stating `size`: every byte past the size field is `0xAA`, so
/// a write past what the caller stated shows.
#[repr(C, align(8))]
struct LentOut([u8; 96]);

impl LentOut {
    fn stating(size: u32) -> Self {
        let mut b = [0xAA_u8; 96];
        b[..4].copy_from_slice(&size.to_ne_bytes());
        Self(b)
    }

    fn out(&mut self) -> *mut busbar_contract::abi::host::service::ServiceOut {
        self.0.as_mut_ptr().cast()
    }

    /// Whether every byte from `from` on is still the caller's.
    fn untouched_from(&self, from: usize) -> bool {
        self.0[from..].iter().all(|b| *b == 0xAA)
    }
}

/// RED (Q128 kernel-scope MEDIUM, the io slot frame): the host writes a caller's `out` only as far
/// as the caller STATED it (`min(out.size, its own)`), and refuses an `out` stated below the first
/// `ServiceOut` before the service runs, writing none of it, so a `ServiceOut` may grow by appending
/// and an older caller's smaller one is never overrun. RED before: the frame wrote a whole
/// `ServiceOut` over whatever the caller lent.
#[test]
fn red_the_io_slot_frame_writes_no_further_than_the_out_the_caller_stated() {
    use busbar_contract::abi::host::service::SERVICE_OUT_V1;
    use busbar_contract::abi::mechanism::call::{Outcome, RawOutcome};
    let mut lent = LentOut::stating(32);
    let raw: RawOutcome = slot::<busbar_contract::abi::host::io::AddrIn>(
        busbar_contract::abi::mechanism::ticket::HostCtx::NONE,
        std::ptr::null(),
        lent.out(),
        busbar_contract::abi::host::io::op::ENDS,
        |_, _, _| unreachable!("a NULL `in` never reaches the body"),
    );
    assert_eq!(raw.outcome(), Outcome::Refused, "a short `out` was served");
    assert!(lent.untouched_from(4), "a short `out` was written");
    let mut lent = LentOut::stating(SERVICE_OUT_V1 as u32);
    let raw: RawOutcome = slot::<busbar_contract::abi::host::io::AddrIn>(
        busbar_contract::abi::mechanism::ticket::HostCtx::NONE,
        std::ptr::null(),
        lent.out(),
        busbar_contract::abi::host::io::op::ENDS,
        |_, _, _| unreachable!("a NULL `in` never reaches the body"),
    );
    assert_eq!(raw.outcome(), Outcome::Fault, "a NULL `in` is FAULT");
    assert!(
        lent.untouched_from(SERVICE_OUT_V1),
        "the host wrote past the `out` stated"
    );
    assert_eq!(lent.0[5], 0, "`exited` is written zero by every frame");
}

/// `io.ends` on a program that has exited answers `exited` = 1 and its exit code in `value`, and
/// writes no far address; a program still running, and every other handle, answers `exited` = 0
/// with its port and far end as before.
#[test]
fn ends_answers_a_programs_own_exit_in_the_exited_byte() {
    let mut buf = [0xAA_u8; busbar_contract::abi::host::io::MAX_ADDR];
    let exited = Ends {
        exit: Some(3),
        ..Ends::default()
    };
    // SAFETY: the test's own buffer, `MAX_ADDR` bytes.
    let a = unsafe { ends_answer(Ok(exited), buf.as_mut_ptr(), buf.len()) };
    assert_eq!(
        (a.outcome, a.exited, a.value, a.len),
        (Outcome::Ready, 1, 3, 0)
    );
    assert!(
        buf.iter().all(|b| *b == 0xAA),
        "an exited program wrote a far address"
    );
    let running = Ends::default();
    // SAFETY: as above.
    let a = unsafe { ends_answer(Ok(running), buf.as_mut_ptr(), buf.len()) };
    assert_eq!(
        (a.outcome, a.exited, a.value, a.len),
        (Outcome::Ready, 0, 0, 0)
    );
    let stream = Ends {
        port: 8080,
        peer: "10.0.0.1:443".into(),
        exit: None,
    };
    // SAFETY: as above.
    let a = unsafe { ends_answer(Ok(stream), buf.as_mut_ptr(), buf.len()) };
    assert_eq!((a.exited, a.value, a.len), (0, 8080, 12));
    assert_eq!(&buf[..12], b"10.0.0.1:443");
}
