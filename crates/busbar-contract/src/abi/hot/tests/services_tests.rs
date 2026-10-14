// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/abi/hot/services.rs`. ONE test arms this process's ports:
//! they are first-install-wins, so a second arming test in this binary would read the first's.

use super::*;

extern "C-unwind" fn host_latch(
    _host: HostCtx,
    _protocol_ptr: *const u8,
    protocol_len: usize,
    _reason_ptr: *const u8,
    reason_len: usize,
) -> bool {
    protocol_len == 5 && reason_len == 6
}
extern "C-unwind" fn host_cap(_host: HostCtx) -> u64 {
    4_096
}

/// A dropped-in image armed over a host table reads the HOST's services through every port; before
/// the arm it read each port's failure path. A table serving from this very image (a linked plane)
/// is refused, and so is a table the airlock refuses — neither installs anything.
#[test]
fn an_armed_image_reads_the_hosts_services_through_every_port() {
    assert!(
        !crate::codec::usage_tap_fault_should_warn("proto", "reason"),
        "unarmed: the failure path"
    );
    assert_eq!(
        crate::codec::max_translate_body_bytes(),
        crate::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT
    );

    // SAFETY (each arm): every table below is a whole `'static` `PlaneHostVtable`.
    assert_eq!(unsafe { arm(core::ptr::null()) }, StatusClass::Refused);
    let mut bad = PlaneHostVtable::EMPTY;
    bad.abi.magic ^= 1;
    let bad: &'static PlaneHostVtable = Box::leak(Box::new(bad));
    assert_eq!(unsafe { arm(bad) }, StatusClass::Refused);
    assert_eq!(
        unsafe { arm(&PlaneHostVtable::SERVICES) },
        StatusClass::Unsupported
    );
    assert_eq!(
        crate::codec::max_translate_body_bytes(),
        crate::codec::TRANSLATE_BODY_MAX_BYTES_DEFAULT,
        "a refused arm installs nothing"
    );

    static HOST: PlaneHostVtable = PlaneHostVtable {
        tap_fault_latch: Some(host_latch),
        translate_cap: Some(host_cap),
        ..PlaneHostVtable::EMPTY
    };
    assert_eq!(unsafe { arm(&HOST) }, StatusClass::Ok);
    assert!(crate::codec::usage_tap_fault_should_warn("proto", "reason"));
    assert!(!crate::codec::usage_tap_fault_should_warn(
        "proto",
        "other-reason"
    ));
    assert_eq!(crate::codec::max_translate_body_bytes(), 4_096);

    // The HOST side of the same seam: `SERVICES` answers from this image's (now armed) ports, and
    // serves no entropy and no clock — the contract holds neither; a host fills those slots itself.
    assert!(PlaneHostVtable::SERVICES.entropy_fill.is_none());
    assert!(PlaneHostVtable::SERVICES.wall_clock.is_none());
    assert_eq!(
        (PlaneHostVtable::SERVICES.translate_cap.unwrap())(HostCtx::NULL),
        4_096
    );
    let latch = PlaneHostVtable::SERVICES.tap_fault_latch.unwrap();
    let (p, r) = ("proto", "reason");
    assert!(latch(
        HostCtx::NULL,
        p.as_ptr(),
        p.len(),
        r.as_ptr(),
        r.len()
    ));
    let invalid = [0xFFu8];
    assert!(
        !latch(HostCtx::NULL, p.as_ptr(), p.len(), invalid.as_ptr(), 1),
        "not UTF-8"
    );

    // Past `REASON_CAP` distinct spellings, every new reason is kept as `UNLISTED_REASON`, so a
    // plane cannot grow the host's memory or label set without bound. (Here, after every latch
    // assertion above: the kept set is process-wide.)
    for i in 0..REASON_CAP {
        let _ = kept(&format!("reason-{i}"));
    }
    assert_eq!(kept("one-past-the-cap"), UNLISTED_REASON);
    assert_eq!(
        kept("reason-0"),
        "reason-0",
        "a kept spelling is still found"
    );
}
