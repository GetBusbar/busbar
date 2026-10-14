// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Tests for `crates/busbar-contract/src/abi/hot/services.rs`. ONE test arms this process's ports:
//! they are first-install-wins, so a second arming test in this binary would read the first's.

use super::*;

extern "C-unwind" fn host_entropy(_host: HostCtx, out: *mut u8, len: usize) -> StatusClass {
    // SAFETY: the slot's buffer discipline.
    unsafe { core::ptr::write_bytes(out, 0xA5, len) };
    StatusClass::Ok
}
extern "C-unwind" fn host_clock(_host: HostCtx) -> u64 {
    1_700_000_000
}
extern "C-unwind" fn host_cap(_host: HostCtx) -> u64 {
    4_096
}

/// A dropped-in image armed over a host table reads the HOST's services through every port; before
/// the arm it read each port's failure path. A table serving from this very image (a linked plane)
/// is refused, and so is a table the airlock refuses — neither installs anything.
#[test]
fn an_armed_image_reads_the_hosts_services_through_every_port() {
    let mut before = [0u8; 4];
    assert!(
        !crate::codec::fill_entropy(&mut before),
        "unarmed: the failure path"
    );
    assert_eq!(crate::codec::wall_clock_now(), None);

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
    assert!(
        !crate::codec::fill_entropy(&mut before),
        "a refused arm installs nothing"
    );

    static HOST: PlaneHostVtable = PlaneHostVtable {
        entropy_fill: Some(host_entropy),
        wall_clock: Some(host_clock),
        translate_cap: Some(host_cap),
        ..PlaneHostVtable::EMPTY
    };
    assert_eq!(unsafe { arm(&HOST) }, StatusClass::Ok);
    let mut drawn = [0u8; 4];
    assert!(crate::codec::fill_entropy(&mut drawn));
    assert_eq!(drawn, [0xA5; 4], "the draw is the host's");
    assert_eq!(crate::codec::wall_clock_now(), Some(1_700_000_000));
    assert_eq!(crate::codec::max_translate_body_bytes(), 4_096);

    // The HOST side of the same seam: `SERVICES` answers from this image's (now armed) ports.
    let mut served = [0u8; 3];
    let fill = PlaneHostVtable::SERVICES.entropy_fill.unwrap();
    assert_eq!(
        fill(HostCtx::NULL, served.as_mut_ptr(), served.len()),
        StatusClass::Ok
    );
    assert_eq!(served, [0xA5; 3]);
    assert_eq!(
        fill(HostCtx::NULL, core::ptr::null_mut(), 1),
        StatusClass::Refused
    );
    assert_eq!(
        (PlaneHostVtable::SERVICES.wall_clock.unwrap())(HostCtx::NULL),
        1_700_000_000
    );
    assert_eq!(
        (PlaneHostVtable::SERVICES.translate_cap.unwrap())(HostCtx::NULL),
        4_096
    );
    // The usage-tap latch slot is RETIRED (row 155): `SERVICES` serves it no longer.
    assert!(PlaneHostVtable::SERVICES.tap_fault_latch.is_none());
}
