// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PIPE-tier tests. No plane-driven spawn exists (FFI-F3; the `egress_*` family that opened one is
//! deleted, BUSBAR-1.6.0.md Appendix A B.6, l.3846), so no pipe is ever open: both pipe slots
//! answer `Gone` for any pipe a plane names (row 166: the unserved spawning path is struck).

use crate::plane_host::with_dispatch_scope;
use busbar_contract::abi::hot::{PipeId, StatusClass};

/// No pipe is ever open: both slots answer `Gone` for any pipe a plane names, and a null
/// out-pointer is refused before the pipe is looked at.
#[test]
fn no_pipe_is_ever_open() {
    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        assert!(
            vt.egress_open.is_none(),
            "no slot opens a subprocess for a plane"
        );
        let mut buf = [0u8; 8];
        let mut written = 0usize;
        for pipe in [PipeId(0), PipeId(1), PipeId(u64::MAX)] {
            assert_eq!(
                (vt.pipe_read.unwrap())(host, pipe, buf.as_mut_ptr(), buf.len(), &mut written),
                StatusClass::Gone
            );
            assert_eq!(
                (vt.pipe_write.unwrap())(host, pipe, buf.as_ptr(), buf.len()),
                StatusClass::Gone
            );
        }
        assert_eq!(
            (vt.pipe_read.unwrap())(
                host,
                PipeId(1),
                buf.as_mut_ptr(),
                buf.len(),
                std::ptr::null_mut()
            ),
            StatusClass::Refused,
            "a null out-pointer is refused before the pipe is looked at"
        );
    });
}
