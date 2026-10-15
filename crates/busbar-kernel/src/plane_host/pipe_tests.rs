// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PIPE-tier tests. FFI-F3: the FFI vtable `egress_open` slot grants NO subprocess capability, so
//! every plane-driven spawn is refused — an absolute, runnable program with a secret environment
//! record included, before anything is decoded or resolved — and no pipe is ever open, so both pipe
//! slots answer `Gone` for any pipe a plane names (row 166: the unserved spawning path is struck).

use crate::plane_host::with_dispatch_scope;
use busbar_contract::abi::hot::pod::POD_VERSION;
use busbar_contract::abi::hot::{EgressDesc, EgressKind, EgressOpen, PipeId, StatusClass};

/// Pack a `program + argv` command into the length-prefixed wire form (`u32 len | bytes`, LE) that
/// [`EgressDesc::target`] carries for a subprocess open. The first token is the program.
fn pack_command(tokens: &[&str]) -> Vec<u8> {
    let mut out = Vec::new();
    for tok in tokens {
        out.extend_from_slice(&(tok.len() as u32).to_le_bytes());
        out.extend_from_slice(tok.as_bytes());
    }
    out
}

/// A subprocess `EgressDesc` borrowing the packed `command` blob. `allowlist_scope` is DATA the host
/// ignores (FFI-F2/F3): a plane-asserted scope bit grants nothing.
fn subprocess_desc(command: &[u8]) -> EgressDesc {
    EgressDesc {
        size: std::mem::size_of::<EgressDesc>() as u32,
        version: POD_VERSION,
        kind: busbar_contract::abi::hot::RawEgressKind::of(EgressKind::Subprocess),
        _reserved: 0,
        allowlist_scope: 0,
        _reserved2: 0,
        target_ptr: command.as_ptr(),
        target_len: command.len(),
        client_identity_ref: 0,
        credential_ref: 0,
        verb_ptr: std::ptr::null(),
        verb_len: 0,
        headers_ptr: std::ptr::null(),
        headers_len: 0,
        body_ptr: std::ptr::null(),
        body_len: 0,
        cred_header_ptr: std::ptr::null(),
        cred_header_len: 0,
        cred_scheme_ptr: std::ptr::null(),
        cred_scheme_len: 0,
        env_ptr: std::ptr::null(),
        env_len: 0,
        cwd_ptr: std::ptr::null(),
        cwd_len: 0,
        stderr_inherit: 0,
        _reserved3: [0; 7],
        trust_anchor_ref: 0,
        timeout_ms: 0,
        resolved_addr: [0; 16],
        resolved_addr_kind: 0,
        _reserved4: [0; 7],
    }
}

/// FFI-F3 (subprocess egress no allowlist): the FFI vtable `egress_open` slot passes an EMPTY host
/// program allowlist, so a plane-driven subprocess spawn is REFUSED outright — even an absolute,
/// otherwise-runnable program. The capability is disabled at the untrusted seam, not merely narrowed.
#[test]
fn the_ffi_slot_refuses_a_plane_driven_subprocess() {
    let command = pack_command(&["/bin/cat"]);
    // A child-environment record naming a SECRET reference (kind 1): refused before it is read.
    let secret = br#"{"module":"env","settings":{"name":"BUSBAR_PIPE_NEVER_RESOLVED"}}"#;
    let mut env = Vec::new();
    env.extend_from_slice(&5u32.to_le_bytes());
    env.extend_from_slice(b"TOKEN");
    env.push(1);
    env.extend_from_slice(&(secret.len() as u32).to_le_bytes());
    env.extend_from_slice(secret);
    // The plane even asserts a (meaningless) privilege bit — it carries no authority over the seam.
    let mut desc = subprocess_desc(&command);
    desc.allowlist_scope = u32::MAX;
    desc.env_ptr = env.as_ptr();
    desc.env_len = env.len();

    let app = crate::test_support::TestApp::new().build();
    with_dispatch_scope(&app, |host, vt| {
        let mut out = std::mem::MaybeUninit::<EgressOpen>::uninit();
        assert_eq!(
            (vt.egress_open.unwrap())(host, &desc as *const EgressDesc, &mut out),
            StatusClass::Refused,
            "the FFI seam admits no plane-driven subprocess — no host program allowlist grants it"
        );
        // No pipe is ever open: both slots answer `Gone` for any pipe a plane names.
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
