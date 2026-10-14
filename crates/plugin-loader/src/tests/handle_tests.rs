// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The instance handle's own arithmetic and its one check (#74). The forged context refused at
//! the host's entries is `host_services_tests::a_forged_context_is_refused_before_it_names_an_instance`.

use super::*;

/// The SipHash-2-4 reference vectors (Aumasson and Bernstein, `vectors.h`): key `00..0f`, message
/// `00..len-1`, for the empty, 8-byte and 16-byte messages.
#[test]
fn siphash24_is_the_reference_function() {
    let k = (0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908);
    assert_eq!(siphash24(k, &[]), 0x726f_db47_dd0e_0e31);
    assert_eq!(
        siphash24(k, &[0x0706_0504_0302_0100]),
        0x93f5_f579_9a93_2462
    );
    assert_eq!(
        siphash24(k, &[0x0706_0504_0302_0100, 0x0f0e_0d0c_0b0a_0908]),
        0x3f2a_cc7f_57c2_9bdb
    );
}

/// A minted handle names its instance and no address; every handle the host did not mint names
/// none and is counted; no context is no context, and is not counted.
#[test]
fn only_a_minted_handle_names_an_instance() {
    let wake: &'static InstanceWake = Box::leak(Box::default());
    let ctx = mint(wake).expect("the host mints a handle");
    assert!(std::ptr::eq(resolve(ctx).expect("its own instance"), wake));
    assert_ne!(
        ctx.handle,
        std::ptr::from_ref(wake) as usize as u64,
        "the handle is not the instance's address"
    );

    let before = forged();
    assert!(resolve(HostCtx::NONE).is_none());
    assert_eq!(forged(), before, "no context is not a forgery");

    let id = ctx.handle & ID_MASK;
    let unminted = (1u64 << HANDLE_ID_BITS) - 2;
    for (why, handle) in [
        ("one tag bit off", ctx.handle ^ (1 << HANDLE_ID_BITS)),
        ("the top tag bit off", ctx.handle ^ (1 << 63)),
        ("an id with no tag", id),
        ("a tag with no id", ctx.handle & !ID_MASK),
        (
            "a correctly tagged id the host never minted",
            (tag_of(key(), unminted) << HANDLE_ID_BITS) | unminted,
        ),
        ("an address", std::ptr::from_ref(wake) as usize as u64),
    ] {
        let at = forged();
        assert!(resolve(HostCtx { handle }).is_none(), "{why}");
        assert!(forged() > at, "{why} was not counted");
    }
}
