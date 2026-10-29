// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The operator's request-body cap: its default, floor and ceiling are the documented ones.

use busbar_kernel::config::limits::{
    DEFAULT_REQUEST_BODY_MAX_BYTES, REQUEST_BODY_MAX_BYTES_CEIL, REQUEST_BODY_MAX_BYTES_FLOOR,
};
/// The knob the binding names, at the values it names them.
#[test]
fn the_body_cap_is_the_operators_and_its_default_and_ceiling_are_the_documented_ones() {
    assert_eq!(
        DEFAULT_REQUEST_BODY_MAX_BYTES,
        32 * 1024 * 1024,
        "default 32 MiB"
    );
    assert_eq!(
        REQUEST_BODY_MAX_BYTES_CEIL,
        1024 * 1024 * 1024,
        "ceiling 1 GiB"
    );
    const { assert!(REQUEST_BODY_MAX_BYTES_FLOOR < DEFAULT_REQUEST_BODY_MAX_BYTES) };
}
