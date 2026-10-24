// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT SDK'S ONE HELPER: a transport door's selector forms, as the codes its Statement
//! carries ([`form_codes`]).
//!
//! The HOT transport lowering that lived here (`export_carrier!`, `export_framer!`, the per-method
//! `#[repr(C)]` slot bridges and the decl a transport cdylib exported as `busbar_transport_decl`) is
//! deleted (row 84): every transport, in this tree and in the fleet, serves its memory-ABI door
//! (`export_door!`), and the loader reads no transport decl. What stays is the helper the doors
//! name at this path.

use crate::abi::shared::code;
use crate::grammar::SelectorForm;

/// `forms` as their codes, in declared order.
#[must_use]
pub const fn form_codes<const N: usize>(forms: &[SelectorForm]) -> [u8; N] {
    let mut list = [0_u8; N];
    let mut i = 0;
    while i < N {
        list[i] = code::selector_form(forms[i]);
        i += 1;
    }
    list
}
