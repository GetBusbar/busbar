// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The auth suite reads a `begin_login` credential form as production reads it.

use super::*;
use busbar_contract::abi::auth::{LoginField, FORM_TEXT};

/// A READY `begin_login` answer whose form is `fields`.
fn form_of(fields: &[LoginField]) -> BeginLoginOut {
    BeginLoginOut {
        head: crate::dispatch::out_head(),
        shape: BEGIN_FORM,
        _reserved: 0,
        authorize_url: AbiStr {
            ptr: std::ptr::null(),
            len: 0,
        },
        form: fields.as_ptr(),
        form_len: fields.len(),
    }
}

/// THE SUITE READS A CREDENTIAL FORM AS PRODUCTION DOES (compiled-in equals dropped-in, and the
/// published suite holds a plugin to what the host holds it to; THE DESIGN
/// `docs/design/BUSBAR-1.6.0.md` §11.13 M1: every slice built from a plugin-reported length is
/// capped). A form over the host's field cap is malformed in the transcript, as the host's login
/// refuses it; a form at the cap is spelled field by field. RED before: the suite formed the slice
/// from `form_len` with no cap and spelled 65 fields, so a plugin the host refuses passed the suite.
#[test]
fn a_form_over_the_hosts_field_cap_is_malformed_in_the_transcript() {
    let name = b"f";
    let field = LoginField {
        name: AbiStr::over(name),
        label: AbiStr::over(name),
        kind: FORM_TEXT,
        required: 0,
    };
    let over = vec![field; 65];
    assert_eq!(spelled_form(&form_of(&over)), "malformed");
    let at = vec![field; 64];
    let spelled = spelled_form(&form_of(&at));
    assert_eq!(spelled, format!("[{}]", vec!["f:text"; 64].join(",")));
}
