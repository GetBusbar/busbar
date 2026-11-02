// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::auth::{LoginField, FORM_TEXT};

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
