// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_contract::abi::auth::{BeginLoginOut, BEGIN_FORM};
use busbar_contract::abi::auth::{LoginField, FORM_TEXT};
use busbar_contract::abi::mechanism::call::AbiStr;
use busbar_contract::auth::{FieldKind, LoginOutcome};

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
    assert!(crate::auth_door::login::begun(&form_of(&over)).is_none());
    let at = vec![field; 64];
    let Some(LoginOutcome::Prompt(form)) = crate::auth_door::login::begun(&form_of(&at)) else {
        panic!("the actual capped reader accepts exactly64 live fields");
    };
    assert_eq!(form.fields.len(), 64);
    assert!(form.fields.iter().all(|field| field.name == "f"
        && field.label == "f"
        && field.kind == FieldKind::Text
        && !field.required));
}
