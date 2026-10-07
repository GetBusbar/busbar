// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The codec reject shapes. Ported from the kernel's deleted handler registry suite
//! (`handlers/tests/contract_tests.rs` `sub_op_reject_carries_op_and_model`; ARCHITECT F25 ruling
//! 2026-10-07): the shape is the contract's, so its test is too.

use busbar_contract::codec::IngressReject;
use busbar_contract::operation::OpVerb;

/// A SUB-OPERATION REJECT CARRIES THE OPERATION AND THE MODEL it refused, so the refusal can name
/// both.
#[test]
fn sub_op_reject_carries_op_and_model() {
    let r = IngressReject::UnsupportedSubOp {
        op: OpVerb::IMAGE,
        model: "gpt-image-1".into(),
    };
    match r {
        IngressReject::UnsupportedSubOp { op, model } => {
            assert_eq!(op, OpVerb::IMAGE);
            assert_eq!(model, "gpt-image-1");
        }
        other => panic!("not a sub-operation reject: {other:?}"),
    }
}
