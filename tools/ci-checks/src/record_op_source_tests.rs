// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `record-op-source`: failing fixtures the rule must find, passing ones it must not, and the
//! real tree.

use super::record_op_source::{findings, record_op_source};
use super::repo_root;

const CALLER: &str = "crates/busbar-kernel/src/push/mod.rs";

#[test]
fn a_held_op_passes() {
    let text = "let request = Request {\n    op: operation(&self.store).await?,\n};\nrecords.conditional_native(&request);\n";
    assert!(findings(CALLER, text).is_empty());
    let text =
        "request.op = store.record_op().await?.into();\nrecords.conditional_native(&request);\n";
    assert!(findings(CALLER, text).is_empty());
}

#[test]
fn a_raw_op_is_refused() {
    for raw in [
        "    op: crate::door::op_id().0,",
        "    op: OpId([7; 16]),",
        "    op: store.next_id()?.operation,",
        "    op: digest[..16].try_into().unwrap(),",
        "    request.op = OpId::from_parts(1, 2);",
    ] {
        let text = format!("records.conditional_native(&request);\n{raw}\n");
        assert_eq!(findings(CALLER, &text).len(), 1, "{raw}");
    }
}

#[test]
fn a_derived_op_is_built_only_by_its_owner() {
    let text = "let op = Op::Derived(DerivedOp::principal_transition(bytes));\n";
    assert_eq!(findings(CALLER, text).len(), 2);
    assert!(findings(
        "crates/busbar-kernel/src/off_path/governance/principal_transition.rs",
        text
    )
    .is_empty());
}

#[test]
fn the_tree_is_clean() {
    assert_eq!(record_op_source(&repo_root()), Ok(Vec::new()));
}
