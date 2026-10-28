// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The one wording every store refuses a forked chain in: the position named, nothing echoed.

use super::*;

#[test]
fn a_forked_audit_chain_names_its_seq() {
    assert_eq!(
        audit_fork(7).0,
        "append_audit: seq 7 already holds a DIFFERENT record — the audit chain has forked"
    );
}

#[test]
fn a_forked_plane_chain_names_its_kind_parent_and_seq() {
    assert_eq!(
        chain_fork("task_event", "t-1", 3).0,
        "append_plane_record: kind 'task_event' parent 't-1' seq 3 already holds a DIFFERENT \
         record — the chain has forked"
    );
}
