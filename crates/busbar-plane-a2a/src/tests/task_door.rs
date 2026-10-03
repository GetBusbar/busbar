// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The door's half of the task verbs: the once-a-second sweep claim and the record kind indices.

use super::*;

/// The first caller of each second runs the sweep, and no other caller of that second does.
#[test]
fn the_sweep_runs_once_a_second() {
    let swept = Keyed::new();
    assert!(claim_sweep(&swept, 10));
    assert!(!claim_sweep(&swept, 10));
    assert!(!claim_sweep(&swept, 9), "time read late never sweeps again");
    assert!(claim_sweep(&swept, 11));
}

/// A record write names its kind by its index in the tail's record kinds.
#[test]
fn a_write_names_its_kind_by_the_tails_index() {
    use crate::records::{KIND_PUSH_CONFIG, KIND_TASK, KIND_TASK_EVENT};
    assert_eq!(
        [KIND_TASK, KIND_TASK_EVENT, KIND_PUSH_CONFIG].map(kind_index),
        [0, 1, 2]
    );
    assert_eq!(
        kind_index("pin"),
        u32::MAX,
        "a kind the tail does not state"
    );
}
