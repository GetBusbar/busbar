// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ERRORS (ABI-MIN3-INTERFACE §14 round 34; T1, run in every plugin's dev CI): a repository's
//! `docs/diagnostics.json` against its binary, through `busbar_plugin_test::errors`. The file arms are W1-T1's.
//! Holding the file against describe's D_ERRORS, the stamp name through `scan::error_identity` and every number
//! seen on ERROR or `log_error` needs a registry (W1-L2, after W1-L1's `error_identity`).
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_test::errors::{diagnostics, same_numbers};

const FILE: &[u8] = br#"[{"code": "BUSBAR-busbar-hook-ranking-0003", "number": 3, "plugin": "busbar-hook-ranking",
  "slug": "no-candidates", "title": "No candidates", "summary": "Nothing to rank.", "action": "Check the pool.",
  "since": "1.6.0"}]"#;

#[test]
fn a_repository_with_no_d_errors_and_no_file_passes() {
    assert_eq!(same_numbers(&[], &[], &[]), Ok(()));
}

#[test]
fn the_file_is_checked_against_the_stamp_name() {
    assert_eq!(diagnostics(FILE, "busbar-hook-ranking"), Ok(vec![3]));
    assert!(diagnostics(FILE, "busbar-hook-webrequest").is_err());
    assert_eq!(same_numbers(&[3], &[3], &[3]), Ok(()));
    assert!(same_numbers(&[3], &[3], &[4]).is_err());
}

#[test]
#[ignore = "owner: W1-L2; blocked (re-checked on dev 2026-11-16): no test constructor for Registry<N> (Needs impl, ConfigBinder, Ceilings, a static Host) and no second-identity MIN-3 fixture image exist in busbar-plugin-test on dev"]
fn the_file_matches_describe_and_every_number_the_suite_saw() {
    todo!("owner: W1-L2 (C-ERRORS)")
}
