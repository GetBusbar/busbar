// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-SCRUB-ONE (ABI-MIN3-INTERFACE §14 round 6): config_validate's redaction, kernel-egress and connector URL
//! masking and the instance scrub set produce identical output on one corpus, through `abi::host::scrub`. The
//! helper arm is W1-H0's (merged); the repoints are K7's, K1's and C1A's, and the corpus arm over all three is the
//! last of them to land.
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_abi::host_side::scrub::{mask_url, strip_userinfo, Scrub};

const CORPUS: &[&str] = &[
    "https://user:pa55@db.test:5432/app",
    "postgres://admin:s3cret@10.0.0.5/db?sslmode=require",
    "redis://:onlypass@cache.test:6379",
    "http://host.test/no/userinfo",
    "not a url at all",
];

#[test]
fn the_scrub_set_and_mask_url_agree_and_strip_userinfo_drops_it() {
    let scrub = Scrub::new();
    for url in CORPUS {
        assert_eq!(scrub.text(url), mask_url(url), "{url}");
    }
    assert!(!mask_url(CORPUS[1]).contains("s3cret"));
    assert_eq!(strip_userinfo(CORPUS[0]), "https://db.test:5432/app");
    assert_eq!(strip_userinfo(CORPUS[3]), CORPUS[3]);
}

#[test]
#[ignore = "owner: W1-C1A"]
fn config_validate_egress_and_connector_masking_agree_on_the_corpus() {
    todo!("owner: W1-C1A (C-SCRUB-ONE)")
}
