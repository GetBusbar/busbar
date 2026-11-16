// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `suites::secret` end to end (ABI-MIN3-INTERFACE §14): a `plugin!`-built in-memory secret admitted through
//! `admit_header` and driven through the registry. The red-first proof of the harness and the secret suite.

use busbar_plugin_test::fake_needs::FakeNeeds;
use busbar_plugin_test::suites;

use crate::min3_secret::PLUGIN;

#[test]
fn the_secret_suite_passes_over_a_plugin_built_secret() {
    suites::secret(
        PLUGIN.plugin(),
        br#"{"db":"hunter2-zq81","api":"k-93ac0d"}"#,
        FakeNeeds::new(),
        &[
            (b"db", b"hunter2-zq81"),
            (br#"{"name":"api"}"#, b"k-93ac0d"),
        ],
        &[
            br#"{"name":"busbar-suite-no-such-secret-7f3a"}"#,
            b"busbar-suite-no-such-secret-7f3a-2",
        ],
    );
}
