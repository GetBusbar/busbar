// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! R34 over core's production source (OBSERVABILITY-HOT-PATH §2.7). The planted-form probe tables
//! went with ruling 308: every escape is now refused outright by bad-patterns BP06, whose own
//! fixtures prove each form, and a probe table of escape text is itself generated escape text.

use crate::{escapes, walk};

#[test]
fn no_disallowed_lint_escape_is_wider_than_one_site_and_one_lint() {
    let found: Vec<String> = walk::production(&["crates"])
        .iter()
        .flat_map(|s| escapes::refusals(&s.rel, &s.file))
        .collect();
    assert!(found.is_empty(), "{}", found.join("\n"));
}
