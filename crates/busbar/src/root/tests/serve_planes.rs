// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::root::test_plugins::{missing, BUILD_BUSBAR_EXAMPLES};

#[test]
#[should_panic(expected = "is not built: run")]
fn a_missing_fixture_cdylib_fails_the_test_and_names_its_build() {
    missing("no_such_fixture", BUILD_BUSBAR_EXAMPLES);
}
