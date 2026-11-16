// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! `spdx-headers`: a failing fixture the check must find, a passing one it must not, and the real tree.

use super::repo_root;
use super::spdx::{header_finding, in_scope, spdx_headers};

#[test]
fn a_header_in_the_first_lines_passes() {
    let rust = "// SPDX-License-Identifier: Apache-2.0\n// Copyright (C) 2026 Busbar Inc\nfn f() {}\n";
    assert_eq!(header_finding("a.rs", rust), None);
    let yaml = "# SPDX-License-Identifier: Apache-2.0\nlisten: x\n";
    assert_eq!(header_finding("tests/migration-corpus/a.yaml", yaml), None);
    let shebang = "#!/usr/bin/env rust-script\n\n// SPDX-License-Identifier: Apache-2.0\n";
    assert_eq!(header_finding("b.rs", shebang), None);
}

#[test]
fn a_missing_header_is_found() {
    let found = header_finding("a.rs", "fn f() {}\n").expect("a finding");
    assert!(
        found.starts_with("a.rs: no `SPDX-License-Identifier: Apache-2.0`"),
        "{found}"
    );
    // Too far down is as good as absent.
    let late = "\n\n\n\n\n// SPDX-License-Identifier: Apache-2.0\n";
    assert!(header_finding("a.rs", late).is_some());
}

#[test]
fn another_licence_is_found() {
    let agpl = format!("# SPDX-License-Identifier: {}-3.0-or-later\n", "AGPL");
    let found = header_finding("tests/migration-corpus/a.yaml", &agpl).expect("a finding");
    assert!(found.contains("names `AGPL-3.0-or-later`"), "{found}");
    // Apache-2.0 plus an exception is not the bare identifier.
    let with = "// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception\n";
    assert!(header_finding("a.rs", with).is_some());
}

#[test]
fn a_second_conflicting_header_is_refused() {
    let conflicting = "// SPDX-License-Identifier: Apache-2.0\n// SPDX-License-Identifier: MIT\n";
    assert!(header_finding("a.rs", conflicting).is_some());
}

#[test]
fn scope_is_rust_and_the_migration_corpus() {
    assert!(in_scope("crates/busbar/src/main.rs"));
    assert!(in_scope(
        "tests/migration-corpus/from-tags/v1.0.0_config.yaml"
    ));
    assert!(!in_scope("providers.yaml"));
    assert!(!in_scope("docs/a.md"));
}

#[test]
fn the_real_tree_is_clean() {
    let findings = spdx_headers(&repo_root()).expect("git checkout");
    assert!(findings.is_empty(), "{findings:#?}");
}
