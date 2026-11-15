// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! (u) the patch writer is byte-exact: the stamp is the only change.

use super::*;

#[test]
fn the_stamp_opens_the_document_after_its_leading_comments() {
    let source =
        "%YAML 1.2\n---\n# fleet A\n\n# keys:\nlisten: \"0.0.0.0:8080\"\nhooks: &h {a: 1}\n";
    let written = stamp(source, 1).unwrap();
    assert_eq!(
        written,
        "%YAML 1.2\n---\n# fleet A\n\n# keys:\nconfig_version: 1\nlisten: \"0.0.0.0:8080\"\nhooks: &h {a: 1}\n"
    );
    assert!(proof_two(source, &written, 33, "config_version: 1\n".len()));
}

#[test]
fn a_document_with_no_key_gets_the_stamp_alone() {
    assert_eq!(
        stamp("# only a comment", 1).unwrap(),
        "# only a comment\nconfig_version: 1\n"
    );
    assert_eq!(stamp("", 1).unwrap(), "config_version: 1\n");
}

#[test]
fn a_root_the_stamp_cannot_open_is_refused_by_proof_one() {
    for source in [
        "{listen: x}\n",
        "- a\n- b\n",
        "  listen: x\n  admin_listen: y\n",
    ] {
        let refused = stamp(source, 1).unwrap_err();
        assert_eq!(refused.word(), "CONFIG", "{source:?}");
    }
}
