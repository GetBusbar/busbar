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

// ---- rewrite: the operator's text edited to a planned tree --------------------------------------

fn tree_of(text: &str) -> yaml::Value {
    document(text).unwrap()
}

fn set(tree: &mut yaml::Value, path: &[&str], value: yaml::Value) {
    use busbar_contract::yaml::MappingExt;
    let (last, parents) = path.split_last().unwrap();
    let mut at = tree;
    for key in parents {
        at = at.as_mapping_mut().unwrap().get_key_mut(*key).unwrap();
    }
    at.as_mapping_mut().unwrap().insert_key(*last, value);
}

fn remove(tree: &mut yaml::Value, path: &[&str]) {
    use busbar_contract::yaml::MappingExt;
    let (last, parents) = path.split_last().unwrap();
    let mut at = tree;
    for key in parents {
        at = at.as_mapping_mut().unwrap().get_key_mut(*key).unwrap();
    }
    at.as_mapping_mut()
        .unwrap()
        .retain(|(key, _)| key.as_str() != Some(*last));
}

/// An unchanged tree writes the source back byte for byte.
#[test]
fn an_unchanged_tree_is_the_source() {
    let source = "# c\nlisten: x   # here\nlimits:\n  a: 1\n";
    assert_eq!(rewrite(source, &tree_of(source), "t").unwrap(), source);
}

/// A changed nested scalar is the only span rewritten: comments, quoting and every other line
/// stay the operator's.
#[test]
fn a_nested_change_rewrites_only_its_entry() {
    let source = "# top\nlimits:   # tuned\n  max_inbound_concurrent: 100   # old\n  request_body_max_bytes: \"1048576\"\nlisten: 0.0.0.0:8080\n";
    let mut planned = tree_of(source);
    set(
        &mut planned,
        &["limits", "max_inbound_concurrent"],
        yaml::Value::from(512u64),
    );
    assert_eq!(
        rewrite(source, &planned, "t").unwrap(),
        "# top\nlimits:   # tuned\n  max_inbound_concurrent: 512\n  request_body_max_bytes: \"1048576\"\nlisten: 0.0.0.0:8080\n"
    );
}

/// Removing entries deletes exactly their lines (at any depth); trailing comments stay.
#[test]
fn a_removed_entry_takes_only_its_lines() {
    let source = "hooks:\n  a:\n    module: x\n  # about b\n  b:\n    module: y\npools:\n  hooks: [a, b]\n# end\n";
    let mut planned = tree_of(source);
    remove(&mut planned, &["hooks", "a"]);
    remove(&mut planned, &["pools"]);
    assert_eq!(
        rewrite(source, &planned, "t").unwrap(),
        "hooks:\n  # about b\n  b:\n    module: y\n# end\n"
    );
}

/// Inserted entries land after the last entry of their mapping, in the planned order, and read
/// back as planned; the source's lines are kept.
#[test]
fn inserted_entries_read_back_as_planned() {
    let source = "listen: x\nhooks:\n  a:\n    module: x\n";
    let mut planned = tree_of(source);
    set(
        &mut planned,
        &["hooks", "b"],
        tree_of("module: y\nphase: [request]\nsettings:\n  k: v\n"),
    );
    set(&mut planned, &["groups"], tree_of("G:\n  enabled: true\n"));
    let written = rewrite(source, &planned, "t").unwrap();
    assert!(written.starts_with(source), "{written}");
    assert!(yaml::same_tree(&tree_of(&written), &planned), "{written}");
    let no_newline = "listen: x";
    let mut planned = tree_of(no_newline);
    set(
        &mut planned,
        &["admin_listen"],
        yaml::Value::Text("y".to_owned()),
    );
    let written = rewrite(no_newline, &planned, "t").unwrap();
    assert!(yaml::same_tree(&tree_of(&written), &planned), "{written}");
}

/// A value whose text is not a block mapping (a flow mapping, an indentless sequence beside a
/// change) is rewritten whole and reads back as planned; the untouched siblings keep their bytes.
#[test]
fn a_flow_value_is_rewritten_whole() {
    let source = "limits: {a: 1, b: 2}\npools:\n  hooks:\n  - a\n  main:\n    hooks: [x]\n";
    let mut planned = tree_of(source);
    set(&mut planned, &["limits", "a"], yaml::Value::from(5u64));
    set(
        &mut planned,
        &["pools", "main", "hooks"],
        yaml::Value::Array(vec![yaml::Value::Text("y".to_owned())]),
    );
    let written = rewrite(source, &planned, "t").unwrap();
    assert!(yaml::same_tree(&tree_of(&written), &planned), "{written}");
    assert!(
        written.contains("pools:\n  hooks:\n  - a\n  main:\n"),
        "{written}"
    );
}

/// An edit whose rewritten text does not read back as planned (here the anchor another entry
/// aliases would be lost) refuses CONFIG naming the pass (proof one); nothing is guessed.
#[test]
fn an_unplaceable_edit_is_refused() {
    let source = "base: &b\n  x: 1\nother: *b\n";
    let mut planned = tree_of(source);
    set(&mut planned, &["base", "x"], yaml::Value::from(2u64));
    let refused = rewrite(source, &planned, "the test pass").unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(refused.to_string().contains("the test pass"), "{refused}");
}
