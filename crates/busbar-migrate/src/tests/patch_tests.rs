// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! (u) the patch writer is byte-exact: the stamp is the only change.

use busbar_contract::yaml::{self, MappingExt, Pairs, Value, ValueExt};

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

/// Rewrite `source` to its tree after `change`, through the patch writer.
fn patched(source: &str, change: impl FnOnce(&mut Pairs)) -> Result<String, Refusal> {
    let before: Value = yaml::from_str(source).unwrap();
    let mut after = before.clone();
    change(after.as_mapping_mut().unwrap());
    rewrite(source, &before, &after, "config.yaml")
}

fn module(word: &str) -> Value {
    Value::Map(vec![(Value::from("module"), Value::from(word))])
}

/// (u)(2): an added top-level key lands where the 1.6.0 schema declares it, after the last key the
/// schema orders before it, at the siblings' indentation; nothing else moves.
#[test]
fn an_added_key_lands_at_the_schema_position() {
    let source = "# keys\nlisten: x\nmodels: {}   # none yet\n\nsecurity: {}\n";
    let out = patched(source, |root| schema_insert(root, "store", module("m"))).unwrap();
    assert_eq!(
        out,
        "# keys\nlisten: x\nmodels: {}   # none yet\nstore:\n  module: m\n\nsecurity: {}\n"
    );
    // A nested entry lands after its preceding sibling, at that sibling's indentation.
    let source = "auth:\n    chain: [sso]   # one\n\nmodels: {}\n";
    let out = patched(source, |root| {
        let Some(Value::Map(auth)) = root.get_key_mut("auth") else {
            panic!("auth")
        };
        auth.push((Value::from("role_bindings"), Value::Map(Vec::new())));
    })
    .unwrap();
    assert_eq!(
        out,
        "auth:\n    chain: [sso]   # one\n    role_bindings: {}\n\nmodels: {}\n"
    );
}

/// (u)(3): proof one, the written bytes re-read as the planned tree; proof two, the written bytes
/// outside the changed spans are the source's: comments, quoting, anchors and blank lines survive.
/// A re-serialize of the planned tree (the planted bad writer) would lose them.
#[test]
fn the_patch_writer_changes_only_the_changed_spans() {
    let source = "\
# fleet
listen: \"0.0.0.0:8080\" # data
base: &b {url: 'https://x'}

security:
  allow_all_metadata: true # retired
  blocked_metadata_hosts:
    - 169.254.169.254
    - db.1
    - metadata.corp
store:
  module: sqlite
";
    let mut planned = None;
    let out = patched(source, |root| {
        let Some(Value::Map(security)) = root.get_key_mut("security") else {
            panic!("security")
        };
        security.retain(|(key, _)| key.as_str() != Some("allow_all_metadata"));
        let Some(Value::Array(hosts)) = security.get_key_mut("blocked_metadata_hosts") else {
            panic!("hosts")
        };
        hosts.retain(|host| host.as_str() != Some("db.1"));
        let Some(Value::Map(store)) = root.get_key_mut("store") else {
            panic!("store")
        };
        store.insert_key("module", Value::from("postgres"));
        planned = Some(Value::Map(root.clone()));
    })
    .unwrap();
    assert_eq!(
        out,
        "\
# fleet
listen: \"0.0.0.0:8080\" # data
base: &b {url: 'https://x'}

security:
  blocked_metadata_hosts:
    - 169.254.169.254
    - metadata.corp
store:
  module: postgres
"
    );
    let planned = planned.unwrap();
    let reread: Value = yaml::from_str(&out).unwrap();
    assert!(yaml::same_tree(&reread, &planned), "proof one");
    let reserialized = yaml::to_string(&planned).unwrap();
    assert_ne!(reserialized, out, "a re-serialize is not the patch");
    assert!(
        !reserialized.contains("# fleet"),
        "a re-serialize loses the comments"
    );
}

/// An edit inside a flow collection re-emits that collection, copying every unchanged key and
/// scalar from its source slice.
#[test]
fn an_edit_inside_a_flow_collection_reemits_it_from_its_source_slices() {
    let out = patched("store: {token: 'x y', size: 0x10}\n", |root| {
        let Some(Value::Map(store)) = root.get_key_mut("store") else {
            panic!("store")
        };
        store.insert(0, (Value::from("module"), Value::from("m")));
    })
    .unwrap();
    assert_eq!(out, "store: {module: m, token: 'x y', size: 0x10}\n");
}

/// An edit the writer cannot place keeps nothing and says where: VERIFY.
#[test]
fn an_edit_the_writer_cannot_place_is_refused_verify() {
    let refused = patched("pools:\n  - a: 1\n    b: 2\n", |root| {
        let Some(Value::Array(pools)) = root.get_key_mut("pools") else {
            panic!("pools")
        };
        let Some(Value::Map(first)) = pools.get_mut(0) else {
            panic!("first")
        };
        first.retain(|(key, _)| key.as_str() != Some("a"));
    })
    .unwrap_err();
    assert_eq!(refused.word(), "VERIFY", "{refused}");
    assert!(refused.to_string().contains("`pools.0`"), "{refused}");
}

// ---- rewrite: the operator's text edited to a planned tree --------------------------------------

fn tree_of(text: &str) -> yaml::Value {
    document(text).unwrap()
}

fn set(tree: &mut yaml::Value, path: &[&str], value: yaml::Value) {
    let (last, parents) = path.split_last().unwrap();
    let mut at = tree;
    for key in parents {
        at = at.as_mapping_mut().unwrap().get_key_mut(*key).unwrap();
    }
    at.as_mapping_mut().unwrap().insert_key(*last, value);
}

fn remove(tree: &mut yaml::Value, path: &[&str]) {
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
    assert_eq!(
        rewrite(source, &tree_of(source), &tree_of(source), "t").unwrap(),
        source
    );
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
        rewrite(source, &tree_of(source), &planned, "t").unwrap(),
        "# top\nlimits:   # tuned\n  max_inbound_concurrent: 512   # old\n  request_body_max_bytes: \"1048576\"\nlisten: 0.0.0.0:8080\n"
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
        rewrite(source, &tree_of(source), &planned, "t").unwrap(),
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
    let written = rewrite(source, &tree_of(source), &planned, "t").unwrap();
    assert!(written.starts_with(source), "{written}");
    assert!(yaml::same_tree(&tree_of(&written), &planned), "{written}");
    let no_newline = "listen: x";
    let mut planned = tree_of(no_newline);
    set(
        &mut planned,
        &["admin_listen"],
        yaml::Value::Text("y".to_owned()),
    );
    let written = rewrite(no_newline, &tree_of(no_newline), &planned, "t").unwrap();
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
    let written = rewrite(source, &tree_of(source), &planned, "t").unwrap();
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
    let refused = rewrite(source, &tree_of(source), &planned, "the test pass").unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(refused.to_string().contains("the test pass"), "{refused}");
}
