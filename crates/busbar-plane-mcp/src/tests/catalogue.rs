//! Tests for `catalogue.rs`. Lifted out of the implementation file so its line count measures
//! implementation and nothing else; still a direct child module, so `use super::*` reaches the
//! private items it always did.

use super::{wire_of, Row, RowKind, MEMBER_KIND, MEMBER_NAME, MEMBER_SERVER, MEMBER_WIRE};

fn a_row(kind: RowKind, name: &str) -> Row {
    Row {
        kind,
        server: "fs".to_string(),
        name: name.to_string(),
        wire: serde_json::json!({ "name": name, "description": "d" }),
    }
}

/// A row survives the trip through its own record body unchanged.
///
/// The round trip is the whole of the face: the root writes rows in this grammar and reads them
/// back through the record leg, so a member the encoder writes and the decoder drops is a member a
/// listing loses between boot and the wire.
#[test]
fn a_row_round_trips_through_its_record_body() {
    for kind in RowKind::ALL {
        let row = a_row(*kind, "fs_grep");
        let body = row.encode().expect("a row encodes");
        assert_eq!(Row::decode(&body), Some(row), "{kind:?} did not round-trip");
    }
}

/// The record body's grammar is PINNED, member by member.
///
/// Written out rather than round-tripped, because a round trip proves the encoder and the decoder
/// agree with each other and not that either agrees with the root that writes rows in this grammar.
#[test]
fn the_record_body_grammar_is_the_declared_four_members() {
    let body = a_row(RowKind::Prompt, "fs_p")
        .encode()
        .expect("a row encodes");
    let value: serde_json::Value = serde_json::from_slice(&body).expect("the body is a document");
    assert_eq!(
        value,
        serde_json::json!({
            MEMBER_KIND: "prompt",
            MEMBER_SERVER: "fs",
            MEMBER_NAME: "fs_p",
            MEMBER_WIRE: { "name": "fs_p", "description": "d" },
        })
    );
    assert_eq!((MEMBER_KIND, MEMBER_SERVER), ("kind", "server"));
    assert_eq!((MEMBER_NAME, MEMBER_WIRE), ("name", "wire"));
}

/// A body that is not a row reads as no row, and a scan skips it rather than composing over it.
///
/// Four shapes of "not a row": not a document, a document missing a member, a kind this grammar
/// does not have, and a coordinate that is not text. Every one is `None`; none is a partial row.
#[test]
fn a_body_that_is_not_a_row_is_no_row() {
    let missing_wire = serde_json::json!({ "kind": "tool", "server": "fs", "name": "x" });
    let unknown_kind =
        serde_json::json!({ "kind": "widget", "server": "fs", "name": "x", "wire": {} });
    let bad_server = serde_json::json!({ "kind": "tool", "server": 7, "name": "x", "wire": {} });
    for body in [
        b"not json".to_vec(),
        serde_json::to_vec(&missing_wire).expect("encodes"),
        serde_json::to_vec(&unknown_kind).expect("encodes"),
        serde_json::to_vec(&bad_server).expect("encodes"),
    ] {
        assert_eq!(Row::decode(&body), None);
    }
    let good = a_row(RowKind::Tool, "fs_grep").encode().expect("encodes");
    let rows = Row::decode_all(&[b"junk".to_vec(), good, b"{}".to_vec()]);
    assert_eq!(rows.len(), 1, "the one row among three bodies");
    assert_eq!(rows[0].name, "fs_grep");
}

/// The kind words are the four the grammar declares, and each parses back to itself.
#[test]
fn the_four_kinds_spell_and_parse() {
    assert_eq!(
        RowKind::ALL.iter().map(|k| k.as_str()).collect::<Vec<_>>(),
        vec!["tool", "prompt", "resource", "resource_template"]
    );
    for kind in RowKind::ALL {
        assert_eq!(RowKind::parse(kind.as_str()), Some(*kind));
    }
    assert_eq!(RowKind::parse("tools"), None, "the plural is not a kind");
}

/// The projection keeps one kind, in the rows' own order, and hands back the wire forms verbatim.
#[test]
fn the_projection_keeps_one_kind_in_row_order() {
    let rows = vec![
        a_row(RowKind::Resource, "fs_z"),
        a_row(RowKind::Tool, "fs_b"),
        a_row(RowKind::Resource, "fs_a"),
    ];
    assert_eq!(
        wire_of(&rows, RowKind::Resource),
        vec![
            serde_json::json!({ "name": "fs_z", "description": "d" }),
            serde_json::json!({ "name": "fs_a", "description": "d" }),
        ],
        "two resources, in the order handed in and not re-sorted"
    );
    assert_eq!(
        wire_of(&rows, RowKind::Prompt),
        Vec::<serde_json::Value>::new()
    );
}
