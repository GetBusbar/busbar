//! The SHARED READERS' own cases, kept out of `infra.rs` because these prove a byte format rather
//! than a gate: `json_lite` exists to read a committed file whose KEY ORDER IS THE DATA and to
//! write it back exactly as Python wrote it. One differing byte is 144 scopes of noise in the first
//! `cargo xtask ledger sync --write` diff, and a reviewer who sees that noise once stops reading
//! the diff at all.

use xtask::json_lite::{self, Json};

#[test]
fn json_objects_keep_the_order_their_keys_arrived_in() {
    // `qa/teller-steps.json`'s `steps` object IS the Teller step order: `list(steps)` in the
    // Python is the sequence the matrix renders in. A reader that sorts renders a different
    // matrix, and one that appends on reassignment reorders the register on the next `sync`.
    let v = json_lite::parse(r#"{"zeta":1,"alpha":2,"mid":3}"#).unwrap();
    let o = v.as_object().unwrap();
    assert_eq!(o.keys().collect::<Vec<_>>(), vec!["zeta", "alpha", "mid"]);

    let mut o = o.clone();
    o.insert("zeta", Json::Int(9));
    assert_eq!(
        o.keys().collect::<Vec<_>>(),
        vec!["zeta", "alpha", "mid"],
        "reassigning an existing key must keep its position, as Python's dict does — \
         `sync --write` assigns preserved values over a derived scope and must not reorder it"
    );
}

#[test]
fn dump_python_reproduces_indent_one_and_inline_empty_containers() {
    let v = json_lite::parse(r#"{"a":[1,2],"b":{},"c":[],"d":{"e":null}}"#).unwrap();
    assert_eq!(
        json_lite::dump_python(&v),
        "{\n \"a\": [\n  1,\n  2\n ],\n \"b\": {},\n \"c\": [],\n \"d\": {\n  \"e\": null\n }\n}"
    );
}

#[test]
fn dump_python_uses_pythons_escape_table_and_not_serde_jsons() {
    // `ensure_ascii=False`: the em-dash in the config snapshot's `_meta.description` and every
    // non-ASCII byte in an auditor name pass through as UTF-8, never as `\uXXXX`. `/` is not
    // escaped. C0 controls outside the seven short forms are `\u00xx`, lowercase hex.
    let mut o = json_lite::Obj::new();
    o.insert("s", Json::Str("a—b/c\t\n\u{1}\"\\".to_string()));
    assert_eq!(
        json_lite::dump_python(&Json::Object(o)),
        "{\n \"s\": \"a—b/c\\t\\n\\u0001\\\"\\\\\"\n}"
    );
}

#[test]
fn the_committed_audit_register_round_trips_byte_for_byte() {
    // THE PARITY PROOF FOR THE WRITER, and the reason this module exists rather than a
    // `preserve_order` feature flag on a dependency eleven crates share: read the register Python
    // wrote and write it back unchanged.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("qa/audit-ledger.json");
    let text = std::fs::read_to_string(&path).unwrap();
    let v = json_lite::parse(&text).unwrap();
    assert_eq!(
        format!("{}\n", json_lite::dump_python(&v)),
        text,
        "the Rust writer must reproduce `json.dump(doc, fh, indent=1, ensure_ascii=False, \
         sort_keys=False)` exactly"
    );
}

#[test]
fn the_committed_teller_matrix_round_trips_and_keeps_its_step_order() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("qa/teller-steps.json");
    let text = std::fs::read_to_string(&path).unwrap();
    let v = json_lite::parse(&text).unwrap();
    let steps: Vec<&str> = v.get("steps").as_object().unwrap().keys().collect();
    assert_eq!(
        steps,
        vec![
            "arrival",
            "decode",
            "authenticate",
            "verify",
            "approve",
            "admit",
            "route",
            "meter",
            "audit",
            "exit"
        ],
        "the Teller step order is the file's key order, not an alphabetical one"
    );
}

#[test]
fn the_uncovered_by_design_constant_matches_the_committed_register() {
    // The excuse list is a CONSTANT in Rust and `sync --write` regenerates the file's copy from it,
    // so an excuse is a source edit somebody reviews rather than a line somebody adds to a 147KB
    // JSON file. This pins the transcription: if the two ever disagree, the next `sync --write`
    // silently rewrites 30 excuses and the diff that matters is buried.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("qa/audit-ledger.json");
    let text = std::fs::read_to_string(&path).unwrap();
    let doc = json_lite::parse(&text).unwrap();
    let committed: Vec<(String, String)> = doc
        .get("uncovered_by_design")
        .as_array()
        .unwrap()
        .iter()
        .map(|e| {
            (
                e.get("glob").as_str().unwrap().to_string(),
                e.get("reason").as_str().unwrap().to_string(),
            )
        })
        .collect();
    let ours: Vec<(String, String)> = xtask::audit::UNCOVERED_BY_DESIGN
        .iter()
        .map(|(g, r)| ((*g).to_string(), (*r).to_string()))
        .collect();
    assert_eq!(committed, ours);
}

#[test]
fn a_document_with_trailing_bytes_is_an_error_not_a_shorter_document() {
    assert!(json_lite::parse("{\"a\":1} {\"b\":2}").is_err());
    assert!(
        json_lite::parse("{\"a\":1}\n").is_ok(),
        "trailing whitespace is fine"
    );
    assert!(
        json_lite::parse(r#""\ud800""#).is_err(),
        "an unpaired surrogate must not decode to U+FFFD — a key that did would not compare \
         equal to itself on the next read"
    );
}

// -------------------------------------------------------------------------------------------
// sha256 — the digest the audit register's staleness rests on
// -------------------------------------------------------------------------------------------

#[test]
fn sha256_matches_the_published_vectors() {
    // If this digest is wrong, every one of the register's recorded tree hashes stops matching at
    // once — and 144 scopes reading `stale` looks exactly like a tree nobody has audited.
    assert_eq!(
        xtask::sha256::hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        xtask::sha256::hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        xtask::sha256::hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
    // A message that lands exactly on a block boundary, and a long one that exercises many blocks
    // — the two lengths a hand-written padder gets wrong.
    assert_eq!(
        xtask::sha256::hex(&[b'a'; 64]),
        "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb"
    );
    assert_eq!(
        xtask::sha256::hex(&[b'a'; 1000000]),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
    );
}

#[test]
fn sha256_streams_the_same_digest_it_computes_in_one_shot() {
    // The register hashes a scope one `path<TAB>oid\n` line at a time, so the streaming path is the
    // one that actually runs.
    let mut h = xtask::sha256::Sha256::new();
    for chunk in [
        "ab",
        "cdbcdecdefdefgefghfghighijhijk",
        "ijkljklmklmnlmnomnopnopq",
    ] {
        h.update(chunk.as_bytes());
    }
    assert_eq!(
        h.hexdigest(),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn py_repr_matches_pythons_percent_r_for_the_values_the_gates_print() {
    assert_eq!(json_lite::py_repr("passed"), "'passed'");
    assert_eq!(json_lite::py_repr("it's"), "\"it's\"");
    assert_eq!(json_lite::py_repr_json(&Json::Null), "None");
    assert_eq!(json_lite::py_repr_json(&Json::Bool(true)), "True");
    assert_eq!(json_lite::py_repr_json(&Json::Int(3)), "3");
    assert_eq!(json_lite::py_type_name(&Json::Array(vec![])), "list");
}
