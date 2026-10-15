//! The protocol seam names no transport's types (BUSBAR-1.6.0.md Part 2 #49, "core names zero plane
//! types"; Part 4: every ABI shape lives in busbar-contract and is neutral; TODO row 34c).
//!
//! `protocol.rs` is the vocabulary a dialect implements and the kernel reads back. A head crosses it
//! as [`HeadFields`](busbar_contract::protocol::HeadFields) pairs and a status as a `u16`; the
//! kernel converts to and from its transport's header and status types at its own edges. The check
//! is a source scan rather than a type assertion, because the property is "this path appears
//! nowhere", which no type can state about itself.

/// `protocol.rs`, as written.
fn protocol_source() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/protocol.rs");
    std::fs::read_to_string(&path).expect("protocol.rs is readable")
}

/// No line of `protocol.rs` reaches into the `http` crate: no `use http`, no `http::` path.
#[test]
fn the_protocol_seam_names_no_http_type() {
    let offenders: Vec<String> = protocol_source()
        .lines()
        .enumerate()
        .filter(|(_, line)| line.contains("http::") || line.trim_start().starts_with("use http"))
        .map(|(i, line)| format!("protocol.rs:{}: {}", i + 1, line.trim()))
        .collect();
    assert!(
        offenders.is_empty(),
        "the protocol seam names the http crate's types: {offenders:#?}"
    );
}

/// A claims predicate reads a head field by name in any case, and the first field whose value is
/// a legal header value is the one it reads: an earlier field carrying a control byte is passed
/// over, exactly as a header map built from the same fields would never have held it.
#[test]
fn a_head_field_is_the_first_legal_value_under_its_name_in_any_case() {
    use busbar_contract::protocol::head_field;

    let fields: &[(&[u8], &[u8])] = &[
        (b"Content-Type", b"application/json"),
        (b"Authorization", b"bad\nvalue"),
        (b"AUTHORIZATION", b"AWS4-HMAC-SHA256 Credential=x"),
        (b"authorization", b"Bearer second"),
        (b"x-tabbed", b"a\tb"),
    ];
    assert_eq!(
        head_field(fields, "authorization"),
        Some(&b"AWS4-HMAC-SHA256 Credential=x"[..])
    );
    assert_eq!(
        head_field(fields, "content-type"),
        Some(&b"application/json"[..])
    );
    assert_eq!(head_field(fields, "x-tabbed"), Some(&b"a\tb"[..]));
    assert_eq!(head_field(fields, "x-api-key"), None);
    let deleted: &[(&[u8], &[u8])] = &[(b"x-del", b"a\x7fb")];
    assert_eq!(head_field(deleted, "x-del"), None);
}
