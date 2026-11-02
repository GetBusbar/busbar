//! The protocol seam names no transport's types (BUSBAR-1.6.0.md Part 2 #49, "core names zero plane

/// A claims predicate reads a head field by name in any case, and the first field whose value is

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
