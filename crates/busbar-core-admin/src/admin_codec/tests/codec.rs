//! Tests for `codec.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

/// The two envelope pointers spell the kernel's own reserved transport fact keys.
///
/// The envelope's two members ARE the request line's structural values, and the kernel reserves
/// the spelling of both. Three planes each guessed `"path"` before the constants existed; this
/// is what stops a fourth guess landing here.
#[test]
fn the_envelope_pointers_spell_the_reserved_keys() {
    use busbar_contract::transport::facts as tfacts;
    assert_eq!(PTR_METHOD, format!("/{}", tfacts::METHOD));
    assert_eq!(PTR_PATH, format!("/{}", tfacts::PATH));
}

#[test]
fn substitutes_info_version_and_leaves_everything_else_byte_identical() {
    let body = br#"{"info":{"title":"busbar admin API","version":"1.5.5"},"paths":{}}"#;
    let rendered = substitute_info_version(body, "1.6.0").expect("info.version present");
    let text = String::from_utf8(rendered).unwrap();
    assert_eq!(
        text,
        r#"{"info":{"title":"busbar admin API","version":"1.6.0"},"paths":{}}"#
    );
}

#[test]
fn absent_info_falls_back_to_none() {
    let body = br#"{"paths":{}}"#;
    assert!(substitute_info_version(body, "1.6.0").is_none());
}

#[test]
fn identify_resolves_every_documented_body_field_verb() {
    // A representative sample, not the full 18: exercised in the table test module instead.
    let body = br#"{"method":"POST","path":"/api/v1/admin/keys","body":{"name":"k1"}}"#;
    let decoded = identify(body).expect("decodes");
    assert_eq!(decoded.entry.verb, "post_keys");
    assert!(decoded.params.is_empty());
}

/// A query string names no operation, so it resolves the same row with it as without.
///
/// The envelope carries the request TARGET, and a target is a path plus whatever the caller
/// appended to it. `verbs::resolve` — the lookup the composition root runs — has always cut at
/// `?`/`#` before matching; this step used to hand the raw target straight to the table and so
/// answered "no such operation" for every paged read a caller actually writes.
#[test]
fn a_query_string_resolves_the_same_verb_as_a_bare_path() {
    let bare = br#"{"method":"GET","path":"/api/v1/admin/audit","body":{}}"#;
    let paged = br#"{"method":"GET","path":"/api/v1/admin/audit?limit=4","body":{}}"#;
    let fragment = br#"{"method":"GET","path":"/api/v1/admin/audit#top","body":{}}"#;
    let verb = identify(bare).expect("decodes").entry.verb;
    assert_eq!(identify(paged).expect("decodes").entry.verb, verb);
    assert_eq!(identify(fragment).expect("decodes").entry.verb, verb);
}

/// A body still arriving is not a body that was refused.
#[test]
fn a_half_arrived_envelope_is_not_yet_an_envelope() {
    let whole = br#"{"method":"POST","path":"/api/v1/admin/keys","body":{"name":"k1"}}"#;
    assert!(envelope_is_complete(whole));
    for cut in 1..whole.len() {
        assert!(
            !envelope_is_complete(&whole[..cut]),
            "cut at {cut} closed an envelope that has not closed"
        );
    }
}

/// A brace inside a string value neither closes the envelope early nor holds it open.
#[test]
fn a_brace_inside_a_string_is_not_structure() {
    assert!(envelope_is_complete(
        br#"{"method":"POST","path":"/api/v1/admin/keys","body":{"name":"a}b{c"}}"#
    ));
    assert!(!envelope_is_complete(
        br#"{"method":"POST","path":"/api/v1/admin/keys","body":{"name":"a}b"#
    ));
    // an escaped quote does not end the string, so the brace after it is still text
    assert!(envelope_is_complete(br#"{"a":"x\"}y"}"#));
}

/// Bytes no further frame can rescue are not `NeedMore`: they are for `identify` to refuse.
#[test]
fn bytes_that_are_not_an_object_at_all_are_complete() {
    assert!(envelope_is_complete(b""));
    assert!(envelope_is_complete(b"   "));
    assert!(envelope_is_complete(b"[1,2,3]"));
    assert!(envelope_is_complete(b"not json"));
}

/// The cut runs before the path parameters are captured, so a trailing query never lands in one.
#[test]
fn a_query_string_is_not_captured_into_a_path_parameter() {
    let body = br#"{"method":"GET","path":"/api/v1/admin/keys/xyz?verbose=1","body":{}}"#;
    let decoded = identify(body).expect("decodes");
    assert_eq!(decoded.entry.verb, "get_keys_id");
    assert_eq!(decoded.params, vec![("id", "xyz")]);
}
