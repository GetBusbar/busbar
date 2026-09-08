//! Tests for `classify.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::relayed_header_name;

/// A protocol may declare its relayed header the way its vendor spells it.
///
/// The wire form of a header name is case-insensitive and a declaration is documentation as much
/// as configuration, so a protocol that declares `x-amzn-RequestId` must be relayable. The name
/// is emitted lowercased, which is the same header.
#[test]
fn a_mixed_case_declared_name_is_relayable() {
    let name = relayed_header_name("x-amzn-RequestId").expect("a legal header name");
    assert_eq!(name.as_str(), "x-amzn-requestid");
    // The all-lowercase spelling of the same header lands on the same name, so what a client
    // receives does not depend on which spelling its protocol declared.
    assert_eq!(
        relayed_header_name("x-amzn-requestid").expect("a legal header name"),
        name
    );
    // The name a lookup matched is the name emitted: a map keyed under one spelling answers the
    // other, which is what makes parsing rather than panicking safe here.
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(name, axum::http::HeaderValue::from_static("req-1"));
    assert_eq!(
        headers
            .get("x-amzn-RequestId")
            .and_then(|v| v.to_str().ok()),
        Some("req-1")
    );
}

/// A name that is not a legal header at all is dropped, never relayed and never fatal.
#[test]
fn an_illegal_declared_name_is_dropped_rather_than_fatal() {
    for illegal in ["x amzn requestid", "x-amzn-\u{1f600}", ""] {
        assert!(
            relayed_header_name(illegal).is_none(),
            "{illegal:?} is not a header name and must not be relayed"
        );
    }
}
