//! Tests for `control.rs`. Lifted out of the implementation file so its line count
//! measures implementation and nothing else; still a direct child module, so `use
//! super::*` reaches the private items it always did.

use super::*;

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
