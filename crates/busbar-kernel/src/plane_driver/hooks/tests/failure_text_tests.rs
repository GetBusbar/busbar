// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A hook's failure text reaches the operator's log; it must not split or spoof a log record
//! (Aikido group 58995534, #119).

use super::failure_text;

#[test]
fn a_failure_text_carries_no_line_break_or_terminal_escape() {
    let raw = "boom\nlevel=ERROR forged record\r\n\u{1b}[31mred\u{1b}[0m\u{202e}\u{0}";
    let text = failure_text(raw);
    assert!(
        !text.chars().any(|c| c.is_control()),
        "a control character survived: {text:?}"
    );
    assert!(!text.contains('\u{202e}'), "a bidi override survived");
    assert!(text.starts_with("boom"), "{text:?}");
}

#[test]
fn a_failure_text_is_bounded() {
    let text = failure_text(&"x".repeat(10_000));
    assert_eq!(text.chars().count(), 300, "the text is capped at 300 chars");
}

#[test]
fn an_empty_failure_text_stays_empty() {
    assert_eq!(failure_text(""), "");
}

#[test]
fn a_plain_failure_text_is_kept_whole() {
    let raw = "settings refused: field `limit` must be a number";
    assert_eq!(failure_text(raw), raw);
}
