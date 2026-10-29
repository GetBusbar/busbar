// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A record's fields as a backend stores them: the scope columns keep the omitted grant and the
//! empty grant apart and never widen a malformed one; a `u64` past `i64::MAX` is refused in words,
//! or pinned for a counter; a negative counter reads as zero.

use super::*;

fn scope(kind: &str, value: &str) -> ScopeRef {
    ScopeRef {
        kind: kind.to_string(),
        value: value.to_string(),
    }
}

/// The omitted grant is two NULLs; an empty grant writes `[]`; pools are 1.5.x's array of names and
/// every other kind is `{kind: [value, ...]}` in kind order.
#[test]
fn scopes_are_written_as_two_columns() {
    assert_eq!(scope_columns(None), (None, None));
    assert_eq!(scope_columns(Some(&[])), (Some("[]".to_string()), None));
    assert_eq!(
        scope_columns(Some(&[ScopeRef::pool("a"), ScopeRef::pool("b")])),
        (Some(r#"["a","b"]"#.to_string()), None)
    );
    assert_eq!(
        scope_columns(Some(&[
            scope("mcp_server", "m2"),
            ScopeRef::pool("a"),
            scope("agent", "x"),
            scope("mcp_server", "m1"),
        ])),
        (
            Some(r#"["a"]"#.to_string()),
            Some(r#"{"agent":["x"],"mcp_server":["m2","m1"]}"#.to_string())
        )
    );
}

/// What is written reads back: the omitted grant as `None`, the empty grant as `Some([])`, a mixed
/// grant pools first, then every other kind in kind order.
#[test]
fn scopes_read_back_as_written() {
    for grant in [
        None,
        Some(vec![]),
        Some(vec![ScopeRef::pool("a")]),
        Some(vec![scope("agent", "x")]),
        Some(vec![
            ScopeRef::pool("a"),
            scope("agent", "x"),
            scope("mcp_server", "m2"),
            scope("mcp_server", "m1"),
        ]),
    ] {
        let (pools, by_kind) = scope_columns(grant.as_deref());
        assert_eq!(scopes_from_columns(pools, by_kind), grant);
    }
}

/// A column that does not parse adds nothing: never the wildcard, never a wider grant. Surrounding
/// whitespace is read through.
#[test]
fn a_malformed_column_reads_as_the_restrictive_grant() {
    assert_eq!(
        scopes_from_columns(Some("not json".to_string()), None),
        Some(vec![])
    );
    assert_eq!(
        scopes_from_columns(None, Some("{".to_string())),
        Some(vec![])
    );
    assert_eq!(
        scopes_from_columns(Some(r#" ["a"] "#.to_string()), Some("[1]".to_string())),
        Some(vec![ScopeRef::pool("a")])
    );
}

/// A value a signed column cannot hold is refused naming the method and the field; one it can hold
/// is stored as itself.
#[test]
fn a_value_past_i64_max_is_refused_in_words() {
    assert_eq!(storable_i64("append_audit", "seq", 7).expect("held"), 7);
    let max = u64::try_from(i64::MAX).expect("i64::MAX is a u64");
    assert_eq!(
        storable_i64("append_audit", "seq", max).expect("held"),
        i64::MAX
    );
    let e = storable_i64("append_audit", "seq", max + 1).expect_err("refused");
    assert_eq!(
        e.0,
        format!(
            "append_audit: seq {} exceeds the storable range (i64::MAX); refusing to store a row \
             that would not read back as itself",
            max + 1
        )
    );
}

/// A counter pins at `i64::MAX` on the way in and reads a negative as `0` on the way out.
#[test]
fn counters_pin_never_wrap() {
    assert_eq!(clamp(5), 5);
    assert_eq!(clamp(u64::MAX), i64::MAX);
    assert_eq!(read_u64(5), 5);
    assert_eq!(read_u64(-1), 0);
    assert_eq!(read_u64(i64::MIN), 0);
}

#[test]
fn prefix_end_carries_past_trailing_0xff_and_has_no_successor_for_all_0xff_or_empty() {
    assert_eq!(prefix_end(b"a"), Some(b"b".to_vec()));
    assert_eq!(prefix_end(b"b\xff"), Some(b"c".to_vec()));
    assert_eq!(prefix_end(b"b\xff\xff"), Some(b"c".to_vec()));
    assert_eq!(prefix_end(b"ab"), Some(b"ac".to_vec()));
    assert_eq!(prefix_end(b"\xff\xff"), None);
    assert_eq!(prefix_end(b""), None);
}
