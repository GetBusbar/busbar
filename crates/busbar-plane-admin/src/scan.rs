//! A tiny, hand-rolled, non-allocating JSON span scanner.
//!
//! The wire shape this plane decodes is a compact JSON envelope the HTTP transport is assumed to
//! have normalized an inbound request into: `{"method":"GET","path":"/api/v1/admin/keys","body":{}}`.
//! (Full HTTP/1.1 text framing — request line, headers, chunked bodies — is a transport's job, not a
//! plane's: "planes do no I/O" and a plane "never holds a connection". This crate owns only the
//! translation from that already-framed shape to a `KernelVerb` destination and back; see the crate
//! root doc comment for the scope boundary this draws around `busbar-transport-http`'s own contract.)
//!
//! This scanner finds the byte range of one field's value inside a flat JSON object without parsing
//! the whole document and without allocating: it walks bytes, tracks brace/bracket depth to skip
//! sibling values it was not asked for, and returns a [`Span`] into the ORIGINAL buffer. It is
//! deliberately not a general JSON parser — no unescaping, no nesting beyond depth-tracked skipping —
//! because the only two things this plane ever needs from a body are "the value of this top-level
//! key" and "the value of this key one level inside another key's object", and a general parser would
//! buy nothing a plane is allowed to keep (a plane holds no interior state and performs no I/O; a
//! parse tree is neither).
//!
//! Every span this module returns borrows the same buffer it was handed. Nothing here allocates,
//! matching the "pure over its inputs, no input or output of its own" rule the plane trait's own
//! doc comment states.

use busbar_contract::bounded::Span;

/// A cursor over a byte slice, advanced by the small set of JSON tokens this scanner understands.
struct Scanner<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Scanner<'a> {
    fn new(bytes: &'a [u8], pos: usize) -> Self {
        Self { bytes, pos }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    /// Parse a JSON string starting at the opening quote. Returns the span of the CONTENT, excluding
    /// the surrounding quotes. Escapes are skipped over (two bytes at a time) rather than decoded:
    /// this scanner never needs the unescaped value, only its raw span, and every field this plane
    /// declares is escape-free in practice (paths, verb names, ids).
    fn string_content(&mut self) -> Option<Span> {
        if self.peek()? != b'"' {
            return None;
        }
        self.pos += 1;
        let start = self.pos;
        loop {
            match self.peek()? {
                b'\\' => self.pos += 2,
                b'"' => {
                    let end = self.pos;
                    self.pos += 1;
                    return Some(Span { start, end });
                }
                _ => self.pos += 1,
            }
        }
    }

    /// Skip one JSON value of any shape at the current position, returning its whole raw span
    /// (quotes included for a string; braces/brackets included for an object/array).
    fn skip_value(&mut self) -> Option<Span> {
        self.skip_ws();
        let start = self.pos;
        match self.peek()? {
            b'"' => {
                self.string_content()?;
            }
            open @ (b'{' | b'[') => {
                let close = if open == b'{' { b'}' } else { b']' };
                let mut depth: i32 = 0;
                loop {
                    let c = self.peek()?;
                    if c == b'"' {
                        self.string_content()?;
                        continue;
                    }
                    if c == open {
                        depth += 1;
                    } else if c == close {
                        depth -= 1;
                        self.pos += 1;
                        if depth == 0 {
                            break;
                        }
                        continue;
                    }
                    self.pos += 1;
                }
            }
            _ => {
                // A number, `true`, `false` or `null`: run to the next structural byte.
                while let Some(c) = self.peek() {
                    if matches!(c, b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r') {
                        break;
                    }
                    self.pos += 1;
                }
            }
        }
        Some(Span {
            start,
            end: self.pos,
        })
    }
}

/// The span of one field's value inside the JSON object occupying `within`.
///
/// `within` must start at the object's opening `{` (or at whitespace before it). A string value's
/// span is its CONTENT (unquoted); every other value's span is its raw token, including an object or
/// array's braces. Returns `None` when the key is absent or `within` is not an object.
#[must_use]
pub(crate) fn object_field(bytes: &[u8], within: Span, key: &str) -> Option<Span> {
    let mut sc = Scanner::new(bytes, within.start);
    sc.skip_ws();
    if sc.peek()? != b'{' {
        return None;
    }
    sc.pos += 1;
    loop {
        sc.skip_ws();
        match sc.peek()? {
            b'}' => return None,
            b',' => {
                sc.pos += 1;
            }
            b'"' => {
                let k = sc.string_content()?;
                let k_str = core::str::from_utf8(&bytes[k.start..k.end]).ok()?;
                sc.skip_ws();
                if sc.peek()? != b':' {
                    return None;
                }
                sc.pos += 1;
                sc.skip_ws();
                if k_str == key {
                    return if sc.peek()? == b'"' {
                        sc.string_content()
                    } else {
                        sc.skip_value()
                    };
                }
                sc.skip_value()?;
            }
            _ => return None,
        }
    }
}

/// The whole-buffer span, for a top-level object field lookup.
#[must_use]
pub(crate) fn whole(bytes: &[u8]) -> Span {
    Span {
        start: 0,
        end: bytes.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_top_level_string_field() {
        let body = br#"{"method":"GET","path":"/api/v1/admin/keys"}"#;
        let span = object_field(body, whole(body), "method").expect("method present");
        assert_eq!(&body[span.start..span.end], b"GET");
        let span = object_field(body, whole(body), "path").expect("path present");
        assert_eq!(&body[span.start..span.end], b"/api/v1/admin/keys");
    }

    #[test]
    fn skips_sibling_objects_and_arrays() {
        let body = br#"{"a":{"nested":[1,2,"x"]},"b":"value"}"#;
        let span = object_field(body, whole(body), "b").expect("b present");
        assert_eq!(&body[span.start..span.end], b"value");
    }

    #[test]
    fn reads_a_nested_object_field() {
        let body =
            br#"{"method":"POST","path":"/api/v1/admin/keys","body":{"name":"k1","group":"g"}}"#;
        let body_span = object_field(body, whole(body), "body").expect("body present");
        let name = object_field(body, body_span, "name").expect("name present");
        assert_eq!(&body[name.start..name.end], b"k1");
    }

    #[test]
    fn absent_key_is_none() {
        let body = br#"{"method":"GET","path":"/x"}"#;
        assert!(object_field(body, whole(body), "body").is_none());
    }
}
