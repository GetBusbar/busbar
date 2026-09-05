//! Finding the byte range of a named place in a body, without parsing the body.
//!
//! The kernel reads a body as SPANS, never as a parsed document, and the plane is what tells it
//! where the spans are. So this is a scanner, not a parser: it walks the bytes once, keeps track of
//! which member it is inside, and records the start and end of the values it was asked for. It
//! allocates nothing per byte, it copies no part of the body, and it answers nothing about a place
//! it was not asked about.
//!
//! It understands only the nesting the pointers need — objects, and the arrays it has to step over —
//! because every place this plane names is a member of an object: the method name, the request
//! identifier, the parameters, the task identifier and the task's reported state. A pointer that
//! names an array element resolves to nothing rather than to a guess.
//!
//! ONE HONEST NOTE. A scanner of this shape already exists beside the other planes. The kernel owns
//! the span grammar and the design says so, but the contract does not hand a plane a scanner, so
//! each plane carries its own reading of the same grammar. That is a finding about the contract, not
//! a decision taken here, and it is written down in the crate's own notes.

use busbar_contract::bounded::Span;

/// The most nesting levels the scanner tracks by name.
///
/// Deeper structure is still stepped over correctly; it simply stops contributing member names to
/// the path, which is right, because no pointer this plane declares reaches that deep.
const MAX_DEPTH: usize = 16;

/// Resolve each requested pointer against a body, in the order the pointers were given.
///
/// A pointer the scanner does not reach is ABSENT from the result rather than present and empty.
/// "the caller named no task" and "the caller named an empty task" are different facts, and the loop
/// settles them differently, so they must not arrive here as the same answer.
#[must_use]
pub fn resolve<'a>(body: &[u8], pointers: &[&'a str]) -> Vec<(&'a str, Span)> {
    let mut found: Vec<(&'a str, Span)> = Vec::with_capacity(pointers.len());
    // The member name at each open object level, as a byte range into the body.
    let mut path: [(usize, usize); MAX_DEPTH] = [(0, 0); MAX_DEPTH];
    // Whether the level at each depth is an object; an array level contributes no member name.
    let mut is_object: [bool; MAX_DEPTH] = [false; MAX_DEPTH];
    let mut depth: usize = 0;
    // The member name most recently read at the current level, still waiting for its value.
    let mut pending: Option<(usize, usize)> = None;
    let mut i = 0usize;

    while i < body.len() {
        match body[i] {
            b' ' | b'\t' | b'\n' | b'\r' | b',' | b':' => i += 1,
            b'{' | b'[' => {
                if depth < MAX_DEPTH {
                    is_object[depth] = body[i] == b'{';
                    path[depth] = pending.unwrap_or((0, 0));
                }
                // A container IS a value, so a pointer naming the container gets the whole of it.
                if let Some(name) = pending.take() {
                    let end = skip_value(body, i);
                    record(body, &mut found, pointers, &path, depth, name, i, end);
                }
                depth += 1;
                i += 1;
            }
            b'}' | b']' => {
                depth = depth.saturating_sub(1);
                pending = None;
                i += 1;
            }
            b'"' => {
                let end = skip_string(body, i);
                // Inside an object, a string in name position is a member name; anywhere else it is
                // a value. Name position is "no member is pending at this level".
                let in_object = depth > 0 && depth <= MAX_DEPTH && is_object[depth - 1];
                if in_object && pending.is_none() {
                    // Strip the quotes: a member name is what lies between them.
                    pending = Some((i + 1, end.saturating_sub(1)));
                } else if let Some(name) = pending.take() {
                    record(body, &mut found, pointers, &path, depth, name, i, end);
                }
                i = end;
            }
            _ => {
                let end = skip_scalar(body, i);
                if let Some(name) = pending.take() {
                    record(body, &mut found, pointers, &path, depth, name, i, end);
                }
                i = end.max(i + 1);
            }
        }
    }
    found
}

/// Record a value's span when the member path that reached it is one of the requested pointers.
///
/// First reading wins. A body that repeats a member is malformed by the object notation's own rule,
/// and the plane's answer to a malformed body is a decode error, never a second span for one name.
#[allow(clippy::too_many_arguments)]
fn record<'a>(
    body: &[u8],
    found: &mut Vec<(&'a str, Span)>,
    pointers: &[&'a str],
    path: &[(usize, usize); MAX_DEPTH],
    depth: usize,
    name: (usize, usize),
    start: usize,
    end: usize,
) {
    for ptr in pointers {
        if found.iter().any(|(p, _)| p == ptr) {
            continue;
        }
        if path_matches(body, path, depth, name, ptr) {
            found.push((*ptr, Span { start, end }));
        }
    }
}

/// Whether the member path that reached a value spells one pointer.
///
/// The path is the member names of the open object levels, outermost first, with the pending name
/// last. The empty pointer matches nothing on purpose: a pointer with no segments names the whole
/// document, and the whole document already has a span the caller knows without asking.
fn path_matches(
    body: &[u8],
    path: &[(usize, usize); MAX_DEPTH],
    depth: usize,
    name: (usize, usize),
    ptr: &str,
) -> bool {
    let mut segments = ptr.split('/').skip(1);
    // Every open object level below the outermost contributes its own member name.
    for (s, e) in path.iter().take(depth.min(MAX_DEPTH)).skip(1) {
        let Some(expected) = segments.next() else {
            return false;
        };
        if body.get(*s..*e) != Some(expected.as_bytes()) {
            return false;
        }
    }
    let Some(last) = segments.next() else {
        return false;
    };
    if segments.next().is_some() {
        return false;
    }
    body.get(name.0..name.1) == Some(last.as_bytes())
}

/// One past the end of the string starting at a quote.
fn skip_string(body: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < body.len() {
        match body[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    body.len()
}

/// One past the end of the scalar starting here.
fn skip_scalar(body: &[u8], start: usize) -> usize {
    let mut i = start;
    while i < body.len() {
        match body[i] {
            b',' | b'}' | b']' | b' ' | b'\t' | b'\n' | b'\r' => return i,
            _ => i += 1,
        }
    }
    body.len()
}

/// One past the end of the value starting here, whatever kind of value it is.
fn skip_value(body: &[u8], start: usize) -> usize {
    match body.get(start) {
        Some(b'"') => skip_string(body, start),
        Some(b'{' | b'[') => {
            let mut depth = 0i32;
            let mut i = start;
            while i < body.len() {
                match body[i] {
                    b'"' => {
                        i = skip_string(body, i);
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth -= 1;
                        if depth == 0 {
                            return i + 1;
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            body.len()
        }
        _ => skip_scalar(body, start),
    }
}

#[cfg(test)]
mod tests {
    use super::resolve;

    /// The pointers this plane actually declares resolve over a request of this protocol's shape.
    #[test]
    fn the_request_pointers_resolve() {
        let body = br#"{"jsonrpc":"2.0","id":"r1","method":"message/send","params":{"message":{"role":"user"}}}"#;
        let found = resolve(body, &["/method", "/id", "/params/message"]);
        let at = |p: &str| {
            found
                .iter()
                .find(|(k, _)| *k == p)
                .map(|(_, s)| &body[s.start..s.end])
        };
        assert_eq!(at("/method"), Some(&br#""message/send""#[..]));
        assert_eq!(at("/id"), Some(&br#""r1""#[..]));
        assert_eq!(at("/params/message"), Some(&br#"{"role":"user"}"#[..]));
    }

    /// A pointer that is not in the body is absent, not empty.
    #[test]
    fn an_absent_pointer_is_absent() {
        let body = br#"{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"id":"t1"}}"#;
        let found = resolve(body, &["/params/message"]);
        assert!(found.is_empty());
    }

    /// A member of the same name nested inside an array does not answer for the outer pointer.
    #[test]
    fn an_array_element_does_not_answer_for_an_object_member() {
        let body = br#"{"result":{"artifacts":[{"id":"inner"}]}}"#;
        let found = resolve(body, &["/params/id"]);
        assert!(found.is_empty());
    }

    /// The scanner is deterministic: the same bytes give the same spans every time.
    #[test]
    fn the_same_bytes_give_the_same_spans() {
        let body = br#"{"jsonrpc":"2.0","id":2,"method":"tasks/cancel","params":{"id":"t-9"}}"#;
        let first = resolve(body, &["/method", "/id", "/params/id"]);
        let second = resolve(body, &["/method", "/id", "/params/id"]);
        assert_eq!(first, second);
    }
}
