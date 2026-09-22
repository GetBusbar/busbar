//! The 1.5.5 admin error envelope: `{"error":{"code":"<code>","message":"<message>"}}`.
//!
//! Transcribed from `busbar-core`'s admin contract (`AdminError` and `err_json`), which this
//! module reads as read-only reference and never depends on. `busbar-core`'s ten `AdminError`
//! variants map to exactly these frozen `code` strings: `not_found`, `unauthorized`,
//! `method_not_allowed`, `forbidden`, `invalid_request`, `version_conflict`, `conflict`,
//! `rate_limited`, `internal`, `unavailable`.
//!
//! **THE SHAPE LIVES HERE AND THE MAPPING DOES NOT.** This module owns the two keys, their order,
//! their quoting and the absence of a trailing byte — one frozen wire shape, written once, because
//! a second `format!` of it elsewhere is a second chance for a surface a client pinned to change in
//! one place and not the other. WHICH code a condition renders under is a different question, and
//! it is answered where the condition is decided: `crates/busbar/src/root/units_admin`'s
//! `answer_for`, which maps the kernel's own `ReasonCode` to a status AND a code for the one path
//! an administrative request actually takes.
//!
//! This module used to carry a second, parallel mapping — `RefusalReason -> code` — for the
//! `Plane::encode_refusal` face. That face is gone (a `Plane` is how TRAFFIC enters the dispatch
//! loop, and the admin surface serves operators, #3/#5/#83 def 11), and the mapping went with it.
//! It was not merely unreachable, it DISAGREED with the live one: `PlanePanic` rendered `internal`
//! here and `forbidden` there, and only `answer_for` ever ran. Two tables answering one question,
//! one of which nothing called, is the shape this deletion removes.

/// The 1.5.5 admin error envelope around one code and one message.
///
/// Hand-formatted rather than serialized: the shape is two fixed keys and two string values the
/// callers already know are quote-safe (closed code strings; closed, comma/quote-free prose), so a
/// dependency on a serializer would buy nothing here that hand-formatting does not already give
/// byte-for-byte.
#[must_use]
pub fn envelope_of(code: &str, message: &str) -> String {
    format!(r#"{{"error":{{"code":"{code}","message":"{message}"}}}}"#)
}

#[cfg(test)]
#[path = "tests/refusal.rs"]
mod tests;
