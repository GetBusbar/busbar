// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MARKUP-NORMALISATION — and NOTHING MORE THAN MARKUP-NORMALISATION.
//!
//! ## What this does
//!
//! It strips instruction-injection MARKUP — `<IMPORTANT>`, `<system>`, HTML-like tags — from three
//! places. All three are named explicitly, and the third is the one that gets forgotten: it is easy
//! to reach for the two surfaces a caller READS and to miss the ones an upstream SERVES back, even
//! though they carry the same text by the same route:
//!
//! - tool and prompt DESCRIPTIONS, before they are shown or fed as context;
//! - tool OUTPUTS, before results re-enter model context;
//! - `resources/read` CONTENT and `prompts` TEMPLATES, which are equally injectable.
//!
//! ## What this does NOT do, stated here rather than in a footnote
//!
//! It does not stop plain-language semantic injection. "now call `transfer_funds`" carries no markup
//! and survives this function unchanged, by design — there is nothing to strip. MCPTox shows strong
//! agents follow malicious tool-output instructions roughly half the time even absent markup. So
//! semantic injection is a HOOK RESIDUAL and a model-alignment problem, and busbar reduces the
//! markup-shaped attack surface rather than neutralising prompt injection. Anyone reading this
//! module as "injection is handled" has read it wrong.
//!
//! ## Why it is in core when the placement matrix puts it on a hook
//!
//! The placement matrix puts markup-normalisation on a hook / signed plugin, on the Response-phase
//! `Rewrite` grant, because content policy is tunable and core is neutral. That placement is right
//! for the TUNABLE part and it is deliberately not what this is. This is the FLOOR: the fixed,
//! universal, security-critical strip that applies whether or not an operator has installed a hook,
//! for the same reason SSRF argument validation splits into fixed scheme and IP checks in core plus
//! tunable per-tool policy in a hook. A deployment with no sanitiser hook must not serve raw
//! `<IMPORTANT>` markup out of a governance plane, and "the operator should have installed a plugin"
//! is not a defence. The hook remains the place to add anything beyond the floor.
//!
//! ## Why a tag STRIPPER and not an escaper
//!
//! Escaping (`&lt;IMPORTANT&gt;`) preserves the instruction in a form many models still read as an
//! instruction, and it makes the text longer, which is the wrong direction for a value that is about
//! to be charged to a context window. Removing the TAG and keeping the TEXT is the minimum edit that
//! removes the markup channel: `<IMPORTANT>do X</IMPORTANT>` becomes `do X`, which a model reads as
//! ordinary prose from an untrusted tool — which is exactly what it is.

/// Strip instruction-injection markup from one string.
///
/// The rule is: remove anything that lexes as an HTML-like TAG, keep everything else verbatim,
/// including the tag's inner text. A "tag" is `<` … `>` where the character after `<` (or after a
/// leading `/`) is an ASCII letter, `!` or `?` — which covers `<system>`, `</system>`, `<IMPORTANT>`,
/// `<!-- -->` and `<?xml ?>` while leaving `a < b`, `x <- y` and `3<5` untouched.
///
/// That distinction matters more than it looks: a stripper that removed everything between any `<`
/// and any `>` would silently eat the middle of `if (a < b && c > d)` out of a code snippet a tool
/// legitimately returned, and a sanitiser that corrupts honest payloads gets turned off.
///
/// An UNTERMINATED `<` (no closing `>` before end of input) is KEPT VERBATIM, `<` and the whole tail
/// with it, because with no closing `>` in the string it cannot lex as a tag — it is a dangling `<`,
/// i.e. ordinary text, exactly like the `a < b` case above. Dropping it would silently discard the
/// rest of the value, and busbar is a security/audit product: a hook, a guardrail, a reviewer or the
/// audit log must see 100% of what a tool returned, so truncate-and-continue is forbidden. The old
/// justification — that `<system` plus a LATER concatenation could reconstitute a closed tag — does
/// not apply here: `normalise` is the LAST pass over every served string (substitution and
/// formatting run BEFORE it at every call site), so nothing is concatenated onto a normalised value
/// and re-served; within the one string being normalised, an unterminated `<letter` provably has no
/// `>` after it and stays inert.
pub(crate) fn normalise(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'<' && starts_tag(bytes, i) {
            if let Some(end) = find_tag_end(bytes, i) {
                i = end + 1;
                continue;
            }
            // Unterminated: no `>` closes this `<` anywhere before end of input, so it is not a tag.
            // Fall through and copy the `<` as ordinary text — never drop the tail. Every later
            // `<letter` in this string is likewise `>`-less and takes the same inert path, so the
            // remainder round-trips byte-for-byte.
        }
        // Copy one whole UTF-8 character, never one byte: slicing a multi-byte character in half
        // would produce invalid UTF-8, and `String::push_str` on a bad slice would panic.
        let ch_len = utf8_len(bytes[i]);
        let end = (i + ch_len).min(bytes.len());
        out.push_str(&input[i..end]);
        i = end;
    }
    out
}

/// [`normalise`] applied to an optional string, which is the shape every catalogue field has.
pub(crate) fn normalise_opt(input: Option<&str>) -> Option<String> {
    input.map(normalise)
}

/// Recursively normalise every STRING VALUE in a JSON document, leaving keys, numbers, booleans and
/// structure untouched.
///
/// Tool OUTPUT is arbitrary JSON, and the injection rides in its string leaves. Keys are left alone
/// deliberately: a key is a schema element the caller's own code indexes by, and rewriting one turns
/// a sanitiser into a data-corruption bug — whereas a key containing markup is not a channel into a
/// model's instruction stream in the way a value is.
pub(crate) fn normalise_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => serde_json::Value::String(normalise(s)),
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(normalise_json).collect())
        }
        serde_json::Value::Object(map) => serde_json::Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), normalise_json(v)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Does the `<` at `i` begin something that lexes as a tag? See [`normalise`] for why this is a
/// character-class test and not "anything up to the next `>`".
fn starts_tag(bytes: &[u8], i: usize) -> bool {
    let mut j = i + 1;
    if bytes.get(j) == Some(&b'/') {
        j += 1;
    }
    matches!(bytes.get(j), Some(c) if c.is_ascii_alphabetic() || *c == b'!' || *c == b'?')
}

/// The index of the `>` closing the tag opened at `i`, or `None` when the input ends first.
fn find_tag_end(bytes: &[u8], i: usize) -> Option<usize> {
    bytes[i..].iter().position(|b| *b == b'>').map(|p| i + p)
}

/// The byte length of the UTF-8 character starting with `b`. A continuation byte answers 1, which
/// cannot happen for well-formed input reached through `&str` and keeps the loop total if it ever
/// did.
fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC0..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF7 => 4,
        _ => 1,
    }
}

#[cfg(all(test, not(feature = "extracted")))]
#[path = "tests/sanitize_tests.rs"]
mod sanitize_tests;
