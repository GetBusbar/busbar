//! `decision` AS THE AUTH VERDICT'S CONTINUE/STOP FIELD, NOT THE DECISIONS PLANE.
//!
//! The decisions plane declares the `KEY` `decision`, so the bare word is a plane needle in every
//! crate. The auth ABI has a field of the same name: the continue/stop verdict an auth answers
//! with (`busbar-contract` `abi/auth/inbound.rs` `pub decision: u32`, `auth_calls.rs` and
//! `abi/sdk/auth_door.rs` `pub decision: Decision`). An auth plugin reading or naming that field
//! (`f.out.decision`, `let decision = …`, `fn …_and_a_decision`) is the auth kind speaking its own
//! ABI, not the auth crate knowing the decisions plane. `1.6.0-TODO.md`: "a word collision never
//! raises a cell: it gets a mask" (ARCHITECT ruling 2026-09-30, WIRE-AUTH residual finding 4:
//! `busbar-auth-webhook-signature × plane` 4, every hit this field).
//!
//! Masked (same-length `x` filler, so lines and columns hold), ONLY while the contract's auth ABI
//! declares that field ([`declared`]), and ONLY in a `.rs` file of ([`scope`]):
//!
//! * an `auth`-kind crate: lower-case `decision` in CODE as a whole identifier or one `_` segment
//!   of one (`decision`, `out.decision`, `names_a_decision`, `decision_of`);
//! * a `plugin-tooling` crate, in a file whose path in the crate names `auth` — the loader's side
//!   of the auth ABI (`auth_axis.rs`, `auth_door.rs` and their tests; ARCHITECT ruling 2026-09-30,
//!   WIRE-AUTH RISE (b), `busbar-plugin-loader × plane` +19): the same, plus the contract's auth
//!   `Decision` type written as a whole name (`Decision::Continue`, `auth_calls::Decision`).
//!
//! Everything else still counts, in those files as anywhere: the string literal `"decision"` (the
//! plane's registry key), `decisions`, `DECISION`, `Decision` outside a loader auth file, a segment
//! joined to the plane marker (`plane_decision`, `plane-decision`), a `…::decision` path segment,
//! the word in prose (which the English-word mask already reads), and every other file.

use std::borrow::Cow;

/// The word this module reads contexts for.
const WORD: &str = "decision";

/// The kind whose crates the mask applies to.
pub(super) const KIND: &str = "auth";

/// The kind whose AUTH files (the loader's side of the auth ABI) the mask applies to.
pub(super) const LOADER_KIND: &str = "plugin-tooling";

/// The contract's auth verdict type, masked in the loader's auth files.
const TYPE: &str = "Decision";

/// Which mask a file at `rel` of a crate of `kind` in `dir` takes: `None`, or `Some(with_type)`.
pub(super) fn scope(kind: Option<&str>, dir: &str, rel: &str) -> Option<bool> {
    match kind {
        Some(KIND) => Some(false),
        Some(LOADER_KIND) if rel.strip_prefix(dir).is_some_and(|t| t.contains("auth")) => {
            Some(true)
        }
        _ => None,
    }
}

/// Whether the contract's auth ABI declares the `decision` field, read off the tree: a
/// `pub decision:` in a `busbar-contract` source whose path names `auth`. When the field goes, the
/// mask goes with it.
pub(super) fn declared(files: &[(String, String)]) -> bool {
    files.iter().any(|(rel, text)| {
        rel.starts_with("crates/busbar-contract/src/")
            && rel.ends_with(".rs")
            && rel.contains("auth")
            && text
                .lines()
                .any(|l| l.trim_start().starts_with("pub decision:"))
    })
}

/// `text` (a file at `rel` in [`scope`]) with every code occurrence of the auth ABI's `decision`
/// field masked, and of its `Decision` type when `with_type`. See the module header.
pub(super) fn mask_auth_decision<'a>(rel: &str, text: &'a str, with_type: bool) -> Cow<'a, str> {
    let hit = |t: &str| t.contains(WORD) || (with_type && t.contains(TYPE));
    if !rel.ends_with(".rs") || !hit(text) {
        return Cow::Borrowed(text);
    }
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if hit(line) {
            out.push_str(&mask_line(line, with_type));
        } else {
            out.push_str(line);
        }
    }
    Cow::Owned(out)
}

fn mask_line(line: &str, with_type: bool) -> String {
    let code_end = super::comment_start(line).unwrap_or(line.len());
    let b = line.as_bytes();
    let mut buf = b.to_vec();
    // Byte ranges inside a `"…"` string literal, before the comment.
    let mut in_str = vec![false; b.len()];
    let mut inside = false;
    let mut i = 0;
    while i < code_end {
        match b[i] {
            b'\\' if inside => {
                in_str[i] = true;
                if i + 1 < b.len() {
                    in_str[i + 1] = true;
                }
                i += 2;
                continue;
            }
            b'"' => {
                in_str[i] = true;
                inside = !inside;
            }
            _ => in_str[i] = inside,
        }
        i += 1;
    }
    let alnum = |k: usize| b.get(k).is_some_and(|c| c.is_ascii_alphanumeric());
    let words: &[&str] = if with_type { &[WORD, TYPE] } else { &[WORD] };
    for word in words {
        let mut from = 0;
        while let Some(off) = line[from..code_end.max(from)].find(word) {
            let i = from + off;
            let j = i + word.len();
            from = j;
            if in_str[i] {
                continue;
            }
            // A whole identifier or one `_` segment: no letter or digit on either side.
            if (i > 0 && alnum(i - 1)) || alnum(j) {
                continue;
            }
            // Joined to the plane marker: the plane, kept. A `…::decision` path segment is a
            // module of that name, kept; the type is reached by path (`auth_calls::Decision`).
            let before = line[..i].to_ascii_lowercase();
            if (*word == WORD && before.ends_with("::"))
                || before.ends_with("plane_")
                || before.ends_with("plane-")
            {
                continue;
            }
            buf[i..j].fill(b'x');
        }
    }
    String::from_utf8(buf).expect("ascii-for-ascii")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(s: &str) -> bool {
        !mask_auth_decision("crates/busbar-auth-x/src/a.rs", s, false).contains(WORD)
    }

    #[test]
    fn the_auth_field_is_masked() {
        for s in [
            "        f.out.decision,\n",
            "fn every_verdict_names_the_signature_lines_and_a_decision() {\n",
            "    for (sig, verdict, decision) in [\n",
            "        assert_eq!(got, decision, \"{line}\");\n",
            "let decision_of = |a: &Answer| a.decision;\n",
        ] {
            assert!(masked(s), "{s}");
        }
    }

    #[test]
    fn the_plane_still_counts() {
        for s in [
            "pub const KEY: &str = \"decision\";\n",
            "let k = \"the decision plane\";\n",
            "use busbar_plane_decisions::decision::Hook;\n",
            "let x = plane_decision();\n",
            "let d = Decision::Stop;\n",
            "let n = decisions.len();\n",
            "// the decision, in prose, is the English mask's to read\n",
        ] {
            assert_eq!(
                mask_auth_decision("crates/busbar-auth-x/src/a.rs", s, false),
                s
            );
        }
        // Only `.rs`; a manifest or a fixture keeps the word.
        assert_eq!(
            mask_auth_decision("crates/busbar-auth-x/Cargo.toml", "decision = 1\n", false),
            "decision = 1\n"
        );
    }

    #[test]
    fn the_loader_auth_files_mask_the_type_too() {
        let rel = "crates/plugin-loader/src/auth_axis.rs";
        let s = "        decision: if out.decision == DECISION_CONTINUE {\n\
                 \x20           Decision::Continue\n\
                 use busbar_contract::auth_calls::{AuthCalls, Decision, Strip};\n";
        let m = mask_auth_decision(rel, s, true);
        assert!(!m.contains(WORD) && !m.contains(TYPE), "{m}");
        assert!(m.contains("DECISION_CONTINUE"), "{m}");
        // The plane's key and a `Decision` in an auth crate's own scope still count.
        let key = "pub const KEY: &str = \"decision\";\n";
        assert_eq!(mask_auth_decision(rel, key, true), key);
        let t = "let d = Decision::Stop;\n";
        assert_eq!(
            mask_auth_decision("crates/busbar-auth-x/src/a.rs", t, false),
            t
        );
        // Which files: auth crates, and the loader's files whose path names `auth`.
        assert_eq!(
            scope(
                Some(KIND),
                "crates/busbar-auth-x",
                "crates/busbar-auth-x/src/a.rs"
            ),
            Some(false)
        );
        assert_eq!(
            scope(Some(LOADER_KIND), "crates/plugin-loader", rel),
            Some(true)
        );
        assert_eq!(
            scope(
                Some(LOADER_KIND),
                "crates/plugin-loader",
                "crates/plugin-loader/src/hook.rs"
            ),
            None
        );
        assert_eq!(
            scope(
                Some("kernel"),
                "crates/busbar-kernel",
                "crates/busbar-kernel/src/auth/mod.rs"
            ),
            None
        );
    }

    #[test]
    fn the_field_is_read_off_the_contract() {
        let with = vec![(
            "crates/busbar-contract/src/abi/auth/inbound.rs".to_string(),
            "pub struct IdentifyOut {\n    pub decision: u32,\n}\n".to_string(),
        )];
        assert!(declared(&with));
        let without = vec![(
            "crates/busbar-contract/src/abi/store/mod.rs".to_string(),
            "pub struct S {\n    pub decision: u32,\n}\n".to_string(),
        )];
        assert!(!declared(&without));
    }
}
