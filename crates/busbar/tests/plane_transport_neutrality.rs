// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VOICE-TRANSPORT/MEDIA NEUTRALITY WITNESS (the `cargo test` twin of
//! `scripts/plane-transport-neutrality.sh`).
//!
//! Owner's ruling: the neutral crates (`busbar-core` / `busbar-substrate` / `busbar-api`) must never
//! learn a protocol's TRANSPORT vocabulary. plane-purity-lint bans the plane KEYS (mcp/a2a/llm/voice)
//! and the LLM dialects; the Plane-4 (busbar-voice) duplex/live-voice plane drags in a SECOND
//! vocabulary that plane-purity does not name — the transport/media nouns
//! `rtc / sdp / webrtc / twilio / dtmf / rtp / sideband / realtime / audio / mulaw / g711 / barge`
//! (docs/design/plane4-duplex-session.md §7.2). A leak of any of them into a neutral crate is the
//! forward-edge regression the plane ABI exists to prevent.
//!
//! This is the belt-and-suspenders twin of the shell gate: the shell gate is the BLOCKING CI gate;
//! this runs in every `cargo test`, so a neutral-crate transport-noun leak reddens the workspace test
//! run too, not only the lint tier. Both share ONE detection discipline (mirrored, not re-invented):
//!   * comments and doc-strings are STRIPPED (respecting string literals) — a doc-comment that
//!     legitimately discusses `audio`/`speech` billing is not a hit; only code tokens are judged;
//!   * a noun flags as a WORD (identifier-boundary, case-insensitive) or a CamelCase TOKEN
//!     (`SdpOffer`, `RtpStream`); the identifier boundary treats `_` as part of the identifier —
//!     EXACTLY as the shell gate's `word_ci` — so the tracked underscore-joined in-core-twin debt
//!     (`input_audio`) is scoped OUT, not flagged (that is a separate, tracked extraction).
//!
//! Modelled on the house source-scanning oracle pattern (`plane_isomorphism.rs` /
//! `capability_equality.rs`): one detector drives both the REAL neutral-crate scan and a planted-hit
//! self-test, so the self-test proves the REAL witness would fire.

use std::path::{Path, PathBuf};

/// The banned voice-transport/media nouns, lowercase (Plane-4, docs/design/plane4-duplex-session.md
/// §7.2). Every one has ZERO code hits in the neutral crates today; this witness keeps it that way.
const NOUNS: &[&str] = &[
    "rtc", "sdp", "webrtc", "twilio", "dtmf", "rtp", "sideband", "realtime", "audio", "mulaw",
    "g711", "barge",
];

/// The NEUTRAL crate source roots (the ABI side). A neutral crate that appears/disappears is one edit.
const NEUTRAL_ROOTS: &[&str] = &[
    "crates/busbar-core/src",
    "crates/busbar-substrate/src",
    "crates/api/src",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root must exist")
}

/// Strip line/block comments from one source line, respecting string literals — the same discipline as
/// the shell gate's `strip()`: a `//` inside a string is NOT a comment, and a token inside a string IS
/// kept. `in_block` persists across lines (block comments span lines); string state is per line.
fn strip_comments(line: &str, in_block: &mut bool) -> String {
    let b = line.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        let c2 = if i + 1 < b.len() {
            &b[i..i + 2]
        } else {
            &b[i..]
        };
        if *in_block {
            if c2 == b"*/" {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_str {
            out.push(c as char);
            if c == b'\\' {
                if i + 1 < b.len() {
                    out.push(b[i + 1] as char);
                }
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c2 == b"/*" {
            *in_block = true;
            i += 2;
            continue;
        }
        if c2 == b"//" {
            break; // line comment (// /// //!) to EOL
        }
        if c == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    out
}

/// Capitalize a noun for the CamelCase rule: first byte upper, the rest lower (`sdp`→`Sdp`,
/// `webrtc`→`Webrtc`, `g711`→`G711`).
fn capitalized(noun: &str) -> String {
    let mut cs = noun.chars();
    match cs.next() {
        Some(first) => first.to_ascii_uppercase().to_string() + &cs.as_str().to_ascii_lowercase(),
        None => String::new(),
    }
}

/// Does this stripped code contain a banned noun as a WORD (identifier-boundary, `_` NOT a boundary)
/// or a CamelCase TOKEN? Returns the offending noun, if any.
fn hit_in_code(code: &str) -> Option<&'static str> {
    // WORD rule: tokenize into maximal identifier runs [A-Za-z0-9_] and compare whole-token,
    // case-insensitively. Splitting on non-identifier chars (NOT on `_`) is exactly the shell gate's
    // `[^a-z0-9_]` boundary, so `input_audio` is one token and does not equal `audio`.
    for token in code.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_')) {
        if token.is_empty() {
            continue;
        }
        for noun in NOUNS {
            if token.eq_ignore_ascii_case(noun) {
                return Some(noun);
            }
        }
    }
    // CamelCase rule: a Capitalized noun followed by an uppercase letter, a non-identifier char, or
    // end-of-line: `SdpOffer`, `RtpStream`, a bare `Sdp`.
    for noun in NOUNS {
        let cap = capitalized(noun);
        let mut from = 0;
        while let Some(rel) = code[from..].find(&cap) {
            let start = from + rel;
            let end = start + cap.len();
            let next = code[end..].chars().next();
            let camel_boundary = match next {
                None => true,
                Some(ch) => ch.is_ascii_uppercase() || !(ch.is_ascii_alphanumeric() || ch == '_'),
            };
            if camel_boundary {
                return Some(noun);
            }
            from = start + 1;
        }
    }
    None
}

/// The Some/None of a whole file, stripped and scanned. Returns `(line_no, noun, trimmed)` hits.
fn scan_source(src: &str) -> Vec<(usize, &'static str, String)> {
    let mut hits = Vec::new();
    let mut in_block = false;
    for (idx, raw) in src.lines().enumerate() {
        let code = strip_comments(raw, &mut in_block);
        if let Some(noun) = hit_in_code(&code) {
            hits.push((idx + 1, noun, raw.trim().to_string()));
        }
    }
    hits
}

/// Every non-test `.rs` under `dir`, recursively. Test scope (`*/tests/*`, `*_test(s).rs`) is excluded
/// — the ban is on the neutral ABI the crates EXPORT, not their unit tests (mirrors the shell gate).
fn neutral_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("tests") {
                continue;
            }
            neutral_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with("_test.rs") || name.ends_with("_tests.rs") {
                continue;
            }
            out.push(path);
        }
    }
}

/// THE REAL WITNESS: no neutral-crate source names a voice-transport/media noun in code.
#[test]
fn neutral_crates_name_no_voice_transport_noun() {
    let root = repo_root();
    let mut files = Vec::new();
    for r in NEUTRAL_ROOTS {
        neutral_rs_files(&root.join(r), &mut files);
    }
    assert!(
        files.len() >= 20,
        "witness found only {} neutral .rs files under {:?} — the scan floor did not bite; a broken \
         walk would pass vacuously",
        files.len(),
        NEUTRAL_ROOTS
    );

    let mut leaks: Vec<String> = Vec::new();
    for path in &files {
        let src = std::fs::read_to_string(path).expect("neutral source must be readable");
        for (line, noun, text) in scan_source(&src) {
            leaks.push(format!(
                "{}:{}  [{}]  {}",
                path.strip_prefix(&root).unwrap_or(path).display(),
                line,
                noun,
                text
            ));
        }
    }

    assert!(
        leaks.is_empty(),
        "voice-transport/media noun(s) leaked into the NEUTRAL crates — the voice plane \
         (busbar-voice) owns these; cross the ABI as an opaque PlaneRecord, never a transport noun:\n  {}",
        leaks.join("\n  ")
    );
}

/// SELF-TEST (the detector is not vacuous): the SAME detector must fire on a planted CamelCase
/// `SdpOffer` and a bare `webrtc` word, must IGNORE a comment/underscore-joined mention, and must
/// keep string-kept tokens. A green real witness means nothing if the detector cannot see a leak.
#[test]
fn detector_fires_on_planted_transport_nouns_and_ignores_comments() {
    // RED: real code — a CamelCase type, a bare word in a string, a lowercase word.
    let red = "pub struct SdpOffer;\nfn f() { let k = \"webrtc\"; }\nlet realtime = true;";
    let red_hits = scan_source(red);
    assert!(
        red_hits.iter().any(|(_, n, _)| *n == "sdp"),
        "detector missed the CamelCase SdpOffer: {red_hits:?}"
    );
    assert!(
        red_hits.iter().any(|(_, n, _)| *n == "webrtc"),
        "detector missed the bare `webrtc` word: {red_hits:?}"
    );
    assert!(
        red_hits.iter().any(|(_, n, _)| *n == "realtime"),
        "detector missed the bare `realtime` word: {red_hits:?}"
    );

    // GREEN: a line comment, a block comment, and the underscore-joined tracked-debt field — none flag.
    let green = "// a comment naming sdp webrtc audio and SdpOffer\n\
                 /* block naming rtp and barge */\n\
                 pub input_audio: Option<u64>,\n\
                 pub struct PlaneRecord;";
    let green_hits = scan_source(green);
    assert!(
        green_hits.is_empty(),
        "detector wrongly flagged a comment or the underscore-joined `input_audio` debt: {green_hits:?}"
    );
}
