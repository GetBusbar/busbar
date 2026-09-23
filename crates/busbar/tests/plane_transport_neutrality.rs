// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE VOICE-TRANSPORT/MEDIA NEUTRALITY WITNESS (the `cargo test` twin of
//! `scripts/plane-transport-neutrality.sh`).
//!
//! Owner's ruling: the neutral crates (`busbar-core` / `busbar-substrate` / `busbar-api`) must never
//! learn a protocol's TRANSPORT vocabulary. plane-purity-lint bans the plane KEYS (mcp/a2a/llm/voice)
//! and the LLM dialects; the Plane-4 (busbar-voice) duplex/live-voice plane drags in a SECOND
//! vocabulary that plane-purity does not name — the transport/media nouns
//! `rtc / sdp / webrtc / twilio / dtmf / rtp / sideband / realtime / audio / mulaw / g711 / barge`.
//! A leak of any of them into a neutral crate is the forward-edge regression the plane ABI exists to
//! prevent.
//!
//! This is the belt-and-suspenders twin of the shell gate: the shell gate is the BLOCKING CI gate;
//! this runs in every `cargo test`, so a neutral-crate transport-noun leak reddens the workspace test
//! run too, not only the lint tier. Both share ONE detection discipline (mirrored, not re-invented):
//!   * comments and doc-strings are STRIPPED (respecting string literals) — a doc-comment that
//!     legitimately discusses `audio`/`speech` billing is not a hit; only code tokens are judged;
//!   * a noun flags as a WORD (case-insensitive) or a CamelCase TOKEN (`SdpOffer`, `RtpStream`);
//!     `_` IS a word boundary, so an underscore-joined identifier is judged SEGMENT BY SEGMENT and
//!     `sdp_offer` / `rtp_stream` / `input_audio` all flag. Rust spells its compound names in
//!     snake_case, so a rule that treated `_` as part of the identifier would exempt the ordinary
//!     spelling of every leak this gate exists to catch — the ban is on the noun, not on one casing
//!     of it.
//!
//! Modelled on the house source-scanning oracle pattern (`plane_isomorphism.rs` /
//! `capability_equality.rs`): one detector drives both the REAL neutral-crate scan and a planted-hit
//! self-test, so the self-test proves the REAL witness would fire.

use std::path::{Path, PathBuf};

/// The banned voice-transport/media nouns, lowercase (the Plane-4 duplex/live-voice transport
/// vocabulary). Every one has ZERO code hits in the neutral crates today; this witness keeps it so.
const NOUNS: &[&str] = &[
    "rtc", "sdp", "webrtc", "twilio", "dtmf", "rtp", "sideband", "realtime", "audio", "mulaw",
    "g711", "barge",
];

/// The NEUTRAL crate source roots (the ABI side). A neutral crate that appears/disappears is one edit.
///
/// These are the SUCCESSORS of the three this gate was written against on 2026-09-03
/// (`busbar-core`, `busbar-substrate`, `busbar-api`). Both of the first two were deleted during
/// 1.6.0 and their contents went to four places, so the successor set is four roots:
///   * `busbar-core` was absorbed INTO `busbar-kernel` (673ecdaaa, #19/#37);
///   * `busbar-substrate`'s ENGINE was absorbed into `busbar-kernel` too (5fa320208), its VALUE
///     families went down to `busbar-substrate-values` (06132b0b1) and its civil/duration/audit
///     vocabulary went to `busbar-contract` (eee77c488), which later also took the slice ABI
///     (b544c8bbf);
///   * `busbar-api` is unmoved.
///
/// Naming all four is not a widening — it is what keeps the ORIGINAL surface covered. The
/// 2026-09-05 split silently carried `busbar-substrate/src/billing.rs` out of this scan, and no
/// commit since has looked at it; listing only the kernel would leave that hole open.
const NEUTRAL_ROOTS: &[&str] = &[
    "crates/busbar-kernel/src",
    "crates/busbar-substrate-values/src",
    "crates/busbar-contract/src",
    "crates/api/src",
];

/// THE NAMED EXEMPTIONS — `(repo-relative file, identifier, reason)`. A hit whose file matches an
/// entry AND whose code carries that entry's identifier is not a leak.
///
/// It is a CHECKED inventory, not a waiver list: `every_exemption_is_live_and_really_needed` below
/// proves each entry names a file that exists, an identifier that is really in it, and a line the
/// detector really does flag. An entry that stops being needed reds as loudly as a new leak, so the
/// list cannot accumulate standing permission.
///
/// There is exactly one, and it is OLDER than this gate rather than a new concession to it. When the
/// gate landed on 2026-09-03 the `_` was NOT a word boundary, and its own self-test named this field
/// as the thing that must NOT flag ("the underscore-joined `input_audio` debt"). Two days later the
/// crate split carried the field out of the scanned roots; the day after that the `_` became a
/// boundary (389d9a0e2) — a tightening that was right, and that never had to reckon with this field
/// because it was no longer in scope. Restoring the roots above puts it back in scope, so the
/// judgement has to be made in the open rather than inherited from an accident of ordering.
const NOUN_EXEMPTIONS: &[(&str, &str, &str)] = &[(
    "crates/busbar-substrate-values/src/billing.rs",
    "input_audio",
    "A BILLING MODALITY, not a transport noun. `TokenUsage` partitions `input` into `input_text` / \
     `input_audio` / `input_image` — the per-modality breakdown a transcription-style operation's \
     usage object reports, modelled since 1.2 and a release older than the fourth plane. It names a \
     UNIT OF BILLABLE WORK, exactly as its two siblings do; nothing about a carrier, a codec or a \
     session reaches this type. The vocabulary this gate exists to keep out is the one a duplex \
     session drags in (rtc/sdp/webrtc/dtmf/rtp/mulaw/g711/barge) — spelling the third modality \
     obliquely while `input_text` and `input_image` stay plain would cost a reader the meaning of \
     the field and buy no neutrality at all.",
)];

/// Is this hit covered by a [`NOUN_EXEMPTIONS`] entry? `path` is repo-relative.
fn is_exempt(path: &str, code: &str) -> bool {
    NOUN_EXEMPTIONS
        .iter()
        .any(|(file, ident, _)| *file == path && code.contains(ident))
}

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

/// Does this stripped code contain a banned noun as a WORD (`_` IS a boundary) or a CamelCase
/// TOKEN? Returns the offending noun, if any.
fn hit_in_code(code: &str) -> Option<&'static str> {
    // WORD rule: tokenize into maximal identifier runs, then split each run on `_` and compare every
    // SEGMENT case-insensitively. `_` is a boundary because snake_case is how Rust spells a compound
    // name: `sdp_offer`, `rtp_stream`, `webrtc_session` and `input_audio` all carry the banned noun
    // just as plainly as the bare word does. Treating `_` as part of the identifier would let the
    // entire snake_case half of the language through a gate whose whole subject is Rust source.
    for run in code.split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_')) {
        for token in run.split('_') {
            if token.is_empty() {
                continue;
            }
            for noun in NOUNS {
                if token.eq_ignore_ascii_case(noun) {
                    return Some(noun);
                }
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
        let rel = path
            .strip_prefix(&root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        for (line, noun, text) in scan_source(&src) {
            if is_exempt(&rel, &text) {
                continue;
            }
            leaks.push(format!("{rel}:{line}  [{noun}]  {text}"));
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
/// `SdpOffer`, a bare `webrtc` word AND an underscore-joined `input_audio`, while still ignoring
/// comments. A green real witness means nothing if the detector cannot see a leak.
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

    // RED: the snake_case spellings. These are the ordinary way a Rust leak would actually appear,
    // and the reason `_` is a boundary — each must be seen through its underscore.
    for (src, want) in [
        ("pub struct S { pub sdp_offer: u8 }", "sdp"),
        ("fn f(rtp_stream: u8) {}", "rtp"),
        ("pub input_audio: Option<u64>,", "audio"),
        ("let n = webrtc_session_id;", "webrtc"),
    ] {
        let hits = scan_source(src);
        assert!(
            hits.iter().any(|(_, n, _)| *n == want),
            "detector missed the underscore-joined `{want}` in {src:?}: {hits:?}"
        );
    }

    // GREEN: comments only — a doc-comment that discusses the vocabulary is not a leak.
    let green = "// a comment naming sdp webrtc audio and SdpOffer and sdp_offer\n\
                 /* block naming rtp and barge and input_audio */\n\
                 pub struct PlaneRecord;";
    let green_hits = scan_source(green);
    assert!(
        green_hits.is_empty(),
        "detector wrongly flagged a comment: {green_hits:?}"
    );
}

/// EVERY [`NOUN_EXEMPTIONS`] ENTRY IS LIVE AND REALLY NEEDED — the property that makes the list an
/// inventory rather than a waiver list.
///
/// For each entry: the file it names exists under a scanned root, the identifier it names is really
/// in that file, and the line carrying that identifier is one the detector REALLY DOES flag. The
/// last clause is the one that matters: without it an entry could be pure decoration, and the day
/// the field is renamed or deleted the exemption would sit there as standing permission for the
/// next thing to reuse the spelling unchecked.
#[test]
fn every_exemption_is_live_and_really_needed() {
    let root = repo_root();
    assert!(
        !NOUN_EXEMPTIONS.is_empty(),
        "the liveness check ran over an empty list and proved nothing"
    );
    for (file, ident, reason) in NOUN_EXEMPTIONS {
        assert!(
            reason.len() > 80,
            "`{file}`/`{ident}` is exempted with no real argument (\"{reason}\"); an exemption \
             without a stated reason is a waiver, and there are none"
        );
        assert!(
            NEUTRAL_ROOTS.iter().any(|r| file.starts_with(r)),
            "exemption `{file}` is not under any NEUTRAL_ROOT {NEUTRAL_ROOTS:?}, so it exempts \
             nothing this gate scans — delete it"
        );
        let path = root.join(file);
        let src = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "exemption names {} which cannot be read ({e}). A stale exemption is standing \
                 permission; delete it or repoint it.",
                path.display()
            )
        });
        let flagged: Vec<(usize, &'static str, String)> = scan_source(&src)
            .into_iter()
            .filter(|(_, _, text)| text.contains(ident))
            .collect();
        assert!(
            !flagged.is_empty(),
            "exemption `{file}`/`{ident}` covers nothing: the detector flags no line in that file \
             carrying `{ident}`. Either the field is gone or the detector stopped seeing it — \
             delete the entry, in the same commit, so the list cannot rot."
        );
        for (_, _, text) in &flagged {
            assert!(
                is_exempt(file, text),
                "the exemption does not actually cover the line it was written for: {text}"
            );
        }
    }
}

/// AND THE EXEMPTION IS NARROW: it covers ONE identifier in ONE file, and nothing else. A planted
/// leak in the exempted file, and the same identifier in a different file, both still flag — which
/// is what stops an entry from turning into a whole-file amnesty.
#[test]
fn an_exemption_covers_one_identifier_in_one_file_and_nothing_else() {
    let (file, ident, _) = NOUN_EXEMPTIONS[0];
    assert!(
        is_exempt(file, &format!("    pub {ident}: Option<u64>,")),
        "the entry must cover its own field"
    );
    assert!(
        !is_exempt(file, "pub struct SdpOffer;"),
        "a DIFFERENT banned noun in the exempted file is still a leak"
    );
    assert!(
        !is_exempt(
            "crates/busbar-kernel/src/lib.rs",
            &format!("pub {ident}: u64,")
        ),
        "the same identifier in a file the entry does not name is still a leak"
    );
}
