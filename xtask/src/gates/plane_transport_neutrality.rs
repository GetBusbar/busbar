//! `cargo xtask gate plane-transport-neutrality` — NO VOICE-TRANSPORT OR MEDIA NOUN IN THE NEUTRAL
//! CRATES. The successor to `scripts/plane-transport-neutrality.sh`, rule for rule.
//!
//! `plane-purity` bans the plane KEYS and the six LLM dialects as tokens in the neutral crates.
//! Plane 4 drags in a second vocabulary it does not name: the duplex/live-voice TRANSPORT and MEDIA
//! nouns. The voice plane owns them 100%; a leak of any of them into a neutral crate is exactly the
//! forward-edge regression — core learning a protocol's transport words — that the plane ABI exists
//! to prevent. Nothing blocking covered them: `plane-abi-neutrality` scans only the hot lane and
//! `plane-grep-gate` is report-only.
//!
//! Three rows:
//!
//! * `plane-transport-neutrality:neutral-roots` — every listed root is on disk. `find $ROOTS …
//!   2>/dev/null | sort` swallowed the diagnostic for a root that had been renamed, split or
//!   drained, and lost `find`'s status through the pipe: an empty file list, a hit total of 0, and a
//!   green PASS over a tree the gate never opened.
//! * `plane-transport-neutrality:zero-file-refusal` — trusted BEFORE the total is. This catches
//!   every OTHER way the list comes back empty: a root that exists but holds no `.rs`, a layout move
//!   that left the sources one level down. A zero-file scan and a perfectly clean tree produce the
//!   IDENTICAL number, so the count alone can never tell them apart.
//! * `plane-transport-neutrality:no-transport-noun` — the finding.
//!
//! ## THE IDENTIFIER BOUNDARY INCLUDES `_`, AND THAT IS THE WHOLE FIX
//!
//! The boundary class was `[^a-z0-9_]`, borrowed from `plane-purity-lint`'s `word_ci` in order to
//! scope out ONE tracked in-core-twin field. But `_` is the joint in every snake_case Rust name, and
//! snake_case is what fns, fields, locals and modules ARE — so that one carve-out silently exempted
//! `sdp_answer_for`, `rtp_port`, `webrtc_kind`, `audio_track` and `dtmf_digits` too. Planted in
//! `crates/api`, all five passed this gate GREEN. The CamelCase rule could not catch them either: it
//! requires a capital, and snake_case has none.
//!
//! So `_` IS a boundary, and the one token that justified the carve-out is exempted BY NAME IN ITS
//! FILE — never by a line number, which rots into a hole at whatever lands on that line, and never
//! by relaxing the boundary, which takes every other name with it.
//!
//! ## AND AN EXEMPTION THAT COVERS NOTHING IS A DEAD ROW
//!
//! The tracked-twin exemption is the only allowlist here, and the rule the whole crate applies to
//! allowlists applies to it: a waiver that no longer covers a live hit is RED, so the carve-out
//! cannot outlive the field it was written for and sit there as a permanent hole nobody re-reads.
//! It is a finding on the same row rather than a row of its own, because the legacy script has no
//! such check and a row it cannot produce would break the parity proof this conversion turns on.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;
use crate::planes::neutral_src_roots;
use crate::scan;

pub const ROW_ROOTS: &str = "plane-transport-neutrality:neutral-roots";
pub const ROW_ZERO_FILES: &str = "plane-transport-neutrality:zero-file-refusal";
pub const ROW_NO_NOUN: &str = "plane-transport-neutrality:no-transport-noun";

/// The banned voice-transport/media nouns (Plane 4). The lowercase forms drive the WORD rule; their
/// capitalized forms drive the CamelCase-token rule. Every one has ZERO hits in the neutral crates
/// today, and the gate keeps it that way.
pub const NOUNS: &[&str] = &[
    "rtc", "sdp", "webrtc", "twilio", "dtmf", "rtp", "sideband", "realtime", "audio", "mulaw",
    "g711", "barge",
];

/// THE ONE TRACKED IN-CORE-TWIN FIELD. `input_audio`/`output_audio` on the substrate BILLING record
/// are usage-accounting modality fields, not a transport leak, and they are the sole reason `_` was
/// ever excluded from the boundary. Exempted here instead: by exact identifier, in exactly the file
/// that declares them. A `_audio` name anywhere else, or a NEW transport name in this file, flags.
const TWIN_FILE: &str = "crates/busbar-substrate-values/src/billing.rs";
const TWIN_IDENTS: &[&str] = &["input_audio", "output_audio"];

const CLEAN: &str = "the scan cleared its floors and named nothing";
const DID_NOT_RUN: &str = "nothing was read, and nothing read is not a clean tree";

/// One hit, in the shell's TSV shape: `NOUN<TAB>file:line<TAB>trimmed-source`.
fn finding(noun: &str, rel: &str, line: usize, text: &str) -> String {
    format!("{noun}\t{rel}:{line}\t{}", text.trim())
}

fn row_no_noun(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(
            ROW_NO_NOUN,
            "0 voice-transport/media nouns in the neutral crates",
            CLEAN,
        );
    }
    Row::fail(
        ROW_NO_NOUN,
        "a voice-transport/media noun leaked into the neutral crates",
        format!(
            "{} finding(s): {} — cross the ABI as an opaque PlaneRecord or a registry capability, \
             never a transport noun in a neutral crate",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// A whole-word, case-insensitive hit of a lowercase needle, where the identifier boundary is
/// `[^a-z0-9]` — SO `_` IS A BOUNDARY. That one character is the difference between catching
/// `sdp_answer_for` and letting it through.
fn word_ci(lower: &str, needle: &str) -> bool {
    let hay: Vec<char> = lower.chars().collect();
    let n: Vec<char> = needle.chars().collect();
    if n.len() > hay.len() {
        return false;
    }
    for i in 0..=(hay.len() - n.len()) {
        if hay[i..i + n.len()] != n[..] {
            continue;
        }
        let before_ok = i == 0 || !is_word_char(hay[i - 1]);
        let after_ok = i + n.len() == hay.len() || !is_word_char(hay[i + n.len()]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// A Capitalized noun followed by an uppercase letter, a non-identifier character, or end of line:
/// `SdpOffer`, `RtpStream`, `WebrtcTrack`, a bare `Sdp`.
fn camel_hit(code: &str) -> bool {
    let chars: Vec<char> = code.chars().collect();
    for noun in NOUNS {
        let mut cap: Vec<char> = noun.chars().collect();
        cap[0] = cap[0].to_ascii_uppercase();
        if cap.len() > chars.len() {
            continue;
        }
        for i in 0..=(chars.len() - cap.len()) {
            if chars[i..i + cap.len()] != cap[..] {
                continue;
            }
            match chars.get(i + cap.len()) {
                None => return true,
                Some(c) if c.is_ascii_uppercase() => return true,
                Some(c) if !c.is_ascii_alphanumeric() => return true,
                _ => {}
            }
        }
    }
    false
}

/// Is this line covered by the tracked-twin exemption?
fn tracked_twin(rel: &str, code: &str) -> bool {
    rel == TWIN_FILE && TWIN_IDENTS.iter().any(|id| code.contains(id))
}

/// The per-file scan: comments stripped (string literals respected), `#[cfg(test)] mod { … }`
/// bodies dropped, test files excluded. One `scan.rs` for the whole crate — the same
/// `production_lines` every other converted scanner points at.
fn scan_file(rel: &str, text: &str, twin_seen: &mut bool) -> Vec<String> {
    // `*/tests/*` and `*_test(s).rs` are fixtures, not the neutral ABI the crates export.
    if rel.contains("/tests/") || rel.ends_with("_test.rs") || rel.ends_with("_tests.rs") {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (lineno, code) in scan::production_lines(text) {
        if tracked_twin(rel, &code) {
            // The exemption FIRED. Recorded so a carve-out that stops covering anything can be
            // reported as the dead row it has become.
            *twin_seen = true;
            continue;
        }
        let lower = code.to_lowercase();
        for noun in NOUNS {
            if word_ci(&lower, noun) {
                out.push(finding(noun, rel, lineno, &code));
            }
        }
        if camel_hit(&code) {
            out.push(finding("CamelCase", rel, lineno, &code));
        }
    }
    out
}

pub struct PlaneTransportNeutralityGate;

impl Gate for PlaneTransportNeutralityGate {
    fn name(&self) -> &'static str {
        "plane-transport-neutrality"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_ROOTS.to_string(),
            ROW_ZERO_FILES.to_string(),
            ROW_NO_NOUN.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let roots = neutral_src_roots();

        // THE ROOT GUARD, root by root, before any number means anything.
        let missing: Vec<String> = roots
            .iter()
            .filter(|r| !cx.abs(r).is_dir() && !cx.exists(r))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Verdict::of(vec![
                Row::fail(
                    ROW_ROOTS,
                    "a neutral root is listed but not present on disk",
                    format!(
                        "{} — a listed root that does not exist is scanned as ZERO files, and zero \
                         passes every ban. If the crate is legitimately gone, DELETE its entry in a \
                         reviewed diff that says so; never leave a stale root in the list.",
                        missing.join(", ")
                    ),
                ),
                Row::fail(ROW_ZERO_FILES, "the scan set is unknown", DID_NOT_RUN.to_string()),
                Row::fail(ROW_NO_NOUN, "the scan did not run", DID_NOT_RUN.to_string()),
            ]);
        }

        let files = match cx.walk(&WalkSpec::new(roots.clone()).ext("rs")) {
            Ok(f) => f,
            Err(e) => {
                return Verdict::of(vec![
                    Row::fail(ROW_ROOTS, "a neutral root could not be read", e.to_string()),
                    Row::fail(
                        ROW_ZERO_FILES,
                        "the scan set is unknown",
                        DID_NOT_RUN.to_string(),
                    ),
                    Row::fail(ROW_NO_NOUN, "the scan did not run", DID_NOT_RUN.to_string()),
                ])
            }
        };

        // THE ZERO-FILE GUARD, resolved before the total means anything.
        if files.is_empty() {
            return Verdict::of(vec![
                Row::pass(ROW_ROOTS, "every neutral root is present on disk", CLEAN),
                Row::fail(
                    ROW_ZERO_FILES,
                    "the neutral roots hold no source to scan",
                    format!(
                        "0 file(s) across {} neutral root(s) ({}) — a scan of zero files reports \
                         zero nouns, which is indistinguishable from a clean tree.",
                        roots.len(),
                        roots.join(", ")
                    ),
                ),
                Row::fail(ROW_NO_NOUN, "the scan did not run", DID_NOT_RUN.to_string()),
            ]);
        }

        let mut offenders = Vec::new();
        let mut twin_seen = false;
        for f in &files {
            offenders.extend(scan_file(&f.rel_str(), &f.text, &mut twin_seen));
        }

        // A WAIVER THAT COVERS NOTHING IS RED. The carve-out cannot outlive the field it excused.
        if !twin_seen && cx.exists(TWIN_FILE) {
            offenders.push(format!(
                "dead-exemption\t{TWIN_FILE}\tthe tracked in-core-twin exemption ({}) no longer \
                 covers any line in its declaring file, so it is a permanent hole nobody re-reads. \
                 Strike it.",
                TWIN_IDENTS.join("/")
            ));
        }
        offenders.sort();

        Verdict::of(vec![
            Row::pass(ROW_ROOTS, "every neutral root is present on disk", CLEAN),
            Row::pass(
                ROW_ZERO_FILES,
                "the neutral roots hold source to scan",
                CLEAN,
            ),
            row_no_noun(&offenders),
        ])
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        Some(translate(run))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the neutral crates name no voice-transport or media noun",
            &[ROW_ROOTS, ROW_ZERO_FILES, ROW_NO_NOUN],
        ));

        // THE ROOT GUARD. `Overlay::remove` cannot trip it — the guard asks `cx.abs(r).is_dir()`,
        // which reads the real disk past the overlay — so the row had no red proof and the guard
        // could have been deleted with the selftest green. Re-rooting the whole context at a tree
        // that holds none of the neutral crates is the plant that works, and it is the shape the
        // guard exists for: a listed root that is not there is scanned as zero files, and zero
        // files pass every ban in this gate.
        report.push(crate::gates::prove_rows_red_at(
            cx,
            self,
            "a neutral root that is not on disk is refused, not scanned as zero files",
            &[ROW_ROOTS],
            crate::gates::PLANE_ROOT_MISSING_FIXTURE,
            &["not present on disk"],
        ));

        let neutral = neutral_src_roots();
        let api = neutral
            .iter()
            .find(|r| r.starts_with("crates/api"))
            .cloned()
            .unwrap_or_else(|| neutral[0].clone());

        // THE CAMELCASE AND BARE-WORD SHAPES the design names.
        let mut ov = Overlay::new();
        ov.set(
            format!("{api}/planted_camel.rs"),
            "pub struct SdpOffer { fingerprint: String }\npub struct RtpStream;\n\
             pub struct TwilioBridge;\nfn negotiate() { let kind = \"webrtc\"; let realtime = true; }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "the CamelCase tokens and the bare transport words are all flagged",
            &[ROW_NO_NOUN],
            ov,
            &["CamelCase", "webrtc", "realtime"],
        ));

        // THE SHAPE THE OLD BOUNDARY MADE INVISIBLE. Every other fixture is CamelCase or a bare
        // lowercase word, which is exactly why the hole survived this gate's own RED proof for as
        // long as it did. Each of these five was planted in a neutral crate and passed GREEN.
        let mut ov = Overlay::new();
        ov.set(
            format!("{api}/planted_snake.rs"),
            "pub fn sdp_answer_for(rtp_port: u16) -> String { let webrtc_kind = rtp_port; \
             format!(\"{}\", webrtc_kind) }\n\
             pub struct Leak { pub audio_track: u32, pub dtmf_digits: u8 }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a transport noun as a segment of a snake_case name is flagged (`_` is a boundary)",
            &[ROW_NO_NOUN],
            ov,
            &["sdp", "rtp", "webrtc", "audio", "dtmf"],
        ));

        // THE EXEMPTION IS KEYED TO FILE AND IDENTIFIER, so it cannot become a blanket hole: the
        // SAME identifier outside its declaring file still flags.
        let mut ov = Overlay::new();
        ov.set(
            format!("{api}/planted_twin_elsewhere.rs"),
            "pub struct U { pub input_audio: Option<u64> }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "the tracked twin identifier outside its declaring file still flags",
            &[ROW_NO_NOUN],
            ov,
            &["audio", "planted_twin_elsewhere.rs"],
        ));

        // ...and a FRESH transport name inside that same file flags too.
        let mut ov = Overlay::new();
        let twin = cx.read(TWIN_FILE).unwrap_or_default();
        ov.set(
            TWIN_FILE,
            format!("{twin}\npub struct V {{ pub sdp_answer: u8 }}\n"),
        );
        report.push(prove_red(
            cx,
            self,
            "a new transport name in the tracked twin's own file still flags",
            &[ROW_NO_NOUN],
            ov,
            &["sdp"],
        ));

        // A DEAD EXEMPTION. Strip the twin field from its declaring file and the carve-out covers
        // nothing — a permanent hole nobody re-reads, reported rather than left standing.
        let mut ov = Overlay::new();
        ov.set(
            TWIN_FILE,
            twin.lines()
                .filter(|l| !TWIN_IDENTS.iter().any(|id| l.contains(id)))
                .collect::<Vec<_>>()
                .join("\n"),
        );
        report.push(prove_red(
            cx,
            self,
            "an exemption that no longer covers a live hit is reported as dead",
            &[ROW_NO_NOUN],
            ov,
            &["dead-exemption"],
        ));

        // PROSE AND TESTS ARE NOT A LEAK — and a gate its own explanation fails is a gate people
        // learn to skip. The CONTROL below is what makes this a proof of the exclusion rather than
        // of a blind scanner: the same tokens in real code DO flag, two cases up.
        let mut ov = Overlay::new();
        ov.set(
            format!("{api}/planted_prose.rs"),
            "// a comment naming sdp webrtc rtp twilio dtmf realtime audio mulaw and SdpOffer\n\
             /* a block comment naming RtpStream and g711 and barge-in also ignored */\n\
             pub fn install() -> u64 { 0 }\n\
             #[cfg(test)]\nmod tests {\n\
             \x20   fn t() { let _ = \"webrtc\"; let _o = SdpOffer::default(); }\n}\n",
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "comment, block-comment and cfg(test) mentions flag nothing",
            &[ROW_NO_NOUN],
        ));

        // THE BLIND SCANS: the gate must not be able to pass by looking at nothing. A root that is
        // not there, and a root that is there and holds no source, are two different facts and each
        // gets its own case.
        let mut ov = Overlay::new();
        match cx.walk(&WalkSpec::new(neutral.clone()).ext("rs")) {
            Ok(files) => {
                for f in &files {
                    ov.remove(&f.rel);
                }
                report.push(prove_red(
                    cx,
                    self,
                    "a neutral root holding no source is refused, not scanned as zero hits",
                    &[ROW_ZERO_FILES],
                    ov,
                    &["indistinguishable from a clean tree"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "plane-transport-neutrality selftest: the neutral roots are unreadable ({e})"
            )),
        }

        report
    }
}

/// Read the shell gate's own output into the same three rows. Its hits are printed as the same TSV
/// triples the scanner emits, indented under the FAIL line.
fn translate(run: &LegacyRun) -> Result<Vec<Row>, String> {
    let mut offenders = Vec::new();
    let mut missing_root = None;
    let mut zero_files = None;
    let mut ran = false;

    for raw in run.lines() {
        let t = decolour(raw);
        let t = t.trim();
        if t.contains("neutral root(s) listed but not present on disk") {
            missing_root = Some(t.to_string());
            continue;
        }
        if t.contains("zero is RED") {
            zero_files = Some(t.to_string());
            continue;
        }
        if t.contains("gate: PASS") || t.starts_with("neutral roots:") {
            ran = true;
            continue;
        }
        if t.contains("gate: FAIL") && t.contains("leaked into the neutral crates") {
            ran = true;
            continue;
        }
        // A hit line is the scanner's TSV, indented: NOUN \t file:line \t source.
        if t.matches('\t').count() >= 2 {
            ran = true;
            offenders.push(t.to_string());
        }
    }

    if missing_root.is_none() && zero_files.is_none() && !ran {
        return Err(format!(
            "the legacy translator recognised nothing in `{}`'s output: no verdict line, no \
             findings. Silence read as a clean tree is the exact defect this gate exists for.",
            run.argv.join(" ")
        ));
    }

    if let Some(why) = missing_root {
        return Ok(vec![
            Row::fail(
                ROW_ROOTS,
                "a neutral root is listed but not present on disk",
                why,
            ),
            Row::fail(
                ROW_ZERO_FILES,
                "the scan set is unknown",
                DID_NOT_RUN.to_string(),
            ),
            Row::fail(ROW_NO_NOUN, "the scan did not run", DID_NOT_RUN.to_string()),
        ]);
    }
    if let Some(why) = zero_files {
        return Ok(vec![
            Row::pass(ROW_ROOTS, "every neutral root is present on disk", CLEAN),
            Row::fail(
                ROW_ZERO_FILES,
                "the neutral roots hold no source to scan",
                why,
            ),
            Row::fail(ROW_NO_NOUN, "the scan did not run", DID_NOT_RUN.to_string()),
        ]);
    }

    offenders.sort();
    Ok(vec![
        Row::pass(ROW_ROOTS, "every neutral root is present on disk", CLEAN),
        Row::pass(
            ROW_ZERO_FILES,
            "the neutral roots hold source to scan",
            CLEAN,
        ),
        row_no_noun(&offenders),
    ])
}

/// Drop the SGR escapes the shell's `red()`/`grn()` wrap their verdict lines in.
fn decolour(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        for c in chars.by_ref() {
            if c == 'm' {
                break;
            }
        }
    }
    out
}
