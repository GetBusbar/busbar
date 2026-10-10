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
//! * `plane-transport-neutrality:neutral-roots` — THE CENSUS ROW. The scanned population is not a
//!   list: it is [`neutral_census`], kind-isolation's crate census read off the kind table, so a
//!   neutral crate created today is scanned today. The row holds that every `crates/*/src` is either
//!   census-neutral (and on disk, and scanned) or named non-neutral by its family (plane,
//!   transport). A crate the census cannot classify — no manifest, a name no kind claims, a name two
//!   kinds claim — is in no population and so in no scan, and is RED here; so is a census-neutral
//!   crate whose `src/` is not on disk, which would be scanned as zero files. (Before the census,
//!   this row checked a hand list, `planes::neutral_src_roots`, that enrolled a new neutral crate
//!   only when somebody remembered it.)
//! * `plane-transport-neutrality:zero-file-refusal` — THE FILE-COUNT FLOOR, trusted BEFORE the total
//!   is: [`MIN_FILES`], the `.rs` count measured on predev. It catches every OTHER way the scan set
//!   shrinks: a root that exists but holds no `.rs`, a layout move that left the sources one level
//!   down, a tree that lost files. It was `files.is_empty()`, under which one surviving file passed.
//!   A shrunken scan and a cleaner tree produce the same number, so the count alone can never tell
//!   them apart.
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
use crate::gates::kind_isolation::{neutral_census, neutral_kind_src_roots};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;
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

/// THE ONE TRACKED IN-CORE-TWIN FIELD. `input_audio`/`output_audio` on the contract BILLING record
/// are usage-accounting modality fields, not a transport leak, and they are the sole reason `_` was
/// ever excluded from the boundary. Exempted here instead: by exact identifier, in exactly the file
/// that declares them. A `_audio` name anywhere else, or a NEW transport name in this file, flags.
const TWIN_FILE: &str = "crates/busbar-contract/src/billing.rs";
const TWIN_IDENTS: &[&str] = &["input_audio", "output_audio"];

/// THE FILE-COUNT FLOOR: the `.rs` files the census-neutral roots held on predev, measured
/// (39374ec00e, 2026-10-09). A scan set under it is refused rather than read as a cleaner tree:
/// the hand list's guard was `files.is_empty()`, so a root list that collapsed to one file passed.
/// Raised as the neutral crates grow; lowered only in a reviewed diff that names the files that
/// legitimately left.
///
/// Was 1231 on 0fd08ee75d. Lowered by the egress-auth move out of the kernel (5c23d7527): 13
/// `busbar-kernel/src` files left (`auth_cache.rs`, `egress_auth/{mod,bearer_token,jwt_bearer,
/// oauth_client_credentials}.rs`, `egress_auth/tests/{bearer_token,helper,jwt_bearer,
/// oauth_client_credentials,prebuilt_auth}_tests.rs`, `tests/auth_cache_tests.rs`,
/// `tests/members/identity/{declared,egress_auth}_tests.rs`) and 11 `busbar-kernel-identity/src`
/// files (`cache.rs`, `ingress_sigv4.rs`, `egress_auth/{mod,declared,declared_tests,tests,
/// token_response}.rs`, `egress_auth/sigv4/{mod,tests}.rs`, `tests/{cache,ingress_sigv4}_tests.rs`),
/// against 6 arrivals there (net -18, 1213); then raised by 7 files predev landed by 39374ec00e.
pub const MIN_FILES: usize = 1220;

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
        // THE POPULATION IS THE CENSUS'S. Every `crates/*` the kind table classes neutral is
        // scanned; a hand list enrolled a new neutral crate only when somebody remembered it.
        let census = match neutral_census(cx) {
            Ok(c) => c,
            Err(e) => {
                return Verdict::of(vec![
                    Row::fail(ROW_ROOTS, "the crate census could not be read", e),
                    Row::fail(
                        ROW_ZERO_FILES,
                        "the scan set is unknown",
                        DID_NOT_RUN.to_string(),
                    ),
                    Row::fail(ROW_NO_NOUN, "the scan did not run", DID_NOT_RUN.to_string()),
                ])
            }
        };

        // THE CENSUS ROW: every `crates/*/src` is census-neutral and scanned, or named non-neutral
        // by its family. A crate the census cannot classify is in no population and so in no scan;
        // a census-neutral crate whose source is not on disk would be scanned as zero files.
        let mut census_findings: Vec<String> = census
            .unclassified
            .iter()
            .map(|(dir, why)| format!("{dir}: {why}"))
            .collect();
        census_findings.extend(census.sourceless.iter().map(|r| {
            format!(
                "{r}: the census classes this crate neutral but its source is not present on \
                 disk — a neutral root that does not exist is scanned as ZERO files, and zero \
                 passes every ban. If the crate is legitimately gone, strike its manifest with it."
            )
        }));
        if census.neutral.is_empty() {
            census_findings.push(
                "the census classes no crate under crates/ neutral — an empty population is the \
                 passing answer to every ban"
                    .to_string(),
            );
        }
        let non_neutral = census
            .non_neutral
            .iter()
            .map(|(dir, family)| format!("{dir} ({family})"))
            .collect::<Vec<_>>()
            .join(", ");
        let roots_row = if census_findings.is_empty() {
            Row::pass(
                ROW_ROOTS,
                "every crates/*/src is census-neutral and scanned, or named non-neutral by its \
                 family",
                format!(
                    "{} census-neutral root(s) scanned; {} crate(s) named non-neutral: {}",
                    census.neutral.len(),
                    census.non_neutral.len(),
                    non_neutral
                ),
            )
        } else {
            Row::fail(
                ROW_ROOTS,
                "a crate under crates/ is outside the neutral census",
                format!(
                    "{} finding(s): {} — every crates/*/src must be census-neutral (and present) \
                     or named non-neutral by its family in the kind table",
                    census_findings.len(),
                    census_findings.join(" | ")
                ),
            )
        };

        // The scan reads the neutral roots that ARE on disk; a sourceless one is already the
        // census row's finding, and the floor below counts what was actually read.
        let roots: Vec<String> = census
            .neutral
            .iter()
            .filter(|r| !census.sourceless.contains(r))
            .cloned()
            .collect();

        // `allow_empty`, because THE FILE-COUNT FLOOR BELOW IS THIS GATE'S OWN ROW. Left to the
        // walk, an empty scan set came back as a walk ERROR and was reported on the roots row as
        // "could not be read" — the refusal happened, but on a row that does not own it.
        let files = if roots.is_empty() {
            Vec::new()
        } else {
            match cx.walk(&WalkSpec::new(roots.clone()).ext("rs").allow_empty()) {
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
            }
        };

        // THE FILE-COUNT FLOOR, resolved before the total means anything. `files.is_empty()`
        // passed a scan set that had collapsed to one surviving file.
        if files.len() < MIN_FILES {
            return Verdict::of(vec![
                roots_row,
                Row::fail(
                    ROW_ZERO_FILES,
                    "the neutral roots hold less source than the measured floor",
                    format!(
                        "{} file(s) across {} census-neutral root(s), under the floor of \
                         {MIN_FILES} measured on predev — a scan that lost files reports fewer \
                         nouns, which is indistinguishable from a clean tree. If the sources \
                         legitimately moved or shrank, re-measure the floor in a reviewed diff.",
                        files.len(),
                        roots.len()
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
            roots_row,
            Row::pass(
                ROW_ZERO_FILES,
                "the neutral roots hold source to scan",
                format!(
                    "{} file(s) across {} census-neutral root(s), floor {MIN_FILES}",
                    files.len(),
                    roots.len()
                ),
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

        // A TREE THE CENSUS CANNOT READ. Re-rooted at a fixture with a `crates/*/src` and no
        // manifest anywhere, the census has nothing to classify; that is refused on the census row,
        // never read as an empty neutral population scanned as zero files.
        report.push(crate::gates::prove_rows_red_at(
            cx,
            self,
            "a tree with no crate census is refused, not scanned as zero files",
            &[ROW_ROOTS],
            crate::gates::PLANE_ROOT_MISSING_FIXTURE,
            &["yielded ZERO files"],
        ));

        let neutral = match neutral_kind_src_roots(cx) {
            Ok(n) => n,
            Err(e) => {
                report.note_infra_failure(format!(
                    "plane-transport-neutrality selftest: the neutral census is unreadable ({e})"
                ));
                return report;
            }
        };
        let api = neutral
            .iter()
            .find(|r| r.starts_with("crates/busbar-kernel/"))
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

        // A NEUTRAL CRATE NOBODY LISTED. The census classes `busbar-kernel-*` neutral by its name,
        // so a crate created today is scanned today: the transport noun in it is a finding on the
        // day it lands, not on the day somebody remembers to enrol its root.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-kernel-planted/Cargo.toml",
            "[package]\nname = \"busbar-kernel-planted\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        );
        ov.set(
            "crates/busbar-kernel-planted/src/lib.rs",
            "pub fn f() -> u16 { let rtp_port = 1; rtp_port }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a new census-neutral crate carrying a transport noun is scanned and flagged",
            &[ROW_NO_NOUN],
            ov,
            &["rtp", "crates/busbar-kernel-planted/src/lib.rs"],
        ));

        // A CRATE THE CENSUS CANNOT CLASSIFY. Its name resolves to no kind, so it is neither a
        // neutral crate the scan reads nor a plane or transport its family names: it is in no
        // population at all, and that is the census row's finding.
        let mut ov = Overlay::new();
        ov.set(
            "crates/widget-planted/Cargo.toml",
            "[package]\nname = \"widget-planted\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        );
        ov.set(
            "crates/widget-planted/src/lib.rs",
            "pub fn f() -> u16 { let rtp_port = 1; rtp_port }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a crates/*/src the census cannot classify is refused on the census row",
            &[ROW_ROOTS],
            ov,
            &["crates/widget-planted", "cannot classify"],
        ));

        // A CENSUS-NEUTRAL CRATE WITH NO SOURCE ON DISK. The manifest says the crate is there and
        // neutral; its `src/` is not. That root would be scanned as zero files.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-kernel-ghost/Cargo.toml",
            "[package]\nname = \"busbar-kernel-ghost\"\nversion = \"0.0.0\"\nedition = \"2021\"\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a census-neutral crate whose src/ is not on disk is refused, not scanned as zero files",
            &[ROW_ROOTS],
            ov,
            &["crates/busbar-kernel-ghost/src", "not present on disk"],
        ));

        // ONE FILE UNDER THE FLOOR. `files.is_empty()` passed a scan set that had collapsed to a
        // single surviving file; the floor is the count measured on predev, so a scan set of
        // `MIN_FILES - 1` is refused rather than read as a cleaner tree. The plant KEEPS exactly
        // that many files and removes the rest: removing one file proved the floor only on a tree
        // that held exactly `MIN_FILES`, and a tree that grows keeps this floor (as `seal-witness`).
        match cx.list(&WalkSpec::new(neutral.clone()).ext("rs")) {
            Ok(rels) => {
                let twin = std::path::Path::new(TWIN_FILE);
                let keep = MIN_FILES - 1 - usize::from(rels.iter().any(|r| r == twin));
                let mut ov = Overlay::new();
                for rel in rels.iter().filter(|r| *r != twin).skip(keep) {
                    ov.remove(rel);
                }
                let found = format!("{} file(s) across", MIN_FILES - 1);
                report.push(prove_red(
                    cx,
                    self,
                    "a neutral scan set one file under the measured floor is refused",
                    &[ROW_ZERO_FILES],
                    ov,
                    &["under the floor", found.as_str()],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "plane-transport-neutrality selftest: the neutral roots are unreadable ({e})"
            )),
        }

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
///
/// THE POPULATIONS DIFFER, AND ONLY IN ONE DIRECTION. The shell scanned its own hand-typed `ROOTS`;
/// this gate scans the census-neutral set, which is a superset of it (it adds `crates/busbar` and
/// `crates/store-memory` on predev 0fd08ee75d, both measured clean). So parity holds row for row
/// over every tree where the added crates carry no noun, and where one does, the Rust gate is red
/// and the shell is green — the enrolment hole the census closes, never a rule the shell had and
/// this gate lost. The shell's census-row and floor checks were a listed-root guard and an empty
/// guard; the translator keeps reading those two shapes onto the same two rows.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// THE FLOOR PLANT ON A TREE THAT HAS GROWN PAST THE FLOOR. Removing one file proved the floor
    /// only while the census-neutral roots held exactly [`MIN_FILES`]; the merge group of #605 ran
    /// it over a predev that held more, and the case came back green. Every owed row is proven RED
    /// over the real tree, whatever it has grown to.
    #[test]
    fn the_selftest_proves_every_owed_row_over_the_real_tree() {
        let cx = Ctx::workspace().expect("workspace context");
        let report = PlaneTransportNeutralityGate.selftest(&cx);
        crate::gates::verify_report(&PlaneTransportNeutralityGate, &report)
            .unwrap_or_else(|errs| panic!("plane-transport-neutrality selftest: {errs:#?}"));
        assert_eq!(report.skipped(), 0, "a case had nothing to plant");
    }
}
