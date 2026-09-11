//! `cargo xtask gate plane-abi-neutrality` — THE NEUTRALITY WITNESS FOR THE PROTOCOL-PLANE ABI.
//! The successor to `scripts/plane-abi-neutrality.sh`, rule for rule.
//!
//! The plane ABI's whole claim is that its capability surface was DERIVED from a primitive taxonomy
//! (carrier / scope / egress / metering), NOT ENUMERATED from any one protocol plane. That claim
//! rots silently the first time someone names a type, fn or variant after a protocol or role noun.
//! This is the machine check that "derived, not enumerated" STAYS true as capabilities are added:
//! it scans the HOT lane of `busbar-plugin` for the banned set and asserts zero. Only the hot lane —
//! the COLD lane keeps its pre-existing store/auth/hook vocabulary and is deliberately exempt, and
//! the shared crate root is neutral by construction.
//!
//! Six rows, and the first three are about whether the ban list can be trusted at all:
//!
//! * `plane-abi-neutrality:mandate-document` — THE MANDATE COMES FROM THE DESIGN, NOT FROM A COPY
//!   OF THE ANSWER. The mandated list used to be a character-for-character duplicate of the ban
//!   list two lines above it, which made the check a tautology: it compared a list against itself,
//!   could not fail, and reported "self-check passed" on the very omission it exists to catch —
//!   `server`/`card`, whose absence let a `server-stream` leak through. So the mandate is READ FROM
//!   THE DOCUMENT that issues it, and a document that is not there is RED rather than a silent
//!   fallback to the ban list, which is the same tautology in a different coat.
//! * `plane-abi-neutrality:ban-list-complete` — every mandated token is in the ban list. A witness
//!   cannot catch a leak of a token it does not list.
//! * `plane-abi-neutrality:plane-keys-covered` — every CANONICAL plane key is banned. The ban list
//!   is a curated superset; the keys it must never omit are single-sourced, so the day a plane lands
//!   this row lands with it.
//! * `plane-abi-neutrality:hot-lane-present` — the lane exists AND holds Rust. A directory that
//!   exists but carries no `.rs` greps clean, and zero banned nouns over zero files is the passing
//!   answer to the only ban here — indistinguishable from a genuinely derived surface.
//! * `plane-abi-neutrality:exported-declarations` — the invariant, ceiling 0.
//! * `plane-abi-neutrality:test-path-ratchet` — BOTH HALVES, NEITHER HIDDEN. A `#[test] fn
//!   …_round_trips_…` under `hot/tests/` exports nothing, so counting it as an ABI leak is the wrong
//!   verdict — but deleting it from the scan without saying so is a gate quietly narrowing itself.
//!   It is a ratchet at today's count that may only go DOWN, and the sites are printed either way.

use crate::ctx::{Ctx, Edit, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;
use crate::planes::{PLANE_GRAMMAR, PLANE_KEYS};

pub const ROW_MANDATE: &str = "plane-abi-neutrality:mandate-document";
pub const ROW_BAN_LIST: &str = "plane-abi-neutrality:ban-list-complete";
pub const ROW_PLANE_KEYS: &str = "plane-abi-neutrality:plane-keys-covered";
pub const ROW_HOT_LANE: &str = "plane-abi-neutrality:hot-lane-present";
pub const ROW_EXPORTED: &str = "plane-abi-neutrality:exported-declarations";
pub const ROW_TEST_RATCHET: &str = "plane-abi-neutrality:test-path-ratchet";

const HOT_LANE: &str = "crates/busbar-plugin/src/hot";
const TAXONOMY_DOC: &str = "docs/design/1.6.0-plane-abi-taxonomy.md";

/// The banned protocol/role nouns. Matched case-insensitively as SUBSTRINGS of identifiers on
/// declaration lines: a banned noun concatenated into a name — `McpTransport`, `server_stream` — is
/// exactly the leak to catch, and a word-boundary match would miss it.
const BANNED: &[&str] = &[
    "llm", "mcp", "a2a", "tool", "agent", "sampling", "task", "server", "card", "round", "prompt",
    "voice", "realtime", "audio",
];

/// The Plane-4 nouns this witness's own header commits to, cited to their section. `voice` is a
/// canonical plane key and is enforced by the totality row below; `realtime` and `audio` are named
/// in prose rather than a machine-readable list, so they are restated here WITH that citation
/// instead of being parsed out of a sentence.
const MANDATED_EXTRA: &[&str] = &["realtime", "audio"];

/// Today's measured number, not a round one. The test tree legitimately says "round trip" about a
/// round trip — but a test name is still a name, and letting the number grow is how the vocabulary
/// creeps back in one helper at a time. Lower it when a name goes; never raise it. A `const` with
/// no environment override: the only way to move one is a reviewable source edit.
///
/// It was 1 when this gate was written against the branch that converted it. The one name it
/// covered is gone from `hot/tests/` on the integration tree, so the ratchet follows it down — that
/// is the direction the paragraph above permits, and leaving it at 1 would have left the gate a
/// spare slot for the next helper to creep into.
const TEST_PATH_RATCHET: usize = 0;

const CLEAN: &str = "the scan cleared its floors and named nothing";
const DID_NOT_RUN: &str = "nothing was read, and nothing read is not a neutral ABI";

fn finding(rel: &str, line: usize, code: &str) -> String {
    format!("{rel}:{line}:{code}")
}

fn row_exported(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(
            ROW_EXPORTED,
            "0 banned protocol/role nouns in exported plane-ABI declarations",
            CLEAN,
        );
    }
    Row::fail(
        ROW_EXPORTED,
        "a banned protocol/role noun is in a plane-ABI declaration",
        format!(
            "{} finding(s): {} — the plane ABI must be DERIVED from the primitive taxonomy, never \
             named after one protocol",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

fn row_ratchet(offenders: &[String]) -> Row {
    if offenders.len().saturating_sub(TEST_PATH_RATCHET) == 0 {
        return Row::pass(
            ROW_TEST_RATCHET,
            "test-path declarations carrying a banned noun are at or under their ratchet",
            CLEAN,
        );
    }
    Row::fail(
        ROW_TEST_RATCHET,
        "test-path declarations carrying a banned noun are over their ratchet",
        format!(
            "{} finding(s) against a ratchet of {TEST_PATH_RATCHET}, which may only go down: {}",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

/// A DECLARATION-ish line: one that introduces a Rust identifier, or a `pub` field / enum variant.
/// The pre-filter is what keeps prose in `///` doc comments — which legitimately discusses
/// neutrality — out of scope, so only the names the ABI actually exports are scanned.
fn is_declaration(line: &str) -> bool {
    let t = line.trim_start();
    let t = t.strip_prefix("pub ").map(str::trim_start).unwrap_or(t);
    for kw in ["struct", "enum", "fn", "type", "const", "trait", "mod"] {
        if let Some(rest) = t.strip_prefix(kw) {
            if rest.starts_with(|c: char| c.is_whitespace()) {
                return true;
            }
        }
    }
    // `Ident:` / `Ident(` / `Ident=` / `Ident,` — a field or an enum variant.
    let mut chars = t.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }
    let ident_len = t
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .unwrap_or(t.len());
    let rest = t[ident_len..].trim_start();
    rest.starts_with([':', '(', '=', ','])
}

/// The scan. MATCHES THE CODE, NOT THE PATH: the shell greps an ABSOLUTE root, so under a checkout
/// directory that happens to contain a banned noun — a git worktree is literally named
/// `agent-<hash>`, and `agent` is banned — a naive match over the prefixed line matched the PATH on
/// every declaration and the witness failed everywhere, spuriously. Only the source line is judged.
fn scan(files: &[crate::ctx::SourceFile]) -> (Vec<String>, Vec<String>) {
    let mut prod = Vec::new();
    let mut test = Vec::new();
    for f in files {
        let rel = f.rel_str();
        let is_test_path =
            rel.contains("/tests/") || rel.ends_with("_test.rs") || rel.ends_with("_tests.rs");
        for (i, line) in f.text.lines().enumerate() {
            if !is_declaration(line) {
                continue;
            }
            let lower = line.to_lowercase();
            if !BANNED.iter().any(|b| lower.contains(b)) {
                continue;
            }
            let hit = finding(&rel, i + 1, line);
            if is_test_path {
                test.push(hit);
            } else {
                prod.push(hit);
            }
        }
    }
    prod.sort();
    test.sort();
    (prod, test)
}

/// The plane keys THIS TREE DECLARES, read off the crates that carry a plane declaration.
///
/// The totality row used to compare `PLANE_KEYS` with `BANNED` — two `const`s in this runner. Two
/// literals agreeing is not a fact about the tree, and no tree could falsify it: the row was green
/// by construction, which is the one shape a ledger row must never have. What the ban list actually
/// has to cover is the planes that EXIST, so they are counted where they are declared. A fifth
/// plane crate landing with a noun nobody banned is the defect this row names, and reading the
/// declarations is what lets it see one.
///
/// The key is the crate directory's name without its `busbar-` prefix, which is how every plane
/// crate in this tree is spelled (`busbar-llm` → `llm`). A plane whose crate is named otherwise
/// reads here as an unbanned key — loud, and in the direction that asks a human to look.
fn declared_plane_keys(cx: &Ctx) -> Result<Vec<String>, String> {
    let files = cx
        .walk(&WalkSpec::new(["crates"]).ext("rs").min_files(1))
        .map_err(|e| e.to_string())?;
    let mut keys: Vec<String> = Vec::new();
    for f in &files {
        if !f
            .text
            .lines()
            .any(|l| l.trim_start().starts_with(PLANE_GRAMMAR))
        {
            continue;
        }
        let rel = f.rel_str();
        let Some(krate) = rel
            .strip_prefix("crates/")
            .and_then(|r| r.split('/').next())
        else {
            continue;
        };
        let key = krate.strip_prefix("busbar-").unwrap_or(krate).to_string();
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys.sort();
    Ok(keys)
}

/// The mandated token list, READ FROM THE DOCUMENT that issues it: the backticked alternation after
/// `banned set` in the taxonomy's neutrality-witness section.
fn mandated(cx: &Ctx) -> Result<Vec<String>, String> {
    let text = cx.read(TAXONOMY_DOC).map_err(|e| {
        format!(
            "the mandate document is missing at {TAXONOMY_DOC} ({e}). The ban list cannot be \
             checked against the design that issues it, so this witness would be checking its own \
             answer. That is the tautology this row exists to refuse."
        )
    })?;
    for line in text.lines() {
        let Some(after) = line.split("banned set `").nth(1) else {
            continue;
        };
        let Some(alt) = after.split('`').next() else {
            continue;
        };
        if alt.trim().is_empty() {
            continue;
        }
        let mut out: Vec<String> = alt.split('|').map(|s| s.trim().to_string()).collect();
        out.extend(MANDATED_EXTRA.iter().map(|s| (*s).to_string()));
        return Ok(out);
    }
    Err(format!(
        "no `banned set `…`` line in {TAXONOMY_DOC}. The witness reads its mandate from that line; \
         if the section was renamed, point this gate at the new one rather than letting the mandate \
         default to the ban list itself."
    ))
}

pub struct PlaneAbiNeutralityGate;

impl Gate for PlaneAbiNeutralityGate {
    fn name(&self) -> &'static str {
        "plane-abi-neutrality"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_MANDATE.to_string(),
            ROW_BAN_LIST.to_string(),
            ROW_PLANE_KEYS.to_string(),
            ROW_HOT_LANE.to_string(),
            ROW_EXPORTED.to_string(),
            ROW_TEST_RATCHET.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut rows = Vec::new();

        let mandate = mandated(cx);
        match &mandate {
            Ok(_) => rows.push(Row::pass(
                ROW_MANDATE,
                "the mandate document issues a banned set this gate can read",
                CLEAN,
            )),
            Err(why) => rows.push(Row::fail(
                ROW_MANDATE,
                "the mandate document cannot be read",
                why.clone(),
            )),
        }

        match &mandate {
            Ok(tokens) => {
                let missing: Vec<&str> = tokens
                    .iter()
                    .map(String::as_str)
                    .filter(|t| !BANNED.contains(t))
                    .collect();
                rows.push(if missing.is_empty() {
                    Row::pass(
                        ROW_BAN_LIST,
                        "the ban list carries every token the design mandates",
                        CLEAN,
                    )
                } else {
                    Row::fail(
                        ROW_BAN_LIST,
                        "the ban list is missing tokens the design mandates",
                        format!(
                            "{} — the witness cannot catch a leak of a token it does not list",
                            missing.join(", ")
                        ),
                    )
                });
            }
            Err(_) => rows.push(Row::fail(
                ROW_BAN_LIST,
                "the mandate is unknown",
                DID_NOT_RUN.to_string(),
            )),
        }

        rows.push(match declared_plane_keys(cx) {
            Err(why) => Row::fail(
                ROW_PLANE_KEYS,
                "the planes this tree declares could not be read",
                format!("{why} — {DID_NOT_RUN}"),
            ),
            Ok(declared) => {
                let mut keys: Vec<String> = PLANE_KEYS.iter().map(|k| (*k).to_string()).collect();
                for k in declared {
                    if !keys.contains(&k) {
                        keys.push(k);
                    }
                }
                let missing_keys: Vec<&str> = keys
                    .iter()
                    .map(String::as_str)
                    .filter(|k| !BANNED.contains(k))
                    .collect();
                if missing_keys.is_empty() {
                    Row::pass(
                        ROW_PLANE_KEYS,
                        "every plane key this tree declares is in the ban list",
                        CLEAN,
                    )
                } else {
                    Row::fail(
                        ROW_PLANE_KEYS,
                        "a plane key this tree declares is not in the ban list",
                        format!(
                            "{} — the witness cannot catch a leak of a plane noun it does not list",
                            missing_keys.join(", ")
                        ),
                    )
                }
            }
        });

        let files = cx.walk(&WalkSpec::new([HOT_LANE]).ext("rs").min_files(1));
        match files {
            Ok(files) => {
                rows.push(Row::pass(
                    ROW_HOT_LANE,
                    "the hot lane is present and holds Rust",
                    CLEAN,
                ));
                let (prod, test) = scan(&files);
                rows.push(row_exported(&prod));
                rows.push(row_ratchet(&test));
            }
            Err(e) => {
                rows.push(Row::fail(
                    ROW_HOT_LANE,
                    "the hot lane is absent or holds no Rust",
                    format!(
                        "{e} A scan of zero files reports zero banned nouns, which reads exactly \
                         like a neutral ABI. If the hot lane moved, point this gate at its new home \
                         in a reviewed diff that says so."
                    ),
                ));
                rows.push(Row::fail(
                    ROW_EXPORTED,
                    "the scan did not run",
                    DID_NOT_RUN.to_string(),
                ));
                rows.push(Row::fail(
                    ROW_TEST_RATCHET,
                    "the scan did not run",
                    DID_NOT_RUN.to_string(),
                ));
            }
        }
        Verdict::of(rows)
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        Some(translate(run))
    }

    fn selftest(&self, cx: &Ctx) -> Report {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the plane ABI names no protocol or role noun",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        // A BANNED NOUN IN AN EXPORTED DECLARATION.
        let mut ov = Overlay::new();
        ov.set(
            format!("{HOT_LANE}/planted_leak.rs"),
            format!("pub struct {}Transport;\n", "Mcp"),
        );
        report.push(prove_red(
            cx,
            self,
            "a banned noun in an exported declaration is a finding",
            &[ROW_EXPORTED],
            ov,
            &["planted_leak.rs"],
        ));

        // ...AND A TAXONOMY-NAMED DECLARATION IS NOT, so the case above is not a witness that
        // refuses everything.
        let mut ov = Overlay::new();
        ov.set(
            format!("{HOT_LANE}/planted_clean.rs"),
            "pub struct CarrierScope;\n",
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "a taxonomy-named declaration is not a finding",
            &[ROW_EXPORTED],
        ));

        // THE TEST-PATH RATCHET: one more than the ratchet is RED, and the site is printed rather
        // than dropped from the scan.
        let mut ov = Overlay::new();
        ov.set(
            format!("{HOT_LANE}/tests/planted_extra_tests.rs"),
            "fn prompt_helper() {}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "one test-path declaration over the ratchet is RED, reported not hidden",
            &[ROW_TEST_RATCHET],
            ov,
            &["ratchet", "planted_extra_tests.rs"],
        ));

        // THE MANDATE DOCUMENT THAT IS NOT THERE. A silent fallback to the ban list is the
        // tautology this row exists to refuse.
        let mut ov = Overlay::new();
        ov.remove(TAXONOMY_DOC);
        report.push(prove_red(
            cx,
            self,
            "a missing mandate document is refused, not defaulted to the ban list",
            &[ROW_MANDATE],
            ov,
            &["mandate document is missing"],
        ));

        // A MANDATE THAT NAMES A TOKEN THE BAN LIST DOES NOT CARRY. This is the case the old
        // byte-copy could not fail: it compared a list against itself.
        let mut ov = Overlay::new();
        if Edit::Append(format!(
            "\nprotocol/role noun — banned set `{}`\n",
            "llm|mcp|a2a|nobody-bans-this"
        ))
        .apply(cx, TAXONOMY_DOC, &mut ov)
        .is_ok()
        {
            // The parser takes the FIRST such line, so the appended one must be the only one: the
            // planted document replaces the section rather than adding a second.
            let text = cx.read(TAXONOMY_DOC).unwrap_or_default();
            let planted: String = text
                .lines()
                .map(|l| {
                    if l.contains("banned set `") {
                        "protocol/role noun — banned set `llm|mcp|a2a|nobody-bans-this`".to_string()
                    } else {
                        l.to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n");
            let mut ov = Overlay::new();
            ov.set(TAXONOMY_DOC, planted);
            report.push(prove_red(
                cx,
                self,
                "a mandate naming a token the ban list omits is refused",
                &[ROW_BAN_LIST],
                ov,
                &["nobody-bans-this"],
            ));
        } else {
            report.note_infra_failure(
                "plane-abi-neutrality selftest: the mandate document could not be planted"
                    .to_string(),
            );
        }

        // THE ZERO-FILE CASE. A hot lane that EXISTS but has been drained is the one way this gate
        // reads its own passing answer off a tree it never opened.
        match cx.walk(&WalkSpec::new([HOT_LANE]).ext("rs")) {
            Ok(files) => {
                let mut ov = Overlay::new();
                for f in &files {
                    ov.remove(&f.rel);
                }
                report.push(prove_red(
                    cx,
                    self,
                    "a hot lane holding no Rust is refused, not scanned as zero banned nouns",
                    &[ROW_HOT_LANE],
                    ov,
                    &["reads exactly like a neutral ABI"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "plane-abi-neutrality selftest: the hot lane is unreadable ({e})"
            )),
        }

        // THE TOTALITY ROW, PLANTED. It reads the planes this tree DECLARES, so a fifth plane crate
        // whose noun nobody added to the ban list is a plant like any other — which is the whole
        // reason the row stopped comparing two `const`s. The witness that cannot see a plane cannot
        // catch a leak of that plane's nouns, and it would have said "every key is covered" while
        // saying it about a list that no longer described the tree.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-quantum/src/lib.rs",
            format!(
                "//! A planted plane crate, declaring a plane whose noun the ban list does not \
                 carry.\n{PLANE_GRAMMAR}: busbar_substrate::plane::registry::PlaneDecl =\n    \
                 busbar_substrate::plane::registry::PlaneDecl {{ key: \"quantum\" }};\n"
            ),
        );
        report.push(crate::gates::prove_rows_red(
            cx,
            self,
            "a plane this tree declares whose noun is not in the ban list is a finding",
            &[ROW_PLANE_KEYS],
            ov,
            &["quantum"],
        ));

        // THE MATCHED HALF of the case above, and the one that would have caught this gate reading
        // four plane crates that declare no plane. A `const` whose name merely BEGINS with the
        // grammar is not a declaration of anything: the row must stay GREEN on a crate carrying one
        // and nothing else. Without the colon in `PLANE_GRAMMAR` this case is RED and names
        // `quantum` — which is exactly the false reading the four `PLANE_DECLARATION` constants
        // produced on the real tree.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-quantum/src/lib.rs",
            // Spelt out rather than built from PLANE_GRAMMAR: the whole point is a name the grammar
            // is a PREFIX of, and a fixture assembled from the needle cannot express one.
            "//! A planted crate whose only `const` has a name BEGINNING with the plane grammar.\n\
             pub const PLANE_DECLARATION: busbar_contract::plane::PlaneDeclaration =\n    \
             busbar_contract::plane::PlaneDeclaration { key: \"quantum\" };\n"
                .to_string(),
        );
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "a const whose NAME merely begins with the plane grammar declares no plane",
            &[ROW_PLANE_KEYS],
            ov,
        ));

        report
    }
}

/// Read the shell witness's own output into the same six rows. Nothing here re-scans the tree.
fn translate(run: &LegacyRun) -> Result<Vec<Row>, String> {
    let mut mandate = None;
    let mut ban_list = None;
    let mut plane_keys = None;
    let mut hot_lane = None;
    let mut prod = Vec::new();
    let mut test = Vec::new();
    let mut ok_line = false;
    let mut in_prod = false;
    let mut in_test = false;

    for raw in run.lines() {
        let t = raw.trim();
        if t.contains("the mandate document is missing at") || t.contains("no `banned set `") {
            mandate = Some(t.to_string());
            continue;
        }
        if t.contains("the ban list is missing mandated tokens:") {
            ban_list = Some(t.to_string());
            continue;
        }
        if t.contains("canonical plane key(s) not in the ban list:") {
            plane_keys = Some(t.to_string());
            continue;
        }
        if t.contains("crate source not found at") || t.contains(".rs file(s); zero is RED") {
            hot_lane = Some(t.to_string());
            continue;
        }
        if t.contains("banned protocol/role noun in a plane-ABI declaration:") {
            in_prod = true;
            in_test = false;
            continue;
        }
        if t.contains("banned noun(s) in test-path declarations under")
            || t.contains("test-path declarations carrying a banned noun")
        {
            in_test = true;
            in_prod = false;
            continue;
        }
        if t.starts_with("ok plane-abi-neutrality:") {
            ok_line = true;
            in_prod = false;
            in_test = false;
            continue;
        }
        // A hit line is `<path>:<lineno>:<code>` under one of the two headings above.
        if (in_prod || in_test) && t.contains(".rs:") {
            if in_prod {
                prod.push(t.to_string());
            } else {
                test.push(t.to_string());
            }
        }
    }

    if mandate.is_none()
        && ban_list.is_none()
        && plane_keys.is_none()
        && hot_lane.is_none()
        && !ok_line
        && prod.is_empty()
        && test.is_empty()
    {
        return Err(format!(
            "the legacy translator recognised nothing in `{}`'s output: no verdict line, no \
             findings. Silence read as a neutral ABI is the exact defect this gate exists for.",
            run.argv.join(" ")
        ));
    }

    let mut rows = Vec::new();
    rows.push(match &mandate {
        Some(why) => Row::fail(
            ROW_MANDATE,
            "the mandate document cannot be read",
            why.clone(),
        ),
        None => Row::pass(
            ROW_MANDATE,
            "the mandate document issues a banned set this gate can read",
            CLEAN,
        ),
    });
    rows.push(match (&mandate, &ban_list) {
        (Some(_), _) => Row::fail(
            ROW_BAN_LIST,
            "the mandate is unknown",
            DID_NOT_RUN.to_string(),
        ),
        (None, Some(why)) => Row::fail(
            ROW_BAN_LIST,
            "the ban list is missing tokens the design mandates",
            why.clone(),
        ),
        (None, None) => Row::pass(
            ROW_BAN_LIST,
            "the ban list carries every token the design mandates",
            CLEAN,
        ),
    });
    rows.push(match &plane_keys {
        Some(why) => Row::fail(
            ROW_PLANE_KEYS,
            "a canonical plane key is not in the ban list",
            why.clone(),
        ),
        None => Row::pass(
            ROW_PLANE_KEYS,
            "every canonical plane key is in the ban list",
            CLEAN,
        ),
    });

    // The three self-checks above EXIT the shell before the scan, so a run that stopped at one of
    // them scanned nothing and the three rows below are DID NOT RUN — never a pass.
    let stopped_early = mandate.is_some() || ban_list.is_some() || plane_keys.is_some();
    if stopped_early {
        rows.push(Row::fail(
            ROW_HOT_LANE,
            "the scan did not run",
            DID_NOT_RUN.to_string(),
        ));
        rows.push(Row::fail(
            ROW_EXPORTED,
            "the scan did not run",
            DID_NOT_RUN.to_string(),
        ));
        rows.push(Row::fail(
            ROW_TEST_RATCHET,
            "the scan did not run",
            DID_NOT_RUN.to_string(),
        ));
        return Ok(rows);
    }
    if let Some(why) = hot_lane {
        rows.push(Row::fail(
            ROW_HOT_LANE,
            "the hot lane is absent or holds no Rust",
            why,
        ));
        rows.push(Row::fail(
            ROW_EXPORTED,
            "the scan did not run",
            DID_NOT_RUN.to_string(),
        ));
        rows.push(Row::fail(
            ROW_TEST_RATCHET,
            "the scan did not run",
            DID_NOT_RUN.to_string(),
        ));
        return Ok(rows);
    }

    rows.push(Row::pass(
        ROW_HOT_LANE,
        "the hot lane is present and holds Rust",
        CLEAN,
    ));
    prod.sort();
    test.sort();
    rows.push(row_exported(&prod));
    rows.push(row_ratchet(&test));
    Ok(rows)
}
