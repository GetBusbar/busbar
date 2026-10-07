//! `cargo xtask gate plane-abi-neutrality` — THE NEUTRALITY WITNESS FOR THE PROTOCOL-PLANE ABI.
//! The successor to `scripts/plane-abi-neutrality.sh`, rule for rule.
//!
//! The plane ABI's whole claim is that its capability surface was DERIVED from a primitive taxonomy
//! (carrier / scope / egress / metering), NOT ENUMERATED from any one protocol plane. That claim
//! rots silently the first time someone names a type, fn or variant after a protocol or role noun.
//! This is the machine check that "derived, not enumerated" STAYS true as capabilities are added:
//! it scans THE PLANE ABI for the banned set and asserts zero. The plane ABI is the per-kind plane
//! ABI (`abi/plane`), the host tables every kind calls (`abi/host`), and the retiring HOT lane
//! (`abi/hot`) for as long as it exists (X5 finding 4: the witness read only the hot lane, the lane
//! the module doc says is deleted with the last plane on it, while the live surface went unopened).
//! The roots are read off the abi module's own `pub mod` lines; the COLD lane keeps its
//! pre-existing store/auth/hook vocabulary and is deliberately exempt, and the shared crate root is
//! neutral by construction.
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
//! * `plane-abi-neutrality:scan-roots` — every live root (`abi/plane`, `abi/host`) is declared by
//!   `abi/mod.rs` AND holds at least its measured file count. A directory that exists but carries no
//!   `.rs` greps clean, and zero banned nouns over zero files is the passing answer to the only ban
//!   here — indistinguishable from a genuinely derived surface. The hot lane is scanned while it
//!   holds Rust and its deletion is not red.
//! * `plane-abi-neutrality:exported-declarations` — the invariant, ceiling 0.
//! * `plane-abi-neutrality:test-path-ratchet` — BOTH HALVES, NEITHER HIDDEN. A `#[test] fn
//!   …_round_trips_…` under `hot/tests/` exports nothing, so counting it as an ABI leak is the wrong
//!   verdict — but deleting it from the scan without saying so is a gate quietly narrowing itself.
//!   It is a ratchet at today's count that may only go DOWN, and the sites are printed either way.

use crate::ctx::{Ctx, Edit, Overlay, WalkError, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;
use crate::planes::{PLANE_GRAMMAR, PLANE_KEYS};

pub const ROW_MANDATE: &str = "plane-abi-neutrality:mandate-document";
pub const ROW_BAN_LIST: &str = "plane-abi-neutrality:ban-list-complete";
pub const ROW_PLANE_KEYS: &str = "plane-abi-neutrality:plane-keys-covered";
pub const ROW_SCAN_ROOTS: &str = "plane-abi-neutrality:scan-roots";
pub const ROW_EXPORTED: &str = "plane-abi-neutrality:exported-declarations";
pub const ROW_TEST_RATCHET: &str = "plane-abi-neutrality:test-path-ratchet";

/// The abi module. Its own `pub mod` lines (in `{ABI_DIR}/mod.rs`) are where the scanned roots are
/// read from: a live root the module does not declare is RED, never a narrower scan.
const ABI_DIR: &str = "crates/busbar-contract/src/abi";

/// THE LIVE PLANE ABI, each with its floor: the `.rs` count measured on predev 5e672d125d. A root
/// below its floor is RED; a root that grows is fine. `plane` is the per-kind plane ABI (THE
/// DESIGN's `abi/plane/`), `host` the host tables every kind calls (`abi/host/`: conn, hook,
/// service). Lower a floor only in a reviewed diff that says which file left and why.
const LIVE_ROOTS: &[(&str, usize)] = &[("plane", 2), ("host", 5)];

/// The RETIRING lane: scanned while it holds Rust, and its deletion (M6-HOT-PLANE) is not red once
/// the live roots above are read.
const RETIRING_ROOT: &str = "hot";
const TAXONOMY_DOC: &str = "docs/design/BUSBAR-1.6.0.md";

/// DOCUMENTED EXEMPTION for [`declared_plane_keys`]: `crates/busbar-contract/src/abi/hot/mod.rs` declares
/// `pub const PLANE_DECL: &[u8] = b"busbar_plane_decl\0";` — the ABI SYMBOL NAME a plane cdylib's
/// hot-lane entrypoint exports, resolved by the loader via `libloading`. It starts with the same
/// `pub const PLANE_DECL` grammar every real plane's declaration marker uses, but it is the loader's
/// OWN vocabulary constant, not a plane declaring itself — `busbar-plugin` is the host, not a plane.
/// Scanned like any other file it makes `declared_plane_keys` read a "plugin" plane into existence,
/// which the total-coverage row then fails to find in [`BANNED`] — a false positive, not a leak.
/// Excluded by exact file, not by loosening the grammar or adding "plugin" to the ban list.
const HOT_LANE_DECL_SITE: &str = "crates/busbar-contract/src/abi/hot/mod.rs";

/// DOCUMENTED EXEMPTION for [`declared_plane_keys`]: the `decisions` plane (jev) declares the key
/// `plane-decisions`, whose noun COLLIDES WITH A NEUTRAL PRIMITIVE. [`BANNED`] matches
/// case-insensitively as a substring, so banning `decision` forbids `Decision`, `GateDecision` and
/// `VerifyDecision` — the admit/throttle/deny verdict types that ARE the primitive governance
/// taxonomy this witness exists to derive the ABI from. Measured: adding the token reds
/// `exported-declarations` with 7 findings in `crates/busbar-contract/src/abi/hot/{host,pod}.rs` and
/// blows the test-path ratchet, every one of them core naming its own verdict rather than a plane
/// leaking. The witness cannot distinguish the two by substring, so the plane key is exempted HERE,
/// in writing, instead of the ban list being loosened or a correct primitive being renamed to dodge
/// a grep. This is the same trade the `PLANE_DECL` exemption above makes.
///
/// NOT a licence: a genuine leak of THIS plane into a neutral crate is caught by `plane-purity` and
/// by the `law0-neutral-instance` class in `kind_isolation::matrix`, which key on the crate edge
/// rather than on a noun and so are immune to the collision.
///
/// Two spellings of the ONE plane, because the key is read two ways (see [`declared_plane_keys`]):
/// `plane-decisions` from the declaration the composition root writes for it, `decisions` from its
/// crate directory `busbar-plane-decisions`. Same plane, same collision, same exemption.
const PRIMITIVE_COLLISION_KEYS: &[&str] = &["plane-decisions", "decisions"];

/// The banned protocol/role nouns. Matched case-insensitively as SUBSTRINGS of identifiers on
/// declaration lines: a banned noun concatenated into a name — `McpTransport`, `server_stream` — is
/// exactly the leak to catch, and a word-boundary match would miss it.
const BANNED: &[&str] = &[
    "llm",
    "mcp",
    "a2a",
    "tool",
    "agent",
    "sampling",
    "task",
    "server",
    "card",
    "round",
    "prompt",
    "voice",
    "realtime",
    "audio",
    // THE FOURTH PLANE BY ITS OWN NAME (DECISIONS #18: the plane is `streaming`; `voice` is a
    // dialect inside it). `busbar-plane-streaming` carries no `PLANE_DECL`, so the declaration scan
    // never read its key and this list never needed it; the crate-directory derivation reads it,
    // and the totality row is red until the noun is banned. Measured 2026-09-24: zero declarations
    // in the hot lane carry it, so banning it moves no finding.
    "streaming",
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
        let rel = f.rel_str();
        if rel == HOT_LANE_DECL_SITE {
            continue;
        }
        // A PLANE CRATE NAMES ITS PLANE IN ITS DIRECTORY, declaration or none. `busbar-plane-*` is
        // the plane kind's own naming scheme (`busbar-plane-<key>[-<dialect>]`), and a plane crate
        // that carries no `PLANE_DECL` — `busbar-plane-streaming` does not — was a plane this row
        // could not see: the fourth plane's noun sat outside the ban list with the row green.
        if let Some(key) = rel
            .strip_prefix("crates/busbar-plane-")
            .and_then(|r| r.split('/').next())
            .and_then(|d| d.split('-').next())
            .filter(|k| !k.is_empty())
        {
            let key = key.to_string();
            if !PRIMITIVE_COLLISION_KEYS.contains(&key.as_str()) && !keys.contains(&key) {
                keys.push(key);
            }
        }
        if !f
            .text
            .lines()
            .any(|l| l.trim_start().starts_with(PLANE_GRAMMAR))
        {
            continue;
        }
        let Some(krate) = rel
            .strip_prefix("crates/")
            .and_then(|r| r.split('/').next())
        else {
            continue;
        };
        // THE COMPOSITION ROOT IS NOT A PLANE CRATE, so the directory rule above cannot name the
        // plane a declaration written there is about. `crates/busbar` strips to `busbar` — the
        // project's own name, in every crate in the tree, and a "plane key" nobody could sanely
        // ban — and that is exactly what this row was failing on.
        //
        // WHY A DECLARATION LIVES IN THE ROOT AT ALL, and why this is not a widening: the decision
        // plane is ONE crate, pure, and a pure plane's manifest may name `busbar-contract` and
        // nothing else (the dep wall, DECISIONS #40). `PlaneDecl` is a `busbar-kernel` type, so the
        // plane crate cannot hold its own declaration; `crates/busbar-plane-decisions/src/registry.rs`
        // was DELETED for carrying that forbidden edge and the declaration was rewritten
        // in the root, both on 2026-09-22. `PRIMITIVE_COLLISION_KEYS` — which names this
        // exact plane, for the noun collision written up on it — was set a day earlier against the
        // address the declaration used to have, and has covered nothing since.
        //
        // So the key is repointed, not the rule relaxed: the root names the plane it declares in the
        // FILE name (`root/plane_decisions.rs` declares `busbar-plane-decisions`), the derived key is
        // the same string the directory rule produced before the move, and the one documented
        // exemption below goes on doing the job it was written for. A root file that declares a
        // `PLANE_DECL` and is NOT named `plane_<key>.rs` still reads as `busbar` and is still loud.
        let key = if krate == "busbar" {
            rel.rsplit('/')
                .next()
                .and_then(|f| f.strip_suffix(".rs"))
                .and_then(|stem| stem.strip_prefix("plane_"))
                .map(|plane| format!("plane-{}", plane.replace('_', "-")))
                .unwrap_or_else(|| krate.to_string())
        } else {
            krate.strip_prefix("busbar-").unwrap_or(krate).to_string()
        };
        if PRIMITIVE_COLLISION_KEYS.contains(&key.as_str()) {
            continue;
        }
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

/// Does `abi/mod.rs` declare `pub mod <name>;`? A `#[path]` on it is refused: the root this gate
/// walks is `{ABI_DIR}/<name>`, and a module declared elsewhere is one it would not be reading.
fn declares(abi_mod: &str, name: &str) -> Result<(), String> {
    let decl = format!("pub mod {name};");
    let mut pending_path = false;
    for line in abi_mod.lines() {
        let t = line.trim();
        if t.starts_with("#[path") {
            pending_path = true;
            continue;
        }
        if t == decl {
            return if pending_path {
                Err(format!(
                    "{ABI_DIR}/mod.rs declares `{decl}` through a `#[path]`, so `{ABI_DIR}/{name}` \
                     is not where it lives"
                ))
            } else {
                Ok(())
            };
        }
        if !t.starts_with("#[") && !t.starts_with("//") && !t.is_empty() {
            pending_path = false;
        }
    }
    Err(format!(
        "{ABI_DIR}/mod.rs no longer declares `{decl}`: the live plane-ABI root `{name}` is not a \
         module of the abi"
    ))
}

/// THE ROOTS, READ OFF THE ABI MODULE'S OWN DECLARATIONS. Every live root must be declared by
/// `abi/mod.rs` and hold at least its floor; the retiring hot lane is scanned while it holds Rust.
/// Returns the files to scan and one count line per root, or every refusal.
fn scan_roots(cx: &Ctx) -> Result<(Vec<crate::ctx::SourceFile>, Vec<String>), Vec<String>> {
    let abi_mod_rel = format!("{ABI_DIR}/mod.rs");
    let abi_mod = cx
        .read(&abi_mod_rel)
        .map_err(|e| vec![format!("{abi_mod_rel} cannot be read ({e})")])?;
    let mut files = Vec::new();
    let mut counts = Vec::new();
    let mut refusals = Vec::new();
    for (name, floor) in LIVE_ROOTS {
        if let Err(why) = declares(&abi_mod, name) {
            refusals.push(why);
            continue;
        }
        let root = format!("{ABI_DIR}/{name}");
        match cx.walk(&WalkSpec::new([root.clone()]).ext("rs").min_files(*floor)) {
            Ok(found) => {
                counts.push(format!("{root}: {} file(s), floor {floor}", found.len()));
                files.extend(found);
            }
            Err(e) => refusals.push(format!("{root} (floor {floor}): {e}")),
        }
    }
    let hot = format!("{ABI_DIR}/{RETIRING_ROOT}");
    match cx.walk(&WalkSpec::new([hot.clone()]).ext("rs").allow_empty()) {
        Ok(found) if !found.is_empty() => {
            counts.push(format!("{hot}: {} file(s), retiring", found.len()));
            files.extend(found);
        }
        Ok(_) | Err(WalkError::MissingRoot { .. }) => {
            counts.push(format!("{hot}: absent (retired)"));
        }
        Err(e) => refusals.push(format!("{hot}: {e}")),
    }
    if refusals.is_empty() {
        Ok((files, counts))
    } else {
        Err(refusals)
    }
}

/// A file's text as an overlay would show it (the overlay's own plant first), for stacking edits.
fn ov_read(cx: &Ctx, ov: &Overlay, rel: &str) -> Option<String> {
    let planted = cx.with_overlay(ov.clone());
    planted.read(rel).ok()
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
            ROW_SCAN_ROOTS.to_string(),
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

        match scan_roots(cx) {
            Ok((files, counts)) => {
                rows.push(Row::pass(
                    ROW_SCAN_ROOTS,
                    "every live plane-ABI root is declared and holds at least its measured floor",
                    counts.join("; "),
                ));
                let (prod, test) = scan(&files);
                rows.push(row_exported(&prod));
                rows.push(row_ratchet(&test));
            }
            Err(refusals) => {
                rows.push(Row::fail(
                    ROW_SCAN_ROOTS,
                    "a live plane-ABI root is undeclared, absent, or under its floor",
                    format!(
                        "{} A scan of zero files reports zero banned nouns, which reads exactly \
                         like a neutral ABI. If a root moved, point this gate at its new home in a \
                         reviewed diff that says so.",
                        refusals.join(" | ")
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

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
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
            format!("{ABI_DIR}/plane/planted_leak.rs"),
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
            format!("{ABI_DIR}/plane/planted_clean.rs"),
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
            format!("{ABI_DIR}/plane/tests/planted_extra_tests.rs"),
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

        // THE LIVE PLANE ABI IS SCANNED (X5 finding 4). The per-kind plane ABI (`abi/plane`) and the
        // host tables every kind calls (`abi/host`) are the plane ABI the planes speak; a protocol
        // noun planted in a declaration in either is a finding, not a file this witness never opens.
        let plane_mod = format!("{ABI_DIR}/plane/mod.rs");
        let mut ov = Overlay::new();
        match Edit::Append(format!("\npub struct {}PlantedSlot;\n", "Mcp"))
            .apply(cx, &plane_mod, &mut ov)
        {
            Ok(()) => report.push(prove_red(
                cx,
                self,
                "a protocol noun in a declaration in abi/plane/mod.rs is a finding",
                &[ROW_EXPORTED],
                ov,
                &["abi/plane/mod.rs", "McpPlantedSlot"],
            )),
            Err(e) => report.note_infra_failure(format!(
                "plane-abi-neutrality selftest: {plane_mod} could not be planted ({e})"
            )),
        }
        let host_root = format!("{ABI_DIR}/host");
        let host_files = cx.walk(&WalkSpec::new([host_root.clone()]).ext("rs"));
        match host_files
            .as_ref()
            .ok()
            .and_then(|fs| fs.iter().find(|f| !f.rel_str().ends_with("/mod.rs")))
        {
            Some(f) => {
                let rel = f.rel_str();
                let mut ov = Overlay::new();
                ov.set(
                    &rel,
                    format!("{}\npub struct {}PlantedTable;\n", f.text, "Tool"),
                );
                report.push(prove_red(
                    cx,
                    self,
                    "a protocol noun in a declaration in an abi/host file is a finding",
                    &[ROW_EXPORTED],
                    ov,
                    &[rel.as_str(), "ToolPlantedTable"],
                ));
            }
            None => report.note_infra_failure(format!(
                "plane-abi-neutrality selftest: no non-mod.rs file under {host_root} to plant"
            )),
        }

        // AN EMPTIED LIVE ROOT IS RED. `abi/plane` drained of Rust scans zero files, and zero
        // banned nouns over zero files is the passing answer this row exists to refuse.
        match cx.walk(&WalkSpec::new([format!("{ABI_DIR}/plane")]).ext("rs")) {
            Ok(files) => {
                let mut ov = Overlay::new();
                for f in &files {
                    ov.remove(&f.rel);
                }
                report.push(prove_red(
                    cx,
                    self,
                    "an emptied abi/plane root is refused, not scanned as zero banned nouns",
                    &[ROW_SCAN_ROOTS],
                    ov,
                    &["abi/plane"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "plane-abi-neutrality selftest: abi/plane is unreadable ({e})"
            )),
        }

        // A LIVE ROOT BELOW ITS MEASURED FLOOR IS RED: one abi/host file gone is a narrower scan,
        // not a cleaner ABI.
        if let Some(f) = host_files.as_ref().ok().and_then(|fs| fs.first()) {
            let mut ov = Overlay::new();
            ov.remove(&f.rel);
            report.push(prove_red(
                cx,
                self,
                "an abi/host root one file under its measured floor is refused",
                &[ROW_SCAN_ROOTS],
                ov,
                &["abi/host", "floor"],
            ));
        }

        // A LIVE ROOT abi/mod.rs NO LONGER DECLARES IS RED: the roots are read off the abi
        // module's own `pub mod` lines, and a plane ABI the module does not declare is not one
        // this witness may silently stop scanning.
        let abi_mod = format!("{ABI_DIR}/mod.rs");
        match cx.read(&abi_mod) {
            Ok(text) if text.lines().any(|l| l.trim() == "pub mod plane;") => {
                let planted: String = text
                    .lines()
                    .filter(|l| l.trim() != "pub mod plane;")
                    .map(|l| format!("{l}\n"))
                    .collect();
                let mut ov = Overlay::new();
                ov.set(&abi_mod, planted);
                report.push(prove_red(
                    cx,
                    self,
                    "a live root abi/mod.rs does not declare is refused",
                    &[ROW_SCAN_ROOTS],
                    ov,
                    &["pub mod plane;"],
                ));
            }
            _ => report.note_infra_failure(format!(
                "plane-abi-neutrality selftest: {abi_mod} declares no `pub mod plane;` to plant over"
            )),
        }

        // ...AND THE RETIRING HOT LANE GOING IS NOT RED: it is scanned while it exists, and its
        // deletion (M6-HOT-PLANE) is the plan, not a blind scan, once the live roots are read.
        match cx.walk(&WalkSpec::new([format!("{ABI_DIR}/hot")]).ext("rs")) {
            Ok(files) => {
                let mut ov = Overlay::new();
                for f in &files {
                    ov.remove(&f.rel);
                }
                report.push(crate::gates::prove_rows_green(
                    cx,
                    self,
                    "the retiring hot lane deleted does not red the scan roots",
                    &[ROW_SCAN_ROOTS],
                    ov,
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "plane-abi-neutrality selftest: the hot lane is unreadable ({e})"
            )),
        }

        // THE MATCHER AND ITS WRITTEN EXEMPTIONS (coordinator rulings on X5 finding 4). Each case
        // appends declarations to live plane-ABI files; `None` is a file that could not be read.
        let plant = |edits: &[(String, &str)]| -> Option<Overlay> {
            let mut ov = Overlay::new();
            for (rel, text) in edits {
                let base = ov_read(cx, &ov, rel)?;
                ov.set(rel, format!("{base}\n{text}\n"));
            }
            Some(ov)
        };
        let plane_mod = format!("{ABI_DIR}/plane/mod.rs");
        let plane_check = format!("{ABI_DIR}/plane/check.rs");
        let host_hook = format!("{ABI_DIR}/host/hook.rs");
        let host_service = format!("{ABI_DIR}/host/service.rs");
        let red_cases: Vec<(&str, Vec<(String, &str)>, Vec<&str>)> = vec![
            (
                "a whole-word protocol noun (ToolSlot) is still a finding, once per name across \
                 its sites",
                vec![
                    (plane_mod.clone(), "pub struct ToolSlot;"),
                    (host_service.clone(), "pub fn take_slot(slot: ToolSlot) {}"),
                ],
                vec!["ToolSlot (2 site(s)"],
            ),
            (
                "a name that is not one of the three hook names does not ride the exemption \
                 (prompt_slot)",
                vec![(plane_mod.clone(), "    pub prompt_slot: u32,")],
                vec!["prompt_slot"],
            ),
            (
                "a name that is not one of the three hook names does not ride the exemption \
                 (PromptCache)",
                vec![(plane_mod.clone(), "pub struct PromptCache;")],
                vec!["PromptCache"],
            ),
            (
                "prompt: PromptView outside the rider sites is a finding",
                vec![(plane_check.clone(), "    pub prompt: PromptView,")],
                vec!["abi/plane/check.rs"],
            ),
            (
                "a member naming PromptView but carrying another noun (tool_view) is a finding",
                vec![(host_hook.clone(), "pub fn tool_view() -> PromptView {}")],
                vec!["tool_view"],
            ),
            (
                "the TaskLost collision excuses that identifier and no other task name",
                vec![(plane_mod.clone(), "pub struct TaskQueue;")],
                vec!["TaskQueue"],
            ),
        ];
        for (name, edits, naming) in red_cases {
            match plant(&edits) {
                Some(ov) => report.push(prove_red(cx, self, name, &[ROW_EXPORTED], ov, &naming)),
                None => report.note_infra_failure(format!(
                    "plane-abi-neutrality selftest: a file of `{name}` could not be read"
                )),
            }
        }
        match plant(&[(plane_mod.clone(), "pub struct BodyTooLargeNote;")]) {
            Some(ov) => report.push(crate::gates::prove_rows_green(
                cx,
                self,
                "a noun that is only letters inside another word (BodyTooLarge) is not a finding",
                &[ROW_EXPORTED],
                ov,
            )),
            None => report.note_infra_failure(format!(
                "plane-abi-neutrality selftest: {plane_mod} could not be read"
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

        // A NEW PLANE CRATE THAT DECLARES NOTHING IS STILL A PLANE (1.6.0 item 3). The case above
        // plants a `PLANE_DECL`; the plane kind's crates do not have to carry one, and the fourth
        // plane did not. Its directory is its name.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-plane-quasar/src/lib.rs",
            "//! A planted plane-kind crate with no PLANE_DECL.\npub struct Plane;\n",
        );
        report.push(crate::gates::prove_rows_red(
            cx,
            self,
            "a new busbar-plane-* crate whose noun is not in the ban list is a finding",
            &[ROW_PLANE_KEYS],
            ov,
            &["quasar"],
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
            ROW_SCAN_ROOTS,
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
            ROW_SCAN_ROOTS,
            "a live plane-ABI root is undeclared, absent, or under its floor",
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
        ROW_SCAN_ROOTS,
        "every live plane-ABI root is declared and holds at least its measured floor",
        CLEAN,
    ));
    prod.sort();
    test.sort();
    rows.push(row_exported(&prod));
    rows.push(row_ratchet(&test));
    Ok(rows)
}
