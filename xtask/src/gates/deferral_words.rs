//! `cargo xtask gate deferral-words` — THE DETECTOR FOR DECISIONS #15, "IT IS 1.6.0-OR-BUST".
//! The successor to `scripts/deferral-words.py`, claim for claim.
//!
//! WHY THIS IS NOT A `grep -F`, AND WHY IT IS NOT A ROW FAMILY OF `no-deferral`. #15 bans four
//! literal strings (`defer`, `1.6.x`, `later`, `out of scope for 1.6.0`). The retired tracker wrote
//! "Out of 1.6.0 scope" — the same phrase with two words transposed — and a literal grep sailed
//! past it: that one miss waived 52 ABI slots. So this detector matches SHAPES, over PROSE
//! (`docs/design`, the spec and its companions). `no-deferral` reads `crates/**/*.rs` for deferral
//! MACROS and TAG labels; the scopes do not overlap (different files, different grammar, different
//! blocking posture), so this is its own gate rather than a row family of that one.
//!
//! * **Layer 1 — NAMED SHAPES** ([`SHAPES`], the enforcement set): regex families, each named, each
//!   case-insensitive, each derived from a phrasing the tree actually used.
//! * **Layer 2 — THE STRUCTURAL RULE** (the reading list, NEVER a gate): a future-time signal with a
//!   work signal in one line, or a modal obligation with an indefinite agent. Noisy by construction.
//!   It is the honesty check on Layer 1: a deferral caught only by Layer 2 means Layer 1 is still a
//!   spelling list.
//!
//! The script's default mode lists hits and exits 0, so the two scan rows are REPORT-ONLY
//! ([`Gate::informational`]): they pass however many hits there are and print the full location
//! list. What the script's exit code actually blocked on was its `--selftest`, the planted-deferral
//! positive control, and that is what the gating rows are:
//!
//! | row | the refusal |
//! | --- | --- |
//! | `:scan-floor` | fewer than [`SCAN_FLOOR`] documents scanned, or one unreadable, is UNPROVEN |
//! | `:layer1` | (report-only) Layer-1 occurrences over the doc set |
//! | `:layer2` | (report-only) Layer-2 reading list over the doc set |
//! | `:control-batch1` | every batch-1 phrase is caught at or above its expected layer |
//! | `:control-batch2` | every batch-2 phrase is caught at or above its expected layer |
//! | `:control-batch3-regressed` | a batch-3 phrase that was caught and now falls through |
//! | `:control-batch3-stale-pin` | a phrase pinned as residue that is now caught: strike its pin |
//!
//! THE PINNED RESIDUE ([`B3_RESIDUE`]) only shrinks. Batch 3 was written after all widening and is
//! never tuned against; the phrases it misses on its first run are the detector's honest miss rate.
//! A pinned phrase now caught means a shape widened past it, so the pin is stale (RED until struck);
//! an unpinned phrase that falls through is a regression (RED). Do NOT close a miss by adding its
//! words to a shape: that turns the detector back into a transcript of what it was shown.
//!
//! Not carried over: the script's `--paths`, `--all-md`, `--expect FILE`, `--summary` and `--layer`
//! flags (ad-hoc operator switches with arguments a gate cannot take). The gate always reads the
//! 1.6.0 document set and reports both layers.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::rx::Regex;

pub const ROW_FLOOR: &str = "deferral-words:scan-floor";
pub const ROW_L1: &str = "deferral-words:layer1";
pub const ROW_L2: &str = "deferral-words:layer2";
pub const ROW_B1: &str = "deferral-words:control-batch1";
pub const ROW_B2: &str = "deferral-words:control-batch2";
pub const ROW_B3_REGRESSED: &str = "deferral-words:control-batch3-regressed";
pub const ROW_B3_STALE: &str = "deferral-words:control-batch3-stale-pin";

/// The 1.6.0 document set the scan reads: the spec, the TODO, the SLOT-LOG and QUESTIONS. A scan of
/// fewer is the instrument going blind, not a clean tree.
pub const SCAN_FLOOR: usize = 4;

const ROOT: &str = "docs/design";
const SRC_EXT: [&str; 5] = ["rs", "sh", "py", "toml", "md"];

/// The overlay command that stands in for the committed control batches and pin in a self-test.
const CONTROLS_KEY: &str = "deferral-words-controls";

// ── LAYER 1 — THE NAMED SHAPES ───────────────────────────────────────────────────────────────────

/// `(shape-name, regex)`; every regex is compiled case-insensitively. The name is what a finding is
/// reported as, so a red can be argued with by name instead of by line.
pub const SHAPES: &[(&str, &str)] = &[
    ("defer-family", r"\bdefer\w*\b"),
    ("bare-later", r"\blater\b"),
    (
        "out-of-scope",
        r"\b(?:out(?:side)?|beyond|not)\s+(?:of\s+|in\s+|the\s+)?(?:\S+\s+){0,4}?scoped?\b",
    ),
    ("scope-out", r"\bscoped?\s+out\b|\bde-?scoped?\b"),
    (
        "next-version",
        concat!(
            r"\b1\.6\.x\b|\b1\.[7-9]\.\d+\b|\bv?[2-9]\.\d+\.\d+\b",
            r"|\b(?:version|release|ship(?:s|ped|ping)?\s+in)\s+v?1\.[7-9]\b"
        ),
    ),
    (
        "past-this-version",
        r"\b(?:post|past|beyond|after|not)[\s-]+1\.6\.0\b|\bnot\s+(?:a\s+)?1\.6\.0\b",
    ),
    (
        "version-bump",
        r"\b(?:minor|major|point|patch)\s+(?:bump|version|release)\b|\bnext\s+(?:minor|major|release|version)\b",
    ),
    (
        "extension-point",
        r"\bextension[\s-]points?\b|\breserved\s+(?:shape|slot|surface)\b|\bnot\s+implemented\s+wiring\b",
    ),
    ("phase-n", r"\bphases?\s+\d+(?:\.\d+)?\b"),
    (
        "wave-later",
        r"\b(?:a|the|some|another|future|later|next|subsequent)\s+(?:later\s+)?waves?\b|\bwave\s+[A-Z]\b",
    ),
    (
        "future-release",
        concat!(
            r"\bfuture\s+(?:release|version|wave|phase|minor|major|bump|work|effort)\b",
            r"|\ba\s+future\b|\bfollow[\s-]?(?:on|up)\b|\bdown\s+the\s+(?:road|line)\b",
            r"|\bat\s+some\s+point\b|\bin\s+due\s+course\b|\bsome\s*day\b|\beventually\b",
            r"|\bin\s+time\b|\btomorrow\b|\bv[\s-]?next\b"
        ),
    ),
    (
        "backlog",
        concat!(
            r"\bpunt(?:ed|ing|s)?\b|\bshelv(?:e|ed|ing|es)\b|\bback[\s-]?log(?:ged)?\b",
            r"|\bice\s*box\b|\bstretch\s+goal\b|\bnice[\s-]to[\s-]have\b|\bparking\s+lot\b",
            r"|\bkick(?:ed|ing)?\s+.{0,20}?down\s+the\s+road\b|\bpush(?:ed|ing)?\s+(?:it\s+|this\s+|out\s+)?(?:to|out|back)\b"
        ),
    ),
    (
        "not-yet-done",
        concat!(
            r"\bnot\s+(?:yet\s+)?(?:implemented|wired|performed|done|built|ported|landed|shipped|converted|migrated|started)\b",
            r"|\byet\s+to\s+be\b|\bhas\s+(?:not|never)\s+been\s+(?:performed|done|built|started|landed)\b",
            r"|\bnothing\s+.{0,40}?has\s+been\s+performed\b|\bno\s+.{0,20}?exists?\s+yet\b|\bunbuilt\b"
        ),
    ),
    (
        "negated-now",
        concat!(
            r"\b(?:not|n't|no|never|without)\b[^.;!?]{0,60}?",
            r"\b(?:today|right\s+now|at\s+this\s+time|at\s+present|currently|as\s+(?:it|things)\s+stands?",
            r"|in\s+this\s+release|this\s+release|in\s+1\.6\.0|for\s+1\.6\.0|here\s+and\s+now)\b"
        ),
    ),
    (
        "undecided",
        concat!(
            r"\bunmapped\b|\bundecided\b|\bopen\s+question\b|\bTBD\b|\bto\s+be\s+(?:decided|determined|ruled)\b",
            r"|\bstill\s+owed\b|\bowed\s+a\s+home\b|\bno\s+destination\b|\bnowhere\s+to\s+go\b",
            r"|\bnot\s+resolved\b|\bpend(?:s|ing|ed)?\b"
        ),
    ),
    (
        "for-now",
        concat!(
            r"\bfor\s+now\b|\bfor\s+the\s+(?:time\s+being|moment)\b|\bin\s+the\s+(?:interim|meantime)\b",
            r"|\bprovisional(?:ly)?\b|\bstop[\s-]?gap\b|\bplaceholder\b|\btemporar(?:y|ily)\b"
        ),
    ),
    (
        "note-not-work",
        concat!(
            r"\ba\s+NOTE,?\s+not\s+a\b|\bdescribes?\s+.{0,30}?rather\s+than\s+(?:does|doing|performing)\b",
            r"|\brecommendation\s+is\s+to\b"
        ),
    ),
    // The four shapes a later batch of the positive control found missing (tuned-against, disclosed).
    (
        "partial-coverage",
        concat!(
            r"\bonly\s+(?:handles?|covers?|supports?|does|implements?|works?)\b",
            r"|\b(?:handles?|covers?|supports?|implements?)\s+only\b",
            r"|\bjust\s+the\s+\w+[\s-]case\b|\bhappy[\s-]path\b",
            r"|\bpartial(?:ly)?\s+(?:implemented|covered|wired|done|built)\b",
            r"|\bnot\s+exhaustive\b|\bsubset\s+of\b"
        ),
    ),
    (
        "approximation",
        concat!(
            r"\bapproximat(?:e|es|ed|ion|ely)\b|\bbest[\s-]effort\b|\brough(?:ly)?\b",
            r"|\bheuristics?\b|\bclose\s+enough\b|\bgood\s+enough\b|\bna(?:i|",
            "\u{ef}",
            r")ve(?:ly)?\b",
            r"|\bsimplif(?:ied|ication|ying)\b|\bball\s*park\b"
        ),
    ),
    (
        "stub-admission",
        concat!(
            r"\bstub(?:bed|s|bing)?\b|\bskeletons?\b|\bscaffold(?:ing|ed)?\b",
            r"|\bdummy\b|\bmocked\s+out\b|\bno[\s-]?ops?\b|\bhard[\s-]?cod(?:e|ed|ing)\b"
        ),
    ),
    (
        "someone-elses-row",
        concat!(
            r"\bseparate\s+(?:piece\s+of\s+)?(?:work|effort|project|change|PR|commit|task|row|wave)\b",
            r"|\bits\s+own\s+(?:row|wave|task|change|PR|commit|effort)\b",
            r"|\bresearch\s+project\b|\bbigger\s+(?:lift|job|change|piece)\b",
            r"|\bcan\s+wait\b|\bnot\s+urgent\b|\bwhoever\b|\bunowned\b|\bno\s+owner\b",
            r"|\bno\s+room\s+for\b|\broom\s+for\b|\bnot\s+(?:my|this|our)\s+row\b"
        ),
    ),
    (
        "denies-deferral",
        concat!(
            r"\b(?:is|are|was)\s+NOT\s+(?:a\s+|banned\s+)?(?:defer\w*|skip)\b",
            r"|\bthis\s+is\s+not\s+a\s+defer\w*\b|\bnot\s+a\s+deferral\b"
        ),
    ),
];

// ── LAYER 2 — THE STRUCTURAL RULE ────────────────────────────────────────────────────────────────

const FUTURE: &str = concat!(
    r"\b(?:will|shall|'ll|going\s+to|gonna|once|after|when|until|before)\b",
    r"|\b(?:later|future|next|subsequent|downstream|upcoming|forthcoming|pending)\b",
    r"|\b(?:some\s*day|eventually|tomorrow|one\s+day|in\s+time|soon|ultimately)\b",
    r"|\bpost[\s-]\w+|\bbeyond\b|\bfollow[\s-]?(?:on|up)\b"
);
const WORK: &str = concat!(
    r"\b(?:ship|land|build|wire|implement|do|add|handle|fix|address|cover|support|complete",
    r"|finish|port|convert|migrate|resolve|revisit|tackle|write|remove|delete|split|extract",
    r"|replace|rewrite|refactor|enforce|prove|test|gate)(?:s|ed|ing)?\b",
    r"|\bcircle\s+back\b|\bcome\s+back\b|\breturn\s+to\b|\bpick\s+(?:it|this|that)\s+up\b",
    r"|\bsort\s+(?:it|this|that)\s+out\b|\bclean\s+(?:it|this|that)\s+up\b",
    r"|\bget\s+to\s+(?:it|this|that)\b|\bleft\s+(?:for|to)\b|\bleave\s+(?:it|this|that)\b",
    r"|\bthe\s+(?:rest|remainder|remaining)\b|\bwork\b"
);
/// RULE B — a modal obligation whose agent is indefinite or absent.
const OBLIGATION: &str = concat!(
    r"\b(?:should|ought\s+to|needs?\s+to|has\s+to|have\s+to|must\s+be|wants?\s+to",
    r"|worth\s+\w+ing|would\s+be\s+(?:nice|better|good)|good\s+enough|for\s+the\s+rig)\b"
);
const INDEFINITE_AGENT: &str = concat!(
    r"\b(?:someone|somebody|anyone|whoever|somebody\s+else|a\s+human|we|us|one)\b",
    r"|\b(?:be|been|being)\s+\w+ed\b"
);

struct Compiled {
    shapes: Vec<(&'static str, Regex)>,
    future: Regex,
    work: Regex,
    obligation: Regex,
    agent: Regex,
}

fn ci(pat: &str) -> Regex {
    Regex::new(&format!("(?i){pat}"))
        .unwrap_or_else(|e| panic!("deferral-words pattern `{pat}`: {e}"))
}

fn compiled() -> &'static Compiled {
    static C: OnceLock<Compiled> = OnceLock::new();
    C.get_or_init(|| Compiled {
        shapes: SHAPES.iter().map(|(n, p)| (*n, ci(p))).collect(),
        future: ci(FUTURE),
        work: ci(WORK),
        obligation: ci(OBLIGATION),
        agent: ci(INDEFINITE_AGENT),
    })
}

/// The Layer-1 shapes that fire on one line, in [`SHAPES`] order.
pub fn layer1_shapes(line: &str) -> Vec<&'static str> {
    compiled()
        .shapes
        .iter()
        .filter(|(_, rx)| rx.is_match(line.as_bytes()))
        .map(|(n, _)| *n)
        .collect()
}

/// Either structural rule, on one line: the firing pair, or `None`.
pub fn layer2_hit(line: &str) -> Option<String> {
    let c = compiled();
    let b = line.as_bytes();
    let grp = |rx: &Regex| {
        rx.search(b)
            .and_then(|m| m.str_of(b, 0))
            .map(|s| s.trim().to_lowercase())
    };
    if let (Some(f), Some(w)) = (grp(&c.future), grp(&c.work)) {
        return Some(format!("future:{f}+work:{w}"));
    }
    let o = grp(&c.obligation)?;
    let a = grp(&c.agent)?;
    Some(format!("obligation:{o}+agent:{a}"))
}

// ── DISCOVERY AND SCAN ───────────────────────────────────────────────────────────────────────────

/// `(?:^|/)(?:BUSBAR-1\.6\.0|1\.6\.0-[^/]*)\.md$` — the 1.6.0 documents among the markdown files.
fn is_doc_glob(rel: &str) -> bool {
    let base = rel.rsplit('/').next().unwrap_or(rel);
    base == "BUSBAR-1.6.0.md" || (base.starts_with("1.6.0-") && base.ends_with(".md"))
}

/// Every file the scan reads: `.rs/.sh/.py/.toml` under `docs/design`, plus the 1.6.0 `.md` set.
fn collect(cx: &Ctx) -> Result<Vec<String>, String> {
    let mut out = BTreeSet::new();
    for ext in SRC_EXT {
        let found = cx
            .list(&WalkSpec::new([ROOT]).ext(ext).allow_empty())
            .map_err(|e| e.to_string())?;
        for p in found {
            let rel = p.to_string_lossy().replace('\\', "/");
            if ext == "md" && !is_doc_glob(&rel) {
                continue;
            }
            out.insert(rel);
        }
    }
    Ok(out.into_iter().collect())
}

/// Python's `str.splitlines()`: `\n`, `\r\n`, `\r`, VT, FF, FS, GS, RS, NEL, LS, PS end a line; a
/// trailing terminator does not start another.
fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        if matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        ) {
            out.push(&s[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' && it.peek().is_some_and(|(_, n)| *n == '\n') {
                it.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// One finding: `(path, line number, shape)`. Layer-2 shapes are `L2:<pair>`.
type Hit = (String, usize, String);

struct Scan {
    files: usize,
    unreadable: Vec<String>,
    l1: Vec<Hit>,
    l2: Vec<Hit>,
}

/// The hits of one document's TEXT, memoised by the text itself: the regex engine is the cost, a
/// self-test runs the whole gate once per plant, and a plant touches one file of four. Same bytes,
/// same hits, so the memo cannot change a verdict. Per line, Layer 1 shapes in [`SHAPES`] order
/// then the Layer-2 pair, exactly the order the script appended them.
fn file_hits(text: &str) -> std::sync::Arc<Vec<(usize, String)>> {
    use std::hash::{Hash, Hasher};
    type Cell = std::sync::Arc<OnceLock<std::sync::Arc<Vec<(usize, String)>>>>;
    type Memo = std::sync::Mutex<BTreeMap<(usize, u64, u64), Cell>>;
    static MEMO: OnceLock<Memo> = OnceLock::new();
    let mut a = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut a);
    let mut b = std::collections::hash_map::DefaultHasher::new();
    (text.len(), text).hash(&mut b);
    0xdef_u32.hash(&mut b);
    let key = (text.len(), a.finish(), b.finish());
    // The cell is handed out under the lock and FILLED OUTSIDE it, so concurrent cases that need the
    // same document take one scan between them instead of one each.
    let cell = MEMO
        .get_or_init(Default::default)
        .lock()
        .expect("memo")
        .entry(key)
        .or_default()
        .clone();
    cell.get_or_init(|| {
        let mut out = Vec::new();
        for (i, raw) in splitlines(text).into_iter().enumerate() {
            for name in layer1_shapes(raw) {
                out.push((i + 1, name.to_string()));
            }
            if let Some(pair) = layer2_hit(raw) {
                out.push((i + 1, format!("L2:{pair}")));
            }
        }
        std::sync::Arc::new(out)
    })
    .clone()
}

fn scan(cx: &Ctx) -> Result<Scan, String> {
    let paths = collect(cx)?;
    let mut s = Scan {
        files: 0,
        unreadable: Vec::new(),
        l1: Vec::new(),
        l2: Vec::new(),
    };
    for rel in paths {
        let text = match cx.read(&rel) {
            Ok(t) => t,
            Err(e) => {
                s.unreadable.push(e);
                continue;
            }
        };
        s.files += 1;
        for (n, shape) in file_hits(&text).iter() {
            let hit = (rel.clone(), *n, shape.clone());
            if shape.starts_with("L2:") {
                s.l2.push(hit);
            } else {
                s.l1.push(hit);
            }
        }
    }
    Ok(s)
}

fn distinct_lines(hits: &[Hit]) -> usize {
    hits.iter()
        .map(|(p, n, _)| (p.as_str(), *n))
        .collect::<BTreeSet<_>>()
        .len()
}

fn locations(hits: &[Hit]) -> String {
    hits.iter()
        .map(|(p, n, s)| format!("{p}:{n} {s}"))
        .collect::<Vec<_>>()
        .join(" | ")
}

// ── THE POSITIVE CONTROL ─────────────────────────────────────────────────────────────────────────

/// `(text, expect_layer)`: `'1'` means a named shape must fire, `'2'` that Layer 2 is enough.
type Case = (String, char);

/// BATCH 1 — written BEFORE the shape set was widened and used to widen it: a regression test, not a
/// proof. Two fell through both layers on the first run; the fix was two new SHAPES, never a word.
const CONTROL_B1: &[(&str, char)] = &[
    ("// The remaining three call sites are left for a follow-on release once the engine split settles.", '1'),
    ("// We will circle back to the retry budget after the duplex landing.", '2'),
    ("// Good enough to unblock the rig; someone should make it exact.", '2'),
    ("/// Only the happy path is wired; the error arm comes with the next tranche of work.", '2'),
    ("// Not wiring this today — the shape is right and the cost is a day we do not have.", '1'),
];

/// BATCH 2 — written AFTER the widening and NEVER used to tune it. A miss here is a finding about the
/// shape set, not a reason to edit it again.
const CONTROL_B2: &[(&str, char)] = &[
    ("// Shipping the single-slot read; the multi-slot lookup can wait for whoever owns tls next quarter.", '1'),
    ("// The reconciler only handles the two-party case. Three-party is a bigger lift than we have room for.", '2'),
    ("/// Approximate. Exactness here is a research project and the rig does not need it.", '2'),
    ("// Leaving the second codepath alone until somebody can prove which one callers actually take.", '2'),
    ("// Stubbed against the happy path so the battery goes green; real fault injection is a separate piece of work.", '1'),
];

/// BATCH 3 — written after the batch-2 widening, never used to tune anything. Its misses are the
/// detector's real, untuned miss rate.
const CONTROL_B3: &[(&str, char)] = &[
    ("// The window accounting rounds to the minute; per-second is more plumbing than this ticket bought.", '1'),
    ("// One provider is enough to prove the seam. The other two land when someone needs them.", '2'),
    ("// This assumes the config never reloads. It does, but not on any path we ship.", '1'),
    ("// I have left the old branch in place because deleting it needs a migration nobody has written.", '2'),
    ("// Enough of the contract to compile. The invariants are documented and unenforced.", '1'),
];

/// BATCH 3'S MEASURED RESIDUE: the indices into [`CONTROL_B3`] that fell through on its first,
/// untuned run, pinned so the exit code means something. The set only shrinks.
pub const B3_RESIDUE: &[usize] = &[0, 2, 3, 4];

struct Controls {
    b1: Vec<Case>,
    b2: Vec<Case>,
    b3: Vec<Case>,
    residue: BTreeSet<usize>,
}

fn own(cases: &[(&str, char)]) -> Vec<Case> {
    cases.iter().map(|(t, w)| (t.to_string(), *w)).collect()
}

impl Controls {
    fn committed() -> Controls {
        Controls {
            b1: own(CONTROL_B1),
            b2: own(CONTROL_B2),
            b3: own(CONTROL_B3),
            residue: B3_RESIDUE.iter().copied().collect(),
        }
    }

    /// The self-test's wire form: `b1|b2|b3 <TAB> <1|2> <TAB> <text>` lines and one
    /// `residue <TAB> 0,2,3` line.
    fn render(&self) -> String {
        let mut out = String::new();
        for (tag, cases) in [("b1", &self.b1), ("b2", &self.b2), ("b3", &self.b3)] {
            for (t, w) in cases {
                out.push_str(&format!("{tag}\t{w}\t{t}\n"));
            }
        }
        let r: Vec<String> = self.residue.iter().map(usize::to_string).collect();
        out.push_str(&format!("residue\t{}\n", r.join(",")));
        out
    }

    fn parse(text: &str) -> Result<Controls, String> {
        let mut c = Controls {
            b1: Vec::new(),
            b2: Vec::new(),
            b3: Vec::new(),
            residue: BTreeSet::new(),
        };
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let mut f = line.splitn(3, '\t');
            let (tag, a) = (f.next().unwrap_or(""), f.next().unwrap_or(""));
            match tag {
                "residue" => {
                    for n in a.split(',').filter(|s| !s.is_empty()) {
                        c.residue
                            .insert(n.parse().map_err(|_| format!("bad residue index `{n}`"))?);
                    }
                }
                "b1" | "b2" | "b3" => {
                    let want = match a {
                        "1" => '1',
                        "2" => '2',
                        other => return Err(format!("bad expect layer `{other}` in `{line}`")),
                    };
                    let case = (f.next().unwrap_or("").to_string(), want);
                    match tag {
                        "b1" => c.b1.push(case),
                        "b2" => c.b2.push(case),
                        _ => c.b3.push(case),
                    }
                }
                other => return Err(format!("unknown control line `{other}`")),
            }
        }
        Ok(c)
    }

    fn load(cx: &Ctx) -> Result<Controls, String> {
        match cx.overlay_command(CONTROLS_KEY) {
            Some(planted) => Controls::parse(&planted),
            None => Ok(Controls::committed()),
        }
    }
}

/// How one control batch fared: how many were caught at or above their layer, and which indices were
/// not (both layers missed it, or only Layer 2 caught a phrase a named shape was expected to).
struct Batch {
    total: usize,
    missed: Vec<usize>,
    notes: Vec<String>,
}

fn run_batch(cases: &[Case]) -> Batch {
    let mut missed = Vec::new();
    let mut notes = Vec::new();
    for (idx, (text, want)) in cases.iter().enumerate() {
        let l1 = layer1_shapes(text);
        if !l1.is_empty() {
            continue;
        }
        match layer2_hit(text) {
            Some(l2) if *want == '2' => {
                let _ = l2;
            }
            Some(l2) => {
                missed.push(idx);
                notes.push(format!("phrase {idx} L1-MISS, L2 caught ({l2}): {text}"));
            }
            None => {
                missed.push(idx);
                notes.push(format!("phrase {idx} MISSED BY BOTH LAYERS: {text}"));
            }
        }
    }
    Batch {
        total: cases.len(),
        missed,
        notes,
    }
}

fn batch_row(id: &str, title: &str, b: &Batch) -> Row {
    if b.missed.is_empty() {
        Row::pass(
            id,
            title,
            format!(
                "{}/{} caught at or above the expected layer",
                b.total, b.total
            ),
        )
    } else {
        Row::fail(
            id,
            title,
            format!(
                "{}/{} caught at or above the expected layer: {}",
                b.total - b.missed.len(),
                b.total,
                b.notes.join(" | ")
            ),
        )
    }
}

// ── THE ROWS ─────────────────────────────────────────────────────────────────────────────────────

fn by_shape(hits: &[Hit], strip_l2: bool) -> String {
    let mut m: BTreeMap<String, usize> = BTreeMap::new();
    for (_, _, s) in hits {
        let k = if strip_l2 {
            s.split(':').next().unwrap_or(s).to_string()
        } else {
            s.clone()
        };
        *m.entry(k).or_default() += 1;
    }
    let mut v: Vec<(String, usize)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.iter()
        .map(|(k, n)| format!("{k}={n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn floor_fail(why: String) -> Vec<Row> {
    let title = "the 1.6.0 document set could not be scanned, so the verdict is UNPROVEN";
    let mut rows = vec![Row::fail(ROW_FLOOR, title, why)];
    for id in [ROW_L1, ROW_L2] {
        rows.push(Row::skip(
            id,
            "unproven — the scan stopped at the floor",
            "no document set was scanned".to_string(),
        ));
    }
    rows
}

pub struct DeferralWordsGate;

impl Gate for DeferralWordsGate {
    fn name(&self) -> &'static str {
        "deferral-words"
    }

    fn owed(&self) -> Vec<String> {
        [
            ROW_FLOOR,
            ROW_L1,
            ROW_L2,
            ROW_B1,
            ROW_B2,
            ROW_B3_REGRESSED,
            ROW_B3_STALE,
        ]
        .iter()
        .map(|s| s.to_string())
        .collect()
    }

    /// The two scan rows are the script's DEFAULT mode, which lists and exits 0: reported, never
    /// judged. The control rows are what its exit code was about.
    fn informational(&self) -> Vec<String> {
        vec![ROW_L1.to_string(), ROW_L2.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut rows = Vec::new();

        // (1) THE SCAN, REPORT-ONLY, behind a floor.
        match scan(cx) {
            Err(why) => rows.extend(floor_fail(format!("discovery failed: {why}"))),
            Ok(s) if s.files < SCAN_FLOOR || !s.unreadable.is_empty() => {
                rows.extend(floor_fail(format!(
                    "{} document(s) scanned (floor {SCAN_FLOOR}); unreadable: [{}]. A scan that \
                     saw nothing reports a clean tree; this verdict is UNPROVEN, not PASS.",
                    s.files,
                    s.unreadable.join(" | ")
                )))
            }
            Ok(s) => {
                rows.push(Row::pass(
                    ROW_FLOOR,
                    "the 1.6.0 document set was scanned",
                    format!(
                        "{} document(s) at or above the floor of {SCAN_FLOOR}",
                        s.files
                    ),
                ));
                rows.push(Row::pass(
                    ROW_L1,
                    "Layer 1 (named shapes) over the 1.6.0 document set — REPORT-ONLY",
                    format!(
                        "{} occurrence(s) on {} distinct line(s) in {} file(s); by shape: {}; hits: {}",
                        s.l1.len(),
                        distinct_lines(&s.l1),
                        s.files,
                        by_shape(&s.l1, false),
                        locations(&s.l1)
                    ),
                ));
                rows.push(Row::pass(
                    ROW_L2,
                    "Layer 2 (structural rule) reading list — NEVER a gate",
                    format!(
                        "{} occurrence(s) on {} distinct line(s); by rule: {}; hits: {}",
                        s.l2.len(),
                        distinct_lines(&s.l2),
                        by_shape(&s.l2, true),
                        locations(&s.l2)
                    ),
                ));
            }
        }

        // (2) THE POSITIVE CONTROL AND ITS PINNED RESIDUE.
        let controls = match Controls::load(cx) {
            Ok(c) => c,
            Err(why) => {
                for id in [ROW_B1, ROW_B2, ROW_B3_REGRESSED, ROW_B3_STALE] {
                    rows.push(Row::fail(
                        id,
                        "the control batches do not load",
                        why.clone(),
                    ));
                }
                return Verdict::of(rows);
            }
        };
        let b1 = run_batch(&controls.b1);
        let b2 = run_batch(&controls.b2);
        let b3 = run_batch(&controls.b3);
        rows.push(batch_row(
            ROW_B1,
            "batch 1 (used to widen the shape set) is caught at or above its layer",
            &b1,
        ));
        rows.push(batch_row(
            ROW_B2,
            "batch 2 (drove the tuned-against families) is caught at or above its layer",
            &b2,
        ));

        let missed3: BTreeSet<usize> = b3.missed.iter().copied().collect();
        let phrase = |i: usize| {
            controls
                .b3
                .get(i)
                .map_or("<no such phrase>".to_string(), |(t, _)| t.clone())
        };
        let regressed: Vec<usize> = missed3.difference(&controls.residue).copied().collect();
        let stale: Vec<usize> = controls.residue.difference(&missed3).copied().collect();
        rows.push(if regressed.is_empty() {
            Row::pass(
                ROW_B3_REGRESSED,
                "no batch-3 phrase that was caught now falls through",
                format!(
                    "BATCH 3 (the untuned one): {} of {} fell through — the honest residue, pinned",
                    b3.missed.len(),
                    b3.total
                ),
            )
        } else {
            Row::fail(
                ROW_B3_REGRESSED,
                "a batch-3 phrase was caught and now falls through",
                regressed
                    .iter()
                    .map(|i| {
                        format!(
                            "batch-3 phrase {i} was caught and now falls through: {}",
                            phrase(*i)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" | "),
            )
        });
        rows.push(if stale.is_empty() {
            Row::pass(
                ROW_B3_STALE,
                "every pinned batch-3 residue phrase still falls through",
                format!("{} pin(s), none stale", controls.residue.len()),
            )
        } else {
            Row::fail(
                ROW_B3_STALE,
                "a pinned batch-3 residue phrase is now caught, so its pin is stale",
                stale
                    .iter()
                    .map(|i| {
                        format!(
                            "batch-3 phrase {i} is pinned as residue and is now caught; strike {i} \
                             from B3_RESIDUE: {}",
                            phrase(*i)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(" | "),
            )
        });
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        // WARM THE DOCUMENT MEMO ON THIS THREAD, ONCE. The cases fan out across workers and each
        // needs the same four documents' hits; left cold, every worker blocks on the first scan and
        // the battery is charged for the waiting eighteen times over.
        let _ = scan(cx);
        let owed = self.owed();
        let all: Vec<&str> = owed.iter().map(String::as_str).collect();
        let committed = Controls::committed();
        let with = |c: &Controls| {
            let mut ov = Overlay::new();
            ov.set_command(CONTROLS_KEY, c.render());
            ov
        };
        let edit = |f: &dyn Fn(&mut Controls)| {
            let mut c = Controls::committed();
            f(&mut c);
            with(&c)
        };

        report.push(prove_green(
            cx,
            self,
            "the committed tree, controls and pinned residue are green",
            &all,
        ));

        // REPORT-ONLY: a planted deferral in the doc set is REPORTED, never red (the script's default
        // mode lists and exits 0).
        let mut ov = Overlay::new();
        ov.set(
            "docs/design/1.6.0-PLANTED.md",
            "# planted\nThe remaining call sites are deferred to a follow-on release.\n",
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "a planted deferral is listed by the report-only scan rows, not scored",
            &[ROW_L1, ROW_L2],
        ));

        // BATCH 1 / 2: a phrase BOTH layers miss, and a phrase a named shape was expected to catch
        // that only Layer 2 does. The script's `bad` counter, both arms.
        for (row, tag) in [(ROW_B1, "batch 1"), (ROW_B2, "batch 2")] {
            let set = |c: &mut Controls, case: Case| {
                if row == ROW_B1 {
                    c.b1.push(case);
                } else {
                    c.b2.push(case);
                }
            };
            report.push(prove_red(
                cx,
                self,
                format!("{tag}: a phrase both layers miss is RED"),
                &[row],
                edit(&|c| set(c, ("// Hello world, nothing to see.".to_string(), '2'))),
                &["MISSED BY BOTH LAYERS"],
            ));
            report.push(prove_red(
                cx,
                self,
                format!("{tag}: a phrase expected at Layer 1 and caught only by Layer 2 is RED"),
                &[row],
                edit(&|c| {
                    set(
                        c,
                        (
                            "// We will circle back to the retry budget after the duplex landing."
                                .to_string(),
                            '1',
                        ),
                    )
                }),
                &["L1-MISS, L2 caught"],
            ));
        }

        // BATCH 3: the pin cuts both ways, and a Layer-2-only catch of a want-'2' phrase is fine.
        report.push(prove_red(
            cx,
            self,
            "batch 3: a phrase that was caught and now falls through is a REGRESSION",
            &[ROW_B3_REGRESSED],
            edit(&|c| {
                c.residue.remove(&4);
            }),
            &["batch-3 phrase 4", "now falls through"],
        ));
        report.push(prove_red(
            cx,
            self,
            "batch 3: a pinned phrase that is now caught means the pin is STALE",
            &[ROW_B3_STALE],
            edit(&|c| {
                c.residue.insert(1);
            }),
            &["batch-3 phrase 1", "strike 1 from B3_RESIDUE"],
        ));
        let mut caught = committed.b3.clone();
        caught[0] = (
            "// The remaining three call sites are left for a follow-on release.".to_string(),
            '1',
        );
        let mut c = Controls::committed();
        c.b3 = caught;
        c.residue.remove(&0);
        report.push(prove_green(
            &cx.with_overlay(with(&c)),
            self,
            "batch 3: a residue phrase widened into a caught one, with its pin struck, is green",
            &[ROW_B3_REGRESSED, ROW_B3_STALE],
        ));

        // THE FLOOR: the document set removed is UNPROVEN, never a clean tree.
        match collect(cx) {
            Ok(files) => {
                let mut ov = Overlay::new();
                for f in &files {
                    ov.remove(f);
                }
                report.push(prove_red(
                    cx,
                    self,
                    "a scan that found no documents is UNPROVEN, never a clean one",
                    &[ROW_FLOOR],
                    ov,
                    &["UNPROVEN, not PASS"],
                ));
            }
            Err(_) => report.note_infra_failure(
                "the floor case could not be planted: discovery does not read the real tree",
            ),
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fires(line: &str, shape: &str) -> bool {
        layer1_shapes(line).contains(&shape)
    }

    #[test]
    fn every_shape_fires_on_a_sample_and_the_transposed_ban_is_named() {
        let samples = [
            ("defer-family", "Deferred work"),
            ("bare-later", "do it Later"),
            ("out-of-scope", "Out of 1.6.0 scope"),
            ("out-of-scope", "outside the scope of this release"),
            ("scope-out", "descoped"),
            ("next-version", "lands in 1.7.0"),
            ("past-this-version", "post-1.6.0"),
            ("version-bump", "a minor bump"),
            ("extension-point", "an extension point"),
            ("phase-n", "Phase 5"),
            ("wave-later", "a later wave"),
            ("future-release", "down the road"),
            ("backlog", "pushed it back"),
            ("not-yet-done", "not yet wired"),
            ("negated-now", "Not wiring this today"),
            ("undecided", "still owed a home"),
            ("for-now", "for now"),
            ("note-not-work", "a NOTE, not a migration"),
            ("partial-coverage", "only handles the two-party case"),
            ("approximation", "a na\u{ef}ve scheme"),
            ("stub-admission", "Stubbed"),
            ("someone-elses-row", "can wait"),
            ("denies-deferral", "this is not a deferral"),
        ];
        for (shape, line) in samples {
            assert!(
                fires(line, shape),
                "{shape} on {line:?}: {:?}",
                layer1_shapes(line)
            );
        }
        assert_eq!(SHAPES.len(), 22);
    }

    #[test]
    fn layer1_is_silent_on_plain_prose() {
        assert!(layer1_shapes("The kernel reads the table and returns the row.").is_empty());
    }

    #[test]
    fn layer2_pairs() {
        assert_eq!(
            layer2_hit("We will circle back to it").as_deref(),
            Some("future:will+work:circle back")
        );
        assert_eq!(
            layer2_hit("someone should make it exact").as_deref(),
            Some("obligation:should+agent:someone")
        );
        assert_eq!(layer2_hit("The table is red."), None);
    }

    #[test]
    fn splitlines_matches_python() {
        assert_eq!(splitlines("a\nb\r\nc\rd\x0ce"), ["a", "b", "c", "d", "e"]);
        assert_eq!(splitlines("a\n"), ["a"]);
        assert_eq!(splitlines("a\n\nb"), ["a", "", "b"]);
        assert!(splitlines("").is_empty());
    }

    #[test]
    fn doc_glob() {
        assert!(is_doc_glob("docs/design/BUSBAR-1.6.0.md"));
        assert!(is_doc_glob("docs/design/1.6.0-TODO.md"));
        assert!(!is_doc_glob("docs/design/1.6.0-PARKED/x.md"));
        assert!(!is_doc_glob("docs/design/NOTES.md"));
    }

    #[test]
    fn controls_roundtrip() {
        let c = Controls::committed();
        let back = Controls::parse(&c.render()).unwrap();
        assert_eq!(back.b3, c.b3);
        assert_eq!(back.residue, c.residue);
    }

    #[test]
    fn the_pinned_residue_is_what_batch_three_misses() {
        let b = run_batch(&own(CONTROL_B3));
        assert_eq!(b.missed, B3_RESIDUE);
        assert!(run_batch(&own(CONTROL_B1)).missed.is_empty());
        assert!(run_batch(&own(CONTROL_B2)).missed.is_empty());
    }
}
