//! `cargo xtask gate plane-pricing-blindness` — NO PLANE CRATE TOUCHES MONEY.
//!
//! THE RULING THIS ENFORCES. DECISION #87 (owner-locked 2026-09-22): **planes always ledger.** A
//! plane appends its raw counts unconditionally, with no branch and no knowledge of whether
//! billing is on; `rate_card` is optional per plane IN CONFIG (#47); and the switch is a READ-TIME
//! property of the money VIEW, kernel-side — "billing off" means the VIEW reads 0, never that the
//! plane skipped the ledger. So per #43 a plane is PRICING-BLIND, and per #71 its whole money
//! obligation is to emit ONE fact per unit: raw counts keyed by its declared meter class. The
//! roster says the same thing in one line (#83, defs 16–20): *"Nothing that prices, admits or
//! dials."*
//!
//! ## THE LINE THIS GATE DRAWS, AND WHY IT IS DRAWN THERE
//!
//! **A plane may COUNT. It may not VALUE.** That is the whole predicate, and every row below is
//! one way of valuing.
//!
//! What a plane legitimately DOES, and what this gate must therefore never flag:
//!
//! * **DECLARES its meter classes.** `MeterClassDecl { key, family, direction, default_divisor }`
//!   in the plane's own `meta.rs` is #71 WORKING, not a violation — the class strings are DATA an
//!   operator prices (#77(4)). All five contract planes declare between one and seven of them, and
//!   [`ROW_DECLARATION`] REQUIRES them to, because a gate that went green by the planes forgetting
//!   to meter would be measuring nothing.
//! * **EMITS a raw count under a declared class.** `UsageLocator { class, quantity: Some(n) }` is
//!   the fact. `quantity` is a count field and handing one over is compliant.
//! * **CONVERTS a count into its own declared class's denomination.** `busbar-plane-streaming`
//!   divides milliseconds by 1000 to report `audio_seconds_in`, and bytes by 4 to estimate
//!   `text_tokens_in` — both make the emitted count agree with the unit the class was DECLARED in.
//!   That is counting, not valuing: no rate is read and no money figure results. Neither is a
//!   needle here, and the census records them as legitimate so the next reader does not re-litigate
//!   them.
//! * **READS a kernel money decision in order to render it.** `RefusalReason::Unpriced`,
//!   `OverBudget`, `OverdraftCeiling`, `NoRate` reach a plane as an INPUT to `encode_refusal`, and
//!   a plane that could not name them could not tell a client why it was refused — which #42
//!   requires, since an unpriced class must REFUSE rather than silently answer zero. Every site in
//!   every plane today is a match ARM (reading); none CONSTRUCTS one outside test code. Reading is
//!   not valuing, so the reason names are not needles.
//!
//! What a plane must NEVER do — the four acts, one row each:
//!
//! | row | the act |
//! | --- | --- |
//! | [`ROW_CARD`] | **RESOLVES A CARD** — names `rate_card`, a `RateCard`, or the pricing switch |
//! | [`ROW_SWITCH`] | **BRANCHES ON BILLING STATE** — #87's own clause: a card needle inside a conditional |
//! | [`ROW_PRICE`] | **PRICES** — names a price, a money lease, a money-nanos quantity, or a posting stamp |
//! | [`ROW_UNIT_KEY`] | **MINTS A KEY** — fabricates a unit identity the kernel owns |
//! | [`ROW_HOLD`] | **ARITHMETICS A HOLD** — opens, sizes, accrues against or settles one |
//!
//! ## WHY THE DENOMINATION WORD IS NOT A NEEDLE
//!
//! #87's own checkbox says "zero `rate_card`/`price`/`nanos`/`spend` references", and run as a bare
//! grep that phrase is useless — it was measured at 125 hits across the five `busbar-plane-*`
//! crates and **essentially all of them are prose**: doc comments explaining that this plane does
//! NOT price. `spend`, `charge`, `settle`, `reserve` and `hold` are all ambiguous in this tree
//! because admission, concurrency, task lifecycle and allocation use the same verbs — `charge_round`
//! charges an admission slot, `settle_leg` settles a durable record, `out.reserve()` reserves a
//! `Vec`, and `PlaneAllocBudget` is an ARENA budget. #42 keeps admission and concurrency ON for an
//! unbilled plane, so none of those is money.
//!
//! `nanos` is the sharpest case. It is the money denomination — and this tree also spells TIME in
//! nanos (`clock.monotonic_nanos`, `SystemTime::…as_nanos`). A denomination word is a VOCABULARY
//! test, not an ACT test. So the rule is a snake segment `_nanos` minus a named
//! [`TIME_NANOS`] allowlist, which leaves `cap_nanos`, `settled_nanos`, `fee_nanos`,
//! `estimate_nanos`, `reserved_nanos`, `exact_nanos` — every one of them money — and lets the two
//! clock spellings through. The allowlist carries the usual discipline: a spelling on it that
//! covers nothing live is reported as DEAD rather than left as a hole nobody re-reads.
//!
//! Everything else is bound to a money NOUN, never a verb. That is the difference between a census
//! of real couplings and a wall of noise nobody reads.
//!
//! ## PRODUCTION SCOPE, ON PURPOSE
//!
//! Comments are stripped, STRING LITERALS ARE BLANKED, and `#[cfg(test)]` bodies and test files are
//! dropped. Two reasons, and the second is the load-bearing one. (1) A diagnostic message that says
//! *"busbar does not spend its own credentials"* is prose that happens to sit inside a `"…"`; the
//! blanker is what stops a gate reading its own explanation as a violation. (2) A plane is written
//! by a third-party team and TESTS ITSELF — its harness has to stand in for the absent kernel to
//! call the plane at all, which is why every `UnitKey::new` in every plane crate today is a test
//! building a `Unit` to hand the plane. Banning that would mean a plane could not be tested in
//! isolation, which contradicts the design. A test that exercises a banned act is a SYMPTOM; this
//! gate names the disease, and the disease is in production code.
//!
//! ## THE SCOPE IS THE ROSTER, NOT THE PREFIX — AND THAT IS WHERE THE MONEY IS
//!
//! Scoping this to `crates/busbar-plane-*` would start it GREEN, because all five extracted
//! contract planes are already money-blind. A gate that starts green on a known violation is
//! worthless. [`PLANE_CRATES`] is therefore every crate the #83 roster places at defs 16–20 IN THE
//! PRESENT TENSE: the five extracted planes, the four pre-fold wire dialects the FOLD row absorbs,
//! and the four legacy orchestration crates the SPLIT row places there — the same SPLIT row that
//! says of them *"but `unit/{admit,approve,meter,route}` and `runtime/metering.rs` decide admission
//! and price — that is defs 5/6, not a plane."* This gate is that sentence, made mechanical.
//!
//! Note also that NO EXISTING xtask PLANE GATE SEES GENERATION 2 AT ALL: [`crate::planes`]'s
//! `PLANE_KEYS` is `["llm","mcp","a2a","voice"]` and its roots resolve by the `pub const PLANE_DECL`
//! grammar, which only the legacy crates carry. `plane-purity`, `plane-purity-strict` and
//! `plane-transport-neutrality` scan zero bytes of `busbar-plane-*`. This gate carries its own list
//! for that reason, and [`ROW_ROOTS`] refuses a listed crate that is not on disk rather than
//! scanning it as zero files — because zero is the passing answer to every ban.
//!
//! ## RED BY DESIGN, ON A NAMED AND FINITE LIST
//!
//! The gate is RED on HEAD and that is the correct starting state. `qa/plane-pricing-blindness.toml`
//! records each live finding as a `[[debt]]` row keyed by (category, file), so the red is a
//! documented burndown rather than a wall of noise, and two rows keep the ledger honest:
//! [`ROW_UNDOCUMENTED`] reds on any live finding the baseline does not name (this is what bites a
//! NEW money reference landing in a plane), and [`ROW_STALE`] reds on any baseline row whose
//! finding is gone (so the ledger cannot outlive the debt it tracked). The gate goes GREEN only
//! when the baseline is empty — i.e. when no plane crate touches money.
//!
//! The key is (category, file) and NOT a line number on purpose: a line number rots into a hole at
//! whatever lands on that line, and these files are under active edit.
//!
//! Regenerate the baseline from the live census with
//! `XTASK_PPB_EMIT_BASELINE=1 cargo xtask gate plane-pricing-blindness 2>qa/plane-pricing-blindness.toml`
//! then review every row by hand — the emitter derives nothing a human should not confirm.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{execute, prove_rows_green, prove_rows_red_at, Case, Expect, Gate, Report};
use crate::ledger::{Row, Status, Verdict};
use crate::scan;

pub const BASELINE: &str = "qa/plane-pricing-blindness.toml";

pub const ROW_ROOTS: &str = "plane-pricing-blindness:plane-roots";
pub const ROW_SCAN_FLOOR: &str = "plane-pricing-blindness:scan-floor";
pub const ROW_DECLARATION: &str = "plane-pricing-blindness:meter-class-declaration";
pub const ROW_CARD: &str = "plane-pricing-blindness:rate-card";
pub const ROW_SWITCH: &str = "plane-pricing-blindness:billing-switch";
pub const ROW_PRICE: &str = "plane-pricing-blindness:price";
pub const ROW_UNIT_KEY: &str = "plane-pricing-blindness:unit-key";
pub const ROW_HOLD: &str = "plane-pricing-blindness:hold";
pub const ROW_UNDOCUMENTED: &str = "plane-pricing-blindness:undocumented";
pub const ROW_STALE: &str = "plane-pricing-blindness:stale-baseline";
pub const ROW_REACHABILITY: &str = "plane-pricing-blindness:reachability";

/// THE NEEDLE every census row carries. `--all` excuses this gate's standing red only when every
/// red row names it; [`ROW_UNDOCUMENTED`] and [`ROW_STALE`] deliberately DO NOT carry it, so a new
/// money reference or a stale ledger row is scored exactly like any other regression.
pub const TRACKED_NEEDLE: &str = "tracked money debt";

const CLEAN: &str = "the scan cleared its floors and named nothing";
const DID_NOT_RUN: &str = "nothing was read, and nothing read is not a clean tree";

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE SCOPE
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// One crate the #83 roster places at defs 16–20, with the roster row that puts it there.
pub struct PlaneCrate {
    pub dir: &'static str,
    /// Which roster row places it — printed in the census so the scope is arguable from the row.
    pub placement: &'static str,
}

/// EVERY CRATE THE ROSTER CALLS A PLANE, PRESENT TENSE.
///
/// `plane-example` is DELIBERATELY ABSENT and this is its written reason: package
/// `busbar-plugin-example-plane` is a hermetic `cdylib` ABI/TCB fixture over `busbar_plugin::hot`,
/// it does not depend on `busbar-contract` at all, declares no `MeterClassDecl` and implements no
/// metering surface. It cannot touch money by construction, so listing it would make this gate
/// assert something vacuously true — and would invite the next ABI fixture to be misfiled as a
/// protocol plane. It is a fixture, not a plane, and the roster's HOMELESS table says so.
pub const PLANE_CRATES: &[PlaneCrate] = &[
    // defs 16–20, CLEAN row: the extracted contract planes. Money-blind today; this locks it in.
    PlaneCrate { dir: "busbar-plane-llm", placement: "#83 def 16-20 (CLEAN)" },
    PlaneCrate { dir: "busbar-plane-mcp", placement: "#83 def 16-20 (CLEAN)" },
    PlaneCrate { dir: "busbar-plane-a2a", placement: "#83 def 16-20 (CLEAN)" },
    // `-streaming` is the #18 name and the MERGE row's ruled BASE for the voice/streaming pair.
    PlaneCrate { dir: "busbar-plane-streaming", placement: "#83 def 16-20 (MERGE base, #18)" },
    // #48's fifth plane. Not wired into the binary yet — and gated anyway, because it is the
    // cleanest #71 exemplar in the tree and a rule that only watches wired code watches it late.
    PlaneCrate { dir: "busbar-plane-decision", placement: "#83 def 16-20 (#48)" },
    // FOLD row: "each is a WIRE DIALECT, which def 16–20 absorbs. They are not homeless; they are
    // pre-fold." Scanned now so the fold cannot carry money across with it.
    PlaneCrate { dir: "busbar-llm-codec", placement: "#83 FOLD -> def 16-20" },
    PlaneCrate { dir: "busbar-voice-codec", placement: "#83 FOLD -> def 16-20" },
    // SPLIT row: "Session, turn and dialect rules -> 16-20. But unit/{admit,approve,meter,route}
    // and runtime/metering.rs decide admission and price - that is defs 5/6, not a plane." THIS
    // GATE IS THAT SENTENCE. These four are where the money actually is.
    PlaneCrate { dir: "busbar-llm", placement: "#83 SPLIT -> def 16-20" },
    PlaneCrate { dir: "busbar-mcp", placement: "#83 SPLIT -> def 16-20" },
    PlaneCrate { dir: "busbar-a2a", placement: "#83 SPLIT -> def 16-20" },
    PlaneCrate { dir: "busbar-voice", placement: "#83 SPLIT -> def 16-20" },
];

/// The five CONTRACT planes that must each still declare at least one meter class ([`ROW_DECLARATION`]).
///
/// The positive half of #71, and the reason this gate cannot pass by measuring nothing: a plane
/// that stopped declaring classes would emit no counts, satisfy every ban below, and read as
/// perfectly clean. The codec halves and the legacy orchestration crates are NOT on this list —
/// they hold wire dialects and session rules, and the declaration lives in the contract plane.
pub const DECLARING_PLANES: &[&str] = &[
    "busbar-plane-llm",
    "busbar-plane-mcp",
    "busbar-plane-a2a",
    "busbar-plane-streaming",
    "busbar-plane-decision",
];

/// The grammar a meter-class declaration is recognised by.
const DECLARATION_GRAMMAR: &str = "MeterClassDecl";

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE PREDICATE
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// How a needle is matched. Two shapes, because a snake_case name and a type name break
/// differently and one rule for both is one rule that is wrong for one of them.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Shape {
    /// A snake_case identifier: must START at an identifier boundary, suffix unconstrained. So
    /// `accrue` catches `accrued` and `accrues`, and `rate_card` catches `rate_card_version` —
    /// but `pricing_enabled` does NOT catch `cost_pricing_enabled`, which is listed separately.
    Ident,
    /// A type name: must start at an identifier boundary AND be followed by end-of-line, an
    /// uppercase letter, or a non-alphanumeric. So `Hold` catches `Hold::open` and `Option<Hold>`
    /// but NOT `Holds` or `Holding`, which are English and appear only in prose anyway.
    Type,
    /// A literal substring, for a needle that spans a `::`.
    Exact,
}

struct Needle {
    text: &'static str,
    shape: Shape,
}

const fn id(text: &'static str) -> Needle {
    Needle { text, shape: Shape::Ident }
}
const fn ty(text: &'static str) -> Needle {
    Needle { text, shape: Shape::Type }
}
const fn ex(text: &'static str) -> Needle {
    Needle { text, shape: Shape::Exact }
}

/// RESOLVES A CARD. #43: "A plane plugin NEVER sees its rate card or fees."
const CARD: &[Needle] = &[
    id("rate_card"),
    id("pricing_enabled"),
    id("cost_pricing_enabled"),
    id("card_at"),
    id("card_in_force"),
    ty("RateCard"),
    ty("RateEntryCfg"),
    ty("PinnedHistory"),
    ty("HistorySeq"),
];

/// NAMES A CURRENCY. #66 makes the 1.6.0 model UNITLESS — there is no currency and no minor unit —
/// so a plane naming one is naming a money concept that does not exist on its side of the seam.
/// Folded into [`CARD`] rather than given a row of its own: resolving what to price IN and
/// resolving what to price AT are the same act from a plane's point of view.
const CURRENCY: &[Needle] = &[id("currency"), ty("Currency")];

/// PRICES — turns a quantity into a money figure, or names the book a figure is written into.
/// #71: "The MONEY VIEW computes Σ count × rate only at READ time, in the kernel."
const PRICE: &[Needle] = &[
    id("price_usage"),
    id("price_for"),
    id("unit_price"),
    id("cost_reserve"),
    id("cost_settle"),
    id("cost_settled"),
    ty("CostHandle"),
    ty("CostLeaseId"),
    ty("SettleOutcome"),
    ty("PostingStamp"),
    ty("Posting"),
    ty("Priced"),
    ty("LedgerToken"),
    ex("NANOS_PER_CENT"),
];

/// MINTS A KEY. #87: a plane emits counts "and NOTHING else — no ... `UnitKey` minting".
///
/// `UnitKey::new` is an unsealed `const fn`; what is privileged is ATTACHING one to a `Unit`, which
/// `Unit::new` gates behind `&dyn KernelSeal`. Both are here: a plane that fabricates a unit
/// identity in production has taken the kernel's job whichever door it used.
const UNIT_KEY: &[Needle] = &[ex("UnitKey::new"), ex("Unit::new"), ty("KernelSeal")];

/// ARITHMETICS A HOLD. #71: "no rate lookup / multiply / currency math runs on the request path."
const HOLD: &[Needle] = &[
    id("accrue"),
    ty("Hold"),
    ty("AccrualMeter"),
    ty("Estimate"),
    ty("ClassEstimate"),
    ty("AdmissionUnit"),
    ty("HoldAccrual"),
];

/// THE MONEY-NANOS RULE. A snake segment `_nanos` is a money quantity in this tree — EXCEPT for the
/// clock spellings named below. See the header: a denomination word is a vocabulary test, not an
/// act test, so the exemption is by exact spelling and it is checked.
const TIME_NANOS: &[&str] = &["monotonic_nanos", "as_nanos", "subsec_nanos", "from_nanos"];

/// The conditional forms a billing-state BRANCH can take. #87: a plane appends "unconditionally,
/// with no branch and no knowledge of whether billing is on".
const CONDITIONALS: &[&str] = &["if ", "if(", "match ", "&&", "||", ".then", ".filter", "? "];

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Category {
    Card,
    Switch,
    Price,
    UnitKey,
    Hold,
}

impl Category {
    fn key(self) -> &'static str {
        match self {
            Category::Card => "rate-card",
            Category::Switch => "billing-switch",
            Category::Price => "price",
            Category::UnitKey => "unit-key",
            Category::Hold => "hold",
        }
    }
    fn row(self) -> &'static str {
        match self {
            Category::Card => ROW_CARD,
            Category::Switch => ROW_SWITCH,
            Category::Price => ROW_PRICE,
            Category::UnitKey => ROW_UNIT_KEY,
            Category::Hold => ROW_HOLD,
        }
    }
    fn act(self) -> &'static str {
        match self {
            Category::Card => "resolves a rate card",
            Category::Switch => "branches on billing state",
            Category::Price => "prices, or names the book a price is written into",
            Category::UnitKey => "mints a unit identity the kernel owns",
            Category::Hold => "opens, sizes, accrues against or settles a money hold",
        }
    }
    fn from_key(k: &str) -> Option<Category> {
        Some(match k {
            "rate-card" => Category::Card,
            "billing-switch" => Category::Switch,
            "price" => Category::Price,
            "unit-key" => Category::UnitKey,
            "hold" => Category::Hold,
            _ => return None,
        })
    }
}

pub const CATEGORIES: &[Category] = &[
    Category::Card,
    Category::Switch,
    Category::Price,
    Category::UnitKey,
    Category::Hold,
];

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Does `needle` hit `code` under `shape`? See [`Shape`] for why there are two rules.
fn hits(code: &str, n: &Needle) -> bool {
    if n.shape == Shape::Exact {
        return code.contains(n.text);
    }
    let hay: Vec<char> = code.chars().collect();
    let pat: Vec<char> = n.text.chars().collect();
    if pat.len() > hay.len() {
        return false;
    }
    for i in 0..=(hay.len() - pat.len()) {
        if hay[i..i + pat.len()] != pat[..] {
            continue;
        }
        // Both shapes require the needle to START at an identifier boundary, so a needle can never
        // match the tail of a longer name (`un` + `priced` must not read as `priced`).
        if i > 0 && is_ident_char(hay[i - 1]) {
            continue;
        }
        match n.shape {
            Shape::Ident => return true,
            Shape::Type => match hay.get(i + pat.len()) {
                None => return true,
                Some(c) if c.is_ascii_uppercase() => return true,
                Some(c) if !c.is_ascii_alphanumeric() => return true,
                _ => {}
            },
            Shape::Exact => unreachable!("handled above"),
        }
    }
    false
}

/// Every `_nanos` segment on the line that is NOT one of the [`TIME_NANOS`] clock spellings, plus
/// whether any clock spelling FIRED (so a dead exemption can be reported as dead).
fn money_nanos(code: &str) -> (bool, bool) {
    let chars: Vec<char> = code.chars().collect();
    let pat: Vec<char> = "_nanos".chars().collect();
    let (mut money, mut clock) = (false, false);
    if pat.len() > chars.len() {
        return (false, false);
    }
    for i in 0..=(chars.len() - pat.len()) {
        if chars[i..i + pat.len()] != pat[..] {
            continue;
        }
        // `_nanos` must END the identifier, or `_nanoseconds` would read as a money quantity.
        if chars
            .get(i + pat.len())
            .is_some_and(|c| is_ident_char(*c))
        {
            continue;
        }
        // Walk back to the start of the identifier this segment belongs to and name it whole.
        let mut start = i;
        while start > 0 && is_ident_char(chars[start - 1]) {
            start -= 1;
        }
        let whole: String = chars[start..i + pat.len()].iter().collect();
        if TIME_NANOS.contains(&whole.as_str()) {
            clock = true;
        } else {
            money = true;
        }
    }
    (money, clock)
}

fn is_conditional(code: &str) -> bool {
    CONDITIONALS.iter().any(|c| code.contains(c))
}

/// Is this a TEST file BY NAME? Test SCOPE inside a production file is handled by
/// [`scan::production_lines`]; this is the file-level half. See the header for why the gate is
/// production-scope on purpose.
///
/// A NAME IS NOT THE WHOLE ANSWER — see [`test_declared_files`] for the other half.
fn is_test_file(rel: &str) -> bool {
    rel.contains("/tests/")
        || rel.contains("/benches/")
        || rel.ends_with("/tests.rs")
        || rel.ends_with("_test.rs")
        || rel.ends_with("_tests.rs")
}

/// FILES THAT ARE TEST SCOPE BUT DO NOT LOOK LIKE IT — every file some module declares under
/// `#[cfg(test)]`, wherever it sits and whatever it is called.
///
/// THE FALSE POSITIVE THIS EXISTS FOR, MEASURED. `crates/busbar-voice/src/runtime/mod.rs:261-263`
/// reads `#[cfg(test)] #[path = "voice_d2_billing_oracle.rs"] mod voice_d2_billing_oracle;` — a
/// money oracle compiled ONLY under `cfg(test)`, living beside its parent rather than under a
/// `tests/` directory. Nothing about its path says "test": not the directory, not the stem. And
/// `scan::production_lines` cannot help, because it strips an INLINE `#[cfg(test)] mod { … }` body
/// and this is a DECLARATION pointing at another file. So the gate flagged six lines of a test
/// double as if the voice plane priced in production.
///
/// The fix is the same rule the reachability work states: **a `mod X;` declaration is not an edge**
/// — and by the same token, the attribute ON that declaration is what decides the scope of the file
/// it names. A file's scope is set by how it is DECLARED, not by what it is called.
///
/// Both spellings are resolved: `#[cfg(test)] mod name;` → `<dir>/name.rs` and `<dir>/name/mod.rs`,
/// and an intervening `#[path = "rel"]` → `<dir>/rel`. Only `#[cfg(test)]` counts; a plain
/// `#[path]` on a production module changes nothing.
fn test_declared_files(files: &[crate::ctx::SourceFile]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for f in files {
        let rel = f.rel_str();
        let Some(dir) = rel.rsplit_once('/').map(|(d, _)| d.to_string()) else {
            continue;
        };
        let lines: Vec<&str> = f.text.lines().collect();
        for (i, raw) in lines.iter().enumerate() {
            if !raw.trim_start().starts_with("#[cfg(test)]") {
                continue;
            }
            // The declaration follows the attribute, possibly behind a `#[path = "…"]`. Three
            // lines is the whole idiom in this tree; more would be reaching.
            let mut path_override: Option<String> = None;
            for probe in lines.iter().skip(i + 1).take(3) {
                let t = probe.trim();
                if let Some(rest) = t.strip_prefix("#[path") {
                    if let Some(v) = rest.split('"').nth(1) {
                        path_override = Some(v.to_string());
                    }
                    continue;
                }
                let Some(rest) = t.strip_prefix("mod ") else {
                    // Anything else (including an inline `mod x {`) ends the idiom.
                    break;
                };
                let name = rest.trim_end_matches(';').trim();
                if name.is_empty() || name.contains('{') {
                    break;
                }
                match &path_override {
                    Some(p) => {
                        out.insert(normalize(&format!("{dir}/{p}")));
                    }
                    None => {
                        out.insert(format!("{dir}/{name}.rs"));
                        out.insert(format!("{dir}/{name}/mod.rs"));
                    }
                }
                break;
            }
        }
    }
    out
}

/// `a/b/../c` → `a/c`, so a `#[path]` that climbs resolves to the key the walk yields.
fn normalize(p: &str) -> String {
    let mut parts: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "." | "" => {}
            ".." => {
                parts.pop();
            }
            s => parts.push(s),
        }
    }
    parts.join("/")
}

/// One confirmed violation: a category, the crate it is in, and the file. The key the baseline
/// uses is `(category, file)` — never a line, which rots into a hole at whatever lands on it.
#[derive(Clone)]
pub struct Finding {
    pub category: Category,
    pub krate: String,
    pub file: String,
    pub placement: &'static str,
    /// Every offending line, for the row detail. Not part of the key.
    pub lines: Vec<(usize, String)>,
}

fn finding_key(f: &Finding) -> (String, String) {
    (f.category.key().to_string(), f.file.clone())
}

/// THE SCAN. One walk of `crates/`, filtered to the roster's plane crates, comments stripped,
/// STRING LITERALS BLANKED, test scope and test files dropped.
///
/// The blanking carries its own `LexState` across the WHOLE file rather than per line, because a
/// Rust string literal spans lines and a per-line blanker reads the body of a multi-line message as
/// code — which is how a diagnostic saying "busbar does not spend its own credentials" becomes a
/// finding. The production-line SET comes from [`scan::production_lines`]; the TEXT that is matched
/// comes from the carried blanker. Two passes, one answer.
pub fn census(cx: &Ctx) -> Result<(Vec<Finding>, bool), String> {
    let by_dir: BTreeMap<&str, &PlaneCrate> =
        PLANE_CRATES.iter().map(|p| (p.dir, p)).collect();

    let files = cx
        .walk(&WalkSpec::new(["crates"]).ext("rs").min_files(1))
        .map_err(|e| e.to_string())?;

    let mut out: BTreeMap<(Category, String), Finding> = BTreeMap::new();
    let mut clock_exemption_fired = false;
    // Resolved BEFORE the scan, because a file's scope is decided by how it is declared and that
    // declaration lives in a different file.
    let test_declared = test_declared_files(&files);

    for f in &files {
        let rel = f.rel_str();
        let Some(krate) = crate_of(&rel) else { continue };
        let Some(plane) = by_dir.get(krate.as_str()) else {
            continue;
        };
        if is_test_file(&rel) || test_declared.contains(&rel) {
            continue;
        }

        let production: BTreeSet<usize> = scan::production_lines(&f.text)
            .into_iter()
            .map(|(n, _)| n)
            .collect();

        let mut lex = scan::LexState::default();
        for (idx, raw) in f.text.lines().enumerate() {
            let code = scan::blank_code(raw, &mut lex);
            let lineno = idx + 1;
            if !production.contains(&lineno) {
                continue;
            }
            if code.trim().is_empty() {
                continue;
            }

            let (money_nanos_hit, clock_hit) = money_nanos(&code);
            if clock_hit {
                clock_exemption_fired = true;
            }

            let card = CARD.iter().chain(CURRENCY).any(|n| hits(&code, n));
            let price = money_nanos_hit || PRICE.iter().any(|n| hits(&code, n));
            let key = UNIT_KEY.iter().any(|n| hits(&code, n));
            let hold = HOLD.iter().any(|n| hits(&code, n));
            // THE #87 ROW. A card needle is a violation wherever it sits; a card needle inside a
            // CONDITIONAL is the specific thing #87 outlaws — "planes always ledger" means the
            // append cannot be behind `if billing_is_on`.
            let switch = card && is_conditional(&code);

            for (cat, fired) in [
                (Category::Card, card),
                (Category::Switch, switch),
                (Category::Price, price),
                (Category::UnitKey, key),
                (Category::Hold, hold),
            ] {
                if !fired {
                    continue;
                }
                out.entry((cat, rel.clone()))
                    .or_insert_with(|| Finding {
                        category: cat,
                        krate: krate.clone(),
                        file: rel.clone(),
                        placement: plane.placement,
                        lines: Vec::new(),
                    })
                    .lines
                    .push((lineno, code.trim().to_string()));
            }
        }
    }

    Ok((out.into_values().collect(), clock_exemption_fired))
}

/// `crates/<dir>/…` → `<dir>`.
fn crate_of(rel: &str) -> Option<String> {
    let rest = rel.strip_prefix("crates/")?;
    let dir = rest.split('/').next()?;
    if dir.is_empty() {
        None
    } else {
        Some(dir.to_string())
    }
}

/// Which of [`DECLARING_PLANES`] still declares at least one meter class.
fn declarations(cx: &Ctx) -> Result<Vec<String>, String> {
    let mut missing = Vec::new();
    for plane in DECLARING_PLANES {
        let root = format!("crates/{plane}/src");
        let found = match cx.walk(&WalkSpec::new([root.clone()]).ext("rs")) {
            Ok(files) => files.iter().any(|f| {
                !is_test_file(&f.rel_str())
                    && scan::production_lines(&f.text)
                        .iter()
                        .any(|(_, l)| l.contains(DECLARATION_GRAMMAR))
            }),
            Err(_) => false,
        };
        if !found {
            missing.push((*plane).to_string());
        }
    }
    Ok(missing)
}

/// WHETHER THE VIOLATING LINE EXECUTES.
///
/// The standing discipline in this tree is that a missing check is not a vulnerability until you
/// show the line runs — and the same is true of a violation. A gate that reds identically on 1,884
/// lines of provably-dead scaffolding and on a live billing branch teaches its readers to bless it.
///
/// This is a HUMAN claim recorded in the ledger, not something the scanner derives: a text gate
/// cannot do call-graph analysis honestly, and one that guessed would be worse than one that asks.
/// [`ROW_REACHABILITY`] is what keeps the claim honest — `Unproven`, or a claim with no citation,
/// is RED, so "I did not look" cannot masquerade as "it is dead".
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Reach {
    /// A non-test call site was traced to the serving path. Cite it in `why`.
    Reachable,
    /// Proven dead: no non-test constructor/caller. Cite the tracing in `why`.
    Unreachable,
    /// Nobody has looked. Scored like a violation, because that is what it might be.
    Unproven,
}

impl Reach {
    fn parse(s: &str) -> Reach {
        match s {
            "reachable" => Reach::Reachable,
            "unreachable" => Reach::Unreachable,
            _ => Reach::Unproven,
        }
    }
}

/// One baseline row.
struct Debt {
    category: String,
    file: String,
    reach: Reach,
    why: String,
}

fn baseline(cx: &Ctx) -> Vec<Debt> {
    let Ok(text) = cx.read(BASELINE) else {
        return Vec::new();
    };
    let Ok(doc) = crate::toml_doc::parse_str(&text) else {
        return Vec::new();
    };
    doc.array_of_tables("debt")
        .into_iter()
        .filter_map(|t| {
            let cat = t.str_of("category")?;
            Category::from_key(cat)?;
            let file = t.str_of("file")?;
            Some(Debt {
                category: cat.to_string(),
                file: file.to_string(),
                reach: Reach::parse(t.str_of("reach").unwrap_or("")),
                why: t.str_of("why").unwrap_or("").trim().to_string(),
            })
        })
        .collect()
}

/// The baseline as a set of `(category, file)` keys.
fn baseline_keys(rows: &[Debt]) -> Vec<(String, String)> {
    rows.iter()
        .map(|d| (d.category.clone(), d.file.clone()))
        .collect()
}

/// The baseline TOML for the current census — one `[[debt]]` per (category, file).
fn emit_baseline(findings: &[Finding]) -> String {
    let mut out = String::new();
    out.push_str(
        "# plane-pricing-blindness burndown ledger — AUTO-DERIVED, HUMAN-REVIEWED.\n\
         # One row per (money category, offending file) in a crate the #83 roster calls a plane.\n\
         # The gate is RED while any row stands; it goes GREEN when this file is empty.\n\
         # Regenerate: XTASK_PPB_EMIT_BASELINE=1 cargo xtask gate plane-pricing-blindness \
         2>qa/plane-pricing-blindness.toml\n\n",
    );
    for f in findings {
        out.push_str("[[debt]]\n");
        out.push_str(&format!("category = \"{}\"\n", f.category.key()));
        out.push_str(&format!("crate = \"{}\"\n", f.krate));
        out.push_str(&format!("file = \"{}\"\n", f.file));
        out.push_str(&format!("count = {}\n", f.lines.len()));
        out.push_str(&format!("placement = \"{}\"\n", f.placement));
        out.push_str(&format!("act = \"{}\"\n", f.category.act()));
        // The emitter CANNOT derive these two, and says so rather than guessing: a reachability
        // claim is a call site somebody traced. `unproven` is RED until a human replaces it.
        out.push_str("reach = \"unproven\"\n");
        out.push_str("why = \"\"\n\n");
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE GATE
// ─────────────────────────────────────────────────────────────────────────────────────────────

pub struct PlanePricingBlindnessGate;

fn did_not_run(rows: &mut Vec<Row>, why: &str) {
    for id in [
        ROW_DECLARATION,
        ROW_CARD,
        ROW_SWITCH,
        ROW_PRICE,
        ROW_UNIT_KEY,
        ROW_HOLD,
        ROW_UNDOCUMENTED,
        ROW_STALE,
        ROW_REACHABILITY,
    ] {
        rows.push(Row::fail(id, "the scan did not run", why.to_string()));
    }
}

impl Gate for PlanePricingBlindnessGate {
    fn name(&self) -> &'static str {
        "plane-pricing-blindness"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_ROOTS.to_string(),
            ROW_SCAN_FLOOR.to_string(),
            ROW_DECLARATION.to_string(),
            ROW_CARD.to_string(),
            ROW_SWITCH.to_string(),
            ROW_PRICE.to_string(),
            ROW_UNIT_KEY.to_string(),
            ROW_HOLD.to_string(),
            ROW_UNDOCUMENTED.to_string(),
            ROW_STALE.to_string(),
            ROW_REACHABILITY.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let mut rows = Vec::new();

        // THE ROOT GUARD, before any number means anything. A listed crate that is not on disk is
        // scanned as ZERO files, and zero is the passing answer to every ban below.
        let missing: Vec<&str> = PLANE_CRATES
            .iter()
            .map(|p| p.dir)
            .filter(|d| {
                let root = format!("crates/{d}/src");
                !cx.abs(&root).is_dir() && !cx.exists(&root)
            })
            .collect();
        rows.push(if missing.is_empty() {
            Row::pass(
                ROW_ROOTS,
                format!("all {} roster plane crates are on disk", PLANE_CRATES.len()),
                CLEAN,
            )
        } else {
            Row::fail(
                ROW_ROOTS,
                "a crate the roster calls a plane is listed but not present on disk",
                format!(
                    "{} — a listed crate that does not exist is scanned as ZERO files, and zero \
                     passes every ban. If it legitimately folded or merged, DELETE its entry in a \
                     reviewed diff that says so; never leave a stale name in PLANE_CRATES.",
                    missing.join(", ")
                ),
            )
        });

        let (findings, clock_fired) = match census(cx) {
            Ok(v) => v,
            Err(e) => {
                rows.push(Row::fail(
                    ROW_SCAN_FLOOR,
                    "the crates tree could not be scanned",
                    format!("{e} — {DID_NOT_RUN}"),
                ));
                did_not_run(&mut rows, DID_NOT_RUN);
                return Verdict::of(rows);
            }
        };
        rows.push(Row::pass(ROW_SCAN_FLOOR, "the crates tree was scanned", CLEAN));

        if std::env::var("XTASK_PPB_EMIT_BASELINE").as_deref() == Ok("1") {
            eprint!("{}", emit_baseline(&findings));
        }

        // THE POSITIVE FLOOR. Without this, a plane that stopped declaring meter classes would
        // satisfy every ban below and read as perfectly clean.
        match declarations(cx) {
            Ok(missing) if missing.is_empty() => rows.push(Row::pass(
                ROW_DECLARATION,
                format!(
                    "all {} contract planes still declare their meter classes (#71)",
                    DECLARING_PLANES.len()
                ),
                CLEAN,
            )),
            Ok(missing) => rows.push(Row::fail(
                ROW_DECLARATION,
                "a plane declares no meter class, so it meters nothing",
                format!(
                    "{} — #71 makes a plane's whole money obligation ONE fact per unit, keyed by a \
                     class it declares. A plane that declares none emits no count, satisfies every \
                     ban in this gate, and reads as clean. That is this gate measuring nothing.",
                    missing.join(", ")
                ),
            )),
            Err(e) => rows.push(Row::fail(
                ROW_DECLARATION,
                "the meter-class declarations could not be read",
                e,
            )),
        }

        // THE LEDGER, read once: the burndown rows and the reachability claim each carries.
        let debts = baseline(cx);
        let reach_of: BTreeMap<(String, String), (Reach, bool)> = debts
            .iter()
            .map(|d| {
                (
                    (d.category.clone(), d.file.clone()),
                    (d.reach, !d.why.is_empty()),
                )
            })
            .collect();

        // THE FIVE CENSUS ROWS, one per banned act — each reporting TWO NUMBERS.
        //
        // Reachable and unreachable are different debts and a single total hides which one you are
        // looking at. A red that is entirely unreachable scaffolding is a DELETION job; a red with
        // even one reachable line is a live money defect. The row says which.
        let mut by_cat: BTreeMap<Category, Vec<&Finding>> = BTreeMap::new();
        for f in &findings {
            by_cat.entry(f.category).or_default().push(f);
        }
        for cat in CATEGORIES {
            match by_cat.get(cat) {
                None => rows.push(Row::pass(
                    cat.row(),
                    format!("no plane crate {}", cat.act()),
                    CLEAN,
                )),
                Some(hits) => {
                    let (mut live, mut dead, mut unknown) = (0usize, 0usize, 0usize);
                    let mut listing: Vec<String> = Vec::new();
                    for f in hits {
                        let mark = match reach_of.get(&finding_key(f)).map(|(r, _)| *r) {
                            Some(Reach::Reachable) => {
                                live += 1;
                                "LIVE"
                            }
                            Some(Reach::Unreachable) => {
                                dead += 1;
                                "dead"
                            }
                            _ => {
                                unknown += 1;
                                "UNPROVEN"
                            }
                        };
                        let first = f
                            .lines
                            .first()
                            .map(|(n, _)| n.to_string())
                            .unwrap_or_default();
                        listing.push(format!("[{mark}] {}:{first}×{}", f.file, f.lines.len()));
                    }
                    rows.push(Row::fail(
                        cat.row(),
                        format!(
                            "a plane crate {} — {} file(s): {live} reachable, {dead} \
                             unreachable, {unknown} unproven",
                            cat.act(),
                            hits.len()
                        ),
                        format!(
                            "{TRACKED_NEEDLE} census — {}: {}. #43 makes a plane PRICING-BLIND and \
                             #71 makes its whole money obligation one raw count per declared class; \
                             this act belongs kernel-side.",
                            hits.len(),
                            listing.join(" | ")
                        ),
                    ));
                }
            }
        }

        // THE REACHABILITY CLAIM, PUT TO THE READER. A burndown row that does not say whether its
        // line executes — or says so with no citation — is not a claim, it is a shrug. "I did not
        // look" must not be able to read as "it is dead", so both are RED here.
        let live_keys: BTreeSet<(String, String)> = findings.iter().map(finding_key).collect();
        let mut unproven: Vec<String> = debts
            .iter()
            .filter(|d| live_keys.contains(&(d.category.clone(), d.file.clone())))
            .filter(|d| d.reach == Reach::Unproven || d.why.is_empty())
            .map(|d| {
                let missing = if d.reach == Reach::Unproven {
                    "no reach"
                } else {
                    "no citation"
                };
                format!("{}@{} ({missing})", d.category, d.file)
            })
            .collect();
        unproven.sort();
        rows.push(if unproven.is_empty() {
            Row::pass(
                ROW_REACHABILITY,
                "every burndown row says whether its line executes, and cites how it was traced",
                CLEAN,
            )
        } else {
            Row::fail(
                ROW_REACHABILITY,
                "a burndown row does not say whether its violating line executes",
                format!(
                    "{TRACKED_NEEDLE} — {} row(s) unproven: {}. Set `reach` to `reachable` or \
                     `unreachable` and put the traced call site in `why`. A gate that reds the \
                     same on provably-dead scaffolding as on a live billing branch teaches its \
                     readers to bless it; that is what this row exists to stop.",
                    unproven.len(),
                    unproven.join(", ")
                ),
            )
        });

        // A CLOCK EXEMPTION THAT COVERS NOTHING IS A DEAD ROW — reported on the price row, because
        // it is the price rule the exemption narrows.
        if !clock_fired && !findings.is_empty() {
            rows.push(Row::fail(
                ROW_PRICE,
                "the clock-nanos exemption no longer covers any live line",
                format!(
                    "TIME_NANOS ({}) narrows the `_nanos` money rule and now fires on nothing, so \
                     it is a permanent hole nobody re-reads. Strike the spellings that are gone.",
                    TIME_NANOS.join("/")
                ),
            ));
        }

        // UNDOCUMENTED: a live finding the baseline does not name. THIS is what bites a NEW money
        // reference landing in a plane crate.
        let baseline = baseline_keys(&debts);
        let mut undocumented: Vec<String> = findings
            .iter()
            .filter(|f| !baseline.contains(&finding_key(f)))
            .map(|f| format!("{}@{}", f.category.key(), f.file))
            .collect();
        undocumented.sort();
        rows.push(if undocumented.is_empty() {
            Row::pass(
                ROW_UNDOCUMENTED,
                "every live money reference is recorded in the baseline burndown",
                CLEAN,
            )
        } else {
            Row::fail(
                ROW_UNDOCUMENTED,
                "a live money reference in a plane crate is NOT in the baseline",
                format!(
                    "{} undocumented: {} — a NEW money reference landed in a crate the roster calls \
                     a plane. Move it kernel-side, or (if it is genuine debt) record it in \
                     {BASELINE} with the act it performs.",
                    undocumented.len(),
                    undocumented.join(", ")
                ),
            )
        });

        // STALE: a baseline row whose finding is gone. The ledger cannot outlive the debt.
        let live: BTreeSet<(String, String)> = findings.iter().map(finding_key).collect();
        let mut stale: Vec<String> = baseline
            .iter()
            .filter(|k| !live.contains(*k))
            .map(|(c, f)| format!("{c}@{f}"))
            .collect();
        stale.sort();
        rows.push(if stale.is_empty() {
            Row::pass(
                ROW_STALE,
                "every baseline row still names a live money reference",
                CLEAN,
            )
        } else {
            Row::fail(
                ROW_STALE,
                "a baseline row no longer names a live money reference",
                format!(
                    "{} stale row(s): {} — the money is gone; strike the row from {BASELINE} in the \
                     same commit that moved it kernel-side.",
                    stale.len(),
                    stale.join(", ")
                ),
            )
        });

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();

        // THE SELF-TEST RUNS OVER TINY FIXTURE TREES, NOT THE 660k-LINE REPO — the same reason
        // instance-noun-neutrality does: a census gate that planted into the real workspace and
        // re-scanned it per case grows a whole-tree scan per plant.
        //
        // `xtask/fixtures/plane-money/` is: a contract plane that declares its meter classes,
        // emits a raw count and renders a kernel money refusal (every LEGITIMATE shape, so the
        // green controls are proofs of the exclusions); a legacy plane crate carrying one planted
        // violation per category; a NON-plane crate carrying the same violations (so the scope is
        // proved to be the roster's plane set and not the whole tree); and a baseline naming one
        // GHOST row and none of the live ones.
        const FIX: &str = "xtask/fixtures/plane-money";
        const FIX_EMPTY: &str = "xtask/fixtures/plane-money-empty";

        // ONE RED CASE PER BANNED ACT.
        for cat in CATEGORIES {
            report.push(prove_rows_red_at(
                cx,
                self,
                format!("a plane crate that {} reds its census row", cat.act()),
                &[cat.row()],
                FIX,
                &["crates/busbar-llm/src/unit/money.rs"],
            ));
        }

        // THE #87 ROW IS NARROWER THAN THE CARD ROW, and the fixture proves it: the card needle
        // appears both inside a conditional and in a plain declaration, and only the conditional
        // may name the switch row. Without this the switch row is just a duplicate of the card row.
        report.push(switch_is_narrower(self, cx, FIX));

        // THE UNDOCUMENTED ROW: the fixture's live findings are absent from its baseline.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a live money reference absent from the baseline reds the undocumented row",
            &[ROW_UNDOCUMENTED],
            FIX,
            &["undocumented"],
        ));

        // THE STALE ROW: the fixture baseline names a ghost the tree does not have.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a baseline row with no live finding reds the stale row",
            &[ROW_STALE],
            FIX,
            &["ghost-nonexistent"],
        ));

        // THE REACHABILITY ROW: the fixture baseline records one live finding with `reach =
        // "unproven"` and one with a reach but an EMPTY `why`. Both are RED, because "I did not
        // look" must not read as "it is dead" and a claim with no citation is not a claim.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a burndown row with no reach claim, or a claim with no citation, reds reachability",
            &[ROW_REACHABILITY],
            FIX,
            &["no reach", "no citation"],
        ));

        // THE POSITIVE FLOOR: the fixture's contract plane declares classes, so the row is GREEN
        // there; strip the declaration and it must RED. A gate that can pass by the planes
        // forgetting to meter is a gate measuring nothing.
        report.push(prove_rows_green(
            cx,
            self,
            "a plane that declares its meter classes satisfies the declaration floor",
            &[ROW_DECLARATION],
            Overlay::new(),
        ));
        report.push(declaration_floor_bites(self, cx, FIX));

        // THE SCAN FLOOR: a `crates/` that holds no Rust is refused, never scanned as zero findings.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a crates tree holding no Rust reds the scan floor",
            &[ROW_SCAN_FLOOR],
            FIX_EMPTY,
            &["could not be scanned"],
        ));

        // THE ROOT GUARD: a listed plane crate that is not on disk is refused rather than scanned
        // as zero files. The fixture holds only two of the roster's crates, so the guard fires
        // there — and it is read outside the overlay, which is why this is a re-root not a plant.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a roster plane crate that is not on disk is refused, not scanned as zero files",
            &[ROW_ROOTS],
            FIX,
            &["not present on disk"],
        ));

        // GREEN CONTROL 1 — PROSE IS NEVER A VIOLATION, and this is the control that matters most:
        // the owner's own grep for `rate_card|nanos|price|spend` measured 125 hits across the five
        // extracted planes and essentially every one was a doc comment saying this plane does NOT
        // price. A gate its own explanation fails is a gate people learn to skip.
        report.push(green_over_fixture(
            self,
            cx,
            FIX,
            "prose naming a rate card, a price and nanos is not a violation",
            &[ROW_CARD, ROW_PRICE, ROW_HOLD],
            |ov| {
                ov.set(
                    "crates/busbar-llm/src/unit/money.rs",
                    "//! This plane never reads a rate_card, never computes a price and holds no\n\
                     //! nanos. A Hold, an AccrualMeter and a PostingStamp are all kernel-side.\n\
                     /* block comment: cost_settle, settled_nanos, UnitKey::new, pricing_enabled */\n\
                     pub fn install() -> u64 { 0 }\n\
                     #[cfg(test)]\nmod tests {\n\
                     \x20   fn t() { let _ = Hold::open(); let _n = settled_nanos(); }\n}\n",
                )
            },
        ));

        // GREEN CONTROL 2 — A STRING LITERAL IS PROSE TOO. A diagnostic that SAYS "does not spend"
        // sits inside `"…"`, and a per-line blanker reads the continuation of a multi-line message
        // as code. The carried LexState is what stops that, and this is its proof.
        report.push(green_over_fixture(
            self,
            cx,
            FIX,
            "a money word inside a multi-line string literal is not a violation",
            &[ROW_CARD, ROW_PRICE, ROW_HOLD],
            |ov| {
                ov.set(
                    "crates/busbar-llm/src/unit/money.rs",
                    "pub fn why() -> &'static str {\n\
                     \x20   \"no rate_card is configured for this model, so the \\\n\
                     \x20     Hold and its settled_nanos and every PostingStamp are \\\n\
                     \x20     the kernel's to compute, never this plane's\"\n}\n",
                )
            },
        ));

        // GREEN CONTROL 3 — THE CLOCK IS NOT MONEY. `monotonic_nanos` and `SystemTime::as_nanos`
        // are real, live spellings in `busbar-plane-llm` and `busbar-llm-codec`; the `_nanos`
        // money rule must let both through while `settled_nanos` (proved red above) does not.
        report.push(green_over_fixture(
            self,
            cx,
            FIX,
            "a clock spelled in nanos is not a money quantity",
            &[ROW_PRICE],
            |ov| {
                ov.set(
                    "crates/busbar-llm/src/unit/money.rs",
                    "pub fn stamp(clock: &Clock) -> u128 {\n\
                     \x20   let a = clock.monotonic_nanos;\n\
                     \x20   let b = std::time::SystemTime::now().elapsed().unwrap().as_nanos();\n\
                     \x20   u128::from(a) + b\n}\n",
                )
            },
        ));

        // GREEN CONTROL 4 — DECLARING A METER CLASS IS #71 WORKING. The fixture's contract plane
        // declares `MeterClassDecl { key, family, direction, default_divisor }` and emits a raw
        // count under it, and converts ms to its own declared seconds denomination. None of that
        // is valuing, and none of it may flag.
        report.push(green_over_fixture(
            self,
            cx,
            FIX,
            "declaring a meter class, emitting a raw count and converting to its own denomination \
             are all #71 working",
            &[ROW_CARD, ROW_SWITCH, ROW_PRICE, ROW_UNIT_KEY, ROW_HOLD],
            |ov| {
                ov.set(
                    "crates/busbar-llm/src/unit/money.rs",
                    "const CLASSES: &[MeterClassDecl] = &[MeterClassDecl {\n\
                     \x20   key: MeterClassId::new(\"audio_seconds_in\"),\n\
                     \x20   family: \"duration\",\n\
                     \x20   direction: ClassDirection::Input,\n\
                     \x20   default_divisor: 1,\n}];\n\
                     pub const fn audio_seconds_in(ms: u64) -> u64 { ms.div_ceil(1_000) }\n\
                     pub fn meter(r: &Response) -> UsageLocators {\n\
                     \x20   let mut l = UsageLocators::default();\n\
                     \x20   let _ = l.lines.push(UsageLocator {\n\
                     \x20       class: CLASS_BYTES, location: None,\n\
                     \x20       quantity: Some(r.ir.body().len() as u64), lane: None });\n\
                     \x20   l\n}\n",
                )
            },
        ));

        // GREEN CONTROL 5 — READING A KERNEL MONEY REFUSAL IS NOT VALUING. Every plane renders
        // `Unpriced` / `OverBudget` / `NoRate` onto its own wire, because #42 requires an unpriced
        // class to REFUSE rather than answer zero and the client has to be told. The needle rules
        // must not catch the reason names — note `Unpriced` must NOT read as `priced`, which is the
        // whole reason every needle has to START at an identifier boundary.
        report.push(green_over_fixture(
            self,
            cx,
            FIX,
            "rendering a kernel money refusal onto the wire is not valuing",
            &[ROW_CARD, ROW_SWITCH, ROW_PRICE, ROW_UNIT_KEY, ROW_HOLD],
            |ov| {
                ov.set(
                    "crates/busbar-llm/src/unit/money.rs",
                    "pub fn refusal_shape(reason: RefusalReason) -> (u16, &'static str) {\n\
                     \x20   match reason {\n\
                     \x20       RefusalReason::OverBudget\n\
                     \x20       | RefusalReason::OverdraftCeiling\n\
                     \x20       | RefusalReason::GroupFrozen => (429, KIND_RATE_LIMIT),\n\
                     \x20       RefusalReason::Unpriced | RefusalReason::NoRate => (400, KIND_BAD),\n\
                     \x20       _ => (500, KIND_INTERNAL),\n\
                     \x20   }\n}\n",
                )
            },
        ));

        // GREEN CONTROL 6 — THE SCOPE IS THE ROSTER'S PLANE SET, NOT THE WHOLE TREE. The fixture's
        // non-plane crate carries the SAME violations the plane crate does. If the crate filter
        // regressed, this would flag — and the kernel is exactly where these acts BELONG.
        report.push(scope_is_the_roster(self, cx, FIX));

        // GREEN CONTROL 7 — A FILE'S SCOPE IS HOW IT IS DECLARED, NOT WHAT IT IS CALLED. This one
        // was a REAL false positive before it was a case: the gate flagged
        // `busbar-voice/src/runtime/voice_d2_billing_oracle.rs`, a money double compiled only
        // under `#[cfg(test)]` via a `#[path]` declaration, sitting beside its parent with nothing
        // test-shaped about its name. The fixture carries the identical shape, and the CONTROL
        // that makes this a proof rather than a blind skip is `money.rs` in the same directory:
        // it is declared `pub mod money;` and every red case above requires it to flag.
        report.push(test_declared_is_not_production(self, cx, FIX));

        report
    }
}

/// Run the gate over `fixture` with `plant` applied and report GREEN iff none of `covers` is red.
fn green_over_fixture<'a>(
    gate: &'a PlanePricingBlindnessGate,
    cx: &Ctx,
    fixture: &str,
    name: &str,
    covers: &[&str],
    plant: impl FnOnce(&mut Overlay),
) -> Case {
    let covers_owned: Vec<String> = covers.iter().map(|s| (*s).to_string()).collect();
    let Ok(fcx) = Ctx::at(cx.abs(fixture), cx.scratch().to_path_buf()) else {
        return Case {
            name: name.to_string(),
            covers: covers_owned,
            expected: Expect::Green,
            got: Expect::Skipped,
        };
    };
    let mut ov = Overlay::new();
    plant(&mut ov);
    let verdict = execute(gate, &fcx.with_overlay(ov));
    let offenders: Vec<String> = verdict
        .rows
        .iter()
        .filter(|r| r.status != Status::Pass && covers.contains(&r.id.as_str()))
        .map(|r| format!("{} {}", r.id, r.detail))
        .collect();
    Case {
        name: name.to_string(),
        covers: covers_owned,
        expected: Expect::Green,
        got: if offenders.is_empty() {
            Expect::Green
        } else {
            Expect::Red { naming: offenders }
        },
    }
}

/// THE #87 ROW IS NARROWER THAN THE CARD ROW. Plant a card needle in a plain declaration and in a
/// conditional; the card row must name both files and the switch row only the conditional one.
fn switch_is_narrower(gate: &PlanePricingBlindnessGate, cx: &Ctx, fixture: &str) -> Case {
    let covers = vec![ROW_SWITCH.to_string()];
    let name =
        "the billing-switch row names a card needle inside a conditional and NOT a plain one"
            .to_string();
    let Ok(fcx) = Ctx::at(cx.abs(fixture), cx.scratch().to_path_buf()) else {
        return Case { name, covers, expected: Expect::Green, got: Expect::Skipped };
    };
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-llm/src/unit/plain.rs",
        "pub fn pricing_enabled(&self) -> bool { self.flag }\n",
    );
    ov.set(
        "crates/busbar-llm/src/unit/branch.rs",
        "pub fn go(&self) { if host.cost_pricing_enabled(&self.cost) { self.meter(); } }\n",
    );
    let verdict = execute(gate, &fcx.with_overlay(ov));
    let detail = |id: &str| {
        verdict
            .rows
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.detail.clone())
            .unwrap_or_default()
    };
    let card = detail(ROW_CARD);
    let switch = detail(ROW_SWITCH);
    let ok = card.contains("plain.rs")
        && card.contains("branch.rs")
        && switch.contains("branch.rs")
        && !switch.contains("plain.rs");
    Case {
        name,
        covers,
        expected: Expect::Green,
        got: if ok {
            Expect::Green
        } else {
            Expect::Red {
                naming: vec![format!(
                    "the switch row is not narrower than the card row — card=[{card}] switch=[{switch}]"
                )],
            }
        },
    }
}

/// THE POSITIVE FLOOR BITES. Strip the fixture plane's `MeterClassDecl` and the declaration row
/// must go RED — otherwise the gate can pass by the planes forgetting to meter.
fn declaration_floor_bites(
    gate: &PlanePricingBlindnessGate,
    cx: &Ctx,
    fixture: &str,
) -> Case {
    let covers = vec![ROW_DECLARATION.to_string()];
    let name = "a plane that declares no meter class reds the declaration floor".to_string();
    let Ok(fcx) = Ctx::at(cx.abs(fixture), cx.scratch().to_path_buf()) else {
        return Case { name, covers, expected: Expect::Red { naming: Vec::new() }, got: Expect::Skipped };
    };
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-plane-llm/src/meta.rs",
        "//! the declaration is gone; this plane now meters nothing\npub const OPS: &[u8] = &[];\n",
    );
    let verdict = execute(gate, &fcx.with_overlay(ov));
    let red = verdict
        .rows
        .iter()
        .find(|r| r.id == ROW_DECLARATION)
        .is_some_and(|r| r.status != Status::Pass && r.detail.contains("busbar-plane-llm"));
    Case {
        name,
        covers,
        expected: Expect::Red { naming: vec!["busbar-plane-llm".to_string()] },
        got: if red {
            Expect::Red { naming: vec!["busbar-plane-llm".to_string()] }
        } else {
            Expect::Green
        },
    }
}

/// A FILE DECLARED UNDER `#[cfg(test)]` IS TEST SCOPE, WHATEVER IT IS CALLED — and the file beside
/// it that is NOT so declared still flags, which is what makes this a proof and not a blind skip.
fn test_declared_is_not_production(
    gate: &PlanePricingBlindnessGate,
    cx: &Ctx,
    fixture: &str,
) -> Case {
    let covers = vec![ROW_PRICE.to_string()];
    let name =
        "a money double declared under #[cfg(test)] is test scope; its production sibling is not"
            .to_string();
    let Ok(fcx) = Ctx::at(cx.abs(fixture), cx.scratch().to_path_buf()) else {
        return Case { name, covers, expected: Expect::Green, got: Expect::Skipped };
    };
    let verdict = execute(gate, &fcx);
    let detail = verdict
        .rows
        .iter()
        .find(|r| r.id == ROW_PRICE)
        .map(|r| r.detail.clone())
        .unwrap_or_default();
    let names_double = detail.contains("oracle_double.rs");
    let names_production = detail.contains("unit/money.rs");
    Case {
        name,
        covers,
        expected: Expect::Green,
        got: if names_production && !names_double {
            Expect::Green
        } else {
            Expect::Red {
                naming: vec![format!(
                    "cfg(test)-declared scope regressed: names_double={names_double} \
                     names_production={names_production}"
                )],
            }
        },
    }
}

/// THE SCOPE IS THE ROSTER'S PLANE SET. The same violation in a NON-plane crate must not flag —
/// the kernel is where these acts belong.
fn scope_is_the_roster(gate: &PlanePricingBlindnessGate, cx: &Ctx, fixture: &str) -> Case {
    let covers = vec![ROW_HOLD.to_string()];
    let name = "the same money act in a NON-plane crate is not a finding".to_string();
    let Ok(fcx) = Ctx::at(cx.abs(fixture), cx.scratch().to_path_buf()) else {
        return Case { name, covers, expected: Expect::Green, got: Expect::Skipped };
    };
    let verdict = execute(gate, &fcx);
    let detail = verdict
        .rows
        .iter()
        .find(|r| r.id == ROW_HOLD)
        .map(|r| r.detail.clone())
        .unwrap_or_default();
    let names_plane = detail.contains("busbar-llm/src/unit/money.rs");
    let names_kernel = detail.contains("busbar-kernel");
    Case {
        name,
        covers,
        expected: Expect::Green,
        got: if names_plane && !names_kernel {
            Expect::Green
        } else {
            Expect::Red {
                naming: vec![format!(
                    "scope regressed: names_plane={names_plane} names_kernel={names_kernel}"
                )],
            }
        },
    }
}
