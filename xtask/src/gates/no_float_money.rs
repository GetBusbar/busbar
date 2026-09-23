//! `cargo xtask gate no-float-money` — NO BINARY FLOATING POINT, AND NO SILENTLY-DEFAULTED COUNT
//! READ, ON ANY MONEY PATH (DECISIONS #77(8), #66, #81, #81a).
//!
//! The 1.6.0 money model is exact arithmetic: a rate is an integer nano-unit, an accumulation is a
//! `u128`, a count is an `i128` mantissa at one fixed decimal scale (`busbar_contract::count`), and
//! a projection truncates once with an integer divisor. `f32`/`f64` on the money path is exactly the
//! failure this bans — a float sums differently depending on order, rounds in ways nobody
//! configured, cannot hold `27.1` at all, and turns "the bill equals the sum of the lines" from a
//! proof into a hope. So the crate that owns the money arithmetic (`busbar-kernel-ledger`), the
//! crate that owns the exact count type (`busbar-contract`'s count module), the crate that decides
//! affordability (`busbar-kernel-budget`) and the kernel's and binary's dedicated money-unit files
//! carry no float in production source.
//!
//! # THE SCAN SET IS THE CHECK
//!
//! For most of this gate's life it scanned the ledger crate and six named files, and that was the
//! whole of it. `crates/busbar-kernel/src/cost.rs` — which owns `RateNanos` and the conversion that
//! builds it — and every file in `crates/busbar-kernel-budget/src` — which decides whether a request
//! is affordable and prices the counters that answer — were in NEITHER set. No amount of float added
//! to either could produce a RED, ever, for any reason. An instrument that cannot produce a NO is
//! not a check, so both are in the set now: the budget crate whole (it is a money crate), the
//! kernel's money files by name (the kernel is not).
//!
//! # THE ONE EXEMPT BOUNDARY (#44)
//!
//! A card is BUILT from configured decimals, and the one decimal-to-integer conversion is allowed to
//! see a float: [`busbar_kernel_ledger::cost::nano_rate`] multiplies a configured `micro_per_unit`
//! by a thousand and rounds half-away-from-zero, ONCE, at card build. That conversion lives in
//! `busbar-kernel-ledger/src/cost/rate.rs` and NOWHERE ELSE, and #44 PERMITS it: it is the
//! config-parse / card-build boundary, not the runtime path. This gate exempts exactly that one file
//! and nothing wider — a float that migrates out of it into `settle.rs`, `posting.rs`, `totals.rs`
//! or a durable-record file is the runtime-path float the ban is about. The card-build path in the
//! binary (the admin correction parser, `card_from_config`) lives in files this gate does not scan,
//! for the same reason: it is the boundary, and the boundary is where a decimal is allowed.
//!
//! # THE SECOND BAN: A COUNT READ THAT QUIETLY BECOMES ZERO (#81)
//!
//! `serde_json`'s integer accessor answers "not an integer" for ANY float-spelled number, including
//! `27.0`. The house idiom paired it with a zero default, so a provider that spelled a count as a
//! float had that count recorded as ZERO — the float reaching the money path not as an `f64` in a
//! signature but as a hole in the ledger. Under #81 a count is read from decimal TEXT and a value
//! that will not fit the scale is a REFUSAL; a silent zero is never an answer.
//!
//! THE GUARD THIS REPLACES WAS BLIND TWICE, AND BOTH BLINDNESSES WERE MEASURED.
//!
//! 1. **It matched one SPELLING, not the shape.** It looked for the METHOD form `as_u64().unwrap_or(0)`
//!    and was invisible to the PATH form `and_then(Value::as_u64).unwrap_or(0)` — which is how the
//!    live sites are actually written. So this row matches by SHAPE: any of the JSON number
//!    accessors ([`NUMBER_ACCESSORS`]), reached as a method, as a path, through a turbofish or
//!    through an aliased import, followed by a default that is a zero
//!    (`unwrap_or(0)`, `unwrap_or_default()`, `unwrap_or_else(|| 0)`, and the suffixed literals).
//! 2. **It scanned one CRATE.** It lived inside the crate it guarded, so the "seventh dialect" it
//!    existed to prevent — a whole other codec crate — was unreachable from it by construction. So
//!    this row's scan set is [`COUNT_READ_ROOTS`], every money AREA enumerated with every directory
//!    it can live in and one floor over their union, rather than a wildcard a crate rename could
//!    drop out of silently. The group, not the single path, is what lets the 57 → 35 crate fold move
//!    a codec into its plane crate without the ban going quiet — and what makes a move OUT of every
//!    known home a red that names the area.
//!
//! The surviving sites are named, one by one, in [`ALLOWED_COUNT_READS`] with the reason each is
//! there. Two classes: [`AllowClass::NotACount`] (a frame index, an audio timing, a media sample
//! rate, the #44 config boundary — permanent) and [`AllowClass::PendingConversion`] (a real count
//! still owed a fix). The gate's job is that the list never GROWS: a defaulted count read that is
//! not on it is a finding.
//!
//! THE LIST IS SHRINKING, WHICH IS THE POINT. The eight billed reads in the LLM codec's own
//! handlers were fixed to REFUSE rather than default (#81/#42) and their allowances are gone. What
//! remains on the pending side is the SECOND copy of the same seam, in the other codec crate — one
//! ruling implemented twice, which is resolved to one implementation and not to a shim, and which
//! is not touched here because that crate is inside a live crate fold.
//!
//! # THE THIRD BAN: A PERSISTED COUNT WITHOUT ITS SCALE (#81a)
//!
//! A count is written down as its MANTISSA, which is meaningless without the scale beside it. #81a
//! fixes the form: one `#[serde(default)]` scale field per record, ABSENT meaning the v1.5.5 whole
//! units and PRESENT meaning scale 6, with the branch at the read and NO rescale of stored bytes. So
//! a record struct that holds a `Count` and no scale discriminator is a row nobody can read back,
//! and this row refuses it. It is armed and currently vacuous — no persisted record holds a `Count`
//! yet — which is the point: it arms the instant the conversion wave lands.
//!
//! Four rows:
//!
//! * `no-float-money:scan-floor` — every scan set is the set it claims to be. Each enumerated money
//!   area clears its floor across its homes and every named file is present (a rename must move the
//!   scope in a reviewed diff, never silently drop a file out of the ban).
//! * `no-float-money:no-float` — the finding: an `f32`/`f64` token in money production source outside
//!   the one exempt boundary.
//! * `no-float-money:count-read-shape` — the finding: a JSON-number count read that defaults to zero
//!   instead of refusing, in any spelling, anywhere on the money path.
//! * `no-float-money:count-scale-discriminator` — the finding: a persisted record that holds a
//!   `Count` without the scale field that says what its mantissa means.

use crate::ctx::{Ctx, Edit, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Case, Gate, Report};
use crate::ledger::{Row, Status, Verdict};
use crate::scan;

pub const ROW_SCAN_FLOOR: &str = "no-float-money:scan-floor";
pub const ROW_NO_FLOAT: &str = "no-float-money:no-float";
pub const ROW_COUNT_READ: &str = "no-float-money:count-read-shape";
pub const ROW_COUNT_SCALE: &str = "no-float-money:count-scale-discriminator";

/// The consolidated one-book money crate (W3.a). Its whole job is integer money arithmetic.
const LEDGER_SRC: &str = "crates/busbar-kernel-ledger/src";

/// THE ONE EXEMPT BOUNDARY (#44). The only file in the money path allowed a float, because it is the
/// config-decimal-to-integer conversion and it happens once, at card build. Matched as a substring
/// of the `/`-prefixed relative path, so it is this file and not a directory.
const CARD_BUILD_BOUNDARY: &str = "busbar-kernel-ledger/src/cost/rate.rs";

/// The `*_tests.rs` sibling, the `tests.rs` module and the `/tests/` tree are fixtures: a float in a
/// test is a test's number, not the money path's, and a wire value a fixture spells any way it likes
/// is the fixture's business.
const EXCLUDE_TESTS_DIR: &str = "/tests/";
const EXCLUDE_TESTS_FILE: &str = "_tests.rs";
const EXCLUDE_TESTS_MOD: &str = "/tests.rs";

/// The denominator floor for the ledger scan. Twenty-three production files (excluding the exempt
/// boundary) when this was written; the floor tracks the real tree rather than `> 0`, because one
/// surviving file is as vacuous as none.
const SCAN_FLOOR: usize = 18;

/// The binary's DEDICATED money-unit files: the durable ledger, the reconciliation identity, the
/// money-book seam and the money migration. Whole files whose every line is money path, so scanning
/// them entire cannot flag a routing weight or a health score — those live in the plane files, which
/// this gate does not scan. The card-build boundary in the binary is NOT here, on purpose (see the
/// module header).
const BINARY_MONEY_FILES: &[&str] = &[
    "crates/busbar/src/root/durability.rs",
    "crates/busbar/src/root/ledger_identity.rs",
    "crates/busbar/src/root/money_book.rs",
    "crates/busbar/src/root/migration.rs",
];

/// The directory the binary money files live under — walked once, then filtered to the named set.
const BINARY_ROOT: &str = "crates/busbar/src/root";

/// The contract's EXACT COUNT module (#81): the type every count is measured in, and its parser.
/// Named rather than walked, because the rest of the contract is not the money path and a wholesale
/// scan of it would flag a transport window or a backoff curve.
const CONTRACT_MONEY_FILES: &[&str] = &[
    "crates/busbar-contract/src/count.rs",
    "crates/busbar-contract/src/tests/count_tests.rs",
];

/// The directory the contract money files live under.
const CONTRACT_ROOT: &str = "crates/busbar-contract/src";

/// THE BUDGET CRATE, scanned whole like the ledger, because it is a dedicated money crate and not a
/// crate that happens to contain some money.
///
/// A budget decision is money arithmetic with a different verb: a hold, an estimate, a cell's
/// counters, a rolling window and a pricer that turns those counters into cents. Every production
/// file under it is on the money path, so the ban applies to the CRATE rather than to a hand-picked
/// file list — a new file added beside `decide.rs` is in the ban the moment it exists, which a named
/// list could never promise.
///
/// THIS ROOT WAS IN NO SCAN SET AT ALL. The ban's sets were the ledger crate and six named files,
/// and `busbar-kernel-budget` was in neither — so no float added anywhere in the crate that decides
/// whether a request is affordable could produce a RED, at any time, for any amount of float. That
/// is not a narrower check than intended; it is not a check.
const BUDGET_SRC: &str = "crates/busbar-kernel-budget/src";

/// The denominator floor for the budget scan. Seven production files when this was written; the
/// floor sits under that so ordinary churn does not trip it and an emptied or relocated crate does.
const BUDGET_FLOOR: usize = 5;

/// The KERNEL's DEDICATED money-unit files.
///
/// Named rather than walked, for the same reason the contract crate is on a named list:
/// `busbar-kernel` is not a money crate, it is the whole kernel — 350-odd files carrying routing
/// weights, health scores, scrape histograms and backoff curves, every one of them a legitimate
/// float. A wholesale scan of it would drown the ban in noise and be waived inside a week. These two
/// files ARE money, end to end:
///
/// * `cost.rs` — the rate projection and the unit-map arithmetic over it. It owns `RateNanos`, the
///   integer nano-rate every hot-path multiply-add runs on, and the conversion that produces it.
/// * `billing.rs` — the billable-item model, the shape a response's metered quantities arrive in.
///
/// NEITHER WAS IN ANY SCAN SET EITHER, and `cost.rs` is where a float is most consequential: it
/// holds a SECOND copy of the card-build conversion. #44 exempts that conversion in exactly one file
/// ([`CARD_BUILD_BOUNDARY`]) precisely so there is one place for the rounding and clamping rules to
/// live; a copy of them somewhere the ban cannot see is how the two drift, and a rate that is judged
/// at one value and billed at another is the failure the whole integer-money model exists to make
/// impossible. The exemption is a FILE, not an arithmetic, so a second copy of it is a finding here.
const KERNEL_MONEY_FILES: &[&str] = &[
    "crates/busbar-kernel/src/billing.rs",
    "crates/busbar-kernel/src/cost.rs",
];

/// The float tokens a money path may not name. Word-boundary matched so `nf64` or an identifier that
/// merely contains the text is not a hit, but the bare type is.
pub const FLOAT_TOKENS: &[&str] = &["f64", "f32"];

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The count-read scan set, the shape it hunts, and the sites it knows about
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// One money AREA scanned for defaulted count reads: every directory it can live in, and the floor
/// its files must clear between them.
///
/// A GROUP rather than one path, because the crate roster is mid-fold (57 → 35) and a codec crate
/// merging into its plane crate must not read as the ban being dropped. The floor is over the UNION,
/// so a fold that moves files between two homes in the same group changes nothing, and a fold that
/// moves them OUT of every home this list knows about is a RED that names the group — which is the
/// correct outcome: a money crate that moves must move the ban with it, in the diff that moves it.
pub struct CountRoot {
    /// What this area is, for the row that names it.
    pub area: &'static str,
    /// Every repo-relative directory the area's files can live in.
    pub homes: &'static [&'static str],
    /// How few production files the homes may hold BETWEEN THEM before the scan is not the scan it
    /// claims to be.
    pub floor: usize,
}

/// EVERY MONEY-PATH ROOT, ENUMERATED. A wildcard would let a crate rename drop a whole codec out of
/// the ban in silence, which is precisely how the guard this replaces came to be unable to see the
/// second codec crate at all. Each floor is set below the tree's real count so ordinary churn does
/// not trip it and an emptied or relocated root does.
pub const COUNT_READ_ROOTS: &[CountRoot] = &[
    CountRoot {
        area: "the LLM codecs, engine and plane",
        homes: &[
            "crates/busbar-llm-codec/src",
            "crates/busbar-llm/src",
            "crates/busbar-plane-llm/src",
        ],
        floor: 70,
    },
    CountRoot {
        area: "the audio codecs, engine and plane",
        homes: &[
            "crates/busbar-voice-codec/src",
            "crates/busbar-voice/src",
            "crates/busbar-plane-streaming/src",
        ],
        floor: 28,
    },
    // THE ONE FOLD THIS GROUP WAS BUILT FOR ACTUALLY HAPPENED, AND THE GROUP DID NOT MOVE WITH IT.
    // `crates/busbar-mcp-codec/src` was this group's first home and the crate dissolved at
    // `5fbd891e0` ("fold(#39): busbar-mcp-codec dissolves — the dialect to the plane, the registry
    // row to the engine"). Its twelve files went to exactly three places, named in that commit's own
    // body: the WIRE DIALECT to `crates/busbar-plane-mcp` (already a home here), the REGISTRY ROW
    // and the two cells to `crates/busbar-mcp/src/codec/`, and the DURABLE ROWS — `McpCallRecord`,
    // `McpDemotionRow` and their store helpers — to `crates/busbar-mcp/src/record.rs`. The last two
    // were in no money scan set at all, so for the life of this branch a count read defaulted to
    // zero in the MCP call record could not have produced a RED for any reason.
    //
    // The group's own doc says a fold "that moves them OUT of every home this list knows about is a
    // RED that names the area" — and it was, correctly: 11 files against a floor of 12. The repair
    // the red asked for is this one, and it is the two destinations the fold commit names, not a
    // lowered floor.
    CountRoot {
        area: "the tool codec, its records and the plane",
        homes: &[
            "crates/busbar-mcp/src/codec",
            "crates/busbar-mcp/src/record.rs",
            "crates/busbar-plane-mcp/src",
        ],
        floor: 12,
    },
    CountRoot {
        area: "the agent codec, node and plane",
        homes: &[
            "crates/busbar-a2a/src/a2a",
            "crates/busbar-a2a/src",
            "crates/busbar-plane-a2a/src",
        ],
        floor: 40,
    },
    CountRoot {
        area: "the kernel",
        homes: &["crates/busbar-kernel/src"],
        floor: 150,
    },
    CountRoot {
        area: "the money book and the budget",
        homes: &[
            "crates/busbar-kernel-ledger/src",
            "crates/busbar-kernel-budget/src",
        ],
        floor: 24,
    },
    CountRoot {
        area: "the contract",
        homes: &["crates/busbar-contract/src"],
        floor: 33,
    },
    CountRoot {
        area: "the neutral carriers",
        homes: &[
            "crates/busbar-substrate-values/src",
            "crates/busbar-plugin/src",
        ],
        floor: 27,
    },
    CountRoot {
        area: "the loader and the store seam",
        homes: &["crates/plugin-loader/src", "crates/api/src"],
        floor: 18,
    },
    CountRoot {
        area: "the composition root",
        homes: &["crates/busbar/src/root"],
        floor: 17,
    },
];

/// THE SEAM BEING REPLACED. Its own body is a list of the needle strings it hunts, so scanning it
/// finds its own patterns rather than a defect. It is excluded for the same reason its in-crate
/// ancestor excluded itself, and it goes away with the conversion wave.
const SUPERSEDED_SEAM: &str = "crates/busbar-llm-codec/src/usage_count.rs";

/// The JSON-number accessors a count could be read through. `as_f64` is here as well as the integer
/// pair because a count that arrives through a double has already lost the exactness #81 requires.
pub const NUMBER_ACCESSORS: &[&str] = &["as_u64", "as_i64", "as_f64", "as_u128", "as_i128"];

/// A default's argument, whitespace removed, that silently substitutes NOTHING for a count. A
/// NON-zero default (`unwrap_or(idx as u64)`) is deliberately out of scope: it substitutes a value
/// the author chose and named, which is a different act from recording that no work happened.
const ZERO_DEFAULT_ARGS: &[&str] = &[
    "",
    "0",
    "0.0",
    "0u8",
    "0u32",
    "0u64",
    "0u128",
    "0i32",
    "0i64",
    "0i128",
    "0f32",
    "0f64",
    "0usize",
    "0_u32",
    "0_u64",
    "0_i64",
    "0_usize",
    "Default::default()",
    "||0",
    "||0.0",
    "||0u64",
    "||0i64",
    "||Default::default()",
];

/// Why a surviving defaulted read is on the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowClass {
    /// Not a count at all, and never will be. Permanent.
    NotACount,
    /// A real count that the #81 conversion wave owes. Temporary, and the gate says how many are
    /// left on every run so the number is never quietly forgotten.
    PendingConversion,
}

/// One named, reasoned survivor.
pub struct Allow {
    /// The repo-relative file it lives in.
    pub file: &'static str,
    /// Text that appears in the expression, within [`ALLOW_WINDOW`] bytes before the match's end.
    /// A needle rather than a line number, so a reformat or an edit elsewhere in the file does not
    /// turn a reasoned allowance into a spurious red.
    pub needle: &'static str,
    /// Permanent, or owed to the conversion wave.
    pub class: AllowClass,
    /// Why.
    pub why: &'static str,
}

/// How far back from a match the allowance needle is looked for.
const ALLOW_WINDOW: usize = 200;

/// THE SURVIVING SITES, EVERY ONE NAMED AND REASONED. Measured 2026-09-22 against this tree.
///
/// This list may SHRINK freely and must never grow without a reviewed diff that says why. A
/// [`AllowClass::PendingConversion`] entry whose site is gone is retired debt, reported in the
/// passing row's detail rather than failed, because the agents converting these sites are live in
/// the tree right now and a gate that reds the moment they succeed is a gate that punishes the fix.
pub const ALLOWED_COUNT_READS: &[Allow] = &[
    // ── Not a count, permanently ──────────────────────────────────────────────────────────────
    Allow {
        file: "crates/busbar-llm-codec/src/bedrock/mod.rs",
        needle: "contentBlockIndex",
        class: AllowClass::NotACount,
        why: "a frame's position in a sequence, not a quantity anybody is billed for",
    },
    Allow {
        file: "crates/busbar-llm-codec/src/cohere/mod.rs",
        needle: "clamp_frame_index",
        class: AllowClass::NotACount,
        why: "a frame's position in a sequence, not a quantity anybody is billed for",
    },
    Allow {
        file: "crates/busbar-llm-codec/src/openai_chat/handler.rs",
        needle: "audio::Segment",
        class: AllowClass::NotACount,
        why: "a transcription segment's own id — metadata echoed back, never metered",
    },
    Allow {
        file: "crates/busbar-llm-codec/src/openai_chat/handler.rs",
        needle: "get(\"start\")",
        class: AllowClass::NotACount,
        why: "a transcription timing offset — metadata echoed back, never metered",
    },
    Allow {
        file: "crates/busbar-llm-codec/src/openai_chat/handler.rs",
        needle: "get(\"end\")",
        class: AllowClass::NotACount,
        why: "a transcription timing offset — metadata echoed back, never metered",
    },
    Allow {
        file: "crates/busbar-voice-codec/src/topology/twilio.rs",
        needle: "get(\"sampleRate\")",
        class: AllowClass::NotACount,
        why: "a media format's sample rate, not a metered quantity",
    },
    Allow {
        file: "crates/busbar-voice-codec/src/topology/twilio.rs",
        needle: "get(\"channels\")",
        class: AllowClass::NotACount,
        why: "a media format's channel count, not a metered quantity",
    },
    Allow {
        file: "crates/busbar-plane-streaming/src/twilio.rs",
        needle: "get(\"sampleRate\")",
        class: AllowClass::NotACount,
        why: "a media format's sample rate, not a metered quantity",
    },
    Allow {
        file: "crates/busbar-plane-streaming/src/twilio.rs",
        needle: "get(\"channels\")",
        class: AllowClass::NotACount,
        why: "a media format's channel count, not a metered quantity",
    },
    Allow {
        file: "crates/busbar-kernel/src/config/migrate.rs",
        needle: "price_per_1k_tokens_cents",
        class: AllowClass::NotACount,
        why:
            "the #44 config boundary: a configured decimal read once at parse, not a runtime count",
    },
    // ── A real count, owed to the #81 conversion wave ─────────────────────────────────────────
    Allow {
        file: "crates/busbar-voice-codec/src/ir/codec/mod.rs",
        needle: "fn u64_at",
        class: AllowClass::PendingConversion,
        why: "the crate's own count helper — every billed read in it defaults to zero",
    },
    Allow {
        file: "crates/busbar-voice-codec/src/ir/codec/mod.rs",
        needle: "let field =",
        class: AllowClass::PendingConversion,
        why: "the crate's own count helper — every billed read in it defaults to zero",
    },
    Allow {
        file: "crates/busbar-voice-codec/src/ir/codec/mod.rs",
        needle: "let stated =",
        class: AllowClass::PendingConversion,
        why: "the crate's own count helper — every billed read in it defaults to zero",
    },
    Allow {
        file: "crates/busbar-voice-codec/src/ir/codec/gemini/mod.rs",
        needle: "let stated_total =",
        class: AllowClass::PendingConversion,
        why: "the crate's own count helper — every billed read in it defaults to zero",
    },
    Allow {
        file: "crates/busbar-voice-codec/src/ir/codec/gemini/mod.rs",
        needle: "get(\"cachedContentTokenCount\")",
        class: AllowClass::PendingConversion,
        why: "a billed count that reads zero when the provider spells it as a float",
    },
];

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The persisted-record scan set (#81a)
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// Where a persisted money record can live. A struct in one of these that holds a `Count` without a
/// scale discriminator is a row nobody can read back.
///
/// EVERY HOME IS NAMED, AND ONLY AN EMPTY SET IS A FAILURE. The record shapes have already moved
/// twice — out of `busbar-api`, into the ledger, and out again into the contract under #83/#84 — so
/// pinning one path would red the gate for a relocation and pinning none would let the ban follow
/// the file out of the tree. The rule is: scan every home that is there, and refuse only when none
/// of them is.
///
/// AND THAT TOLERANCE IS WHY THE SECOND MOVE LEFT A DEAD ENTRY BEHIND FOR FREE. `cx.read` on a home
/// that is not there is a `continue`, so `crates/busbar-kernel-ledger/src/records.rs` sat in this
/// list naming nothing and cost the row no verdict at all. The move is on the record, not inferred:
///
/// ```text
/// $ git log --diff-filter=R --name-status -- crates/busbar-kernel-ledger/src/records.rs
/// 1059d3c36  R100  crates/busbar-kernel-ledger/src/records.rs -> crates/busbar-contract/src/records.rs
/// ```
///
/// `R100` — a byte-identical rename, into the home that is already first on this list. So the entry
/// is struck rather than repointed: its destination is enumerated, and the ledger crate is not a
/// persisted-record home any more by a second measure as well — it derives `Serialize` on nothing
/// (`grep -rn 'derive(.*Serialize' crates/busbar-kernel-ledger/src` is empty against a control of 19
/// hits in the contract's `records.rs`). Nothing this list used to see is unseen now.
const PERSISTED_RECORD_HOMES: &[&str] = &[
    "crates/busbar-contract/src/records.rs",
    "crates/api/src/usage_migration.rs",
    "crates/plugin-loader/src/legacy_usage.rs",
];

/// What a record must name beside a `Count` for the mantissa to mean anything. Any of them: the
/// constant, the serde default function, or a field whose name is the discriminator itself.
const SCALE_DISCRIMINATORS: &[&str] = &[
    "scale",
    "SCALE_MICRO_UNITS",
    "SCALE_WHOLE_UNITS",
    "stored_scale_default",
];

pub struct NoFloatMoneyGate;

/// The one line a float finding is written as. Built by `run` from its own scan; a stable shape so
/// the row detail reads the same way for every offender.
fn finding(rel: &str, line: usize, token: &str) -> String {
    format!("{rel}:{line}: `{token}` on the money path (exact arithmetic only, #77.8) outside the #44 card-build boundary")
}

/// Is `needle` present in `hay` at an identifier boundary? The characters either side must not be
/// alphanumeric or `_`, so `f64` matches `x: f64` and `as f64` but not `nf64` or `f640`.
fn word_hit(hay: &str, needle: &str) -> bool {
    word_positions(hay, needle).next().is_some()
}

/// Every identifier-boundary position of `needle` in `hay`.
fn word_positions<'a>(hay: &'a str, needle: &'a str) -> impl Iterator<Item = usize> + 'a {
    let bytes = hay.as_bytes();
    let n = needle.as_bytes();
    let wordy = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    (0..bytes.len()).filter(move |&i| {
        if n.is_empty() || i + n.len() > bytes.len() || &bytes[i..i + n.len()] != n {
            return false;
        }
        let before_ok = i == 0 || !wordy(bytes[i - 1]);
        let after_ok = i + n.len() == bytes.len() || !wordy(bytes[i + n.len()]);
        before_ok && after_ok
    })
}

/// A PASSING row's detail carries no run-specific count: the denominator is guarded by the floor,
/// which is a reviewable `const`, not by a number printed into a row where a drift reads as a finding.
const CLEAN: &str = "the scan cleared its floor and named no float on the money path";

/// The finding row, built from an offender list — the one constructor `run` calls, so the detail is
/// only ever about which offenders were found.
fn row_no_float(offenders: &[String], scan_problems: &[String]) -> Row {
    // A SCAN SET THAT DID NOT FULLY RESOLVE CANNOT REPORT A CLEAN TREE. An unread root contributes
    // zero offenders, and zero is the passing answer to every ban — so the absence is the finding.
    if !scan_problems.is_empty() {
        return Row::fail(
            ROW_NO_FLOAT,
            "the money-float scan set did not fully resolve, so its silence means nothing",
            format!(
                "{} unread scope(s), plus {} finding(s) from the scopes that did read: {}",
                scan_problems.len(),
                offenders.len(),
                scan_problems
                    .iter()
                    .chain(offenders.iter())
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" | ")
            ),
        );
    }
    if offenders.is_empty() {
        return Row::pass(
            ROW_NO_FLOAT,
            "no floating point on the money runtime path",
            CLEAN,
        );
    }
    Row::fail(
        ROW_NO_FLOAT,
        "floating point reaches the money runtime path (integer-only, #77.8)",
        format!("{} finding(s): {}", offenders.len(), offenders.join(" | ")),
    )
}

/// Scan one file's comment-stripped lines for the banned float tokens, appending findings.
fn scan_file(rel: &str, text: &str, offenders: &mut Vec<String>) {
    let mut in_block = false;
    for (i, raw) in text.lines().enumerate() {
        // Comments stripped, string literals intact — a float in prose about the ban is exempt, a
        // float in code is not.
        let code = scan::strip_comment_line(raw, &mut in_block);
        for token in FLOAT_TOKENS {
            if word_hit(&code, token) {
                offenders.push(finding(rel, i + 1, token));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The count-read shape
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// A file's production code with comments stripped and every line joined, plus the source line each
/// byte came from.
///
/// The join is what makes the scan blind to FORMATTING: a chain rustfmt broke across six lines and
/// the same chain on one line are the same text here, so a defect cannot hide behind a line break.
/// String literals are kept, because the wire key a read names is the evidence that says which
/// quantity it is reading.
struct Flat {
    text: String,
    line_of: Vec<usize>,
}

fn flatten(src: &str) -> Flat {
    let mut text = String::new();
    let mut line_of: Vec<usize> = Vec::new();
    let mut in_block = false;
    for (i, raw) in src.lines().enumerate() {
        let code = scan::strip_comment_line(raw, &mut in_block);
        let trimmed = code.trim();
        if trimmed.is_empty() {
            continue;
        }
        if !text.is_empty() {
            text.push(' ');
            line_of.push(i + 1);
        }
        let before = text.len();
        text.push_str(trimmed);
        line_of.resize(line_of.len() + (text.len() - before), i + 1);
    }
    Flat { text, line_of }
}

/// One defaulted count read, as found.
struct CountHit {
    line: usize,
    accessor: &'static str,
    /// The text leading up to the read, which is what an allowance needle is matched against.
    window: String,
}

/// Step past whitespace, the accessor's own parens, a closing paren that ends an `and_then(…)`, and
/// a turbofish — everything that can sit between the accessor's name and the `.` that follows it.
fn skip_to_dot(bytes: &[u8], text: &str, mut i: usize) -> Option<usize> {
    let mut budget = 64usize;
    while i < bytes.len() && budget > 0 {
        budget -= 1;
        match bytes[i] {
            b' ' | b')' => i += 1,
            // The accessor's own call, whatever it was handed: `as_u64()` reached as a method and
            // `Json::as_u64(v)` reached as a path are the same read, and the path form is precisely
            // the spelling the guard this replaces could not see.
            b'(' => i = balanced(bytes, i, b'(', b')')?,
            b':' if text[i..].starts_with("::<") => {
                i = text[i..].find('>')? + i + 1;
            }
            _ => break,
        }
    }
    (i < bytes.len() && bytes[i] == b'.').then_some(i + 1)
}

/// The index just past the group that opens at `i`, or `None` if it never closes.
fn balanced(bytes: &[u8], i: usize, open: u8, close: u8) -> Option<usize> {
    let mut depth = 0usize;
    let mut j = i;
    while j < bytes.len() {
        if bytes[j] == open {
            depth += 1;
        } else if bytes[j] == close {
            depth -= 1;
            if depth == 0 {
                return Some(j + 1);
            }
        }
        j += 1;
    }
    None
}

/// Read the identifier at `i`, returning it and the index past it.
fn read_ident(bytes: &[u8], text: &str, mut i: usize) -> (String, usize) {
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    let start = i;
    while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
        i += 1;
    }
    (text[start..i].to_string(), i)
}

/// Read the parenthesised argument at `i` with whitespace removed, and the index of its closing
/// paren. `None` when there is no balanced argument list there.
fn read_args(bytes: &[u8], text: &str, mut i: usize) -> Option<(String, usize)> {
    while i < bytes.len() && bytes[i] == b' ' {
        i += 1;
    }
    if i >= bytes.len() || bytes[i] != b'(' {
        return None;
    }
    let start = i + 1;
    let end = balanced(bytes, i, b'(', b')')?;
    let arg: String = text[start..end - 1]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    Some((arg, end))
}

/// Does a silent zero default follow the accessor that ends at `i`? Returns the index past it.
fn zero_default_after(flat: &Flat, i: usize) -> Option<usize> {
    let bytes = flat.text.as_bytes();
    let dot = skip_to_dot(bytes, &flat.text, i)?;
    let (name, after) = read_ident(bytes, &flat.text, dot);
    match name.as_str() {
        "unwrap_or_default" | "unwrap_or" | "unwrap_or_else" => {
            let (arg, end) = read_args(bytes, &flat.text, after)?;
            ZERO_DEFAULT_ARGS.contains(&arg.as_str()).then_some(end)
        }
        _ => None,
    }
}

/// Every defaulted JSON-number read in one file, by shape.
fn scan_count_reads(text: &str) -> Vec<CountHit> {
    let flat = flatten(text);
    let mut hits = Vec::new();
    for &accessor in NUMBER_ACCESSORS {
        for start in word_positions(&flat.text, accessor) {
            let Some(end) = zero_default_after(&flat, start + accessor.len()) else {
                continue;
            };
            let mut back = start.saturating_sub(ALLOW_WINDOW);
            while back > 0 && !flat.text.is_char_boundary(back) {
                back -= 1;
            }
            hits.push(CountHit {
                line: flat.line_of.get(start).copied().unwrap_or(0),
                accessor,
                window: flat.text[back..end.min(flat.text.len())].to_string(),
            });
        }
    }
    hits.sort_by_key(|h| h.line);
    hits
}

/// The rows the count-read scan produces, and the allowances it actually used.
struct CountReadScan {
    offenders: Vec<String>,
    used: std::collections::BTreeSet<usize>,
    pending: usize,
}

fn row_count_read(scan: &CountReadScan) -> Row {
    if !scan.offenders.is_empty() {
        return Row::fail(
            ROW_COUNT_READ,
            "a count is read with a silent zero default instead of a refusal (#81)",
            format!(
                "{} finding(s): {} — read the number's decimal TEXT through \
                 `busbar_contract::count` and let a value that does not fit REFUSE; a defaulted \
                 read records zero for work that really happened",
                scan.offenders.len(),
                scan.offenders.join(" | ")
            ),
        );
    }
    let retired: Vec<&str> = ALLOWED_COUNT_READS
        .iter()
        .enumerate()
        .filter(|(i, _)| !scan.used.contains(i))
        .map(|(_, a)| a.needle)
        .collect();
    let mut detail = format!(
        "every defaulted number read on the money path is a named, reasoned allowance; {} still \
         owed to the #81 conversion wave",
        scan.pending
    );
    if !retired.is_empty() {
        detail.push_str(&format!(
            " — {} allowance(s) now match nothing and can be deleted: {}",
            retired.len(),
            retired.join(", ")
        ));
    }
    Row::pass(
        ROW_COUNT_READ,
        "no count is read with a silent zero default",
        detail,
    )
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The persisted-count scale discriminator (#81a)
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// Every `struct … { … }` body in a file, with the line its header sits on.
fn struct_bodies(text: &str) -> Vec<(usize, String)> {
    let flat = flatten(text);
    let bytes = flat.text.as_bytes();
    let mut out = Vec::new();
    for start in word_positions(&flat.text, "struct") {
        // The body opens at the first `{` after the header, and closes at its match.
        let Some(open) = flat.text[start..].find('{').map(|d| start + d) else {
            continue;
        };
        // A `;` before the brace means this was a unit or tuple struct and the brace belongs to
        // something else entirely.
        if flat.text[start..open].contains(';') {
            continue;
        }
        let Some(close) = balanced(bytes, open, b'{', b'}') else {
            continue;
        };
        out.push((
            flat.line_of.get(start).copied().unwrap_or(0),
            flat.text[start..close].to_string(),
        ));
    }
    out
}

fn row_count_scale(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        return Row::pass(
            ROW_COUNT_SCALE,
            "every persisted count carries the scale that says what its mantissa means",
            "no persisted record holds a bare `Count`; the row arms the moment one does (#81a)"
                .to_string(),
        );
    }
    Row::fail(
        ROW_COUNT_SCALE,
        "a persisted record holds a count with no scale discriminator (#81a)",
        format!(
            "{} finding(s): {} — a mantissa without its scale is a row nobody can read back; add a \
             `#[serde(default = \"stored_scale_default\")] scale` field and branch at the read, and \
             do NOT rescale stored values",
            offenders.len(),
            offenders.join(" | ")
        ),
    )
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The gate
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// Walk one area's production files across every home it can live in, or say why it could not be.
///
/// The floor is applied to the UNION, not to each home, so a file that moved from one home in the
/// group to another is invisible here and a set that emptied out of all of them is not.
fn walk_area(cx: &Ctx, area: &CountRoot) -> Result<Vec<crate::ctx::SourceFile>, String> {
    let mut files = Vec::new();
    for home in area.homes {
        let spec = WalkSpec::new([*home]).ext("rs").exclude([
            EXCLUDE_TESTS_DIR,
            EXCLUDE_TESTS_FILE,
            EXCLUDE_TESTS_MOD,
        ]);
        // A home that is not there is a home the fold has already emptied; the floor over the union
        // is what says whether the AREA is still being scanned.
        if let Ok(found) = cx.walk(&spec) {
            files.extend(found);
        }
    }
    if files.len() < area.floor {
        return Err(format!(
            "{}: {} production file(s) across {}, below the floor of {}",
            area.area,
            files.len(),
            area.homes.join(" + "),
            area.floor
        ));
    }
    Ok(files)
}

impl Gate for NoFloatMoneyGate {
    fn name(&self) -> &'static str {
        "no-float-money"
    }

    fn owed(&self) -> Vec<String> {
        vec![
            ROW_SCAN_FLOOR.to_string(),
            ROW_NO_FLOAT.to_string(),
            ROW_COUNT_READ.to_string(),
            ROW_COUNT_SCALE.to_string(),
        ]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        // The ledger crate, minus the one exempt boundary and the fixtures, held to its floor.
        let ledger_spec = WalkSpec::new([LEDGER_SRC])
            .ext("rs")
            .exclude([EXCLUDE_TESTS_DIR, EXCLUDE_TESTS_FILE, CARD_BUILD_BOUNDARY])
            .min_files(SCAN_FLOOR);
        let ledger_files = match cx.walk(&ledger_spec) {
            Ok(f) => f,
            Err(e) => {
                // The scan could not be taken. It is NOT a clean money path; every owed row says so
                // rather than one being quietly omitted.
                return Verdict::of(vec![
                    Row::fail(
                        ROW_SCAN_FLOOR,
                        "the money scan set could not be read",
                        format!(
                            "{e} If the ledger crate legitimately moved, point the root at its new \
                             home in a reviewed diff that says so — do not lower the floor."
                        ),
                    ),
                    Row::fail(
                        ROW_NO_FLOAT,
                        "the money-float scan did not run",
                        "nothing was read, and nothing read is not a clean money path".to_string(),
                    ),
                    Row::fail(
                        ROW_COUNT_READ,
                        "the count-read scan did not run",
                        "nothing was read, and nothing read is not a clean money path".to_string(),
                    ),
                    Row::fail(
                        ROW_COUNT_SCALE,
                        "the persisted-count scan did not run",
                        "nothing was read, and nothing read is not a clean money path".to_string(),
                    ),
                ]);
            }
        };

        let mut set_problems: Vec<String> = Vec::new();

        // PROBLEMS THAT NARROW THE FLOAT SCAN SPECIFICALLY. Kept apart from `set_problems` so the
        // finding row itself can refuse to print "no floats found" over a scan set that did not
        // fully resolve — a half-taken scan reads exactly like a clean one, and it is not one.
        let mut float_scan_problems: Vec<String> = Vec::new();

        // THE BUDGET CRATE, held to its own floor, the same treatment the ledger gets. A dedicated
        // money crate that reads as empty is REFUSED, never scanned as zero hits and printed green.
        let budget_files = match cx.walk(
            &WalkSpec::new([BUDGET_SRC])
                .ext("rs")
                .exclude([EXCLUDE_TESTS_DIR, EXCLUDE_TESTS_FILE, EXCLUDE_TESTS_MOD])
                .min_files(BUDGET_FLOOR),
        ) {
            Ok(f) => f,
            Err(e) => {
                float_scan_problems.push(format!(
                    "{e} If the budget crate legitimately moved, point {BUDGET_SRC} at its new home \
                     in a reviewed diff that says so — do not lower the floor."
                ));
                Vec::new()
            }
        };

        // The binary's dedicated money files and the contract's count module: walk each root once,
        // keep the named set. Every named file must be present — a rename that dropped one out of
        // the ban is a scan-set integrity failure, not a silent narrowing.
        let mut named_files: Vec<crate::ctx::SourceFile> = Vec::new();
        for (root, wanted) in [
            (BINARY_ROOT, BINARY_MONEY_FILES),
            (CONTRACT_ROOT, CONTRACT_MONEY_FILES),
        ] {
            let found = match cx.walk(&WalkSpec::new([root]).ext("rs")) {
                Ok(f) => f,
                Err(e) => {
                    set_problems.push(format!("{root} could not be read: {e}"));
                    Vec::new()
                }
            };
            let present: std::collections::BTreeSet<String> =
                found.iter().map(|f| f.rel_str()).collect();
            for want in wanted.iter() {
                if !present.contains(*want) {
                    set_problems.push(format!(
                        "{want} is missing from the scan set — a money file that moved must move \
                         the ban with it in a reviewed diff, never drop out of it silently"
                    ));
                }
            }
            named_files.extend(
                found
                    .into_iter()
                    .filter(|f| wanted.contains(&f.rel_str().as_str())),
            );
        }

        // THE KERNEL'S NAMED MONEY FILES, read directly rather than reached through a walk of their
        // root. The root here is the whole kernel; reading 350-odd files to keep two is a scan cost
        // with no scan value. Absence is treated exactly as it is for the other named sets: a money
        // file that moved must move the ban with it in the diff that moves it, never drop out of it.
        for want in KERNEL_MONEY_FILES {
            match cx.read(*want) {
                Ok(text) => named_files.push(crate::ctx::SourceFile {
                    rel: std::path::PathBuf::from(*want),
                    abs: cx.abs(want),
                    text,
                }),
                Err(e) => float_scan_problems.push(format!(
                    "{want} is missing from the scan set ({e}) — a money file that moved must move \
                     the ban with it in a reviewed diff, never drop out of it silently"
                )),
            }
        }

        let mut offenders = Vec::new();
        for f in &ledger_files {
            scan_file(&f.rel_str(), &f.text, &mut offenders);
        }
        for f in &budget_files {
            scan_file(&f.rel_str(), &f.text, &mut offenders);
        }
        for f in &named_files {
            scan_file(&f.rel_str(), &f.text, &mut offenders);
        }
        offenders.sort();
        offenders.dedup();
        set_problems.extend(float_scan_problems.iter().cloned());

        // THE COUNT-READ SHAPE, over every enumerated money root.
        let mut count_scan = CountReadScan {
            offenders: Vec::new(),
            used: std::collections::BTreeSet::new(),
            pending: 0,
        };
        for area in COUNT_READ_ROOTS {
            let files = match walk_area(cx, area) {
                Ok(f) => f,
                Err(e) => {
                    set_problems.push(format!(
                        "{e} — if this area legitimately moved, add its new home to the group in a \
                         reviewed diff; do not lower the floor"
                    ));
                    continue;
                }
            };
            for f in &files {
                let rel = f.rel_str();
                if rel == SUPERSEDED_SEAM {
                    continue;
                }
                for hit in scan_count_reads(&f.text) {
                    let allowed = ALLOWED_COUNT_READS
                        .iter()
                        .enumerate()
                        .find(|(_, a)| a.file == rel && hit.window.contains(a.needle));
                    match allowed {
                        Some((i, a)) => {
                            count_scan.used.insert(i);
                            if a.class == AllowClass::PendingConversion {
                                count_scan.pending += 1;
                            }
                        }
                        None => count_scan.offenders.push(format!(
                            "{rel}:{}: `{}` defaulted to zero instead of refusing (#81)",
                            hit.line, hit.accessor
                        )),
                    }
                }
            }
        }
        count_scan.offenders.sort();
        count_scan.offenders.dedup();

        // THE PERSISTED-COUNT DISCRIMINATOR (#81a).
        let mut scale_offenders = Vec::new();
        let mut homes_read = 0usize;
        for rel in PERSISTED_RECORD_HOMES {
            let Ok(text) = cx.read(*rel) else {
                continue;
            };
            homes_read += 1;
            for (line, body) in struct_bodies(&text) {
                if !word_hit(&body, "Count") {
                    continue;
                }
                if SCALE_DISCRIMINATORS.iter().any(|d| word_hit(&body, d)) {
                    continue;
                }
                scale_offenders.push(format!(
                    "{rel}:{line}: a persisted struct holds a `Count` and names no scale"
                ));
            }
        }
        scale_offenders.sort();
        scale_offenders.dedup();
        if homes_read == 0 {
            set_problems.push(format!(
                "not one of the {} named persisted-record homes could be read — the record shapes \
                 moved somewhere this gate does not know about, and a ban that scans nothing is not \
                 a ban",
                PERSISTED_RECORD_HOMES.len()
            ));
        }

        let scan_floor = if set_problems.is_empty() {
            Row::pass(
                ROW_SCAN_FLOOR,
                "every money scan set is present and above its floor",
                format!(
                    "the ledger crate, the budget crate, {} named money file(s) and {} enumerated \
                     money area(s) all read",
                    BINARY_MONEY_FILES.len()
                        + CONTRACT_MONEY_FILES.len()
                        + KERNEL_MONEY_FILES.len(),
                    COUNT_READ_ROOTS.len()
                ),
            )
        } else {
            Row::fail(
                ROW_SCAN_FLOOR,
                "a money scan set is missing or below its floor",
                format!(
                    "{} problem(s): {}",
                    set_problems.len(),
                    set_problems.join(" | ")
                ),
            )
        };

        Verdict::of(vec![
            scan_floor,
            row_no_float(&offenders, &float_scan_problems),
            row_count_read(&count_scan),
            row_count_scale(&scale_offenders),
        ])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the money path names no float, defaults no count and persists no scaleless mantissa",
            &[
                ROW_SCAN_FLOOR,
                ROW_NO_FLOAT,
                ROW_COUNT_READ,
                ROW_COUNT_SCALE,
            ],
        ));

        // The token is BUILT, not written, so this gate's own source does not carry the needle it
        // hunts and cannot be reported by a sibling scanner for holding it.
        let float_ty = format!("f{}", "64");

        // A FLOAT IN THE LEDGER CRATE'S RUNTIME SOURCE IS FLAGGED.
        report.push(plant(
            cx,
            self,
            "a float in the ledger crate's runtime source is flagged",
            &[ROW_NO_FLOAT],
            &format!("{LEDGER_SRC}/planted_runtime_float.rs"),
            Edit::Create(format!(
                "pub fn drift(nanos: u128) -> u128 {{\n    let scale: {float_ty} = 1.0;\n    (nanos as {float_ty} * scale) as u128\n}}\n"
            )),
            &[&float_ty],
        ));

        // A FLOAT IN A NAMED BINARY MONEY FILE IS FLAGGED.
        report.push(plant(
            cx,
            self,
            "a float appended to a binary money-unit file is flagged",
            &[ROW_NO_FLOAT],
            BINARY_MONEY_FILES[0],
            Edit::Append(format!(
                "\npub fn planted_drift(x: {float_ty}) -> {float_ty} {{ x * 2.0 }}\n"
            )),
            &[&float_ty],
        ));

        // A FLOAT IN THE EXACT COUNT MODULE IS FLAGGED. The whole point of #81 is that the count
        // type never sees a double; the ban has to reach the file that says so.
        report.push(plant(
            cx,
            self,
            "a float appended to the exact count module is flagged",
            &[ROW_NO_FLOAT],
            CONTRACT_MONEY_FILES[0],
            Edit::Append(format!(
                "\npub fn planted_count_drift(x: {float_ty}) -> i128 {{ x as i128 }}\n"
            )),
            &[&float_ty],
        ));

        // THE #44 EXEMPTION HOLDS. A float in the card-build boundary (cost/rate.rs) is PERMITTED —
        // it is the one decimal-to-integer conversion — so the gate stays GREEN. A gate that flagged
        // its own permitted boundary would force the float off the boundary, which #44 forbids.
        let mut ov = Overlay::new();
        match Edit::Append(format!(
            "\npub fn extra_boundary_rate(m: {float_ty}) -> u64 {{ (m * 1000.0) as u64 }}\n"
        ))
        .apply(cx, CARD_BUILD_BOUNDARY_REL, &mut ov)
        {
            Ok(()) => report.push(Case {
                name: "a float in the #44 card-build boundary stays green (exempt)".to_string(),
                covers: vec![ROW_NO_FLOAT.to_string()],
                expected: crate::gates::Expect::Green,
                got: verdict_expect(self, &cx.with_overlay(ov)),
            }),
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not plant into the card-build boundary ({e})"
            )),
        }

        // A FLOAT UNDER A `/tests/` DIRECTORY IS A FIXTURE'S NUMBER, not the money path's.
        let mut ov = Overlay::new();
        ov.set(
            format!("{LEDGER_SRC}/tests/planted_fixture.rs"),
            format!("fn f() {{ let _: {float_ty} = 1.0; }}\n"),
        );
        report.push(Case {
            name: "a float under a /tests/ directory is excluded".to_string(),
            covers: vec![ROW_NO_FLOAT.to_string()],
            expected: crate::gates::Expect::Green,
            got: verdict_expect(self, &cx.with_overlay(ov)),
        });

        // A COMMENT-ONLY MENTION IS PROSE. The rule that exempts it is the rule that lets the money
        // path document the ban.
        let mut ov = Overlay::new();
        ov.set(
            format!("{LEDGER_SRC}/planted_prose.rs"),
            format!(
                "// This crate must never name an {float_ty} on the money path.\npub fn f() {{}}\n"
            ),
        );
        report.push(Case {
            name: "a comment-only mention of the vocabulary stays green".to_string(),
            covers: vec![ROW_NO_FLOAT.to_string()],
            expected: crate::gates::Expect::Green,
            got: verdict_expect(self, &cx.with_overlay(ov)),
        });

        // ── THE COUNT-READ SHAPE ──────────────────────────────────────────────────────────────
        //
        // THE PATH FORM, which is the spelling the guard this replaces could not see at all. Planted
        // in the first codec crate.
        report.push(plant(
            cx,
            self,
            "the PATH form of a defaulted count read is flagged in the first codec crate",
            &[ROW_COUNT_READ],
            "crates/busbar-llm-codec/src/planted_path_form.rs",
            Edit::Create(
                "use serde_json::Value;\npub fn planted(u: &Value) -> u64 {\n    u.get(\"planted_tokens\").and_then(Value::as_u64).unwrap_or(0)\n}\n"
                    .to_string(),
            ),
            &["planted_path_form", "as_u64"],
        ));

        // THE SECOND CODEC CRATE, which the guard this replaces could not reach by construction.
        report.push(plant(
            cx,
            self,
            "a defaulted count read is flagged in the SECOND codec crate too",
            &[ROW_COUNT_READ],
            "crates/busbar-voice-codec/src/planted_second_crate.rs",
            Edit::Create(
                "use serde_json::Value;\npub fn planted(u: &Value) -> u64 {\n    u.get(\"planted_tokens\").and_then(Value::as_u64).unwrap_or_default()\n}\n"
                    .to_string(),
            ),
            &["planted_second_crate", "as_u64"],
        ));

        // THE METHOD FORM, the turbofish, the alias, and the `as_i64`/`as_f64` siblings — every
        // spelling the one-pattern guard would have let through.
        for (what, body) in [
            ("the method form", "v.as_u64().unwrap_or(0)"),
            ("an aliased import", "Json::as_u64(v).unwrap_or(0)"),
            ("the as_i64 sibling", "v.as_i64().unwrap_or(0)"),
            ("the as_f64 sibling", "v.as_f64().unwrap_or(0.0)"),
            ("an unwrap_or_else zero", "v.as_u64().unwrap_or_else(|| 0)"),
            (
                "a line break inside the chain",
                "v\n        .as_u64()\n        .unwrap_or(0)",
            ),
        ] {
            report.push(plant(
                cx,
                self,
                &format!("{what} of a defaulted count read is flagged"),
                &[ROW_COUNT_READ],
                "crates/busbar-llm-codec/src/planted_spelling.rs",
                Edit::Create(format!(
                    "use serde_json::Value as Json;\npub fn planted(v: &Json) -> u64 {{\n    {body}\n}}\n"
                )),
                &["planted_spelling"],
            ));
        }

        // A NON-ZERO DEFAULT IS OUT OF SCOPE, on purpose: it substitutes a value the author chose
        // and named, which is a different act from recording that no work happened.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-llm-codec/src/planted_named_default.rs",
            "use serde_json::Value;\npub fn planted(v: &Value, idx: u64) -> u64 {\n    v.as_u64().unwrap_or(idx)\n}\n",
        );
        report.push(Case {
            name: "a NAMED non-zero default is not a silent zero and stays green".to_string(),
            covers: vec![ROW_COUNT_READ.to_string()],
            expected: crate::gates::Expect::Green,
            got: verdict_expect(self, &cx.with_overlay(ov)),
        });

        // A READ THAT PROPAGATES `None` IS THE CORRECT SHAPE and must stay green, or the gate would
        // be pushing authors away from the very thing it wants.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-llm-codec/src/planted_propagating.rs",
            "use serde_json::Value;\npub fn planted(v: &Value) -> Option<u64> {\n    v.get(\"tokens\").and_then(Value::as_u64)\n}\n",
        );
        report.push(Case {
            name: "a read that propagates None instead of defaulting stays green".to_string(),
            covers: vec![ROW_COUNT_READ.to_string()],
            expected: crate::gates::Expect::Green,
            got: verdict_expect(self, &cx.with_overlay(ov)),
        });

        // AN ENUMERATED COUNT-READ ROOT THAT READS AS EMPTY IS REFUSED, not scanned as zero hits.
        // This is the instrument check for blindness 2: a renamed crate must be a red, never a
        // silent narrowing of the ban.
        let root = COUNT_READ_ROOTS[0].homes[0];
        let mut ov = Overlay::new();
        match cx.walk(&WalkSpec::new([root]).ext("rs")) {
            Ok(files) => {
                for f in &files {
                    ov.remove(&f.rel);
                }
                report.push(prove_red(
                    cx,
                    self,
                    "an enumerated count-read root that reads as empty is refused",
                    &[ROW_SCAN_FLOOR],
                    ov,
                    &["floor"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: count-read root {root} is unreadable ({e})"
            )),
        }

        // ── THE PERSISTED-COUNT DISCRIMINATOR ─────────────────────────────────────────────────
        let record_home = PERSISTED_RECORD_HOMES
            .iter()
            .copied()
            .find(|p| cx.exists(p))
            .unwrap_or(PERSISTED_RECORD_HOMES[0]);
        report.push(plant(
            cx,
            self,
            "a persisted record holding a Count with no scale field is flagged",
            &[ROW_COUNT_SCALE],
            record_home,
            Edit::Append(
                "\npub struct PlantedRow {\n    pub tokens: Count,\n    pub model: String,\n}\n"
                    .to_string(),
            ),
            &["scale"],
        ));

        // AND THE SAME RECORD WITH ITS DISCRIMINATOR IS CORRECT, so the gate is a rule and not a
        // ban on the type.
        let mut ov = Overlay::new();
        match Edit::Append(
            "\npub struct PlantedRow {\n    pub tokens: Count,\n    #[serde(default = \"stored_scale_default\")]\n    pub scale: u32,\n}\n"
                .to_string(),
        )
        .apply(cx, record_home, &mut ov)
        {
            Ok(()) => report.push(Case {
                name: "a persisted record that DOES carry its scale stays green".to_string(),
                covers: vec![ROW_COUNT_SCALE.to_string()],
                expected: crate::gates::Expect::Green,
                got: verdict_expect(self, &cx.with_overlay(ov)),
            }),
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not plant into {record_home} ({e})"
            )),
        }

        // THE INSTRUMENT: the root that reads as empty. A ledger crate that moved or was renamed must
        // be REFUSED, not scanned as zero hits and printed green.
        let mut ov = Overlay::new();
        match cx.walk(&WalkSpec::new([LEDGER_SRC]).ext("rs").exclude([
            EXCLUDE_TESTS_DIR,
            EXCLUDE_TESTS_FILE,
            CARD_BUILD_BOUNDARY,
        ])) {
            Ok(files) => {
                for f in &files {
                    ov.remove(&f.rel);
                }
                report.push(prove_red(
                    cx,
                    self,
                    "a ledger scan root that reads as empty is refused, not scanned as zero hits",
                    &[ROW_SCAN_FLOOR],
                    ov,
                    &["floor"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: the base tree's ledger root is unreadable ({e}), so the \
                 empty-root plant has nothing to empty"
            )),
        }

        // A NAMED BINARY MONEY FILE THAT VANISHES IS A SCAN-SET INTEGRITY FAILURE.
        let mut ov = Overlay::new();
        ov.remove(std::path::Path::new(BINARY_MONEY_FILES[0]));
        report.push(prove_red(
            cx,
            self,
            "a named binary money file dropping out of the tree is refused",
            &[ROW_SCAN_FLOOR],
            ov,
            &["missing"],
        ));

        // AND SO IS THE EXACT COUNT MODULE VANISHING.
        let mut ov = Overlay::new();
        ov.remove(std::path::Path::new(CONTRACT_MONEY_FILES[0]));
        report.push(prove_red(
            cx,
            self,
            "the exact count module dropping out of the tree is refused",
            &[ROW_SCAN_FLOOR],
            ov,
            &["missing"],
        ));

        report
    }
}

/// The `/`-prefixed-substring boundary constant re-expressed as the actual repo-relative path an
/// `Edit` writes to (the exclude fragment omits the leading `crates/`-less prefix nuance).
const CARD_BUILD_BOUNDARY_REL: &str = "crates/busbar-kernel-ledger/src/cost/rate.rs";

fn verdict_expect(gate: &dyn Gate, cx: &Ctx) -> crate::gates::Expect {
    let verdict = crate::gates::execute(gate, cx);
    if verdict.red {
        crate::gates::Expect::Red {
            naming: verdict
                .rows
                .iter()
                .filter(|r| r.status != Status::Pass)
                .map(|r| format!("{} {} {}", r.id, r.title, r.detail))
                .chain(verdict.problems.iter().cloned())
                .collect(),
        }
    } else {
        crate::gates::Expect::Green
    }
}

fn plant<'a>(
    cx: &'a Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    path: &str,
    edit: Edit,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    let mut ov = Overlay::new();
    if edit.apply(cx, path, &mut ov).is_err() {
        return Case {
            name: name.to_string(),
            covers: covers.iter().map(|s| (*s).to_string()).collect(),
            expected: crate::gates::Expect::Red {
                naming: naming.iter().map(|s| (*s).to_string()).collect(),
            },
            got: crate::gates::Expect::Skipped,
        }
        .into();
    }
    prove_red(cx, gate, name, covers, ov, naming)
}
