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
//! # THE MONEY-INTAKE BOUNDARIES (#44) — ALL OF THEM, NAMED IN [`MONEY_INTAKE`]
//!
//! A card is BUILT from configured decimals, and the decimal-to-integer conversion is allowed to see
//! a float: config carries figures a human wrote down, the ledger stores integers, and somewhere the
//! one has to become the other. #44 PERMITS that conversion. What it permits is the CONVERSION, not
//! a float that goes on living after it — so the rule this gate encodes is: **a float may appear AT
//! an intake boundary and nowhere past it.**
//!
//! THE SURFACE IS AUDITABLE BY READING [`MONEY_INTAKE`], which is the whole point of its existing.
//! Every place money enters this system from configuration is a row in that table, with the file it
//! lives in, the FUNCTION that is the boundary, and how much of the file that boundary covers.
//! There are three today and the table says which is which:
//!
//! * `busbar-kernel-ledger/src/cost/rate.rs` :: `nano_rate` — the card-build arithmetic itself.
//!   The WHOLE FILE is the conversion (#44), which is why it is excluded from the ledger walk.
//! * `crates/busbar/src/root/kernel.rs` :: `card_from_config` — **THE SECOND INTAKE, AND IT WAS
//!   UNDECLARED AND UNSCANNED.** This is where the deployment's configured rates become the card
//!   every plane's exit prices against: the root reads config, `card_from_config` relays it into the
//!   cost unit, and `CardRepricer::rates_applied` appends the result to the history. This gate's own
//!   header used to say the file "lives in files this gate does not scan, for the same reason: it is
//!   the boundary" — but "the boundary" is one FUNCTION in a 1 300-line composition-root file, and a
//!   float anywhere else in it (in the repricer, in the epoch read, in the units registry) could not
//!   produce a RED for any amount of float. The file is scanned now, with `card_from_config`'s own
//!   body the only span in it a float may appear in.
//! * `busbar-kernel-budget/src/price.rs` :: `RateNanos::from_micros_per_token` — the door's copy of
//!   the same intake, four configured micro-unit decimals in and four `u64` nano-rates out, each
//!   through the ledger's `nano_rate`. The budget crate is scanned WHOLE, so this boundary had been
//!   reading as four standing findings on `no-float-money:no-float` — a red that named a legitimate
//!   conversion, which is the same instrument fault as a green that names nothing: the row was not
//!   falsifiable, because it was already red, and EVERY red plant in this gate's self-test was
//!   scored `PROOF IMPOSSIBLE` behind it.
//!
//! AND THE RULE THAT MAKES "AT THE BOUNDARY" MEAN SOMETHING: every boundary's declared RETURN TYPE
//! is checked, and a float in it is a finding. Decimals go in, integers come out — a boundary that
//! hands a float back has not converted anything, it has moved the float one frame up the stack,
//! which is precisely "a float that survives past the conversion".
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

/// THE LEDGER'S CARD-BUILD BOUNDARY (#44), as the ledger WALK's exclude fragment. The whole file is
/// the config-decimal-to-integer conversion, so it is not walked; it is still READ, by the intake
/// pass, because [`MONEY_INTAKE`] holds it to the return-type rule like every other boundary.
/// Matched as a substring of the `/`-prefixed relative path, so it is this file and not a directory.
const CARD_BUILD_BOUNDARY: &str = "busbar-kernel-ledger/src/cost/rate.rs";

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE MONEY-INTAKE BOUNDARIES — WHERE A CONFIGURED DECIMAL BECOMES A STORED INTEGER
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// How much of an intake's file the conversion is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntakeExtent {
    /// THE WHOLE FILE IS THE CONVERSION. Only `cost/rate.rs`: its every item is the card build —
    /// the raw tier decimals, the rounding, the clamp and the card they produce — so there is no
    /// "past the boundary" inside it to scan for. It is excluded from the ledger walk for this
    /// reason and for no other.
    WholeFileIsTheConversion,
    /// ONLY THE NAMED FUNCTION IS THE CONVERSION, and the rest of the file is money runtime path.
    /// A float inside the named body is the configured decimal being converted; a float ANYWHERE
    /// ELSE in the file is a float that survived the intake, which is the finding.
    OnlyTheBoundaryFn,
}

/// ONE PLACE MONEY ENTERS THIS SYSTEM FROM CONFIGURATION.
///
/// A boundary this table does not name is a boundary the gate cannot reason about: either it is in
/// no scan set (invisible, the `card_from_config` case) or it is scanned with no exemption at all
/// (a standing red over a legitimate conversion, the `from_micros_per_token` case). Both silence
/// the instrument, one by never saying no and one by never being able to say yes.
pub struct MoneyIntake {
    /// The repo-relative file the boundary lives in.
    pub file: &'static str,
    /// The FUNCTION that is the boundary. Named, not inferred: the exempt span is a body somebody
    /// can open and read, and a rename that moves it is a scan-set failure rather than a silent
    /// widening (a boundary that cannot be found exempts nothing and is REFUSED).
    pub boundary: &'static str,
    /// How much of `file` the conversion covers.
    pub extent: IntakeExtent,
    /// Why this is an intake at all.
    pub why: &'static str,
}

/// EVERY MONEY-INTAKE BOUNDARY IN THE TREE. Read this table and you have read the gate's exempt
/// surface; there is nowhere else a float is permitted on the money path.
pub const MONEY_INTAKE: &[MoneyIntake] = &[
    MoneyIntake {
        file: "crates/busbar-kernel-ledger/src/cost/rate.rs",
        boundary: "nano_rate",
        extent: IntakeExtent::WholeFileIsTheConversion,
        why: "#44's card build: a configured `micro_per_unit` times a thousand, rounded               half-away-from-zero, ONCE, into an integer nano-rate. The whole file is that               arithmetic and the card it produces.",
    },
    MoneyIntake {
        file: "crates/busbar/src/root/kernel.rs",
        boundary: "card_from_config",
        extent: IntakeExtent::OnlyTheBoundaryFn,
        why: "THE SECOND INTAKE: the composition root relaying the deployment's configured rates               into the cost unit's card, on boot and on every live rate apply. Its call path —               `CardRepricer::rates_applied`, which appends the built card to the history, and               `RateEpoch::effective_from_at`, which dates a price against it — is the rest of this               file, and is scanned.",
    },
    MoneyIntake {
        file: "crates/busbar-kernel-budget/src/price.rs",
        boundary: "from_micros_per_token",
        extent: IntakeExtent::OnlyTheBoundaryFn,
        why: "The admission door's intake of the same configured figures: four micro-unit decimals               in, four integer nano-rates out, each one through the ledger's `nano_rate` so the               clamp and the rounding are the card's and not a second copy of them.",
    },
];

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE MONEY-EGRESS BOUNDARIES — WHERE A STORED INTEGER IS HANDED TO A FLOAT-ONLY SINK
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// ONE PLACE A MONEY FIGURE LEAVES THIS SYSTEM THROUGH AN API THAT ONLY TAKES A FLOAT.
///
/// The mirror of [`MoneyIntake`]. The `/metrics` exposition is the case that made this table: the
/// `metrics` facade stores every gauge as floating-point bits (`Gauge::set<T: IntoF64>`, with no
/// `IntoF64` for a 64-bit integer) and the Prometheus exporter prints that value, so the served
/// spend figure has been a float since 1.5.x through no arithmetic of busbar's. The money stays an
/// integer right up to that sink, and the conversion is ONE named function per listed file. The
/// file is scanned whole; a float anywhere outside the named body — including a second function
/// that does the same conversion under another name — is a finding.
///
/// AND THE RULE THAT MAKES "AT THE BOUNDARY" MEAN SOMETHING, mirrored from the intake's return-type
/// rule: an egress boundary's PARAMETERS are checked, and a float in them is a finding. Integers go
/// in; a boundary that TAKES a float was handed a figure that was already a float before it got
/// there, which is a float on the money path one frame down the stack.
pub struct MoneyEgress {
    /// The repo-relative file the boundary lives in. It must also be in a scan set — an egress
    /// exemption over a file nobody scans exempts nothing and hides that nobody scans it.
    pub file: &'static str,
    /// The FUNCTION that is the boundary, found by name. Absent is REFUSED, never "exempts nothing".
    pub boundary: &'static str,
    /// Why this sink forces a float at all.
    pub why: &'static str,
}

/// EVERY MONEY-EGRESS BOUNDARY IN THE TREE, at most one per file. Read this table and [`MONEY_INTAKE`]
/// and you have read the gate's whole exempt surface.
pub const MONEY_EGRESS: &[MoneyEgress] = &[MoneyEgress {
    file: "crates/busbar-kernel/src/metrics/money.rs",
    boundary: "set_gauge",
    why: "The `/metrics` money gauges (spend, budget-remaining, token counts): an `i64`/`u64` figure \
          widened to `i128`, then handed to the `metrics` facade, whose gauge stores and the \
          Prometheus exporter prints a float. Byte-identical to 1.5.5, which cast the same integer \
          into the same gauge (item 24).",
}];

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
///
/// THE THIRD ENTRY IS THE MONEY-PATH DURABLE RECORD SHAPES, ADDED 2026-09-23. `records.rs`'s own
/// first line is "The MONEY-PATH DURABLE RECORD SHAPES — the data types a `db` plugin … reads and
/// writes"; it is the file `money-invariants:no-plugin-keyed-money` and `:no-stored-price` scan for
/// #77(1) and #77(3), and it is the FIRST home in [`PERSISTED_RECORD_HOMES`] below. It was in this
/// gate's float set through none of those. A float in a persisted money record is the failure #77(8)
/// is about, written down and read back by every store plugin. MEASURED at the time of the widening:
/// zero `f64`/`f32` in it today.
///
/// THE REST OF THE CONTRACT STAYS OFF THIS LIST, and the measurement is why rather than the prose:
/// the only production float in `crates/busbar-contract/src` outside these files is
/// `signal.rs:158`, `SignalValue::F64(f64)` — the closed scalar wire value for the hook
/// decide/tap path, a ratio and not a price. A wholesale scan of the contract would red this gate
/// on a hook signal. PARK: SHAPE D is unclosed here — a new money file beside `count.rs` is in no
/// scan set until somebody edits this list, and nothing tells them to.
const CONTRACT_MONEY_FILES: &[&str] = &[
    "crates/busbar-contract/src/count.rs",
    "crates/busbar-contract/src/tests/count_tests.rs",
    "crates/busbar-contract/src/records.rs",
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

/// ── TWO DEDICATED MONEY CRATES THAT WERE IN NO SCAN SET AT ALL (2026-09-23) ─────────────────────
///
/// The census in `docs/design/1.6.0-gate-blindspots.md` planted ten floats on the money path and
/// this gate named two. Two of the eight it missed were whole CRATES, and both of them are where
/// money stops being arithmetic and becomes a fact somebody can be billed from:
///
/// * `busbar-kernel-audit` — **the sealed facts line.** A unit's money facts are sealed and signed
///   here, so a float in it is a float in the number the seal attests to. The signature does not
///   make an inexact figure exact; it makes it permanent.
/// * `busbar-kernel-wal` — **money-record durability.** What is written down is what is read back
///   and billed. A float anywhere between the settle and the write is a rounding nobody configured,
///   made durable.
///
/// Both are scanned WHOLE, like the ledger and the budget crates and for the same reason: they are
/// dedicated money crates rather than crates that happen to contain some money, so a new file added
/// beside an existing one is in the ban the moment it exists. MEASURED at the time of the widening:
/// neither crate carries a single `f64`/`f32` in production code today, so this costs the tree no
/// new finding and buys the ban two crates it could not previously have gone red about for any
/// amount of float. The plants prove it is not vacuous.
const AUDIT_SRC: &str = "crates/busbar-kernel-audit/src";

/// The denominator floor for the audit scan. Ten production files when this was written.
const AUDIT_FLOOR: usize = 7;

const WAL_SRC: &str = "crates/busbar-kernel-wal/src";

/// The denominator floor for the WAL scan. Eight production files when this was written.
const WAL_FLOOR: usize = 6;

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
///
/// THE THIRD ENTRY, ADDED 2026-09-23: `rate_apply.rs` — the RATE-APPLY SEAM. Its own header says
/// "this seam carries a price": it is the one notification that says "this deployment's configured
/// rates are now these", raised at boot and on every live apply/reload, and answered by whoever
/// holds a card. A float introduced between the config resolution and the card swap reprices every
/// derived spend figure on the next read, which is the same failure `cost.rs` is on this list for
/// and one seam earlier. It moved into the kernel by identity from `busbar-substrate/src/rate_apply.rs`
/// (`5fa320208`, R100) and was in no money scan set on either side of the move. MEASURED: zero
/// `f64`/`f32` in it today.
///
/// THE FOURTH ENTRY, ADDED 2026-09-23 (item 24): `metrics/money.rs` — THE SERVED MONEY GAUGES.
/// `busbar_key_spend_cents`, `busbar_bucket_spend_cents` and `busbar_bucket_budget_remaining_cents`
/// are money a customer scrapes, and they were published from `metrics.rs`, a file of routing
/// weights and durations this list could not take whole (armed over it, it named fourteen floats,
/// three of them money). The money gauges were split into their own file so it could be taken whole,
/// and the one conversion the `metrics` facade forces is the declared [`MONEY_EGRESS`] boundary in it.
///
/// THE REST OF THE KERNEL STAYS OFF THIS LIST for the reason the paragraph above gives, and the
/// measurement backs it: the kernel is 350-odd files of routing weights, health scores and backoff
/// curves, all of them legitimate floats. PARK: this is SHAPE D and it is unclosed — nothing in the
/// tree tells the author of the next kernel money file to add it here.
const KERNEL_MONEY_FILES: &[&str] = &[
    "crates/busbar-kernel/src/billing.rs",
    "crates/busbar-kernel/src/cost.rs",
    "crates/busbar-kernel/src/rate_apply.rs",
    "crates/busbar-kernel/src/metrics/money.rs",
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

/// The 1-based line spans, per file, that a declared money-intake boundary covers. Empty for every
/// file that is not an intake, which is all but two of them.
type IntakeSpans = std::collections::BTreeMap<String, Vec<(usize, usize)>>;

/// Scan one file's comment-stripped lines for the banned float tokens, appending findings.
///
/// A line INSIDE a declared intake boundary's body is skipped: that is the configured decimal being
/// converted, which #44 permits. Every other line of the same file is scanned, which is the whole
/// difference between "this file is a boundary" and "this function is a boundary".
fn scan_file(rel: &str, text: &str, exempt: &IntakeSpans, offenders: &mut Vec<String>) {
    let spans = exempt.get(rel).map(Vec::as_slice).unwrap_or(&[]);
    let mut in_block = false;
    for (i, raw) in text.lines().enumerate() {
        // Comments stripped, string literals intact — a float in prose about the ban is exempt, a
        // float in code is not.
        let code = scan::strip_comment_line(raw, &mut in_block);
        let line = i + 1;
        if spans
            .iter()
            .any(|(first, last)| line >= *first && line <= *last)
        {
            continue;
        }
        for token in FLOAT_TOKENS {
            if word_hit(&code, token) {
                offenders.push(finding(rel, line, token));
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// Finding a declared intake boundary, and holding it to "integers come out"
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// A declared boundary, as found in its file.
struct Boundary {
    /// 1-based and inclusive: the `fn` line through the line the body closes on.
    first_line: usize,
    last_line: usize,
    /// The return type as declared, or `""` for a boundary that returns unit.
    returns: String,
    /// The parameter list as declared, from the first `(` to the last `)` of the header.
    params: String,
}

/// Is this line the declaration of `fn <name>`?
fn declares_fn(code: &str, name: &str) -> bool {
    word_positions(code, name).any(|i| {
        let before = code[..i].trim_end();
        let Some(head) = before.strip_suffix("fn") else {
            return false;
        };
        head.chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
    })
}

/// Find the declared boundary `fn <name>` in `text` and measure it.
///
/// Comments and the CONTENTS of every literal are blanked first, through [`scan::blank_code`] — the
/// one lexer in this crate a delimiter count may read. A brace inside a message string that
/// stretched the exempt span past the body it belongs to would silently widen the exemption, which
/// is the failure this whole gate is about, committed by its own scanner.
fn find_boundary(text: &str, name: &str) -> Option<Boundary> {
    let mut st = scan::LexState::default();
    let lines: Vec<String> = text.lines().map(|l| scan::blank_code(l, &mut st)).collect();
    let start = lines.iter().position(|code| declares_fn(code, name))?;

    // THE HEADER runs from the declaration to the `{` that opens the body, at paren depth zero.
    let mut header = String::new();
    let mut depth = 0i32;
    let mut open = None;
    'lines: for (i, code) in lines.iter().enumerate().skip(start) {
        for ch in code.chars() {
            match ch {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                '{' if depth <= 0 => {
                    open = Some(i);
                    break 'lines;
                }
                _ => {}
            }
            header.push(ch);
        }
        header.push(' ');
    }
    let open = open?;

    // THE BODY closes where its brace balance comes back to zero.
    let mut brace = 0i32;
    let mut last = None;
    for (i, code) in lines.iter().enumerate().skip(open) {
        brace += scan::delta(code, '{', '}');
        if brace <= 0 {
            last = Some(i);
            break;
        }
    }

    // THE RETURN TYPE is what follows the `->` after the parameter list, which is the LAST `)` in
    // the header — an arrow inside the parameters belongs to a closure type in an argument.
    let returns = header
        .rfind(')')
        .and_then(|close| header[close..].find("->").map(|a| close + a + 2))
        .map(|at| header[at..].trim().to_string())
        .unwrap_or_default();

    // THE PARAMETERS are the header from its first `(` to that same last `)`.
    let params = match (header.find('('), header.rfind(')')) {
        (Some(open), Some(close)) if open < close => header[open..=close].to_string(),
        _ => String::new(),
    };

    Some(Boundary {
        first_line: start + 1,
        last_line: last? + 1,
        returns,
        params,
    })
}

/// THE FINDING THAT SAYS A FLOAT SURVIVED THE CONVERSION. Decimals go in, integers come out; a
/// boundary that hands a float back has moved the float one frame up the stack rather than
/// converting it, and everything it reaches is runtime money path.
fn returns_float(intake: &MoneyIntake, b: &Boundary) -> Option<String> {
    let token = FLOAT_TOKENS.iter().find(|t| word_hit(&b.returns, t))?;
    Some(format!(
        "{}:{}: the money-intake boundary `fn {}` RETURNS `{}` (`{}`) — a conversion hands back an \
         INTEGER; a float returned from the intake is a float that survived it, and every caller of \
         it is runtime money path",
        intake.file, b.first_line, intake.boundary, b.returns, token
    ))
}

/// THE EGRESS MIRROR OF [`returns_float`]: integers go IN to an egress boundary. A boundary that
/// takes a float was handed a figure that was already a float, which is the finding one frame down.
fn takes_float(egress: &MoneyEgress, b: &Boundary) -> Option<String> {
    let token = FLOAT_TOKENS.iter().find(|t| word_hit(&b.params, t))?;
    Some(format!(
        "{}:{}: the money-egress boundary `fn {}` TAKES a float (`{}` in `{}`) — money reaches an \
         egress boundary as an INTEGER; a float handed to it is a float on the money path before it",
        egress.file, b.first_line, egress.boundary, token, b.params
    ))
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
///
/// THE UNION IS A SET OF PATHS, NOT A SUM OF WALKS (item 214). A group may name one home inside
/// another — the agent group names `crates/busbar-a2a/src/a2a` AND `crates/busbar-a2a/src` — and
/// summing one walk per home counted the 34 nested files twice: 85 against a floor of 40 where the
/// distinct count is 51. A whole home could then leave the tree and the doubled remainder still
/// cleared the floor, so the area never went red for the move its own doc says it reds for. Each
/// file is kept once, by its repo-relative path, and the floor is held against that count. The
/// same dedup keeps a nested file from being SCANNED twice, which doubled its findings.
fn walk_area(cx: &Ctx, area: &CountRoot) -> Result<Vec<crate::ctx::SourceFile>, String> {
    let mut seen: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
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
            files.extend(found.into_iter().filter(|f| seen.insert(f.rel_str())));
        }
    }
    if files.len() < area.floor {
        return Err(format!(
            "{}: {} distinct production file(s) across {}, below the floor of {}",
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

        // THE SEALED-FACTS AND DURABILITY CRATES (2026-09-23), each held to its own floor the way
        // the ledger and the budget are. Same treatment for the same reason: a dedicated money crate
        // that reads as empty is REFUSED, never scanned as zero hits and printed green.
        let mut whole_crate_files: Vec<crate::ctx::SourceFile> = Vec::new();
        for (root, floor, what) in [
            (AUDIT_SRC, AUDIT_FLOOR, "the sealed money-facts crate"),
            (WAL_SRC, WAL_FLOOR, "the money-record durability crate"),
        ] {
            match cx.walk(
                &WalkSpec::new([root])
                    .ext("rs")
                    .exclude([EXCLUDE_TESTS_DIR, EXCLUDE_TESTS_FILE, EXCLUDE_TESTS_MOD])
                    .min_files(floor),
            ) {
                Ok(f) => whole_crate_files.extend(f),
                Err(e) => float_scan_problems.push(format!(
                    "{e} {root} is {what}. If it legitimately moved, point the root at its new home \
                     in a reviewed diff that says so — do not lower the floor."
                )),
            }
        }

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

        // ── THE MONEY-INTAKE BOUNDARIES ───────────────────────────────────────────────────────
        //
        // Every row of [`MONEY_INTAKE`] is READ, whatever its extent: the boundary has to be found
        // where the table says it is, and it has to hand back an integer. A boundary that cannot be
        // found exempts NOTHING and is refused — the alternative is a table that names a function
        // somebody renamed, quietly exempting a span that is no longer there or, worse, still
        // naming a span that is now something else.
        let mut offenders = Vec::new();
        let mut intake_spans: IntakeSpans = std::collections::BTreeMap::new();
        let mut intake_texts: Vec<(&'static str, String)> = Vec::new();
        for intake in MONEY_INTAKE {
            let text = match cx.read(intake.file) {
                Ok(t) => t,
                Err(e) => {
                    float_scan_problems.push(format!(
                        "{}: the declared money-intake boundary's file could not be read ({e}) — an \
                         intake that cannot be read is an exemption nobody can audit and a money \
                         path nobody scanned",
                        intake.file
                    ));
                    continue;
                }
            };
            let Some(b) = find_boundary(&text, intake.boundary) else {
                float_scan_problems.push(format!(
                    "{}: the declared money-intake boundary `fn {}` is not in that file — the \
                     exemption names a function that is not there, so either the boundary moved \
                     (move this row with it, in the diff that moves it) or the table is stale",
                    intake.file, intake.boundary
                ));
                continue;
            };
            if let Some(escaped) = returns_float(intake, &b) {
                offenders.push(escaped);
            }
            if intake.extent == IntakeExtent::OnlyTheBoundaryFn {
                intake_spans
                    .entry(intake.file.to_string())
                    .or_default()
                    .push((b.first_line, b.last_line));
                intake_texts.push((intake.file, text));
            }
        }

        // AN INTAKE FILE THE OTHER SETS DO NOT ALREADY CARRY IS SCANNED HERE. `price.rs` arrives
        // through the budget crate's walk; `root/kernel.rs` is in no other set at all, which is the
        // hole — the second intake and its whole call path were invisible to this ban.
        let already: std::collections::BTreeSet<String> = ledger_files
            .iter()
            .chain(budget_files.iter())
            .chain(whole_crate_files.iter())
            .chain(named_files.iter())
            .map(|f| f.rel_str())
            .collect();
        for (file, text) in intake_texts {
            if !already.contains(file) {
                named_files.push(crate::ctx::SourceFile {
                    rel: std::path::PathBuf::from(file),
                    abs: cx.abs(file),
                    text,
                });
            }
        }

        // ── THE MONEY-EGRESS BOUNDARIES ───────────────────────────────────────────────────────
        //
        // Each one is FOUND by name in its file, holds to "integers go in", and exempts exactly its
        // own body. Its file must already be in a scan set: the exemption is a span inside a scanned
        // file, never a way to name a file nobody reads. One boundary per file — a second row for the
        // same file would be a second exempt conversion, which is what the table exists to refuse.
        let mut egress_seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
        for egress in MONEY_EGRESS {
            if !egress_seen.insert(egress.file) {
                float_scan_problems.push(format!(
                    "{}: declares a SECOND money-egress boundary (`fn {}`) — one conversion per \
                     file, and a second is a float outside the first",
                    egress.file, egress.boundary
                ));
                continue;
            }
            let Some(src) = named_files
                .iter()
                .chain(ledger_files.iter())
                .chain(budget_files.iter())
                .chain(whole_crate_files.iter())
                .find(|f| f.rel_str() == egress.file)
            else {
                float_scan_problems.push(format!(
                    "{}: a declared money-egress boundary in a file no money scan set reads (or a \
                     file that is not there) — add the file to a scan set, or move the row with \
                     the file",
                    egress.file
                ));
                continue;
            };
            let Some(b) = find_boundary(&src.text, egress.boundary) else {
                float_scan_problems.push(format!(
                    "{}: the declared money-egress boundary `fn {}` is not in that file — the \
                     exemption names a function that is not there, so either the boundary moved \
                     (move this row with it, in the diff that moves it) or the table is stale",
                    egress.file, egress.boundary
                ));
                continue;
            };
            if let Some(escaped) = takes_float(egress, &b) {
                offenders.push(escaped);
            }
            intake_spans
                .entry(egress.file.to_string())
                .or_default()
                .push((b.first_line, b.last_line));
        }

        for f in &ledger_files {
            scan_file(&f.rel_str(), &f.text, &intake_spans, &mut offenders);
        }
        for f in &budget_files {
            scan_file(&f.rel_str(), &f.text, &intake_spans, &mut offenders);
        }
        for f in &whole_crate_files {
            scan_file(&f.rel_str(), &f.text, &intake_spans, &mut offenders);
        }
        for f in &named_files {
            scan_file(&f.rel_str(), &f.text, &intake_spans, &mut offenders);
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
                    "the ledger, budget, sealed-facts and durability crates, {} named money file(s), \
                     {} enumerated money area(s) and {} declared money-intake boundary(ies) all read",
                    BINARY_MONEY_FILES.len()
                        + CONTRACT_MONEY_FILES.len()
                        + KERNEL_MONEY_FILES.len(),
                    COUNT_READ_ROOTS.len(),
                    MONEY_INTAKE.len()
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

        // ── THE SECOND MONEY-INTAKE BOUNDARY (`card_from_config`) ─────────────────────────────
        //
        // Four cases, because "the boundary is in the scan set" is four claims and only one of them
        // is "a float here goes red": the file is scanned, the boundary's own body is not, the
        // boundary has to still be where the table says, and what comes out of it has to be an
        // integer.
        let second = &MONEY_INTAKE[1];

        // 1. A FLOAT IN THE INTAKE'S FILE BUT OUTSIDE ITS BOUNDARY IS FLAGGED. THE HOLE: this file
        //    was in no scan set at all, so no amount of float in the repricer that appends the card
        //    to the history, or in the epoch read that dates a price against it, could go red.
        report.push(plant(
            cx,
            self,
            "a float in the second intake's file, outside its boundary, is flagged",
            &[ROW_NO_FLOAT],
            second.file,
            Edit::Append(format!(
                "\npub fn planted_reprice(x: {float_ty}) -> {float_ty} {{ x * 1.5 }}\n"
            )),
            &[&float_ty, "root/kernel.rs"],
        ));

        // 2. AND A FLOAT INSIDE THE BOUNDARY'S OWN BODY STAYS GREEN. The conversion is where a
        //    configured decimal is allowed to be; a gate that flagged it would push the conversion
        //    out of the one place #44 puts it, which is the failure `cost.rs` is on the named list
        //    for. Planted INSIDE the measured span rather than appended, so the two cases differ in
        //    exactly the thing under test: where in the file the float is.
        match intake_body_plant(cx, second, &format!("let _planted_micro: {float_ty} = 27.1; let _planted_nanos = (_planted_micro * 1000.0) as u64;")) {
            Ok(ov) => report.push(Case {
                name: "a float INSIDE the second intake's boundary stays green (the conversion)"
                    .to_string(),
                covers: vec![ROW_NO_FLOAT.to_string()],
                expected: crate::gates::Expect::Green,
                got: verdict_expect(self, &cx.with_overlay(ov)),
            }),
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not plant inside {}'s boundary ({e})",
                second.file
            )),
        }

        // 3. A DECLARED BOUNDARY THAT IS NOT THERE EXEMPTS NOTHING AND IS REFUSED. A rename that
        //    moved the conversion must move the table row with it; the alternative is a span
        //    exemption pointing at whatever now occupies those lines.
        match rename_boundary(cx, second) {
            Ok(ov) => report.push(prove_red(
                cx,
                self,
                "a declared money-intake boundary that is no longer in its file is refused",
                &[ROW_SCAN_FLOOR],
                ov,
                &["is not in that file"],
            )),
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not rename {}'s boundary ({e})",
                second.file
            )),
        }

        // 4. AND A BOUNDARY THAT HANDS BACK A FLOAT IS A FLOAT THAT SURVIVED THE CONVERSION.
        //    Planted on the #44 boundary specifically, because that file is exempt WHOLE: the
        //    return-type rule is the only rule that can red it, so this case proves that rule
        //    ALONE and could not be passing on a neighbour's finding.
        let first = &MONEY_INTAKE[0];
        match cx.read(first.file) {
            Ok(text) => {
                let mut ov = Overlay::new();
                ov.set(
                    first.file,
                    text.replace(
                        &format!(
                            "fn {}(micro_per_unit: {float_ty}) -> u64 {{",
                            first.boundary
                        ),
                        &format!(
                            "fn {}(micro_per_unit: {float_ty}) -> {float_ty} {{",
                            first.boundary
                        ),
                    ),
                );
                report.push(prove_red(
                    cx,
                    self,
                    "a money-intake boundary that RETURNS a float is refused",
                    &[ROW_NO_FLOAT],
                    ov,
                    &["RETURNS"],
                ));
            }
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not read the #44 boundary {} ({e})",
                first.file
            )),
        }

        // ── THE MONEY-EGRESS BOUNDARY (`metrics/money.rs` :: `set_gauge`, item 24) ─────────────
        //
        // Six claims, one case each: the file is scanned and a float outside the boundary goes red;
        // a SECOND conversion under another name goes red; the boundary's own body does not; the
        // boundary must still be where the table says; integers go in; and the file itself cannot
        // drop out of the scan set.
        let egress = &MONEY_EGRESS[0];

        // 1. A FLOAT IN THE EGRESS FILE, OUTSIDE ITS BOUNDARY, IS FLAGGED. This is the case that
        //    could not exist before item 24: the served spend gauges were in no scan set at all.
        report.push(plant(
            cx,
            self,
            "a float in the money-egress file, outside its boundary, is flagged",
            &[ROW_NO_FLOAT],
            egress.file,
            Edit::Append(format!(
                "\npub fn planted_spend(cents: i64) -> {float_ty} {{ cents as {float_ty} / 100.0 }}\n"
            )),
            &[&float_ty, "metrics/money.rs"],
        ));

        // 2. A SECOND BOUNDARY — the same conversion under another name — IS FLAGGED. One named
        //    function is the exemption; a copy of it beside the original is a float outside it.
        report.push(plant(
            cx,
            self,
            "a second conversion function beside the money-egress boundary is flagged",
            &[ROW_NO_FLOAT],
            egress.file,
            Edit::Append(format!(
                "\npub(super) fn set_gauge_too(gauge: metrics::Gauge, value: i64) {{\n    gauge.set(value as {float_ty});\n}}\n"
            )),
            &[&float_ty, "metrics/money.rs"],
        ));

        // 3. A FLOAT INSIDE THE BOUNDARY'S OWN BODY STAYS GREEN — that is the one conversion the
        //    float-only sink forces. Planted inside the measured span, so this and case 1 differ in
        //    exactly where in the file the float sits.
        match body_plant(
            cx,
            egress.file,
            egress.boundary,
            &format!("let _planted_again: {float_ty} = exact as {float_ty};"),
        ) {
            Ok(ov) => report.push(Case {
                name:
                    "a float INSIDE the money-egress boundary stays green (the sink's conversion)"
                        .to_string(),
                covers: vec![ROW_NO_FLOAT.to_string()],
                expected: crate::gates::Expect::Green,
                got: verdict_expect(self, &cx.with_overlay(ov)),
            }),
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not plant inside {}'s egress boundary ({e})",
                egress.file
            )),
        }

        // 4. A DECLARED EGRESS BOUNDARY THAT IS NOT THERE EXEMPTS NOTHING AND IS REFUSED.
        match rename_fn(cx, egress.file, egress.boundary) {
            Ok(ov) => report.push(prove_red(
                cx,
                self,
                "a declared money-egress boundary that is no longer in its file is refused",
                &[ROW_SCAN_FLOOR],
                ov,
                &["is not in that file"],
            )),
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not rename {}'s egress boundary ({e})",
                egress.file
            )),
        }

        // 5. AN EGRESS BOUNDARY THAT TAKES A FLOAT WAS HANDED ONE: the money was a float before it.
        match cx.read(egress.file) {
            Ok(text) => {
                let from = "value: impl Into<i128>)";
                let to = format!("value: {float_ty})");
                if text.contains(from) {
                    let mut ov = Overlay::new();
                    ov.set(egress.file, text.replacen(from, &to, 1));
                    report.push(prove_red(
                        cx,
                        self,
                        "a money-egress boundary that TAKES a float is refused",
                        &[ROW_NO_FLOAT],
                        ov,
                        &["TAKES"],
                    ));
                } else {
                    report.note_infra_failure(format!(
                        "no-float-money selftest: {}'s boundary no longer spells `{from}`, so the \
                         float-parameter plant has nothing to replace",
                        egress.file
                    ));
                }
            }
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not read the egress file {} ({e})",
                egress.file
            )),
        }

        // 6. AND THE EGRESS FILE VANISHING IS A SCAN-SET INTEGRITY FAILURE, not an empty scan.
        let mut ov = Overlay::new();
        ov.remove(std::path::Path::new(egress.file));
        report.push(prove_red(
            cx,
            self,
            "the money-egress file dropping out of the tree is refused",
            &[ROW_SCAN_FLOOR],
            ov,
            &["metrics/money.rs"],
        ));

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

/// An overlay that puts `stmt` INSIDE an intake boundary's measured body, on its own line just
/// before the line the body closes on. Textual, like the scan it is planted for: the point is where
/// the line SITS, not what it compiles to.
fn intake_body_plant(cx: &Ctx, intake: &MoneyIntake, stmt: &str) -> Result<Overlay, String> {
    body_plant(cx, intake.file, intake.boundary, stmt)
}

/// The same plant for any named boundary — intake or egress.
fn body_plant(cx: &Ctx, file: &str, boundary: &str, stmt: &str) -> Result<Overlay, String> {
    let text = cx.read(file)?;
    let b = find_boundary(&text, boundary).ok_or_else(|| {
        format!("{file}: `fn {boundary}` is not in the file, so there is no body to plant inside")
    })?;
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    if b.last_line == 0 || b.last_line > lines.len() {
        return Err(format!("{file}: the boundary's body has no last line"));
    }
    lines.insert(b.last_line - 1, format!("    {stmt}"));
    let mut ov = Overlay::new();
    ov.set(file, format!("{}\n", lines.join("\n")));
    Ok(ov)
}

/// An overlay in which the declared boundary has been renamed out from under the table row that
/// names it.
fn rename_boundary(cx: &Ctx, intake: &MoneyIntake) -> Result<Overlay, String> {
    rename_fn(cx, intake.file, intake.boundary)
}

/// The same rename for any named boundary — intake or egress.
fn rename_fn(cx: &Ctx, file: &str, boundary: &str) -> Result<Overlay, String> {
    let text = cx.read(file)?;
    let renamed = text.replace(
        &format!("fn {boundary}"),
        &format!("fn {boundary}_moved_away"),
    );
    if renamed == text {
        return Err(format!(
            "{file}: nothing to rename — `fn {boundary}` is not spelled in that file"
        ));
    }
    let mut ov = Overlay::new();
    ov.set(file, renamed);
    Ok(ov)
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn cx() -> Ctx {
        Ctx::workspace().expect("workspace context")
    }

    /// THE TABLE IS THE SURFACE, so the table has to be true of the tree: every declared boundary is
    /// where it says it is, and every one of them hands back an integer.
    #[test]
    fn every_declared_intake_boundary_is_found_and_hands_back_an_integer() {
        let cx = cx();
        for intake in MONEY_INTAKE {
            let text = cx
                .read(intake.file)
                .unwrap_or_else(|e| panic!("{}: {e}", intake.file));
            let b = find_boundary(&text, intake.boundary).unwrap_or_else(|| {
                panic!("{}: `fn {}` was not found", intake.file, intake.boundary)
            });
            assert!(
                b.last_line >= b.first_line,
                "{}: `fn {}` measured backwards",
                intake.file,
                intake.boundary
            );
            assert!(
                returns_float(intake, &b).is_none(),
                "{}: `fn {}` returns `{}`",
                intake.file,
                intake.boundary,
                b.returns
            );
        }
    }

    /// THE EXEMPTION IS A FUNCTION, NOT A FILE. The second intake's file is 1 300 lines of
    /// composition root; if the span it exempts crept over the repricer that appends the built card
    /// to the history, the hole would be closed on paper and open in fact.
    #[test]
    fn the_exempt_span_is_the_boundary_and_not_the_file() {
        let cx = cx();
        let intake = &MONEY_INTAKE[1];
        let text = cx.read(intake.file).expect("the second intake's file");
        let b = find_boundary(&text, intake.boundary).expect("the second intake's boundary");
        let lines: Vec<&str> = text.lines().collect();

        assert!(
            lines[b.first_line - 1].contains(&format!("fn {}", intake.boundary)),
            "the span starts on `{}`",
            lines[b.first_line - 1]
        );
        assert!(
            b.last_line < lines.len(),
            "the span reaches the end of a {}-line file",
            lines.len()
        );
        // The call path around it — the repricer that appends the card, and the epoch read that
        // dates a price against it — is OUTSIDE the span and therefore scanned.
        for needle in ["fn rates_applied", "fn effective_from_at"] {
            let at = lines
                .iter()
                .position(|l| l.contains(needle))
                .map(|i| i + 1)
                .unwrap_or_else(|| panic!("{needle} is not in {}", intake.file));
            assert!(
                at < b.first_line || at > b.last_line,
                "{needle} (line {at}) sits inside the exempt span {}..={}",
                b.first_line,
                b.last_line
            );
        }
    }

    /// A BRACE IN A MESSAGE IS NOT A BODY. The span is measured over blanked literals, because a
    /// scanner that let `"{"` stretch its own exemption would be the very failure this gate names.
    #[test]
    fn a_brace_inside_a_literal_does_not_stretch_the_span() {
        let src =
            "fn boundary(x: f64) -> u64 {\n    let _ = \"{{{\";\n    x as u64\n}\nfn after() {}\n";
        let b = find_boundary(src, "boundary").expect("the boundary");
        assert_eq!((b.first_line, b.last_line), (1, 4));
        assert_eq!(b.returns, "u64");
    }

    /// DECIMALS IN, INTEGERS OUT. A boundary that hands a float back is a float that survived the
    /// conversion, and every caller of it is runtime money path.
    #[test]
    fn a_boundary_that_returns_a_float_is_a_finding() {
        let intake = &MONEY_INTAKE[0];
        let b = find_boundary(
            "fn nano_rate(micro: f64) -> f64 {\n    micro * 1000.0\n}\n",
            "nano_rate",
        )
        .expect("the boundary");
        let finding = returns_float(intake, &b).expect("a float return is a finding");
        assert!(finding.contains("RETURNS"), "{finding}");
    }

    /// AND A FN NAME THAT IS MERELY A SUFFIX OF ANOTHER IS NOT THE BOUNDARY.
    #[test]
    fn a_similarly_spelled_function_is_not_the_boundary() {
        let src = "fn not_the_rate(x: u64) -> u64 { x }\nfn the_rate(x: f64) -> u64 { x as u64 }\n";
        let b = find_boundary(src, "the_rate").expect("the boundary");
        assert_eq!(b.first_line, 2);
    }

    /// THE EGRESS TABLE IS SURFACE TOO, so it has to be true of the tree: every declared egress
    /// boundary is where it says it is, takes no float, is the only one in its file, and its file
    /// is in a money scan set.
    #[test]
    fn every_declared_egress_boundary_is_found_takes_an_integer_and_is_scanned() {
        let cx = cx();
        let mut seen = std::collections::BTreeSet::new();
        for egress in MONEY_EGRESS {
            assert!(
                seen.insert(egress.file),
                "{}: two egress boundaries",
                egress.file
            );
            assert!(
                KERNEL_MONEY_FILES.contains(&egress.file)
                    || BINARY_MONEY_FILES.contains(&egress.file)
                    || CONTRACT_MONEY_FILES.contains(&egress.file),
                "{}: the egress file is in no named money scan set",
                egress.file
            );
            let text = cx
                .read(egress.file)
                .unwrap_or_else(|e| panic!("{}: {e}", egress.file));
            let b = find_boundary(&text, egress.boundary).unwrap_or_else(|| {
                panic!("{}: `fn {}` was not found", egress.file, egress.boundary)
            });
            assert!(
                b.first_line < b.last_line,
                "{}: measured backwards",
                egress.file
            );
            assert!(
                takes_float(egress, &b).is_none(),
                "{}: `fn {}` takes `{}`",
                egress.file,
                egress.boundary,
                b.params
            );
        }
    }

    /// A float outside the egress boundary is a finding; the same float inside it is not.
    #[test]
    fn a_float_outside_the_egress_boundary_is_a_finding_and_inside_is_not() {
        let src = "pub(super) fn set_gauge(g: G, value: i64) {\n    g.set(value as f64);\n}\n\
                   pub fn leak(c: i64) -> f64 {\n    c as f64\n}\n";
        let b = find_boundary(src, "set_gauge").expect("boundary");
        let mut spans: IntakeSpans = std::collections::BTreeMap::new();
        spans.insert("m.rs".into(), vec![(b.first_line, b.last_line)]);
        let mut offenders = Vec::new();
        scan_file("m.rs", src, &spans, &mut offenders);
        assert_eq!(offenders.len(), 2, "{offenders:?}");
        assert!(offenders
            .iter()
            .all(|o| o.starts_with("m.rs:4:") || o.starts_with("m.rs:5:")));
        let taking = find_boundary("fn set_gauge(g: G, v: f64) {\n}\n", "set_gauge").unwrap();
        assert!(takes_float(&MONEY_EGRESS[0], &taking).is_some());
    }

    /// ITEM 214: A HOME NESTED INSIDE ANOTHER IS COUNTED ONCE. The floor is set one above the
    /// distinct count of the outer home, and the inner home adds no file the outer one lacks — so
    /// the area is below its floor. A walk that summed per-home counted the inner home's files
    /// twice and cleared it.
    #[test]
    fn a_nested_home_is_counted_once_against_the_area_floor() {
        let cx = cx();
        const OUTER: &[&str] = &["crates/busbar-a2a/src"];
        let inner = "crates/busbar-a2a/src/a2a";
        let alone = walk_area(
            &cx,
            &CountRoot {
                area: "outer alone",
                homes: OUTER,
                floor: 1,
            },
        )
        .expect("the outer home walks");
        let nested_count = alone
            .iter()
            .filter(|f| f.rel_str().starts_with(&format!("{inner}/")))
            .count();
        assert!(nested_count > 0, "the control needs a populated inner home");
        let floor = alone.len() + 1;
        let homes: &'static [&'static str] = &["crates/busbar-a2a/src/a2a", "crates/busbar-a2a/src"];
        let got = walk_area(
            &cx,
            &CountRoot {
                area: "nested",
                homes,
                floor,
            },
        );
        match got {
            Err(e) => assert!(e.contains(&format!("{} distinct", alone.len())), "{e}"),
            Ok(files) => panic!(
                "{} file(s) cleared a floor of {floor} over {} distinct — the nested home was \
                 counted twice",
                files.len(),
                alone.len()
            ),
        }
    }

    /// Both arms of the framework, over the real tree.
    #[test]
    fn the_gate_is_green_on_the_workspace() {
        let verdict = crate::gates::execute(&NoFloatMoneyGate, &cx());
        assert!(
            !verdict.red,
            "no-float-money is RED on the real tree: {:?}",
            verdict.problems
        );
    }
}
