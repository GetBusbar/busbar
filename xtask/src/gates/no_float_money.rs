//! `cargo xtask gate no-float-money` — NO BINARY FLOATING POINT, AND NO SILENTLY-DEFAULTED COUNT
//! READ, ON ANY MONEY PATH (DECISIONS #77(8), #66, #81, #81a).
//!
//! The 1.6.0 money model is exact arithmetic: a rate is an integer nano-unit, an accumulation is a
//! `u128`, a count is an `i128` mantissa at one fixed decimal scale (`busbar_contract::count`), and
//! a projection truncates once with an integer divisor. `f32`/`f64` on the money path is exactly the
//! failure this bans — a float sums differently depending on order, rounds in ways nobody
//! configured, cannot hold `27.1` at all, and turns "the bill equals the sum of the lines" from a
//! proof into a hope. So the crate that owns the money arithmetic (`busbar-kernel-ledger`), the
//! crate that owns the exact count type (`busbar-contract`'s count module), the kernel module that
//! decides affordability (`busbar-kernel/src/governance`, less one named routing ratio) and the
//! kernel's and binary's dedicated money-unit files carry no float in production source.
//!
//! # THE SCAN SET IS THE CHECK
//!
//! For most of this gate's life it scanned the ledger crate and six named files, and that was the
//! whole of it. `crates/busbar-kernel/src/cost.rs` — which owns `RateNanos` and the conversion that
//! builds it — and the admission decision — which decides whether a request is affordable and
//! prices the counters that answer — were in NEITHER set. No amount of float added to either could
//! produce a RED, ever, for any reason. An instrument that cannot produce a NO is not a check, so
//! both are in the set now: the live admission decision (`busbar-kernel/src/governance`) whole, with
//! [`NOT_MONEY_RATIO`] its one named exemption, and the kernel's money files by name (the kernel is
//! not a money crate).
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
//! lives in and the ITEM, by name, that is the conversion. Only the named items' own spans are
//! exempt; every other line of the file is scanned. Two files carry intakes today:
//!
//! * `busbar-kernel-ledger/src/cost/rate.rs` — the card-build arithmetic itself (#44): `nano_rate`
//!   and the four constructor fns that hand a configured decimal to it, plus `TierRates`, the
//!   record of configured decimals they read. **THE FILE IS NOT EXEMPT.** It used to be dropped
//!   from the ledger walk whole as "the card build", while it also holds the `u128` accumulation
//!   (`nanos_sum`), the card digest and the runtime price reads (`fee_of`, `fee_unit_price_nanos`,
//!   `nanos_per_unit`): a float in any of those read GREEN for any amount of float (audit xtask-X3
//!   finding 1). It is walked with the rest of the ledger now, and only the named items are exempt.
//! * `crates/busbar/src/root/kernel.rs` :: `card_from_config` — **THE SECOND INTAKE, AND IT WAS
//!   UNDECLARED AND UNSCANNED.** This is where the deployment's configured rates become the card
//!   every plane's exit prices against: the root reads config, `card_from_config` relays it into the
//!   cost unit, and `CardRepricer::rates_applied` appends the result to the history. This gate's own
//!   header used to say the file "lives in files this gate does not scan, for the same reason: it is
//!   the boundary" — but "the boundary" is one FUNCTION in a 1 300-line composition-root file, and a
//!   float anywhere else in it (in the repricer, in the epoch read, in the units registry) could not
//!   produce a RED for any amount of float. The file is scanned now, with `card_from_config`'s own
//!   body the only span in it a float may appear in.
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
//! there. AN ALLOWANCE IS ANCHORED TO THE `fn` ITEM THE READ SITS IN, and states exactly how many
//! defaulted reads that item holds: a new read in the same item, or an allowance that no longer
//! matches its count (including one that matches nothing), FAILS the row. It used to be a needle
//! found anywhere in the 200 bytes before a read, so a new billed read written just after an
//! allowed timing read rode its allowance, and a dead allowance was a note on a passing row (audit
//! xtask-X3 finding 7). Two classes: [`AllowClass::NotACount`] (a frame index, an audio timing, a media sample
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
//! AND THE LIST GREW ONCE, BY MEASUREMENT (item 178). The "fixed" codec reads had moved their
//! silent zero one call down, into `.and_then(read_count_u64).unwrap_or(0)`, and the accessor
//! needles could not see the helper — so the allowances went away because the detector went blind,
//! not because the sites did. [`COUNT_HELPERS`] makes them visible; the 32 it found are armed as
//! pending under [`PENDING_CEILING`], which may only fall.
//!
//! AND IT FELL TO ZERO (item 133). All 32 LLM-codec reads and the voice codec's billed reads now
//! refuse an unreadable count; the voice `u64_at` was measured to read no billed count and is a
//! [`AllowClass::NotACount`]. No pending allowance remains, and the ceiling holds it at none.
//!
//! # THE THIRD BAN: A PERSISTED COUNT WITHOUT ITS SCALE (#81a)
//!
//! A count is written down as its MANTISSA, which is meaningless without the scale beside it. #81a
//! fixes the form: one `#[serde(default)]` scale field per record, ABSENT meaning the v1.5.5 whole
//! units and PRESENT meaning scale 6, with the branch at the read and NO rescale of stored bytes. So
//! a record struct that holds a `Count` and no scale discriminator is a row nobody can read back,
//! and this row refuses it. THE HOMES ARE DERIVED, NOT LISTED: every production file in `crates/`
//! that names `Serialize` in code is a persisted-record home, and the census is held to a floor so
//! an emptied census is refused rather than read as "no record holds a `Count`" (audit xtask-X3
//! finding 12: the one listed home held no `Count` and persisted rows lived in other crates).
//!
//! # TEST SCOPE IS DECIDED BY DECLARATION, NOT BY NAME
//!
//! A file is left out of a scan as a test only when [`scan::cfg_test_module_files`] says its module
//! is declared under a test-only `cfg` (or by a file that is). A `tests.rs`, a `*_tests.rs` or a
//! file under a `tests/` directory that is declared WITHOUT the gate is compiled into the shipped
//! crate and is scanned like any other (audit xtask-X3 finding 8). Every walk is rooted in a
//! crate's `src/`, so a crate's top-level `tests/` integration targets are never in it.
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

#[cfg(test)]
#[path = "tests/no_float_money_scope_tests.rs"]
mod no_float_money_scope_tests;

pub const ROW_SCAN_FLOOR: &str = "no-float-money:scan-floor";
pub const ROW_NO_FLOAT: &str = "no-float-money:no-float";
pub const ROW_COUNT_READ: &str = "no-float-money:count-read-shape";
pub const ROW_COUNT_SCALE: &str = "no-float-money:count-scale-discriminator";

/// The consolidated one-book money crate (W3.a). Its whole job is integer money arithmetic.
const LEDGER_SRC: &str = "crates/busbar-kernel-ledger/src";

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// THE MONEY-INTAKE BOUNDARIES — WHERE A CONFIGURED DECIMAL BECOMES A STORED INTEGER
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// What kind of item an intake row names. Either way ONLY THE NAMED ITEM IS THE CONVERSION, and
/// the rest of its file is money runtime path, scanned: a float inside the named item is the
/// configured decimal being converted; a float ANYWHERE ELSE in the file is a float that survived
/// the intake, which is the finding. There is no whole-file exemption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntakeItem {
    /// `fn <boundary>`: its body is exempt, and its declared RETURN TYPE is held to "integers come
    /// out".
    ConversionFn,
    /// `struct <boundary>` and its inherent `impl <boundary>` blocks: THE RECORD OF CONFIGURED
    /// DECIMALS a conversion fn reads, exempt as declared. It carries decimals INTO a named
    /// conversion fn, so it has no "integers come out" to hold it to; what it hands on is read by
    /// one of the named fns or the read is a finding in the fn that makes it.
    DecimalRecord,
}

/// ONE PLACE MONEY ENTERS THIS SYSTEM FROM CONFIGURATION.
///
/// A boundary this table does not name is a boundary the gate cannot reason about: either it is in
/// no scan set (invisible, the `card_from_config` case) or it is scanned with no exemption at all
/// (a standing red over a legitimate conversion). Both silence the instrument, one by never saying
/// no and one by never being able to say yes.
pub struct MoneyIntake {
    /// The repo-relative file the boundary lives in.
    pub file: &'static str,
    /// The ITEM that is the boundary. Named, not inferred: the exempt span is a body somebody can
    /// open and read, and a rename that moves it is a scan-set failure rather than a silent
    /// widening (a boundary that cannot be found exempts nothing and is REFUSED).
    pub boundary: &'static str,
    /// Whether `boundary` names a conversion fn or the record of decimals one reads.
    pub item: IntakeItem,
    /// Why this is an intake at all.
    pub why: &'static str,
}

/// EVERY MONEY-INTAKE BOUNDARY IN THE TREE. Read this table and you have read the gate's exempt
/// surface; there is nowhere else a float is permitted on the money path.
pub const MONEY_INTAKE: &[MoneyIntake] = &[
    MoneyIntake {
        file: CARD_BUILD_FILE,
        boundary: "nano_rate",
        item: IntakeItem::ConversionFn,
        why: "#44's card build: a configured `micro_per_unit` times a thousand, rounded \
              half-away-from-zero, ONCE, into an integer nano-rate.",
    },
    MoneyIntake {
        file: CARD_BUILD_FILE,
        boundary: "representable_nano_rate",
        item: IntakeItem::ConversionFn,
        why: "#44's card-build question (item 22): `nano_rate`'s quantisation, or `None` for a \
              configured decimal the card cannot hold. A configured `f64` in, `Option<u64>` out.",
    },
    MoneyIntake {
        file: CARD_BUILD_FILE,
        boundary: "from_micro_rates",
        item: IntakeItem::ConversionFn,
        why: "#44: the card constructor over configured micro-unit decimals; each one goes to \
              `place_rate` and nowhere else. Decimals in, a card of integer cells out.",
    },
    MoneyIntake {
        file: CARD_BUILD_FILE,
        boundary: "from_config",
        item: IntakeItem::ConversionFn,
        why: "#44: THE CARD A DEPLOYMENT CONFIGURED, built from its `TierRates` decimals by the \
              class fan-out into `from_micro_rates`. Decimals in, a card out.",
    },
    MoneyIntake {
        file: CARD_BUILD_FILE,
        boundary: "place_rate",
        item: IntakeItem::ConversionFn,
        why: "#44: the one placement of a configured decimal into a cell, through \
              `representable_nano_rate`; returns unit and leaves an integer cell.",
    },
    MoneyIntake {
        file: CARD_BUILD_FILE,
        boundary: "TierRates",
        item: IntakeItem::DecimalRecord,
        why: "#44: one lane's four configured micro-unit decimals, the raw-value record \
              `from_config` converts, and its `by_class` fan-out. The record a conversion reads.",
    },
    MoneyIntake {
        file: "crates/busbar/src/root/kernel.rs",
        boundary: "card_from_config",
        item: IntakeItem::ConversionFn,
        why: "THE SECOND INTAKE: the composition root relaying the deployment's configured rates               into the cost unit's card, on boot and on every live rate apply. Its call path —               `CardRepricer::rates_applied`, which appends the built card to the history, and               `RateEpoch::effective_from_at`, which dates a price against it — is the rest of this               file, and is scanned.",
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
    file: "crates/busbar-kernel/src/snapshot/money.rs",
    boundary: "set_gauge",
    why: "The `/metrics` money gauges (spend, budget-remaining, token counts): an `i64`/`u64` figure \
          widened to `i128`, then handed to the `metrics` facade, whose gauge stores and the \
          Prometheus exporter prints a float. Byte-identical to 1.5.5, which cast the same integer \
          into the same gauge (item 24).",
}];

/// A WALK OF PRODUCTION SOURCE: `spec`'s files less the ones whose module is declared under a
/// test-only `cfg` ([`production_only`]), held to `floor` AFTER the test files are gone. A float in
/// a test is a test's number, not the money path's; a file is a test because it is DECLARED as one,
/// never because of what it is called.
fn walk_production(
    cx: &Ctx,
    spec: &WalkSpec,
    floor: usize,
) -> Result<Vec<crate::ctx::SourceFile>, crate::ctx::WalkError> {
    let kept = production_only(cx, cx.walk(spec)?);
    if kept.len() < floor {
        return Err(crate::ctx::WalkError::BelowFloor {
            found: kept.len(),
            floor,
            roots: spec.roots().to_vec(),
        });
    }
    Ok(kept)
}

/// `files` less every file [`scan::cfg_test_module_files`] puts in test scope. A file the overlay
/// does not touch is read from disk, so its declarations are keyed stably (its absolute path) and
/// read once per process; a planted file is read fresh.
fn production_only(cx: &Ctx, files: Vec<crate::ctx::SourceFile>) -> Vec<crate::ctx::SourceFile> {
    let planted: std::collections::BTreeSet<&std::path::Path> = cx
        .overlay()
        .map(|ov| ov.paths().map(std::path::PathBuf::as_path).collect())
        .unwrap_or_default();
    let test = scan::cfg_test_module_files(files.iter().map(|f| {
        let stable =
            (!planted.contains(f.rel.as_path())).then(|| f.abs.to_string_lossy().into_owned());
        (f.rel_str(), f.text.as_str(), stable)
    }));
    files
        .into_iter()
        .filter(|f| !test.contains(&f.rel_str()))
        .collect()
}

/// The denominator floor for the ledger scan. Twenty-three production files (then excluding the
/// card-build file, which is walked now) when this was written; the floor tracks the real tree rather than `> 0`, because one
/// surviving file is as vacuous as none.
const SCAN_FLOOR: usize = 18;

/// The binary's DEDICATED money-unit files: the durable ledger, the reconciliation identity and
/// the money migration. Whole files whose every line is money path, so scanning them entire cannot
/// flag a routing weight or a health score — those live in the plane files, which this gate does
/// not scan. The card-build boundary in the binary is NOT here, on purpose (see the module header).
const BINARY_MONEY_FILES: &[&str] = &[
    // `847c22f98` split this file (structure-lint oversized) into `durability/mod.rs` (the seam,
    // the journal writers, the money-book impl) and `durability/replay.rs` (the book-rebuild
    // replay it split out). Both halves are the money path the single file used to be, so both are
    // named — a rename that dropped either one silently is exactly the scan-set integrity failure
    // this list exists to catch, so BOTH stay named rather than the ban following only one half.
    "crates/busbar/src/root/durability/mod.rs",
    "crates/busbar/src/root/durability/replay.rs",
    // The money-book seam (Settling, Settled, MoneyBook, SharedBook), split out of `mod.rs` for
    // structure-lint: the settle path the exit arms take, so it stays in the scan.
    "crates/busbar/src/root/durability/book.rs",
    "crates/busbar/src/root/ledger_identity.rs",
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
/// #77(1) and #77(3), and it is a home in the [`persisted_record_homes`] census below. It was in this
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

/// THE ADMISSION DECISION, scanned whole like the ledger: the kernel's governance module, where
/// `try_admit` decides whether a request is affordable, charges and refunds the budget cells, and
/// reads the windows they roll over. Every production file under it is on the money path, so the ban
/// applies to the DIRECTORY rather than to a hand-picked file list — a new file added beside
/// `state.rs` is in the ban the moment it exists, which a named list could never promise.
///
/// THIS ROOT USED TO BE `crates/busbar-kernel-budget/src`, a crate whose admission stack had no
/// production caller while the live decision sat here, in no scan set at all. The crate is deleted
/// (ARCHITECT ruling 2026-09-30, "busbar-kernel-budget is deleted whole") and the scan follows the
/// decision that is live, not the name that used to be on it.
const GOVERNANCE_SRC: &str = "crates/busbar-kernel/src/governance";

/// The denominator floor for the governance scan: the MEASURED production file count at the move
/// (`group_provision`, `mint_policy`, `mod`, `revocation`, `self_serve`, `signing`, `state`). One
/// file fewer is a relocation the scan did not follow, and it is refused.
const GOVERNANCE_FLOOR: usize = 7;

/// THE ONE FLOAT IN THE GOVERNANCE SCOPE THAT IS NOT MONEY, named, and the only one there can be.
///
/// A single value, not a table: a second exemption in this scope is a second edit to this constant's
/// type, in a reviewed diff, never a row appended beside the first.
pub struct NotMoneyRatio {
    /// The repo-relative file the function lives in. It must be inside [`GOVERNANCE_SRC`].
    pub file: &'static str,
    /// The FUNCTION whose body is exempt, found by name. Absent exempts NOTHING and is REFUSED.
    pub function: &'static str,
    /// Why this float is not money.
    pub why: &'static str,
}

/// `state.rs` :: `rate_headroom` — WHY IT IS NOT MONEY. It answers "how close is this key to its
/// request/token cap", as the fraction `[0.0, 1.0]` of the tightest windowed `requests`/`tokens`
/// limit still unused, and the routing `usage` policy ranks lanes by it. Its inputs are COUNTS
/// (requests and tokens, never a price or a cent), its answer is a ratio no ledger, cap comparison
/// or bill ever reads, and `try_admit` — which is scanned, float-free — is what blocks. Converting it
/// to an integer would change the routing order, so it is exempt by name instead; every other float
/// in the governance scope is a finding.
pub const NOT_MONEY_RATIO: NotMoneyRatio = NotMoneyRatio {
    file: "crates/busbar-kernel/src/governance/state.rs",
    function: "rate_headroom",
    why: "an f64 routing headroom ratio over request/token COUNTS, not money: the routing `usage` \
          policy ranks by it, no ledger, cap or bill reads it, and `try_admit` is what blocks",
};

/// ── TWO DEDICATED MONEY CRATES THAT WERE IN NO SCAN SET AT ALL (2026-09-23) ─────────────────────
///
/// The 1.6.0 gate blind-spot census planted ten floats on the money path and
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
/// holds a SECOND copy of the card-build conversion. #44 exempts that conversion as named items in
/// exactly one file ([`CARD_BUILD_FILE`], rows of [`MONEY_INTAKE`]) precisely so there is one place
/// for the rounding and clamping rules to live; a copy of them somewhere the ban cannot see is how
/// the two drift, and a rate that is judged at one value and billed at another is the failure the
/// whole integer-money model exists to make impossible. The exemption is a NAMED ITEM, not an
/// arithmetic, so a second copy of it is a finding here.
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
/// THE FOURTH ENTRY, ADDED 2026-09-23 (item 24): `snapshot/money.rs` — THE SERVED MONEY GAUGES.
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
    "crates/busbar-kernel/src/snapshot/money.rs",
    "crates/busbar-kernel/src/plane_driver/money.rs",
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
    // `busbar-llm-codec` DISSOLVED (owner ruling R7, 2026-09-27, #39: no `busbar-*-codec` crate):
    // its files folded whole into `crates/busbar-plane-llm/src`, already a home here, so the union
    // this group scans lost no file and the dead `crates/busbar-llm-codec/src` home is struck.
    CountRoot {
        area: "the LLM codecs, engine and plane",
        homes: &["crates/busbar-llm/src", "crates/busbar-plane-llm/src"],
        floor: 70,
    },
    // `busbar-voice-codec` DISSOLVED THE SAME WAY, same ruling: its files folded whole into
    // `crates/busbar-plane-streaming/src`, already a home here, so the dead
    // `crates/busbar-voice-codec/src` home is struck.
    CountRoot {
        area: "the audio codecs, engine and plane",
        // `crates/busbar-voice/src` is struck: FLIP-STREAMING deleted the legacy streams crate.
        homes: &["crates/busbar-plane-streaming/src"],
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
    //
    // `crates/busbar-mcp/src/record.rs` drained in its turn: `3147ec7e1` ("busbar-mcp record.rs
    // moves into busbar-plane-mcp (fold A1)") moves the file byte-identically to
    // `crates/busbar-plane-mcp/src/record.rs` and says so in its own body ("door-only: the record.rs
    // plugin-path row drains"). The destination needs no third home added: it is the same directory
    // as `crates/busbar-plane-mcp/src`, already a home below, so the moved file was never out of this
    // group's count for a single scan.
    //
    // `crates/busbar-mcp/src/codec` IS STRUCK (P3 DEL-MCP, ARCHITECT 2026-10-05): the engine and
    // its registry row are deleted, and the mcp plane is its door crate alone — the home already
    // listed. The floor does not move.
    CountRoot {
        area: "the tool codec, its records and the plane",
        homes: &["crates/busbar-plane-mcp/src"],
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
    // The money book's floor moves 24 -> 21 for a DELETION, not a move (p6-ledger-fix, Q128 audit
    // item 3): `usage/meter.rs`, `usage/evidence.rs` and `usage/lane.rs` were the kernel-side
    // metering fold, which no production path constructed and the spec does not want (the plane
    // reports, the kernel writes: `BUSBAR-1.6.0.md` §7). Their code went nowhere, so there is no new
    // home to add; the floor is the measured count after the deletion.
    CountRoot {
        area: "the money book",
        homes: &["crates/busbar-kernel-ledger/src"],
        floor: 21,
    },
    CountRoot {
        area: "the contract",
        homes: &["crates/busbar-contract/src"],
        floor: 33,
    },
    CountRoot {
        area: "the neutral carriers",
        // The shared value crate these carriers lived in is deleted (#83a SD-8): its SHAPES are the
        // contract's (SD-1 moved them to the files listed here) and its semantics are the kernel's,
        // which "the kernel" area scans. The ban moved with the carriers, to where they live.
        homes: &[
            "crates/busbar-contract/src/abi",
            "crates/busbar-contract/src/ir",
            "crates/busbar-contract/src/billing.rs",
            "crates/busbar-contract/src/codec.rs",
            "crates/busbar-contract/src/diagnostic.rs",
            "crates/busbar-contract/src/media.rs",
            "crates/busbar-contract/src/protocol.rs",
            "crates/busbar-contract/src/upstream.rs",
        ],
        floor: 27,
    },
    CountRoot {
        area: "the loader and the store seam",
        homes: &["crates/plugin-loader/src"],
        floor: 18,
    },
    CountRoot {
        area: "the composition root",
        homes: &["crates/busbar/src/root"],
        floor: 17,
    },
];

/// THE LLM CODEC'S COUNT SEAM (`usage_count.rs`) IS SCANNED LIKE EVERY OTHER FILE. It used to be
/// skipped by name as "the seam being replaced", while it is the live reader the handlers call
/// (`billed_count_opt`); its needle strings sit in comments, which the scan strips (audit xtask-X3
/// finding 11). Named here so the selftest can plant into it.
const COUNT_SEAM: &str = "crates/busbar-plane-llm/src/codec/usage_count.rs";

/// The JSON-number accessors a count could be read through. `as_f64` is here as well as the integer
/// pair because a count that arrives through a double has already lost the exactness #81 requires.
pub const NUMBER_ACCESSORS: &[&str] = &["as_u64", "as_i64", "as_f64", "as_u128", "as_i128"];

/// THE HOUSE COUNT READERS: a helper that answers `Option<count>` for a JSON value, where `None`
/// means "present and unreadable" as well as "absent". Defaulting one to zero is the SAME silent
/// zero the accessors above produce — the helper only moved it one call down (item 178).
///
/// `read_count_u64` is the LLM codec's own seam, and every billed read in that crate goes through
/// it. The accessor list alone could not see a single one of them: the needle is `read_count_u64`,
/// not `as_u64`, so 32 live `.and_then(read_count_u64).unwrap_or(0)` sites read as a clean tree
/// while the row's title promised the opposite. The seam's own doc names the idiom as the defect
/// (`usage_count.rs`: "Why this exists rather than `.and_then(read_count_u64).unwrap_or(0)`") and
/// points at `billed_count`, which keeps absent-is-zero and makes unreadable a refusal.
pub const COUNT_HELPERS: &[&str] = &["read_count_u64"];

/// The numeric type suffixes a literal (or an `as` cast) can carry.
const NUMERIC_TYPES: &[&str] = &[
    "u128", "i128", "usize", "isize", "u16", "u32", "u64", "i16", "i32", "i64", "f32", "f64", "u8",
    "i8",
];

/// The unsigned types whose `MIN` is zero.
const UNSIGNED_TYPES: &[&str] = &["u8", "u16", "u32", "u64", "u128", "usize"];

/// DOES THIS DEFAULT EVALUATE TO ZERO? Decided by VALUE, not by a list of spellings (audit xtask-X3
/// finding 11): any integer or float literal whose value is zero, in any radix and with any suffix
/// or `as` cast (`0`, `0u16`, `0_i16`, `0.0`, `0e0`, `0x0`, `0 as u64`); an unsigned type's `MIN`;
/// any `…::default()` (the receiver is a JSON number, so its `Default` is zero); a closure or a
/// block whose value is one of those (`|| 0`, `{ 0 }`); and the function path `Default::default` /
/// `u64::default` handed to `unwrap_or_else`. A NON-zero default (`unwrap_or(idx as u64)`) is out
/// of scope on purpose: it substitutes a value the author chose and named, which is a different act
/// from recording that no work happened.
fn is_zero_value(arg: &str) -> bool {
    let squeezed: String = arg.chars().filter(|c| !c.is_whitespace()).collect();
    let mut a = squeezed.as_str();
    // Wrapping parens, a block, and a no-argument closure all hand back what is inside them.
    loop {
        let wrapped = |open: u8, close: u8| {
            a.len() >= 2
                && a.as_bytes()[0] == open
                && balanced(a.as_bytes(), 0, open, close) == Some(a.len())
        };
        if wrapped(b'(', b')') || wrapped(b'{', b'}') {
            a = &a[1..a.len() - 1];
        } else if let Some(body) = a.strip_prefix("||") {
            a = body;
        } else if let Some(body) = a.strip_prefix("|_|") {
            a = body;
        } else {
            break;
        }
    }
    if a.ends_with("::default()") || a.ends_with("::default") || a == "Default::default" {
        return true;
    }
    if let Some(ty) = a.strip_suffix("::MIN") {
        let ty = ty.trim_start_matches('<').trim_end_matches('>');
        return UNSIGNED_TYPES.contains(&ty);
    }
    // `0 as u64` squeezes to `0asu64`.
    let mut lit = a;
    if let Some(at) = lit.rfind("as") {
        if NUMERIC_TYPES.contains(&&lit[at + 2..]) {
            lit = &lit[..at];
        }
    }
    let lit: String = lit.chars().filter(|c| *c != '_').collect();
    let mut lit = lit.as_str();
    for ty in NUMERIC_TYPES {
        if let Some(head) = lit.strip_suffix(ty) {
            if !head.is_empty() {
                lit = head;
                break;
            }
        }
    }
    let lower = lit.to_ascii_lowercase();
    for radix in ["0x", "0o", "0b"] {
        if let Some(digits) = lower.strip_prefix(radix) {
            return !digits.is_empty() && digits.chars().all(|c| c == '0');
        }
    }
    let mantissa = lower.split('e').next().unwrap_or_default();
    let exponent_ok = match lower.split_once('e') {
        None => true,
        Some((_, e)) => {
            let e = e.trim_start_matches(['+', '-']);
            !e.is_empty() && e.chars().all(|c| c.is_ascii_digit())
        }
    };
    !mantissa.is_empty()
        && mantissa.starts_with('0')
        && mantissa.chars().all(|c| c == '0' || c == '.')
        && mantissa.matches('.').count() <= 1
        && exponent_ok
}

/// The first top-level argument of an argument list (whitespace kept), for `map_or(default, f)`.
fn first_arg(args: &str) -> &str {
    let mut depth = 0i32;
    for (i, c) in args.char_indices() {
        match c {
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth -= 1,
            ',' if depth == 0 => return &args[..i],
            _ => {}
        }
    }
    args
}

/// Why a surviving defaulted read is on the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowClass {
    /// Not a count at all, and never will be. Permanent.
    NotACount,
    /// A real count that the #81 conversion wave owes. Temporary, and the gate says how many are
    /// left on every run so the number is never quietly forgotten.
    PendingConversion,
}

/// One named, reasoned survivor: every defaulted read in ONE `fn` item.
pub struct Allow {
    /// The repo-relative file it lives in.
    pub file: &'static str,
    /// The `fn` the reads sit in — the INNERMOST `fn` item enclosing each read. An item rather than
    /// a line number, so a reformat or an edit elsewhere in the file does not turn a reasoned
    /// allowance into a spurious red; an item rather than a text window, so a read in a NEIGHBOURING
    /// item never rides it.
    pub item: &'static str,
    /// EXACTLY how many defaulted reads the item holds. One more is a new read riding the allowance;
    /// one fewer (or none) is an allowance that no longer says what is there. Both fail the row.
    pub reads: usize,
    /// Permanent, or owed to the conversion wave.
    pub class: AllowClass,
    /// Why.
    pub why: &'static str,
}

/// THE MOST [`AllowClass::PendingConversion`] HITS THE ROW WILL CARRY. Armed 2026-09-23 at the
/// number measured the day [`COUNT_HELPERS`] made the codec's 32 helper reads visible: 5 in the
/// voice codec plus those 32. A needle names a site's shape, not its count, so without this a
/// second defaulted read beside an allowed one rode the same allowance for free. It may only go
/// DOWN, in the diff that converts a site; a run above it is a finding. LOWERED 37 → 0 on
/// 2026-09-24 (items 133 + the voice twins): every LLM-codec billed read now goes through the
/// refusing `billed`/`billed_opt` readers, every duplex billed read through the voice codec's
/// `billed_count`, and `u64_at` was measured to read no billed count at all.
pub const PENDING_CEILING: usize = 0;

/// THE SURVIVING SITES, EVERY ONE NAMED AND REASONED. Measured 2026-09-22 against this tree; re-keyed
/// 2026-10-07 from text needles to the enclosing `fn` item (audit xtask-X3 finding 7).
///
/// This list may SHRINK and must never grow without a reviewed diff that says why. An entry whose
/// reads are gone FAILS the row until it is deleted: a standing permission nobody uses is a
/// permission the next read takes. RETIRED AT THE RE-KEY, each measured matching nothing on predev
/// `5e672d125d` (the row's own "now match nothing" note): `openai_chat/handler.rs` `get(keys::END)`
/// and the `get("channels")` row (`topology/twilio.rs`; the legacy `twilio.rs` copy went with
/// FLIP-STREAMING's deletion of `plane.rs` and friends) — their reads were already
/// inside the window of the `get(keys::START)` / `get("sampleRate")` rows, and they are counted by
/// those items' rows now. `audio::Segment`, `get(keys::START)` and `get(keys::END)` fold into the one
/// `read_transcription_response` row.
pub const ALLOWED_COUNT_READS: &[Allow] = &[
    // ── Not a count, permanently ──────────────────────────────────────────────────────────────
    Allow {
        file: "crates/busbar-plane-llm/src/codec/bedrock/mod.rs",
        item: "clamp_content_block_index",
        reads: 1,
        class: AllowClass::NotACount,
        why: "a frame's position in a sequence (`contentBlockIndex`), not a quantity anybody is \
              billed for",
    },
    Allow {
        file: "crates/busbar-plane-llm/src/codec/cohere/mod.rs",
        item: "clamp_frame_index",
        reads: 1,
        class: AllowClass::NotACount,
        why: "a frame's position in a sequence, not a quantity anybody is billed for",
    },
    // NEWLY SEEN 2026-10-07 by the value-decided zero (`map_or(0, …)`, audit X3 #11), ruled NotACount
    // by the coordinator (Rule A) on three conditions: each value traced to every use and none
    // reaches a usage, token or billed field; v1.5.5 carried the same default; an exact-count plant.
    Allow {
        file: "crates/busbar-plane-llm/src/codec/openai_chat/reader.rs",
        item: "read_response_events",
        reads: 1,
        class: AllowClass::NotACount,
        why: "the stream tool-call `index` (:1026), clamped to MAX_TOOL_INDEX; it is only the \
              `open_tools` key (:1063, :1073, :1164), the LEGACY_FUNCTION_CALL_KEY compare (:1067) \
              and the `tool_ir_index` key (:1078, :1098, :1165) — block bookkeeping, never a usage \
              field. v1.5.5 `crates/busbar/src/proto/openai_chat/reader.rs:611` has the same \
              `map_or(0, …min(MAX_TOOL_INDEX))`",
    },
    Allow {
        file: "crates/busbar-plane-llm/src/codec/openai_responses/reader.rs",
        item: "read_response_events",
        reads: 3,
        class: AllowClass::NotACount,
        why: "the stream `output_index` of the reasoning delta (:890), the text delta (:949) and \
              the #305 annotation arm (:1021, `34a06f2500`), which mirrors :949 so a citation lands \
              on the block its text did (an index-less annotation goes with index-less text, at 0); \
              clamped to MAX_OUTPUT_INDEX; it is only the `open_tools` key (raw or + \
              TEXT_INDEX_KEY_OFFSET) and the IrStreamEvent BlockStart/BlockDelta `index` — block \
              position, never a usage field. v1.5.5 `crates/busbar/src/proto/openai_responses/\
              reader.rs:679` and `:718` have the same default; 1.5.5 had no annotation arm",
    },
    Allow {
        file: "crates/busbar-plane-llm/src/codec/openai_chat/handler.rs",
        item: "read_transcription_response",
        reads: 5,
        class: AllowClass::NotACount,
        why: "a transcription segment's own id and the segment and word timing offsets \
              (`start`/`end`) — metadata echoed back, never metered",
    },
    Allow {
        file: "crates/busbar-plane-streaming/src/codec/topology/twilio.rs",
        item: "decode",
        reads: 2,
        class: AllowClass::NotACount,
        why: "a media format's sample rate and channel count, not metered quantities",
    },
    Allow {
        file: "crates/busbar-kernel/src/config/migrate.rs",
        item: "migrate_governance",
        reads: 1,
        class: AllowClass::NotACount,
        why: "the #44 config boundary: `price_per_1k_tokens_cents`, a configured decimal read once \
              at parse, not a runtime count",
    },
    Allow {
        file: "crates/busbar-plane-streaming/src/codec/ir/codec/mod.rs",
        item: "u64_at",
        reads: 1,
        class: AllowClass::NotACount,
        why: "measured 2026-09-24: its only callers are a truncate's content_index and three audio \
              timings (audio_end_ms, audio_start_ms) — an index and timing metadata, never metered; \
              every billed duplex count reads through `billed_count`, which refuses",
    },
];

// ─────────────────────────────────────────────────────────────────────────────────────────────────
// The persisted-record scan set (#81a)
// ─────────────────────────────────────────────────────────────────────────────────────────────────

/// WHERE A PERSISTED MONEY RECORD CAN LIVE: DERIVED, NOT LISTED (audit xtask-X3 finding 12). Every
/// production `.rs` file under a crate's `src/` that names `Serialize` in CODE (a derive, an `impl`,
/// an import — comments and literals do not count) is a home, and every `struct` in a home that
/// holds a `Count` must name its scale. A record is persisted by being serialised, wherever it
/// lives, so the census follows the derive rather than a path.
///
/// THE LIST THIS REPLACES named one file, `crates/busbar-contract/src/records.rs`, which holds no
/// `Count` at all — the row was vacuous by construction, and persisted rows in other crates (the mcp
/// plane's `record.rs` rows derive `Serialize`) were in no home. The record shapes have moved twice
/// (`busbar-api` → the ledger → the contract, `1059d3c36` R100), which is why a path list goes stale.
const PERSISTED_CENSUS_ROOT: &str = "crates";

/// THE FLOOR UNDER THE DERIVED CENSUS. An empty census is "no record holds a `Count`" for a reason
/// nobody can see, so it is refused; the floor sits below the measured count (MEASURED 2026-10-07 on
/// predev `5e672d125d`: see the census test) so ordinary churn does not trip it and a census that
/// went blind does.
const PERSISTED_CENSUS_FLOOR: usize = 60;

/// Every persisted-record home among `files`: production files under a crate's `src/` that name
/// `Serialize` in code.
fn persisted_record_homes(
    cx: &Ctx,
    files: Vec<crate::ctx::SourceFile>,
) -> Vec<crate::ctx::SourceFile> {
    production_only(
        cx,
        files
            .into_iter()
            .filter(|f| f.rel_str().contains("/src/"))
            .collect(),
    )
    .into_iter()
    .filter(|f| {
        if !f.text.contains("Serialize") {
            return false;
        }
        let mut st = scan::LexState::default();
        f.text
            .lines()
            .any(|l| word_hit(&scan::blank_code(l, &mut st), "Serialize"))
    })
    .collect()
}

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
    let mut lex = scan::LexState::default();
    for (i, raw) in text.lines().enumerate() {
        // Comments stripped, string literals intact — a float in prose about the ban is exempt, a
        // float in code is not.
        let code = scan::strip_comment_line(raw, &mut in_block);
        // The SAME line with every literal's contents blanked too, for the spellings below: a
        // version string `"1.0"` is not a float, and `1.0` in code is.
        let blanked = scan::blank_code(raw, &mut lex);
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
        for spelled in float_spellings(&blanked) {
            offenders.push(finding(rel, line, &spelled));
        }
    }
}

/// EVERY OTHER WAY A FLOAT IS SPELLED ON A LINE (item 213). [`FLOAT_TOKENS`] is a case-sensitive
/// whole-word match on `f64`/`f32`, and a float does not have to be written that way to be on the
/// line: `(factor * 1_000_000_000.0) as u128` names no float type and IS float arithmetic, and so
/// is `let mut acc = 0.0;`. Four spellings, each a real Rust float:
///
/// * a FLOAT LITERAL — `1.0`, `1_000.5`, `0.25` (a digit, a dot, a digit; a tuple index `x.0.1`
///   and a range `0..5` are not);
/// * an EXPONENT LITERAL — `1e9`, `2.5E-3`, which Rust types as a float with no dot at all;
/// * a SUFFIXED LITERAL — `0f64`, `1_f32`, `2.5f64`, where the word match misses because the digit
///   before the `f` is part of the same word;
/// * a float TYPE NAMED INSIDE AN IDENTIFIER — `SignalValue::F64`, `as_f64`, `to_f32`, where one
///   `_`-separated segment is `f64`/`f32` in either case. The bare `f64`/`f32` is left to
///   [`FLOAT_TOKENS`], so one token is never reported twice.
///
/// Reads a line whose literals and comments [`scan::blank_code`] has already blanked.
fn float_spellings(blanked: &str) -> Vec<String> {
    let chars: Vec<char> = blanked.chars().collect();
    let wordy = |c: char| c.is_ascii_alphanumeric() || c == '_';
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let prev = i.checked_sub(1).map(|p| chars[p]);
        if !wordy(c) || prev.is_some_and(wordy) {
            i += 1;
            continue;
        }
        // A token begins here. A number directly after a `.` is a tuple index or a field, never a
        // literal, so it is read and skipped as one.
        let start = i;
        while i < chars.len() && wordy(chars[i]) {
            i += 1;
        }
        if c.is_ascii_digit() {
            if prev == Some('.') {
                continue;
            }
            let mut dotted = false;
            if i + 1 < chars.len() && chars[i] == '.' && chars[i + 1].is_ascii_digit() {
                dotted = true;
                i += 1;
                while i < chars.len() && wordy(chars[i]) {
                    i += 1;
                }
            }
            // `1e-9` / `1.5E+3`: the sign splits the word, so the exponent is read through it.
            if i + 1 < chars.len()
                && matches!(chars[i], '+' | '-')
                && matches!(chars[i - 1], 'e' | 'E')
                && chars[i + 1].is_ascii_digit()
            {
                i += 1;
                while i < chars.len() && wordy(chars[i]) {
                    i += 1;
                }
            }
            let lit: String = chars[start..i].iter().collect();
            let lower = lit.to_ascii_lowercase();
            let radix =
                lower.starts_with("0x") || lower.starts_with("0o") || lower.starts_with("0b");
            let suffixed = lower.ends_with("f64") || lower.ends_with("f32");
            let exponent = !radix
                && lower.char_indices().any(|(k, ch)| {
                    ch == 'e'
                        && k > 0
                        && lower[..k]
                            .chars()
                            .all(|d| d.is_ascii_digit() || d == '_' || d == '.')
                });
            if (!radix && (dotted || exponent)) || (!radix && suffixed) {
                out.push(lit);
            }
            continue;
        }
        let ident: String = chars[start..i].iter().collect();
        if FLOAT_TOKENS.contains(&ident.as_str()) {
            continue;
        }
        if ident
            .split('_')
            .any(|seg| FLOAT_TOKENS.contains(&seg.to_ascii_lowercase().as_str()))
        {
            out.push(ident);
        }
    }
    out
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

/// Is this line the declaration of `<kw> <name>` (`fn`, `struct`, or an inherent `impl`)? The
/// keyword must sit directly before the name, so `impl Default for Name` is not `impl Name`.
fn declares(code: &str, kw: &str, name: &str) -> bool {
    word_positions(code, name).any(|i| {
        let before = code[..i].trim_end();
        let Some(head) = before.strip_suffix(kw) else {
            return false;
        };
        head.chars()
            .next_back()
            .is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_'))
    })
}

/// Is this line the declaration of `fn <name>`?
fn declares_fn(code: &str, name: &str) -> bool {
    declares(code, "fn", name)
}

/// Every span a [`IntakeItem::DecimalRecord`] covers: `struct <name>` and each inherent
/// `impl <name>` block, 1-based and inclusive. Empty when the struct is not declared in `text`: a
/// record that cannot be found exempts nothing, and the caller refuses it.
fn record_spans(text: &str, name: &str) -> Vec<(usize, usize)> {
    let mut st = scan::LexState::default();
    let lines: Vec<String> = text.lines().map(|l| scan::blank_code(l, &mut st)).collect();
    if !lines.iter().any(|code| declares(code, "struct", name)) {
        return Vec::new();
    }
    lines
        .iter()
        .enumerate()
        .filter(|(_, code)| declares(code, "struct", name) || declares(code, "impl", name))
        .filter_map(|(start, _)| measure_item(&lines, start))
        .map(|b| (b.first_line, b.last_line))
        .collect()
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
    measure_item(&lines, start)
}

/// Measure the item declared on `lines[start]` (already blanked): its header, and its body to the
/// brace that closes it. An item that ends in `;` at depth zero before any `{` (a tuple or unit
/// struct) is its header lines alone.
fn measure_item(lines: &[String], start: usize) -> Option<Boundary> {
    // THE HEADER runs from the declaration to the `{` that opens the body, at paren depth zero.
    let mut header = String::new();
    let mut depth = 0i32;
    let mut open = None;
    'lines: for (i, code) in lines.iter().enumerate().skip(start) {
        for ch in code.chars() {
            match ch {
                '(' | '[' => depth += 1,
                ')' | ']' => depth -= 1,
                ';' if depth <= 0 => {
                    return Some(Boundary {
                        first_line: start + 1,
                        last_line: i + 1,
                        returns: String::new(),
                        params: String::new(),
                    });
                }
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
}

/// Step past whitespace, the accessor's own parens, a closing paren that ends an `and_then(…)`, and
/// a turbofish — everything that can sit between the accessor's name and the `.` that follows it.
fn skip_to_dot(bytes: &[u8], text: &str, i: usize) -> Option<usize> {
    let i = skip_call(bytes, text, i)?;
    (i < bytes.len() && bytes[i] == b'.').then_some(i + 1)
}

/// The index of the first byte after the accessor's call that is not whitespace, a paren group or a
/// turbofish: a `.` (a method follows) or a `{` (the body of an `if let` the read is the scrutinee
/// of).
fn skip_call(bytes: &[u8], text: &str, mut i: usize) -> Option<usize> {
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
    Some(i)
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

/// Does a silent zero default follow the accessor that starts at `start` and ends at `i`? Returns
/// the index past it. The default is judged by VALUE ([`is_zero_value`]), in every shape that
/// substitutes it: `unwrap_or_default()`, `unwrap_or(Z)`, `unwrap_or_else(Z)`, `map_or(Z, f)`,
/// `map_or_else(Z, f)`, and `if let Some(n) = <read> { … } else { Z }`.
fn zero_default_after(flat: &Flat, start: usize, i: usize) -> Option<usize> {
    let bytes = flat.text.as_bytes();
    let next = skip_call(bytes, &flat.text, i)?;
    if bytes.get(next) == Some(&b'{') {
        return if_let_else_zero(flat, start, next);
    }
    let dot = skip_to_dot(bytes, &flat.text, i)?;
    let (name, after) = read_ident(bytes, &flat.text, dot);
    match name.as_str() {
        "unwrap_or_default" => read_args(bytes, &flat.text, after).map(|(_, end)| end),
        "unwrap_or" | "unwrap_or_else" => {
            let (arg, end) = read_args(bytes, &flat.text, after)?;
            is_zero_value(&arg).then_some(end)
        }
        "map_or" | "map_or_else" => {
            let open = flat.text[after..].find('(')? + after;
            let end = balanced(bytes, open, b'(', b')')?;
            is_zero_value(first_arg(&flat.text[open + 1..end - 1])).then_some(end)
        }
        _ => None,
    }
}

/// `if let Some(n) = <read> { … } else { Z }` with `Z` zero: the `{` at `body` opens the `if let`
/// body, and the read starting at `start` must be that `if let`'s scrutinee (no `{`, `}` or `;`
/// between the `if let` and the read).
fn if_let_else_zero(flat: &Flat, start: usize, body: usize) -> Option<usize> {
    let bytes = flat.text.as_bytes();
    let head = &flat.text[..start];
    let at = head.rfind("if let ")?;
    if head[at..].contains(['{', '}', ';']) {
        return None;
    }
    let after_body = balanced(bytes, body, b'{', b'}')?;
    let rest = flat.text[after_body..].trim_start();
    let rest = rest.strip_prefix("else")?.trim_start();
    if !rest.starts_with('{') {
        return None;
    }
    let open = flat.text.len() - rest.len();
    let close = balanced(bytes, open, b'{', b'}')?;
    is_zero_value(&flat.text[open..close]).then_some(close)
}

/// Every defaulted JSON-number read in one file, by shape — MEMOISED on the file's bytes.
///
/// The reading is a pure function of the text, and it is the dearest thing this gate does: one
/// byte-by-byte word scan per accessor per file. A self-test case IS a gate run over a tree one
/// plant away from the last, so the battery used to re-read every count-read area's unchanged files
/// once per case — 36 times. The verdict over the hits (which allowance each one uses, which file
/// it is in) is still taken fresh on every run.
fn scan_count_reads(text: &str) -> std::sync::Arc<Vec<CountHit>> {
    use std::hash::{Hash, Hasher};
    static MEMO: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<u64, std::sync::Arc<Vec<CountHit>>>>,
    > = std::sync::OnceLock::new();
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    let key = h.finish();
    let memo = MEMO.get_or_init(Default::default);
    if let Some(found) = memo.lock().unwrap_or_else(|e| e.into_inner()).get(&key) {
        return std::sync::Arc::clone(found);
    }
    let hits = std::sync::Arc::new(read_count_hits(text));
    memo.lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(key, std::sync::Arc::clone(&hits));
    hits
}

/// The reading [`scan_count_reads`] remembers.
fn read_count_hits(text: &str) -> Vec<CountHit> {
    let flat = flatten(text);
    let mut hits = Vec::new();
    for &accessor in NUMBER_ACCESSORS.iter().chain(COUNT_HELPERS) {
        for start in word_positions(&flat.text, accessor) {
            if zero_default_after(&flat, start, start + accessor.len()).is_none() {
                continue;
            }
            hits.push(CountHit {
                line: flat.line_of.get(start).copied().unwrap_or(0),
                accessor,
            });
        }
    }
    hits.sort_by_key(|h| h.line);
    hits
}

/// Every `fn` item in `text` as (name, first line, last line), 1-based and inclusive, measured over
/// blanked literals and comments. A body-less `fn` (a trait method's declaration) is not an item a
/// read can sit in and is left out.
fn fn_items(text: &str) -> Vec<(String, usize, usize)> {
    let mut st = scan::LexState::default();
    let lines: Vec<String> = text.lines().map(|l| scan::blank_code(l, &mut st)).collect();
    let mut out = Vec::new();
    for (i, code) in lines.iter().enumerate() {
        for at in word_positions(code, "fn") {
            let rest = code[at + 2..].trim_start();
            let name: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                .collect();
            if name.is_empty() || !rest[name.len()..].trim_start().starts_with(['(', '<']) {
                continue;
            }
            if let Some(last) = item_last_line(&lines, i, at) {
                out.push((name, i + 1, last));
            }
        }
    }
    out
}

/// The 1-based line the item declared at `lines[start][col..]` closes on: its header runs to the
/// `{` at paren depth zero, its body to the brace that balances it. `None` for a declaration that
/// ends in `;` first.
fn item_last_line(lines: &[String], start: usize, col: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut brace = 0i32;
    let mut opened = false;
    for (i, code) in lines.iter().enumerate().skip(start) {
        let from = if i == start { col } else { 0 };
        for ch in code[from..].chars() {
            match ch {
                '(' | '[' if !opened => depth += 1,
                ')' | ']' if !opened => depth -= 1,
                ';' if !opened && depth <= 0 => return None,
                '{' => {
                    if opened || depth <= 0 {
                        opened = true;
                        brace += 1;
                    }
                }
                '}' if opened => {
                    brace -= 1;
                    if brace == 0 {
                        return Some(i + 1);
                    }
                }
                _ => {}
            }
        }
    }
    None
}

/// The innermost `fn` item enclosing 1-based `line`, or `""` for a read in no `fn` at all (which
/// no allowance can name).
fn enclosing_fn(items: &[(String, usize, usize)], line: usize) -> &str {
    items
        .iter()
        .filter(|(_, first, last)| *first <= line && line <= *last)
        .max_by_key(|(_, first, _)| *first)
        .map_or("", |(name, _, _)| name.as_str())
}

/// The rows the count-read scan produces, and how many reads each allowance matched.
struct CountReadScan {
    offenders: Vec<String>,
    /// Reads matched, per [`ALLOWED_COUNT_READS`] index.
    used: std::collections::BTreeMap<usize, usize>,
    pending: usize,
}

/// EVERY ALLOWANCE THAT DOES NOT SAY WHAT IS THERE: one that matched no read, and one whose item
/// holds more or fewer defaulted reads than it states. Each is a finding, never a note.
fn allowance_drift(used: &std::collections::BTreeMap<usize, usize>) -> Vec<String> {
    ALLOWED_COUNT_READS
        .iter()
        .enumerate()
        .filter_map(|(i, a)| {
            let got = used.get(&i).copied().unwrap_or(0);
            if got == a.reads {
                return None;
            }
            Some(if got == 0 {
                format!(
                    "{} `fn {}`: the allowance matched NO defaulted read — delete it (a standing \
                     permission nobody uses is a permission the next read takes)",
                    a.file, a.item
                )
            } else {
                format!(
                    "{} `fn {}`: {got} defaulted read(s) where the allowance states {} — a new read \
                     is riding it, or one left and the count was not lowered",
                    a.file, a.item, a.reads
                )
            })
        })
        .collect()
}

fn row_count_read(scan: &CountReadScan) -> Row {
    let drift = allowance_drift(&scan.used);
    if !drift.is_empty() {
        return Row::fail(
            ROW_COUNT_READ,
            "a count-read allowance does not match the reads it names",
            format!(
                "{} allowance(s) out of step: {}{}",
                drift.len(),
                drift.join(" | "),
                if scan.offenders.is_empty() {
                    String::new()
                } else {
                    format!(
                        " — and {} unallowed defaulted read(s): {}",
                        scan.offenders.len(),
                        scan.offenders.join(" | ")
                    )
                }
            ),
        );
    }
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
    if scan.pending > PENDING_CEILING {
        return Row::fail(
            ROW_COUNT_READ,
            "a count is read with a silent zero default instead of a refusal (#81)",
            format!(
                "{} defaulted count read(s) ride a pending-conversion allowance, above the armed \
                 ceiling of {PENDING_CEILING} — a NEW silent zero landed beside an allowed one; \
                 read it through `billed_count` so an unreadable count REFUSES",
                scan.pending
            ),
        );
    }
    let detail = format!(
        "every defaulted number read on the money path is a named, reasoned allowance on its own \
         `fn`, each matching exactly the reads it states; {} still owed to the #81 conversion wave",
        scan.pending
    );
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
        let spec = WalkSpec::new([*home]).ext("rs");
        // A home that is not there is a home the fold has already emptied; the floor over the union
        // is what says whether the AREA is still being scanned.
        if let Ok(found) = cx.walk(&spec) {
            files.extend(found.into_iter().filter(|f| seen.insert(f.rel_str())));
        }
    }
    // Test scope over the UNION, so a module declared in one home and living in another resolves.
    let files = production_only(cx, files);
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
        // The ledger crate WHOLE, card-build file included, minus the test-scope files, held to its floor.
        // The card build's conversion is exempt by named item ([`MONEY_INTAKE`]), never by file.
        let ledger_spec = WalkSpec::new([LEDGER_SRC]).ext("rs");
        let ledger_files = match walk_production(cx, &ledger_spec, SCAN_FLOOR) {
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

        // THE ADMISSION DECISION, held to its own floor, the same treatment the ledger gets. A
        // money scope that reads as empty is REFUSED, never scanned as zero hits and printed green.
        let governance_files = match walk_production(
            cx,
            &WalkSpec::new([GOVERNANCE_SRC]).ext("rs"),
            GOVERNANCE_FLOOR,
        ) {
            Ok(f) => f,
            Err(e) => {
                float_scan_problems.push(format!(
                    "{e} If the admission decision legitimately moved, point {GOVERNANCE_SRC} at \
                     its new home in a reviewed diff that says so — do not lower the floor."
                ));
                Vec::new()
            }
        };

        // ITS ONE NAMED NOT-MONEY EXEMPTION, found by name in a file the walk above read. Absent
        // exempts NOTHING and is refused, the same rule every intake and egress boundary keeps.
        let mut ratio_span: Option<(usize, usize)> = None;
        match governance_files
            .iter()
            .find(|f| f.rel_str() == NOT_MONEY_RATIO.file)
        {
            None if !governance_files.is_empty() => float_scan_problems.push(format!(
                "{}: the named not-money exemption's file is not in the {GOVERNANCE_SRC} scan — \
                 move the exemption with the file, in the diff that moves it",
                NOT_MONEY_RATIO.file
            )),
            None => {}
            Some(f) => match find_boundary(&f.text, NOT_MONEY_RATIO.function) {
                Some(b) => ratio_span = Some((b.first_line, b.last_line)),
                None => float_scan_problems.push(format!(
                    "{}: the named not-money exemption `fn {}` is not in that file — the \
                     exemption names a function that is not there, so either it moved (move \
                     `NOT_MONEY_RATIO` with it) or it is stale",
                    NOT_MONEY_RATIO.file, NOT_MONEY_RATIO.function
                )),
            },
        }

        // THE SEALED-FACTS AND DURABILITY CRATES (2026-09-23), each held to its own floor the way
        // the ledger and the budget are. Same treatment for the same reason: a dedicated money crate
        // that reads as empty is REFUSED, never scanned as zero hits and printed green.
        let mut whole_crate_files: Vec<crate::ctx::SourceFile> = Vec::new();
        for (root, floor, what) in [
            (AUDIT_SRC, AUDIT_FLOOR, "the sealed money-facts crate"),
            (WAL_SRC, WAL_FLOOR, "the money-record durability crate"),
        ] {
            match walk_production(cx, &WalkSpec::new([root]).ext("rs"), floor) {
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
        // Every row of [`MONEY_INTAKE`] is READ: the boundary has to be found where the table says
        // it is, a conversion fn has to hand back an integer, and only the named item's own span is
        // exempt. A boundary that cannot be
        // found exempts NOTHING and is refused — the alternative is a table that names a function
        // somebody renamed, quietly exempting a span that is no longer there or, worse, still
        // naming a span that is now something else.
        let mut offenders = Vec::new();
        let mut intake_spans: IntakeSpans = std::collections::BTreeMap::new();
        if let Some(span) = ratio_span {
            intake_spans
                .entry(NOT_MONEY_RATIO.file.to_string())
                .or_default()
                .push(span);
        }
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
            let spans = match intake.item {
                IntakeItem::ConversionFn => match find_boundary(&text, intake.boundary) {
                    Some(b) => {
                        if let Some(escaped) = returns_float(intake, &b) {
                            offenders.push(escaped);
                        }
                        vec![(b.first_line, b.last_line)]
                    }
                    None => Vec::new(),
                },
                IntakeItem::DecimalRecord => record_spans(&text, intake.boundary),
            };
            if spans.is_empty() {
                float_scan_problems.push(format!(
                    "{}: the declared money-intake boundary `{}` is not in that file — the \
                     exemption names an item that is not there, so either the boundary moved \
                     (move this row with it, in the diff that moves it) or the table is stale",
                    intake.file, intake.boundary
                ));
                continue;
            }
            intake_spans
                .entry(intake.file.to_string())
                .or_default()
                .extend(spans);
            if !intake_texts.iter().any(|(f, _)| *f == intake.file) {
                intake_texts.push((intake.file, text));
            }
        }

        // AN INTAKE FILE THE OTHER SETS DO NOT ALREADY CARRY IS SCANNED HERE. `root/kernel.rs` is in
        // no other set at all, which is the hole — the second intake and its whole call path were
        // invisible to this ban. (`cost/rate.rs` is the ledger walk's, so it is not added twice.)
        let already: std::collections::BTreeSet<String> = ledger_files
            .iter()
            .chain(governance_files.iter())
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
                .chain(governance_files.iter())
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
        for f in &governance_files {
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

        // THE COUNT-READ SHAPE, over every enumerated money root. A file two areas share (the
        // contract's neutral carriers are inside the contract area) is read once, so its reads are
        // counted against an allowance once.
        let mut scanned: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
        let mut count_scan = CountReadScan {
            offenders: Vec::new(),
            used: std::collections::BTreeMap::new(),
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
                if !scanned.insert(rel.clone()) {
                    continue;
                }
                let hits = scan_count_reads(&f.text);
                if hits.is_empty() {
                    continue;
                }
                let items = fn_items(&f.text);
                for hit in hits.iter() {
                    let item = enclosing_fn(&items, hit.line);
                    let allowed = ALLOWED_COUNT_READS
                        .iter()
                        .enumerate()
                        .find(|(_, a)| a.file == rel && !item.is_empty() && a.item == item);
                    match allowed {
                        Some((i, a)) => {
                            *count_scan.used.entry(i).or_default() += 1;
                            if a.class == AllowClass::PendingConversion {
                                count_scan.pending += 1;
                            }
                        }
                        None => count_scan.offenders.push(format!(
                            "{rel}:{}: `{}` defaulted to zero instead of refusing (#81), in `fn {}`",
                            hit.line,
                            hit.accessor,
                            if item.is_empty() { "<none>" } else { item }
                        )),
                    }
                }
            }
        }
        count_scan.offenders.sort();
        count_scan.offenders.dedup();

        // THE PERSISTED-COUNT DISCRIMINATOR (#81a), over the DERIVED homes.
        let mut scale_offenders = Vec::new();
        // LISTED, THEN READ ONLY UNDER `src/`: a crate's integration tests, benches and fixtures
        // are never a home, so they are never read.
        let homes = match cx.list(&WalkSpec::new([PERSISTED_CENSUS_ROOT]).ext("rs")) {
            Ok(rels) => {
                let mut files = Vec::new();
                for rel in rels
                    .into_iter()
                    .filter(|r| r.to_string_lossy().contains("/src/"))
                {
                    match cx.read(&rel) {
                        Ok(text) => files.push(crate::ctx::SourceFile {
                            abs: cx.abs(&rel),
                            rel,
                            text,
                        }),
                        Err(e) => set_problems.push(format!(
                            "the persisted-record census could not read {}: {e}",
                            rel.display()
                        )),
                    }
                }
                persisted_record_homes(cx, files)
            }
            Err(e) => {
                set_problems.push(format!("the persisted-record census could not walk: {e}"));
                Vec::new()
            }
        };
        for home in &homes {
            let rel = home.rel_str();
            for (line, body) in struct_bodies(&home.text) {
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
        if homes.len() < PERSISTED_CENSUS_FLOOR {
            set_problems.push(format!(
                "the persisted-record census found {} production file(s) naming `Serialize` under \
                 {PERSISTED_CENSUS_ROOT}/*/src, below the floor of {PERSISTED_CENSUS_FLOOR} — a census \
                 that went blind reads exactly like a tree with no persisted `Count`, and a ban that \
                 scans nothing is not a ban",
                homes.len()
            ));
        }

        let scan_floor = if set_problems.is_empty() {
            Row::pass(
                ROW_SCAN_FLOOR,
                "every money scan set is present and above its floor",
                format!(
                    "the ledger, governance, sealed-facts and durability scopes, {} named money \
                     file(s), {} enumerated money area(s) and {} declared money-intake \
                     boundary(ies) all read",
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

        // ITEM 213: A FLOAT THAT NEVER SPELLS ITS TYPE IS FLAGGED. A signal variant, a float
        // literal and an inferred accumulator — the line names neither type word.
        report.push(plant(
            cx,
            self,
            "a float spelled as a literal and a signal variant, never as the type word, is flagged",
            &[ROW_NO_FLOAT],
            &format!("{LEDGER_SRC}/planted_unspelled_float.rs"),
            Edit::Create(
                "pub fn drift(v: Signal) -> u128 {\n    match v { Signal::F64(k) => (k * 1_000_000_000.0) as u128, _ => 0 }\n}\n"
                    .to_string(),
            ),
            &["planted_unspelled_float", "1_000_000_000.0"],
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

        // ── THE CARD-BUILD FILE (`cost/rate.rs`, #44) IS SCANNED; ITS CONVERSION FNS ARE NOT ────
        //
        // The file used to be dropped from the ledger walk whole, as "the card build", while it
        // also holds the u128 accumulation (`nanos_sum`), the card digest and the runtime price
        // reads (`fee_of`, `fee_unit_price_nanos`, `nanos_per_unit`). A float in any of those read
        // GREEN for any amount of float (audit xtask-X3 finding 1). Four cases: a float in the
        // accumulation, a float in a price read and a new float fn beside the conversion are each
        // RED; a float inside the named conversion fn stays green.
        for (what, boundary, stmt) in [
            (
                "u128 accumulation (`nanos_sum`)",
                "nanos_sum",
                format!("let _planted_sum = (q as {float_ty} * r as {float_ty}) as u128;"),
            ),
            (
                "runtime price read (`fee_of`)",
                "fee_of",
                format!("let _planted_fee = self.fee as {float_ty} * 1.5;"),
            ),
        ] {
            match body_plant(cx, CARD_BUILD_FILE, boundary, &stmt) {
                Ok(ov) => report.push(prove_red(
                    cx,
                    self,
                    format!("a float in the card-build file's {what} is flagged"),
                    &[ROW_NO_FLOAT],
                    ov,
                    &[&float_ty, "cost/rate.rs"],
                )),
                Err(e) => report.note_infra_failure(format!(
                    "no-float-money selftest: could not plant inside `fn {boundary}` ({e})"
                )),
            }
        }
        report.push(plant(
            cx,
            self,
            "a new float fn beside the card-build conversion is flagged (the file is not exempt)",
            &[ROW_NO_FLOAT],
            CARD_BUILD_FILE,
            Edit::Append(format!(
                "\npub fn extra_boundary_rate(m: {float_ty}) -> u64 {{ (m * 1000.0) as u64 }}\n"
            )),
            &[&float_ty, "cost/rate.rs"],
        ));
        match body_plant(
            cx,
            CARD_BUILD_FILE,
            "nano_rate",
            &format!("let _planted_micro: {float_ty} = micro_per_unit * 1.0;"),
        ) {
            Ok(ov) => report.push(Case {
                name: "a float INSIDE the named card-build conversion `nano_rate` stays green"
                    .to_string(),
                covers: vec![ROW_NO_FLOAT.to_string()],
                expected: crate::gates::Expect::Green,
                got: verdict_expect(self, &cx.with_overlay(ov)),
            }),
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not plant inside `fn nano_rate` ({e})"
            )),
        }

        // ── THE ADMISSION DECISION AND ITS ONE NOT-MONEY EXEMPTION (`rate_headroom`) ──────────
        //
        // The ruling that moved this scan (2026-09-30) grants ONE exemption in the governance scope,
        // so these cases prove that it is one: any other float there, in another file or in the same
        // file outside the named function, is still a finding.
        let governance_mod = format!("{GOVERNANCE_SRC}/mod.rs");

        // 1. A FLOAT IN ANOTHER GOVERNANCE FILE IS FLAGGED.
        report.push(plant(
            cx,
            self,
            "a float in a governance file other than the named ratio's is flagged",
            &[ROW_NO_FLOAT],
            &governance_mod,
            Edit::Append(format!(
                "\npub fn planted_budget_scale(cents: i64) -> {float_ty} {{ cents as {float_ty} }}\n"
            )),
            &[&float_ty, "governance/mod.rs"],
        ));

        // 2. A FLOAT IN THE RATIO'S OWN FILE, OUTSIDE THE NAMED FUNCTION, IS FLAGGED. The exemption
        //    is a function, not a file.
        report.push(plant(
            cx,
            self,
            "a float in the named ratio's file, outside `rate_headroom`, is flagged",
            &[ROW_NO_FLOAT],
            NOT_MONEY_RATIO.file,
            Edit::Append(format!(
                "\npub fn planted_cap_ratio(cap: u64) -> {float_ty} {{ cap as {float_ty} * 0.5 }}\n"
            )),
            &[&float_ty, "governance/state.rs"],
        ));

        // 3. AND A FLOAT INSIDE THE NAMED FUNCTION STAYS GREEN: that body is the exemption.
        match body_plant(
            cx,
            NOT_MONEY_RATIO.file,
            NOT_MONEY_RATIO.function,
            &format!("let _planted_ratio: {float_ty} = 0.5;"),
        ) {
            Ok(ov) => report.push(Case {
                name: "a float INSIDE `rate_headroom` stays green (the one not-money exemption)"
                    .to_string(),
                covers: vec![ROW_NO_FLOAT.to_string()],
                expected: crate::gates::Expect::Green,
                got: verdict_expect(self, &cx.with_overlay(ov)),
            }),
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not plant inside {} ({e})",
                NOT_MONEY_RATIO.function
            )),
        }

        // 4. THE NAMED FUNCTION RENAMED AWAY EXEMPTS NOTHING AND IS REFUSED.
        match rename_fn(cx, NOT_MONEY_RATIO.file, NOT_MONEY_RATIO.function) {
            Ok(ov) => report.push(prove_red(
                cx,
                self,
                "the named not-money exemption no longer in its file is refused",
                &[ROW_SCAN_FLOOR, ROW_NO_FLOAT],
                ov,
                &["not-money exemption"],
            )),
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not rename {} ({e})",
                NOT_MONEY_RATIO.function
            )),
        }

        // ── THE SECOND MONEY-INTAKE BOUNDARY (`card_from_config`) ─────────────────────────────
        //
        // Four cases, because "the boundary is in the scan set" is four claims and only one of them
        // is "a float here goes red": the file is scanned, the boundary's own body is not, the
        // boundary has to still be where the table says, and what comes out of it has to be an
        // integer.
        let second = intake_row("card_from_config");

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
        //    Planted on the #44 boundary's own declaration line, which sits inside its exempt span:
        //    the return-type rule is the only rule that can red it, so this case proves that rule
        //    ALONE and could not be passing on a neighbour's finding.
        let first = intake_row("nano_rate");
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

        // ── THE MONEY-EGRESS BOUNDARY (`snapshot/money.rs` :: `set_gauge`, item 24) ─────────────
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
            &[&float_ty, "snapshot/money.rs"],
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
            &[&float_ty, "snapshot/money.rs"],
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
            &["snapshot/money.rs"],
        ));

        // ── TEST SCOPE IS THE DECLARING `mod`'S CFG GATE, NOT THE FILE'S NAME (audit X3 #8) ────
        //
        // A test-shaped name declared WITHOUT the gate is compiled into the crate and is scanned;
        // the same file declared under `#[cfg(test)]` is a fixture's number and is not.
        let ledger_lib = format!("{LEDGER_SRC}/lib.rs");
        let fixture = format!("fn f() {{ let _: {float_ty} = 1.0; }}\n");
        for (what, file, decl, red) in [
            (
                "an un-gated `*_tests.rs` module in the ledger",
                format!("{LEDGER_SRC}/planted_tests.rs"),
                "\npub mod planted_tests;\n",
                true,
            ),
            (
                "an un-gated module under the ledger's `tests/` directory",
                format!("{LEDGER_SRC}/tests/planted_fixture.rs"),
                "\n#[path = \"tests/planted_fixture.rs\"]\npub mod planted_fixture;\n",
                true,
            ),
            (
                "a `#[cfg(test)]`-declared module under the ledger's `tests/` directory",
                format!("{LEDGER_SRC}/tests/planted_fixture.rs"),
                "\n#[cfg(test)]\n#[path = \"tests/planted_fixture.rs\"]\nmod planted_fixture;\n",
                false,
            ),
        ] {
            let mut ov = Overlay::new();
            ov.set(&file, fixture.clone());
            if let Err(e) = Edit::Append(decl.to_string()).apply(cx, &ledger_lib, &mut ov) {
                report.note_infra_failure(format!(
                    "no-float-money selftest: could not declare a planted module in {ledger_lib} ({e})"
                ));
                continue;
            }
            if red {
                report.push(prove_red(
                    cx,
                    self,
                    format!("a float in {what} is scanned (compiled into the crate)"),
                    &[ROW_NO_FLOAT],
                    ov,
                    &[&float_ty, "planted_"],
                ));
            } else {
                report.push(Case {
                    name: format!("a float in {what} is test scope and stays green"),
                    covers: vec![ROW_NO_FLOAT.to_string()],
                    expected: crate::gates::Expect::Green,
                    got: verdict_expect(self, &cx.with_overlay(ov)),
                });
            }
        }

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
            "crates/busbar-plane-llm/src/planted_path_form.rs",
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
            "crates/busbar-plane-streaming/src/planted_second_crate.rs",
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
            // ITEM 178: THE CODEC'S OWN COUNT HELPER. Its `None` means "present and unreadable"
            // as well as "absent", so a zero default on it is the same silent zero — and every
            // billed read in the codec is spelled this way, none of which the row could see.
            (
                "the count helper, path form",
                "Some(v).and_then(crate::usage_count::read_count_u64).unwrap_or(0)",
            ),
            (
                "the count helper, call form",
                "read_count_u64(v).unwrap_or_default()",
            ),
            (
                "a line break inside the chain",
                "v\n        .as_u64()\n        .unwrap_or(0)",
            ),
            // AUDIT X3 #11: THE ZERO IS DECIDED BY VALUE, NOT BY A LIST OF SPELLINGS.
            ("a 0u16 literal", "v.as_u64().unwrap_or(0u16 as u64)"),
            ("a 0i16 literal", "v.as_i64().unwrap_or(0i16 as i64) as u64"),
            ("u64::MIN", "v.as_u64().unwrap_or(u64::MIN)"),
            (
                "unwrap_or_else(Default::default)",
                "v.as_u64().unwrap_or_else(Default::default)",
            ),
            ("a map_or zero", "v.as_u64().map_or(0, |n| n)"),
            (
                "an if-let with a zero else",
                "if let Some(n) = v.as_u64() { n } else { 0 }",
            ),
        ] {
            report.push(plant(
                cx,
                self,
                &format!("{what} of a defaulted count read is flagged"),
                &[ROW_COUNT_READ],
                "crates/busbar-plane-llm/src/planted_spelling.rs",
                Edit::Create(format!(
                    "use serde_json::Value as Json;\npub fn planted(v: &Json) -> u64 {{\n    {body}\n}}\n"
                )),
                &["planted_spelling"],
            ));
        }

        // AUDIT X3 #11: THE COUNT SEAM ITSELF IS SCANNED. It was skipped by name as "the seam being
        // replaced" while it is the live reader the handlers call.
        report.push(plant(
            cx,
            self,
            "a defaulted count read in the LLM codec's count seam (`usage_count.rs`) is flagged",
            &[ROW_COUNT_READ],
            COUNT_SEAM,
            Edit::Append(
                "\npub fn planted_seam(v: &serde_json::Value) -> u64 {\n    v.as_u64().unwrap_or(0)\n}\n"
                    .to_string(),
            ),
            &["usage_count.rs", "planted_seam"],
        ));

        // AUDIT X3 #8, the count-read half: an un-gated `*_tests.rs` module is production.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-plane-llm/src/planted_census_tests.rs",
            "pub fn planted(v: &serde_json::Value) -> u64 {\n    v.as_u64().unwrap_or(0)\n}\n",
        );
        match Edit::Append("\npub mod planted_census_tests;\n".to_string()).apply(
            cx,
            "crates/busbar-plane-llm/src/lib.rs",
            &mut ov,
        ) {
            Ok(()) => report.push(prove_red(
                cx,
                self,
                "a defaulted count read in an un-gated `*_tests.rs` module is flagged",
                &[ROW_COUNT_READ],
                ov,
                &["planted_census_tests"],
            )),
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not declare a planted module in the llm plane ({e})"
            )),
        }

        // ── AUDIT X3 #7: AN ALLOWANCE IS ITS `fn` AND ITS EXACT COUNT ──────────────────────────
        //
        // 1. A NEW defaulted read placed right after two allowed media-format reads, in the same
        //    item, is a finding: it used to sit inside the allowance's 200-byte window and ride it.
        let twilio = "crates/busbar-plane-streaming/src/codec/topology/twilio.rs";
        match cx.read(twilio) {
            Ok(text) => {
                let at = "                let media_format = MediaFormat {";
                if text.contains(at) {
                    let mut ov = Overlay::new();
                    ov.set(
                        twilio,
                        text.replacen(
                            at,
                            &format!(
                                "                let _planted_billed = mf.get(\"usage\").and_then(serde_json::Value::as_u64).unwrap_or(0);\n{at}"
                            ),
                            1,
                        ),
                    );
                    report.push(prove_red(
                        cx,
                        self,
                        "a new defaulted read beside allowed ones in the same `fn` is a finding",
                        &[ROW_COUNT_READ],
                        ov,
                        &["twilio.rs", "decode", "3 defaulted read(s)"],
                    ));
                } else {
                    report.note_infra_failure(format!(
                        "no-float-money selftest: {twilio} no longer spells `{at}`"
                    ));
                }
            }
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not read {twilio} ({e})"
            )),
        }

        // 1b. THE EXACT COUNT HOLDS FOR THE RULED INDEX ROWS TOO: one more defaulted read inside
        //     `read_response_events` (a fifth across the two ruled rows) is a finding.
        let responses = "crates/busbar-plane-llm/src/codec/openai_responses/reader.rs";
        match body_plant(
            cx,
            responses,
            "read_response_events",
            "let _planted_tokens = data.get(\"usage\").and_then(|u| u.as_u64()).map_or(0, |v| v);",
        ) {
            Ok(ov) => report.push(prove_red(
                cx,
                self,
                "a fifth defaulted read in a ruled `read_response_events` is a finding",
                &[ROW_COUNT_READ],
                ov,
                &[
                    "openai_responses/reader.rs",
                    "read_response_events",
                    "4 defaulted read(s)",
                ],
            )),
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not plant inside {responses} ({e})"
            )),
        }

        // 2. AN ALLOWANCE WHOSE READ IS GONE FAILS THE ROW. It used to be a note on a PASS.
        let u64_at = ALLOWED_COUNT_READS
            .iter()
            .find(|a| a.item == "u64_at")
            .map_or("", |a| a.file);
        match cx.read(u64_at) {
            Ok(text) => {
                let from = "and_then(Value::as_u64).unwrap_or_default()";
                if text.contains(from) {
                    let mut ov = Overlay::new();
                    ov.set(
                        u64_at,
                        text.replacen(from, "and_then(Value::as_u64).unwrap_or(7)", 1),
                    );
                    report.push(prove_red(
                        cx,
                        self,
                        "an allowance that matches no defaulted read fails the row",
                        &[ROW_COUNT_READ],
                        ov,
                        &["u64_at", "matched NO"],
                    ));
                } else {
                    report.note_infra_failure(format!(
                        "no-float-money selftest: {u64_at} no longer spells `{from}`"
                    ));
                }
            }
            Err(e) => report.note_infra_failure(format!(
                "no-float-money selftest: could not read the u64_at allowance's file ({e})"
            )),
        }

        // A NON-ZERO DEFAULT IS OUT OF SCOPE, on purpose: it substitutes a value the author chose
        // and named, which is a different act from recording that no work happened.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-plane-llm/src/planted_named_default.rs",
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
            "crates/busbar-plane-llm/src/planted_propagating.rs",
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
        // silent narrowing of the ban. The floor is over the UNION of a group's homes (a fold that
        // moves files between two homes in the same group must not trip it), so emptying the group
        // means emptying EVERY home, not just the first — a group with one home (pre-fold) and a
        // group with several (post-fold, e.g. the LLM codecs group) are proven the same way.
        let homes = COUNT_READ_ROOTS[0].homes;
        let mut ov = Overlay::new();
        match cx.walk(&WalkSpec::new(homes.iter().copied()).ext("rs")) {
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
                "no-float-money selftest: count-read roots {homes:?} are unreadable ({e})"
            )),
        }

        // ── THE PERSISTED-COUNT DISCRIMINATOR ─────────────────────────────────────────────────
        //
        // AUDIT X3 #12: THE HOMES ARE DERIVED. A serialised record holding a `Count` OUTSIDE the
        // contract's `records.rs` — the mcp plane's persisted rows — is a home too.
        report.push(plant(
            cx,
            self,
            "a Serialize record holding a Count with no scale, outside records.rs, is flagged",
            &[ROW_COUNT_SCALE],
            "crates/busbar-plane-mcp/src/record.rs",
            Edit::Append(
                "\n#[derive(serde::Serialize)]\npub struct PlantedMcpRow {\n    pub tokens: Count,\n}\n"
                    .to_string(),
            ),
            &["plane-mcp/src/record.rs", "names no scale"],
        ));
        let record_home = "crates/busbar-contract/src/records.rs";
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
        // EVERY file goes, test files included: a test file whose declaring parent is gone has no
        // gate over it any more and reads as production.
        match cx.walk(&WalkSpec::new([LEDGER_SRC]).ext("rs")) {
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

/// THE LEDGER'S CARD-BUILD FILE (#44). Walked with the rest of the ledger; its conversion items are
/// rows of [`MONEY_INTAKE`], and nothing else in it is exempt.
const CARD_BUILD_FILE: &str = "crates/busbar-kernel-ledger/src/cost/rate.rs";

/// The [`MONEY_INTAKE`] row naming `boundary`. Panics on a name the table does not hold: a
/// selftest that plants against a row which is not there is a broken selftest, not a skipped case.
fn intake_row(boundary: &str) -> &'static MoneyIntake {
    MONEY_INTAKE
        .iter()
        .find(|i| i.boundary == boundary)
        .unwrap_or_else(|| panic!("MONEY_INTAKE names no `{boundary}`"))
}

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
    /// THE COUNT-READ SCAN IS READ ONCE PER FILE. It was re-run over every count-read area's
    /// unchanged files on every gate run, so the 36-case battery paid for it 36 times.
    #[test]
    fn the_count_read_scan_reads_an_unchanged_file_once() {
        let src = "fn zz_memo_probe(v: &Value) -> u64 { v.as_u64().unwrap_or(0) }\n";
        let a = scan_count_reads(src);
        let b = scan_count_reads(src);
        assert!(
            std::sync::Arc::ptr_eq(&a, &b),
            "the second ask is answered from the memo"
        );
        let c = scan_count_reads("fn zz_memo_probe_two() {}\n");
        assert!(
            !std::sync::Arc::ptr_eq(&a, &c),
            "changed bytes are a new reading"
        );
    }

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
            if intake.item == IntakeItem::DecimalRecord {
                assert!(
                    !record_spans(&text, intake.boundary).is_empty(),
                    "{}: `struct {}` was not found",
                    intake.file,
                    intake.boundary
                );
                continue;
            }
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

    /// THE ONE NOT-MONEY EXEMPTION IS WHERE IT SAYS IT IS: inside the governance scope, and a
    /// function that is still in its file.
    #[test]
    fn the_one_not_money_exemption_is_found_inside_the_governance_scope() {
        assert!(
            NOT_MONEY_RATIO
                .file
                .starts_with(&format!("{GOVERNANCE_SRC}/")),
            "{} is outside {GOVERNANCE_SRC}",
            NOT_MONEY_RATIO.file
        );
        let text = cx()
            .read(NOT_MONEY_RATIO.file)
            .unwrap_or_else(|e| panic!("{}: {e}", NOT_MONEY_RATIO.file));
        let b = find_boundary(&text, NOT_MONEY_RATIO.function).unwrap_or_else(|| {
            panic!(
                "{}: `fn {}` was not found",
                NOT_MONEY_RATIO.file, NOT_MONEY_RATIO.function
            )
        });
        assert!(b.last_line > b.first_line, "measured backwards");
    }

    /// THE EXEMPTION IS A FUNCTION, NOT A FILE. The second intake's file is 1 300 lines of
    /// composition root; if the span it exempts crept over the repricer that appends the built card
    /// to the history, the hole would be closed on paper and open in fact.
    #[test]
    fn the_exempt_span_is_the_boundary_and_not_the_file() {
        let cx = cx();
        let intake = intake_row("card_from_config");
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
        let intake = intake_row("nano_rate");
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
        let homes: &'static [&'static str] =
            &["crates/busbar-a2a/src/a2a", "crates/busbar-a2a/src"];
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

    /// ITEM 213: A FLOAT NOT SPELLED `f64`/`f32` IS STILL A FLOAT. Every line below is float
    /// arithmetic or a float type, and none of them carries the bare word the old match needed;
    /// the control lines below them are integers and must stay clean.
    #[test]
    fn a_float_spelled_without_the_type_word_is_a_finding() {
        let src = "pub fn rate(v: SignalValue) -> u128 {\n\
                   \x20   match v { SignalValue::F64(factor) => (factor * 1_000_000_000.0) as u128, _ => 0 }\n\
                   }\n\
                   pub fn acc() -> u64 { let mut a = 0.0; a += 1.5; a as u64 }\n\
                   pub fn e() -> u64 { 1e9 as u64 }\n\
                   pub fn e2() -> u64 { 2.5E-3 as u64 }\n\
                   pub fn sfx() -> u64 { 0f64 as u64 }\n\
                   pub fn j(v: &Value) -> u64 { v.as_f64().map(|x| x as u64).unwrap_or(1) }\n\
                   pub fn ints(t: (u64, (u64, u64))) -> u64 { let _r = 0..5; let _h = 0xE5; let _s = 12usize; let _v = \"1.0\"; t.1.0 + 1_000 + 7u64.max(2) }\n";
        let mut offenders = Vec::new();
        scan_file("m.rs", src, &IntakeSpans::new(), &mut offenders);
        let lines: std::collections::BTreeSet<&str> = offenders
            .iter()
            .map(|o| o.split(':').nth(1).unwrap_or_default())
            .collect();
        assert_eq!(
            lines,
            ["2", "4", "5", "6", "7", "8"].into_iter().collect(),
            "{offenders:#?}"
        );
        for spelled in [
            "`F64`",
            "`1_000_000_000.0`",
            "`0.0`",
            "`1.5`",
            "`1e9`",
            "`2.5E-3`",
            "`0f64`",
            "`as_f64`",
        ] {
            assert!(
                offenders.iter().any(|o| o.contains(spelled)),
                "{spelled} was not named: {offenders:#?}"
            );
        }
    }

    /// ITEM 178: A ZERO DEFAULT ON THE CODEC'S COUNT HELPER IS THE SAME SILENT ZERO. The accessor
    /// list alone saw none of the 32 live `.and_then(read_count_u64).unwrap_or(0)` sites.
    #[test]
    fn a_defaulted_read_through_the_count_helper_is_a_hit() {
        let src = "fn f(u: &Value) -> u64 {\n    u.get(\"input_tokens\")\n        \
                   .and_then(crate::usage_count::read_count_u64)\n        .unwrap_or(0)\n}\n\
                   fn g(v: &Value) -> u64 { read_count_u64(v).unwrap_or_default() }\n\
                   fn h(v: &Value) -> Option<u64> { read_count_u64(v) }\n";
        let hits = scan_count_reads(src);
        let lines: Vec<(usize, &str)> = hits.iter().map(|h| (h.line, h.accessor)).collect();
        assert_eq!(
            lines,
            vec![(3, "read_count_u64"), (6, "read_count_u64")],
            "the helper defaulted to zero must be a hit, and the undefaulted read must not"
        );
    }

    /// ITEM 178: THE PENDING ALLOWANCES ARE HELD TO THEIR ARMED NUMBER. A needle names a shape, so
    /// a second site beside an allowed one would otherwise ride it for free.
    #[test]
    fn pending_conversions_above_the_ceiling_are_a_finding() {
        let at = CountReadScan {
            offenders: Vec::new(),
            used: ALLOWED_COUNT_READS
                .iter()
                .enumerate()
                .map(|(i, a)| (i, a.reads))
                .collect(),
            pending: PENDING_CEILING,
        };
        assert_eq!(row_count_read(&at).status, Status::Pass);
        let over = CountReadScan {
            pending: PENDING_CEILING + 1,
            ..at
        };
        let row = row_count_read(&over);
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
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

#[cfg(test)]
#[path = "tests/no_float_money_tests.rs"]
mod no_float_money_tests;
