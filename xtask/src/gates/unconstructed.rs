//! `cargo xtask gate unconstructed` — A DECLARED CAPABILITY HAS A PRODUCTION CONSTRUCTION SITE,
//! OR IT IS WRITTEN DOWN AS ONE THAT DOES NOT SHIP.
//!
//! ## THE RULE THIS GATE IS
//!
//! **A CAPABILITY THAT IS NEVER CONSTRUCTED IS A CAPABILITY THAT DOES NOT SHIP. Its tests prove
//! the code works; they prove nothing about whether it runs.**
//!
//! ## The failure this exists for, proven three times in one tree on 2026-09-22
//!
//! 1. **The production audit chain is UNSIGNED.** `AuditChain::signing_with`
//!    (`crates/busbar-kernel-audit/src/record.rs`) is a complete, green, well-tested signing
//!    implementation with **zero non-test callers**. The one production construction site,
//!    `crates/busbar/src/root/durability/mod.rs` → `record: AuditChain::new()`, passes no signer and no
//!    config supplies a key. Every deployed node therefore seals a chain whose tamper-evidence is
//!    unsigned, while sixteen `sign_tests.rs` cases prove the signing works.
//! 2. **`#79`'s dated-history derivation has no production feed.** `booked_lines()` returns
//!    `Vec::new()` in both production impls; only a test double is non-empty, and the derivation
//!    returns `None` on empty. That empty answer is DELIBERATE and well argued — fabricating lines
//!    would invent the stored price `#77(3)` forbids — so it is UNFINISHED WIRING, not a
//!    mispricing. **This gate does NOT see it** and does not pretend to: see the limits below.
//! 3. Neither auth crate carries `#![forbid(unsafe_code)]`; both sit on a `known_missing_forbid`
//!    list. The INVISIBILITY was closed. The debt was not.
//!
//! In all three the code is correct, the tests are green, and the thing does not run. **Nothing in
//! this repository measured that**, and three `DONE` rows were wrong in exactly this way.
//!
//! ## WHY THE `reachability` GATE DOES NOT ALREADY CATCH THIS
//!
//! [`crate::gates::reachability`] answers a NEIGHBOURING question and is not a substitute. It asks
//! *is this MODULE reached from `fn main()`, and does this plane have a unit path the root
//! constructs?* `crates/busbar/src/root/durability/mod.rs` passes every one of its rows: the module is
//! reached, `build_for_node` is called, a chain IS constructed. The capability that never runs is
//! **one builder call inside a function that does run** — a level of granularity module reachability
//! cannot express. The two gates compose: `reachability` says the code is reached, this gate says
//! the capability inside it was switched on.
//!
//! ## WHAT COUNTS AS A CONSTRUCTION SITE — and why decoration cannot satisfy it
//!
//! A construction site is **a call, in production code, in the declared scope**. Four things are
//! rejected by shape, because each of them is how an unconstructed capability disguises itself as a
//! constructed one:
//!
//! * a **`use` statement** — importing a thing is not calling it, and a `use` is what makes a
//!   capability's name appear in a file that never invokes it;
//! * a **comment or doc comment** — every line is read off [`ScopeLine::counted`], the copy with
//!   literal and comment bodies blanked, so a name inside `///` or inside a `"…"` is not a hit.
//!   A gate that trusts a comment inherits the lie;
//! * a **type alias** (`type X = …`) and an **attribute** (`#[…]`) — both name a capability without
//!   reaching it;
//! * **the definition itself** — `fn signing_with(` is where the capability is BUILT, and reading it
//!   as evidence that it is CALLED is the precise confusion this gate exists to end.
//!
//! And one structural guarantee that is stronger than any of those filters: **every `construct`
//! needle in the declaration file must end in `(`**, checked by [`ROW_SCAN_FLOOR`] before a single
//! file is read. The gate cannot be *configured* to accept a non-call. A future editor cannot
//! quietly weaken a row to `construct = "signing_with"` and have it pass on a `use` line — the
//! declaration is refused outright.
//!
//! ## THE THREE OUTCOMES, KEPT APART
//!
//! * **A capability with a production construction site PASSES**, and its row prints the site.
//! * **An UNDECLARED capability with no production construction site is RED**, naming the
//!   capability and printing every mention it rejected, with the reason each was rejected — so the
//!   reader sees *five mentions, none of them a call* rather than a bare absence.
//! * **A DECLARED-UNSHIPPED one is a TRACKED ROW**: it passes, and it prints its reason and its
//!   switch on every run. That is the [`crate::gates::reachability`] `[[dormant]]` bargain, for the
//!   same reason — the three findings above were all *known* to somebody and written down nowhere a
//!   machine reads.
//!
//! and the ledger cannot outlive the debt: [`ROW_STALE`] reds when a declared-unshipped capability
//! ACQUIRES a production site (strike the row in the commit that wires it), or when a declaration
//! names a symbol that is no longer defined where it says.
//!
//! A declaration is refused if its reason is shorter than [`MIN_REASON`]. A shrug is not a reason.
//!
//! ## WHAT THIS GATE CAN AND CANNOT SEE — stated plainly, because the limits matter
//!
//! It reads SOURCE TEXT. It does not expand macros and it does not resolve types, so:
//!
//! * **It proves a production CALL SITE EXISTS in the declared scope. It does not prove that call
//!   is reached from `fn main()`.** That is [`crate::gates::reachability`]'s row, deliberately not
//!   re-implemented here, and the honest claim is the two together. A capability constructed only
//!   inside a function nothing calls would pass this gate and fail that one.
//! * **A construction reached only through MACRO EXPANSION is invisible to it** — that direction is
//!   a FALSE RED, which someone reads and answers, rather than a false green.
//! * **SO IS A CAPABILITY REACHED THROUGH A FUNCTION POINTER, A VTABLE SLOT OR FFI**, and this one
//!   bit a real sweep: `metrics_emit` (`crates/busbar-plugin/src/hot/host.rs:1146`,
//!   `crates/busbar-kernel/src/plane_host/vtable.rs:234`) is an `extern "C-unwind" fn` INSTALLED
//!   into a slot (`metrics_emit: Some(stub::metrics_emit)`, `host.rs:958`) and invoked by a plugin
//!   across the ABI. It is called by nobody BY NAME, so a call-shaped scan reports zero callers and
//!   is WRONG. The remedy is in the declaration, not the scanner: for such a capability the
//!   `construct` needle must be the INSTALLATION (`metrics_emit: Some(`), which is where the
//!   composition decision actually happens. A row whose needle is the call shape would be a false
//!   RED, and a reader who did not know this would answer it by deleting live code.
//! * **A needle is matched as TEXT, not resolved as a path.** `.signing_with(` on an unrelated type
//!   would count. The declaration's `scope` is what keeps that narrow, and it is why `scope` is
//!   per-capability rather than "the workspace".
//! * **Test scope is [`crate::scan::test_scope`]'s answer**, the one every other scanner in this
//!   crate uses, plus a path rule: a file under a `tests/` directory, or named `tests.rs` or
//!   `*_tests.rs`, is test code whatever its contents say.
//! * **IT DOES NOT SEE PROVEN INSTANCE 2, and no row here pretends otherwise.** `booked_lines()`
//!   IS called in production (`crates/busbar/src/root/units_admin/mod.rs:1419`); what is missing
//!   is a non-empty FEED, not a construction site. That is a neighbouring shape — *constructed,
//!   but with its input hardwired empty* — which a construction-site scanner cannot express. A row
//!   for it here would report GREEN and be worse than no row at all, so it is an OPEN ledger row
//!   instead.

use std::collections::{BTreeMap, BTreeSet};

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_rows_green, prove_rows_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::scan::{test_scope, ScopeLine};

/// Where the capability declarations live. DATA, not a Rust table: the whole point is that a human
/// writes the sentence and a reviewer reads it in a diff.
pub const DECLARATIONS: &str = "qa/unconstructed.toml";

/// A declaration shorter than this is a shrug, not a reason. The same figure
/// [`crate::gates::reachability::MIN_REASON`] and every other written excuse in this crate uses.
pub const MIN_REASON: usize = 40;

/// A `construct` needle shorter than this cannot be narrow enough to mean anything. `.f(` is three.
const MIN_NEEDLE: usize = 4;

const GATE: &str = "unconstructed";
const CLEAN: &str = "clean";
const DID_NOT_RUN: &str = "DID NOT RUN";

pub const ROW_SCAN_FLOOR: &str = "unconstructed:scan-floor";
pub const ROW_STALE: &str = "unconstructed:stale-declaration";

/// THE REVIEWED REGISTER OF UNSHIPPED CAPABILITIES — the ratchet the `unshipped` flag never had
/// (item 230).
///
/// `unshipped = true` in [`DECLARATIONS`] used to be the whole of the bargain, and the site row it
/// governs was `Row::pass` in BOTH branches, so it could not fail at all. A new money capability
/// found unconstructed could therefore be silenced BY ITS OWN AUTHOR in the commit that introduced
/// it — five lines of TOML with two 40-character sentences — and it would self-register as owed,
/// self-register as informational, and pass forever. Nothing capped how many rows carried the flag.
///
/// So the flag is honoured only for an id NAMED HERE. An `unshipped` declaration this list does not
/// name is RED on its own site row: a new "does not ship" is an edit to the gate, reviewed as one,
/// never a sentence in the file the gate reads. And the list cannot outlive its facts: an id here
/// that [`DECLARATIONS`] no longer declares `unshipped` reds [`ROW_STALE`], so the list only
/// shrinks as the debts drain. Armed 2026-09-23 at the eighteen the file declares today.
pub const KNOWN_UNSHIPPED: &[&str] = &[
    "audit-chain-signing",
    "breaker-request-budget",
    "breaker-error-map",
    "breaker-with-limits",
    "budget-pricer-card",
    "ledger-checkpoint-seal",
    "ledger-checkpoint-journal",
    // `ledger-adjusting-entries` STRUCK 2026-09-25 (#77(2)(3), Q36/Q9): the adjusting-entry code
    // is deleted; an amendment reprices as a view.
    // `money-one-function-view` STRUCK 2026-09-24 (owner ruling Q12/Q25c; item 421).
    "voice-denied-destinations",
    "plane-plugin-open",
    "export-plugin-open",
    // `wal-corruption-verdict` STRUCK 2026-09-24 (owner ruling Q38): recover_and_truncate branches
    // on the verdict and quarantines a Corrupt remainder before the cut.
    // `crash-recovery-open-holds` STRUCK 2026-09-24 (item 127): the boot path calls `recover_all`.
    "breaker-pool-observation",
    // `plugin-abi-keyed-units` STRUCK 2026-09-24 (owner ruling Q33d/Q35; item 123).
    "hold-late-accrual-parent-exit",
    // `rate-card-multi-currency` STRUCK 2026-09-25 (#66, spec Q4): `set_rate`/`set_fee` deleted.
    // The thirteen 1.6.0 admin verbs with no effect bound: not served (architect ruling
    // 2026-09-24); binding each strikes its row.
    "admin-verb-verify-effect",
    "admin-verb-plane-facts-effect",
    "admin-verb-plane-record-write-effect",
    "admin-verb-set-operator-key-effect",
    "admin-verb-set-escrow-effect",
    "admin-verb-set-dual-control-effect",
    "admin-verb-set-overdraft-ceiling-effect",
    "admin-verb-set-dispute-max-age-effect",
    "admin-verb-commit-upgrade-effect",
    "admin-verb-resolve-dispute-effect",
    "admin-verb-resolve-slice-effect",
    "admin-verb-export-keyset-effect",
    "admin-verb-approve-effect",
];

/// The per-capability row id.
pub fn row_site(id: &str) -> String {
    format!("unconstructed:site:{id}")
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE DECLARATION
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// One declared capability: what it is, where it is BUILT, what CONSTRUCTING it looks like, and
/// where a production construction site would have to be.
#[derive(Debug, Clone)]
struct Capability {
    id: String,
    /// The file the capability is implemented in. Must be readable and must define `symbol`.
    built: String,
    /// The item name whose definition must exist in `built` — the staleness anchor.
    symbol: String,
    /// The call shapes that count. ANY one of them is a construction site. Each must end in `(`.
    construct: Vec<String>,
    /// The roots a production construction site must appear under.
    scope: Vec<String>,
    why: String,
    /// `true` when this capability is KNOWN not to ship. It passes and prints.
    unshipped: bool,
    /// The event that retires an `unshipped` row. Required when `unshipped`.
    switch: String,
}

fn declarations(cx: &Ctx) -> Result<Vec<Capability>, String> {
    let text = cx.read(DECLARATIONS).map_err(|e| {
        format!(
            "{DECLARATIONS} could not be read ({e}). An absent declaration file reads exactly like \
             a tree with nothing to declare; it is not one."
        )
    })?;
    let doc = crate::toml_doc::parse_str(&text)
        .map_err(|e| format!("{DECLARATIONS} does not parse: {e}"))?;
    Ok(doc
        .array_of_tables("capability")
        .into_iter()
        .map(|t| Capability {
            id: t.str_of("id").unwrap_or_default().to_string(),
            built: t.str_of("built").unwrap_or_default().to_string(),
            symbol: t.str_of("symbol").unwrap_or_default().to_string(),
            construct: t.list_of("construct"),
            scope: t.list_of("scope"),
            why: t.str_of("why").unwrap_or_default().to_string(),
            unshipped: t.bool_of("unshipped").unwrap_or(false),
            switch: t.str_of("switch").unwrap_or_default().to_string(),
        })
        .collect())
}

/// EVERY WAY A DECLARATION CAN BE MALFORMED, checked before anything is measured.
///
/// A row that does not parse into a rule is not a rule that passes — it is a rule that is not
/// there, which is the exact shape of the failure this whole gate is about.
fn declaration_faults(caps: &[Capability]) -> Vec<String> {
    let mut faults = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for c in caps {
        if c.id.is_empty() {
            faults.push("a [[capability]] row has no `id`".to_string());
            continue;
        }
        if !seen.insert(c.id.as_str()) {
            faults.push(format!("`{}` is declared twice", c.id));
        }
        if c.built.is_empty() {
            faults.push(format!("`{}` names no `built` file", c.id));
        }
        if c.symbol.is_empty() {
            faults.push(format!("`{}` names no `symbol`", c.id));
        }
        if c.scope.is_empty() {
            faults.push(format!("`{}` names no `scope`", c.id));
        }
        if c.construct.is_empty() {
            faults.push(format!("`{}` names no `construct` needle", c.id));
        }
        // THE STRUCTURAL GUARANTEE. A needle that is not call-shaped would let a `use` line, a
        // type alias or a bare mention satisfy the rule, which is the one thing this gate exists
        // to refuse. It is checked here, on the DECLARATION, so the refusal cannot be edited away
        // one row at a time.
        for n in &c.construct {
            if !n.ends_with('(') {
                faults.push(format!(
                    "`{}` declares construct needle {n:?}, which does not end in `(`. A \
                     construction site is a CALL; a needle that is not call-shaped would be \
                     satisfied by a `use` statement, a doc comment or a type alias, and those are \
                     precisely the decorations this gate refuses to accept as evidence",
                    c.id
                ));
            }
            if n.len() < MIN_NEEDLE {
                faults.push(format!(
                    "`{}` declares construct needle {n:?}, shorter than {MIN_NEEDLE} characters — \
                     too broad to mean anything",
                    c.id
                ));
            }
        }
        if c.why.len() < MIN_REASON {
            faults.push(format!(
                "`{}` carries a {}-character `why`; {MIN_REASON} is the floor — a shrug is not a \
                 reason",
                c.id,
                c.why.len()
            ));
        }
        if c.unshipped && c.switch.len() < MIN_REASON {
            faults.push(format!(
                "`{}` is declared `unshipped` with a {}-character `switch`; an unshipped row \
                 without the event that retires it is a debt with no expiry, which is the state \
                 this file exists to end",
                c.id,
                c.switch.len()
            ));
        }
    }
    faults
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE SCAN
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// One file, read once, carrying the two facts every rule below needs.
struct Scanned {
    rel: String,
    lines: Vec<ScopeLine>,
    /// A path that is test code whatever its contents say.
    test_path: bool,
}

/// A file under a `tests/` directory, or named `tests.rs` / `*_tests.rs`, is test code. This is the
/// PATH half of the answer; [`test_scope`] is the CONTENTS half, and both are applied.
fn path_is_test(rel: &str) -> bool {
    rel.contains("/tests/")
        || rel.ends_with("/tests.rs")
        || rel.ends_with("_tests.rs")
        || rel.contains("/benches/")
        || rel.contains("/fuzz/")
}

/// Walk one scope root. Cached by the caller: two capabilities naming the same scope read it once.
fn scan_root(cx: &Ctx, root: &str) -> Result<Vec<Scanned>, String> {
    let spec = WalkSpec::new([root.to_string()])
        .ext("rs")
        .exclude([".claude/".to_string(), "/target/".to_string()])
        .min_files(1);
    let files = cx
        .walk(&spec)
        .map_err(|e| format!("{root} could not be walked: {e}"))?;
    Ok(files
        .into_iter()
        .map(|f| {
            let rel = f.rel_str();
            Scanned {
                lines: test_scope(&f.text),
                test_path: path_is_test(&rel),
                rel,
            }
        })
        .collect())
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// WHAT COUNTS, AND WHAT WAS REJECTED AND WHY
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// One line that MENTIONS a capability, and the verdict on it.
#[derive(Debug, Clone)]
struct Mention {
    rel: String,
    no: usize,
    text: String,
    /// `None` when it counts as a construction site; `Some(reason)` when it was rejected.
    rejected: Option<String>,
}

impl Mention {
    fn cite(&self) -> String {
        match &self.rejected {
            None => format!("{}:{} `{}`", self.rel, self.no, self.text),
            Some(why) => format!(
                "{}:{} ({why}) `{}`",
                self.rel,
                self.no,
                why_free(&self.text)
            ),
        }
    }
}

fn why_free(t: &str) -> &str {
    t
}

/// THE ANTI-DECORATION RULE, in one function.
///
/// Read off `counted` — the copy with literal and comment bodies blanked — so a name inside a
/// string or a doc comment cannot match at all. Everything that survives that is then rejected by
/// SHAPE if it is one of the four disguises.
fn classify(line: &ScopeLine, rel: &str, test_path: bool, symbol: &str) -> Option<String> {
    if test_path {
        return Some("test path".to_string());
    }
    if line.gated {
        return Some("test scope (#[cfg(test)])".to_string());
    }
    if line.is_comment {
        return Some("comment".to_string());
    }
    let t = line.code.trim_start();
    if t.starts_with("use ") || t.starts_with("pub use ") {
        return Some("`use` statement — importing a capability is not calling it".to_string());
    }
    if t.starts_with("#[") || t.starts_with("#![") {
        return Some("attribute".to_string());
    }
    if t.starts_with("type ") || t.starts_with("pub type ") {
        return Some("type alias".to_string());
    }
    if t.starts_with("mod ") || t.starts_with("pub mod ") {
        return Some("module declaration".to_string());
    }
    if is_fn_decl(t) && word_hit(t, symbol) {
        return Some(format!(
            "the definition of `{symbol}` itself — where it is BUILT, not where it is CALLED"
        ));
    }
    let _ = rel;
    None
}

/// `fn`, with only visibility and qualifier words before it. The word `fn` inside a literal cannot
/// reach here — this reads the comment- and literal-aware `code`.
fn is_fn_decl(code: &str) -> bool {
    let mut seen_fn = false;
    for w in code.split_whitespace() {
        let w = w.trim_start_matches('(');
        if w == "fn" {
            seen_fn = true;
            break;
        }
        if !matches!(
            w,
            "pub" | "const" | "async" | "unsafe" | "extern" | "default" | "#[must_use]"
        ) && !w.starts_with("pub(")
        {
            return false;
        }
    }
    seen_fn
}

/// A whole-word hit where the identifier boundary is `[^A-Za-z0-9_]`.
fn word_hit(hay: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let mut from = 0;
    while let Some(i) = hay[from..].find(needle) {
        let at = from + i;
        let before = hay[..at].chars().next_back();
        let after = hay[at + needle.len()..].chars().next();
        let ok_b = before.is_none_or(|c| !is_word_char(c));
        let ok_a = after.is_none_or(|c| !is_word_char(c));
        if ok_b && ok_a {
            return true;
        }
        from = at + needle.len();
    }
    false
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Every mention of `cap`'s construct needles under its scope, each already judged.
fn mentions(files: &[&Scanned], cap: &Capability) -> Vec<Mention> {
    let mut out = Vec::new();
    for f in files {
        for line in &f.lines {
            // THE SEARCH IS OVER `counted`, NEVER `code`: a needle inside a string literal or a
            // doc comment is blanked there and cannot match. This is the first and strongest of
            // the anti-decoration filters, and it is applied before any shape rule.
            let hit = cap.construct.iter().any(|n| line.counted.contains(n));
            if !hit {
                continue;
            }
            out.push(Mention {
                rel: f.rel.clone(),
                no: line.no,
                text: line.code.trim().to_string(),
                rejected: classify(line, &f.rel, f.test_path, &cap.symbol),
            });
        }
    }
    out
}

/// Is `symbol` DEFINED in `built`? The staleness anchor: a declaration about a capability that no
/// longer exists is a row that outlived its subject.
fn defines(text: &str, symbol: &str) -> bool {
    test_scope(text).iter().any(|l| {
        let t = l.code.trim_start();
        !l.is_comment && is_fn_decl(t) && word_hit(t, symbol)
    })
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// THE VERDICT
// ─────────────────────────────────────────────────────────────────────────────────────────────

fn all_rows_did_not_run(caps: &[Capability], why: &str) -> Verdict {
    let mut rows = vec![Row::fail(
        ROW_SCAN_FLOOR,
        "the declared capabilities could not be measured",
        format!("{why} — {DID_NOT_RUN}"),
    )];
    rows.push(Row::fail(ROW_STALE, "the scan did not run", DID_NOT_RUN));
    for c in caps {
        rows.push(Row::fail(
            row_site(&c.id),
            "the scan did not run",
            DID_NOT_RUN,
        ));
    }
    Verdict::of(rows)
}

pub struct UnconstructedGate;

impl Gate for UnconstructedGate {
    fn name(&self) -> &'static str {
        GATE
    }

    fn owed(&self) -> Vec<String> {
        // THE OWED SET IS READ OFF THE DECLARATION FILE, because the rows ARE the declarations.
        // A capability added to the file without being measured, or measured without being owed,
        // is exactly the reconciliation failure `execute` exists to catch.
        let mut ids = vec![ROW_SCAN_FLOOR.to_string(), ROW_STALE.to_string()];
        if let Ok(caps) = Ctx::workspace().and_then(|cx| declarations(&cx)) {
            for c in &caps {
                if !c.id.is_empty() {
                    ids.push(row_site(&c.id));
                }
            }
        }
        ids.sort();
        ids.dedup();
        ids
    }

    /// THE REVIEWED DECLARED-UNSHIPPED ROWS, and only those.
    ///
    /// A row for a capability declared `unshipped` AND named in [`KNOWN_UNSHIPPED`] PASSES whether
    /// a construction site is found or not — that is the whole bargain — so no plant over the tree
    /// can drive it RED. It is still exercised by the green case, still reconciled, and the day it
    /// acquires a site [`ROW_STALE`] reds instead. An `unshipped` row the register does NOT name is
    /// not informational: it is red, and the self-test proves it.
    fn informational(&self) -> Vec<String> {
        match Ctx::workspace().and_then(|cx| declarations(&cx)) {
            Ok(caps) => caps
                .iter()
                .filter(|c| c.unshipped && !c.id.is_empty())
                .filter(|c| KNOWN_UNSHIPPED.contains(&c.id.as_str()))
                .map(|c| row_site(&c.id))
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let caps = match declarations(cx) {
            Ok(c) => c,
            Err(e) => return all_rows_did_not_run(&[], &e),
        };

        // THE DECLARATION IS CHECKED BEFORE THE TREE IS READ. A malformed row is not a rule that
        // passes; it is a rule that is not there.
        let faults = declaration_faults(&caps);
        if !faults.is_empty() {
            return all_rows_did_not_run(
                &caps,
                &format!("{DECLARATIONS} is malformed: {}", faults.join("; ")),
            );
        }

        // Every scope root, walked once.
        let mut roots: BTreeSet<String> = BTreeSet::new();
        for c in &caps {
            roots.extend(c.scope.iter().cloned());
        }
        let mut scanned: BTreeMap<String, Vec<Scanned>> = BTreeMap::new();
        for r in &roots {
            match scan_root(cx, r) {
                Ok(f) => {
                    scanned.insert(r.clone(), f);
                }
                Err(e) => return all_rows_did_not_run(&caps, &e),
            }
        }
        let total: usize = scanned.values().map(Vec::len).sum();

        // Every `built` file, read once. Unreadable is infrastructure (scan-floor); readable but
        // no longer defining the symbol is staleness.
        let mut built_text: BTreeMap<String, String> = BTreeMap::new();
        for c in &caps {
            if built_text.contains_key(&c.built) {
                continue;
            }
            match cx.read(&c.built) {
                Ok(t) => {
                    built_text.insert(c.built.clone(), t);
                }
                Err(e) => {
                    return all_rows_did_not_run(
                        &caps,
                        &format!(
                            "`{}` declares it is built in {}, which could not be read ({e}). A \
                             capability whose implementation this gate cannot find is one it \
                             cannot judge",
                            c.id, c.built
                        ),
                    )
                }
            }
        }

        let mut rows = vec![Row::pass(
            ROW_SCAN_FLOOR,
            "the declarations parsed, every construct needle is call-shaped, and every scope was \
             walked",
            format!(
                "{CLEAN} — {} capability declaration(s) in {DECLARATIONS}, {} scope root(s), {} \
                 file(s) scanned, {} implementation file(s) read; every `construct` needle ends in \
                 `(` so no `use`, doc comment or type alias can satisfy a row",
                caps.len(),
                roots.len(),
                total,
                built_text.len()
            ),
        )];

        let mut stale: Vec<String> = Vec::new();

        for c in &caps {
            let files: Vec<&Scanned> = c
                .scope
                .iter()
                .filter_map(|r| scanned.get(r))
                .flatten()
                .collect();
            let all = mentions(&files, c);
            let (sites, rejected): (Vec<&Mention>, Vec<&Mention>) =
                all.iter().partition(|m| m.rejected.is_none());

            // STALENESS, half one: the declaration's subject must still exist.
            if let Some(t) = built_text.get(&c.built) {
                if !defines(t, &c.symbol) {
                    stale.push(format!(
                        "`{}` declares `{}` is built in {}, which defines no such item. A \
                         declaration cannot outlive its subject — strike the row or correct it",
                        c.id, c.symbol, c.built
                    ));
                }
            }

            let id = row_site(&c.id);
            if sites.is_empty() {
                let detail = format!(
                    "NO PRODUCTION CONSTRUCTION SITE for `{}` (built in {}, construct {:?}) \
                     anywhere under {:?}. {} mention(s) found and every one was rejected: {}. \
                     A CAPABILITY THAT IS NEVER CONSTRUCTED IS A CAPABILITY THAT DOES NOT SHIP — \
                     its tests prove the code works; they prove nothing about whether it runs. \
                     Wire it at the composition root, or declare it `unshipped = true` in \
                     {DECLARATIONS} with the reason and the switch that retires the row. WHY THIS \
                     CAPABILITY MATTERS: {}",
                    c.symbol,
                    c.built,
                    c.construct,
                    c.scope,
                    rejected.len(),
                    if rejected.is_empty() {
                        "(none — the name appears nowhere in scope at all)".to_string()
                    } else {
                        rejected
                            .iter()
                            .take(12)
                            .map(|m| m.cite())
                            .collect::<Vec<_>>()
                            .join("; ")
                    },
                    c.why
                );
                if c.unshipped && !KNOWN_UNSHIPPED.contains(&c.id.as_str()) {
                    rows.push(Row::fail(
                        id,
                        format!(
                            "`{}` is declared unshipped but is NOT on the reviewed register",
                            c.id
                        ),
                        format!(
                            "SELF-DECLARED UNSHIPPED: `{}` carries `unshipped = true` in \
                             {DECLARATIONS} and is not named in KNOWN_UNSHIPPED \
                             (xtask/src/gates/unconstructed.rs). A declaration may not silence its \
                             own capability: a new \"does not ship\" is an edit to the gate's \
                             register, reviewed as one. {} REASON: {} SWITCH: {}",
                            c.id, detail, c.why, c.switch
                        ),
                    ));
                } else if c.unshipped {
                    rows.push(Row::pass(
                        id,
                        format!("`{}` — DECLARED UNSHIPPED, tracked", c.id),
                        format!(
                            "DECLARED-UNSHIPPED and therefore not red, but it does NOT run. {} \
                             REASON: {} SWITCH: {}",
                            detail, c.why, c.switch
                        ),
                    ));
                } else {
                    rows.push(Row::fail(
                        id,
                        format!("`{}` is never constructed in production", c.id),
                        detail,
                    ));
                }
            } else {
                let cites: Vec<String> = sites.iter().take(6).map(|m| m.cite()).collect();
                if c.unshipped {
                    // STALENESS, half two: the debt was paid and the row was not struck.
                    stale.push(format!(
                        "`{}` is declared `unshipped` but NOW HAS {} production construction \
                         site(s): {}. The ledger cannot outlive the debt it tracked — strike the \
                         row in the same commit that wired it",
                        c.id,
                        sites.len(),
                        cites.join("; ")
                    ));
                }
                rows.push(Row::pass(
                    id,
                    format!("`{}` is constructed in production", c.id),
                    format!(
                        "{CLEAN} — {} production construction site(s) for `{}`: {}{} ({} \
                         decorative or test mention(s) rejected)",
                        sites.len(),
                        c.symbol,
                        cites.join("; "),
                        if sites.len() > cites.len() {
                            ", …"
                        } else {
                            ""
                        },
                        rejected.len()
                    ),
                ));
            }
        }

        // STALENESS, half three: the register cannot outlive the declarations it reviews.
        for known in KNOWN_UNSHIPPED {
            if !caps.iter().any(|c| c.unshipped && c.id == *known) {
                stale.push(format!(
                    "`{known}` is on the KNOWN_UNSHIPPED register and {DECLARATIONS} no longer \
                     declares it `unshipped` — strike it from the register in the same commit, or \
                     the register becomes room for the next self-declared debt"
                ));
            }
        }

        rows.push(if stale.is_empty() {
            Row::pass(
                ROW_STALE,
                "no declaration outlived its subject",
                format!(
                    "{CLEAN} — every declared capability is still defined where it says, and no \
                     `unshipped` row has quietly acquired a construction site ({} row(s) checked)",
                    caps.len()
                ),
            )
        } else {
            Row::fail(
                ROW_STALE,
                "a declaration outlived the debt it tracked",
                stale.join(" | "),
            )
        });

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();

        // THE PLANTS ARE OVER THE REAL TREE, not a fixture tree. This gate's entire subject is THIS
        // repository's composition root, and a fixture would prove the predicate without proving it
        // is about anything. Every plant below edits one real file IN AN OVERLAY, which lives in
        // this process and writes no byte to disk.
        const DURABILITY: &str = "crates/busbar/src/root/durability/mod.rs";
        const SETTLE: &str = "crates/busbar-kernel-ledger/src/settle.rs";
        const REAL_SITE: &str = "ledger: Ledger::dual_writing(legacy_rows),";

        let real = cx.read(DURABILITY).unwrap_or_default();
        let decls = cx.read(DECLARATIONS).unwrap_or_default();

        // ── THE ONE STANDING RED THESE CONTROLS MUST NOT STAND ON (item 89). ────────────────
        // `money-one-function-view` is declared `unshipped` and HAS a production construction
        // site today, so `stale-declaration` is RED on the real tree. That is a money row, PARKED
        // for its owner, and this selftest does not answer it: `gate unconstructed` stays RED on
        // it. But every control that covers `stale-declaration` (and the whole-gate green arm)
        // would then be planting into a row that is already red — PROOF IMPOSSIBLE, and the
        // harness said so. So those controls run over a FIXTURE: the real tree with that one
        // site's needle masked, i.e. the tree as the declaration still describes it. Everything
        // else those controls read is the real tree, and every other control is unchanged.
        let masked = parked_money_masked(cx);
        let base = cx.with_overlay(masked.clone());
        let on_base = |path: &str, content: String| {
            let mut ov = masked.clone();
            ov.set(path, content);
            ov
        };

        // ── CONTROL 1 — THE GREEN ARM. ──────────────────────────────────────────────────────
        // The unplanted tree must be green, or every RED below proves only that the gate is red
        // about everything. It covers EVERY owed row, which is what makes the informational
        // `unshipped` rows exercised rather than merely declared.
        let owed: Vec<String> = self.owed();
        report.push(prove_green(
            &base,
            self,
            "the real tree, with the one parked money site masked, is GREEN: every declared \
             capability is constructed, or declared unshipped and still unconstructed",
            &owed.iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        // ── CONTROL 2 — THE RED ARM: REMOVE A REAL CONSTRUCTION SITE. ───────────────────────
        // `Ledger::dual_writing` IS constructed on HEAD. Take that one call away — the exact edit
        // a refactor would make — and the gate must go RED naming that capability. This is what
        // makes control 1's green a measurement rather than a default.
        let gone = real.replace(REAL_SITE, "ledger: Ledger::new(),");
        report.push(prove_rows_red(
            cx,
            self,
            "removing the real `Ledger::dual_writing` construction site reds its row, BY NAME",
            &[&row_site("ledger-dual-write")],
            {
                let mut ov = Overlay::new();
                ov.set(DURABILITY, gone.clone());
                ov
            },
            &["NO PRODUCTION CONSTRUCTION SITE", "dual_writing"],
        ));

        // ── CONTROL 3 — DECORATION IS NOT CONSTRUCTION. ─────────────────────────────────────
        // The call is replaced by four disguises at once, all naming the capability in full: a doc
        // comment, a commented-out call, a string literal, and a trailing comment. The row must
        // STAY RED. A gate that passed this would be satisfied by a MENTION — which is exactly what
        // the three proven instances looked like from a distance.
        let decorated = format!(
            "{}\n",
            gone.replace(
                "ledger: Ledger::new(),",
                "ledger: Ledger::new(), // Ledger::dual_writing(legacy_rows) is the strong form\n\
                 /// This node uses Ledger::dual_writing(legacy_rows) for reconciliation.\n\
                 // let _ = Ledger::dual_writing(legacy_rows);\n\
                 // const NOTE: &str = \"Ledger::dual_writing(legacy_rows)\";",
            )
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a doc comment, a commented-out call and a string literal naming the capability in \
             full do NOT satisfy the row",
            &[&row_site("ledger-dual-write")],
            {
                let mut ov = Overlay::new();
                ov.set(DURABILITY, decorated);
                ov
            },
            &["NO PRODUCTION CONSTRUCTION SITE", "dual_writing"],
        ));

        // ── CONTROL 4 — A `use` LINE IS NOT A CONSTRUCTION SITE. ────────────────────────────
        // Deliberately adversarial TEXT rather than valid Rust: the gate is a text scanner, so the
        // question is whether the SCANNER can be fooled by an import that carries the needle, not
        // whether rustc would accept the bait. The row must stay red AND say `use` statement.
        let imported = format!(
            "use crate::root::Ledger::dual_writing();\ntype AlsoDualWriting = Ledger::dual_writing();\n{gone}"
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a `use` line and a type alias carrying the needle do NOT satisfy the row",
            &[&row_site("ledger-dual-write")],
            {
                let mut ov = Overlay::new();
                ov.set(DURABILITY, imported);
                ov
            },
            &["NO PRODUCTION CONSTRUCTION SITE", "use` statement"],
        ));

        // ── CONTROL 5 — A TEST-ONLY CALL IS NOT A PRODUCTION SITE. ──────────────────────────
        // THE EXACT SHAPE OF THE PROVEN AUDIT-SIGNING FINDING: a real call, in a real production
        // file, under `#[cfg(test)]`. Sixteen green tests are what this looks like from the inside.
        let test_only = format!(
            "{gone}\n#[cfg(test)]\nmod planted {{\n    fn f() {{ let _ = Ledger::dual_writing(rows); }}\n}}\n"
        );
        report.push(prove_rows_red(
            cx,
            self,
            "a real call under #[cfg(test)] does NOT count as a production construction site",
            &[&row_site("ledger-dual-write")],
            {
                let mut ov = Overlay::new();
                ov.set(DURABILITY, test_only);
                ov
            },
            &["NO PRODUCTION CONSTRUCTION SITE", "test scope"],
        ));

        // ── CONTROL 6 — THE GATE CAN SEE A CONSTRUCTION WHEN ONE APPEARS. ───────────────────
        // The counterpart of control 2, and the one that proves the gate is not simply blind to
        // this needle: WIRE THE AUDIT SIGNER — the real, proven-unconstructed capability — and the
        // debt row must be caught as STALE, because the declaration now says something false.
        let signed = real.replace(
            "record: AuditChain::new(),",
            "record: AuditChain::new().signing_with(key),",
        );
        report.push(prove_rows_red(
            &base,
            self,
            "wiring the audit signer reds `stale-declaration`: an unshipped row that ACQUIRES a \
             construction site must be struck",
            &[ROW_STALE],
            on_base(DURABILITY, signed),
            &["declared `unshipped` but NOW HAS", "audit-chain-signing"],
        ));

        // ── CONTROL 7 — A NON-CALL NEEDLE IS REFUSED AT THE DECLARATION. ────────────────────
        // The gate cannot be CONFIGURED to accept decoration. Weakening a row's needle to a bare
        // name is refused outright rather than quietly passing on the `use` line control 4 plants.
        report.push(prove_rows_red(
            cx,
            self,
            "a `construct` needle that is not call-shaped is REFUSED, so no row can be weakened \
             into accepting a mention",
            &[ROW_SCAN_FLOOR],
            {
                let mut ov = Overlay::new();
                ov.set(
                    DECLARATIONS,
                    decls.replace(
                        "construct = [\"Ledger::dual_writing(\"]",
                        "construct = [\"dual_writing\"]",
                    ),
                );
                ov
            },
            &["does not end in `(`"],
        ));

        // ── CONTROL 8 — A SHRUG IS NOT A REASON. ────────────────────────────────────────────
        report.push(prove_rows_red(
            cx,
            self,
            "an `unshipped` row whose `switch` is a shrug is refused: a debt with no expiry is the \
             state this file exists to end",
            &[ROW_SCAN_FLOOR],
            {
                let mut ov = Overlay::new();
                let mut lines: Vec<String> = decls.lines().map(str::to_string).collect();
                for l in &mut lines {
                    if l.starts_with("switch    =") {
                        *l = "switch    = \"soon\"".to_string();
                    }
                }
                ov.set(DECLARATIONS, lines.join("\n"));
                ov
            },
            &["a debt with no expiry"],
        ));

        // ── CONTROL 9 — AN ABSENT DECLARATION FILE IS A GAP, NEVER A PASS. ──────────────────
        // A gate that cannot find its subject reports that. An empty declaration file and a tree
        // with nothing to declare must never produce the same output.
        report.push(prove_rows_red(
            cx,
            self,
            "an absent declaration file is DID NOT RUN, never a green tree",
            &[ROW_SCAN_FLOOR],
            {
                let mut ov = Overlay::new();
                ov.remove(DECLARATIONS);
                ov
            },
            &[DID_NOT_RUN],
        ));

        // ── CONTROL 10 — A DECLARATION THAT OUTLIVED ITS SUBJECT. ───────────────────────────
        report.push(prove_rows_red(
            &base,
            self,
            "a declaration naming a symbol its `built` file no longer defines reds \
             `stale-declaration`",
            &[ROW_STALE],
            on_base(
                SETTLE,
                cx.read(SETTLE)
                    .unwrap_or_default()
                    .replace("pub fn dual_writing(", "pub fn renamed_away("),
            ),
            &["defines no such item"],
        ));

        // ── CONTROL 12 — A SELF-DECLARED UNSHIPPED CAPABILITY IS RED (item 230). ────────────
        // The five-line silencing, planted: a new capability declared `unshipped` with a full
        // reason and switch, in the declaration file only. Its row must RED, because the register
        // the gate holds does not name it.
        report.push(prove_rows_red(
            cx,
            self,
            "an `unshipped` declaration the reviewed register does not name reds its own row",
            &[&row_site(PLANTED_UNSHIPPED)],
            {
                let mut ov = Overlay::new();
                ov.set(
                    DECLARATIONS,
                    format!("{decls}\n{}", planted_unshipped_toml()),
                );
                ov
            },
            &["SELF-DECLARED UNSHIPPED", PLANTED_UNSHIPPED],
        ));

        // ── CONTROL 11 — RESTORING THE SITE RETURNS THE ROW TO GREEN. ───────────────────────
        // Control 2's overlay with the call put back. This is what proves control 2's RED is about
        // THE MISSING CALL and not about the edit, the overlay, or the file having been touched.
        //
        // THE BASELINE IS CONTROL 2'S PLANTED TREE, not the real one (item 209). Taken over the
        // real tree, "put the call back" wrote the bytes `durability.rs` already has — a plant that
        // planted nothing, so its green was a statement about the unplanted tree. Over the tree
        // with the site REMOVED, restoring it is a real edit, and the row going green is the
        // restoration's doing.
        let site_removed = {
            let mut ov = Overlay::new();
            ov.set(DURABILITY, gone.clone());
            cx.with_overlay(ov)
        };
        report.push(prove_rows_green(
            &site_removed,
            self,
            "restoring the construction site returns the row to GREEN",
            &[&row_site("ledger-dual-write")],
            {
                let mut ov = Overlay::new();
                ov.set(
                    DURABILITY,
                    gone.replace("ledger: Ledger::new(),", REAL_SITE),
                );
                ov
            },
        ));

        report
    }
}

/// The production file carrying the construction site that makes `money-one-function-view` stale,
/// and the needle there. PARKED-OWNER money: the selftest masks it for its `stale-declaration`
/// controls and answers nothing about it. Once the owner's ruling lands (the row struck, or the
/// site removed) the needle is gone and the mask is empty, so it cannot hide anything else.
const PARKED_MONEY_SITE: &str = "crates/busbar-core-admin/src/v1/service.rs";
const PARKED_MONEY_NEEDLE: &str = "LedgerEntry::new(";

/// The fixture overlay: [`PARKED_MONEY_SITE`] with [`PARKED_MONEY_NEEDLE`] rewritten to a name no
/// declaration constructs, or an empty overlay when the needle is not there.
fn parked_money_masked(cx: &Ctx) -> Overlay {
    let mut ov = Overlay::new();
    if let Ok(text) = cx.read(PARKED_MONEY_SITE) {
        if text.contains(PARKED_MONEY_NEEDLE) {
            ov.set(
                PARKED_MONEY_SITE,
                text.replace(PARKED_MONEY_NEEDLE, "LedgerEntry::parked_owner_masked("),
            );
        }
    }
    ov
}

/// The id of the self-test's planted, self-declared unshipped capability.
const PLANTED_UNSHIPPED: &str = "planted-self-silenced-money";

/// A well-formed `unshipped` declaration naming a real, unconstructed symbol, and naming an id the
/// register does not carry — the five-line silencing item 230 describes.
fn planted_unshipped_toml() -> String {
    format!(
        "[[capability]]\n\
         id        = \"{PLANTED_UNSHIPPED}\"\n\
         built     = \"crates/busbar-kernel-ledger/src/settle.rs\"\n\
         symbol    = \"dual_writing\"\n\
         construct = [\"Ledger::planted_never_called(\"]\n\
         scope     = [\"crates\"]\n\
         why       = \"a money capability found unconstructed and silenced by its own author in one commit\"\n\
         unshipped = true\n\
         switch    = \"the commit that wires it at the composition root and strikes this declaration\"\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::Status;

    /// ITEM 230: an `unshipped` declaration the reviewed register does not name is RED on its own
    /// site row — the flag no longer silences a capability its author just introduced.
    #[test]
    fn a_self_declared_unshipped_capability_is_red() {
        let cx = Ctx::workspace().expect("workspace context");
        let decls = cx.read(DECLARATIONS).expect("declarations");
        let mut ov = Overlay::new();
        ov.set(
            DECLARATIONS,
            format!("{decls}\n{}", planted_unshipped_toml()),
        );
        let verdict = UnconstructedGate.run(&cx.with_overlay(ov));
        let row = verdict
            .rows
            .iter()
            .find(|r| r.id == row_site(PLANTED_UNSHIPPED))
            .expect("the planted capability has a row");
        assert_eq!(row.status, Status::Fail, "{}", row.detail);
        assert!(
            row.detail.contains("SELF-DECLARED UNSHIPPED"),
            "{}",
            row.detail
        );
    }

    /// The register and the declaration file agree today: every id on the register is declared
    /// `unshipped`, and every `unshipped` declaration is on the register.
    #[test]
    fn the_register_matches_the_declarations() {
        let cx = Ctx::workspace().expect("workspace context");
        let caps = declarations(&cx).expect("declarations");
        let declared: BTreeSet<&str> = caps
            .iter()
            .filter(|c| c.unshipped)
            .map(|c| c.id.as_str())
            .collect();
        let known: BTreeSet<&str> = KNOWN_UNSHIPPED.iter().copied().collect();
        assert_eq!(declared, known);
    }
}
