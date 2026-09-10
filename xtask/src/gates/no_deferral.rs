//! `cargo xtask gate no-deferral` — THE NO-DEFERRAL GATE. The successor to
//! `scripts/no-deferral-gate.sh`, claim for claim, plus its `--strict-done` twin registered under
//! its own name (`no-deferral-strict-done`) rather than hidden behind a boolean.
//!
//! THE SINGLE CLAIM: the shipped source tree contains nothing known-and-deferred. Every capability
//! the tree DECLARES it also IMPLEMENTS — no `todo!()` a caller can reach, no self-labelled
//! "SKELETON / dev-only until DoD" a shipping feature depends on. Two orthogonal detectors:
//!
//! * **Class A** — a deferral MACRO invocation, matched ANYWHERE on the COMMENT-STRIPPED line. It
//!   is the comment strip that excludes prose, never a position anchor: an anchor at line start
//!   also excluded `_ => todo!(…)`, `let v = unimplemented!();` and `fn f() -> u8 { todo!() }`,
//!   which are reachable deferrals and are how most of them are actually written.
//! * **Class B** — a deferral PHRASE the author self-declares, matched on the RAW line, because
//!   comments are exactly where those labels live.
//!
//! `#[cfg(test)]` scaffolding is out of scope for both — but the predicate is matched AS A
//! PREDICATE, not hunted for as a substring: `#[cfg(not(test))]` is the arm that SHIPS, and a
//! substring hunt for the word `test` turned the scaffolding exclusion into a way to hide a
//! deferral in the one place that guarantees users reach it.
//!
//! ## Four rows, and each is a refusal the shell learned the hard way
//!
//! | row | the refusal |
//! | --- | --- |
//! | `:waiver-shape` | every waiver row is an exact `path:line` carrying an expiry that RESOLVES |
//! | `:discovery-floor` | a scan below [`DISCOVERY_FLOOR`] files is UNPROVEN, never PASS |
//! | `:unwaived` | over-count: a marker nobody waived is a new, undeclared deferral |
//! | `:stale-waiver` | under-count: a waiver matching no marker outlived the thing it excused |
//! | `:strict-done` | (strict only) the only permanent exemptions are the `*/hot/*` fixtures |
//!
//! **THE FLOOR IS ON THE RUN PATH.** In the shell it lived only in `--selftest`, and the self-test
//! is not the mode anything blocks on: a tree where discovery came back empty printed PASS, and
//! `--strict-done` — the mode the release verification calls to decide this version is done — went
//! on to certify that the tracked debt was cleared having examined nothing at all. Below the floor
//! the floor row is FAIL and every other row is SKIP, which the reconciler reds by name: "did not
//! run" and "ran and found nothing" are two facts and this gate keeps them apart.
//!
//! **NO GLOBS.** One un-expiring glob row (`crates/busbar-plugin/src/hot/*`) once covered all 52
//! markers of a whole directory and would have covered any number more, forever: the stale-waiver
//! check cannot fire on a glob while even one of its markers survives, so 51 could be resolved with
//! the row still reading as live. A matcher that is not an exact `path:line` is refused at load.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;
use crate::scan;

pub const ROW_WAIVER_SHAPE: &str = "no-deferral:waiver-shape";
pub const ROW_DISCOVERY_FLOOR: &str = "no-deferral:discovery-floor";
pub const ROW_UNWAIVED: &str = "no-deferral:unwaived";
pub const ROW_STALE_WAIVER: &str = "no-deferral:stale-waiver";
pub const ROW_STRICT_DONE: &str = "no-deferral:strict-done";

/// The denominator floor, a `const` in the gate's own module with no environment override. The
/// only way to lower one is a reviewable source edit.
pub const DISCOVERY_FLOOR: usize = 50;

const WAIVERS: &str = "scripts/no-deferral.waivers";
const TRACKER: &str = "docs/design/1.6.0-TRACKER.md";

#[derive(Debug, Clone)]
struct Waiver {
    matcher: String,
    /// A `*/hot/*` matcher is the ONE permanent exemption `--strict-done` still accepts.
    hot: bool,
}

// ── THE SCANNER ──────────────────────────────────────────────────────────────────────────────────

/// Is `needle` present in `hay` with neither neighbour an identifier character? `extra` names the
/// characters that also disqualify a left neighbour (`.` for the macro classes, so `x.todo!()` and
/// `my_todo!()` are both non-matches).
fn word_at(hay: &str, needle: &str, extra_left: &[char]) -> bool {
    let bytes: Vec<char> = hay.chars().collect();
    let want: Vec<char> = needle.chars().collect();
    if want.is_empty() || bytes.len() < want.len() {
        return false;
    }
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    for i in 0..=bytes.len() - want.len() {
        if bytes[i..i + want.len()] != want[..] {
            continue;
        }
        if i > 0 {
            let prev = bytes[i - 1];
            if ident(prev) || extra_left.contains(&prev) {
                continue;
            }
        }
        let after = bytes.get(i + want.len()).copied();
        match after {
            Some(c) if ident(c) => continue,
            _ => return true,
        }
    }
    false
}

/// `mod` as a word, requiring a character after it — the shell's
/// `(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])`, which does not match a line ending in a bare `mod`.
fn has_mod(code: &str) -> bool {
    let bytes: Vec<char> = code.chars().collect();
    let ident = |c: char| c.is_ascii_alphanumeric() || c == '_';
    for i in 0..bytes.len().saturating_sub(2) {
        if bytes[i] != 'm' || bytes[i + 1] != 'o' || bytes[i + 2] != 'd' {
            continue;
        }
        if i > 0 && ident(bytes[i - 1]) {
            continue;
        }
        match bytes.get(i + 3) {
            Some(c) if !ident(*c) => return true,
            _ => {}
        }
    }
    false
}

/// A deferral macro invocation: `(^|[^A-Za-z0-9_.])(unimplemented|todo|unreachable_placeholder)!\s*\(`
fn class_a(code: &str) -> bool {
    for name in ["unimplemented", "todo", "unreachable_placeholder"] {
        let mut from = 0usize;
        while let Some(pos) = code[from..].find(name) {
            let at = from + pos;
            from = at + name.len();
            let prev_ok = at == 0
                || code[..at]
                    .chars()
                    .next_back()
                    .map(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '.'))
                    .unwrap_or(true);
            if !prev_ok {
                continue;
            }
            let rest = &code[from..];
            let Some(rest) = rest.strip_prefix('!') else {
                continue;
            };
            if rest.trim_start().starts_with('(') {
                return true;
            }
        }
    }
    false
}

/// A self-declared debt label, matched on the RAW line.
fn class_b(raw: &str) -> bool {
    word_at(raw, "SKELETON", &[])
        || two_words(raw, "dev-only", "until")
        || two_words(raw, "until", "DoD")
        || two_words(raw, "HONEST", "PENDING")
        || raw.contains("PlaneDecl::STUB")
}

/// `first` followed by one-or-more spaces/tabs and then `second`.
fn two_words(hay: &str, first: &str, second: &str) -> bool {
    let mut from = 0usize;
    while let Some(pos) = hay[from..].find(first) {
        let at = from + pos;
        from = at + first.len();
        let rest = &hay[from..];
        let trimmed = rest.trim_start_matches([' ', '\t']);
        if trimmed.len() < rest.len() && trimmed.starts_with(second) {
            return true;
        }
    }
    false
}

/// A BARE `test` predicate — `test` as a member of a `cfg(...)`/`any(...)`/`all(...)` list.
fn bare_test_pred(code: &str) -> bool {
    if !code.contains("#[cfg(") {
        return false;
    }
    let bytes: Vec<char> = code.chars().collect();
    let mut i = 0;
    while i + 4 <= bytes.len() {
        if bytes[i..].starts_with(&['t', 'e', 's', 't']) {
            // walk left over whitespace to a `(` or `,`
            let mut l = i;
            while l > 0 && (bytes[l - 1] == ' ' || bytes[l - 1] == '\t') {
                l -= 1;
            }
            let left_ok = l > 0 && (bytes[l - 1] == '(' || bytes[l - 1] == ',');
            // ...and right over whitespace to a `,` or `)`
            let mut r = i + 4;
            while r < bytes.len() && (bytes[r] == ' ' || bytes[r] == '\t') {
                r += 1;
            }
            let right_ok = r < bytes.len() && (bytes[r] == ',' || bytes[r] == ')');
            if left_ok && right_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// A NEGATED test predicate — `not(test)`, `not(any(test…))`, `not(all(test…))`. What disqualifies
/// a block from being scaffolding is `not(` wrapping the TEST predicate itself, so
/// `#[cfg(all(test, not(target_env = "musl")))]` is still scaffolding.
fn negated_test_pred(code: &str) -> bool {
    let squeezed: String = code.chars().filter(|c| *c != ' ' && *c != '\t').collect();
    squeezed.contains("not(test)")
        || squeezed.contains("not(any(test,")
        || squeezed.contains("not(any(test)")
        || squeezed.contains("not(all(test,")
        || squeezed.contains("not(all(test)")
}

/// Every marker in one file, as `file:line` — the form a waiver matcher is written in. One entry
/// per detector that fired, so a line carrying both a macro and a label counts twice, exactly as
/// the shell's marker file does. `#[cfg(test)] mod { … }` bodies are excluded from BOTH classes.
fn markers_in(rel: &str, text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    let mut testdepth: i32 = 0;
    let mut pend = false;
    let mut lex = scan::LexState::default();

    for (i, raw) in text.lines().enumerate() {
        let code = scan::strip_comment_line(raw, &mut in_block);
        // `code` keeps literal contents so `class_a` can still see a marker spelled in one; the
        // brace arithmetic reads the blanked copy, or a `'{'` in a test module leaves `testdepth`
        // permanently open and every marker after it goes unreported.
        let counted = scan::blank_code(raw, &mut lex);
        let nopen = counted.matches('{').count() as i32;
        let nclose = counted.matches('}').count() as i32;

        // THE TEST-SCOPE MACHINE READS THE BLANKED LINE, NOT `code`. `code` keeps literal contents
        // on purpose, so `let s = "#[cfg(test)] mod x {";` used to arm the attribute, open a test
        // block and swallow every marker after it — the same class of bug as counting a brace
        // inside a literal, one layer up: not the delimiter but the KEYWORD read out of a string.
        // The attribute and the `mod` keyword hold no literal, so blanking cannot hide a real one.
        let is_cfgtest = bare_test_pred(&counted) && !negated_test_pred(&counted);
        let modded = has_mod(&counted);
        let mut entered = false;

        // The attribute and the `mod` it governs may be on one line or two, so the block opens on
        // whichever line carries the `mod` — the attribute's own line when they share one, or the
        // line the pending attribute is still waiting for.
        if (is_cfgtest || pend) && modded {
            testdepth = (nopen - nclose).max(0);
            entered = testdepth > 0;
            pend = false;
        } else if pend && !counted.trim().is_empty() && !is_cfgtest {
            pend = false;
        } else if testdepth > 0 {
            testdepth = (testdepth + nopen - nclose).max(0);
        }
        if is_cfgtest && !modded {
            pend = true;
        }
        if testdepth > 0 || entered {
            continue;
        }

        let loc = format!("{rel}:{}", i + 1);
        if class_a(&code) {
            out.push(loc.clone());
        }
        if class_b(raw) {
            out.push(loc);
        }
    }
    out
}

// ── DISCOVERY ────────────────────────────────────────────────────────────────────────────────────

/// `find crates/*/src -name '*.rs' | grep -vE '/tests/|/test_support/|_tests?\.rs$' | sort`.
fn discover(cx: &Ctx) -> Result<Vec<(String, String)>, String> {
    let files = cx
        .walk(
            &WalkSpec::new(["crates"])
                .ext("rs")
                .exclude(["/tests/", "/test_support/"]),
        )
        .map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for f in files {
        let rel = f.rel_str();
        let mut parts = rel.split('/');
        let under_src =
            parts.next() == Some("crates") && parts.next().is_some() && parts.next() == Some("src");
        if !under_src {
            continue;
        }
        if rel.ends_with("_test.rs") || rel.ends_with("_tests.rs") {
            continue;
        }
        out.push((rel, f.text));
    }
    Ok(out)
}

// ── WAIVERS ──────────────────────────────────────────────────────────────────────────────────────

/// Load the committed allowlist, refusing every shape a waiver must not have. A reason says why a
/// marker is exempt today; it says nothing about when it stops being exempt, so each row also names
/// the tracker row that retires it, and that row is LOOKED UP: a `[retires: X]` pointing at nothing
/// is a promise nobody made.
fn load_waivers(cx: &Ctx) -> Result<Vec<Waiver>, String> {
    let text = cx
        .read(WAIVERS)
        .map_err(|e| format!("the waivers file {WAIVERS} could not be read: {e}"))?;
    let tracker = cx.read(TRACKER).map_err(|e| {
        format!(
            "the tracker {TRACKER} could not be read, so no waiver's expiry can be checked: {e}"
        )
    })?;

    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim_end();
        if t.trim().is_empty() || t.trim_start().starts_with('#') {
            continue;
        }
        let Some(split) = t.find(char::is_whitespace) else {
            return Err(format!("waiver row has no reason: '{t}'"));
        };
        let matcher = t[..split].to_string();
        let reason = t[split..].trim().to_string();
        if reason.is_empty() {
            return Err(format!("waiver row has no reason: '{t}'"));
        }
        if !is_exact_location(&matcher) {
            return Err(format!(
                "waiver matcher `{matcher}` is not an exact path:line — a glob absorbs whatever \
                 appears under it, in silence, and its stale check cannot fire while even one of \
                 its markers survives: '{t}'"
            ));
        }
        let Some(id) = expiry_id(&reason) else {
            return Err(format!(
                "waiver row carries no expiry: '{t}'. Every row must end in `[retires: <ID>]` \
                 naming the {TRACKER} row that retires it; a waiver that cannot expire is a \
                 permanent unreviewed exemption."
            ));
        };
        if !tracker_has_row(&tracker, &id) {
            return Err(format!(
                "waiver names expiry `{id}`, which is not a row in {TRACKER}: '{t}'. The waiver \
                 outlived the work that was supposed to retire it, or the id is a typo."
            ));
        }
        out.push(Waiver {
            hot: matcher.contains("/hot/"),
            matcher,
        });
    }
    Ok(out)
}

/// A matcher ends in `:<digits>`, the only shape this gate accepts.
fn is_exact_location(matcher: &str) -> bool {
    match matcher.rsplit_once(':') {
        Some((head, tail)) => {
            !head.is_empty() && !tail.is_empty() && tail.chars().all(|c| c.is_ascii_digit())
        }
        None => false,
    }
}

/// The `[retires: <ID>]` tag's id.
fn expiry_id(reason: &str) -> Option<String> {
    let at = reason.find("[retires:")?;
    let rest = &reason[at + "[retires:".len()..];
    let end = rest.find(']')?;
    let id = rest[..end].trim();
    if id.is_empty()
        || !id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
    {
        return None;
    }
    Some(id.to_string())
}

/// `^- \[[ x]\] <id>\s` in the tracker.
fn tracker_has_row(tracker: &str, id: &str) -> bool {
    tracker.lines().any(|l| {
        for head in ["- [ ] ", "- [x] "] {
            if let Some(rest) = l.strip_prefix(head) {
                if let Some(tail) = rest.strip_prefix(id) {
                    if tail.starts_with([' ', '\t']) {
                        return true;
                    }
                }
            }
        }
        false
    })
}

// ── THE ROWS ─────────────────────────────────────────────────────────────────────────────────────

/// The row constructors, used by BOTH [`Gate::run`] and the legacy translator, so the prose in a
/// row's title and detail comes from one place and cannot differ for a reason that is not about the
/// tree. The only thing the two sides can disagree on is the offender set, which is the only thing
/// worth comparing.
fn row_waiver_shape(rows: Option<usize>, why: Option<&str>) -> Row {
    match why {
        None => Row::pass(
            ROW_WAIVER_SHAPE,
            "every waiver is an exact location with an expiry that resolves",
            format!(
                "{} waiver row(s) loaded from {WAIVERS}",
                rows.unwrap_or_default()
            ),
        ),
        Some(why) => Row::fail(
            ROW_WAIVER_SHAPE,
            "the allowlist does not load",
            why.to_string(),
        ),
    }
}

fn row_discovery_floor(found: Option<usize>, why: Option<&str>) -> Row {
    match why {
        None => Row::pass(
            ROW_DISCOVERY_FLOOR,
            "discovery found a scan set worth drawing a verdict from",
            format!("at or above the floor of {DISCOVERY_FLOOR} shipped source file(s)"),
        ),
        Some(why) => Row::fail(
            ROW_DISCOVERY_FLOOR,
            "the scan set is below its floor, so the verdict is UNPROVEN",
            match found {
                Some(n) => format!(
                    "discovery found only {n} shipped source file(s) (floor {DISCOVERY_FLOOR}). \
                     {why}"
                ),
                None => why.to_string(),
            },
        ),
    }
}

fn row_unwaived(total: usize, offenders: &[String]) -> Row {
    if offenders.is_empty() {
        Row::pass(
            ROW_UNWAIVED,
            "every deferral marker is a floor-checked allowlist entry",
            format!("{total} marker(s) found, every one waived"),
        )
    } else {
        Row::fail(
            ROW_UNWAIVED,
            "the shipped tree defers something the allowlist does not account for",
            format!(
                "{} un-waived marker(s): {}",
                offenders.len(),
                offenders.join(", ")
            ),
        )
    }
}

fn row_stale(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        Row::pass(
            ROW_STALE_WAIVER,
            "every waiver still describes a marker that is really there",
            "no allowlist row matched zero markers".to_string(),
        )
    } else {
        Row::fail(
            ROW_STALE_WAIVER,
            "a waiver outlived the marker it excused",
            format!(
                "{} stale waiver(s): {}",
                offenders.len(),
                offenders.join(", ")
            ),
        )
    }
}

fn row_strict(offenders: &[String]) -> Row {
    if offenders.is_empty() {
        Row::pass(
            ROW_STRICT_DONE,
            "the tree carries ONLY the permanent hot/* foundation fixtures",
            "every waiver is a */hot/* row".to_string(),
        )
    } else {
        Row::fail(
            ROW_STRICT_DONE,
            "a non-hot/* waiver is still present, so the tracked debt has not cleared",
            format!(
                "{} non-hot waiver(s): {}",
                offenders.len(),
                offenders.join(", ")
            ),
        )
    }
}

/// The rows below a refusal: SKIP, never PASS. Every SKIP is RED at the reconciler unless
/// allowlisted, which is what makes "did not run" reportable rather than silent.
fn unproven(id: &str, why: &str) -> Row {
    Row::skip(
        id,
        "unproven — the run stopped above this check",
        why.to_string(),
    )
}

// ── THE GATE ─────────────────────────────────────────────────────────────────────────────────────

pub struct NoDeferralGate {
    /// The `--strict-done` form the release verification calls: a named twin, not a boolean read
    /// from the environment. `DONE_GROUP_FLOOR`'s env-overridability is the cautionary case.
    pub strict: bool,
}

impl NoDeferralGate {
    pub fn check() -> NoDeferralGate {
        NoDeferralGate { strict: false }
    }

    pub fn strict_done() -> NoDeferralGate {
        NoDeferralGate { strict: true }
    }

    fn stopped(&self, at: &str, why: &str, first: Row) -> Verdict {
        let mut rows = vec![first];
        for id in [
            ROW_WAIVER_SHAPE,
            ROW_DISCOVERY_FLOOR,
            ROW_UNWAIVED,
            ROW_STALE_WAIVER,
        ] {
            if id != at && self.owed().iter().any(|o| o == id) {
                rows.push(unproven(id, why));
            }
        }
        if self.strict {
            rows.push(unproven(ROW_STRICT_DONE, why));
        }
        Verdict::of(rows)
    }
}

impl Gate for NoDeferralGate {
    fn name(&self) -> &'static str {
        if self.strict {
            "no-deferral-strict-done"
        } else {
            "no-deferral"
        }
    }

    fn owed(&self) -> Vec<String> {
        let mut ids = vec![
            ROW_WAIVER_SHAPE.to_string(),
            ROW_DISCOVERY_FLOOR.to_string(),
            ROW_UNWAIVED.to_string(),
            ROW_STALE_WAIVER.to_string(),
        ];
        if self.strict {
            ids.push(ROW_STRICT_DONE.to_string());
        }
        ids
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        // (0) THE ALLOWLIST, FIRST. Without it there is nothing to reconcile against and every
        //     count below is a number with no claim attached.
        let waivers = match load_waivers(cx) {
            Ok(w) => w,
            Err(why) => {
                return self.stopped(
                    ROW_WAIVER_SHAPE,
                    "the allowlist did not load, so nothing below it was reconciled",
                    row_waiver_shape(None, Some(&why)),
                )
            }
        };

        // (1) THE FLOOR. Broken discovery reports a clean tree.
        let files = match discover(cx) {
            Ok(f) => f,
            Err(why) => {
                return self.stopped(
                    ROW_DISCOVERY_FLOOR,
                    "discovery failed, so no marker set was scanned",
                    row_discovery_floor(None, Some(&why)),
                )
            }
        };
        if files.len() < DISCOVERY_FLOOR {
            let mut v = self.stopped(
                ROW_DISCOVERY_FLOOR,
                "discovery came back below its floor, so no verdict was drawn",
                row_discovery_floor(
                    Some(files.len()),
                    Some("Broken discovery reports a clean tree. This verdict is UNPROVEN, not PASS."),
                ),
            );
            // The allowlist DID load; say so rather than reporting it unproven.
            v.rows.retain(|r| r.id != ROW_WAIVER_SHAPE);
            v.rows.push(row_waiver_shape(Some(waivers.len()), None));
            return Verdict::of(v.rows);
        }

        // (2) SCAN, then reconcile BOTH WAYS.
        let mut markers: Vec<String> = Vec::new();
        for (rel, text) in &files {
            markers.extend(markers_in(rel, text));
        }

        let mut unwaived: Vec<String> = Vec::new();
        let mut hit = vec![false; waivers.len()];
        for m in &markers {
            match waivers.iter().position(|w| &w.matcher == m) {
                Some(i) => hit[i] = true,
                None => unwaived.push(m.clone()),
            }
        }
        unwaived.sort();
        unwaived.dedup();

        let stale: Vec<String> = waivers
            .iter()
            .zip(&hit)
            .filter(|(_, h)| !**h)
            .map(|(w, _)| w.matcher.clone())
            .collect();

        let mut rows = vec![
            row_waiver_shape(Some(waivers.len()), None),
            row_discovery_floor(Some(files.len()), None),
            row_unwaived(markers.len(), &unwaived),
            row_stale(&stale),
        ];
        if self.strict {
            let nonhot: Vec<String> = waivers
                .iter()
                .filter(|w| !w.hot)
                .map(|w| w.matcher.clone())
                .collect();
            rows.push(row_strict(&nonhot));
        }
        Verdict::of(rows)
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        Some(translate(self.strict, run))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        let owed: Vec<String> = self.owed();
        let all: Vec<&str> = owed.iter().map(String::as_str).collect();

        report.push(prove_green(
            cx,
            self,
            "the committed tree's every marker is a waived one, and every waiver is live",
            &all,
        ));

        // ── CLASS A, AWAY FROM LINE START. Each of these compiles, ships and panics when a caller
        //    gets there; the anchored scanner reported this whole file as zero markers.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/xtask_no_deferral_plant.rs",
            "pub fn dispatch(kind: u8) -> u8 {\n    match kind {\n        0 => 1,\n        _ => \
             todo!(\"the duplex dialect is not wired yet\"),\n    }\n}\npub fn other() -> u8 { let \
             v = unimplemented!(); v }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a match arm and an initialiser are reachable deferrals, wherever they sit on the line",
            &[ROW_UNWAIVED],
            ov,
            &[
                "xtask_no_deferral_plant.rs:4",
                "xtask_no_deferral_plant.rs:7",
            ],
        ));

        // ── CLASS B, on the raw line.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/xtask_no_deferral_plant.rs",
            "// SKELETON: this plane mounts nothing yet\npub fn q() -> u8 { 1 }\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a self-declared debt label in a comment is the whole point of Class B",
            &[ROW_UNWAIVED],
            ov,
            &["xtask_no_deferral_plant.rs:1"],
        ));

        // ── `#[cfg(not(test))]` IS THE CODE THAT SHIPS. The one attribute that guarantees code
        //    reaches users was the one attribute that guaranteed the scanner would not look.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/xtask_no_deferral_plant.rs",
            "#[cfg(not(test))]\nmod production {\n    // SKELETON: the real session is not \
             implemented\n    pub fn q() -> u8 {\n        todo!(\"dev-only until DoD\")\n    }\n}\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a cfg(not(test)) module is scanned, not excused as scaffolding",
            &[ROW_UNWAIVED],
            ov,
            &[
                "xtask_no_deferral_plant.rs:3",
                "xtask_no_deferral_plant.rs:5",
            ],
        ));

        // ── ...AND THE RULE DID NOT WIDEN INTO "SCAN EVERYTHING". Genuine scaffolding, prose and
        //    the lowercase domain word are all still silent, planted together so a green here is
        //    not one case's luck.
        let mut ov = Overlay::new();
        ov.set(
            "crates/busbar-core/src/xtask_no_deferral_plant.rs",
            "// no `unimplemented!()` stub remains — the fan-out filled every slot.\n/* a design \
             note mentioning todo!() in prose is not a deferral */\nfn writer() { let _ = \"the \
             full message skeleton is emitted here\"; }\n#[cfg(all(test, unix))]\nmod tests {\n    \
             // SKELETON fixture\n    fn f() { todo!() }\n}\n",
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "prose, a lowercase 'skeleton' and a real cfg(all(test,…)) module are all silent",
            &[ROW_UNWAIVED],
        ));

        // ── A WAIVER THAT MATCHES NOTHING. Under-count: the marker was resolved and the row lied
        //    about the tree for as long as nobody looked.
        report.push(prove_red(
            cx,
            self,
            "a waiver matching zero markers is a stale exemption",
            &[ROW_STALE_WAIVER],
            waivers_overlay(
                cx,
                "crates/busbar-core/src/no-such-file.rs:1\tplanted, matches nothing [retires: H5]",
            ),
            &["no-such-file.rs:1"],
        ));

        // ── THE THREE WAIVER-SHAPE REFUSALS, each its own case, each driving the real loader.
        report.push(prove_red(
            cx,
            self,
            "a waiver row carrying no [retires: …] is refused",
            &[ROW_WAIVER_SHAPE],
            waivers_overlay(cx, "crates/x/src/a.rs:1\ta reason with no expiry at all"),
            &["carries no expiry"],
        ));
        report.push(prove_red(
            cx,
            self,
            "an expiry naming a tracker row that does not exist is refused",
            &[ROW_WAIVER_SHAPE],
            waivers_overlay(cx, "crates/x/src/a.rs:1\ta reason [retires: ZZ999]"),
            &["not a row in"],
        ));
        report.push(prove_red(
            cx,
            self,
            "a directory glob is refused: one absorbed 52 markers and could never go stale",
            &[ROW_WAIVER_SHAPE],
            waivers_overlay(
                cx,
                "crates/busbar-plugin/src/hot/*\ta whole tree [retires: H5]",
            ),
            &["not an exact path:line"],
        ));

        // ── THE FLOOR, ON THE RUN PATH. Discovery emptied: every other row must go UNPROVEN rather
        //    than report a clean tree, and `--strict-done` must not certify anything at all.
        let emptied = match discover(cx) {
            Ok(files) => {
                let mut ov = Overlay::new();
                for (rel, _) in &files {
                    ov.remove(rel);
                }
                Some(ov)
            }
            Err(_) => None,
        };
        match emptied {
            Some(ov) => report.push(prove_red(
                cx,
                self,
                "a tree discovery came back empty over is UNPROVEN, never a clean one",
                &[ROW_DISCOVERY_FLOOR],
                ov,
                &["UNPROVEN, not PASS"],
            )),
            None => report.note_infra_failure(
                "the floor case could not be planted: discovery does not read the real tree",
            ),
        }

        if self.strict {
            // A NON-HOT WAIVER IS THE TRACKED DEBT. Planted as a real marker outside hot/ with a
            // well-formed waiver for it, so the over/under-count rows stay green and the only
            // finding is the one --strict-done exists for.
            let mut ov = waivers_overlay(
                cx,
                "crates/busbar-core/src/xtask_no_deferral_plant.rs:1\tplanted voice-shaped debt \
                 [retires: H5]",
            );
            ov.set(
                "crates/busbar-core/src/xtask_no_deferral_plant.rs",
                "pub fn q() -> u8 { todo!() }\n",
            );
            report.push(prove_red(
                cx,
                self,
                "a waiver outside hot/* means the tracked debt has not cleared",
                &[ROW_STRICT_DONE],
                ov,
                &["non-hot waiver"],
            ));
        }

        report
    }
}

/// The committed allowlist plus one planted row. Built from what the gate would otherwise READ, so
/// a case is expressed against the real file rather than against a hand-written copy of it.
fn waivers_overlay(cx: &Ctx, extra: &str) -> Overlay {
    let mut ov = Overlay::new();
    let base = cx.read(WAIVERS).unwrap_or_default();
    ov.set(WAIVERS, format!("{base}{extra}\n"));
    ov
}

// ── THE LEGACY TRANSLATOR ────────────────────────────────────────────────────────────────────────

/// Read `scripts/no-deferral-gate.sh`'s own output into the rows this gate would emit for the same
/// tree. It writes no ledger — it prints prose and exits 0 or 1 — and a harness that could only
/// compare two exit statuses would be proving that both sides said red, never that they said red
/// about the same marker of the same file.
fn translate(strict: bool, run: &LegacyRun) -> Result<Vec<Row>, String> {
    let lines: Vec<String> = run.lines().map(decolour).collect();

    let mut waiver_rows: Option<usize> = None;
    let mut waiver_why: Option<String> = None;
    let mut total: Option<usize> = None;
    let mut floor_why: Option<String> = None;
    let mut found: Option<usize> = None;
    let mut unwaived: Vec<String> = Vec::new();
    let mut stale: Vec<String> = Vec::new();
    let mut nonhot: Vec<String> = Vec::new();
    let mut strict_clean = false;

    #[derive(PartialEq)]
    enum Section {
        None,
        Unwaived,
        Stale,
        Strict,
    }
    let mut section = Section::None;

    for line in &lines {
        let t = line.trim();
        if t.starts_with("== ") {
            section = match t {
                s if s.contains("UN-WAIVED deferral markers") => Section::Unwaived,
                s if s.contains("STALE waivers") => Section::Stale,
                s if s.contains("STRICT-DONE: non-hot") => Section::Strict,
                _ => Section::None,
            };
            continue;
        }
        if let Some(rest) = t.strip_prefix("waivers:") {
            // The FIRST paren: the tail of this line is `(52 row(s))`, and reading from the last
            // one finds `(s))` and parses it as no waivers at all — which is the passing answer to
            // "does every waiver expire".
            waiver_rows = rest
                .split_once('(')
                .and_then(|(_, tail)| tail.split_whitespace().next())
                .and_then(|n| n.parse().ok());
            continue;
        }
        if let Some(rest) = t.strip_prefix("markers found:") {
            total = rest.split_whitespace().next().and_then(|n| n.parse().ok());
            continue;
        }
        if t.contains("no-deferral gate: waiver") || t.contains("waivers file") {
            waiver_why = Some(t.to_string());
            continue;
        }
        if t.contains("the tracker") && t.contains("is missing") {
            waiver_why = Some(t.to_string());
            continue;
        }
        if let Some(rest) = t.strip_prefix("no-deferral gate: discovery found only ") {
            found = rest.split_whitespace().next().and_then(|n| n.parse().ok());
            floor_why = Some(
                "Broken discovery reports a clean tree. This verdict is UNPROVEN, not PASS."
                    .to_string(),
            );
            continue;
        }
        if t.starts_with("strict-done: every waiver is a") {
            strict_clean = true;
            continue;
        }
        match section {
            Section::Unwaived => {
                // `  <file:line>   <CLASS>: <text>`
                let mut it = t.split_whitespace();
                if let (Some(loc), Some(cls)) = (it.next(), it.next()) {
                    let cls = cls.trim_end_matches(':');
                    // The CLASS is what identifies this as a marker line rather than a note; the
                    // location is what the two implementations are compared on. The shell prints
                    // the first marker's class for every marker at one location, so a line
                    // carrying both a macro and a label reports class A twice — a display artefact
                    // that says nothing about the tree and must not be compared as though it did.
                    if cls == "A" || cls == "B" {
                        unwaived.push(loc.to_string());
                    }
                }
            }
            Section::Stale => {
                if let Some(m) = t.split_whitespace().next() {
                    stale.push(m.to_string());
                }
            }
            Section::Strict => {
                if let Some(m) = t.split_whitespace().next() {
                    nonhot.push(m.to_string());
                }
            }
            Section::None => {}
        }
    }

    let mut rows = Vec::new();
    if let Some(why) = waiver_why {
        rows.push(row_waiver_shape(None, Some(&why)));
        let note = "the allowlist did not load, so nothing below it was reconciled";
        rows.push(unproven(ROW_DISCOVERY_FLOOR, note));
        rows.push(unproven(ROW_UNWAIVED, note));
        rows.push(unproven(ROW_STALE_WAIVER, note));
        if strict {
            rows.push(unproven(ROW_STRICT_DONE, note));
        }
        return Ok(rows);
    }

    rows.push(row_waiver_shape(waiver_rows, None));

    if let Some(why) = floor_why {
        rows.push(row_discovery_floor(found, Some(&why)));
        let note = "discovery came back below its floor, so no verdict was drawn";
        rows.push(unproven(ROW_UNWAIVED, note));
        rows.push(unproven(ROW_STALE_WAIVER, note));
        if strict {
            rows.push(unproven(ROW_STRICT_DONE, note));
        }
        return Ok(rows);
    }

    let Some(total) = total else {
        return Err(format!(
            "the legacy translator found no marker count in `{}`'s output. Silence read as a clean \
             tree is the exact defect this gate exists for. stdout: {}",
            run.argv.join(" "),
            run.stdout.trim()
        ));
    };
    rows.push(row_discovery_floor(None, None));
    unwaived.sort();
    unwaived.dedup();
    rows.push(row_unwaived(total, &unwaived));
    rows.push(row_stale(&stale));
    if strict {
        if !strict_clean && nonhot.is_empty() {
            return Err(format!(
                "`{}` printed no --strict-done verdict at all, so the strictest claim this gate \
                 makes would be compared against nothing",
                run.argv.join(" ")
            ));
        }
        rows.push(row_strict(&nonhot));
    }
    Ok(rows)
}

/// Drop the SGR escapes the shell's `red()`/`grn()` wrap their lines in.
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
