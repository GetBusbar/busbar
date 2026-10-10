//! THE BASE A BRANCH IS MEASURED AGAINST, and the ceilings-file editors the self-test uses.
//!
//! This module used to hold the two rules about the ceilings themselves, `ceiling-rose` (no number
//! in a qa ceilings file may rise against the base) and `ceiling-slack` (every ceiling equals its
//! measurement), with the `[gate.ceiling_raises]` / `[gate.ceiling_reservations]` transactions
//! that excused them. All of that is DELETED: size is not a CI check (owner 2026-10-02), and those
//! rows were what turned every feature PR that added lines into a hand-declared raise. What is left
//! is what other rules still need:
//!
//! * [`base_ref`] — the base commit (`ceiling-census` compares its floors against it, and
//!   `kind-isolation` reads the base's ledger to refuse a row this branch minted);
//! * [`pins`], [`set_int`], [`add_to_list`] — the self-test's GREEN FIXTURE pins the remaining
//!   count ratchets (`legacy-reach`, `ports-only`) to what they measure, inside an overlay, so a
//!   plant can drive them red. Nothing writes these to the committed file.

use crate::ctx::Ctx;
use crate::gates::construction::model::Cfg;

/// THE VARIABLE THAT NAMES THE BASE for a caller that knows better than the derivation (CI
/// measuring a merge target, a self-test pointing at a planted ref). The release turnstile sets it
/// to the PR's base sha. An override that does not resolve is RED like any other base that cannot
/// be established — it is not a way to turn a base comparison off. See [`base_ref`].
pub const BASE_ENV: &str = "XTASK_CEILING_BASE";

/// The overlay command key a self-test plants to pin [`base_ref`]'s answer. See there.
pub const BASE_PIN_KEY: &str = "construction-ceiling-base";

/// One ceiling: the row it governs, and the exact place in the ceilings file the number is written.
#[derive(Debug, Clone)]
pub struct Pin {
    pub row: String,
    /// The TOML table path, as [`crate::toml_doc::Document::table`] spells it.
    pub table: String,
    pub key: String,
}

impl Pin {
    fn new(row: impl Into<String>, table: impl Into<String>, key: impl Into<String>) -> Pin {
        Pin {
            row: row.into(),
            table: table.into(),
            key: key.into(),
        }
    }
}

/// Every COUNT RATCHET the self-test's green fixture pins to its measurement, derived from the
/// ceilings file: the root's legacy reach (total and per prefix) and the per-plane ports-only
/// figures. No size figure is here: the line-count ceilings are deleted.
///
/// The rows deliberately NOT here are the ones whose threshold is a POLICY rather than a
/// measurement: `max_extra_sites = 0`, `max_hits = 0`, `max_lines = 200`. Zero is not slack — a
/// rule that permits nothing is already exact — and a function-length limit is a rule about the
/// shape of a function, not a ratchet over what the tree happens to contain today.
pub fn pins(cfg: &Cfg) -> Vec<Pin> {
    let mut out = vec![Pin::new("legacy-reach", "rules.legacy-reach", "ceiling")];
    for (key, _) in cfg.doc.children("rules.legacy-reach.prefixes") {
        out.push(Pin::new(
            format!("legacy-reach:{key}"),
            format!("rules.legacy-reach.prefixes.{key}"),
            "figure",
        ));
    }
    for crate_name in cfg
        .gate()
        .map(|g| g.list_of("plane_crates"))
        .unwrap_or_default()
    {
        out.push(Pin::new(
            format!("ports-only:{crate_name}"),
            "rules.ports-only.max_per_crate",
            crate_name.clone(),
        ));
        out.push(Pin::new(
            format!("ports-only-tests:{crate_name}"),
            "rules.ports-only-tests.max_per_crate",
            crate_name,
        ));
    }
    out
}

/// Rewrite `table.key`'s integer, in place, preserving every byte around it.
///
/// A line editor rather than a serializer, because the ceilings file is the owner's prose and a
/// round-trip through a writer this crate does not have would reformat all of it. Written for the
/// self-test's green fixture, inside an overlay; nothing writes this to the committed file.
pub fn set_int(text: &str, table: &str, key: &str, value: i64) -> Option<String> {
    let mut cur = String::new();
    let mut out: Vec<String> = Vec::new();
    let mut hit = false;
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with('[') && t.ends_with(']') {
            cur = t[1..t.len() - 1].trim().to_string();
            out.push(raw.to_string());
            continue;
        }
        if !hit && cur == table {
            if let Some((k, _)) = t.split_once('=') {
                if k.trim() == key && !t.starts_with('#') {
                    let indent: String = raw.chars().take_while(|c| c.is_whitespace()).collect();
                    out.push(format!("{indent}{key} = {value}"));
                    hit = true;
                    continue;
                }
            }
        }
        out.push(raw.to_string());
    }
    if !hit {
        return None;
    }
    let mut s = out.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    Some(s)
}

/// Add `items` to the list `table.key`, in place, creating the key directly under the table's header
/// when it is absent. The entries go in right after the list's opening `[`, so a one-line list, a
/// multi-line list and an empty `[]` all stay valid TOML. `None` when the table has no header line.
///
/// Written for the construction self-test's GREEN FIXTURE (item 89), which records today's debt in
/// the rule's own review lists INSIDE AN OVERLAY so a case can ask about a site the debt does not
/// touch. Nothing writes this to the committed file.
pub fn add_to_list(text: &str, table: &str, key: &str, items: &[String]) -> Option<String> {
    let quoted = items
        .iter()
        .map(|i| format!("\"{}\"", i.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(", ");
    let mut cur = String::new();
    let mut out: Vec<String> = Vec::new();
    let (mut header_at, mut done) = (None, false);
    for raw in text.lines() {
        let t = raw.trim();
        if t.starts_with('[') && t.ends_with(']') {
            cur = t[1..t.len() - 1].trim().to_string();
            out.push(raw.to_string());
            if cur == table && header_at.is_none() {
                header_at = Some(out.len());
            }
            continue;
        }
        if !done && cur == table && !t.starts_with('#') {
            if let Some((k, v)) = t.split_once('=') {
                if k.trim().trim_matches('"') == key && v.trim_start().starts_with('[') {
                    let at = raw.find('[').unwrap_or(raw.len());
                    let (head, tail) = raw.split_at(at + 1);
                    out.push(format!("{head} {quoted},{tail}"));
                    done = true;
                    continue;
                }
            }
        }
        out.push(raw.to_string());
    }
    if !done {
        let at = header_at?;
        out.insert(at, format!("{key} = [{quoted}]"));
    }
    let mut s = out.join("\n");
    if text.ends_with('\n') {
        s.push('\n');
    }
    Some(s)
}

/// THE BASE, AND THE DERIVATION THAT PRODUCED IT.
///
/// `how` is not decoration. The bug this type exists to prevent was never a base that was WRONG in
/// a way anybody could see — it was a base that was UNSAID: a row printed "the base dc7bb323" and
/// nothing anywhere printed which ref that came from or how far back it was, so a ref that had
/// stopped resolving, and later a ref that had gone four days stale, both read exactly like a
/// working gate. Every row that establishes a base now states the derivation in its own
/// detail, so "measuring the wrong thing" is a sentence a reader can disagree with.
#[derive(Debug, Clone)]
pub struct Base {
    /// The commit itself.
    pub sha: String,
    /// How it was arrived at, in words, for the row detail.
    pub how: String,
}

impl Base {
    /// The abbreviated sha every finding quotes.
    pub fn short(&self) -> &str {
        &self.sha[..8.min(self.sha.len())]
    }
}

impl std::fmt::Display for Base {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.sha)
    }
}

/// THE BASE THIS RUN IS MEASURED AGAINST: the remote tip of the line `HEAD` is on, or `HEAD~1` when
/// `HEAD` already is that tip.
///
/// WHY THE LINE'S OWN REMOTE TIP AND NOT A NAMED UPSTREAM. See [`BASE_ENV`] for the history; the
/// short form is that `merge-base(HEAD, <some fixed branch>)` answers "where did this branch fork"
/// and that is only the right question when HEAD is a fork. Every place this gate actually runs, it
/// is not: CI runs it on a pushed branch, and the agents run it on a shared integration line they
/// commit directly onto. In both, the unit of judgement is the COMMIT, and the commits under
/// judgement are precisely the ones this checkout has that the line's remote tip does not.
///
/// THE FOUR WAYS THIS RETURNS RED, none of which used to be red:
/// 1. `HEAD` is detached and no [`BASE_ENV`] was given, so there is no line to take a tip from.
/// 2. The ref does not resolve — a rename, an unfetched remote, a shallow clone. This is the
///    original failure: it used to fall through to `HEAD~1` and measure one commit forever.
/// 3. `git merge-base` prints nothing: unrelated histories.
/// 4. THE REF HAS DIVERGED FROM `HEAD` — the merge-base is neither `HEAD` nor the ref's own tip, so
///    the ref carries commits `HEAD` does not and the merge-base is a fork point in the past. This
///    is the second failure, and it is the generalisation of the first: a base that RESOLVES can
///    still be unestablishable. `origin/predev` was 88 commits ahead of a 178-commit-old fork
///    point, and the gate reported four days of the whole team's movement as the work of the
///    commit in front of it. "Cannot be established" has to mean this too, or the next stale
///    ref is as silent as the last one.
///
/// Only case (4)'s complement — the merge-base IS the ref's tip, or IS `HEAD` — is a base, and in
/// both the span it names is a contiguous run of commits every one of which is on this line.
pub fn base_ref(cx: &Ctx) -> Result<Base, String> {
    // A SELF-TEST'S PINNED BASE. Every other input to this derivation is live git: `HEAD`, the
    // line's remote tip, the merge-base. On a shared checkout that other writers commit onto, a
    // self-test that takes minutes sees `HEAD~1` move under it, so the base a fixture planted
    // `git-show:<sha>:<file>` for at the start is not the base a case asks about at the end — and
    // the case reports a race as a rule's verdict. The fixture pins the sha it planted against. An
    // EMPTY value is "not pinned", so a case can plant the unpinned derivation back (the case that
    // proves an unresolvable ref is refused needs the live arm). No real run carries an overlay.
    if let Some(sha) = cx.overlay_command(BASE_PIN_KEY) {
        if !sha.trim().is_empty() {
            return Ok(Base {
                sha: sha.trim().to_string(),
                how: "pinned by the self-test's fixture".to_string(),
            });
        }
    }
    let head = cx.git(&["rev-parse", "HEAD"])?.trim().to_string();
    let (r, why) = base_line(cx)?;
    if !cx.git_ref_resolves(&r) {
        return Err(format!(
            "the base ref '{r}' does not resolve in this checkout -- fetch it, push this line, or \
             set {BASE_ENV}. A base that cannot be established is RED, never a silent fall-back to \
             the last commit"
        ));
    }
    let mb = cx
        .git(&["merge-base", "HEAD", &r])
        .map_err(|e| format!("'{r}' resolves but HEAD has no merge-base with it: {e}"))?
        .trim()
        .to_string();
    if mb.is_empty() {
        return Err(format!(
            "'{r}' resolves but `git merge-base` printed nothing -- unrelated histories, most \
             likely"
        ));
    }
    if mb == head {
        // HEAD IS the tip of its own line: "what is under judgement here" is the last commit.
        let sha = cx.git(&["rev-parse", "HEAD~1"])?.trim().to_string();
        return Ok(Base {
            sha,
            how: format!("HEAD~1, because HEAD is at or behind {r} ({why})"),
        });
    }
    let tip = cx
        .git(&["rev-parse", &format!("{r}^{{commit}}")])?
        .trim()
        .to_string();
    if mb != tip {
        let (ahead, behind) = (
            cx.git(&["rev-list", "--count", &format!("{mb}..{head}")])
                .unwrap_or_default()
                .trim()
                .to_string(),
            cx.git(&["rev-list", "--count", &format!("{mb}..{tip}")])
                .unwrap_or_default()
                .trim()
                .to_string(),
        );
        return Err(format!(
            "'{r}' has DIVERGED from HEAD: their merge-base {} is {ahead} commit(s) behind HEAD \
             and {behind} commit(s) behind '{r}', so it is a fork point in the past rather than \
             this line's base. Measuring against it would report everything anyone moved in \
             those {ahead} commits as this change's own. Rebase onto '{r}', fetch it, or set \
             {BASE_ENV}. A base that cannot be established is RED, never a silent fall-back",
            &mb[..8.min(mb.len())]
        ));
    }
    let ahead = cx
        .git(&["rev-list", "--count", &format!("{mb}..{head}")])
        .unwrap_or_default()
        .trim()
        .to_string();
    Ok(Base {
        sha: mb,
        how: format!("{why}, {ahead} commit(s) behind HEAD"),
    })
}

/// THE REF [`base_ref`] WILL MEASURE AGAINST, and the words for how it was chosen — resolved or
/// not, merge-based or not.
///
/// Separate from [`base_ref`] so the self-test can ask which ref this checkout would use and then
/// plant THAT ref as unresolvable. The alternative is a case that hardcodes a branch name, which is
/// the same mistake as the constant this function replaced: it would prove the arm on the machine
/// it was written on and quietly stop exercising it everywhere else.
pub fn base_line(cx: &Ctx) -> Result<(String, String), String> {
    if let Some(r) = base_override() {
        let why = format!("{BASE_ENV}={r}");
        return Ok((r, why));
    }
    let branch = cx
        .git(&["symbolic-ref", "--quiet", "--short", "HEAD"])
        .map_err(|_| {
            format!(
                "HEAD is detached, so there is no line to take a remote tip from and no base can \
                 be derived. Set {BASE_ENV} to the commit this checkout should be measured \
                 against. A base that cannot be established is RED, never a silent fall-back to \
                 the last commit."
            )
        })?
        .trim()
        .to_string();
    let r = format!("origin/{branch}");
    let why = format!("the remote tip of the line HEAD is on, {r}");
    Ok((r, why))
}

/// [`BASE_ENV`], trimmed, with an empty value read as absent.
///
/// A direct `std::env::var` rather than a field on [`Ctx`]'s environment struct because this is an
/// ESCAPE HATCH for a caller who knows better, not a mode the gate has: nothing in the ordinary run
/// sets it, and an override that does not resolve is refused by [`base_ref`] like any other base.
fn base_override() -> Option<String> {
    std::env::var(BASE_ENV)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = "# a comment\n[gate.x]\ngrammar = 500\n\n[rules.x]\nn = 1\n";

    /// The re-pin edits ONE line and leaves every other byte — the prose around a ceiling is what
    /// makes the diff reviewable.
    #[test]
    fn a_re_pin_changes_one_line_and_nothing_else() {
        let out = set_int(DOC, "gate.x", "grammar", 388).expect("the key is there");
        assert_eq!(
            out,
            "# a comment\n[gate.x]\ngrammar = 388\n\n[rules.x]\nn = 1\n"
        );
    }

    /// A key in a table this pin does not name is not the key: `n` under `[rules.x]` must not be
    /// found by a pin that names `[rules.y]`.
    #[test]
    fn a_pin_that_names_no_key_writes_nothing() {
        assert!(set_int(DOC, "rules.y", "n", 9).is_none());
        assert!(set_int(DOC, "rules.x", "missing", 9).is_none());
    }

    /// The self-test fixture's list editor: an entry lands in the named table's list (made when
    /// absent, prepended when present) and the result still parses.
    #[test]
    fn the_fixture_editor_adds_to_a_list() {
        let doc = "[a]\nk = [\n  \"x\",\n]\n[b]\nn = 1\n[d]\nm = 3\n";
        let added = add_to_list(doc, "a", "k", &["y".to_string()]).expect("table a");
        let made = add_to_list(&added, "b", "new-key", &["z".to_string()]).expect("table b");
        let parsed = crate::toml_doc::parse_str(&made).expect("still TOML");
        assert_eq!(parsed.table("a").expect("a").list_of("k"), vec!["y", "x"]);
        assert_eq!(parsed.table("b").expect("b").list_of("new-key"), vec!["z"]);
        assert!(add_to_list(doc, "nope", "k", &[]).is_none());
    }
}
