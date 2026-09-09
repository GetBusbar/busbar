//! `cargo xtask ledger <sub>` — the audit register's commands.
//!
//! `sync` / `status` / `next` / `record` / `fixed`, plus `--check`, which is ALSO the registered
//! gate `audit-ledger` (see `gates/audit_ledger.rs`). The two are one implementation: `--check`
//! prints the human blocks the Python printed, and the gate reconciles the same findings as ledger
//! rows. A register that reads red one way and green the other would be worse than either.
//!
//! Every stdout line here is byte-identical to `scripts/audit-ledger.py`'s, and both data files —
//! `qa/audit-ledger.json` and `docs/design/AUDIT-STATUS.md` — are written byte-identically. That is
//! not politeness: the register is 147KB of committed evidence and the report is a committed
//! document, so a rewrite that reflowed either would bury the one line that changed.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::audit::{self, Git, RowView};
use crate::json_lite::{self, Json, Obj};

const USAGE: &str = "\
usage:
  cargo xtask ledger sync [--write]      derive the scope list from the tree
  cargo xtask ledger status              print the table and write docs/design/AUDIT-STATUS.md
  cargo xtask ledger next                the worklist, worst first
  cargo xtask ledger record --scope S --round N --result R --report P --auditor A [--counts ..] [--at REV]
  cargo xtask ledger fixed --scope S [--commit REV]
  cargo xtask ledger --check             red on an open HIGH/MEDIUM scope or incomplete coverage";

/// `die()` — to stderr, exit 2.
fn die(msg: String) -> i32 {
    eprintln!("audit-ledger: {msg}");
    2
}

struct Args {
    map: BTreeMap<String, String>,
    flags: Vec<String>,
    sub: Option<String>,
}

/// The options this command takes a value for. AN UNKNOWN OPTION IS AN ERROR, never a value
/// quietly filed under a name nothing reads: `--att 4d5a05af` would otherwise stamp HEAD while the
/// auditor believed they had named the commit they read, and the record would claim a tree nobody
/// looked at. An unexpected positional has always been an error; a misspelt flag is the same
/// mistake.
const OPTIONS: [&str; 10] = [
    "ledger",
    "report-md",
    "scope",
    "round",
    "result",
    "report",
    "auditor",
    "counts",
    "at",
    "commit",
];

const SWITCHES: [&str; 3] = ["check", "selftest", "write"];

fn parse(args: &[String]) -> Result<Args, String> {
    let mut out = Args {
        map: BTreeMap::new(),
        flags: Vec::new(),
        sub: None,
    };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if let Some(name) = a.strip_prefix("--") {
            if SWITCHES.contains(&name) {
                out.flags.push(name.to_string());
            } else if OPTIONS.contains(&name) {
                let Some(v) = args.get(i + 1) else {
                    return Err(format!("`--{name}` needs a value"));
                };
                out.map.insert(name.to_string(), v.clone());
                i += 1;
            } else {
                return Err(format!(
                    "unknown option `--{name}` (options: {}; switches: {})",
                    OPTIONS.join(", "),
                    SWITCHES.join(", ")
                ));
            }
        } else if out.sub.is_none() {
            out.sub = Some(a.clone());
        } else {
            return Err(format!("unexpected argument `{a}`"));
        }
        i += 1;
    }
    Ok(out)
}

pub fn main(root: &std::path::Path, args: &[String]) -> i32 {
    let a = match parse(args) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("xtask ledger: {e}");
            eprintln!("{USAGE}");
            return 2;
        }
    };

    let register: PathBuf = a
        .map
        .get("ledger")
        .map_or_else(|| root.join(audit::REGISTER_REL), PathBuf::from);
    let report: PathBuf = a
        .map
        .get("report-md")
        .map_or_else(|| root.join(audit::REPORT_REL), PathBuf::from);
    let git = Git::new(root);

    // `--check` beats any subcommand given beside it, exactly as the Python's dispatch does.
    if a.flags.iter().any(|f| f == "check") {
        return cmd_check(&git, &register);
    }

    match a.sub.as_deref() {
        Some("sync") => cmd_sync(&git, &register, a.flags.iter().any(|f| f == "write")),
        Some("status") => cmd_status(&git, &register, &report),
        Some("next") => cmd_next(&git, &register),
        Some("record") => cmd_record(&git, &register, &a),
        Some("fixed") => cmd_fixed(&git, &register, &a),
        Some(other) => {
            eprintln!("xtask ledger: unknown subcommand `{other}`");
            eprintln!("{USAGE}");
            2
        }
        None => {
            println!("{USAGE}");
            2
        }
    }
}

fn read_scopes(register: &std::path::Path) -> Vec<Json> {
    // A MISSING REGISTER IS AN EMPTY ONE, and `sync` then reports every derived scope as added —
    // which is the honest reading, because nothing has been recorded about any of them.
    audit::load(register)
        .ok()
        .and_then(|d| d.get("scopes").as_array().map(<[Json]>::to_vec))
        .unwrap_or_default()
}

fn ids(scopes: &[Json]) -> Vec<String> {
    scopes
        .iter()
        .filter_map(|s| s.get("id").as_str().map(str::to_string))
        .collect()
}

fn cmd_sync(git: &Git, register: &std::path::Path, write: bool) -> i32 {
    let derived = audit::derive_scopes(git.repo());
    let existing = read_scopes(register);
    let derived_ids = ids(&derived);
    let existing_ids = ids(&existing);

    let added: Vec<&String> = derived_ids
        .iter()
        .filter(|i| !existing_ids.contains(i))
        .collect();
    let removed: Vec<&String> = existing_ids
        .iter()
        .filter(|i| !derived_ids.contains(i))
        .collect();

    for sid in &added {
        println!("+ {sid}");
    }
    for sid in &removed {
        println!("- {sid}  (path gone from the tree; its audit record goes with it)");
    }

    let merged = audit::merge(&derived, &existing);
    if added.is_empty() && removed.is_empty() {
        println!(
            "sync: no change -- the scope list already matches the tree ({} scopes)",
            derived.len()
        );
    }
    if write {
        if let Err(e) = audit::save(register, &audit::new_doc(merged.clone())) {
            eprintln!("audit-ledger: {e}");
            return 2;
        }
        println!(
            "sync: wrote {} ({} scopes)",
            rel(git, register),
            merged.len()
        );
    } else if !added.is_empty() || !removed.is_empty() {
        println!("sync: dry run -- pass --write to apply");
    }
    0
}

fn rel(git: &Git, path: &std::path::Path) -> String {
    path.strip_prefix(git.repo())
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// `x if x is not None else "-"` — `round` and `age` print a dash rather than an empty column.
fn dash(v: Option<impl ToString>) -> String {
    v.map_or_else(|| "-".to_string(), |x| x.to_string())
}

fn sorted_rows(rows: Vec<RowView>) -> Vec<RowView> {
    let mut rows = rows;
    rows.sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
    rows
}

fn cmd_status(git: &Git, register: &std::path::Path, report: &std::path::Path) -> i32 {
    let doc = match audit::load(register) {
        Ok(d) => d,
        Err(e) => return die(e),
    };
    let rows = match audit::rows(&doc, git) {
        Ok(r) => sorted_rows(r),
        Err(e) => return die(e),
    };
    let head = git.head().unwrap_or_default();

    let mut out: Vec<String> = vec![
        format!(
            "{:<46} {:<11} {:<12} {:>5} {:>6} {:>7}",
            "SCOPE", "KIND", "STATUS", "ROUND", "AGE", "LOC"
        ),
        "-".repeat(92),
    ];
    for r in &rows {
        out.push(format!(
            "{:<46} {:<11} {:<12} {:>5} {:>6} {:>7}",
            r.id,
            r.kind,
            r.status,
            dash(r.scope.get("round").as_i64()),
            dash(r.age),
            r.loc
        ));
    }
    let prod = audit::production(&rows);
    out.push(String::new());
    out.push(format!(
        "PRODUCTION LOC BY STATUS ({} scopes, {} LOC)",
        prod.len(),
        prod.iter().map(|r| r.loc).sum::<usize>()
    ));
    for key in audit::STATUS_BARS {
        let (got, pct) = audit::bar(&prod, key);
        out.push(format!("  {key:<12} {got:>7} LOC  {pct:>5.1}%"));
    }
    out.push(String::new());
    out.push(format!("HEAD {head}"));
    println!("{}", out.join("\n"));

    match write_report(report, &rows, &prod, &head) {
        Ok(()) => {
            println!("wrote {}", rel(git, report));
            0
        }
        Err(e) => die(e),
    }
}

/// The committed markdown report. Written with the same statuses the table above prints, from the
/// same rows, so the document and the terminal can never disagree.
fn write_report(
    path: &std::path::Path,
    rows: &[RowView],
    prod: &[&RowView],
    head: &str,
) -> Result<(), String> {
    let mut md: Vec<String> = vec![
        "# busbar audit status".to_string(),
        String::new(),
        "GENERATED by `cargo xtask ledger status` from `qa/audit-ledger.json`. Do not hand-edit."
            .to_string(),
        String::new(),
        "An audit result describes one tree. When a scope's tree hash moves, its result expires and"
            .to_string(),
        "the scope reads `stale` -- the code must be looked at again. Nothing here is a wall clock;"
            .to_string(),
        "`age` is commits between the audited commit and HEAD.".to_string(),
        String::new(),
        format!("HEAD at generation: `{head}`"),
        String::new(),
        "## Totals over production LOC".to_string(),
        String::new(),
        "| status | LOC | share |".to_string(),
        "| --- | ---: | ---: |".to_string(),
    ];
    for key in audit::STATUS_BARS {
        let (got, pct) = audit::bar(prod, key);
        md.push(format!("| {key} | {got} | {pct:.1}% |"));
    }

    for kind in ["production", "test", "instrument"] {
        let of_kind: Vec<&RowView> = rows.iter().filter(|r| r.kind == kind).collect();
        if of_kind.is_empty() {
            continue;
        }
        md.push(String::new());
        md.push(format!("## {kind} scopes ({})", of_kind.len()));
        md.push(String::new());
        md.push(
            "| scope | status | round | age (commits) | LOC | result | auditor | report |"
                .to_string(),
        );
        md.push("| --- | --- | ---: | ---: | ---: | --- | --- | --- |".to_string());
        for r in of_kind {
            let sc = &r.scope;
            let counts = sc.get("counts");
            let mut res = sc.get("result").as_str().unwrap_or("unaudited").to_string();
            if counts.truthy() {
                let listed: Vec<String> = audit::SEVERITIES
                    .iter()
                    .filter(|k| counts.as_object().is_some_and(|o| o.contains_key(k)))
                    .map(|k| format!("{k}={}", json_lite::py_repr_json(counts.get(k))))
                    .collect();
                res = format!("{res} ({})", listed.join(", "));
            } else if res == "findings" {
                res = format!("{res} (severities unrecorded)");
            }
            let auditor = sc.get("auditor").as_str().unwrap_or("-");
            let rep = sc
                .get("report")
                .as_str()
                .map_or_else(|| "-".to_string(), |p| format!("`{p}`"));
            md.push(format!(
                "| `{}` | {} | {} | {} | {} | {res} | {auditor} | {rep} |",
                r.id,
                r.status,
                dash(sc.get("round").as_i64()),
                dash(r.age),
                r.loc
            ));
        }
    }

    md.push(String::new());
    md.push("## Statuses".to_string());
    md.push(String::new());
    for key in audit::NEXT_ORDER.iter().chain(["in_progress"].iter()) {
        md.push(format!("- `{key}` -- {}", audit::next_why(key)));
    }
    md.push(String::new());

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
    }
    std::fs::write(path, md.join("\n")).map_err(|e| format!("{}: {e}", path.display()))
}

fn cmd_next(git: &Git, register: &std::path::Path) -> i32 {
    let doc = match audit::load(register) {
        Ok(d) => d,
        Err(e) => return die(e),
    };
    let rows = match audit::rows(&doc, git) {
        Ok(r) => r,
        Err(e) => return die(e),
    };

    // `in_progress` is not on the worklist: a round is already running against it, and putting it
    // back on the queue is how two auditors end up reading the same scope.
    let mut ranked: Vec<(usize, i64, String, &RowView)> = rows
        .iter()
        .filter_map(|r| {
            let band = audit::NEXT_ORDER.iter().position(|s| *s == r.status)?;
            // Among CLEAN scopes the oldest read comes first; among everything else the biggest.
            let second = if r.status == "clean" {
                -(r.age.unwrap_or(0) as i64)
            } else {
                -(r.loc as i64)
            };
            Some((band, second, r.id.clone(), r))
        })
        .collect();
    ranked.sort_by(|a, b| (a.0, a.1, &a.2).cmp(&(b.0, b.1, &b.2)));

    println!(
        "{:<4} {:<46} {:<11} {:<12} {:>7}  WHY",
        "#", "SCOPE", "KIND", "STATUS", "LOC"
    );
    for (i, (_, _, _, r)) in ranked.iter().enumerate() {
        println!(
            "{:<4} {:<46} {:<11} {:<12} {:>7}  {}",
            i + 1,
            r.id,
            r.kind,
            r.status,
            r.loc,
            audit::next_why(r.status)
        );
    }
    0
}

fn need<'a>(a: &'a Args, key: &str) -> Result<&'a String, String> {
    a.map
        .get(key)
        .ok_or_else(|| format!("`--{key}` is required"))
}

fn find_scope<'a>(scopes: &'a mut [Json], sid: &str) -> Option<&'a mut Json> {
    scopes
        .iter_mut()
        .find(|s| s.get("id").as_str() == Some(sid))
}

// ---------------------------------------------------------------------------------------------
// public-hygiene refusal — `record --report` must not reintroduce the class of leak this branch
// just cleaned out of qa/audit-ledger.json (an audit-round label, a bare commit-hash citation, a
// pointer to a document the reader has never seen). `scripts/public-hygiene-lint.py` is the full
// 11-rule instrument and stays the source of truth for what SHIPS; xtask has no `regex` dependency
// (see xtask/Cargo.toml's own comment on why), so this is a dependency-free, hand-rolled mirror of
// the THREE rules that actually fired against this file — `internal-issue-id`,
// `commit-hash-citation` and `private-doc-reference` — narrow enough to be exact where it matters
// and conservative (never over-fires on legitimate technical prose) rather than byte-for-byte with
// the Python. It runs on `--report` alone: `--auditor` is a free-text identity field the register
// already spells many ways (`opus-pass1`, `round-4 finder fleet`), not a place this refusal reaches.
// ---------------------------------------------------------------------------------------------

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// Case-insensitive whole-word search: hyphen-permissive, exactly as in the Python's `\b` (a
/// hyphenated identifier that embeds the flagged word still matches; an underscore-joined one,
/// which reads as a name rather than prose, does not).
fn contains_word_ci(text: &str, word: &str) -> bool {
    let hay: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();
    let pat: Vec<char> = word.chars().flat_map(char::to_lowercase).collect();
    if pat.is_empty() || hay.len() < pat.len() {
        return false;
    }
    for i in 0..=(hay.len() - pat.len()) {
        if hay[i..i + pat.len()] == pat[..] {
            let before_ok = i == 0 || !is_ident_char(hay[i - 1]);
            let after = i + pat.len();
            let after_ok = after >= hay.len() || !is_ident_char(hay[after]);
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

/// Mirrors `\b(?:round|wave|audit)\s*#?\s*\d+\b` (`hash_required = false`) and
/// `\b(?:task|item|finding|issue|defect|gap|guard|ticket)s?\s*#\s*\d+` (`hash_required = true`):
/// one of `words`, word-bounded, an optional trailing `s`, optional spaces, a `#` (required only
/// when `hash_required`), optional spaces, then at least one digit. Returns the matched slice.
fn word_then_number(text: &str, words: &[&str], hash_required: bool) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let lower: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();
    for word in words {
        let pat: Vec<char> = word.chars().flat_map(char::to_lowercase).collect();
        if pat.len() > lower.len() {
            continue;
        }
        for i in 0..=(lower.len() - pat.len()) {
            if lower[i..i + pat.len()] != pat[..] {
                continue;
            }
            let before_ok = i == 0 || !is_ident_char(lower[i - 1]);
            if !before_ok {
                continue;
            }
            let mut k = i + pat.len();
            if k < lower.len() && lower[k] == 's' {
                k += 1;
            }
            while k < lower.len() && lower[k] == ' ' {
                k += 1;
            }
            let saw_hash = k < lower.len() && lower[k] == '#';
            if saw_hash {
                k += 1;
            }
            if hash_required && !saw_hash {
                continue;
            }
            while k < lower.len() && lower[k] == ' ' {
                k += 1;
            }
            let digits_start = k;
            while k < lower.len() && lower[k].is_ascii_digit() {
                k += 1;
            }
            if k > digits_start {
                return Some(chars[i..k].iter().collect());
            }
        }
    }
    None
}

/// Rule 1 — `internal-issue-id`: an audit-round or tracker citation the reader cannot open.
fn rule_internal_issue_id(text: &str) -> Option<String> {
    // The literal word this whole rule exists to catch, not a citation of it.
    // public-hygiene-lint: allow — the pattern this rule is written to detect, not a leaked reference
    if contains_word_ci(text, "codeaudit") {
        return Some("cites the audit-tool name this rule exists to catch".to_string());
    }
    if let Some(hit) = word_then_number(text, &["round", "wave", "audit"], false) {
        return Some(format!("cites `{hit}`, an audit-round label"));
    }
    if let Some(hit) = word_then_number(
        text,
        &[
            "task", "item", "finding", "issue", "defect", "gap", "guard", "ticket",
        ],
        true,
    ) {
        return Some(format!("cites `{hit}`, a tracker/finding id"));
    }
    None
}

/// The crypto/algorithm vocabulary that keeps a hex-shaped word from reading as a commit citation
/// (`sha256`, `secp256k1`, `(ed25519)`, `blake3`, `hash & (N-1)`'s neighbours). `sha`/`secp`/`aes`/
/// `poly` only count when immediately followed by a digit, matching the Python's `sha-?\d` etc.;
/// the rest are plain substrings.
fn crypto_context(text: &str) -> bool {
    let lower = text.to_lowercase();
    if [
        "digest", "checksum", "blake", "hmac", "argon", "scrypt", "bcrypt", "base64", "25519",
        "chacha",
    ]
    .iter()
    .any(|w| lower.contains(w))
    {
        return true;
    }
    let chars: Vec<char> = lower.chars().collect();
    for prefix in ["sha", "secp", "aes", "poly"] {
        let mut start = 0;
        while let Some(pos) = lower[start..].find(prefix) {
            let idx = start + pos;
            let mut after = idx + prefix.len();
            if chars.get(after) == Some(&'-') {
                after += 1;
            }
            if chars.get(after).is_some_and(char::is_ascii_digit) {
                return true;
            }
            start = idx + 1;
        }
    }
    false
}

fn looks_like_hash(hit: &[char]) -> bool {
    (7..=40).contains(&hit.len())
        && hit.iter().any(char::is_ascii_digit)
        && hit.iter().any(|c| c.is_ascii_alphabetic())
}

/// Rule 2 — `commit-hash-citation`: a keyword-led or bare-parenthesized hex run. A hash resolves
/// only against history the reader does not have.
fn rule_commit_hash(text: &str) -> Option<String> {
    if crypto_context(text) {
        return None;
    }
    let chars: Vec<char> = text.chars().collect();
    let lower: Vec<char> = text.chars().flat_map(char::to_lowercase).collect();

    for kw in [
        "fixed in",
        "landed in",
        "introduced in",
        "reverted in",
        "commit",
        "sha",
        "rev",
        "revision",
    ] {
        let pat: Vec<char> = kw.chars().collect();
        if pat.len() > lower.len() {
            continue;
        }
        for i in 0..=(lower.len() - pat.len()) {
            if lower[i..i + pat.len()] != pat[..] {
                continue;
            }
            let before_ok = i == 0 || !is_ident_char(lower[i - 1]);
            if !before_ok {
                continue;
            }
            let mut k = i + pat.len();
            while k < lower.len() && lower[k] == ' ' {
                k += 1;
            }
            for quote in ['`', '"', '\''] {
                if k < lower.len() && lower[k] == quote {
                    k += 1;
                }
            }
            let start = k;
            while k < lower.len() && lower[k].is_ascii_hexdigit() {
                k += 1;
            }
            if looks_like_hash(&chars[start..k]) {
                let hit: String = chars[start..k].iter().collect();
                return Some(format!("cites commit `{hit}`"));
            }
        }
    }

    // The bare parenthetical form: a hex run inside unlabeled parentheses.
    for i in 0..chars.len() {
        if chars[i] != '(' {
            continue;
        }
        let mut k = i + 1;
        while k < chars.len() && chars[k] == ' ' {
            k += 1;
        }
        let start = k;
        while k < chars.len() && chars[k].is_ascii_hexdigit() {
            k += 1;
        }
        let mut close = k;
        while close < chars.len() && chars[close] == ' ' {
            close += 1;
        }
        if close < chars.len() && chars[close] == ')' && (7..=12).contains(&(k - start)) {
            let hit: &[char] = &chars[start..k];
            if looks_like_hash(hit) {
                let hit: String = hit.iter().collect();
                return Some(format!("cites commit `({hit})`"));
            }
        }
    }
    None
}

/// Rule 3 — `private-doc-reference`: a pointer to a document the reader cannot open. This mirrors
/// the LITERAL-NAME half of the Python rule (the half responsible for the 3 real hits this branch
/// found and fixed) rather than the `§`-with-forbid-list half, whose false-positive controls (a
/// doc citing its own section, RFC/OIDC/JSON-RPC citations) are load-bearing enough that a partial
/// port would either miss real leaks or nag on legitimate standards prose.
fn rule_private_doc(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    // Two of the Python rule's literal-phrase needles, quoted here only because this function's
    // whole job is to detect them, not to cite them.
    // public-hygiene-lint: allow — needles this rule is written to detect, not leaked references
    if lower.contains("companion design") {
        return Some("cites an internal companion write-up the reader cannot open".into());
    }
    // public-hygiene-lint: allow — needle this rule is written to detect, not a leaked reference
    if lower.contains("design doc") || lower.contains("design document") {
        return Some("cites an internal planning document the reader cannot open".into());
    }
    // Named internal documents. Each is a needle this rule exists to catch, not a citation of one.
    for needle in [
        "engine-bugs.md",            // public-hygiene-lint: allow — needle, not a citation
        "mcp-design.md",             // public-hygiene-lint: allow — needle, not a citation
        "a2a-design.md",             // public-hygiene-lint: allow — needle, not a citation
        "smart-router-design.md",    // public-hygiene-lint: allow — needle, not a citation
        "config-redesign-design.md", // public-hygiene-lint: allow — needle, not a citation
        "busbarai-private",          // public-hygiene-lint: allow — needle, not a citation
        "_handoffs",                 // public-hygiene-lint: allow — needle, not a citation
    ] {
        if lower.contains(needle) {
            return Some("cites an internal document the reader cannot open".to_string());
        }
    }
    if let Some(pos) = lower.find("-spec.md") {
        let start = lower[..pos]
            .rfind(|c: char| !is_ident_char(c) && c != '-')
            .map_or(0, |p| p + 1);
        let hit = &text[start..pos + "-spec.md".len()];
        return Some(format!(
            "cites `{hit}`, an internal spec document the reader cannot open"
        ));
    }
    if let Some(pos) = lower.find("audit-decisions") {
        if let Some(end) = lower[pos..].find(".md") {
            let hit = &text[pos..pos + end + 3];
            return Some(format!(
                "cites `{hit}`, an internal document the reader cannot open"
            ));
        }
    }
    None
}

/// The three rules together, for `record --report`. `None` means the text is clean.
pub fn hygiene_refusal(report: &str) -> Option<String> {
    rule_internal_issue_id(report)
        .or_else(|| rule_commit_hash(report))
        .or_else(|| rule_private_doc(report))
}

#[cfg(test)]
mod hygiene_tests {
    use super::hygiene_refusal;

    // Every fixture below quotes a REAL example of the class each rule refuses -- that is the
    // point of a RED test -- so each is exactly the kind of text `hygiene_refusal` exists to
    // catch, not a reference leaked into shipped prose. Each line carries its own escape hatch
    // (the marker is per-line, not per-file) rather than one blanket exemption for the module.
    #[test]
    fn red_internal_issue_id() {
        // public-hygiene-lint: allow — RED fixture quoting the exact class this rule refuses
        assert!(hygiene_refusal("gate/audits/codeaudit-examples-r1.md").is_some());
        // public-hygiene-lint: allow — RED fixture quoting the exact class this rule refuses
        assert!(hygiene_refusal("filed against round 4 of the audit").is_some());
        // public-hygiene-lint: allow — RED fixture quoting the exact class this rule refuses
        assert!(hygiene_refusal("would have caught task #141 earlier").is_some());
    }

    #[test]
    fn red_commit_hash() {
        // public-hygiene-lint: allow — RED fixture quoting the exact class this rule refuses
        assert!(hygiene_refusal("fixed in 4bb03d7 after the parser regressed").is_some());
        // Pure-digit parentheticals are not hex CITATIONS (no [a-f] letter to distinguish them
        // from any other number in prose) -- matches the lint's own `(?=[0-9a-f]*[a-f])` guard.
        assert!(hygiene_refusal("the prior behaviour (2789501) allowed it").is_none());
        // public-hygiene-lint: allow — RED fixture quoting the exact class this rule refuses
        assert!(hygiene_refusal("the prior behaviour (53d5774bd70d) allowed it").is_some());
    }

    #[test]
    fn red_private_doc() {
        // public-hygiene-lint: allow — RED fixture quoting the exact class this rule refuses
        assert!(hygiene_refusal("see the companion design for the projection rules").is_some());
        // public-hygiene-lint: allow — RED fixture quoting the exact class this rule refuses
        assert!(hygiene_refusal("recorded in audit-decisions-1.5.3.md as resolved").is_some());
        // public-hygiene-lint: allow — RED fixture quoting the exact class this rule refuses
        assert!(hygiene_refusal("filed in plugin-settings-schema-SPEC.md").is_some());
    }

    #[test]
    fn green_ordinary_behaviour_prose() {
        assert!(hygiene_refusal("zero; read fully").is_none());
        assert!(hygiene_refusal(
            "foreign wire field bricks a VirtualKey row (fixed); redeem_plane_token defaulted \
             to first-redemption (fixed); all 10 production files read"
        )
        .is_none());
        // Crypto vocabulary that merely LOOKS hex-shaped must stay silent.
        assert!(hygiene_refusal("the digest is sha256(prev_hash | seq | ts)").is_none());
        assert!(hygiene_refusal("a signed token: (ed25519), two base64url segments").is_none());
        // Ordinary prose using "round" as an English word with no attached number stays silent.
        assert!(
            hygiene_refusal("every fix proven by a failing case first, 15/15 plants caught")
                .is_none()
        );
    }
}

fn cmd_record(git: &Git, register: &std::path::Path, a: &Args) -> i32 {
    let doc = match audit::load(register) {
        Ok(d) => d,
        Err(e) => return die(e),
    };
    let (sid, round, result, report, auditor) = match (
        need(a, "scope"),
        need(a, "round"),
        need(a, "result"),
        need(a, "report"),
        need(a, "auditor"),
    ) {
        (Ok(a1), Ok(a2), Ok(a3), Ok(a4), Ok(a5)) => (a1, a2, a3, a4, a5),
        _ => {
            eprintln!("{USAGE}");
            return 2;
        }
    };
    let Ok(round) = round.parse::<i64>() else {
        return die(format!("--round {round} is not an integer"));
    };
    if !audit::RESULTS.contains(&result.as_str()) {
        return die(format!(
            "--result {} is not one of {}",
            json_lite::py_repr(result),
            audit::RESULTS.join(", ")
        ));
    }
    // A RECORD IS A CLAIM SOMEBODY MAKES, and both halves of "who says so" have to be there. An
    // empty `--report` or `--auditor` writes a row the report renders as evidence and the confirming
    // rule reads as a voice, out of a flag that was passed and left blank.
    for (flag, value) in [("report", report), ("auditor", auditor)] {
        if value.trim().is_empty() {
            return die(format!(
                "--{flag} {} is blank -- a record names who read the scope and what they wrote",
                json_lite::py_repr(value)
            ));
        }
    }
    // THE REGISTER IS A PUBLIC FILE. `public-hygiene-lint.py` gates every file a customer can
    // read, qa/audit-ledger.json included, and a `--report` that cites an audit round, a bare
    // commit hash or a document the reader cannot open is the exact class of leak this refuses
    // before it is ever written, rather than caught the next time the lint happens to run.
    if let Some(why) = hygiene_refusal(report) {
        return die(format!(
            "--report {} {why} -- describe the BEHAVIOUR the round found, not the artifact that \
             recorded it (see scripts/public-hygiene-lint.py)",
            json_lite::py_repr(report)
        ));
    }

    let counts = match parse_counts(a.map.get("counts").map(String::as_str)) {
        Ok(c) => c,
        Err(e) => return die(e),
    };

    let at = match a.map.get("at") {
        Some(rev) => match git.run(&["rev-parse", rev]) {
            Ok(s) => s.trim().to_string(),
            Err(e) => return die(e),
        },
        None => match git.head() {
            Ok(h) => h,
            Err(e) => return die(e),
        },
    };
    let all = match git.files_at(&at) {
        Ok(f) => f,
        Err(e) => return die(e),
    };

    let mut scopes = doc.get("scopes").as_array().unwrap_or(&[]).to_vec();
    let Some(sc) = find_scope(&mut scopes, sid) else {
        return die(format!(
            "no scope {} in the register (see `status` for the list)",
            json_lite::py_repr(sid)
        ));
    };
    let hash = audit::tree_hash(sc, &all);

    let Some(o) = sc.as_object_mut() else {
        return die(format!("scope {sid} is not an object"));
    };
    o.insert("round", Json::Int(round));
    o.insert("result", Json::Str(result.clone()));
    o.insert("counts", Json::Object(counts.clone()));
    o.insert("report", Json::Str(report.clone()));
    o.insert("auditor", Json::Str(auditor.clone()));
    o.insert("tree_hash", hash.clone().map_or(Json::Null, Json::Str));
    o.insert("audited_at", Json::Str(at.clone()));
    // A NEW ROUND CLEARS ANY FIX STAMP. The fix was stamped against an earlier reading; carrying it
    // forward would let a new round inherit a closure it did not earn.
    o.insert("fixed_at", Json::Null);

    // THE ROUNDS LIST IS APPEND-ONLY. This is the evidence `clean` is computed from, and a command
    // that could overwrite a round is a command that could erase the second auditor.
    let mut r = Obj::new();
    r.insert("round", Json::Int(round));
    r.insert("result", Json::Str(result.clone()));
    r.insert("auditor", Json::Str(auditor.clone()));
    r.insert("audited_at", Json::Str(at.clone()));
    r.insert("tree_hash", hash.clone().map_or(Json::Null, Json::Str));
    r.insert("counts", Json::Object(counts));
    r.insert("report", Json::Str(report.clone()));
    let mut rounds = o
        .get("rounds")
        .and_then(Json::as_array)
        .map(<[Json]>::to_vec)
        .unwrap_or_default();
    rounds.push(Json::Object(r));
    o.insert("rounds", Json::Array(rounds));

    let mut out = doc.clone();
    if let Some(d) = out.as_object_mut() {
        d.insert("scopes", Json::Array(scopes));
    }
    if let Err(e) = audit::save(register, &out) {
        return die(e);
    }
    println!(
        "recorded {sid}: round {round} {result} at {} ({})",
        &at[..8.min(at.len())],
        short12(hash.as_deref())
    );
    0
}

/// `(tree_hash or "no-files")[:12]` — a scope that owns no file has no hash, and saying so is the
/// point: it can never be clean.
fn short12(h: Option<&str>) -> String {
    let s = h.unwrap_or("no-files");
    s[..12.min(s.len())].to_string()
}

fn parse_counts(spec: Option<&str>) -> Result<Obj, String> {
    let mut counts = Obj::new();
    let Some(spec) = spec.filter(|s| !s.is_empty()) else {
        return Ok(counts);
    };
    for part in spec.split(',') {
        if part.trim().is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        let k = k.trim().to_uppercase();
        if !audit::SEVERITIES.contains(&k.as_str()) {
            return Err(format!(
                "unknown severity {} (want one of {})",
                json_lite::py_repr(&k),
                audit::SEVERITIES.join(", ")
            ));
        }
        let n: i64 = v
            .trim()
            .parse()
            .map_err(|_| format!("severity {k} = {} is not a count", json_lite::py_repr(v)))?;
        counts.insert(k, Json::Int(n));
    }
    Ok(counts)
}

fn cmd_fixed(git: &Git, register: &std::path::Path, a: &Args) -> i32 {
    let doc = match audit::load(register) {
        Ok(d) => d,
        Err(e) => return die(e),
    };
    let Ok(sid) = need(a, "scope") else {
        eprintln!("{USAGE}");
        return 2;
    };
    let mut scopes = doc.get("scopes").as_array().unwrap_or(&[]).to_vec();
    let Some(sc) = find_scope(&mut scopes, sid) else {
        return die(format!(
            "no scope {} in the register (see `status` for the list)",
            json_lite::py_repr(sid)
        ));
    };

    // ONLY A `findings` SCOPE CAN BE MARKED FIXED. Stamping a fix on anything else is stamping a
    // closure over a finding nobody recorded.
    if sc.get("result").as_str() != Some("findings") {
        return die(format!(
            "{sid} has result {} -- only a `findings` scope can be marked fixed",
            json_lite::py_repr_json(sc.get("result"))
        ));
    }

    let fix_at = match a.map.get("commit") {
        Some(rev) => match git.run(&["rev-parse", rev]) {
            Ok(s) => s.trim().to_string(),
            Err(e) => return die(e),
        },
        None => match git.head() {
            Ok(h) => h,
            Err(e) => return die(e),
        },
    };

    // THE ROUND MUST HAVE READ THE TREE IT CLAIMS. If the stored hash is not the hash of the scope
    // at the commit the round names, the round was stamped against a tree it did not read, and a
    // fix stamped on top of that inherits the lie.
    //
    // AND A COMMIT GIT CANNOT PRODUCE IS NOT A COMMIT THAT AGREED. Refusing to resolve the audited
    // commit is exactly the shape this rule exists to catch, so it is a refusal here, not a skip.
    let at = sc.get("audited_at").as_str().unwrap_or("?").to_string();
    let at = at[..8.min(at.len())].to_string();
    match audit::audited_tree_hash(sc, git) {
        Ok(actual) if actual.as_deref() == sc.get("tree_hash").as_str() => {}
        Ok(_) => {
            return die(format!(
                "{sid}: the recorded hash is not the tree at the audited commit {at} -- the round \
                 was stamped against a tree it did not read. Re-record it before stamping a fix."
            ))
        }
        Err(e) => {
            return die(format!(
                "{sid}: the audited commit {at} cannot be resolved in this repository ({e}) -- the \
                 tree the round claims to have read cannot be produced, so the stamp cannot be \
                 checked. Re-record it before stamping a fix."
            ))
        }
    }

    let all = match git.files_at(&fix_at) {
        Ok(f) => f,
        Err(e) => return die(e),
    };
    // RE-HASH TO THE FIX COMMIT. This is what makes `fixed` non-self-certifying: the fixer's own
    // pre-fix zero rounds carry the OLD hash and therefore confirm nothing about the fixed tree.
    let hash = audit::tree_hash(sc, &all);
    let Some(o) = sc.as_object_mut() else {
        return die(format!("scope {sid} is not an object"));
    };
    o.insert("fixed_at", Json::Str(fix_at.clone()));
    o.insert("tree_hash", hash.clone().map_or(Json::Null, Json::Str));

    let mut out = doc.clone();
    if let Some(d) = out.as_object_mut() {
        d.insert("scopes", Json::Array(scopes));
    }
    if let Err(e) = audit::save(register, &out) {
        return die(e);
    }
    println!(
        "fixed {sid} at {} (re-hashed {})",
        &fix_at[..8.min(fix_at.len())],
        short12(hash.as_deref())
    );
    0
}

// ---------------------------------------------------------------------------------------------
// --check, shared with the registered gate
// ---------------------------------------------------------------------------------------------

/// Everything `--check` is red about, each block separately so the gate can own one row per rule.
#[derive(Default)]
pub struct CheckFindings {
    pub gaps: Vec<String>,
    pub missing: Vec<String>,
    pub problems: Vec<String>,
    pub invalid: Vec<String>,
    pub opens: Vec<String>,
    pub stamped: Vec<String>,
    /// Records whose `audited_at` is reachable from neither HEAD nor any `refs/audit-pins/*`.
    pub unreachable: Vec<String>,
    pub owed: Vec<String>,
    pub scopes: usize,
    pub clean_pct: f64,
}

impl CheckFindings {
    pub fn red(&self) -> bool {
        !self.gaps.is_empty()
            || !self.missing.is_empty()
            || !self.problems.is_empty()
            || !self.invalid.is_empty()
            || !self.opens.is_empty()
            || !self.stamped.is_empty()
            || !self.unreachable.is_empty()
            || !self.owed.is_empty()
    }
}

/// Every commit a record names, resolved at most once. `Err` is cached too: a commit that cannot be
/// produced cannot be produced on the second ask either, and asking again would be one process per
/// round for the answer that is already known.
type TreeCache = BTreeMap<String, Result<BTreeMap<String, String>, String>>;

/// The hash `rec`'s scope's files ACTUALLY had at the commit `rec` names, through the cache.
fn stamped_hash(
    git: &Git,
    trees: &mut TreeCache,
    sc: &Json,
    rec: &Json,
) -> Result<Option<String>, String> {
    let Some(at) = audit::record_at(rec) else {
        return Err("the record names no audited_at commit".to_string());
    };
    let files = trees
        .entry(at.to_string())
        .or_insert_with(|| git.files_at(at));
    match files {
        Ok(files) => Ok(audit::tree_hash(sc, files)),
        Err(e) => Err(e.clone()),
    }
}

/// The whole `--check` computation, once, for both the printer and the gate.
pub fn check(git: &Git, register: &std::path::Path) -> Result<CheckFindings, String> {
    let doc = audit::load(register)?;
    let all = git.files_at("HEAD")?;
    let rows = audit::rows(&doc, git)?;
    let mut f = CheckFindings {
        scopes: rows.len(),
        ..CheckFindings::default()
    };

    f.gaps = audit::coverage_gaps(&doc, &all);

    // THE TREE IMPLIES SCOPES THE REGISTER DOES NOT CARRY. A new crate is uncovered the moment it
    // lands, and this is the line that says so.
    let have: Vec<String> = rows.iter().map(|r| r.id.clone()).collect();
    f.missing = audit::derive_scopes(git.repo())
        .iter()
        .filter_map(|d| d.get("id").as_str().map(str::to_string))
        .filter(|i| !have.contains(i))
        .collect();

    f.problems = audit::register_problems(&doc);

    // ONE `ls-tree` PER COMMIT, not one per record. 150 scopes carrying 236 rounds name a couple of
    // dozen distinct commits between them, and re-resolving each one per round is the difference
    // between a check and a coffee break.
    let mut trees: TreeCache = BTreeMap::new();

    // ONE REACHABILITY ANSWER PER COMMIT, and the pins read once. `merge-base --is-ancestor` is a
    // process; 150 scopes carrying 236 rounds name a couple of dozen distinct commits between them.
    let pins = git.audit_pins();
    let mut reach: BTreeMap<String, Option<String>> = BTreeMap::new();

    for r in &rows {
        let sc = &r.scope;
        if r.status == "invalid" {
            f.invalid.push(format!(
                "{}  result {}",
                r.id,
                json_lite::py_repr_json(sc.get("result"))
            ));
        }

        // OPEN AT HIGH/MEDIUM, and a scope with findings but NO recorded severities counts too —
        // "we found things but did not say what" is not a lower severity than HIGH.
        //
        // The severities come from the RECORD THAT FOUND THEM, which is not always the scope's
        // top-level record: a later `record --result in_progress` overwrites `counts` with `{}`, and
        // reading the counts from there would report "severities unrecorded" about a round that
        // recorded them, or drop the scope entirely.
        if let (true, Some(found)) = (
            matches!(r.status, "open" | "stale"),
            audit::open_findings(sc, r.current_hash.as_deref()),
        ) {
            let counts = found.get("counts");
            let empty = !counts.truthy();
            let high = counts.get("HIGH").as_i64().unwrap_or(0);
            let medium = counts.get("MEDIUM").as_i64().unwrap_or(0);
            if empty || high != 0 || medium != 0 {
                let listed: Vec<String> = audit::SEVERITIES
                    .iter()
                    .filter(|k| counts.get(k).as_i64().unwrap_or(0) != 0)
                    .map(|k| format!("{k}={}", json_lite::py_repr_json(counts.get(k))))
                    .collect();
                let sev = if listed.is_empty() {
                    "severities unrecorded".to_string()
                } else {
                    listed.join(", ")
                };
                let stale = if r.status == "stale" {
                    "  (and the tree has moved since -- stale)"
                } else {
                    ""
                };
                f.opens.push(format!(
                    "{}  round {}  {sev}{stale}",
                    r.id,
                    dash(found.get("round").as_i64())
                ));
            }
        }

        // A RECORD WHOSE HASH IS NOT THE TREE AT THE COMMIT IT NAMES was stamped against a tree it
        // did not read, and every later reading of it is a reading of nothing. EVERY ROUND is a
        // record: `clean` is computed from the rounds list, so a round nobody re-hashes is a round
        // anybody can append. The top-level record is exempt once a fix is stamped, because `fixed`
        // deliberately re-hashes it to the fix commit.
        let mut records: Vec<(String, &Json)> = Vec::new();
        if !sc.get("fixed_at").truthy() {
            records.push((r.id.clone(), sc));
        }
        for (i, round) in sc
            .get("rounds")
            .as_array()
            .unwrap_or(&[])
            .iter()
            .enumerate()
        {
            records.push((format!("{} round[{i}]", r.id), round));
        }
        for (label, rec) in records {
            let Some(at) = audit::record_at(rec) else {
                continue;
            };
            let short = &at[..8.min(at.len())];

            // A COMMIT NOBODY CAN REACH IS A TREE NOBODY CAN RE-READ. The hash check above proves
            // the record's `tree_hash` is what its commit's tree ACTUALLY held — and it proves it
            // by asking git to produce that tree today. A commit on no branch, no tag and no pin is
            // one `git gc` away from not being producible at all, at which point every round
            // stamped against it becomes unverifiable and the register's whole claim rests on a
            // number nobody can recompute. The register is the tree's audit history; a history that
            // cites commits the repository is free to discard is a history of nothing.
            //
            // Reachable from HEAD is the ordinary case. Reachable from `refs/audit-pins/*` is the
            // declared one, for a reading taken off the current line — a ref somebody wrote, that
            // `for-each-ref` shows and that clones and fetches carry.
            let verdict = reach
                .entry(at.to_string())
                .or_insert_with(|| {
                    if git.reachable().contains(at) {
                        return None;
                    }
                    Some(if git.resolves(at) {
                        format!(
                            "resolves, and is an ancestor of neither HEAD nor any of the {} \
                             refs/audit-pins/* ref(s) this repository carries — one `git gc` from \
                             a tree nobody can re-read. Pin it: git update-ref \
                             refs/audit-pins/<name> {at}",
                            pins.len()
                        )
                    } else {
                        "does not resolve in this repository at all, so the tree it claims to \
                         have read cannot be produced from here"
                            .to_string()
                    })
                })
                .clone();
            if let Some(why) = verdict {
                f.unreachable
                    .push(format!("{label}  audited_at {short} {why}"));
            }
            match stamped_hash(git, &mut trees, sc, rec) {
                Ok(actual) if actual.as_deref() == rec.get("tree_hash").as_str() => {}
                Ok(_) => f.stamped.push(format!("{label}  audited_at {short}")),
                // FAILING TO RESOLVE THE COMMIT IS THE FINDING, not the absence of one. A rule whose
                // whole purpose is catching a stamp against an unread tree cannot go quiet exactly
                // when the named tree is the one git cannot produce.
                Err(e) => f.stamped.push(format!(
                    "{label}  audited_at {short} cannot be resolved in this repository, so the tree \
                     it claims to have read cannot be produced ({e})"
                )),
            }
        }

        // `fixed` IS NOT SELF-CERTIFYING. A scope whose HIGH or MEDIUM count is non-zero stays red
        // until SOMEBODY ELSE records a confirming zero round against the RE-HASHED tree. The bar is
        // the HIGH/MEDIUM bar an open scope is held to — a MEDIUM that closes itself is the same
        // hole as a HIGH that does, one severity down — and the fixer's own name, however it is
        // spelled this time, is not somebody else.
        let counts = sc.get("counts");
        let owing: Vec<String> = ["HIGH", "MEDIUM"]
            .iter()
            .filter(|k| counts.get(k).as_i64().unwrap_or(0) != 0)
            .map(|k| format!("{k}={}", json_lite::py_repr_json(counts.get(k))))
            .collect();
        if r.status == "fixed" && !owing.is_empty() {
            let fixer = audit::auditor_identity(sc.get("auditor"));
            let others: Vec<String> = audit::confirming_auditors(sc, r.current_hash.as_deref())
                .into_iter()
                .filter(|a| Some(a) != fixer.as_ref())
                .collect();
            if others.is_empty() {
                f.owed.push(format!(
                    "{}  round {}  {}",
                    r.id,
                    dash(sc.get("round").as_i64()),
                    owing.join(", ")
                ));
            }
        }
    }

    let prod = audit::production(&rows);
    f.clean_pct = audit::bar(&prod, "clean").1;
    Ok(f)
}

fn cmd_check(git: &Git, register: &std::path::Path) -> i32 {
    let f = match check(git, register) {
        Ok(f) => f,
        Err(e) => return die(e),
    };

    if !f.gaps.is_empty() {
        println!(
            "audit ledger: {} tracked file(s) belong to NO scope -- coverage is incomplete:",
            f.gaps.len()
        );
        for p in f.gaps.iter().take(20) {
            println!("  {p}");
        }
        if f.gaps.len() > 20 {
            println!("  ... and {} more", f.gaps.len() - 20);
        }
        println!("  run: cargo xtask ledger sync --write");
    }
    block(
        &f.missing,
        "scope(s) the tree implies are not in the register:",
        "  + ",
    );
    block(
        &f.problems,
        "register entr(ies) the instrument cannot read:",
        "  ",
    );
    block(
        &f.invalid,
        "scope(s) whose recorded result is not a result:",
        "  ",
    );
    block(
        &f.opens,
        "scope(s) OPEN at HIGH/MEDIUM (findings recorded, no fix stamped):",
        "  ",
    );
    block(
        &f.stamped,
        "record(s) whose hash is not the tree at the commit they claim to have read:",
        "  ",
    );
    block(
        &f.owed,
        "scope(s) whose HIGH/MEDIUM findings are stamped fixed with no confirming round:",
        "  ",
    );

    if f.red() {
        println!("audit ledger --check: RED");
        return 1;
    }
    println!(
        "audit ledger --check: GREEN -- {} scopes, coverage complete, no scope open at \
         HIGH/MEDIUM ({:.1}% of production LOC clean)",
        f.scopes, f.clean_pct
    );
    0
}

fn block(items: &[String], heading: &str, prefix: &str) {
    if items.is_empty() {
        return;
    }
    println!("audit ledger: {} {heading}", items.len());
    for i in items {
        println!("{prefix}{i}");
    }
}
