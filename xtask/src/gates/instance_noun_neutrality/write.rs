//! `cargo xtask gate instance-noun-neutrality --write` — THE LEDGER MOVES DOWN, NEVER UP.
//!
//! The burndown ledger is a ratchet: a `(noun, file)` row may fall when a drain lands, and a row
//! whose leak is gone must be struck. Both are chores a tool can do. What a tool must NEVER do is
//! the other direction — record a leak the ledger did not name, or raise a row's count — because
//! that is a baseline absorbing a rise, and the whole point of `:undocumented` is that a new
//! coupling is read by a person. The emitter this replaces printed the full census, so one
//! regeneration run quietly baselined 28 new rows and raised 3 more.
//!
//! So the arm derives the ledger it would write PARTIALLY: every lowering and every strike is
//! written (and `[pragma_ceiling]` carried down to the live count), and a row that would be added
//! or raised is REFUSED — left exactly as committed, never written, named in the verdict, and the
//! arm exits nonzero — UNLESS the ledger itself carries an owner-cited `[[allow_rise]]` for exactly
//! that `(noun, file)` at or above the live count. A refused rise therefore never holds a drain's
//! lowering hostage, and a lowering never carries a rise in with it:
//!
//! ```toml
//! [[allow_rise]]
//! noun = "mcp"
//! file = "crates/x/src/lib.rs"
//! count = 73
//! owner = "OWNER"        # an owner ruling: `Q<n>` or the word OWNER
//! reason = "..."
//! ```
//!
//! An allow is a line in a reviewed diff, not a flag: it names the owner ruling that licensed the
//! rise, and it stays in the ledger until that owner strikes it. An allow that cites no owner is
//! refused, and so is one below the live count.
//!
//! The rewrite is LINE-LEVEL over the committed file (a row's reviewed `category`/`wave` text is
//! kept); only `count` lines move, struck rows go, and `[pragma_ceiling]` is carried at the lower
//! of its value and the live pragma count. The `XTASK_INSN_EMIT_BASELINE` emitter prints this same
//! derivation (the lowered ledger, every refused row left as committed), so neither door can raise.

use std::collections::BTreeMap;

use crate::ctx::Ctx;
use crate::ledger::Row;

use super::{exempt, Leak, BASELINE};

/// The row `--write` reports on. Owed only by the write construction, which emits it INSTEAD of
/// the ordinary rows.
pub const ROW_WRITE: &str = "instance-noun-neutrality:write";

/// One owner-cited licence to record a leak above the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Allow {
    count: usize,
    owner: String,
}

/// Does `owner` cite an owner ruling? `Q<digits>` anywhere, or the word `OWNER`.
fn cites_owner(owner: &str) -> bool {
    if owner.contains("OWNER") {
        return true;
    }
    let b = owner.as_bytes();
    b.windows(2).any(|w| w[0] == b'Q' && w[1].is_ascii_digit())
}

/// What `--write` would do: the text it would write, what moved, and every row it refused to move
/// (each left in `text` exactly as committed).
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Derived {
    pub text: String,
    pub lowered: Vec<String>,
    pub struck: Vec<String>,
    pub raised_by_allow: Vec<String>,
    pub refused: Vec<String>,
}

/// One top-level block of the ledger: its header line (`[[leak]]`, `[pragma_ceiling]`, …) and the
/// lines under it. The prefix before the first header is a block with an empty header.
struct Block {
    header: String,
    lines: Vec<String>,
}

fn blocks(text: &str) -> Vec<Block> {
    let mut out = vec![Block {
        header: String::new(),
        lines: Vec::new(),
    }];
    for line in text.split_inclusive('\n') {
        let t = line.trim();
        if t.starts_with('[') && !t.starts_with("[\"") {
            out.push(Block {
                header: t.to_string(),
                lines: vec![line.to_string()],
            });
        } else if let Some(b) = out.last_mut() {
            b.lines.push(line.to_string());
        }
    }
    out
}

fn value<'a>(lines: &'a [String], key: &str) -> Option<&'a str> {
    lines.iter().find_map(|l| {
        let (k, v) = l.split_once('=')?;
        (k.trim() == key).then(|| v.trim())
    })
}

fn str_value(lines: &[String], key: &str) -> Option<String> {
    let v = value(lines, key)?;
    let v = v.strip_prefix('"')?.strip_suffix('"')?;
    Some(v.to_string())
}

fn int_value(lines: &[String], key: &str) -> Option<usize> {
    value(lines, key)?.parse().ok()
}

fn set_int(lines: &mut [String], key: &str, n: usize) {
    for l in lines.iter_mut() {
        if l.split_once('=').is_some_and(|(k, _)| k.trim() == key) {
            *l = format!("{key} = {n}\n");
        }
    }
}

fn render_new(l: &Leak) -> String {
    format!(
        "[[leak]]\nnoun = \"{}\"\nkind = \"{}\"\nfile = \"{}\"\ncount = {}\ncategory = \"{}\"\nwave = \"{}\"\n\n",
        l.noun,
        l.kind,
        l.file,
        l.count,
        l.category,
        l.wave.replace('"', "'")
    )
}

/// THE DERIVATION `--write` and the emitter share. Every fall and strike is applied; every refusal
/// (a rise or an addition no owner-cited allow licenses, or a row too malformed to judge) is named
/// in `refused` and its row is left in `text` byte for byte as committed.
pub(super) fn derive(committed: &str, leaks: &[Leak], live_pragmas: usize) -> Derived {
    let live: BTreeMap<(String, String), &Leak> = leaks
        .iter()
        .map(|l| ((l.noun.to_string(), l.file.clone()), l))
        .collect();
    let mut bs = blocks(committed);
    let mut refused: Vec<String> = Vec::new();

    // The allows first: a rise may be licensed only by one that cites its owner.
    let mut allows: BTreeMap<(String, String), Allow> = BTreeMap::new();
    for b in bs.iter().filter(|b| b.header == "[[allow_rise]]") {
        let (Some(noun), Some(file)) = (str_value(&b.lines, "noun"), str_value(&b.lines, "file"))
        else {
            refused.push("an [[allow_rise]] names no `noun` or no `file`".to_string());
            continue;
        };
        let owner = str_value(&b.lines, "owner").unwrap_or_default();
        let count = int_value(&b.lines, "count");
        match count {
            Some(count) if cites_owner(&owner) => {
                allows.insert((noun, file), Allow { count, owner });
            }
            Some(_) => refused.push(format!(
                "[[allow_rise]] {noun}@{file} cites no owner ruling (owner = \"{owner}\"; needs \
                 `Q<n>` or OWNER) — an allow nobody owns licenses nothing"
            )),
            None => refused.push(format!(
                "[[allow_rise]] {noun}@{file} has no integer `count` — an unbounded allow licenses \
                 nothing"
            )),
        }
    }
    let licensed = |key: &(String, String), now: usize| -> Result<String, String> {
        match allows.get(key) {
            Some(a) if a.count >= now => Ok(a.owner.clone()),
            Some(a) => Err(format!(
                " (its [[allow_rise]] from {} stops at {})",
                a.owner, a.count
            )),
            None => Err(String::new()),
        }
    };

    let mut seen: Vec<(String, String)> = Vec::new();
    let mut keep = vec![true; bs.len()];
    let mut lowered = Vec::new();
    let mut struck = Vec::new();
    let mut raised_by_allow = Vec::new();
    for (i, b) in bs.iter_mut().enumerate() {
        if b.header == "[pragma_ceiling]" {
            if let Some(c) = int_value(&b.lines, exempt::CEILING_KEY) {
                set_int(&mut b.lines, exempt::CEILING_KEY, c.min(live_pragmas));
            }
            continue;
        }
        if b.header != "[[leak]]" {
            continue;
        }
        let (Some(noun), Some(file)) = (str_value(&b.lines, "noun"), str_value(&b.lines, "file"))
        else {
            refused.push(
                "a [[leak]] row names no `noun` or no `file` — fix the ledger by hand first"
                    .to_string(),
            );
            continue;
        };
        let was = int_value(&b.lines, "count").unwrap_or(0);
        let key = (noun.clone(), file.clone());
        seen.push(key.clone());
        let now = live.get(&key).map_or(0, |l| l.count);
        let site = format!("{noun}@{file}");
        if now == 0 {
            keep[i] = false;
            struck.push(site);
        } else if now < was {
            set_int(&mut b.lines, "count", now);
            lowered.push(format!("{site} {was} -> {now}"));
        } else if now > was {
            match licensed(&key, now) {
                Ok(owner) => {
                    set_int(&mut b.lines, "count", now);
                    raised_by_allow.push(format!("{site} {was} -> {now} ({owner})"));
                }
                Err(why) => refused.push(format!("{site} would RISE {was} -> {now}{why}")),
            }
        }
    }

    let mut appended = String::new();
    for (key, l) in &live {
        if seen.contains(key) {
            continue;
        }
        let site = format!("{}@{}", key.0, key.1);
        match licensed(key, l.count) {
            Ok(owner) => {
                appended.push_str(&render_new(l));
                raised_by_allow.push(format!("{site} NEW {} ({owner})", l.count));
            }
            Err(why) => refused.push(format!("{site} would be ADDED at {}{why}", l.count)),
        }
    }

    let mut text: String = bs
        .iter()
        .zip(&keep)
        .filter(|(_, k)| **k)
        .flat_map(|(b, _)| b.lines.iter().map(String::as_str))
        .collect();
    if !appended.is_empty() {
        if !text.ends_with("\n\n") {
            text.push('\n');
        }
        text.push_str(&appended);
    }
    Derived {
        text,
        lowered,
        struck,
        raised_by_allow,
        refused,
    }
}

/// The write arm's one row. Refuses wholesale on an unscannable tree or an unsettled pragma census;
/// on an unlicensed rise or addition it writes every lowering and strike, never the rise, and FAILS.
pub(super) fn rule_write(cx: &Ctx) -> Row {
    let census = match super::census(cx) {
        Ok(c) => c,
        Err(e) => {
            return Row::fail(
                ROW_WRITE,
                "the measurement --write would re-pin to could not be taken",
                format!("{e} — NOTHING was written."),
            )
        }
    };
    let refused_pragmas = census.pragmas.iter().filter(|p| !p.honoured()).count();
    if refused_pragmas > 0 {
        return Row::fail(
            ROW_WRITE,
            "--write refuses: a frozen-literal pragma is refused, so the census is not settled",
            format!(
                "{refused_pragmas} refused pragma(s); NOTHING was written. Run the gate for the \
                 findings."
            ),
        );
    }
    let committed = match cx.read(BASELINE) {
        Ok(t) => t,
        Err(e) => {
            return Row::fail(
                ROW_WRITE,
                "the ledger could not be read",
                format!("{BASELINE}: {e} — NOTHING was written."),
            )
        }
    };
    let derived = derive(&committed, &census.leaks, census.pragmas.len());
    let moved = format!(
        "{} lowered, {} struck, {} raised under an owner-cited allow. Lowered: {}. Struck: {}. \
         Allowed: {}",
        derived.lowered.len(),
        derived.struck.len(),
        derived.raised_by_allow.len(),
        derived.lowered.join(", "),
        derived.struck.join(", "),
        derived.raised_by_allow.join(", ")
    );
    // A SELFTEST RUN (an overlay over a fixture) measures the derivation and writes nothing: the
    // fixture on disk is not the ledger under test.
    let written = if derived.text == committed || cx.overlay().is_some() {
        Ok(false)
    } else {
        std::fs::write(cx.abs(BASELINE), &derived.text)
            .map(|()| true)
            .map_err(|e| e.to_string())
    };
    let written = match written {
        Ok(w) => w,
        Err(e) => {
            return Row::fail(
                ROW_WRITE,
                "the ledger could not be written",
                format!("{e} — the derivation was measured and not committed."),
            )
        }
    };
    let wrote = if written {
        format!("{BASELINE} written")
    } else {
        format!("{BASELINE} not rewritten")
    };
    if !derived.refused.is_empty() {
        return Row::fail(
            ROW_WRITE,
            "--write refuses a row that would be ADDED or would RISE — every lowering and strike is \
             written, a rise or an addition never",
            format!(
                "{} refusal(s), each row left at its committed count — a rise or an addition is \
                 NEVER written. A leak the ledger does not name, or one above its row, is a \
                 landing a person reads — drain it, or record an owner-cited [[allow_rise]] in \
                 {BASELINE}. Refused: {}. {wrote}: {moved}",
                derived.refused.len(),
                derived.refused.join(", ")
            ),
        );
    }
    if !written && derived.text == committed {
        return Row::pass(
            ROW_WRITE,
            "the ledger already equals what the tree measures",
            format!("{BASELINE} is at the measurement; nothing to write"),
        );
    }
    Row::pass(
        ROW_WRITE,
        "every row that fell is lowered and every drained row struck",
        format!("{wrote}: {moved}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leak(noun: &'static str, file: &str, count: usize) -> Leak {
        Leak {
            noun,
            kind: "plane",
            file: file.to_string(),
            count,
            category: "core",
            wave: "w",
        }
    }

    const LEDGER: &str = "# header\n\n[pragma_ceiling]\nfrozen_literal = 3\n\n\
                          [[leak]]\nnoun = \"mcp\"\nkind = \"plane\"\nfile = \"crates/a.rs\"\ncount = 5\ncategory = \"core\"\nwave = \"reviewed\"\n\n\
                          [[leak]]\nnoun = \"a2a\"\nkind = \"plane\"\nfile = \"crates/b.rs\"\ncount = 2\ncategory = \"core\"\nwave = \"reviewed\"\n\n";

    #[test]
    fn a_fall_is_lowered_a_drain_struck_and_the_pragma_ceiling_carried_down() {
        let d = derive(LEDGER, &[leak("mcp", "crates/a.rs", 3)], 2);
        assert!(d.refused.is_empty(), "only falls: {:?}", d.refused);
        assert!(d.text.contains("count = 3\n"), "{}", d.text);
        assert!(!d.text.contains("crates/b.rs"), "{}", d.text);
        assert!(d.text.contains("frozen_literal = 2\n"), "{}", d.text);
        assert!(
            d.text.contains("wave = \"reviewed\""),
            "reviewed text is kept"
        );
        assert_eq!(d.lowered, vec!["mcp@crates/a.rs 5 -> 3".to_string()]);
        assert_eq!(d.struck, vec!["a2a@crates/b.rs".to_string()]);
    }

    #[test]
    fn a_rise_or_a_new_row_is_refused_and_left_as_committed_while_the_fall_is_written() {
        let d = derive(
            LEDGER,
            &[
                leak("mcp", "crates/a.rs", 1),
                leak("a2a", "crates/b.rs", 9),
                leak("llm", "crates/c.rs", 1),
            ],
            2,
        );
        assert_eq!(
            d.refused,
            vec![
                "a2a@crates/b.rs would RISE 2 -> 9".to_string(),
                "llm@crates/c.rs would be ADDED at 1".to_string(),
            ]
        );
        // The fall is written, the rising row keeps its committed count, the new row is absent, and
        // the pragma ceiling comes down to the live count.
        assert_eq!(d.lowered, vec!["mcp@crates/a.rs 5 -> 1".to_string()]);
        let expected = LEDGER
            .replace(
                "file = \"crates/a.rs\"\ncount = 5",
                "file = \"crates/a.rs\"\ncount = 1",
            )
            .replace("frozen_literal = 3", "frozen_literal = 2");
        assert_eq!(d.text, expected);
        assert!(!d.text.contains("crates/c.rs"), "{}", d.text);
    }

    #[test]
    fn a_pragma_ceiling_is_never_raised() {
        let d = derive(
            LEDGER,
            &[leak("mcp", "crates/a.rs", 5), leak("a2a", "crates/b.rs", 2)],
            7,
        );
        assert!(d.refused.is_empty(), "{:?}", d.refused);
        assert_eq!(d.text, LEDGER);
    }

    #[test]
    fn an_owner_cited_allow_licenses_exactly_its_rise() {
        let allowed = format!(
            "{LEDGER}[[allow_rise]]\nnoun = \"a2a\"\nfile = \"crates/b.rs\"\ncount = 9\nowner = \"Q76\"\nreason = \"r\"\n\n\
             [[allow_rise]]\nnoun = \"llm\"\nfile = \"crates/c.rs\"\ncount = 1\nowner = \"OWNER RULING x\"\nreason = \"r\"\n"
        );
        let d = derive(
            &allowed,
            &[
                leak("mcp", "crates/a.rs", 5),
                leak("a2a", "crates/b.rs", 9),
                leak("llm", "crates/c.rs", 1),
            ],
            3,
        );
        assert!(d.refused.is_empty(), "both licensed: {:?}", d.refused);
        assert!(d.text.contains("count = 9\n"));
        assert!(d.text.contains("file = \"crates/c.rs\""));
        assert!(
            d.text.contains("[[allow_rise]]"),
            "the allow stays until its owner strikes it"
        );
        // Past the allow's count, or with no owner cited, it licenses nothing.
        let over = derive(
            &allowed,
            &[
                leak("mcp", "crates/a.rs", 5),
                leak("a2a", "crates/b.rs", 10),
            ],
            3,
        )
        .refused;
        assert!(over[0].contains("stops at 9"), "{over:?}");
        let unowned = allowed.replace("owner = \"Q76\"", "owner = \"me\"");
        let err = derive(
            &unowned,
            &[leak("mcp", "crates/a.rs", 5), leak("a2a", "crates/b.rs", 9)],
            3,
        )
        .refused;
        assert!(
            err.iter().any(|e| e.contains("cites no owner ruling")),
            "{err:?}"
        );
    }
}
