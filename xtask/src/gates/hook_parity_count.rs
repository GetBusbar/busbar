//! `cargo xtask gate hook-parity-count` — THE HOOK PARITY SUITE HAS ONE SIZE.
//!
//! The llm flip's gate is "every v1.5.5 hook test green on the driver" (BUSBAR-1.6.0.md l.2685),
//! and the suite's size was written four ways: 184 (the spec's appendix and Part 3, the driver's
//! header), 178 (Part 5, the TODO, the hook ABI's acceptance line), 189 (a raw attribute count) and,
//! counted by name off the `v1.5.5` tag, 181. A gate whose denominator is written four ways can be
//! declared met against whichever is smallest.
//!
//! THE NUMBER LIVES ONCE, where ARCHITECT ruling M9 (2026-10-14) puts it: the hook acceptance suite's
//! enumeration, `crates/busbar-kernel/src/hooks/tests/m4_acceptance_suite.rs` ([`SOURCE`]), whose
//! `HOOK_PARITY_TESTS`, `PROXY_ORIGIN` and `CORE_ORIGIN` its own test holds to the
//! corpus it lists. This gate reads those three constants from that file and holds every other
//! writing to them.
//!
//! | row | the claim |
//! | --- | --- |
//! | `hook-parity-count:written` | every place the spec, the TODO or a crate's source writes the suite's size or its split writes the enumeration's number, and the scan found the places |
//!
//! A quotation of a superseded figure is not a claim; the one there is ([`QUOTED`]) is named by
//! file and text, and an entry that quotes nothing is RED, so the exemption cannot outlive its quote.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_WRITTEN: &str = "hook-parity-count:written";

/// The one home of the suite's size (ARCHITECT ruling M9).
pub const SOURCE: &str = "crates/busbar-kernel/src/hooks/tests/m4_acceptance_suite.rs";

/// The figures the enumeration states: `(size, llm origin, kernel/loader/ranking origin)`.
#[derive(Clone, Copy)]
struct Owed {
    size: u64,
    llm: u64,
    rest: u64,
}

/// `const <name>: usize = <n>;` read out of the enumeration's file.
fn constant(text: &str, name: &str) -> Result<u64, String> {
    let needle = format!("const {name}: usize = ");
    let at = text
        .find(&needle)
        .ok_or_else(|| format!("{SOURCE} states no `{needle}<n>;`"))?;
    let tail = &text[at + needle.len()..];
    tail[..tail.find(';').unwrap_or(0)]
        .trim()
        .parse()
        .map_err(|_| format!("{SOURCE}: `{name}` is not a plain number"))
}

fn owed(cx: &Ctx) -> Result<Owed, String> {
    let text = cx.read(SOURCE).map_err(|e| format!("{SOURCE}: {e}"))?;
    let owed = Owed {
        size: constant(&text, "HOOK_PARITY_TESTS")?,
        llm: constant(&text, "PROXY_ORIGIN")?,
        rest: constant(&text, "CORE_ORIGIN")?,
    };
    if owed.llm + owed.rest != owed.size || owed.size == 0 {
        return Err(format!(
            "{SOURCE}: the split {} + {} does not make the size {}",
            owed.llm, owed.rest, owed.size
        ));
    }
    Ok(owed)
}

const DOCS: &[&str] = &["docs/design/BUSBAR-1.6.0.md", "docs/design/1.6.0-TODO.md"];

/// A superseded figure QUOTED, not claimed: `(file, the quoted text on its line)`.
const QUOTED: &[(&str, &str)] = &[(
    "crates/busbar-kernel/src/hooks/tests/m4_acceptance_suite.rs",
    "(\"178 hook tests plus 4 auth-cache tests\")",
)];

/// The fewest writings the scan must find. Today: the spec's eight and the driver's header; a scan
/// that finds fewer has gone blind, and a blind scan finds no wrong number.
const FLOOR: usize = 6;

/// Which figure a writing names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Figure {
    Size,
    Llm,
    Rest,
}

impl Figure {
    fn of(self, o: Owed) -> u64 {
        match self {
            Figure::Size => o.size,
            Figure::Llm => o.llm,
            Figure::Rest => o.rest,
        }
    }
}

/// How a writing names a figure: the phrase that follows the number, and which figure it is.
const AFTER: &[(&str, Figure)] = &[
    (" v1.5.5 hook tests", Figure::Size),
    (" 1.5.5 hook tests", Figure::Size),
    (" hook tests", Figure::Size),
    (" on the driver", Figure::Size),
    (" of llm origin", Figure::Llm),
    (" llm-origin", Figure::Llm),
    (" of kernel, loader and ranking origin", Figure::Rest),
    (" kernel/loader/ranking", Figure::Rest),
];

/// How a writing names the suite's size BEFORE the number.
const BEFORE: &[&str] = &["every hook test green on the driver — "];

/// One writing: where, the number written, and the figure it names.
struct Writing {
    at: String,
    written: u64,
    figure: Figure,
}

/// The number whose digits end at byte `end` of `line`, read only when it is a whole number: the
/// `5` that ends `1.5.5` or `v2` is a version, not a count.
fn number_ending_at(line: &str, end: usize) -> Option<u64> {
    let head = &line[..end];
    let rest = head.trim_end_matches(|c: char| c.is_ascii_digit());
    if rest.len() == head.len()
        || rest
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '.' || c == '_')
    {
        return None;
    }
    head[rest.len()..].parse().ok()
}

/// The number whose digits start at byte `start` of `line`.
fn number_starting_at(line: &str, start: usize) -> Option<u64> {
    let tail = &line[start..];
    let digits = tail.len() - tail.trim_start_matches(|c: char| c.is_ascii_digit()).len();
    tail[..digits].parse().ok()
}

/// Every writing of the suite's size or split on `line`.
fn writings_on(line: &str) -> Vec<(u64, Figure)> {
    let mut out = Vec::new();
    for (phrase, owed) in AFTER {
        for (at, _) in line.match_indices(phrase) {
            let Some(n) = number_ending_at(line, at) else {
                continue;
            };
            // `184/184 on the driver`: both halves are the size.
            if *phrase == " on the driver" {
                let digits = n.to_string().len();
                if at > digits && line.as_bytes()[at - digits - 1] == b'/' {
                    if let Some(m) = number_ending_at(line, at - digits - 1) {
                        out.push((m, *owed));
                    }
                } else {
                    continue;
                }
            }
            out.push((n, *owed));
        }
    }
    for phrase in BEFORE {
        for (at, _) in line.match_indices(phrase) {
            if let Some(n) = number_starting_at(line, at + phrase.len()) {
                out.push((n, Figure::Size));
            }
        }
    }
    out
}

fn quoted(file: &str, line: &str) -> bool {
    QUOTED.iter().any(|(f, q)| *f == file && line.contains(q))
}

/// Every writing in the spec, the TODO and the crates' source, and the quotes that matched.
fn writings(cx: &Ctx) -> Result<(Vec<Writing>, Vec<usize>), String> {
    let mut files: Vec<(String, String)> = Vec::new();
    for doc in DOCS {
        files.push((
            doc.to_string(),
            cx.read(doc).map_err(|e| format!("{doc}: {e}"))?,
        ));
    }
    let crates = cx
        .walk(&WalkSpec::new(["crates"]).ext("rs"))
        .map_err(|e| format!("crates/**/*.rs: {e}"))?;
    files.extend(crates.into_iter().map(|f| (f.rel_str(), f.text)));
    let mut found = Vec::new();
    let mut quotes_used = vec![0; QUOTED.len()];
    for (file, text) in &files {
        for (k, line) in text.lines().enumerate() {
            if let Some(q) = QUOTED
                .iter()
                .position(|(f, q)| f == file && line.contains(q))
            {
                quotes_used[q] += 1;
            }
            if quoted(file, line) {
                continue;
            }
            for (written, figure) in writings_on(line) {
                found.push(Writing {
                    at: format!("{file}:{}", k + 1),
                    written,
                    figure,
                });
            }
        }
    }
    Ok((found, quotes_used))
}

pub struct HookParityCountGate;

impl Gate for HookParityCountGate {
    fn name(&self) -> &'static str {
        "hook-parity-count"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_WRITTEN.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let read = owed(cx).and_then(|o| writings(cx).map(|w| (o, w)));
        let (owed, (found, quotes_used)) = match read {
            Ok(w) => w,
            Err(e) => {
                return Verdict::of(vec![Row::fail(
                    ROW_WRITTEN,
                    "the hook parity suite's writings could not be read",
                    format!("{e} — an unread document holds no wrong number, and no right one"),
                )])
            }
        };
        let mut problems: Vec<String> = found
            .iter()
            .filter(|w| w.written != w.figure.of(owed))
            .map(|w| {
                format!(
                    "{}: writes {} where the suite owes {} ({SOURCE})",
                    w.at,
                    w.written,
                    w.figure.of(owed)
                )
            })
            .collect();
        for (k, used) in quotes_used.iter().enumerate() {
            if *used == 0 {
                problems.push(format!(
                    "{}: the quoted-figure exemption `{}` quotes nothing; strike it",
                    QUOTED[k].0, QUOTED[k].1
                ));
            }
        }
        if found.len() < FLOOR {
            problems.push(format!(
                "the scan found {} writing(s) of the suite's size, under its floor of {FLOOR}: a \
                 scan that finds nothing finds no wrong number",
                found.len()
            ));
        }
        let row = if problems.is_empty() {
            Row::pass(
                ROW_WRITTEN,
                "every writing of the hook parity suite's size is the one number",
                format!(
                    "{} writing(s), each {} (or its split {} + {}), the enumeration's in {SOURCE}",
                    found.len(),
                    owed.size,
                    owed.llm,
                    owed.rest
                ),
            )
        } else {
            Row::fail(
                ROW_WRITTEN,
                "the hook parity suite's size is written more than one way",
                problems.join(" | "),
            )
        };
        Verdict::of(vec![row])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the tree writes the hook parity suite's size one way",
            &[ROW_WRITTEN],
        ));
        let spec = cx.read(DOCS[0]).unwrap_or_default();
        let plants: [(&str, &str, &str); 4] = [
            (
                "a stale 178 written back into the spec is RED",
                "the 181 v1.5.5 hook tests: 69",
                "the 178 v1.5.5 hook tests: 69",
            ),
            (
                "a split that no longer sums is RED",
                "69 of llm origin",
                "70 of llm origin",
            ),
            (
                "the flip gate's figure is read where it is written",
                "green on the driver — 181:",
                "green on the driver — 184:",
            ),
            (
                "the kernel-side split is read where it is written",
                "112 of kernel, loader and ranking origin",
                "114 of kernel, loader and ranking origin",
            ),
        ];
        for (name, from, to) in plants {
            let mut ov = Overlay::new();
            ov.set(DOCS[0], spec.replacen(from, to, 1));
            report.push(prove_red(
                cx,
                self,
                name,
                &[ROW_WRITTEN],
                ov,
                &["where the suite owes"],
            ));
        }
        // THE SOURCE MOVES, THE WRITINGS DO NOT: an enumeration that says 182 reds every 181.
        let source = cx.read(SOURCE).unwrap_or_default();
        let mut ov = Overlay::new();
        ov.set(
            SOURCE,
            source
                .replacen(
                    "HOOK_PARITY_TESTS: usize = 181",
                    "HOOK_PARITY_TESTS: usize = 182",
                    1,
                )
                .replacen("CORE_ORIGIN: usize = 112", "CORE_ORIGIN: usize = 113", 1),
        );
        report.push(prove_red(
            cx,
            self,
            "every writing is held to the enumeration's constant, read from its file",
            &[ROW_WRITTEN],
            ov,
            &["where the suite owes 182"],
        ));
        let m4 = QUOTED[0].0;
        let text = cx.read(m4).unwrap_or_default();
        let mut ov = Overlay::new();
        ov.set(m4, text.replace(QUOTED[0].1, "(the brief's own tally)"));
        report.push(prove_red(
            cx,
            self,
            "a quoted-figure exemption that quotes nothing is RED",
            &[ROW_WRITTEN],
            ov,
            &["quotes nothing"],
        ));
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_writing_shape_is_read() {
        assert_eq!(
            writings_on("the 178 v1.5.5 hook tests verbatim"),
            vec![(178, Figure::Size)]
        );
        assert_eq!(
            writings_on("the 178 1.5.5 hook tests"),
            vec![(178, Figure::Size)]
        );
        assert_eq!(
            writings_on("gate = 184/178 on the driver (70 llm-origin; 114 kernel/loader/ranking)"),
            vec![
                (184, Figure::Size),
                (178, Figure::Size),
                (70, Figure::Llm),
                (114, Figure::Rest)
            ]
        );
        assert_eq!(
            writings_on("every hook test green on the driver — 189: the"),
            vec![(189, Figure::Size)]
        );
        assert!(writings_on("the hook tests run on the driver").is_empty());
        assert!(writings_on("~~184~~ v1.5.5 hook tests").is_empty());
    }

    #[test]
    fn the_constants_are_read_from_the_enumeration() {
        let text = "pub(crate) const HOOK_PARITY_TESTS: usize = 181;\n";
        assert_eq!(constant(text, "HOOK_PARITY_TESTS"), Ok(181));
        assert!(constant(text, "PROXY_ORIGIN").is_err());
    }
}
