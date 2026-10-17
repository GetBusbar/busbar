//! `cargo xtask gate default-measurements` — A DEFAULT AUTHORISED BY A MEASUREMENT NAMES ITS COMMAND.
//!
//! TODO l.2147-2175 ("TWO WRITTEN BYTE-NEUTRALITY CLAIMS ARE FALSE — and each was the justification
//! for a default"): `root-llm` and `root-admin` were turned on by default on the strength of a comment
//! beside each saying the owed golden read the same either way. Both measurements were false at HEAD,
//! and nothing re-ran them: "a fact written into a comment is a snapshot with no expiry date on it."
//! The remedy it names, made mechanical: **any comment that authorises a default by citing a
//! measurement must name the command that reproduces it, and that command joins the gate set.**
//!
//! | row | the claim |
//! | --- | --- |
//! | `default-measurements:cited` | in every workspace manifest, the comment block of each feature on the `default` line (and of the `default` line itself) that cites a measurement names `` `cargo xtask gate <name>` `` with `<name>` a registered gate, and the scan read the manifests it owes |
//!
//! A comment CITES A MEASUREMENT when it carries one of [`CLAIM_WORDS`]. Over-matching is the safe
//! direction (BUSBAR-1.6.0.md: "when an instrument must choose, it false-fails"): a block that uses
//! the words without making the claim names a gate anyway or loses the words.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_CITED: &str = "default-measurements:cited";

/// The spellings of a measurement claim, matched lowercase.
pub const CLAIM_WORDS: &[&str] = &[
    "measur",
    "read the same",
    "moved no",
    "byte-identical",
    "re-run",
    "owed golden",
];

/// The command a claim must name.
const COMMAND: &str = "`cargo xtask gate ";

/// The manifest the selftest plants into: the composition root's, which carries the defaults.
const ROOT_MANIFEST: &str = "crates/busbar/Cargo.toml";

/// The fewest manifests the scan must read: the 24 workspace crates less those that leave.
const FLOOR: usize = 10;

/// One feature's comment block in a manifest's `[features]` table.
struct Feature {
    name: String,
    line: usize,
    comment: String,
}

/// The `[features]` table of `text`: each feature with the `#` block directly above it (a blank line
/// ends a block), and the names on the `default` line (a multi-line array is joined).
fn features(text: &str) -> (Vec<Feature>, Vec<String>) {
    let lines: Vec<&str> = text.lines().collect();
    let (mut out, mut default) = (Vec::new(), Vec::new());
    let (mut in_features, mut block) = (false, Vec::<&str>::new());
    let mut i = 0;
    while i < lines.len() {
        let s = lines[i].trim();
        if s.starts_with('[') {
            in_features = s == "[features]";
            block.clear();
        } else if in_features && s.starts_with('#') {
            block.push(s);
        } else if in_features && s.is_empty() {
            block.clear();
        } else if in_features {
            if let Some((name, rest)) = s.split_once('=') {
                let name = name.trim().to_string();
                let mut value = rest.to_string();
                let start = i;
                while !value.contains(']') && i + 1 < lines.len() {
                    i += 1;
                    value.push_str(lines[i]);
                }
                if name == "default" {
                    default = value
                        .split('"')
                        .skip(1)
                        .step_by(2)
                        .map(str::to_string)
                        .collect();
                }
                out.push(Feature {
                    name,
                    line: start + 1,
                    comment: block.join("\n"),
                });
            }
            block.clear();
        }
        i += 1;
    }
    (out, default)
}

/// What is wrong with one manifest: each default-authorising block that cites a measurement and
/// names no registered gate.
fn offenders(rel: &str, text: &str) -> Vec<String> {
    let (feats, default) = features(text);
    let mut out = Vec::new();
    for f in feats
        .iter()
        .filter(|f| f.name == "default" || default.contains(&f.name))
    {
        let lower = f.comment.to_lowercase();
        let Some(word) = CLAIM_WORDS.iter().find(|w| lower.contains(*w)) else {
            continue;
        };
        let named: Vec<&str> = f
            .comment
            .match_indices(COMMAND)
            .filter_map(|(at, _)| {
                let tail = &f.comment[at + COMMAND.len()..];
                tail.split(|c: char| c == '`' || c.is_whitespace()).next()
            })
            .collect();
        if named.is_empty() {
            out.push(format!(
                "{rel}:{} `{}`: its comment authorises a default by a measurement (\"{word}\") and \
                 names no `cargo xtask gate <name>` that reproduces it",
                f.line, f.name
            ));
        } else if let Some(bad) = named.iter().find(|n| crate::gates::find(n).is_none()) {
            out.push(format!(
                "{rel}:{} `{}`: it names `cargo xtask gate {bad}`, which is no registered gate: \
                 the command must join the gate set",
                f.line, f.name
            ));
        }
    }
    out
}

pub struct DefaultMeasurementsGate;

impl Gate for DefaultMeasurementsGate {
    fn name(&self) -> &'static str {
        "default-measurements"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_CITED.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let manifests = match cx.walk(&WalkSpec::new(["crates"]).ext("toml")) {
            Ok(files) => files
                .into_iter()
                .filter(|f| {
                    let rel = f.rel_str();
                    rel.ends_with("/Cargo.toml") && rel.matches('/').count() == 2
                })
                .collect::<Vec<_>>(),
            Err(e) => {
                return Verdict::of(vec![Row::fail(
                    ROW_CITED,
                    "the workspace manifests could not be read",
                    format!("crates/*/Cargo.toml: {e} — an unread manifest cites nothing"),
                )])
            }
        };
        let mut problems: Vec<String> = manifests
            .iter()
            .flat_map(|f| offenders(&f.rel_str(), &f.text))
            .collect();
        if manifests.len() < FLOOR {
            problems.push(format!(
                "the scan read {} manifest(s), under its floor of {FLOOR}",
                manifests.len()
            ));
        }
        let row = if problems.is_empty() {
            Row::pass(
                ROW_CITED,
                "every default a comment authorises by a measurement names the gate that re-runs it",
                format!("{} manifest(s) read", manifests.len()),
            )
        } else {
            Row::fail(
                ROW_CITED,
                "a default is authorised by a measurement nothing re-runs",
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
            "the manifests' default comments cite no measurement without its gate",
            &[ROW_CITED],
        ));
        let root = cx.read(ROOT_MANIFEST).unwrap_or_default();
        let plant = |comment: &str| {
            root.replacen(
                "\nroot-admin = [",
                &format!("\n# {comment}\nroot-admin = ["),
                1,
            )
        };
        let mut ov = Overlay::new();
        ov.set(
            ROOT_MANIFEST,
            plant("the whole owed golden read the same either way"),
        );
        report.push(prove_red(
            cx,
            self,
            "a default authorised by an unreproduced measurement is RED (TODO l.2165)",
            &[ROW_CITED],
            ov,
            &["root-admin", "names no `cargo xtask gate <name>`"],
        ));
        let mut ov = Overlay::new();
        ov.set(
            ROOT_MANIFEST,
            plant("measured byte-identical by `cargo xtask gate no-such-gate`"),
        );
        report.push(prove_red(
            cx,
            self,
            "a measurement whose command is no registered gate is RED",
            &[ROW_CITED],
            ov,
            &["no-such-gate", "no registered gate"],
        ));
        let mut ov = Overlay::new();
        ov.set(
            ROOT_MANIFEST,
            plant("measured: `cargo xtask gate default-measurements` re-runs it"),
        );
        report.push(prove_green(
            &cx.with_overlay(ov),
            self,
            "a measurement that names a registered gate is green",
            &[ROW_CITED],
        ));
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MANIFEST: &str = "[package]\nname = \"x\"\n\n[features]\n\
        default = [\"on\"]\n\
        # measured: the golden read the same either way\n\
        on = []\n\
        # measured too, but never a default\n\
        off = []\n";

    #[test]
    fn only_a_default_feature_s_measurement_is_judged() {
        let found = offenders("crates/x/Cargo.toml", MANIFEST);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("`on`"), "{found:?}");
    }

    #[test]
    fn a_blank_line_ends_a_comment_block() {
        let text = MANIFEST.replace("either way\non", "either way\n\non");
        assert!(offenders("crates/x/Cargo.toml", &text).is_empty());
    }
}
