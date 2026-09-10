//! `cargo xtask gate duplex-ws-default-edge` — THE MONEY-PATH WS-EDGE DEP-CLOSURE GATE. The
//! successor to `scripts/duplex-ws-default-edge.sh`, claim for claim.
//!
//! The inbound WS-accept seam names `axum::extract::ws::WebSocketUpgrade` ONLY under the neutral
//! `duplex-ws` / `runtime` features, which pull `axum/ws` and hence `tokio-tungstenite`. The
//! DEFAULT shipped money-path build enables none of those, so its compiled dependency closure must
//! carry no `tokio-tungstenite` — the invariant that keeps the LLM money path byte-identical and
//! voice strong-form deletable. A future edit that welds `axum/ws` onto a default-on feature (or
//! makes an always-compiled type name a WS type) silently breaks it.
//!
//! Five claims, five rows, so a claim cannot be deleted without an owed row going missing:
//!
//! | row | build | the WS crate |
//! | --- | --- | --- |
//! | `:core-default` | `busbar-core`, default features | ABSENT |
//! | `:core-no-default` | `busbar-core`, `--no-default-features` | ABSENT |
//! | `:binary-default` | `busbar`, default features | PRESENT — voice is armed default-on |
//! | `:binary-no-default` | `busbar`, `--no-default-features` | ABSENT — the edge goes with voice |
//! | `:voice-feature-control` | `busbar --features plane-voice` | PRESENT — the positive control |
//!
//! ## A TREE THAT WAS NEVER RESOLVED IS NOT A TREE WITHOUT THE EDGE
//!
//! `cargo tree … 2>/dev/null | grep -c` folded four different things into the number 0: the edge is
//! absent — the answer this gate wants — and also cargo not installed, a feature name in the
//! argument list that no longer exists, and a workspace that does not build. All three failures
//! printed "ok — no tokio-tungstenite", this gate's PASS, with the diagnostic already discarded.
//! `-p busbar-voice` after a crate rename is not a hypothetical; it is the ordinary way this file
//! rots. So the resolve is separated from the count in [`Ctx::cargo_tree`], and an unresolved tree
//! is RED for BOTH directions of assertion — the absence case as much as the presence case, because
//! "absent" is the claim an unresolved tree fakes.

use crate::ctx::{Ctx, Overlay};
use crate::gates::{prove_green, prove_red, Case, Expect, Gate, Report};
use crate::ledger::{Row, Verdict};
use crate::parity::LegacyRun;

pub const ROW_CORE_DEFAULT: &str = "duplex-ws-default-edge:core-default";
pub const ROW_CORE_NO_DEFAULT: &str = "duplex-ws-default-edge:core-no-default";
pub const ROW_BINARY_DEFAULT: &str = "duplex-ws-default-edge:binary-default";
pub const ROW_BINARY_NO_DEFAULT: &str = "duplex-ws-default-edge:binary-no-default";
pub const ROW_VOICE_CONTROL: &str = "duplex-ws-default-edge:voice-feature-control";

/// The crate whose presence IS the WS edge.
const WS_CRATE: &str = "tokio-tungstenite";

const CLEAN: &str = "the tree resolved and the claim held";

/// What a claim expects of its resolved tree.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Expects {
    Absent,
    Present,
}

struct Claim {
    row: &'static str,
    args: &'static [&'static str],
    expects: Expects,
    label: &'static str,
}

const CLAIMS: &[Claim] = &[
    Claim {
        row: ROW_CORE_DEFAULT,
        args: &["-p", "busbar-core"],
        expects: Expects::Absent,
        label: "busbar-core (default, money path)",
    },
    Claim {
        row: ROW_CORE_NO_DEFAULT,
        args: &["-p", "busbar-core", "--no-default-features"],
        expects: Expects::Absent,
        label: "busbar-core (--no-default)",
    },
    Claim {
        row: ROW_BINARY_DEFAULT,
        args: &["-p", "busbar"],
        expects: Expects::Present,
        label: "busbar (default / shipped, voice armed default-on)",
    },
    Claim {
        row: ROW_BINARY_NO_DEFAULT,
        args: &["-p", "busbar", "--no-default-features"],
        expects: Expects::Absent,
        label: "busbar (--no-default, voice removed)",
    },
    Claim {
        row: ROW_VOICE_CONTROL,
        args: &["-p", "busbar", "--features", "plane-voice"],
        expects: Expects::Present,
        label: "busbar (--features plane-voice)",
    },
];

/// The row one claim answers on, built from the resolved tree — or from the reason there is none.
fn row_for(claim: &Claim, tree: Result<String, String>) -> Row {
    let tree = match tree {
        Ok(t) => t,
        Err(why) => {
            return Row::fail(
                claim.row,
                "the dependency tree could not be resolved",
                format!(
                    "{}: {why} An unresolved tree carries no packages, and no packages reads as \
                     'no {WS_CRATE}' — which is this gate's PASS. It is RED instead.",
                    claim.label
                ),
            )
        }
    };
    let hits = tree.lines().filter(|l| l.contains(WS_CRATE)).count();
    match (claim.expects, hits) {
        (Expects::Absent, 0) => Row::pass(
            claim.row,
            "the WS edge is absent from a build that must not carry it",
            CLEAN,
        ),
        (Expects::Absent, n) => Row::fail(
            claim.row,
            "the WS edge leaked into a build that must not carry it",
            format!(
                "{}: {WS_CRATE} present ({n}) in {}",
                claim.label, claim.label
            ),
        ),
        (Expects::Present, 0) => Row::fail(
            claim.row,
            "the WS edge is missing where it must exist",
            format!(
                "{}: {WS_CRATE} absent — the positive control is what proves the absence claims \
                 above are about the tree and not about a scan that finds nothing anywhere",
                claim.label
            ),
        ),
        (Expects::Present, _) => {
            Row::pass(claim.row, "the WS edge is present where it must be", CLEAN)
        }
    }
}

pub struct DuplexWsDefaultEdgeGate;

impl Gate for DuplexWsDefaultEdgeGate {
    fn name(&self) -> &'static str {
        "duplex-ws-default-edge"
    }

    fn owed(&self) -> Vec<String> {
        CLAIMS.iter().map(|c| c.row.to_string()).collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        Verdict::of(
            CLAIMS
                .iter()
                .map(|c| row_for(c, cx.cargo_tree(c.args)))
                .collect(),
        )
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        let run = &runs[0];
        Some(translate(run))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the money path carries no WS edge and voice still does",
            &self.owed().iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        // A TREE THAT RESOLVED AND NAMED NOTHING is RED for an ABSENCE claim: no packages reads as
        // "no tokio-tungstenite", which is the answer this gate wants and must not be handed for
        // free.
        let mut ov = Overlay::new();
        ov.set_command("cargo-tree:-p busbar-core", "");
        report.push(prove_red(
            cx,
            self,
            "an empty tree is RED for an ABSENCE claim, not read as 'no WS edge'",
            &[ROW_CORE_DEFAULT],
            ov,
            &["could not be resolved"],
        ));

        // ...and for a PRESENCE claim too, so the case above is not just "this gate refuses
        // everything unknown".
        let mut ov = Overlay::new();
        ov.set_command("cargo-tree:-p busbar", "");
        report.push(prove_red(
            cx,
            self,
            "an empty tree is RED for a PRESENCE claim too",
            &[ROW_BINARY_DEFAULT],
            ov,
            &["could not be resolved"],
        ));

        // THE EDGE IN A BUILD THAT MUST NOT CARRY IT. Planted as a resolved tree that names the WS
        // crate, which is what welding `axum/ws` onto a default-on feature would produce.
        let mut ov = Overlay::new();
        ov.set_command(
            "cargo-tree:-p busbar-core --no-default-features",
            format!("busbar-core v1.6.0\naxum v0.8.0\n{WS_CRATE} v0.24.0\n"),
        );
        report.push(prove_red(
            cx,
            self,
            "the WS edge appearing in the no-default money path is a finding",
            &[ROW_CORE_NO_DEFAULT],
            ov,
            &["leaked into a build that must not carry it"],
        ));

        // THE EDGE GOING MISSING WHERE IT MUST BE. Without the positive control, every absence
        // claim above would still pass over a resolver that found nothing anywhere.
        let mut ov = Overlay::new();
        ov.set_command(
            "cargo-tree:-p busbar --features plane-voice",
            "busbar v1.6.0\naxum v0.8.0\n",
        );
        report.push(prove_red(
            cx,
            self,
            "the positive control going missing is a finding, not a quieter tree",
            &[ROW_VOICE_CONTROL],
            ov,
            &["missing where it must exist"],
        ));

        // THE EDGE SURVIVING THE REMOVAL OF VOICE. This is the claim the whole gate is named for,
        // and it is planted THROUGH the gate like every other one: a resolved no-default tree for
        // the binary that still names the WS crate is what a default-on `axum/ws` would produce.
        let mut ov = Overlay::new();
        ov.set_command(
            "cargo-tree:-p busbar --no-default-features",
            format!("busbar v1.6.0\naxum v0.8.0\n{WS_CRATE} v0.24.0\n"),
        );
        report.push(prove_red(
            cx,
            self,
            "the WS edge outliving voice in the no-default binary is a finding",
            &[ROW_BINARY_NO_DEFAULT],
            ov,
            &["leaked into a build that must not carry it"],
        ));

        // THE ARGUMENT LIST THAT ROTTED, driven against the REAL resolver: a feature name that no
        // longer exists is the ordinary way this file goes stale, and it must be RED rather than a
        // quiet "the edge is gone". Nothing is planted here on purpose — an overlay would be
        // proving the overlay.
        //
        // IT COVERS NO ROW, deliberately. It never reaches `Gate::run`, so it cannot prove any
        // rule can still fail; what it proves is the resolver refusal every row above is built on.
        // Declaring a row here would discharge that row's coverage against a case the gate is not
        // in.
        let rotted = cx.cargo_tree(&["-p", "busbar", "--features", "no-such-feature"]);
        report.push(Case {
            name: "the resolver behind every claim refuses a feature name that no longer exists"
                .to_string(),
            covers: Vec::new(),
            expected: Expect::Red {
                naming: vec!["no-such-feature".to_string()],
            },
            got: match rotted {
                Ok(_) => Expect::Green,
                Err(why) => Expect::Red { naming: vec![why] },
            },
        });

        report
    }
}

/// Read the shell gate's own output into the same five rows. Its per-claim lines carry the label,
/// which is what routes each verdict back to the row it answers on.
fn translate(run: &LegacyRun) -> Result<Vec<Row>, String> {
    let mut seen: Vec<(&'static str, Row)> = Vec::new();
    let mut recognised = false;

    for raw in run.lines() {
        let t = decolour(raw);
        let t = t.trim().to_string();
        let Some(claim) = CLAIMS.iter().find(|c| t.contains(c.label)) else {
            continue;
        };
        if seen.iter().any(|(row, _)| *row == claim.row) {
            continue;
        }
        recognised = true;
        let row = if t.contains("could not resolve the dependency tree") {
            Row::fail(
                claim.row,
                "the dependency tree could not be resolved",
                format!(
                    "{}: {t} An unresolved tree carries no packages, and no packages reads as 'no \
                     {WS_CRATE}' — which is this gate's PASS. It is RED instead.",
                    claim.label
                ),
            )
        } else if t.starts_with("ok —") || t.starts_with("ok -") {
            match claim.expects {
                Expects::Absent => Row::pass(
                    claim.row,
                    "the WS edge is absent from a build that must not carry it",
                    CLEAN,
                ),
                Expects::Present => {
                    Row::pass(claim.row, "the WS edge is present where it must be", CLEAN)
                }
            }
        } else if t.contains("present") && t.contains("in the WS-free build") {
            Row::fail(
                claim.row,
                "the WS edge leaked into a build that must not carry it",
                format!("{}: {WS_CRATE} present in {}", claim.label, claim.label),
            )
        } else if t.contains("MISSING where the WS edge must exist") {
            Row::fail(
                claim.row,
                "the WS edge is missing where it must exist",
                format!(
                    "{}: {WS_CRATE} absent — the positive control is what proves the absence claims \
                     above are about the tree and not about a scan that finds nothing anywhere",
                    claim.label
                ),
            )
        } else {
            continue;
        };
        seen.push((claim.row, row));
    }

    if !recognised {
        return Err(format!(
            "the legacy translator recognised no per-claim verdict in `{}`'s output. Silence read \
             as five passing claims is the exact defect this gate exists for.",
            run.argv.join(" ")
        ));
    }
    Ok(CLAIMS
        .iter()
        .map(|c| {
            seen.iter()
                .find(|(row, _)| *row == c.row)
                .map(|(_, r)| r.clone())
                .unwrap_or_else(|| {
                    // A claim the script never printed a verdict for DID NOT RUN. The reconciler
                    // would red it anyway; naming it is what tells a reader which fact this is.
                    Row::fail(
                        c.row,
                        "the claim was never asserted",
                        format!(
                            "{}: the legacy run printed no verdict for it, and a claim that did \
                             not run is not a claim that passed",
                            c.label
                        ),
                    )
                })
        })
        .collect())
}

/// Drop the SGR escapes the shell's `red()`/`grn()` wrap their per-claim lines in.
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
