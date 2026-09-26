//! Selftest cases for the frozen-literal pragma, its ratchet, and the precise `streaming` rule.
//!
//! EVERY CASE IS A TRANSITION over the fixture, never a single run: the CLEAN overlay must leave the
//! row GREEN and the PLANTED overlay must turn it RED, naming what was planted. A row that was
//! already red cannot pass a case (PROOF IMPOSSIBLE is structurally ruled out), and a row that has
//! gone missing — a rule deleted — fails every case that covers it.

use crate::ctx::{Ctx, Overlay};
use crate::gates::{execute, Case, Expect, Report};
use crate::ledger::Status;

use super::{
    row_id, InstanceNounNeutralityGate, BASELINE, ROW_FROZEN_LITERAL, ROW_PRAGMA_CEILING, ROW_WRITE,
};

// qa-names: crates/busbar-core/src/lib.rs -- xtask/src/gates/instance_noun_neutrality/cases.rs -- an overlay-only fixture file every case plants a neutral body into; the crate is absent from the tree on purpose, so the only noun the scan meets is the planted one
const CORE: &str = "crates/busbar-core/src/lib.rs";
// qa-names: crates/busbar-core/src/frozen.rs -- xtask/src/gates/instance_noun_neutrality/cases.rs -- the overlay-only file each case plants its frozen literal into; it exists only inside the self-test overlay, never on the tree
const PLANT: &str = "crates/busbar-core/src/frozen.rs";
// qa-names: docs/pin.md -- xtask/src/gates/instance_noun_neutrality/cases.rs -- the overlay-only pinning document a planted frozen-literal marker cites; one case deletes it to prove a cited pin that does not exist is refused
const PIN: &str = "docs/pin.md";
const NEUTRAL: &str = "pub fn install() {}\n";
const GOOD: &str = "pub const DOOR: &str = \"the mcp door\"; \
                    // noun-neutrality: frozen-literal pinned-by=docs/pin.md the door's wire text\n";
const PIN_TEXT: &str = "The catalog renders: the mcp door\n";

fn ov(files: &[(&str, &str)]) -> Overlay {
    let mut o = Overlay::new();
    // Every case runs over a neutral busbar-core, so the only noun in the tree is the planted one.
    o.set(CORE, NEUTRAL);
    for (p, t) in files {
        o.set(*p, (*t).to_string());
    }
    o
}

fn row_of(
    gate: &InstanceNounNeutralityGate,
    fcx: &Ctx,
    o: Overlay,
    row: &str,
) -> Option<(bool, String)> {
    execute(gate, &fcx.with_overlay(o))
        .rows
        .iter()
        .find(|r| r.id == row)
        .map(|r| (r.status != Status::Pass, r.detail.clone()))
}

/// GREEN under `clean`, RED under `planted`: the planted detail is returned for naming.
fn transition(
    gate: &InstanceNounNeutralityGate,
    cx: &Ctx,
    fixture: &str,
    row: &str,
    clean: Overlay,
    planted: Overlay,
) -> Expect {
    let Ok(fcx) = Ctx::at(cx.abs(fixture), cx.scratch().to_path_buf()) else {
        return Expect::Skipped;
    };
    match (
        row_of(gate, &fcx, clean, row),
        row_of(gate, &fcx, planted, row),
    ) {
        (Some((false, _)), Some((true, detail))) => Expect::Red {
            naming: vec![detail],
        },
        (c, p) => Expect::Red {
            naming: vec![format!(
                "no GREEN->RED transition on {row}: clean={c:?} planted={p:?}"
            )],
        },
    }
}

fn stays_green(
    gate: &InstanceNounNeutralityGate,
    cx: &Ctx,
    fixture: &str,
    rows: &[String],
    o: Overlay,
) -> Expect {
    let Ok(fcx) = Ctx::at(cx.abs(fixture), cx.scratch().to_path_buf()) else {
        return Expect::Skipped;
    };
    let verdict = execute(gate, &fcx.with_overlay(o));
    let red: Vec<String> = rows
        .iter()
        .filter(|id| {
            verdict
                .rows
                .iter()
                .find(|r| &r.id == *id)
                .is_none_or(|r| r.status != Status::Pass)
        })
        .map(|id| format!("{id} is red or missing"))
        .collect();
    if red.is_empty() {
        Expect::Green
    } else {
        Expect::Red { naming: red }
    }
}

pub(super) fn push(
    gate: &InstanceNounNeutralityGate,
    cx: &Ctx,
    fix: &str,
    report: &mut Report<'_>,
) {
    let mut red = |name: &str, row: &str, naming: &str, clean: Overlay, planted: Overlay| {
        report.push(Case {
            name: name.to_string(),
            covers: vec![row.to_string()],
            expected: Expect::Red {
                naming: vec![naming.to_string()],
            },
            got: transition(gate, cx, fix, row, clean, planted),
        });
    };
    let good = || ov(&[(PLANT, GOOD), (PIN, PIN_TEXT)]);
    let mcp = row_id("mcp");

    // THE EXEMPTION IS REAL, AND ONLY THE MARKER GRANTS IT: with the pragma the `mcp` row is green;
    // the same literal with the marker stripped reds it, naming the file.
    red(
        "a pinned frozen-literal pragma exempts its literal; the same literal unmarked is a leak",
        &mcp,
        PLANT,
        good(),
        ov(&[
            (PLANT, "pub const DOOR: &str = \"the mcp door\";\n"),
            (PIN, PIN_TEXT),
        ]),
    );
    // A literal that spans lines is exempt on every line; the marker sits on the closing line.
    let multi = "pub const DOOR: &str = \"the mcp \\\n    door\"; \
                 // noun-neutrality: frozen-literal pinned-by=docs/pin.md the door's wire text\n";
    red(
        "a marker on a multi-line literal's closing line exempts the noun on its first line",
        &mcp,
        PLANT,
        ov(&[(PLANT, multi), (PIN, PIN_TEXT)]),
        ov(&[
            (PLANT, &multi.replace("// noun-neutrality", "// no marker")),
            (PIN, PIN_TEXT),
        ]),
    );
    // (2) LITERAL ONLY: an identifier on a marked line is still counted.
    red(
        "an identifier on a marked line is still a leak — the marker covers the literal only",
        &mcp,
        PLANT,
        good(),
        ov(&[(PLANT, &GOOD.replace("DOOR", "MCP_DOOR")), (PIN, PIN_TEXT)]),
    );
    // (2) A MARKER ON AN IDENTIFIER IS REFUSED.
    red(
        "a frozen-literal pragma on an identifier is refused",
        ROW_FROZEN_LITERAL,
        "IDENTIFIER",
        good(),
        ov(&[
            (
                PLANT,
                "pub fn mcp_door() {} \
                 // noun-neutrality: frozen-literal pinned-by=docs/pin.md the door's wire text\n",
            ),
            (PIN, PIN_TEXT),
        ]),
    );
    // (1) NO REASON.
    red(
        "a frozen-literal pragma with no reason is refused",
        ROW_FROZEN_LITERAL,
        "states no reason",
        good(),
        ov(&[
            (
                PLANT,
                "pub const DOOR: &str = \"the mcp door\"; \
                 // noun-neutrality: frozen-literal pinned-by=docs/pin.md\n",
            ),
            (PIN, PIN_TEXT),
        ]),
    );
    // (3) NO CITATION.
    red(
        "a frozen-literal pragma citing no pin is refused",
        ROW_FROZEN_LITERAL,
        "cites nothing",
        good(),
        ov(&[
            (
                PLANT,
                "pub const DOOR: &str = \"the mcp door\"; \
                 // noun-neutrality: frozen-literal the door's wire text\n",
            ),
            (PIN, PIN_TEXT),
        ]),
    );
    // (3) A CITED PIN THAT DOES NOT PIN THE LITERAL.
    red(
        "a frozen-literal pragma citing a file that does not contain the literal is refused",
        ROW_FROZEN_LITERAL,
        "does not contain the literal",
        good(),
        ov(&[
            (PLANT, GOOD),
            (PIN, "The catalog renders: the other door\n"),
        ]),
    );
    // (3) A CITED PIN THAT DOES NOT EXIST.
    red(
        "a frozen-literal pragma citing a missing file is refused",
        ROW_FROZEN_LITERAL,
        "cannot be read",
        good(),
        ov(&[(PLANT, GOOD)]),
    );
    // (3) SELF-CITATION: a literal trivially mentions itself.
    red(
        "a frozen-literal pragma citing its own file is refused",
        ROW_FROZEN_LITERAL,
        "own file",
        good(),
        ov(&[
            (PLANT, &GOOD.replace("docs/pin.md", PLANT)),
            (PIN, PIN_TEXT),
        ]),
    );
    // (4) THE COUNT ROSE: one armed pragma is green, a second unarmed one reds the ratchet.
    let armed = "[pragma_ceiling]\nfrozen_literal = 1\n";
    let two = format!(
        "{GOOD}pub const DOOR2: &str = \"the mcp door\"; \
         // noun-neutrality: frozen-literal pinned-by=docs/pin.md the door's wire text\n"
    );
    red(
        "a frozen-literal pragma count above its ledger ceiling reds the ratchet",
        ROW_PRAGMA_CEILING,
        "frozen_literal ROSE: 2 > ceiling 1",
        ov(&[(PLANT, GOOD), (PIN, PIN_TEXT), (BASELINE, armed)]),
        ov(&[(PLANT, &two), (PIN, PIN_TEXT), (BASELINE, armed)]),
    );
    // (4) AN UNARMED LEDGER is a ceiling of zero, not a missing check.
    red(
        "a frozen-literal pragma with no ledger ceiling at all reds the ratchet",
        ROW_PRAGMA_CEILING,
        "frozen_literal ROSE: 1 > ceiling 0",
        ov(&[]),
        good(),
    );
    // (4) IT CAN ONLY FALL: a ceiling left above the live count is slack the ledger must give back.
    red(
        "a ledger ceiling above the live pragma count reds the ratchet until it is lowered",
        ROW_PRAGMA_CEILING,
        "fell to 1 under ceiling 2",
        ov(&[(PLANT, GOOD), (PIN, PIN_TEXT), (BASELINE, armed)]),
        ov(&[
            (PLANT, GOOD),
            (PIN, PIN_TEXT),
            (BASELINE, "[pragma_ceiling]\nfrozen_literal = 2\n"),
        ]),
    );
    red(
        "a ledger ceiling that is not a bare integer is refused, not compared",
        ROW_PRAGMA_CEILING,
        "not a bare non-negative integer",
        ov(&[(PLANT, GOOD), (PIN, PIN_TEXT), (BASELINE, armed)]),
        ov(&[
            (PLANT, GOOD),
            (PIN, PIN_TEXT),
            (BASELINE, "[pragma_ceiling]\nfrozen_literal = \"1\"\n"),
        ]),
    );

    // THE PRECISE `streaming` RULE. Each spelling that names the PLANE, planted into a core file,
    // reds the row; deleting the rule (or the noun) leaves no row to transition and fails these.
    let streaming = row_id("streaming");
    for (what, line) in [
        (
            "the plane crate's path",
            "use busbar_plane_streaming::Meta;\n",
        ),
        (
            "the plane crate's feature",
            "#[cfg(feature = \"plane-streaming\")]\npub fn f() {}\n",
        ),
        ("a plane type", "pub fn f(_: StreamingPlane) {}\n"),
        (
            "the streams: section type",
            "pub fn f(_: StreamsSection) {}\n",
        ),
        (
            "the top-level streams: section key",
            "pub const Y: &str = \"streams:\\n  fees: {}\";\n",
        ),
    ] {
        red(
            &format!("{what} named in a core file reds the streaming row"),
            &streaming,
            CORE,
            ov(&[]),
            {
                let mut o = Overlay::new();
                o.set(CORE, line.to_string());
                o
            },
        );
    }
    // THE GENERIC VOCABULARY STAYS GREEN: the adjective, tonic's API, an export sink's indented
    // `streams:` list, and the RFC 6750/8705/7469 auth-scheme words (no longer instance nouns).
    let generic = "pub fn serve(streaming: bool) -> bool { streaming }\n\
                   pub const NON: &str = \"a non-streaming body; stream: true\";\n\
                   pub fn body(_b: tonic::Streaming<u8>) {}\n\
                   pub fn call(grpc: &mut Grpc) { grpc.streaming(h, r); }\n\
                   pub const EXPORT: &str = \"export:\\n  s:\\n    streams: [logs]\\n\";\n\
                   pub const SINK: &str = \"module: webhook\\nstreams: [logs]\\n\";\n\
                   pub const AUTH: &str = \"Authorization: Bearer abc\";\n\
                   pub fn bearer_token() {}\npub fn mtls_bind() {}\npub fn spki_pin() {}\n";
    let mut all_nouns: Vec<String> = super::NOUNS.iter().map(|n| row_id(n.key)).collect();
    all_nouns.push(streaming.clone());
    report.push(Case {
        name: "generic streaming/bearer/mTLS/SPKI vocabulary in a core file names no instance"
            .to_string(),
        covers: vec![streaming],
        expected: Expect::Green,
        got: stays_green(gate, cx, fix, &all_nouns, {
            let mut o = Overlay::new();
            o.set(CORE, generic.to_string());
            o
        }),
    });
}

/// THE WRITE ARM'S REFUSALS, each a GREEN->RED transition of `instance-noun-neutrality:write` over
/// the fixture. The clean overlay's ledger already equals the measurement, so the green arm writes
/// nothing; the planted overlay makes a row RISE or a leak NEW, which must be refused — never
/// written — while any row that fell is still lowered.
pub(super) fn push_write(cx: &Ctx, fix: &str, report: &mut Report<'_>) {
    let gate = InstanceNounNeutralityGate::write();
    let one = "pub fn mcp_door() {}\n";
    let ledger = |extra: &str| {
        format!(
            "[[leak]]\nnoun = \"mcp\"\nkind = \"plane\"\nfile = \"{CORE}\"\ncount = 1\n\
             category = \"core\"\nwave = \"w\"\n\n{extra}"
        )
    };
    let case = |name: &str, naming: &[&str], clean: Overlay, planted: Overlay| Case {
        name: name.to_string(),
        covers: vec![ROW_WRITE.to_string()],
        expected: Expect::Red {
            naming: naming.iter().map(|n| (*n).to_string()).collect(),
        },
        got: transition(&gate, cx, fix, ROW_WRITE, clean, planted),
    };
    let at = |core: &str, baseline: &str| ov(&[(CORE, core), (BASELINE, baseline)]);

    // A RISING LEAK PLUS --write IS REFUSED: the row is not raised to the census.
    report.push(case(
        "--write refuses when a baselined leak RISES above its row",
        &["would RISE 1 -> 2", "is NEVER written"],
        at(one, &ledger("")),
        at("pub fn mcp_door() {}\npub fn mcp_seat() {}\n", &ledger("")),
    ));
    // A NEW LEAK PLUS --write IS REFUSED: the ledger does not learn a coupling nobody read.
    report.push(case(
        "--write refuses when a live leak has no ledger row",
        &[
            "a2a@crates/busbar-core/src/lib.rs would be ADDED at 1",
            "is NEVER written",
        ],
        at(one, &ledger("")),
        at("pub fn mcp_door() {}\npub fn a2a_door() {}\n", &ledger("")),
    ));
    // AN ALLOW THAT CITES NO OWNER LICENSES NOTHING: the same rise, with an unowned allow, is
    // still refused, naming the allow.
    let unowned = "[[allow_rise]]\nnoun = \"mcp\"\nfile = \"crates/busbar-core/src/lib.rs\"\n\
                   count = 2\nowner = \"me\"\nreason = \"r\"\n";
    report.push(case(
        "--write refuses a rise whose [[allow_rise]] cites no owner ruling",
        &["cites no owner ruling", "is NEVER written"],
        at(one, &ledger("")),
        at(
            "pub fn mcp_door() {}\npub fn mcp_seat() {}\n",
            &ledger(unowned),
        ),
    )); // A MIXED TREE: one row RISES and another FELL. The fall is lowered, the rise is refused and
        // left at its committed count, and the arm still exits RED — a lowering never carries a rise
        // in, and a rise never holds a lowering hostage.
    let two = |mcp: usize, a2a: usize| {
        format!(
            "[[leak]]\nnoun = \"a2a\"\nkind = \"plane\"\nfile = \"{CORE}\"\ncount = {a2a}\n\
             category = \"core\"\nwave = \"w\"\n\n\
             [[leak]]\nnoun = \"mcp\"\nkind = \"plane\"\nfile = \"{CORE}\"\ncount = {mcp}\n\
             category = \"core\"\nwave = \"w\"\n\n"
        )
    };
    report.push(case(
        "--write on a mixed tree lowers the row that fell and refuses the row that rose",
        &[
            "mcp@crates/busbar-core/src/lib.rs would RISE 1 -> 2",
            "Lowered: a2a@crates/busbar-core/src/lib.rs 2 -> 1",
            "is NEVER written",
        ],
        at("pub fn mcp_door() {}\npub fn a2a_door() {}\n", &two(1, 1)),
        at(
            "pub fn mcp_door() {}\npub fn mcp_seat() {}\npub fn a2a_door() {}\n",
            &two(1, 2),
        ),
    ));
}
