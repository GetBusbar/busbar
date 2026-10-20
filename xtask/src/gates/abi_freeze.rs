//! `cargo xtask gate abi-freeze` — THE CONDEMNED ABI LANES STAY DELETED.
//!
//! `busbar-contract/src/abi/hot` and `abi/cold` were the HOT and COLD plugin lanes.
//! `BUSBAR-1.6.0.md` THE DESIGN, §11 replaced both with the one memory ABI, and both directories
//! are deleted (status row 84; the cold lane in #961). A line written there is a line written only
//! to be deleted, so:
//!
//! * a condemned directory that holds any file is RED (`REGROWN`): the work belongs in the memory
//!   ABI. The walk sees the disk, the base layer and the overlay, so a lane laid back by any of
//!   them is seen;
//! * a `[[frozen]]` row in `qa/abi-freeze.toml` is RED whatever it says. A row held a lane to a
//!   typed line count, and that is a hand-kept size integer, which Law 9 deletes
//!   (BUSBAR-1.6.0.md l.2100-2102: "No CI rung measures or blocks on size ... There is no
//!   hand-kept size integer in the tree"). A row typed at a regrown lane's size used to forgive
//!   the regrowth; nothing forgives it now (audit XF HIGH 1).
//!
//! Nothing here counts lines: the measure is "does the lane exist", never "how big is it".

use crate::ctx::{Ctx, Overlay, WalkError, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_FROZEN: &str = "abi-freeze:frozen";

/// The ledger that once held one `[[frozen]]` size row per lane. It holds none now, and any row
/// it holds is RED.
pub const LEDGER: &str = "qa/abi-freeze.toml";

/// The directories that must stay deleted. Each is judged on every run; no ledger row lifts one.
pub const CONDEMNED: &[&str] = &[
    // qa-names: crates/busbar-contract/src/abi/hot -- xtask/src/gates/abi_freeze.rs -- the hot lane is deleted (row 84); it stays condemned so a directory that grows back there is REGROWN and red, and this declaration reds the day the path exists again
    "crates/busbar-contract/src/abi/hot",
    // qa-names: crates/busbar-contract/src/abi/cold -- xtask/src/gates/abi_freeze.rs -- the cold lane is deleted (row 84, #961); it stays condemned so a directory that grows back there is REGROWN and red, and this declaration reds the day the path exists again
    "crates/busbar-contract/src/abi/cold",
];

/// Every file under `dir`, whatever its extension.
///
/// THE WALK IS ASKED, NOT THE DIRECTORY. A `cx.exists(dir)` stat cannot see a directory only the
/// overlay lays, and a deleted lane growing back is exactly such a directory. The walk resolves a
/// root from the disk, the base layer AND the overlay, and refuses only a root none of them lays,
/// which is the one "nothing here" this turns into no files.
fn files_under(cx: &Ctx, dir: &str) -> Result<Vec<String>, String> {
    match cx.list(&WalkSpec::new([dir]).allow_empty()) {
        Ok(files) => Ok(files
            .into_iter()
            .map(|f| f.to_string_lossy().replace('\\', "/"))
            .collect()),
        Err(WalkError::MissingRoot { .. }) => Ok(Vec::new()),
        Err(e) => Err(format!("{dir}: {e}")),
    }
}

/// The `dir` of every `[[frozen]]` row, or why the ledger could not be read. An absent ledger
/// holds no row.
fn size_rows(cx: &Ctx) -> Result<Vec<String>, String> {
    if !cx.exists(LEDGER) {
        return Ok(Vec::new());
    }
    let text = cx.read(LEDGER)?;
    let doc = crate::toml_lite::parse_text(&text);
    Ok(doc
        .array_table("frozen")
        .iter()
        .map(|t| t.get_one("dir").unwrap_or("(no dir)").to_string())
        .collect())
}

fn findings(cx: &Ctx) -> Result<(Vec<String>, String), String> {
    let mut bad = Vec::new();
    for dir in size_rows(cx)? {
        bad.push(format!(
            "SIZE ROW {dir}: a [[frozen]] row in {LEDGER} is a hand-kept size integer, which Law 9 \
             deletes (BUSBAR-1.6.0.md l.2102); strike it -- a condemned lane is held deleted, not \
             held to a size"
        ));
    }
    let mut seen = Vec::new();
    for dir in CONDEMNED {
        let files = files_under(cx, dir)?;
        seen.push(format!("{dir}: {} file(s)", files.len()));
        if !files.is_empty() {
            bad.push(format!(
                "REGROWN {dir}: {} file(s) ({}) under a deleted, condemned lane; the work belongs \
                 in the memory ABI (THE DESIGN §11)",
                files.len(),
                files.join(", ")
            ));
        }
    }
    Ok((bad, seen.join("; ")))
}

pub struct AbiFreezeGate;

impl Gate for AbiFreezeGate {
    fn name(&self) -> &'static str {
        "abi-freeze"
    }

    fn owed(&self) -> Vec<String> {
        vec![ROW_FROZEN.to_string()]
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let row = match findings(cx) {
            Ok((bad, seen)) if bad.is_empty() => Row::pass(
                ROW_FROZEN,
                "the condemned abi/hot and abi/cold lanes are deleted and no size row stands",
                seen,
            ),
            Ok((bad, _)) => Row::fail(
                ROW_FROZEN,
                "a condemned ABI lane holds a file, or a size row stands",
                bad.join(" | "),
            ),
            Err(why) => Row::fail(ROW_FROZEN, "the abi-freeze ledger could not be read", why),
        };
        Verdict::of(vec![row])
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        report.push(prove_green(
            cx,
            self,
            "the tree's condemned lanes are deleted and hold no row",
            &[ROW_FROZEN],
        ));

        // THE HOT LANE GROWING BACK. The lane is deleted (row 84): a file there is RED.
        let mut regrown = Overlay::new();
        regrown.set(
            format!("{}/mod.rs", CONDEMNED[0]),
            "pub struct PlantedHotShape;\n".to_string(),
        );
        report.push(prove_red(
            cx,
            self,
            "a deleted HOT lane that grows back is REGROWN and RED",
            &[ROW_FROZEN],
            regrown,
            &["REGROWN", CONDEMNED[0]],
        ));

        // THE COLD LANE GROWING BACK, with a file no `.rs` walk would read: every file counts.
        let mut planted = Overlay::new();
        planted.set(
            format!("{}/planted.json", CONDEMNED[1]),
            "{}\n".to_string(),
        );
        report.push(prove_red(
            cx,
            self,
            "a deleted COLD lane that grows back, in any file, is REGROWN and RED",
            &[ROW_FROZEN],
            planted,
            &["REGROWN", CONDEMNED[1]],
        ));

        let ledger = cx.read(LEDGER).unwrap_or_default();
        let hot_row = format!(
            "{ledger}\n[[frozen]]\ndir = \"{}\"\nlines = \"1\"\n",
            CONDEMNED[0]
        );

        // A SIZE ROW ALONE (its directory deleted) is a hand-kept size integer, and RED.
        let mut row_alone = Overlay::new();
        row_alone.set(LEDGER, hot_row.clone());
        report.push(prove_red(
            cx,
            self,
            "a [[frozen]] size row is RED on its own, naming the size integer",
            &[ROW_FROZEN],
            row_alone,
            &["SIZE ROW", "hand-kept size integer", CONDEMNED[0]],
        ));

        // A SIZE ROW THAT MATCHES ITS REGROWN LANE. A `[[frozen]]` row is a hand-kept size integer,
        // which Law 9 deletes (BUSBAR-1.6.0.md l.2102 "There is no hand-kept size integer in the
        // tree"): typed at exactly the regrown lane's size it forgave the regrowth. It is RED as a
        // size integer, and the lane it names is RED as regrown (audit XF HIGH 1).
        let mut matched = Overlay::new();
        matched.set(LEDGER, hot_row);
        matched.set(
            format!("{}/mod.rs", CONDEMNED[0]),
            "pub struct Regrown;\n".to_string(),
        );
        report.push(prove_red(
            cx,
            self,
            "a size row typed at its regrown lane's size forgives nothing: RED, naming the size integer",
            &[ROW_FROZEN],
            matched,
            &["hand-kept size integer", "REGROWN", CONDEMNED[0]],
        ));
        report
    }
}
