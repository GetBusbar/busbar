//! `cargo xtask gate abi-freeze` — THE CONDEMNED ABI LANES DO NOT GROW.
//!
//! `busbar-contract/src/abi/hot` and `abi/cold` are the HOT and COLD plugin lanes.
//! `BUSBAR-1.6.0.md` THE DESIGN, §11 replaces both with the one memory ABI, and both directories
//! are deleted when the last plugin moves onto it. Every line added to either lane in the meantime
//! is a line written only to be deleted, and a contract ceiling raised to hold it.
//!
//! So each condemned directory is FROZEN at its measured size in `qa/abi-freeze.toml`:
//!
//! * a directory that measures MORE than its row is RED: the lane grew, and the growth belongs
//!   in the memory ABI;
//! * a directory that measures LESS than its row is RED too: that is stale slack, and slack is
//!   room to grow back into. Lower the row on the commit that deleted the lines, or strike it
//!   once the directory is gone;
//! * a row whose directory reads as nothing while the row still holds lines is the same stale
//!   slack, and names the strike.
//!
//! The measure is every line of every file under the directory, whatever its extension. A frozen
//! lane's tests die with it, so they are frozen with it.

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{prove_green, prove_red, Gate, Report};
use crate::ledger::{Row, Verdict};

pub const ROW_FROZEN: &str = "abi-freeze:frozen";

/// The ledger: one `[[frozen]]` row per condemned directory.
pub const LEDGER: &str = "qa/abi-freeze.toml";

/// The directories this gate refuses to see unfrozen. A ledger that drops one is RED, so the
/// freeze cannot be lifted by deleting its row.
pub const CONDEMNED: &[&str] = &[
    "crates/busbar-contract/src/abi/hot",
    "crates/busbar-contract/src/abi/cold",
];

/// Every line of every file under `dir`, and how many files that is.
fn measure(cx: &Ctx, dir: &str) -> Result<(u64, usize), String> {
    if !cx.exists(dir) {
        return Ok((0, 0));
    }
    let files = cx
        .list(&WalkSpec::new([dir]))
        .map_err(|e| format!("{dir}: {e}"))?;
    let mut lines = 0u64;
    let mut n = 0usize;
    for f in files {
        let rel = f.to_string_lossy().replace('\\', "/");
        let text = cx.read(&rel).unwrap_or_default();
        lines += text.lines().count() as u64;
        n += 1;
    }
    Ok((lines, n))
}

/// The `[[frozen]]` rows as `(dir, lines)`, or why the ledger could not be read.
fn rows(cx: &Ctx) -> Result<Vec<(String, u64)>, String> {
    let text = cx.read(LEDGER)?;
    let doc = crate::toml_lite::parse_text(&text);
    let mut out = Vec::new();
    for t in doc.array_table("frozen") {
        let dir = t
            .get_one("dir")
            .ok_or_else(|| format!("{LEDGER}: a [[frozen]] row has no `dir`"))?
            .to_string();
        let lines = t
            .get_one("lines")
            .ok_or_else(|| format!("{LEDGER}: [[frozen]] {dir} has no `lines`"))?
            .trim()
            .parse::<u64>()
            .map_err(|e| format!("{LEDGER}: [[frozen]] {dir} `lines` is not a count: {e}"))?;
        out.push((dir, lines));
    }
    Ok(out)
}

fn findings(cx: &Ctx) -> Result<(Vec<String>, String), String> {
    let rows = rows(cx)?;
    let mut bad = Vec::new();
    let mut seen = Vec::new();
    for (dir, frozen) in &rows {
        let (now, files) = measure(cx, dir)?;
        seen.push(format!("{dir} {now}/{frozen} line(s) over {files} file(s)"));
        if now > *frozen {
            bad.push(format!(
                "GREW {dir}: {frozen} -> {now} line(s). This lane is condemned (the memory ABI replaces it); \
                 the growth belongs in the memory ABI, not here"
            ));
        } else if now < *frozen {
            let what = if now == 0 {
                "strike the row".to_string()
            } else {
                format!("lower the row to {now}")
            };
            bad.push(format!(
                "STALE SLACK {dir}: frozen at {frozen}, measures {now} — {what} in the commit that \
                 deleted the lines, or the lane can grow back into it"
            ));
        }
    }
    for dir in CONDEMNED {
        if !rows.iter().any(|(d, _)| d == dir) {
            let (now, _) = measure(cx, dir)?;
            if now > 0 {
                bad.push(format!(
                    "UNFROZEN {dir}: {now} line(s) and no [[frozen]] row in {LEDGER}"
                ));
            }
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
                "the condemned abi/hot and abi/cold lanes measure exactly their frozen size",
                seen,
            ),
            Ok((bad, _)) => Row::fail(
                ROW_FROZEN,
                "a condemned ABI lane is not at its frozen size",
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
            "the tree's hot and cold lanes measure their frozen size",
            &[ROW_FROZEN],
        ));

        // GROWTH: one more line in an existing HOT file.
        let hot_file = format!("{}/mod.rs", CONDEMNED[0]);
        let mut grown = Overlay::new();
        grown.set(
            hot_file.clone(),
            format!(
                "{}// one more line\n",
                cx.read(&hot_file).unwrap_or_default()
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "a line appended to the HOT lane is RED, naming the directory",
            &[ROW_FROZEN],
            grown,
            &["GREW", CONDEMNED[0]],
        ));

        // A NEW FILE in the COLD lane is growth as well.
        let mut planted = Overlay::new();
        planted.set(
            format!("{}/planted.rs", CONDEMNED[1]),
            "pub struct PlantedColdShape;\n".to_string(),
        );
        report.push(prove_red(
            cx,
            self,
            "a new file in the COLD lane is RED",
            &[ROW_FROZEN],
            planted,
            &["GREW", CONDEMNED[1]],
        ));

        // SLACK: the row above the measurement.
        let ledger = cx.read(LEDGER).unwrap_or_default();
        let mut slack = Overlay::new();
        slack.set(LEDGER, ledger.replacen("lines = \"", "lines = \"9", 1));
        report.push(prove_red(
            cx,
            self,
            "a frozen row above its directory's measurement is stale slack, and RED",
            &[ROW_FROZEN],
            slack,
            &["STALE SLACK"],
        ));

        // LIFTING THE FREEZE by striking a row is refused.
        let mut lifted = Overlay::new();
        lifted.set(
            LEDGER,
            ledger.replacen(
                &format!("dir = \"{}\"", CONDEMNED[0]),
                "dir = \"crates/busbar-contract/src/abi/not-hot\"",
                1,
            ),
        );
        report.push(prove_red(
            cx,
            self,
            "a condemned directory with no [[frozen]] row is RED",
            &[ROW_FROZEN],
            lifted,
            &["UNFROZEN", CONDEMNED[0]],
        ));
        report
    }
}
