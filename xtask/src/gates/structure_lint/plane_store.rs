//! INVARIANT (a): A PLANE NEVER HOLDS THE POWER TO FORGE THE AUDIT CHAIN.
//!
//! `Store` bundles the append-only AUDIT CHAIN with the per-plane durable state, so a plane handed
//! an `Arc<dyn Store>` could forge the chain. The seam narrows that to `PlaneStore` — plane methods
//! only — and these two rules are what keep it narrowed, on the two seams a widening would come
//! through:
//!
//! * THE SINK ATTACH. Every `fn set_sink` on a plane trust-state type must NAME `PlaneStore`, and
//!   must not name `dyn Store`, the chain, or the governance context. The AUDIT sink is
//!   DELIBERATELY out of scope: the audit ring IS the chain, so its sink is correctly a `Store`.
//! * THE BOOT SURFACE. `BootCtx` is what a plane's hydrate/start hook is handed at boot; a boot hook
//!   that could reach the chain could forge the one hash chain. Its field DOC PROSE is included in
//!   the scan and that is deliberately conservative — a doc that spelled the governance context
//!   would over-flag, which is the safe direction for a rule guarding the audit chain.
//!
//! Both carry a scan-set row for the reason every other family does: a renamed sink or a moved
//! struct scans nothing, and nothing found is a ban's pass.

use crate::ctx::{Ctx, WalkSpec};
use crate::gates::structure_lint::roots::Addresses;
use crate::gates::structure_lint::{row, Findings};
use crate::ledger::Row;

pub const ROW_SINK_SCAN_SET: &str = "structure-lint:plane-sink:scan-set";
pub const ROW_SINK_NOT_NARROWED: &str = "structure-lint:plane-sink:not-narrowed";
pub const ROW_SINK_WIDENED: &str = "structure-lint:plane-sink:widened";
pub const ROW_BOOTCTX_SUBJECT: &str = "structure-lint:boot-ctx:subject";
pub const ROW_BOOTCTX_NOT_NARROWED: &str = "structure-lint:boot-ctx:not-narrowed";
pub const ROW_BOOTCTX_WIDENED: &str = "structure-lint:boot-ctx:widened";

const SINK_DECL: &str = "fn set_sink";
const NARROWED: &str = "PlaneStore";
const BOOTCTX_DECL: &str = "pub struct BootCtx";
/// The two handles that carry the chain by name.
const WIDE_HANDLES: [&str; 2] = ["audit::Chain", "GovCtx"];

pub fn finding_sink_scope(scope: &str) -> String {
    format!(
        "PLANE-SINK-SCOPE-MISSING: `{scope}` holds no source, so the plane trust-state types moved. \
         Re-point this rule at their new home — do not drop it, it guards invariant (a)."
    )
}

pub fn finding_no_sink(scope: &str) -> String {
    format!(
        "NO-PLANE-SINK: no `{SINK_DECL}` under `{scope}`, so this rule scanned NOTHING. That is the \
         false green — a renamed or removed sink attach, not a clean bill."
    )
}

pub fn finding_sink_not_narrowed(site: &str) -> String {
    format!("PLANE-SINK-NOT-NARROWED: a plane `set_sink` does not name `dyn {NARROWED}`: {site}")
}

pub fn finding_sink_widened(site: &str) -> String {
    format!(
        "PLANE-SINK-WIDENED: a plane `set_sink` names the audit-carrying `Store` / a chain / a gov \
         handle, which hands a plane the power to forge the audit chain: {site}"
    )
}

pub fn finding_bootctx_missing(file: &str) -> String {
    format!(
        "BOOTCTX-MISSING: no `{BOOTCTX_DECL}` in `{file}`; the boot-hook seam moved or was renamed. \
         Re-point this rule at its new home — do not drop it, it guards invariant (a) for boot hooks."
    )
}

pub fn finding_bootctx_not_narrowed() -> String {
    format!(
        "BOOTCTX-NOT-NARROWED: `BootCtx` names no `{NARROWED}` — a boot hook's store surface must be \
         the narrowed trait, not the audit-carrying `Store`."
    )
}

pub fn finding_bootctx_widened(site: &str) -> String {
    format!(
        "BOOTCTX-WIDENED: a `BootCtx` field reaches past the plane surface to the audit chain: {site}"
    )
}

pub fn scan(cx: &Ctx, a: &Addresses, f: &mut Findings) {
    scan_sinks(cx, a, f);
    scan_bootctx(cx, a, f);
}

fn scan_sinks(cx: &Ctx, a: &Addresses, f: &mut Findings) {
    let scope = format!("{}/plane", a.core);
    let Ok(files) = cx.walk(&WalkSpec::new([scope.clone()]).ext("rs")) else {
        f.sink_scan_set.push(finding_sink_scope(&scope));
        return;
    };
    if files.is_empty() {
        f.sink_scan_set.push(finding_sink_scope(&scope));
        return;
    }

    let mut sinks = 0usize;
    for s in &files {
        let rel = s.rel_str();
        for (i, line) in s.text.lines().enumerate() {
            if !line.contains(SINK_DECL) {
                continue;
            }
            sinks += 1;
            let site = format!("{rel}:{}: {}", i + 1, line.trim());
            if !line.contains(NARROWED) {
                f.sink_not_narrowed.push(finding_sink_not_narrowed(&site));
            }
            if line.contains("dyn Store") || WIDE_HANDLES.iter().any(|h| line.contains(h)) {
                f.sink_widened.push(finding_sink_widened(&site));
            }
        }
    }
    if sinks == 0 {
        f.sink_scan_set.push(finding_no_sink(&scope));
    }
}

fn scan_bootctx(cx: &Ctx, a: &Addresses, f: &mut Findings) {
    let file = format!("{}/plane/registry.rs", a.core);
    let Ok(text) = cx.read(&file) else {
        f.bootctx_subject.push(finding_bootctx_missing(&file));
        return;
    };
    // The struct body only: from the declaration line to its closing brace at column 0.
    let mut body: Vec<(usize, &str)> = Vec::new();
    let mut inside = false;
    for (i, line) in text.lines().enumerate() {
        if line.contains(BOOTCTX_DECL) {
            inside = true;
        }
        if inside {
            body.push((i + 1, line));
            if line.starts_with('}') && body.len() > 1 {
                break;
            }
        }
    }
    if body.is_empty() {
        f.bootctx_subject.push(finding_bootctx_missing(&file));
        return;
    }

    // POSITIVE: the store surface must name the narrowed trait.
    if !body.iter().any(|(_, l)| l.contains(NARROWED)) {
        f.bootctx_not_narrowed.push(finding_bootctx_not_narrowed());
    }
    for (no, line) in &body {
        // NEGATIVE (trait object): every `dyn ` bound in the struct must be the narrowed trait. A
        // widening to any spelling of the audit-carrying store lacks it on its line.
        let dyn_wide = line.contains("dyn ") && !line.contains(NARROWED);
        let named_wide = WIDE_HANDLES.iter().any(|h| line.contains(h));
        let _ = no;
        if dyn_wide || named_wide {
            // THE FIELD IS THE OFFENDER, not its line number: the shell numbered the struct BODY
            // rather than the file, so a number here would be a parity diff about counting rather
            // than about the tree — and the field is what a reader has to change anyway.
            f.bootctx_widened.push(finding_bootctx_widened(line.trim()));
        }
    }
}

pub fn rows(f: &Findings) -> Vec<Row> {
    vec![
        row(
            ROW_SINK_SCAN_SET,
            "the plane sink rule found sinks to judge",
            "the plane sink rule found nothing to judge, which is not a clean bill",
            &f.sink_scan_set,
        ),
        row(
            ROW_SINK_NOT_NARROWED,
            "every plane sink names the narrowed trait",
            "a plane sink does not name the narrowed trait",
            &f.sink_not_narrowed,
        ),
        row(
            ROW_SINK_WIDENED,
            "no plane sink names the audit-carrying store, the chain or the gov handle",
            "a plane sink was widened back to the power invariant (a) forbids",
            &f.sink_widened,
        ),
        row(
            ROW_BOOTCTX_SUBJECT,
            "the boot-hook seam is where this rule looks for it",
            "the boot-hook seam moved or was renamed, so this rule reads nothing",
            &f.bootctx_subject,
        ),
        row(
            ROW_BOOTCTX_NOT_NARROWED,
            "the boot surface names the narrowed trait",
            "the boot surface names no narrowed trait",
            &f.bootctx_not_narrowed,
        ),
        row(
            ROW_BOOTCTX_WIDENED,
            "no boot-surface field reaches past the plane surface",
            "a boot-surface field reaches the audit chain",
            &f.bootctx_widened,
        ),
    ]
}
