//! `cargo xtask txn-fence` — THE COMPILE FENCE for the config-mutation transaction guard (the port
//! of `scripts/txn-fence.sh`, verdict for verdict).
//!
//! `crates/busbar-kernel/src/config/tests/txn_fence.rs` is a NEGATIVE test: a transaction body that
//! tries to reach a blocking store call (`store.list_keys()`, `txn.store()`) or to `.await` inside
//! the section. It must FAIL to compile. This command builds it and inverts the verdict: a clean
//! build is a FAILED fence, because it would mean `Txn` had grown a way to touch the store from the
//! async thread (or the body had become async), re-opening the blocking-under-the-lock class.
//!
//! Why not `trybuild`: it builds ui cases as a crate that `use`s the crate under test, which needs
//! the guard to be nameable from outside; it is `pub(crate)`. Compiling the fence INSIDE the real
//! crate checks the real `Txn`, not a copy of its signature.
//!
//! The fence is a rustc cfg, not a cargo feature: a feature whose only effect is to break the build
//! would make `--all-features` red for no defect. `cargo rustc` scopes the flag to the one crate
//! that carries the fence, so nothing else in the graph is rebuilt under it.
//!
//! THE PACKAGE NAME IS LOAD-BEARING IN THE DANGEROUS DIRECTION, because the PASS condition is a
//! build FAILURE: `cargo rustc` on a package that does not exist fails too. The only thing standing
//! between that and a fence reported as holding over a crate that was never compiled is the
//! expected-error check, which is why [`verdict`] requires every [`EXPECTED`] message.

use std::process::Command;

/// The crate that carries the fence.
pub const PACKAGE: &str = "busbar-kernel";

/// The rustc cfg that compiles the fence.
pub const CFG: &str = "txn_fence_red";

/// The three refusals the fence exists to produce. A failure without all three failed for some
/// other reason (a drifted file, a missing package) and proves nothing.
pub const EXPECTED: [&str; 3] = [
    "cannot find value `store` in this scope",
    "no method named `store` found",
    "`await` is only allowed inside",
];

/// The verdict over one build: `Ok` with the line to print when the fence holds, `Err` with the
/// lines to print when it does not.
pub fn verdict(build_succeeded: bool, output: &str) -> Result<String, Vec<String>> {
    if build_succeeded {
        return Err(vec![
            "  FENCE BREACHED: crates/busbar-kernel/src/config/tests/txn_fence.rs COMPILED."
                .to_string(),
            "  A transaction body must not be able to name a store, reach one through Txn, or .await."
                .to_string(),
        ]);
    }
    let missing: Vec<String> = EXPECTED
        .iter()
        .filter(|want| !output.contains(**want))
        .map(|want| format!("  MISSING EXPECTED ERROR: {want}"))
        .collect();
    if missing.is_empty() {
        return Ok(
            "  ok — the body cannot name a store, cannot reach one through Txn, and cannot .await"
                .to_string(),
        );
    }
    let mut lines = missing;
    lines.push(
        "  The fence failed to compile, but not for the reasons it asserts. Full output:"
            .to_string(),
    );
    lines.push(output.to_string());
    Err(lines)
}

pub fn main(args: &[String]) -> i32 {
    if !args.is_empty() {
        eprintln!("usage: cargo xtask txn-fence");
        return 2;
    }
    let root = match crate::ctx::workspace_root() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("xtask: {e}");
            return 3;
        }
    };
    println!("== txn compile fence (this build MUST fail) ==");
    let out = match Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args(["rustc", "-p", PACKAGE, "--lib", "--", "--cfg", CFG])
        .current_dir(&root)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            eprintln!("xtask txn-fence: cargo did not start: {e}");
            return 3;
        }
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    match verdict(out.status.success(), &text) {
        Ok(line) => {
            println!("{line}");
            0
        }
        Err(lines) => {
            for l in lines {
                println!("{l}");
            }
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{verdict, EXPECTED};

    fn all_three() -> String {
        EXPECTED
            .iter()
            .map(|e| format!("error[E0000]: {e}\n"))
            .collect()
    }

    #[test]
    fn a_failure_for_all_three_reasons_holds() {
        assert!(verdict(false, &all_three()).is_ok());
    }

    #[test]
    fn a_clean_build_is_a_breach() {
        let lines = verdict(true, &all_three()).unwrap_err();
        assert!(lines[0].contains("FENCE BREACHED"), "{lines:?}");
    }

    #[test]
    fn a_failure_for_another_reason_is_red_and_names_what_is_missing() {
        // `cargo rustc -p` on a package that does not exist: a failure, and the wrong one.
        let out = "error: package ID specification `busbar-core` did not match any packages";
        let lines = verdict(false, out).unwrap_err();
        for want in EXPECTED {
            assert!(
                lines
                    .iter()
                    .any(|l| l == &format!("  MISSING EXPECTED ERROR: {want}")),
                "{lines:?}"
            );
        }
        assert_eq!(lines.last().map(String::as_str), Some(out));
    }

    #[test]
    fn each_expected_error_is_required_on_its_own() {
        for drop in EXPECTED {
            let out: String = EXPECTED
                .iter()
                .filter(|e| **e != drop)
                .map(|e| format!("{e}\n"))
                .collect();
            let lines = verdict(false, &out).unwrap_err();
            assert_eq!(
                lines[0],
                format!("  MISSING EXPECTED ERROR: {drop}"),
                "{lines:?}"
            );
        }
    }
}
