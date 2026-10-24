//! The dispatcher's arms and its EXIT CODES, driven through `cli::main` directly rather than
//! through a subprocess — a test that shells out to the binary can only assert on printed text.
//!
//! The codes are a contract `full-gate.sh` already relies on: 0 green, 1 the gate failed, 2 the
//! ARGUMENTS were wrong, 3 the gate could not run. Collapsing 1 and 3 is how a runner reports green
//! over a gate that never executed, and collapsing 2 into either is how a typo'd flag ends up being
//! handed to the thing the flag was meant to control.

fn run(args: &[&str]) -> i32 {
    let owned: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    xtask::cli::main(&owned)
}

#[test]
fn no_subcommand_and_an_unknown_subcommand_are_argument_errors() {
    assert_eq!(run(&[]), 2);
    assert_eq!(run(&["not-a-subcommand"]), 2);
}

#[test]
fn an_unknown_gate_is_an_argument_error_and_never_falls_through_into_running_something() {
    assert_eq!(run(&["gate", "denylst"]), 2);
    assert_eq!(run(&["gate"]), 2);
    assert_eq!(run(&["selftest", "no-such-gate"]), 2);
}

#[test]
fn list_and_a_named_gate_run_over_the_real_tree() {
    assert_eq!(run(&["gate", "--list"]), 0);
    assert_eq!(run(&["gate", "segregation"]), 0);
    assert_eq!(run(&["gate", "segregation", "--format=tsv"]), 0);

    // `--all` IS NOT RUN HERE. Every registered gate is run over the real tree by the gates check
    // (`xtask gate <name> --format=tsv`, one per gate, in the hop's gate battery), so running them
    // all again from this file paid for the same verdicts twice in one hop (verification runs
    // once per input). The arm's argument handling stays pinned, cheaply, in `cli::tests`
    // (`gate --all --frobnicate` is 2).
}

#[test]
fn selftest_proves_a_named_gates_red_proof() {
    // ONE GATE'S SELF-TEST, NOT EVERY GATE'S. This file's subject is the DISPATCHER, and its arms
    // are pinned by a single gate: the named `selftest <gate>` arm and the `gate <name> --selftest`
    // spelling both reach that gate's red proof and exit 0. The all-gates `selftest` arm is the
    // same loop over the registry, and every gate's proof is judged by itself, gate by gate, in
    // the `selftest-1` .. `selftest-4` checks (.ci/dev.yaml), which run `xtask selftest
    // --shard=K/4`: one `xtask selftest <gate>` process for each registered gate. Running the whole registry from here as well cost about
    // five minutes of runner time per hop for verdicts those checks already hold, and it is the
    // only reason this case ever went red on a branch that reds some OTHER gate. An unknown gate
    // name is refused with 2 in
    // `an_unknown_gate_is_an_argument_error_and_never_falls_through_into_running_something`.
    assert_eq!(run(&["selftest", "segregation"]), 0);
    assert_eq!(run(&["gate", "segregation", "--selftest"]), 0);
}

/// THE DENYLIST GATE'S PRE-REGISTRY SPELLING. It drives `cargo xtask denylist` through the
/// dispatcher and pins the verdict, the self-test and the TSV arm at 0.
#[test]
fn the_pre_registry_denylist_spelling_still_works_unchanged() {
    assert_eq!(run(&["denylist"]), 0);
    assert_eq!(run(&["denylist", "--selftest"]), 0);
    assert_eq!(run(&["denylist", "--format=tsv"]), 0);
}

#[test]
fn the_parity_arm_needs_a_legacy_command_and_refuses_one_that_wrote_no_rows() {
    // `--parity` with nothing after `--` is an argument error, not a vacuous green.
    assert_eq!(run(&["gate", "segregation", "--parity"]), 2);

    // A legacy script that writes no ledger rows cannot be at parity with anything: the harness
    // reports 3 (could not run), never 0.
    assert_eq!(
        run(&["gate", "segregation", "--parity", "--", "/usr/bin/true"]),
        3
    );
}

// ── THE TREE READ IS THE TREE RUN IN ────────────────────────────────────────────────────────────
//
// A binary built in one tree and run in another must read the tree it runs in, or refuse — never
// silently read the tree it was compiled in. These run the BUILT binary, with a current directory
// that is not this tree.

fn xtask_bin() -> std::process::Command {
    std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
}

/// A throwaway busbar-shaped git tree: a repository holding `xtask/Cargo.toml`.
fn other_tree(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("xtask-root-{tag}-{}-{}", std::process::id(), {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        format!(
            "{}-{}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
            line!(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        )
    }));
    std::fs::create_dir_all(dir.join("xtask")).unwrap();
    std::fs::write(
        dir.join("xtask/Cargo.toml"),
        "[package]\nname = \"xtask\"\n",
    )
    .unwrap();
    let ok = std::process::Command::new("git")
        .args(["init", "-q"])
        .current_dir(&dir)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    assert!(ok, "git init {}", dir.display());
    dir
}

#[test]
fn a_binary_run_in_another_tree_reads_that_tree_not_its_build_tree() {
    let dir = other_tree("git");
    let out = xtask_bin().arg("root").current_dir(&dir).output().unwrap();
    let printed = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let build = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    assert_ne!(
        std::path::Path::new(&printed).canonicalize().ok(),
        build.canonicalize().ok(),
        "the binary read its BUILD tree from inside another tree"
    );
    assert!(
        printed.contains("xtask-root-git-"),
        "the root read is the tree it ran in: {printed}"
    );
}

#[test]
fn a_binary_run_outside_any_tree_refuses_rather_than_reading_its_build_tree() {
    let dir = std::env::temp_dir().join(format!("xtask-root-bare-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = xtask_bin()
        .arg("root")
        .current_dir(&dir)
        // No git tree above a temp dir on CI or here, and none may be found through the env.
        .env("GIT_CEILING_DIRECTORIES", std::env::temp_dir())
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    assert_eq!(
        out.status.code(),
        Some(3),
        "stdout {} stderr {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("refusing to read the BUILD tree"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn an_explicit_root_is_the_tree_read() {
    let dir = other_tree("explicit");
    let out = xtask_bin()
        .args(["--root", dir.to_str().unwrap(), "root"])
        .output()
        .unwrap();
    let printed = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(printed.contains("xtask-root-explicit-"), "{printed}");
}
