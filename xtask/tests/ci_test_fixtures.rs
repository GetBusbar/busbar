//! A test that loads an example cdylib names the command that builds it, and fails (never skips)
//! when the library is absent. ModernCI's `scope: affected` narrows a run to the crates a change
//! touches, so a run of `busbar` alone used to build no other package's examples: the loader's
//! neutral frame door was missing and 22 composition-root tests failed on a change that never
//! touched them. Every CI step that runs the suites therefore builds each named fixture package BY
//! NAME before its first suite, and this file holds the CI files to that.

use std::path::{Path, PathBuf};

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The packages whose examples some test under `crates/` tells its reader to build, read from the
/// command the test prints (`cargo build -p <package> --examples`).
fn fixture_packages(root: &Path) -> Vec<String> {
    const HEAD: &str = "cargo build -p ";
    const TAIL: &str = " --examples";
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    let mut packages: Vec<String> = Vec::new();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        for line in text.lines() {
            let mut rest = line;
            while let Some(at) = rest.find(HEAD) {
                let after = &rest[at + HEAD.len()..];
                let Some(end) = after.find(TAIL) else { break };
                let package = &after[..end];
                if !package.is_empty() && !package.contains(' ') {
                    packages.push(package.to_string());
                }
                rest = &after[end..];
            }
        }
    }
    packages.sort();
    packages.dedup();
    packages
}

/// Every `run` block in `.ci/*.yaml` that runs the suites, by `<file>:<check>`.
fn suite_steps(root: &Path) -> Vec<(String, String)> {
    let mut steps = Vec::new();
    let mut files: Vec<PathBuf> = std::fs::read_dir(root.join(".ci"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|e| e == "yaml"))
        .collect();
    files.sort();
    for file in files {
        let text = std::fs::read_to_string(&file).unwrap();
        let doc: serde_yaml::Value = serde_yaml::from_str(&text)
            .unwrap_or_else(|e| panic!("{} does not parse: {e}", file.display()));
        let Some(checks) = doc.get("checks").and_then(|c| c.as_mapping()) else {
            continue;
        };
        for (name, check) in checks {
            let Some(run) = check.get("run").and_then(|r| r.as_str()) else {
                continue;
            };
            if run.contains("cargo nextest run") {
                let label = format!(
                    "{}:{}",
                    file.file_name().unwrap().to_string_lossy(),
                    name.as_str().unwrap_or("?")
                );
                steps.push((label, run.to_string()));
            }
        }
    }
    steps
}

#[test]
fn an_affected_scope_run_of_busbar_alone_builds_the_examples_its_tests_load() {
    let root = repo_root();
    let packages = fixture_packages(root);
    assert!(
        packages.iter().any(|p| p == "busbar-plugin-loader")
            && packages.iter().any(|p| p == "busbar"),
        "the scan found no test naming the loader's or busbar's example build, so it proved \
         nothing: {packages:?}"
    );
    let steps = suite_steps(root);
    assert!(
        steps.iter().any(|(label, _)| label == "default.yaml:test"),
        "no suite step was found in .ci/ (expected default.yaml:test): {:?}",
        steps.iter().map(|(l, _)| l).collect::<Vec<_>>()
    );
    let mut missing = Vec::new();
    for (label, run) in &steps {
        let before_suites: Vec<&str> = run
            .lines()
            .map(str::trim)
            .take_while(|l| !l.starts_with("cargo nextest run"))
            .collect();
        for package in &packages {
            let wanted = format!("cargo build --locked -p {package} --examples");
            if !before_suites.contains(&wanted.as_str()) {
                missing.push(format!("{label}: `{wanted}`"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "a suite step can run without the example cdylibs its tests load; a run scoped to one \
         crate builds no other package's examples, so each must be built by name before the \
         first suite:\n{}",
        missing.join("\n")
    );
}
