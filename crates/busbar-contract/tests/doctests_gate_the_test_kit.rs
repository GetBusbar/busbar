// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DOCTEST THAT NAMES THE TEST KIT RUNS ONLY WHERE THE KIT IS COMPILED.
//!
//! The test kit (`abi::sdk::test_support`, `testkit`, `services::double`, `plugin::TestKernelSeal`
//! and `KernelSeal::acquire_for_kernel`) is compiled only with the dev-only `test-seal` or
//! `services-double` feature. `cargo test -p busbar-contract` turns neither on; the workspace run
//! does, through the dev edges of the crates that link this one. A doctest whose fence is a plain
//! ```` ``` ```` or ```` ```compile_fail ```` and whose body names the kit is therefore two
//! different tests: under the workspace it checks what it says, and under the crate's own run a
//! runnable one fails to build and a `compile_fail` one passes on the missing module, never on the
//! guard it was written for.
//!
//! Such a fence is written as the pair the caps module docs use:
//!
//! ```text
//! #[cfg_attr(feature = "test-seal", doc = "```compile_fail")]
//! #[cfg_attr(not(feature = "test-seal"), doc = "```ignore")]
//! ```
//!
//! This test reads every source file of the crate (the kit's own files aside: they are not compiled
//! without the feature, so their doctests are not collected) and refuses a plain fence whose body
//! names the kit. A RED plant and its GREEN twin hold the reader itself.

use std::path::{Path, PathBuf};

/// The names a doctest uses to reach the kit.
const KIT: &[&str] = &[
    "test_support",
    "testkit",
    "services::double",
    "TestKernelSeal",
    "acquire_for_kernel",
];

/// The kit's own files, relative to `src/`: compiled only with the feature, so rustdoc collects
/// none of their doctests without it.
const KIT_FILES: &[&str] = &[
    "abi/sdk/test_support/",
    "testkit.rs",
    "testkit/",
    "services_double.rs",
];

/// Info strings rustdoc compiles: an empty one, `rust`, and any carrying `compile_fail`,
/// `should_panic`, `no_run` or an edition. `ignore` and non-Rust languages are not compiled.
fn compiled(info: &str) -> bool {
    let words: Vec<&str> = info
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|w| !w.is_empty())
        .collect();
    if words.contains(&"ignore") {
        return false;
    }
    words.iter().all(|w| {
        matches!(*w, "rust" | "compile_fail" | "should_panic" | "no_run")
            || w.starts_with("edition")
            || (w.starts_with('E') && w[1..].chars().all(|c| c.is_ascii_digit()))
    })
}

/// What one source line is, for fence tracking.
enum Line<'a> {
    /// A `///` or `//!` line, with its text after the marker.
    Doc(&'a str),
    /// A `#[cfg_attr(.., doc = "```..")]` or `#![..]` fence: an opening switched by a feature.
    SwitchedFence,
    Other,
}

fn classify(line: &str) -> Line<'_> {
    let t = line.trim_start();
    if let Some(rest) = t.strip_prefix("///").or_else(|| t.strip_prefix("//!")) {
        return Line::Doc(rest.strip_prefix(' ').unwrap_or(rest));
    }
    if (t.starts_with("#[cfg_attr(") || t.starts_with("#![cfg_attr(")) && t.contains("doc = \"```")
    {
        return Line::SwitchedFence;
    }
    Line::Other
}

/// Every plain-fenced compiled doctest in `src` whose body names the kit, as its 1-based opening
/// line, and the number of feature-switched fences whose body names it.
fn scan(src: &str) -> (Vec<usize>, usize) {
    let mut ungated = Vec::new();
    let mut switched = 0;
    // (opening line, plain and compiled, body names the kit)
    let mut open: Option<(usize, bool, bool, bool)> = None;
    let mut last_was_switch = false;
    for (i, line) in src.lines().enumerate() {
        match classify(line) {
            Line::SwitchedFence => {
                // The pair's second attribute opens the same block as its first.
                if !last_was_switch && open.is_none() {
                    open = Some((i + 1, false, false, true));
                }
                last_was_switch = true;
                continue;
            }
            Line::Doc(text) => {
                let fence = text.trim_start();
                if let Some(info) = fence.strip_prefix("```") {
                    match open.take() {
                        None => open = Some((i + 1, compiled(info.trim()), false, false)),
                        Some((at, plain_compiled, names, by_switch)) => {
                            if names && plain_compiled {
                                ungated.push(at);
                            }
                            if names && by_switch {
                                switched += 1;
                            }
                        }
                    }
                } else if let Some((_, _, names, _)) = open.as_mut() {
                    if KIT.iter().any(|k| text.contains(k)) {
                        *names = true;
                    }
                }
            }
            Line::Other => {}
        }
        last_was_switch = false;
    }
    (ungated, switched)
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("read {}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

#[test]
fn no_plain_fenced_doctest_names_the_test_kit() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);
    let mut found = Vec::new();
    let mut switched = 0;
    for f in &files {
        let rel = f
            .strip_prefix(&src)
            .expect("under src")
            .to_string_lossy()
            .replace('\\', "/");
        if KIT_FILES.iter().any(|k| rel.starts_with(k)) || format!("/{rel}").contains("/tests/") {
            continue;
        }
        let text = std::fs::read_to_string(f).expect("read source");
        let (ungated, s) = scan(&text);
        switched += s;
        found.extend(ungated.into_iter().map(|l| format!("src/{rel}:{l}")));
    }
    assert!(
        found.is_empty(),
        "doctests that name the test kit behind a plain fence (switch the fence on `test-seal`, \
         as caps/hold.rs does): {found:?}"
    );
    // The six `MacroDoor` pairs in abi/sdk/door.rs are switched fences that name the kit. A reader
    // that saw none of them read nothing.
    assert!(
        switched >= 6,
        "the scan saw {switched} feature-switched doctest(s) naming the kit; abi/sdk/door.rs alone \
         holds six, so the reader no longer sees them"
    );
}

/// RED: a plain fence over a body that names the kit is refused, runnable or `compile_fail`.
#[test]
fn a_plain_fence_naming_the_kit_is_refused() {
    let planted = "\
/// ```
/// let _ = busbar_contract::abi::sdk::test_support::DoorView::of(f);
/// ```
///
/// ```compile_fail,E0599
/// busbar_contract::caps::KernelSeal::acquire_for_kernel();
/// ```
pub struct S;
";
    assert_eq!(scan(planted), (vec![1, 5], 0));
}

/// GREEN twin: the same bodies behind feature-switched fences, and kit-free or `ignore` fences,
/// pass.
#[test]
fn a_switched_fence_naming_the_kit_passes() {
    let twin = "\
#[cfg_attr(feature = \"test-seal\", doc = \"```\")]
#[cfg_attr(not(feature = \"test-seal\"), doc = \"```ignore\")]
/// let _ = busbar_contract::abi::sdk::test_support::DoorView::of(f);
/// ```
///
#[cfg_attr(feature = \"test-seal\", doc = \"```compile_fail,E0599\")]
#[cfg_attr(not(feature = \"test-seal\"), doc = \"```ignore\")]
/// busbar_contract::caps::KernelSeal::acquire_for_kernel();
/// ```
///
/// ```
/// let _ = 1 + 1;
/// ```
///
/// ```ignore
/// let _ = busbar_contract::testkit::Log::new();
/// ```
pub struct S;
";
    assert_eq!(scan(twin), (vec![], 2));
}
