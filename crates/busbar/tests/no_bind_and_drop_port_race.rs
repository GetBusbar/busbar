// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! STRUCTURE-LINT: no test or bench in this crate may re-plant the `free_port()` shape — a
//! `bind(".*:0")` whose listener is queried for its port and dropped, unnamed, in the SAME
//! expression, before a child process gets a chance to bind that number.
//!
//! Nine files (`no_data_dir_neutrality`, `boot_lines_neutrality`, `thread_per_core_serves`,
//! `scrape_shape_1_5_5`, `mcp_open_front_door`, `ledger_identity`, `inbound_concurrency_shed`,
//! `metrics_scrape_boot_window`, and the `hook_path` bench) each carried a copy of exactly this
//! shape:
//!
//! ```text
//! std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
//! ```
//!
//! The listener is a temporary — never bound to a name — so it is dropped the instant the
//! expression finishes evaluating, and only afterward does the fixture write config/provider YAML,
//! generate a signing key, or boot a second child, and only THEN spawn the process that binds the
//! number. Measured: one such test failed a 3-hour proof in 0.07s on a shared box with connection
//! refused — something else on the box was handed the freed port in that gap.
//!
//! `common::ReservedPort` (`crates/busbar/tests/common/mod.rs`) is the fix: it holds the listener
//! open, by NAME, until the caller explicitly releases it right before the spawn that needs the
//! number. This gate is what keeps a tenth copy of the bind-and-drop shape from being planted the
//! next time a test needs a literal port — the fix is a name change (`let _ = TcpListener::bind`
//! becomes `let reserved = ReservedPort::reserve()`), and a gate is cheaper than a code-review
//! comment for catching its absence.
//!
//! Detection is textual rather than semantic (this crate's tests are not asking `rustc` for a type
//! graph), but the fingerprint is exact: `bind(` naming a `:0` address, chained — with no `;` and no
//! `let` splitting the listener off into a name — straight through `.local_addr(` to `.port(`. A
//! held reservation never has this shape: the bind and the `.port()` read live in two different
//! items (`ReservedPort::reserve` binds; `ReservedPort::port` reads `self.0.local_addr()` later, on
//! a named field), so nothing this gate is meant to allow can trip it.

use std::path::{Path, PathBuf};

/// Every `.rs` file directly in `crates/busbar/tests/` (recursively — `common/` included) and
/// `crates/busbar/benches/`. These two directories are the whole of the crate's test/bench surface
/// that can spawn a real child process against a literal port, which is the only place this shape
/// has ever appeared.
fn scanned_files() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut out = Vec::new();
    for sub in ["tests", "benches"] {
        walk(&root.join(sub), &mut out);
    }
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

/// Strip `//`-to-EOL comments, naively but sufficiently: every occurrence of the banned shape in
/// this crate's history has been plain code, never string- or comment-embedded, and a lint that
/// over-fires on a comment mentioning the shape (as this file's own doc does, in a fenced block) is
/// exactly the false positive worth avoiding — hence the fenced example above is prose, not source,
/// and is never read by this scanner (this file scans OTHER files, not itself... except itself, so
/// see the self-exclusion below).
fn strip_line_comments(src: &str) -> String {
    src.lines()
        .map(|line| match line.find("//") {
            Some(i) => &line[..i],
            None => line,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// One occurrence of the banned shape: a `bind(` whose argument names a `:0` address, chained
/// (no `;`) through to a `.local_addr(` and then (no `;`) to a `.port(` — the exact
/// bind-query-and-drop idiom `free_port()` reproduced nine times.
fn find_bind_and_drop(text: &str) -> Vec<usize> {
    let bytes = text.as_bytes();
    let mut hits = Vec::new();
    let mut search_from = 0usize;
    while let Some(rel) = text[search_from..].find("bind(") {
        let bind_at = search_from + rel;
        // The address argument: up to the matching `)`, bounded generously (addresses are short).
        let arg_end = text[bind_at..]
            .find(')')
            .map(|i| bind_at + i)
            .unwrap_or(bind_at);
        let arg = &text[bind_at..arg_end];
        search_from = bind_at + "bind(".len();
        if !arg.contains(":0\"") {
            continue;
        }
        // From the `)` closing `bind(...)`, walk forward through the method chain: no `;`, `{` or
        // `}` allowed before EITHER `.local_addr(` or the `.port(` that must follow it — those are
        // statement/item boundaries, and crossing one means the listener was bound to a name (or
        // the bind and the read live in two different functions, as `ReservedPort::reserve`/`port`
        // do) rather than living and dying inside one throwaway expression. A generous but bounded
        // character window keeps a pathological file (no `;`/`{`/`}` for a long stretch) from
        // reading arbitrarily far ahead.
        const WINDOW: usize = 400;
        let after_bind = after_bind_slice(text, arg_end, WINDOW);
        let boundary = after_bind.find([';', '{', '}']).unwrap_or(after_bind.len());
        let chain = &after_bind[..boundary];
        let Some(local_addr_at) = chain.find(".local_addr(") else {
            continue;
        };
        if chain[local_addr_at..].contains(".port(") {
            hits.push(byte_to_line(bytes, bind_at));
        }
    }
    hits
}

fn byte_to_line(bytes: &[u8], at: usize) -> usize {
    bytes[..at].iter().filter(|&&b| b == b'\n').count() + 1
}

/// Up to `window` bytes of `text` starting at `from`, trimmed back to the nearest char boundary so
/// the slice never panics on a multi-byte UTF-8 sequence.
fn after_bind_slice(text: &str, from: usize, window: usize) -> &str {
    let end = (from + window).min(text.len());
    let mut end = end;
    while end > from && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[from..end]
}

#[test]
fn no_test_or_bench_binds_an_ephemeral_port_and_drops_it_before_a_child_binds_it() {
    let mut offenders: Vec<String> = Vec::new();
    for path in scanned_files() {
        // This file's own doc comment quotes the shape in a fenced example, by name, on purpose —
        // it is prose describing the very thing the gate refuses, not a reintroduction of it.
        if path.file_name().and_then(|n| n.to_str()) == Some("no_bind_and_drop_port_race.rs") {
            continue;
        }
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        let stripped = strip_line_comments(&raw);
        for line in find_bind_and_drop(&stripped) {
            offenders.push(format!("{}:{line}", path.display()));
        }
    }
    assert!(
        offenders.is_empty(),
        "a test or bench binds an ephemeral loopback port and drops it (unnamed) before a child \
         process gets to bind the number — the exact `free_port()` shape nine files carried and \
         `common::ReservedPort` replaced (see this file's own doc). Use \
         `common::ReservedPort::reserve()`/`.port()`/`.release()` instead, releasing only \
         immediately before the `Command::spawn` that binds the number:\n{}",
        offenders.join("\n")
    );
}

/// SELF-TEST: the detector actually fires on the shape it exists to refuse, and does not fire on
/// the `ReservedPort` shape that replaced it — proved directly, on strings, rather than trusted
/// because the boot test above happens to be green today (which a detector that matched nothing
/// would also be).
#[test]
fn the_detector_fires_on_the_banned_shape_and_not_on_a_held_reservation() {
    let banned = r#"
        fn free_port() -> u16 {
            std::net::TcpListener::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap()
                .port()
        }
    "#;
    assert!(
        !find_bind_and_drop(&strip_line_comments(banned)).is_empty(),
        "the detector must fire on the exact shape it exists to refuse"
    );

    let held = r#"
        pub struct ReservedPort(std::net::TcpListener);
        impl ReservedPort {
            pub fn reserve() -> Self {
                ReservedPort(std::net::TcpListener::bind("127.0.0.1:0").expect("a free port"))
            }
            pub fn port(&self) -> u16 {
                self.0.local_addr().expect("a bound address").port()
            }
        }
    "#;
    assert!(
        find_bind_and_drop(&strip_line_comments(held)).is_empty(),
        "the detector must not fire on a listener that is bound to a name and read later — that is \
         the fix, not the defect"
    );
}
