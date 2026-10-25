// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! CANARIES, SINKS, THE SEARCH AND THE VERDICT.
//!
//! A [`Canary`] is a unique fake credential (`CANARY-<kind>-<16 hex>`) planted through one input
//! kind. A [`Sink`] is any text or bytes a black box can see (the node's log, a refusal, `--validate`
//! output, an admin response, an exported record, a far end's received request, an ABI crossing the
//! recording shim saw). [`search`] finds every sink holding any form of a canary; [`judge`] holds the
//! hits against the canary's [`Expect`]:
//!
//! * `Expect::Leaks` (XFAIL, a known leak): passes while it leaks, listing the hits; once it stops
//!   leaking it still passes but says "now clean, flip to Expect::Clean".
//! * `Expect::Clean` (strict): any hit fails.
//!
//! The hits are also written to `target/canary-report/<scenario>.txt` for reading after a CI run.

use std::fmt::Write as _;
use std::path::PathBuf;

/// What a canary is expected to do today.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Expect {
    /// A known leak (XFAIL): hits are listed, and the canary passes while they exist.
    Leaks,
    /// Strict: a single hit fails.
    Clean,
}

/// One planted credential.
#[derive(Debug, Clone)]
pub struct Canary {
    /// The input kind it was planted through.
    pub kind: &'static str,
    /// The value planted.
    pub value: String,
    /// The searched forms: the value's unique hex tail (so a canary found wrapped, prefixed or
    /// truncated at its head is still found), plus any derived encodings ([`Canary::also`]).
    pub forms: Vec<String>,
    /// Sinks that are this credential's DESIGNED destination, not a leak (a provider key at its
    /// own provider's far end). Matched as a prefix of the sink's name.
    pub delivered_to: Vec<&'static str>,
    pub expect: Expect,
}

impl Canary {
    /// A fresh canary for `kind`: `CANARY-<kind>-<16 random hex>`.
    pub fn new(kind: &'static str, expect: Expect) -> Self {
        let mut raw = [0u8; 8];
        getrandom::fill(&mut raw).expect("random bytes for a canary");
        let tail = hex::encode(raw);
        let slug: String = kind
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect();
        Canary {
            kind,
            value: format!("CANARY-{slug}-{tail}"),
            forms: vec![tail],
            delivered_to: Vec::new(),
            expect,
        }
    }

    /// Also search for `form` (an encoding the value is known to travel in, e.g. Basic auth).
    pub fn also(mut self, form: String) -> Self {
        self.forms.push(form);
        self
    }

    /// `sink` (a sink-name prefix) is where this credential is MEANT to go.
    pub fn delivered_to(mut self, sink: &'static str) -> Self {
        self.delivered_to.push(sink);
        self
    }
}

/// One thing a black box can see.
#[derive(Debug, Clone)]
pub struct Sink {
    /// Its class and name, e.g. `log:node`, `admin:/api/v1/admin/providers`, `abi:op:open.settings`.
    pub name: String,
    /// Where, within the class (a plugin label, a file, a request).
    pub at: String,
    pub bytes: Vec<u8>,
}

impl Sink {
    pub fn text(name: impl Into<String>, at: impl Into<String>, text: impl Into<String>) -> Self {
        Sink {
            name: name.into(),
            at: at.into(),
            bytes: text.into().into_bytes(),
        }
    }

    pub fn raw(name: impl Into<String>, at: impl Into<String>, bytes: Vec<u8>) -> Self {
        Sink {
            name: name.into(),
            at: at.into(),
            bytes,
        }
    }
}

/// One canary found in one sink.
#[derive(Debug, Clone)]
pub struct Hit {
    pub sink: String,
    pub at: String,
    /// The line it sat on (the canary's forms masked), for the report.
    pub context: String,
}

/// Every hit of `canary` in `sinks`, designed deliveries excluded.
pub fn search(canary: &Canary, sinks: &[Sink]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for sink in sinks {
        if canary.delivered_to.iter().any(|d| sink.name.starts_with(d)) {
            continue;
        }
        let text = String::from_utf8_lossy(&sink.bytes);
        for (no, line) in text.lines().enumerate() {
            if canary.forms.iter().any(|f| line.contains(f.as_str())) {
                hits.push(Hit {
                    sink: sink.name.clone(),
                    at: if text.lines().nth(1).is_some() {
                        format!("{} line {}", sink.at, no + 1)
                    } else {
                        sink.at.clone()
                    },
                    context: masked(line, canary),
                });
            }
        }
    }
    hits
}

/// `line` with each canary form replaced by `<CANARY>`, cut to a readable length.
fn masked(line: &str, canary: &Canary) -> String {
    let mut out = line.replace(&canary.value, "<CANARY>");
    for f in &canary.forms {
        out = out.replace(f.as_str(), "<CANARY>");
    }
    let mut cut: String = out.chars().take(220).collect();
    if cut.len() < out.len() {
        cut.push('…');
    }
    cut
}

/// One canary's verdict.
pub struct Verdict {
    pub ok: bool,
    pub text: String,
}

/// `canary`'s hits held against its expectation.
pub fn judge(canary: &Canary, hits: &[Hit]) -> Verdict {
    let mut text = String::new();
    let status = match (canary.expect, hits.is_empty()) {
        (Expect::Leaks, false) => "XFAIL (known leak)",
        (Expect::Leaks, true) => "NOW CLEAN: flip to Expect::Clean",
        (Expect::Clean, true) => "clean",
        (Expect::Clean, false) => "FAIL (expected clean, leaked)",
    };
    let _ = writeln!(text, "[{}] {} hit(s): {status}", canary.kind, hits.len());
    for h in hits {
        let _ = writeln!(text, "    {} @ {}: {}", h.sink, h.at, h.context);
    }
    Verdict {
        ok: !(canary.expect == Expect::Clean && !hits.is_empty()),
        text,
    }
}

/// The directory the reports go to: `<target>/canary-report`, found from this test binary's path
/// (`<target>/<profile>/deps/canary-<hash>`), so it holds under cargo, nextest and a custom
/// `CARGO_TARGET_DIR` alike.
pub fn report_dir() -> PathBuf {
    let exe = std::env::current_exe().expect("the test binary's path");
    let target = exe
        .ancestors()
        .find(|p| p.file_name().is_some_and(|n| n == "deps"))
        .and_then(|deps| deps.parent())
        .and_then(|profile| profile.parent())
        .map(PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    target.join("canary-report")
}

/// SWEEP one scenario: search every canary in `sinks`, judge each, write the report to
/// `<target>/canary-report/<scenario>.txt` and print it; panic when a strict canary leaked.
pub fn sweep(scenario: &str, canaries: &[Canary], sinks: &[Sink], notes: &[String]) {
    let mut report = String::new();
    let _ = writeln!(report, "# canary scenario: {scenario}");
    let _ = writeln!(report, "# sinks searched: {}", sinks.len());
    let mut names: Vec<&str> = sinks.iter().map(|s| s.name.as_str()).collect();
    names.sort_unstable();
    names.dedup();
    for n in names {
        let _ = writeln!(report, "#   {n}");
    }
    for n in notes {
        let _ = writeln!(report, "# note: {n}");
    }
    let mut failed = Vec::new();
    for c in canaries {
        let hits = search(c, sinks);
        let v = judge(c, &hits);
        report.push_str(&v.text);
        if !v.ok {
            failed.push(c.kind);
        }
    }
    let dir = report_dir();
    let _ = std::fs::create_dir_all(&dir);
    // Every sink searched, beside the report, so a reader can see the sweep was live (the canaries
    // are fake values; nothing here is a credential).
    let mut dump = String::new();
    for s in sinks {
        let text = String::from_utf8_lossy(&s.bytes);
        let cut: String = text.chars().take(4096).collect();
        let _ = writeln!(
            dump,
            "===== {} @ {} ({} bytes)\n{cut}",
            s.name,
            s.at,
            s.bytes.len()
        );
    }
    let _ = std::fs::write(dir.join(format!("{scenario}.sinks.txt")), dump);
    let file = dir.join(format!("{scenario}.txt"));
    std::fs::write(&file, &report).expect("write the canary report");
    println!("{report}(written to {})", file.display());
    assert!(
        failed.is_empty(),
        "canaries expected CLEAN leaked in scenario {scenario}: {failed:?}\n{report}"
    );
}
