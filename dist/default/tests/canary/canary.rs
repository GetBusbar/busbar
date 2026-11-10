// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::fmt::Write as _;
use std::path::PathBuf;

/// One required delivery to the exact recipient at the exact boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub sink: String,
    pub owner: String,
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
    /// Required authorized deliveries; every other observed crossing is a failure.
    pub deliveries: Vec<Delivery>,
}

impl Canary {
    pub fn new(kind: &'static str) -> Self {
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
            deliveries: Vec::new(),
        }
    }

    pub fn also(mut self, form: String) -> Self {
        self.forms.push(form);
        self
    }

    pub fn delivered_to(mut self, sink: impl Into<String>, owner: impl Into<String>) -> Self {
        let delivery = Delivery {
            sink: sink.into(),
            owner: owner.into(),
        };
        assert!(
            !self.deliveries.contains(&delivery),
            "one requirement per exact delivery"
        );
        self.deliveries.push(delivery);
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
    /// Exact recipient metadata, before diagnostic line numbers are added.
    pub owner: String,
    /// The line it sat on (the canary's forms masked), for the report.
    pub context: String,
}

pub fn search(canary: &Canary, sinks: &[Sink]) -> Vec<Hit> {
    let mut hits = Vec::new();
    for sink in sinks {
        let text = String::from_utf8_lossy(&sink.bytes);
        for (no, line) in text.lines().enumerate() {
            if canary.forms.iter().any(|f| line.contains(f.as_str())) {
                hits.push(Hit {
                    sink: sink.name.clone(),
                    owner: sink.at.clone(),
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

pub struct Verdict {
    pub ok: bool,
    pub text: String,
}

pub fn judge(canary: &Canary, hits: &[Hit]) -> Verdict {
    let mut text = String::new();
    let matches =
        |delivery: &Delivery, hit: &Hit| delivery.sink == hit.sink && delivery.owner == hit.owner;
    let unexpected: Vec<_> = hits
        .iter()
        .filter(|hit| {
            !canary
                .deliveries
                .iter()
                .any(|delivery| matches(delivery, hit))
        })
        .collect();
    let missing: Vec<_> = canary
        .deliveries
        .iter()
        .filter(|delivery| !hits.iter().any(|hit| matches(delivery, hit)))
        .collect();
    let ok = unexpected.is_empty() && missing.is_empty();
    let _ = writeln!(
        text,
        "[{}] {} unexpected hit(s), {} missing required deliveries: {}",
        canary.kind,
        unexpected.len(),
        missing.len(),
        if ok { "clean" } else { "FAIL" }
    );
    for delivery in &canary.deliveries {
        let count = hits.iter().filter(|hit| matches(delivery, hit)).count();
        let _ = writeln!(
            text,
            "    required {} @ {}: {count} observed hit(s)",
            delivery.sink, delivery.owner
        );
    }
    for hit in unexpected {
        let _ = writeln!(
            text,
            "    unexpected {} @ {}: {}",
            hit.sink, hit.at, hit.context
        );
    }
    Verdict { ok, text }
}

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
        "canary delivery contract failed in scenario {scenario}: {failed:?}\n{report}"
    );
}
