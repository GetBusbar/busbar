//! `cargo xtask gate c1-literals` — THE KERNEL NAMES NO PLUGIN, STYLE OR PROTOCOL (M0 ABI-SPEC).
//!
//! C1: the kernel is one governance loop that names no plugin. Across all seven kinds, a plugin
//! instance, an auth style or a wire protocol is Statement data a plugin declares — never a
//! string the kernel or the loader spells. This gate reads, over the kernel crates
//! (`busbar-kernel`, `busbar-kernel-*`) and the loader (`busbar-plugin-loader`):
//!
//! * **`literal`** — a string literal in production code holding a word of [`VOCABULARY`]. A
//!   `#[cfg(feature = "…")]` site is a literal too, so every cfg site naming one is read here.
//! * **`feature`** — a `[features]` name in one of those crates' manifests holding such a word.
//!
//! The vocabulary is the first-party plugin instance names (planes, stores, secrets, auth plugins,
//! hooks, exports), the planes' protocol and dialect names, the provider auth styles, and the
//! transport schemes (`http`, `https`, `h2`, `grpc`, `sse`, `ws`, `wss`, `websocket`, `tcp`,
//! `stdio`, `unix`). BUSBAR-1.6.0.md l.98-102 (#49) supersedes the M0 carve-out: "Core never knows
//! what `http`, `https` or `grpc` mean — those strings are data passing through it from a plane to
//! a transport." A scheme the kernel or loader spells is a C1 leak like any other word.
//!
//! [`MASKS`] removes a few exact strings before the words are read. Each one spells a vocabulary
//! word without naming a transport: an identifier URI, a frozen 1.5.5 env var, or `unix` as the
//! OS or as time. Each mask is an exact string, never a word, so a bare scheme in the same literal
//! still reds (the selftest proves it).
//!
//! REPORT-ONLY, armed at today's count as the drain-only ledger `qa/c1-literals.toml`.

use crate::ctx::{Ctx, Overlay};
use crate::gates::one_abi::{self, Finding, Spec};
use crate::gates::{Gate, Report};
use crate::ledger::Verdict;
use crate::manifest;

pub const ROW_LITERAL: &str = "c1-literals:literal";
pub const ROW_FEATURE: &str = "c1-literals:feature";

/// The words the kernel may not spell, lower case. A word holding `-` also matches with `_`.
pub const VOCABULARY: &[&str] = &[
    // planes
    "llm",
    "mcp",
    "a2a",
    "voice",
    "streaming",
    // plane protocols and dialect documents (a transport carrier id is NOT here: it is the kernel's own neutral vocabulary)
    "jsonrpc",
    "openapi",
    // provider dialects and auth styles
    "openai",
    "anthropic",
    "gemini",
    "bedrock",
    "sigv4",
    // stores and secrets
    "postgres",
    "mysql",
    "sqlite",
    "valkey",
    "redis",
    "vault",
    // auth plugins
    "oidc",
    "github",
    "ldap",
    "admin-tokens",
    // hooks
    "webrequest",
    "ranking",
    // exports
    "prometheus",
    "otlp",
    "webhook",
    // transport schemes (BUSBAR-1.6.0.md l.98-102: data passing from a plane to a transport)
    "http",
    "https",
    "h2",
    "grpc",
    "sse",
    "ws",
    "wss",
    "websocket",
    "tcp",
    "stdio",
    "unix",
];

/// EXACT STRINGS removed from a literal before its words are read (coordinator ruling R1 on the
/// widened vocabulary, 2026-10-14). Each spells a vocabulary word without naming a transport. Each
/// is an exact string, not a word or a pattern, so the transport sense is still caught: `"http"`,
/// `"unix:"` or a second URL beside a masked one still reds (see the selftest).
pub const MASKS: &[&str] = &[
    // An XML namespace name, an identifier URI that is never dialled (the inline SVG
    // busbar-kernel/src/auth/token.rs renders).
    "http://www.w3.org/2000/svg",
    // The JSON Schema dialect identifier a `$schema` names, never dialled (plugin-loader pack.rs).
    "https://json-schema.org/draft/2020-12/schema",
    // The frozen 1.5.5 env var name (v1.5.5:crates/busbar/src/main.rs:3142) and the inline
    // capture of the kernel's const that holds it (appbuild.rs `ENV_UPSTREAM_H2_PRIOR_KNOWLEDGE`).
    "BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE",
    "{ENV_UPSTREAM_H2_PRIOR_KNOWLEDGE}",
    // `unix` as time and as the operating system, never the `unix:` socket scheme.
    "unix_ms",
    "unix seconds",
    "on unix",
];

pub const SPEC: Spec = Spec {
    gate: "c1-literals",
    ledger: "qa/c1-literals.toml",
    rules: &[
        (
            ROW_LITERAL,
            "no string literal in the kernel or loader names a plugin, style or protocol",
        ),
        (
            ROW_FEATURE,
            "no kernel or loader feature names a plugin, style or protocol",
        ),
    ],
    header: "# c1-literals: DRAIN-ONLY ledger (M0 ABI-SPEC, REPORT-ONLY).\n\
             # THE RULE (ARCHITECT ruling on M0): a plane's dialect or protocol name, a plugin\n\
             # instance name, an auth style or a transport scheme (http, https, h2, grpc, sse, ws,\n\
             # wss, websocket, tcp, stdio, unix; BUSBAR-1.6.0.md l.98-102) spelled by the kernel or\n\
             # the loader IS a C1 leak. The word list is VOCABULARY, and the exact strings read\n\
             # past (an identifier URI, a frozen env var, `unix` as time or the OS) are MASKS, in\n\
             # xtask/src/gates/c1_literals.rs.\n\
             # The kernel and the loader name no plugin, style or protocol: each row is a file and\n\
             # the vocabulary word one of its string literals (or a manifest's feature) spells\n\
             # today. Strike a row in the commit that drains it; never add one.\n\
             # Regenerate with `cargo xtask gate c1-literals --write`.\n",
};

/// Is `m` a crate this gate reads?
fn in_scope(name: &str) -> bool {
    name == "busbar-kernel" || name.starts_with("busbar-kernel-") || name == "busbar-plugin-loader"
}

/// Every vocabulary word `text` spells, each once.
pub fn words_in(text: &str) -> Vec<&'static str> {
    let masked = MASKS
        .iter()
        .fold(text.to_string(), |t, mask| t.replace(mask, " "));
    let lower = masked.to_ascii_lowercase();
    let tokens: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    VOCABULARY
        .iter()
        .copied()
        .filter(|w| {
            if w.contains('-') {
                lower.contains(w) || lower.contains(&w.replace('-', "_"))
            } else {
                tokens.contains(w)
            }
        })
        .collect()
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let members = match one_abi::members(cx) {
        Ok(m) => m,
        Err(e) => return (findings, vec![e]),
    };
    let scope: Vec<_> = members.iter().filter(|m| in_scope(&m.name)).collect();
    if scope.len() < 5 {
        errors.push(format!(
            "the kernel and loader read as {} crate(s); the scan has gone blind",
            scope.len()
        ));
    }
    for m in scope {
        for feature in manifest::feature_table(&m.manifest).keys() {
            for w in words_in(feature) {
                findings.push(Finding::new(
                    ROW_FEATURE,
                    &m.manifest_rel(),
                    format!("{w} ({feature})"),
                    0,
                ));
            }
        }
        let files = match one_abi::rs_files(cx, &m.dir) {
            Ok(f) => f,
            Err(e) => {
                errors.push(e);
                continue;
            }
        };
        for f in &files {
            let rel = f.rel_str();
            for sl in one_abi::production(&f.text) {
                for lit in one_abi::literals(&sl) {
                    for w in words_in(&lit) {
                        findings.push(Finding::new(ROW_LITERAL, &rel, w, sl.no));
                    }
                }
            }
        }
    }
    (findings, errors)
}

pub struct C1LiteralsGate;

impl Gate for C1LiteralsGate {
    fn name(&self) -> &'static str {
        SPEC.gate
    }

    fn owed(&self) -> Vec<String> {
        SPEC.owed()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let (findings, errors) = scan(cx);
        one_abi::verdict(cx, &SPEC, findings, errors)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let file = "crates/busbar-kernel/src/planted_c1.rs";
        let manifest = "crates/busbar-kernel-wal/Cargo.toml";
        let mut lit = Overlay::new();
        lit.set(file, "pub const PLANTED: &str = \"valkey\";\n");
        let feature = {
            let text = cx.read(manifest).unwrap_or_default();
            let text = if text.contains("[features]\n") {
                text.replacen("[features]\n", "[features]\nplanted-otlp = []\n", 1)
            } else {
                format!("{text}\n[features]\nplanted-otlp = []\n")
            };
            let mut ov = Overlay::new();
            ov.set(manifest, text);
            ov
        };
        let mut scheme = Overlay::new();
        scheme.set(file, "pub const PLANTED: &str = \"http\";\n");
        let mut socket = Overlay::new();
        socket.set(file, "pub const PLANTED: &str = \"unix:/run/x.sock\";\n");
        let mut beside = Overlay::new();
        beside.set(
            file,
            "pub const PLANTED: &str = \"http://www.w3.org/2000/svg grpc://x\";\n",
        );
        let mut masked = Overlay::new();
        masked.set(
            file,
            "pub const A: &str = \"<svg xmlns='http://www.w3.org/2000/svg'/>\";\n\
             pub const B: &str = \"https://json-schema.org/draft/2020-12/schema\";\n\
             pub const C: &str = \"BUSBAR_UPSTREAM_H2_PRIOR_KNOWLEDGE\";\n\
             pub const D: &str = \"quarantine-{unix_ms}\";\n\
             pub const E: &str = \"a timestamp in unix seconds\";\n\
             pub const F: &str = \"SIGTERM on unix\";\n",
        );
        let mut comment = Overlay::new();
        comment.set(
            file,
            "// valkey, in a comment, is prose\npub const X: u8 = 0;\n",
        );
        let mut report = one_abi::selftest(
            cx,
            self,
            &SPEC,
            vec![
                (
                    ROW_LITERAL,
                    "a kernel literal naming a store is RED, naming the word",
                    lit,
                    vec![file, "valkey"],
                ),
                (
                    ROW_FEATURE,
                    "a kernel feature naming an export is RED",
                    feature,
                    vec![manifest, "otlp"],
                ),
                (
                    ROW_LITERAL,
                    "a kernel literal spelling a transport scheme is RED",
                    scheme,
                    vec![file, "http"],
                ),
                (
                    ROW_LITERAL,
                    "a `unix:` socket scheme is RED (the masks read past only time and the OS)",
                    socket,
                    vec![file, "unix"],
                ),
                (
                    ROW_LITERAL,
                    "a scheme beside a masked identifier URI is still RED",
                    beside,
                    vec![file, "grpc"],
                ),
            ],
        );
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "the masked strings (identifier URIs, the 1.5.5 env var, unix time and OS) are not a scheme",
            &[ROW_LITERAL],
            masked,
        ));
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "a vocabulary word in a comment is not a literal",
            &[ROW_LITERAL],
            comment,
        ));
        report
    }
}
