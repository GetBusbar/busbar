//! `cargo xtask gate c1-literals` — THE KERNEL NAMES NO PLUGIN, STYLE OR PROTOCOL (M0 ABI-SPEC).
//!
//! C1: the kernel is one governance loop that names no plugin. Across all seven kinds, a plugin
//! instance, an auth style or a wire protocol is Statement data a plugin declares — never a
//! string the kernel or the loader spells. This gate reads, over the kernel crates
//! (`busbar-kernel`, `busbar-kernel-*`) and the loader (`busbar-plugin-loader`):
//!
//! * **`literal`** — a string literal in production code holding a word of the [`vocabulary`]. A
//!   `#[cfg(feature = "…")]` site is a literal too, so every cfg site naming one is read here.
//! * **`feature`** — a `[features]` name in one of those crates' manifests holding such a word.
//!
//! The vocabulary is DERIVED from the plugin registry, `plugins.yaml` ([`vocabulary`]): every
//! registered instance of the seven kinds by its alias, repo name, former and retired names, so a
//! plugin the registry gains is a word here with no edit. [`NOT_INSTANCES`] adds the few words no
//! entry declares (the llm plane's dialects, the plane protocols, the transport schemes a
//! registered transport serves beyond its alias), and [`ORDINARY`] names the registered names that
//! are ordinary words, read under a stricter rule. BUSBAR-1.6.0.md l.98-102 (#49) supersedes the M0 carve-out: "Core never knows
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

/// THE WORDS NO REGISTRY ENTRY DECLARES, each with why it is not an instance. Everything else the
/// kernel may not spell is read off `plugins.yaml` ([`vocabulary`]): BUSBAR-1.6.0.md l.2068-2069,
/// "Where a roster of instances must exist, it is derived from the instances' own declarations; a
/// roster maintained by hand is a defect with a date on it." A word here that the registry comes to
/// declare is an error (the hand copy has gone stale), so this list only ever holds non-instances.
pub const NOT_INSTANCES: &[(&str, &str)] = &[
    // The llm plane's dialects and auth styles: names inside one plane, not a registry entry.
    (
        "voice",
        "an llm dialect (BUSBAR-1.6.0.md l.1193), not a plugin",
    ),
    ("openai", "an llm provider dialect, not a plugin"),
    ("anthropic", "an llm provider dialect, not a plugin"),
    ("gemini", "an llm provider dialect, not a plugin"),
    ("bedrock", "an llm provider dialect, not a plugin"),
    // Plane protocols and dialect documents.
    (
        "jsonrpc",
        "the mcp and a2a planes' wire protocol, not a plugin",
    ),
    ("openapi", "a dialect document format, not a plugin"),
    // Transport schemes a registered transport serves under a name other than its alias
    // (BUSBAR-1.6.0.md l.98-102: data passing from a plane to a transport).
    ("https", "the http transport's TLS scheme"),
    ("h2", "the http transport's HTTP/2 scheme"),
    ("sse", "the http transport's event-stream scheme"),
    ("wss", "the ws transport's TLS scheme"),
    ("websocket", "the ws transport's protocol name"),
    ("unix", "the socket scheme a transport dials"),
];

/// THE REGISTERED NAMES THAT ARE ORDINARY WORDS, each with why. Such a name still counts, under a
/// stricter rule than a token match ([`words_in`]): the whole literal is the name (`"memory"`,
/// `get("env")`), or the name is the value of an instance selector (`module: env`,
/// `auth: header`). Matched as a bare token each would read every "config file", "frame header"
/// or "beyond memory" in the kernel's prose as a plugin. A name here the registry no longer
/// declares is an error.
pub const ORDINARY: &[(&str, &str)] = &[
    (
        "env",
        "the env secret; also \"environment\" in every error naming an env var",
    ),
    (
        "file",
        "the file secret and export; also every \"config file\", \"plugin file\"",
    ),
    (
        "memory",
        "the memory store; also every \"in memory\", \"beyond memory\"",
    ),
    (
        "header",
        "the header auth plugin; also every HTTP and frame \"header\"",
    ),
    (
        "decisions",
        "the decisions plane; also every routing or policy \"decisions\" in prose",
    ),
];

/// The keys whose value names an instance or a style: `store.module: <name>`, a secret's or
/// export's `module:`, a provider's `auth: <style>` (the 1.5.5 config schema's selectors).
pub const SELECTORS: &[&str] = &["module", "auth"];

/// A registered name shorter than this is not a word: a one-character name is spelled by every
/// one-letter literal, so no census could tell the plugin from text (plugins.yaml, `secret-c`'s
/// own comment). Its alias (`secret-c`) still counts.
pub const MIN_NAME_LEN: usize = 2;

/// The words the kernel may not spell, lower case: the registry's names plus [`NOT_INSTANCES`],
/// and which of them are [`ORDINARY`].
#[derive(Debug, Clone, Default)]
pub struct Vocabulary {
    pub words: std::collections::BTreeSet<String>,
    pub ordinary: std::collections::BTreeSet<String>,
}

/// THE VOCABULARY, DERIVED from `plugins.yaml` (read through the overlay): every entry's alias,
/// the `<name>` of its `busbar-<kind>-<name>` repo, its `former_names`, its `retired` names, and
/// the `legacy:` block's 1.5.5 manifest names. A compound name (`busbar-store-mysql-plugin`,
/// `webhook-signature`) one of whose `-` parts is already a non-ordinary word is dropped: that
/// word already reads it, and a second finding for one site is noise. The plugin declarations
/// (`declares.json`) carry only `needs`, which names registered aliases, so they add no word.
///
/// # Errors
/// The registry does not read, declares no plugin, or a hand list here has gone stale.
pub fn vocabulary(cx: &Ctx) -> Result<Vocabulary, String> {
    use serde_json::Value;
    let text = cx.read(crate::fleet::registry::REGISTRY)?;
    let doc = crate::yaml_lite::parse_structure(&text)
        .map_err(|e| format!("{}: {e}", crate::fleet::registry::REGISTRY))?;
    let entries = match doc.get("plugins") {
        Some(Value::Array(a)) if !a.is_empty() => a,
        _ => {
            return Err(format!(
                "{}: no `plugins:` entry; the vocabulary has gone blind",
                crate::fleet::registry::REGISTRY
            ))
        }
    };
    let mut names: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for e in entries {
        let str_of = |k: &str| e.get(k).and_then(Value::as_str).map(str::to_string);
        let repo = str_of("repo").unwrap_or_default();
        let kind = str_of("kind").unwrap_or_default();
        let alias = str_of("alias").ok_or_else(|| {
            format!(
                "{}: entry `{repo}` has no alias",
                crate::fleet::registry::REGISTRY
            )
        })?;
        names.insert(alias);
        if let Some(name) = repo.strip_prefix(&format!("busbar-{kind}-")) {
            names.insert(name.to_string());
        }
        for k in ["former_names", "retired"] {
            if let Some(Value::Array(items)) = e.get(k) {
                names.extend(items.iter().filter_map(Value::as_str).map(str::to_string));
            }
        }
    }
    if let Some(Value::Object(legacy)) = doc.get("legacy") {
        for (k, v) in legacy {
            if k.starts_with(crate::fleet::registry::NAME_1_5_5) {
                if let Some(v) = v.as_str() {
                    names.insert(v.to_string());
                }
            }
        }
    }
    let registered: std::collections::BTreeSet<String> = names
        .into_iter()
        .map(|n| n.trim().to_ascii_lowercase())
        .filter(|n| n.len() >= MIN_NAME_LEN)
        .collect();
    let mut errors = Vec::new();
    for (w, why) in NOT_INSTANCES {
        if registered.contains(*w) {
            errors.push(format!(
                "`{w}` is in NOT_INSTANCES ({why}) and the registry declares it: strike the hand copy"
            ));
        }
    }
    for (w, why) in ORDINARY {
        if !registered.contains(*w) {
            errors.push(format!(
                "`{w}` is in ORDINARY ({why}) and the registry no longer declares it: strike it"
            ));
        }
    }
    if !errors.is_empty() {
        return Err(errors.join(" ; "));
    }
    let ordinary: std::collections::BTreeSet<String> =
        ORDINARY.iter().map(|(w, _)| (*w).to_string()).collect();
    let mut words = registered;
    words.extend(NOT_INSTANCES.iter().map(|(w, _)| (*w).to_string()));
    let plain = words.clone();
    words.retain(|w| {
        !w.contains('-')
            || !w
                .split('-')
                .any(|part| part != w && plain.contains(part) && !ordinary.contains(part))
    });
    Ok(Vocabulary { words, ordinary })
}

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
             # the loader IS a C1 leak. The words are read off plugins.yaml, and the exact strings read\n\
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

/// Does `w` occur in `hay` bounded by non-alphanumeric characters? Each bounded start, in order.
fn bounded(hay: &str, w: &str) -> Vec<usize> {
    let alnum = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric());
    let mut out = Vec::new();
    let mut from = 0;
    while let Some(i) = hay[from..].find(w) {
        let at = from + i;
        if !alnum(hay[..at].chars().next_back()) && !alnum(hay[at + w.len()..].chars().next()) {
            out.push(at);
        }
        from = at + w.len();
    }
    out
}

/// Is the occurrence of an ordinary word at `at` the value of a [`SELECTORS`] key
/// (`store.module: memory`, `"module":"env"`, `auth = 'header'`)?
fn selected(lower: &str, at: usize) -> bool {
    let quote = |c: char| matches!(c, ' ' | '\'' | '"' | '`' | '\\');
    let before = lower[..at].trim_end_matches(quote);
    let Some(key) = before
        .strip_suffix(':')
        .or_else(|| before.strip_suffix('='))
        .map(|k| k.trim_end_matches(quote))
    else {
        return false;
    };
    SELECTORS.iter().any(|s| {
        key.strip_suffix(s)
            .is_some_and(|head| !head.ends_with(|c: char| c.is_ascii_alphanumeric() || c == '_'))
    })
}

/// Every vocabulary word `text` spells, each once. A plain word is a token (split at every
/// non-alphanumeric); a compound (`admin-tokens`) is a bounded run, spelled with `-` or `_`. In
/// `prose` (a string literal) an [`ORDINARY`] word counts only as the whole literal or as a
/// [`SELECTORS`] value; in an identifier (a feature name) it is a token like any other word.
pub fn words_in(vocab: &Vocabulary, text: &str, prose: bool) -> Vec<String> {
    let masked = MASKS
        .iter()
        .fold(text.to_string(), |t, mask| t.replace(mask, " "));
    let lower = masked.to_ascii_lowercase();
    let tokens: Vec<&str> = lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect();
    vocab
        .words
        .iter()
        .filter(|w| {
            if prose && vocab.ordinary.contains(*w) {
                lower.trim() == w.as_str()
                    || bounded(&lower, w)
                        .into_iter()
                        .any(|at| selected(&lower, at))
            } else if w.contains('-') {
                !bounded(&lower, w).is_empty() || !bounded(&lower, &w.replace('-', "_")).is_empty()
            } else {
                tokens.contains(&w.as_str())
            }
        })
        .cloned()
        .collect()
}

pub fn scan(cx: &Ctx) -> (Vec<Finding>, Vec<String>) {
    let mut findings = Vec::new();
    let mut errors = Vec::new();
    let vocab = match vocabulary(cx) {
        Ok(v) => v,
        Err(e) => return (findings, vec![e]),
    };
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
            for w in words_in(&vocab, feature, false) {
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
                    for w in words_in(&vocab, &lit, true) {
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
        // A plugin the registry gains is a word the kernel may not spell, with no edit here: the
        // vocabulary is the registry's, never a hand copy of it (BUSBAR-1.6.0.md l.2068-2069).
        let registered = {
            let reg = cx.read("plugins.yaml").unwrap_or_default();
            let reg = reg.replacen(
                "\nplugins:\n",
                "\nplugins:\n  - repo: busbar-store-zephyrdb\n    kind: store\n    alias: zephyrdb\n    \
                 crate: busbar-store-zephyrdb-plugin\n    version_line: \"1.0\"\n    service: none\n    \
                 release_gate: optional\n    gate: suite\n    description: \"planted\"\n    \
                 declares: \"store-zephyrdb/declares.json\"\n",
                1,
            );
            let mut ov = Overlay::new();
            ov.set("plugins.yaml", reg);
            ov.set(file, "pub const PLANTED: &str = \"zephyrdb\";\n");
            ov
        };
        // A registered auth plugin's name in a style the kernel spells (providers.rs's serde rename).
        let mut style = Overlay::new();
        style.set(
            file,
            "pub const PLANTED: &str = \"oauth-client-credentials\";\n",
        );
        // A registered instance whose name is an ordinary word, named as the instance a config
        // selects (`module: <name>`), is RED.
        let mut selected = Overlay::new();
        selected.set(
            file,
            "pub const PLANTED: &str = \"set secret.module: env\";\n",
        );
        let mut bare = Overlay::new();
        bare.set(file, "pub const PLANTED: &str = \"memory\";\n");
        // The same ordinary words in prose, and a one-letter instance name, are not an instance.
        let mut prose = Overlay::new();
        prose.set(
            file,
            "pub const A: &str = \"cannot read config file {}: {e}\";\n\
             pub const B: &str = \"the frame's header does not match\";\n\
             pub const C: &str = \"offset beyond memory\";\n\
             pub const D: &str = \"conformance.json: transport.carrier.dial.env: {e}\";\n\
             pub const E: &str = \"routing decisions are logged\";\n\
             pub const F: &str = \"class {c}\";\n\
             pub const G: &str = \"C\";\n",
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
                (
                    ROW_LITERAL,
                    "a kernel literal naming an instance plugins.yaml gains is RED (the vocabulary is the registry's)",
                    registered,
                    vec![file, "zephyrdb"],
                ),
                (
                    ROW_LITERAL,
                    "a kernel literal naming a registered auth plugin (`oauth`) is RED",
                    style,
                    vec![file, "oauth"],
                ),
                (
                    ROW_LITERAL,
                    "an ordinary-word instance a config selects (`module: env`) is RED",
                    selected,
                    vec![file, "env"],
                ),
                (
                    ROW_LITERAL,
                    "an ordinary-word instance spelled as the whole literal (`\"memory\"`) is RED",
                    bare,
                    vec![file, "memory"],
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
        report.push(crate::gates::prove_rows_green(
            cx,
            self,
            "an ordinary word in prose, and a one-letter name, is not an instance",
            &[ROW_LITERAL],
            prose,
        ));
        report
    }
}
