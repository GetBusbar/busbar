//! `cargo xtask gate instance-noun-neutrality` — THE WHOLE-APP KIND-NEUTRALITY WITNESS.
//!
//! THE OWNER'S RULE, RATIFIED. A concrete plugin-INSTANCE noun may appear ONLY inside its own
//! plugin crate family. Nothing else in the entire application — not the composition root, not a
//! sibling plugin, not a shared crate, not core, not the substrate — is allowed to KNOW a concrete
//! instance. This is the single enforceable witness for DECISION #1 (core names zero plane/plugin
//! types), DECISION #8 (the broker law: plugins never talk to each other), and DECISION #18
//! (streaming is the plane; voice is a dialect inside it) and DECISION #48 (the plane roster is
//! FIVE — llm, mcp, a2a, streaming, decisions(jev) — so all five instance nouns are censused).
//! It generalises `plane-abi-neutrality`
//! (hot lane only) and `plane-transport-neutrality` (neutral crates only) to EVERY crate and EVERY
//! one of the seven plugin kinds: plane, transport, store, auth, secret, hook, export.
//!
//! THE MENTAL MODEL THAT MAKES TESTS FIRST-CLASS. Every plugin is written by a third-party team;
//! we build only the kernel. A plugin tests itself; the kernel never tests or names a plugin. So a
//! concrete instance noun in a NON-family crate is a leak whether it sits in production code or in
//! a test module — the ban is enforced identically over both. Comments are the one thing NOT
//! scanned: a doc comment discussing the architecture legitimately names `mcp`, and so does this
//! very file. The scan strips comments (line and block, string literals preserved) and judges the
//! code that remains, test code included.
//!
//! ## WHY A NOUN IS EITHER A PRECISE TOKEN OR NOT SCANNED AT ALL
//!
//! A census that over-flags is noise nobody reads. Every noun below is matched two ways and only
//! two: as a WORD (case-insensitive, with `_` as a boundary, so `mcp_codec` and `handle_mcp` both
//! hit but `rustls` does not hit `tls` and `assess` does not hit `sse`), and as a CamelCase segment
//! (`McpTransport`, `SdpOffer`). Nouns whose bare 2–3 char form is hopelessly ambiguous are matched
//! ONLY on an unambiguous identifier (never bare `aws`; the example/test plugins on their
//! full crate identifier), never on a raw substring. The result is a census of REAL couplings.
//!
//! ## THE BASELINE IS A BURNDOWN LEDGER, NOT AN EXCUSE
//!
//! Real leaks exist today (the composition root names its planes; auth schemes are DECISION #3
//! internal units and leak heavily into core; sibling planes reference one another). The gate is
//! therefore RED today, ON PURPOSE. `qa/instance-noun-neutrality.toml` records EACH current leak as
//! a `[[leak]]` row with its category and owning wave, so the red is a documented burndown rather
//! than a wall of noise. Two rows keep the ledger honest: `:undocumented` reds on any live leak the
//! baseline does not name (this is what bites a NEW coupling), and `:stale-baseline` reds on any
//! baseline row whose leak is gone (so the ledger cannot outlive the debt it tracked). The gate
//! goes GREEN only when the baseline is empty — i.e. when the app knows no concrete instance
//! outside its family.
//!
//! ## FROZEN TEXT IS MARKED, NEVER ALLOW-LISTED BY FILE
//!
//! A noun inside frozen customer- or operator-visible text (a diagnostics catalog entry, an error
//! string) cannot be drained without changing what a customer sees. Such a literal carries
//! `// noun-neutrality: frozen-literal pinned-by=<drift test or rendered doc> <reason>` — the same
//! per-line, reasoned shape as plane-purity-strict's frozen-wire pragma. It exempts the LITERAL
//! only (never an identifier on the line), it is refused unless the cited file exists and contains
//! the literal, and the pragma count is ratcheted by `[pragma_ceiling] frozen_literal` in the
//! ledger, so it can only fall. See the `exempt` module. `:frozen-literal` reds a refused marker;
//! `:pragma-ceiling` reds a count that moved off its ceiling in either direction.
//!
//! Move the ledger DOWN with `cargo xtask gate instance-noun-neutrality --write`: it lowers every
//! row that fell and strikes every row that drained, and it REFUSES WHOLESALE — nothing written —
//! if any row would be added or would rise, unless the ledger carries an owner-cited
//! `[[allow_rise]]` for exactly that row (see the `write` module). A baseline never absorbs a rise.
//! The older `XTASK_INSN_EMIT_BASELINE=1` emitter prints the same derivation (and, on a refusal, the
//! committed ledger unchanged), so neither door can raise a row.

use std::collections::BTreeMap;

use crate::ctx::{Ctx, Overlay, WalkSpec};
use crate::gates::{execute, prove_rows_red_at, Case, Expect, Gate, Report};
use crate::ledger::{Row, Status, Verdict};
use crate::scan::strip_comment_line;

mod cases;
mod exempt;
mod write;

pub use write::ROW_WRITE;

pub const BASELINE: &str = "qa/instance-noun-neutrality.toml";
const CROSS_ROW: &str = "instance-noun-neutrality";

pub fn row_id(key: &str) -> String {
    format!("{CROSS_ROW}:{key}")
}
pub const ROW_SCAN_FLOOR: &str = "instance-noun-neutrality:scan-floor";
pub const ROW_UNDOCUMENTED: &str = "instance-noun-neutrality:undocumented";
pub const ROW_STALE: &str = "instance-noun-neutrality:stale-baseline";
/// THE ZERO-MATCH REFUSAL. A baseline row whose `file` is not a Rust file the census scanned — a
/// path that was deleted, renamed, or split into a DIRECTORY (`engine_kit.rs` -> `engine_kit/`) —
/// names nothing the gate can measure, so it can only ever read as "zero leaks here". That is a
/// false zero inside the census, and this row refuses it BY PATH, distinct from `:stale-baseline`
/// (a real file whose leak is gone). A row missing its `noun` or `file` key is the same false zero
/// (it used to be dropped silently) and is refused here too.
pub const ROW_DEAD_PATH: &str = "instance-noun-neutrality:dead-path";
/// Every `frozen-literal` pragma is reasoned, literal-only and pinned (see the `exempt` module).
pub const ROW_FROZEN_LITERAL: &str = "instance-noun-neutrality:frozen-literal";
/// THE RATCHET: the live pragma count equals `[pragma_ceiling] frozen_literal` in the ledger. A count
/// above the ceiling is a new exemption nobody armed; a count below it is slack the ledger must give
/// back — so the number can only fall.
pub const ROW_PRAGMA_CEILING: &str = "instance-noun-neutrality:pragma-ceiling";

/// THE NEEDLE every per-noun census row carries. `--all` excuses this gate's standing red only when
/// every red row names it (see the REPORT_ONLY posture); the `:undocumented` and `:stale-baseline`
/// rows deliberately DO NOT carry it, so a new coupling or a stale ledger row scores under `--all`.
pub const TRACKED_NEEDLE: &str = "tracked known-debt";

/// One plugin-instance noun, its kind, the crate family that is allowed to name it, and the tokens
/// it is matched on. A crate is "in the family" when its directory name (`busbar-mcp`) is listed.
struct Noun {
    key: &'static str,
    kind: &'static str,
    /// Crate directory names under `crates/` that MAY name this instance. Empty = the backend has
    /// no crate in this tree yet, so ANY reference to it is premature coupling.
    family: &'static [&'static str],
    /// Word/CamelCase tokens. All are lowercase; the CamelCase rule capitalises the first letter.
    tokens: &'static [&'static str],
    /// EXACT CamelCase needles (`StreamingPlane`), matched by the CamelCase rule as written — for a
    /// plane type whose name is two words, which capitalising one token cannot spell.
    camel: &'static [&'static str],
    /// A plane's config SECTION key (`streams`), matched only where it IS the top-level section:
    /// `streams:` opening a literal, after an escaped `\n`, or at column 0 of a multi-line literal.
    /// The key must end its line (its value is a mapping block): an export sink's `streams: [logs]`
    /// projection list, indented or not, is a different key.
    section: Option<&'static str>,
}

// ── PLANES (DECISION #1 / #18 / #48) ──────────────────────────────────────────────────────────
const FAM_MCP: &[&str] = &["busbar-mcp", "busbar-plane-mcp"];
const FAM_A2A: &[&str] = &["busbar-a2a", "busbar-plane-a2a"];
const FAM_LLM: &[&str] = &["busbar-llm", "busbar-plane-llm", "busbar-llm-codec"];
// The streaming family. `busbar-streaming-codec` is named by the owner's map but does not exist in
// this tree; `busbar-plane-voice` was DELETED into `busbar-plane-streaming` (#18/#83 — one plane per
// protocol, and the plane is streaming). The family is what EXISTS.
const FAM_STREAM: &[&str] = &[
    "busbar-plane-streaming",
    "busbar-voice",
    "busbar-voice-codec",
];
// The FIFTH plane (DECISION #48, owner-locked: llm, mcp, a2a, streaming, decisions(jev)). Its one
// crate is `busbar-plane-decision`; #39 folds codecs and dialects INTO the plane crate, so there is
// no `busbar-decision-codec` for the family to list. The family is what EXISTS.
const FAM_DECISION: &[&str] = &["busbar-plane-decision"];

// ── TRANSPORTS (each concrete transport is its own crate, except the HTTP dialects) ────────────
// `sse` (an HTTP response body) and `grpc` (HTTP/2 framing) were FOLDED INTO
// `busbar-transport-http`: the crate that may name each
// instance is the one that holds it now.
const FAM_HTTP: &[&str] = &["busbar-transport-http"];
const FAM_WS: &[&str] = &["busbar-transport-ws"];
const FAM_STDIO: &[&str] = &["busbar-transport-stdio"];
const FAM_TCP: &[&str] = &["busbar-transport-tcp"];
const FAM_TLS: &[&str] = &["busbar-transport-tls"];
const FAM_SSE: &[&str] = &["busbar-transport-http"];
const FAM_GRPC: &[&str] = &["busbar-transport-http"];

// ── STORES (no backend crate exists in this tree — any reference is premature coupling) ────────
const FAM_NONE: &[&str] = &[];

// ── AUTH SCHEMES (DECISION #3: currently internal units, so heavy known-debt into core/units) ──
const FAM_AUTH: &[&str] = &["auth-static-plugin", "auth-admin-tokens", "busbar-oauth2"];

/// DOCUMENTED EXEMPTION for the `gcp` noun: these 2 files use "GCP" as the general
/// Google-Cloud-Platform term in cloud-metadata/SSRF security prose — `busbar-a2a`'s
/// `fetch_tests.rs` table entries `"AWS/GCP/Azure IMDS link-local"` / `"the GCP metadata NAME"`, and
/// `busbar-substrate-values`'s boot diagnostic warning that the metadata-SSRF guard covers
/// `"169.254.169.254, the GCP/Azure metadata hosts"` — never the name of a concrete `gcp`
/// auth-scheme plugin instance. This is exactly the vocabulary problem the header note above
/// already excludes bare `aws` for (broad infra, never an instance spelling);
/// `gcp` was never given the same treatment even though no code anywhere in this tree defines a
/// `"gcp"` scheme constant for either file to be leaking (checked: `auth-static-plugin`,
/// `auth-admin-tokens`, `busbar-oauth2` name nothing spelled `gcp`). Excluded by exact file, not by
/// loosening the token or dropping the noun — a real `gcp` auth scheme, when one lands, will get its
/// own unambiguous scheme spelling (a plugin crate identifier), and that spelling
/// (not bare `gcp`) is what should be tracked.
const GCP_GENERIC_MENTION_FILES: &[&str] = &[
    "crates/busbar-a2a/src/a2a/tests/fetch_tests.rs",
    "crates/busbar-substrate-values/src/diagnostics/mod.rs",
];

// ── HOOK / EXPORT (self-contained example/test plugins; matched on crate identity) ─────────────
// The SECRET kind has no crate in this tree: its in-tree fixture was deleted (owner, "FIXTURES":
// "real plugins are the examples") and it is proven by the real plugin repo GetBusbar/hashicorp-vault,
// so its noun below is censused like the stores — an empty family, every hit a leak.
const FAM_HOOK: &[&str] = &["hook-test-plugin"];
const FAM_EXPORT: &[&str] = &["export-example-plugin"];
// The two store-kind crates that DO exist in this tree, and the one in-tree hook plugin (item 197).
// Each is matched, like the example/test plugins above, on its own crate identifier.
const FAM_STORE_MEMORY: &[&str] = &["store-memory"];
const FAM_STORE_EXAMPLE: &[&str] = &["store-example-plugin"];
const FAM_HOOKS_RANKING: &[&str] = &["hooks-ranking"];

/// PROTOCOL VOCABULARY (owner rulings Q1, 2026-09-23 and Q76, 2026-09-25): wire/auth scheme words
/// every auth instance speaks, so they name no instance and are NEVER a noun token. The selftest
/// plants each into a core file and requires every census row to stay green.
const PROTOCOL_VOCABULARY: &[&str] = &["bearer", "spki", "mtls", "sigv4"];

const NOUNS: &[Noun] = &[
    // Planes.
    Noun {
        key: "mcp",
        kind: "plane",
        family: FAM_MCP,
        tokens: &["mcp"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "a2a",
        kind: "plane",
        family: FAM_A2A,
        tokens: &["a2a"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "llm",
        kind: "plane",
        family: FAM_LLM,
        tokens: &["llm"],
        camel: &[],
        section: None,
    },
    // `streaming` — KEYED ON THE PLANE'S OWN SPELLINGS, NEVER ON THE BARE WORD. The plane is named
    // `streaming` (#18), but the word is also ordinary HTTP vocabulary: a streamed response, a
    // `stream: true` request, a "non-streaming" body, tonic's `Streaming<T>` and `Grpc::streaming`.
    // The bare word hit 74 files, and those are an adjective, not a coupling. What names the PLANE is
    // its crate/feature/module path (`busbar_plane_streaming`, `plane-streaming`, `plane_streaming`),
    // its types (`StreamingPlane…`, the `streams:` section's `StreamsSection`/`StreamsCfg`), and the
    // top-level `streams:` section key itself (#47). The spec's neutrality witness bans protocol
    // nouns from ABI, capability and carrier NAMES; these are those names.
    Noun {
        key: "streaming",
        kind: "plane",
        family: FAM_STREAM,
        tokens: &[
            "plane_streaming",
            "plane-streaming",
            "streaming_plane",
            "streaming-plane",
        ],
        camel: &[
            "StreamingPlane",
            "PlaneStreaming",
            "StreamsSection",
            "StreamsCfg",
        ],
        section: Some("streams"),
    },
    Noun {
        key: "voice",
        kind: "plane",
        family: FAM_STREAM,
        tokens: &["voice"],
        camel: &[],
        section: None,
    },
    // The `decisions` plane (#48) — KEYED ON `jev`, THE DIALECT IT SPEAKS, NEVER ON `decision`.
    // Both match rules here are name-shaped (`word_ci` treats `_` as a boundary; `camel_hit`
    // capitalises the first letter), so a `decision`/`decisions` token would hit `Decision`,
    // `GateDecision` and `VerifyDecision` — the admit/throttle/deny verdict types that ARE the
    // primitive governance taxonomy, measured at 514 occurrences across 53 files OUTSIDE this
    // plane, every one of them core naming its own verdict rather than a plane leaking. That is
    // precisely the hazard `plane_abi_neutrality::PRIMITIVE_COLLISION_KEYS` documents in writing
    // for this same plane key, and its resolution is the one taken here: do not loosen the match
    // rule, do not rename a correct primitive to dodge a grep — spell the INSTANCE the way only
    // the instance is spelled. `jev` (the typesafe.ai decision API, #41/#47) is that spelling and
    // is unambiguous anywhere in the tree. A token that floods is a gate nobody reads.
    Noun {
        key: "jev",
        kind: "plane",
        family: FAM_DECISION,
        tokens: &["jev"],
        camel: &[],
        section: None,
    },
    // Transports — KEYED ON THE PLUGIN-INSTANCE IDENTIFIER, NOT THE BARE PROTOCOL WORD. Bare
    // `http`/`tcp`/`tls`/… are the wire protocols and the `http` crate's own types, used as neutral
    // plumbing across nearly every crate (URL schemes, `http::HeaderMap`, OTLP endpoints); censusing
    // those is noise, not plugin-instance coupling. What #1/#8 forbid is a crate reaching for the
    // concrete transport PLUGIN, which reads `busbar_transport_http` / `transport_http` /
    // `transport-http` (the crate, module and feature spellings). Those are what the census tracks.
    Noun {
        key: "http",
        kind: "transport",
        family: FAM_HTTP,
        tokens: &["busbar_transport_http", "transport_http", "transport-http"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "ws",
        kind: "transport",
        family: FAM_WS,
        tokens: &["busbar_transport_ws", "transport_ws", "transport-ws"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "stdio",
        kind: "transport",
        family: FAM_STDIO,
        tokens: &[
            "busbar_transport_stdio",
            "transport_stdio",
            "transport-stdio",
        ],
        camel: &[],
        section: None,
    },
    Noun {
        key: "tcp",
        kind: "transport",
        family: FAM_TCP,
        tokens: &["busbar_transport_tcp", "transport_tcp", "transport-tcp"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "tls",
        kind: "transport",
        family: FAM_TLS,
        tokens: &["busbar_transport_tls", "transport_tls", "transport-tls"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "sse",
        kind: "transport",
        family: FAM_SSE,
        tokens: &["busbar_transport_sse", "transport_sse", "transport-sse"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "grpc",
        kind: "transport",
        family: FAM_GRPC,
        tokens: &["busbar_transport_grpc", "transport_grpc", "transport-grpc"],
        camel: &[],
        section: None,
    },
    // Stores — no backend crate in this tree, so the family is empty and every hit is a leak.
    Noun {
        key: "postgres",
        kind: "store",
        family: FAM_NONE,
        tokens: &["postgres"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "mysql",
        kind: "store",
        family: FAM_NONE,
        tokens: &["mysql"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "valkey",
        kind: "store",
        family: FAM_NONE,
        tokens: &["valkey", "redis"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "sqlite",
        kind: "store",
        family: FAM_NONE,
        tokens: &["sqlite"],
        camel: &[],
        section: None,
    },
    // Stores that DO have a crate (item 197). The four above are censused on backends with no crate
    // here; these two ARE the store kind's in-tree instances, and until this row they had no Noun
    // at all, so the kind's real instance vocabulary was unpoliced. Matched on the crate identifier
    // (bare `memory` is a core word; the example plugin's name is its only unambiguous spelling).
    Noun {
        key: "memory",
        kind: "store",
        family: FAM_STORE_MEMORY,
        tokens: &["busbar_store_memory"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "store",
        kind: "store",
        family: FAM_STORE_EXAMPLE,
        tokens: &["busbar_store_example_plugin"],
        camel: &[],
        section: None,
    },
    // Auth schemes — matched on the unambiguous scheme name only.
    //
    // `bearer`, `mtls`, `spki` AND `sigv4` ARE NOT HERE, AND THAT IS A RULING, NOT AN OMISSION.
    // They are standards, not plugin instances: `Bearer` is the RFC 6750 HTTP authentication scheme
    // every OAuth 2.0 client and server speaks, mutual TLS is the RFC 8705 client-certificate
    // binding, an SPKI pin is the RFC 7469 public-key fingerprint, and SigV4 is AWS's published
    // request-signing wire scheme. An auth plugin INSTANCE is a crate (`auth-static-plugin`, an
    // `auth-github`); a word every one of them speaks names none of them. BUSBAR-1.6.0.md "Owner
    // rulings — 2026-09-23", Q1: "Auth vocabulary (`bearer`, `spki`, `mtls`) is protocol
    // vocabulary, not an instance noun … The neutrality gate exempts the three." 1.6.0-QUESTIONS.md
    // OWNER ANSWERS 2026-09-25, Q76: "SigV4 is PROTOCOL VOCABULARY (joins bearer/spki/mtls; the gate
    // stops counting it)." The words are listed in [`PROTOCOL_VOCABULARY`]; no noun may match one.
    Noun {
        key: "gcp",
        kind: "auth",
        family: FAM_AUTH,
        tokens: &["gcp"],
        camel: &[],
        section: None,
    },
    // Secret / hook / export — bare `secret`/`hook`/`export` are core subsystems (secret-ref,
    // busbar-core-hooks, export verbs), so the ENFORCEABLE instance token is the plugin's own crate
    // identifier. Zero false positives; reds only if core names the plugin. The secret kind's
    // instance is the real plugin repo's crate (`busbar-hashicorp-vault`), which has no crate here.
    Noun {
        key: "vault",
        kind: "secret",
        family: FAM_NONE,
        tokens: &["hashicorp_vault"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "hook",
        kind: "hook",
        family: FAM_HOOK,
        tokens: &["hook_test_plugin"],
        camel: &[],
        section: None,
    },
    // The hook kind's one in-tree instance (item 197), on its crate identifier.
    Noun {
        key: "ranking",
        kind: "hook",
        family: FAM_HOOKS_RANKING,
        tokens: &["busbar_hooks_ranking"],
        camel: &[],
        section: None,
    },
    Noun {
        key: "export",
        kind: "export",
        family: FAM_EXPORT,
        tokens: &["export_example_plugin"],
        camel: &[],
        section: None,
    },
];

const CLEAN: &str = "the scan cleared its floors and named nothing";
const DID_NOT_RUN: &str = "nothing was read, and nothing read is not a neutral app";

/// One live leak: an instance noun named in a crate outside its family.
#[derive(Clone)]
struct Leak {
    noun: &'static str,
    kind: &'static str,
    file: String,
    count: usize,
    category: &'static str,
    wave: &'static str,
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
}

/// A whole-word, case-insensitive hit of a lowercase needle where the identifier boundary is
/// `[^a-z0-9]` — SO `_` IS A BOUNDARY. `handle_mcp` and `mcp_codec` hit; `rustls`, `assess`,
/// `settles`, `rows`, `throws` do not.
fn word_ci(lower: &str, needle: &str) -> bool {
    let hay: Vec<char> = lower.chars().collect();
    let n: Vec<char> = needle.chars().collect();
    if n.is_empty() || n.len() > hay.len() {
        return false;
    }
    for i in 0..=(hay.len() - n.len()) {
        if hay[i..i + n.len()] != n[..] {
            continue;
        }
        let before_ok = i == 0 || !is_word_char(hay[i - 1]);
        let after_ok = i + n.len() == hay.len() || !is_word_char(hay[i + n.len()]);
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// A Capitalized needle followed by an uppercase letter, a non-identifier character, or end of
/// line: `McpTransport`, `WsFrame`, a bare `Sdp`.
fn camel_hit(code: &str, needle: &str) -> bool {
    let chars: Vec<char> = code.chars().collect();
    let mut cap: Vec<char> = needle.chars().collect();
    if cap.is_empty() {
        return false;
    }
    cap[0] = cap[0].to_ascii_uppercase();
    if cap.len() > chars.len() {
        return false;
    }
    for i in 0..=(chars.len() - cap.len()) {
        if chars[i..i + cap.len()] != cap[..] {
            continue;
        }
        // The char BEFORE must not be a lowercase letter or digit — otherwise this is the tail of
        // a longer word (`deepMcp` is not a leak of `mcp`; `DeepMcp` is caught by the word rule via
        // its lowercased form only if `mcp` is boundary-clean, which it is not here — the word rule
        // and this rule are deliberately complementary, not identical).
        let before_ok = i == 0 || !chars[i - 1].is_ascii_lowercase();
        if !before_ok {
            continue;
        }
        match chars.get(i + cap.len()) {
            None => return true,
            Some(c) if c.is_ascii_uppercase() => return true,
            Some(c) if !c.is_ascii_alphanumeric() => return true,
            _ => {}
        }
    }
    false
}

/// An EXACT CamelCase needle, with [`camel_hit`]'s boundaries: not the tail of a lowercase word, and
/// followed by an uppercase letter, a non-identifier character, or end of line.
fn camel_exact_spans(chars: &[char], needle: &str) -> Vec<(usize, usize)> {
    let n: Vec<char> = needle.chars().collect();
    let mut out = Vec::new();
    if n.is_empty() || n.len() > chars.len() {
        return out;
    }
    for i in 0..=(chars.len() - n.len()) {
        if chars[i..i + n.len()] != n[..] {
            continue;
        }
        if i > 0 && chars[i - 1].is_ascii_lowercase() {
            continue;
        }
        match chars.get(i + n.len()) {
            None => out.push((i, i + n.len())),
            Some(c) if c.is_ascii_uppercase() || !c.is_ascii_alphanumeric() => {
                out.push((i, i + n.len()))
            }
            _ => {}
        }
    }
    out
}

/// A plane's top-level config section key, ending its line: `<key>:` opening a literal, after an
/// escaped newline (`\nstreams:`), or at column 0 (a multi-line literal's own line).
fn section_spans(chars: &[char], key: &str) -> Vec<(usize, usize)> {
    let n: Vec<char> = format!("{key}:").chars().collect();
    let mut out = Vec::new();
    if n.len() > chars.len() {
        return out;
    }
    for i in 0..=(chars.len() - n.len()) {
        if chars[i..i + n.len()] != n[..] {
            continue;
        }
        let top = i == 0
            || chars[i - 1] == '"'
            || (i >= 2 && chars[i - 2] == '\\' && chars[i - 1] == 'n');
        // A plane section's value is a MAPPING block, so the key ends its line; an export sink's
        // `streams: [logs]` projection list carries its value inline and is a different key.
        let rest = &chars[i + n.len()..];
        let block = rest.iter().all(|c| c.is_whitespace())
            || rest.first() == Some(&'"')
            || (rest.first() == Some(&'\\') && rest.get(1) == Some(&'n'));
        if top && block {
            out.push((i, i + n.len()));
        }
    }
    out
}

/// Every occurrence of `needle` [`word_ci`] would accept, as char spans over `lower`.
fn word_spans(lower: &[char], needle: &str) -> Vec<(usize, usize)> {
    let n: Vec<char> = needle.chars().collect();
    let mut out = Vec::new();
    if n.is_empty() || n.len() > lower.len() {
        return out;
    }
    for i in 0..=(lower.len() - n.len()) {
        if lower[i..i + n.len()] != n[..] {
            continue;
        }
        let before_ok = i == 0 || !is_word_char(lower[i - 1]);
        let after_ok = i + n.len() == lower.len() || !is_word_char(lower[i + n.len()]);
        if before_ok && after_ok {
            out.push((i, i + n.len()));
        }
    }
    out
}

/// Every occurrence of `needle` [`camel_hit`] would accept, as char spans over `chars`.
fn camel_spans(chars: &[char], needle: &str) -> Vec<(usize, usize)> {
    let mut cap: Vec<char> = needle.chars().collect();
    if cap.is_empty() {
        return Vec::new();
    }
    cap[0] = cap[0].to_ascii_uppercase();
    camel_exact_spans(chars, &cap.iter().collect::<String>())
}

/// The noun's occurrences on one line, as char spans. `orig` and `lower` MUST be char-aligned (an
/// ASCII lowercasing), which the pragma analysis guarantees; the census proper asks [`line_hits`].
fn noun_spans(orig: &[char], lower: &[char], noun: &Noun) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for t in noun.tokens {
        out.extend(word_spans(lower, t));
        out.extend(camel_spans(orig, t));
    }
    for c in noun.camel {
        out.extend(camel_exact_spans(orig, c));
    }
    if let Some(key) = noun.section {
        out.extend(section_spans(orig, key));
    }
    out.sort_unstable();
    out.dedup();
    out
}

fn line_hits(orig: &str, lower: &str, noun: &Noun) -> bool {
    noun.tokens
        .iter()
        .any(|t| word_ci(lower, t) || camel_hit(orig, t))
        || (!noun.camel.is_empty() || noun.section.is_some()) && {
            let chars: Vec<char> = orig.chars().collect();
            noun.camel
                .iter()
                .any(|c| !camel_exact_spans(&chars, c).is_empty())
                || noun
                    .section
                    .is_some_and(|k| !section_spans(&chars, k).is_empty())
        }
}

/// The crate directory name for a `crates/<name>/...` path, or `None` for anything else.
fn crate_of(rel: &str) -> Option<&str> {
    rel.strip_prefix("crates/")
        .and_then(|r| r.split('/').next())
}

/// Every crate that is SOME noun's family — used to tell a cross-plugin leak from a core one.
fn is_family_crate(krate: &str) -> bool {
    NOUNS.iter().any(|n| n.family.contains(&krate))
}

/// Category + owning wave for a leak, from the crate it landed in. Cross-plugin is checked first: a
/// plane naming another plane is the broker-law violation, wherever the crate otherwise sorts.
fn categorize(krate: &str, file: &str) -> (&'static str, &'static str) {
    if is_family_crate(krate) {
        return (
            "cross-plugin",
            "cross-plugin cleanup — broker law #8 (plugins never name each other)",
        );
    }
    if krate == "busbar" || file.contains("/bin/") {
        return (
            "composition-root",
            "keystone / composition-root — register_planes both-ways self-registration",
        );
    }
    match krate {
        "busbar-substrate" | "busbar-substrate-values" => (
            "substrate",
            "substrate neutralization — opaque PlaneRecord across the ABI, never an instance noun",
        ),
        "api" | "busbar-contract" | "busbar-contract-transport" | "busbar-caps"
        | "busbar-grammar" => (
            "shared-crate",
            "shared-crate neutralization — the ABI-side crates must compile with every plugin removed",
        ),
        _ => (
            "core",
            "core neutralization — DECISION #1 (core names no instance); auth schemes are DECISION #3 internal-unit debt",
        ),
    }
}

/// THE SCAN. Walks every `.rs` under `crates/`, strips comments (test code kept), and records one
/// entry per (noun, file) where a non-family crate names the noun. Also returns every path it
/// scanned, so a baseline row can be checked against what the census can actually measure.
/// The census's findings: the live leaks, every path it scanned, and every reviewed pragma it met
/// (honoured or refused) — see the `exempt` module.
struct Census {
    leaks: Vec<Leak>,
    scanned: std::collections::BTreeSet<String>,
    pragmas: Vec<exempt::Pragma>,
}

/// The nouns a file in `krate` at `rel` may not name.
fn counted_nouns<'n>(krate: &str, rel: &str) -> Vec<&'n Noun> {
    NOUNS
        .iter()
        .filter(|n| !n.family.contains(&krate))
        .filter(|n| !(n.key == "gcp" && GCP_GENERIC_MENTION_FILES.contains(&rel)))
        .collect()
}

fn census(cx: &Ctx) -> Result<Census, String> {
    let files = cx
        .walk(&WalkSpec::new(["crates"]).ext("rs").min_files(1))
        .map_err(|e| e.to_string())?;
    let mut leaks: Vec<Leak> = Vec::new();
    let mut pragmas: Vec<exempt::Pragma> = Vec::new();
    let mut scanned: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for f in &files {
        let rel = f.rel_str();
        scanned.insert(rel.to_string());
        let Some(krate) = crate_of(&rel) else {
            continue;
        };
        // Strip comments once; keep (original, lowercased) for the two match rules.
        let mut in_block = false;
        let lines: Vec<(String, String)> = f
            .text
            .lines()
            .map(|l| {
                let s = strip_comment_line(l, &mut in_block);
                let lower = s.to_lowercase();
                (s, lower)
            })
            .collect();
        let nouns = counted_nouns(krate, &rel);
        // THE PRAGMAS, only where a marker is spelled: every other file is judged exactly as before.
        let lexed = f
            .text
            .contains(exempt::MARKER)
            .then(|| exempt::lex(&f.text));
        let mut exempt_ids = std::collections::BTreeSet::new();
        if let Some(fl) = &lexed {
            let mut found = exempt::collect(&rel, fl);
            let spans = |idx: usize| {
                let (orig, lower) = fl.line(idx);
                nouns
                    .iter()
                    .flat_map(|n| noun_spans(orig, lower, n))
                    .collect::<Vec<_>>()
            };
            exempt::judge(cx, fl, &mut found, &spans);
            exempt_ids = exempt::exempt_literals(&found);
            pragmas.extend(found);
        }
        for noun in nouns {
            let count = lines
                .iter()
                .enumerate()
                .filter(|(_, (orig, lower))| line_hits(orig, lower, noun))
                .filter(|(idx, _)| match &lexed {
                    Some(fl) if !exempt_ids.is_empty() && *idx < fl.lines() => {
                        let (orig, lower) = fl.line(*idx);
                        !exempt::line_exempt(fl, *idx, &noun_spans(orig, lower, noun), &exempt_ids)
                    }
                    _ => true,
                })
                .count();
            if count == 0 {
                continue;
            }
            let (category, wave) = categorize(krate, &rel);
            leaks.push(Leak {
                noun: noun.key,
                kind: noun.kind,
                file: rel.clone(),
                count,
                category,
                wave,
            });
        }
    }
    leaks.sort_by(|a, b| (a.noun, &a.file).cmp(&(b.noun, &b.file)));
    Ok(Census {
        leaks,
        scanned,
        pragmas,
    })
}

/// One baseline `[[leak]]` row: its `(noun, file)` key and the `count` it recorded. A row with no
/// integer `count` records ZERO — it authorises no references at all, so any live count in that
/// file is growth. It is never read as "unbounded".
type BaselineRow = ((String, String), usize);

/// The baseline rows, plus the 1-based ordinal of every `[[leak]]` row that lacks a `noun` or a
/// `file` (such a row names nothing and is refused by `:dead-path`). The count is READ (item 198):
/// the ledger records one per row and nothing compared it, so a baselined file was an unbounded
/// growth zone.
fn baseline_keys(cx: &Ctx) -> (Vec<BaselineRow>, Vec<usize>) {
    let Ok(text) = cx.read(BASELINE) else {
        return (Vec::new(), Vec::new());
    };
    let Ok(doc) = crate::toml_doc::parse_str(&text) else {
        return (Vec::new(), Vec::new());
    };
    let mut keys = Vec::new();
    let mut malformed = Vec::new();
    for (i, t) in doc.array_of_tables("leak").into_iter().enumerate() {
        let count = t
            .int_of("count")
            .and_then(|c| usize::try_from(c).ok())
            .unwrap_or(0);
        match (t.str_of("noun"), t.str_of("file")) {
            (Some(noun), Some(file)) => keys.push(((noun.to_string(), file.to_string()), count)),
            _ => malformed.push(i + 1),
        }
    }
    (keys, malformed)
}

fn leak_key(l: &Leak) -> (String, String) {
    (l.noun.to_string(), l.file.clone())
}

/// The live leaks the baseline does not cover: a `(noun, file)` pair it does not name, OR a pair it
/// names whose live count EXCEEDS the recorded count (item 198). The ledger is a burndown: a count
/// may fall without an edit, but a baselined file may not quietly take on more coupling.
fn undocumented_leaks(leaks: &[Leak], baseline: &[BaselineRow]) -> Vec<String> {
    let mut out: Vec<String> = leaks
        .iter()
        .filter_map(|l| {
            let key = leak_key(l);
            match baseline.iter().find(|(k, _)| *k == key) {
                None => Some(format!("{}@{}", l.noun, l.file)),
                Some((_, recorded)) if l.count > *recorded => {
                    Some(format!("{}@{} grew {recorded}→{}", l.noun, l.file, l.count))
                }
                Some(_) => None,
            }
        })
        .collect();
    out.sort();
    out
}

/// The validity row: every marker honoured, or the refused ones named with every reason.
fn pragma_row(pragmas: &[exempt::Pragma]) -> Row {
    let refused: Vec<String> = pragmas
        .iter()
        .filter(|p| !p.honoured())
        .map(|p| format!("{} — {}", p.site(), p.problems.join("; ")))
        .collect();
    if refused.is_empty() {
        let listing: Vec<String> = pragmas
            .iter()
            .map(|p| {
                format!(
                    "{} ({} — {})",
                    p.site(),
                    p.cite.as_deref().unwrap_or(""),
                    p.reason
                )
            })
            .collect();
        Row::pass(
            ROW_FROZEN_LITERAL,
            "every frozen-literal pragma is reasoned, literal-only and pinned",
            format!(
                "{} pragma(s) honoured: {}",
                pragmas.len(),
                listing.join(" ")
            ),
        )
    } else {
        Row::fail(
            ROW_FROZEN_LITERAL,
            "a frozen-literal pragma is refused — it exempts nothing",
            format!(
                "{} of {} pragma(s) refused: {}",
                refused.len(),
                pragmas.len(),
                refused.join(" | ")
            ),
        )
    }
}

/// THE RATCHET ROW: the live pragma count against its ledger ceiling, exactly.
fn ceiling_row(ceiling: &Result<usize, String>, live: usize) -> Row {
    let key = exempt::CEILING_KEY;
    let bad = match ceiling {
        Ok(c) if live == *c => None,
        Ok(c) if live > *c => Some(format!(
            "{key} ROSE: {live} > ceiling {c} — a new exemption nobody armed"
        )),
        Ok(c) => Some(format!(
            "{key} fell to {live} under ceiling {c} — lower `[pragma_ceiling] {key} = {live}` in \
             {BASELINE} so it cannot climb back"
        )),
        Err(raw) => Some(format!(
            "{key} ceiling `{raw}` is not a bare non-negative integer — an uncomparable ceiling \
             enforces nothing"
        )),
    };
    match bad {
        None => Row::pass(
            ROW_PRAGMA_CEILING,
            "the frozen-literal pragma count sits exactly at its ledger ceiling",
            format!("{key} {live} == ceiling {live}"),
        ),
        Some(why) => Row::fail(
            ROW_PRAGMA_CEILING,
            "the frozen-literal pragma count moved off its ledger ceiling",
            why,
        ),
    }
}

/// The gate, and its `--write` construction. The write arm is a SEPARATE construction rather than
/// a flag read off the context inside `run`, so `owed` — which the reconciliation is written
/// against — can say what this run emits: one row, the ledger edit's own.
pub struct InstanceNounNeutralityGate {
    write: bool,
}

impl InstanceNounNeutralityGate {
    /// The judging gate.
    pub fn check() -> InstanceNounNeutralityGate {
        InstanceNounNeutralityGate { write: false }
    }

    /// `--write`: lower and strike ledger rows to the measurement; a row that would be added or
    /// would rise without an owner-cited `[[allow_rise]]` is refused — left as committed, named,
    /// and the arm exits nonzero (see the `write` module).
    pub fn write() -> InstanceNounNeutralityGate {
        InstanceNounNeutralityGate { write: true }
    }
}

impl Gate for InstanceNounNeutralityGate {
    fn name(&self) -> &'static str {
        "instance-noun-neutrality"
    }

    /// `write` DOES NOT SHOW IN THE NAME and it changes both the owed set and the verdict, so the
    /// baseline cache must be told about it or one arm would be handed the other's clean run.
    fn baseline_key(&self) -> Option<String> {
        Some(format!("{}:write={}", self.name(), self.write))
    }

    fn owed(&self) -> Vec<String> {
        if self.write {
            return vec![ROW_WRITE.to_string()];
        }
        let mut ids: Vec<String> = NOUNS.iter().map(|n| row_id(n.key)).collect();
        ids.push(ROW_SCAN_FLOOR.to_string());
        ids.push(ROW_UNDOCUMENTED.to_string());
        ids.push(ROW_STALE.to_string());
        ids.push(ROW_DEAD_PATH.to_string());
        ids.push(ROW_FROZEN_LITERAL.to_string());
        ids.push(ROW_PRAGMA_CEILING.to_string());
        ids
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        if self.write {
            return Verdict::of(vec![write::rule_write(cx)]);
        }
        let census = match census(cx) {
            Ok(c) => c,
            Err(e) => {
                let mut rows = vec![Row::fail(
                    ROW_SCAN_FLOOR,
                    "the crates tree could not be scanned",
                    format!("{e} — {DID_NOT_RUN}"),
                )];
                for n in NOUNS {
                    rows.push(Row::fail(
                        row_id(n.key),
                        "the scan did not run",
                        DID_NOT_RUN,
                    ));
                }
                rows.push(Row::fail(
                    ROW_UNDOCUMENTED,
                    "the scan did not run",
                    DID_NOT_RUN,
                ));
                rows.push(Row::fail(ROW_STALE, "the scan did not run", DID_NOT_RUN));
                for id in [ROW_DEAD_PATH, ROW_FROZEN_LITERAL, ROW_PRAGMA_CEILING] {
                    rows.push(Row::fail(id, "the scan did not run", DID_NOT_RUN));
                }
                return Verdict::of(rows);
            }
        };
        let Census {
            leaks,
            scanned,
            pragmas,
        } = census;
        let ceiling = exempt::ceiling(cx.read(BASELINE).ok().as_deref());

        // The baseline-regeneration affordance: print the ledger `--write` would write and keep
        // going, so the ordinary verdict still prints too. It is the SAME derivation as `--write`
        // (see the `write` module), so it can only lower a row or strike one: a row that would be
        // added or would rise is left as committed, and the `:undocumented` row below names it.
        if std::env::var("XTASK_INSN_EMIT_BASELINE").as_deref() == Ok("1") {
            let committed = cx.read(BASELINE).unwrap_or_default();
            eprint!("{}", write::derive(&committed, &leaks, pragmas.len()).text);
        }

        let (baseline, malformed) = baseline_keys(cx);
        let mut rows = Vec::new();

        rows.push(Row::pass(
            ROW_SCAN_FLOOR,
            "the crates tree was scanned",
            CLEAN,
        ));

        // Per-noun census rows.
        let mut by_noun: BTreeMap<&str, Vec<&Leak>> = BTreeMap::new();
        for l in &leaks {
            by_noun.entry(l.noun).or_default().push(l);
        }
        for n in NOUNS {
            let fam = n.family.join(", ");
            let fam = if fam.is_empty() {
                "(no crate in this tree)".to_string()
            } else {
                fam
            };
            match by_noun.get(n.key) {
                None => rows.push(Row::pass(
                    row_id(n.key),
                    format!("no crate outside the {} family names `{}`", n.kind, n.key),
                    CLEAN,
                )),
                Some(hits) => {
                    let listing: Vec<String> = hits
                        .iter()
                        .map(|l| format!("{}×{} [{}]", l.file, l.count, l.category))
                        .collect();
                    rows.push(Row::fail(
                        row_id(n.key),
                        format!(
                            "`{}` ({}) is named in {} file(s) outside its family [{fam}]",
                            n.key,
                            n.kind,
                            hits.len()
                        ),
                        format!(
                            "{TRACKED_NEEDLE} census — {}: {}",
                            hits.len(),
                            listing.join(" | ")
                        ),
                    ));
                }
            }
        }

        // Undocumented: a live leak the baseline does not name. This is what bites a NEW coupling.
        let undocumented = undocumented_leaks(&leaks, &baseline);
        rows.push(if undocumented.is_empty() {
            Row::pass(
                ROW_UNDOCUMENTED,
                "every live leak is recorded in the baseline burndown",
                CLEAN,
            )
        } else {
            Row::fail(
                ROW_UNDOCUMENTED,
                "a live instance-noun leak is NOT in the baseline, or outgrew its baselined count",
                format!(
                    "{} undocumented leak(s): {} — a NEW cross-family coupling landed. Neutralize \
                     it, or (if it is genuine debt) record it in {BASELINE} with its owning wave.",
                    undocumented.len(),
                    undocumented.join(", ")
                ),
            )
        });

        // Stale: a baseline row whose leak is gone. The ledger cannot outlive the debt it tracked.
        let live: std::collections::BTreeSet<(String, String)> =
            leaks.iter().map(leak_key).collect();
        let mut stale: Vec<String> = baseline
            .iter()
            .map(|(k, _)| k)
            .filter(|k| !live.contains(*k))
            .map(|(n, f)| format!("{n}@{f}"))
            .collect();
        stale.sort();
        rows.push(if stale.is_empty() {
            Row::pass(
                ROW_STALE,
                "every baseline row still names a live leak",
                CLEAN,
            )
        } else {
            Row::fail(
                ROW_STALE,
                "a baseline row no longer names a live leak",
                format!(
                    "{} stale row(s): {} — the coupling is gone; strike the row from {BASELINE} in \
                     the same commit that neutralized it.",
                    stale.len(),
                    stale.join(", ")
                ),
            )
        });

        // Dead path: a baseline row whose file the census did not scan (gone, renamed, a directory,
        // not Rust, outside `crates/`) — or a row with no file at all. It measures nothing, so it
        // can only read as a zero; refuse it by path rather than let it sit in the ledger.
        let mut dead: Vec<String> = baseline
            .iter()
            .map(|(k, _)| k)
            .filter(|(_, f)| !scanned.contains(f))
            .map(|(n, f)| format!("{n}@{f}"))
            .collect();
        dead.sort();
        dead.extend(
            malformed
                .iter()
                .map(|i| format!("[[leak]] #{i} has no `noun` or no `file`")),
        );
        rows.push(if dead.is_empty() {
            Row::pass(
                ROW_DEAD_PATH,
                "every baseline row names a Rust file the census scanned",
                CLEAN,
            )
        } else {
            Row::fail(
                ROW_DEAD_PATH,
                "a baseline row names a path the census cannot scan",
                format!(
                    "{} zero-match row(s): {} — the path matches no scanned `.rs` file (deleted, \
                     renamed, or now a directory), so the row can only ever measure zero. Repoint it \
                     at the file(s) that now hold the code, or strike it, in {BASELINE}.",
                    dead.len(),
                    dead.join(", ")
                ),
            )
        });

        rows.push(pragma_row(&pragmas));
        rows.push(ceiling_row(&ceiling, pragmas.len()));

        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();

        // THE WRITE ARM PROVES ITS REFUSALS, which are exactly the paths that write nothing (a
        // battery that let the lowering path edit the ledger it is proving would make itself pass;
        // the lowering is proved by the `write` module's unit tests instead). The same cases run in
        // the judging battery, so a CI that never passes `--write` still proves the arm refuses.
        cases::push_write(cx, "xtask/fixtures/instance-noun", &mut report);
        if self.write {
            return report;
        }

        // THE SELF-TEST RUNS OVER TINY FIXTURE TREES, NOT THE 660k-LINE REPO. A census gate that
        // planted into the real workspace and re-scanned it per case measured 168 751 work units —
        // the exact "grew a whole-tree scan per plant" regression the budget exists to catch. The
        // fixtures carry the same shapes in two crates, so every proof below is a millisecond scan.
        //
        // `xtask/fixtures/instance-noun/` is: busbar-core (a NON-family crate) naming EVERY noun in
        // code, busbar-mcp (mcp's OWN family) naming mcp legitimately, and a baseline that names one
        // GHOST leak and none of the live ones. So over it: every per-noun row is RED (busbar-core),
        // the family file is NOT named (skip), `:undocumented` is RED (live leaks unrecorded), and
        // `:stale-baseline` is RED (the ghost). `xtask/fixtures/instance-noun-empty/` has a `crates/`
        // that holds no `.rs`, so `:scan-floor` refuses it.
        const FIX: &str = "xtask/fixtures/instance-noun";
        const FIX_EMPTY: &str = "xtask/fixtures/instance-noun-empty";

        // ONE RED CASE PER NOUN: the fixture's busbar-core names it, so its census row goes RED and
        // names that file. If a noun's matcher regressed, its row would be PASS and the case fail.
        for n in NOUNS {
            report.push(prove_rows_red_at(
                cx,
                self,
                format!(
                    "`{}` named by a non-family crate reds its census row",
                    n.key
                ),
                &[&row_id(n.key)],
                FIX,
                &["crates/busbar-core/src/lib.rs"],
            ));
        }

        // THE UNDOCUMENTED ROW: the fixture's live leaks are absent from its baseline.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a live leak absent from the baseline reds the undocumented row",
            &[ROW_UNDOCUMENTED],
            FIX,
            &["crates/busbar-core/src/lib.rs"],
        ));

        // THE STALE ROW: the fixture baseline names a ghost leak the tree does not have.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a baseline row with no live leak reds the stale row",
            &[ROW_STALE],
            FIX,
            &["ghost-nonexistent"],
        ));

        // THE SCAN FLOOR: a `crates/` that holds no Rust is refused, never scanned as zero leaks.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a crates tree holding no Rust reds the scan floor",
            &[ROW_SCAN_FLOOR],
            FIX_EMPTY,
            &["could not be scanned"],
        ));

        // THE DEAD-PATH ROW. The fixture baseline's ghost row names a file that does not exist.
        report.push(prove_rows_red_at(
            cx,
            self,
            "a baseline row naming a nonexistent file reds the dead-path row",
            &[ROW_DEAD_PATH],
            FIX,
            &["crates/ghost-nonexistent.rs"],
        ));

        // The item-113 shape exactly: a row naming a path that is now a DIRECTORY. Transition-proved
        // over the fixture: a baseline naming only the real file is GREEN on `:dead-path`; adding a
        // row whose `file` is the directory `crates/busbar-core/src` turns it RED, naming that path.
        const LIVE_ROW: &str =
            "[[leak]]\nnoun = \"mcp\"\nfile = \"crates/busbar-core/src/lib.rs\"\n\n";
        report.push(Case {
            name: "a baseline row naming a directory (zero files) reds the dead-path row"
                .to_string(),
            covers: vec![ROW_DEAD_PATH.to_string()],
            expected: Expect::Red {
                naming: vec!["mcp@crates/busbar-core/src".to_string()],
            },
            got: dead_path_transition(
                self,
                cx,
                FIX,
                LIVE_ROW,
                &format!("{LIVE_ROW}[[leak]]\nnoun = \"mcp\"\nfile = \"crates/busbar-core/src\"\n"),
            ),
        });

        // A row with no `file` key names nothing either; it used to be dropped silently.
        report.push(Case {
            name: "a baseline row missing its file key reds the dead-path row".to_string(),
            covers: vec![ROW_DEAD_PATH.to_string()],
            expected: Expect::Red {
                naming: vec!["[[leak]] #2 has no `noun` or no `file`".to_string()],
            },
            got: dead_path_transition(
                self,
                cx,
                FIX,
                LIVE_ROW,
                &format!("{LIVE_ROW}[[leak]]\nnoun = \"mcp\"\n"),
            ),
        });

        // GREEN CONTROL 1 — COMMENTS ARE NEVER A LEAK. Over the fixture, replace busbar-core with a
        // file whose only `mysql` is in comments: the mysql row goes GREEN, while the RED case above
        // proves the same word in code reds it — together, proof of the comment strip.
        let cx_c = cx.clone();
        report.push(Case {
            name: "a comment naming a store noun is not a leak".to_string(),
            covers: vec![row_id("mysql")],
            expected: Expect::Green,
            got: green_over_fixture(self, &cx_c, FIX, "mysql", |ov| {
                ov.set(
                    "crates/busbar-core/src/lib.rs",
                    "// a comment naming mysql is not a leak\n\
                     /* block comment: mysql again */\npub fn install() {}\n",
                );
            }),
        });

        // GREEN CONTROL 2 — THE FAMILY EXEMPTION IS NOT VACUOUS. The fixture already names mcp in
        // both busbar-core (leak) and busbar-mcp (family). Assert the mcp row names the core file and
        // NOT the family one; if `family.contains` regressed, the family file would appear.
        let cx_f = cx.clone();
        report.push(Case {
            name: "a token inside its own family crate is not a leak; outside it is".to_string(),
            covers: vec![row_id("mcp")],
            expected: Expect::Green,
            got: {
                match Ctx::at(cx_f.abs(FIX), cx_f.scratch().to_path_buf()) {
                    Err(_) => Expect::Skipped,
                    Ok(fcx) => {
                        let verdict = execute(self, &fcx);
                        let detail = verdict
                            .rows
                            .iter()
                            .find(|r| r.id == row_id("mcp"))
                            .map(|r| r.detail.clone())
                            .unwrap_or_default();
                        let names_core = detail.contains("busbar-core");
                        let names_family = detail.contains("busbar-mcp");
                        if names_core && !names_family {
                            Expect::Green
                        } else {
                            Expect::Red {
                                naming: vec![format!(
                                    "family-skip regressed: names_core={names_core} \
                                     names_family={names_family}"
                                )],
                            }
                        }
                    }
                }
            },
        });

        // THE FROZEN-LITERAL PRAGMA, ITS RATCHET, AND THE PRECISE `streaming` RULE — each a
        // GREEN->RED transition over the fixture (see `cases`).
        cases::push(self, cx, FIX, &mut report);

        report
    }
}

/// Run the gate over `fixture` with `plant` applied, and report GREEN iff `row_id(noun)` is not red.
fn green_over_fixture(
    gate: &InstanceNounNeutralityGate,
    cx: &Ctx,
    fixture: &str,
    noun: &str,
    plant: impl FnOnce(&mut Overlay),
) -> Expect {
    let Ok(fcx) = Ctx::at(cx.abs(fixture), cx.scratch().to_path_buf()) else {
        return Expect::Skipped;
    };
    let mut ov = Overlay::new();
    plant(&mut ov);
    let verdict = execute(gate, &fcx.with_overlay(ov));
    let red = verdict
        .rows
        .iter()
        .any(|r| r.id == row_id(noun) && r.status != Status::Pass);
    if red {
        Expect::Red {
            naming: vec![format!("`{noun}` went red on a comment-only mention")],
        }
    } else {
        Expect::Green
    }
}

/// A `:dead-path` TRANSITION over `fixture`: with `clean_baseline` the row must be GREEN (else the
/// case reports a red naming the broken control), and with `planted_baseline` the row's RED detail
/// is returned for the case to match its naming against.
fn dead_path_transition(
    gate: &InstanceNounNeutralityGate,
    cx: &Ctx,
    fixture: &str,
    clean_baseline: &str,
    planted_baseline: &str,
) -> Expect {
    let Ok(fcx) = Ctx::at(cx.abs(fixture), cx.scratch().to_path_buf()) else {
        return Expect::Skipped;
    };
    let dead_row = |baseline: &str| {
        let mut ov = Overlay::new();
        ov.set(BASELINE, baseline.to_string());
        let verdict = execute(gate, &fcx.with_overlay(ov));
        verdict
            .rows
            .iter()
            .find(|r| r.id == ROW_DEAD_PATH)
            .map(|r| (r.status != Status::Pass, r.detail.clone()))
    };
    match (dead_row(clean_baseline), dead_row(planted_baseline)) {
        (Some((false, _)), Some((true, detail))) => Expect::Red {
            naming: vec![detail],
        },
        (clean, planted) => Expect::Red {
            naming: vec![format!(
                "no GREEN->RED transition on {ROW_DEAD_PATH}: clean={clean:?} planted={planted:?}"
            )],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leak(file: &str, count: usize) -> Leak {
        Leak {
            noun: "a2a",
            kind: "plane",
            file: file.to_string(),
            count,
            category: "c",
            wave: "w",
        }
    }

    /// ITEM 198: the burndown ledger's `count` is compared. Forty more references in a baselined
    /// file used to leave `:undocumented` byte-identical because only `(noun, file)` was a key.
    #[test]
    fn a_baselined_file_that_grew_its_leak_count_is_undocumented() {
        let baseline: Vec<BaselineRow> = vec![
            (("a2a".to_string(), "crates/x/src/lib.rs".to_string()), 1),
            (("a2a".to_string(), "crates/y/src/lib.rs".to_string()), 5),
        ];
        let leaks = vec![
            leak("crates/x/src/lib.rs", 41),
            leak("crates/y/src/lib.rs", 3),
            leak("crates/z/src/lib.rs", 1),
        ];
        assert_eq!(
            undocumented_leaks(&leaks, &baseline),
            vec![
                "a2a@crates/x/src/lib.rs grew 1→41".to_string(),
                "a2a@crates/z/src/lib.rs".to_string(),
            ],
            "growth past the recorded count must be named; a shrink must not"
        );
    }
}
