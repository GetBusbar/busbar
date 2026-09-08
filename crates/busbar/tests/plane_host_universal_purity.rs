// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE UNIVERSAL-`EngineHost` SEMANTIC-PURITY WITNESS (finding F3 of
//! docs/design/playbook/neutrality-findings-and-prevention.md — the mechanical backstop that
//! converts a SEMANTIC coupling into a compile-shape invariant).
//!
//! ## The coupling this gate mechanises
//!
//! `crates/busbar-substrate/src/plane_host/mod.rs` declares the universal host seam `EngineHost` as
//! the SUM of ~13 capability-slice supertraits (`BreakerHost`, `LanePoolHost`, `MeteringHost`,
//! `ClockHost`, `TelemetryHost`, `JournalHost`, `MountHost`, `RegistryHost`, `HookConfigHost`,
//! `BudgetHost`, `IdentityHost`, `AdmissionHost`, `CompletionHost`). Every plane holds an
//! `Arc<dyn EngineHost>` and inherits EVERY method of EVERY slice. Some of those methods are
//! SINGLE-PLANE-PURPOSED — `JournalHost::call_log_emit`/`call_log_emit_hostless` (payload
//! `plane::calllog::CallInput` carries MCP vocabulary: `server`/`tool`/`tool_digest`/`pin_generation`),
//! `IdentityHost::quarantine_settle`/`approval_redeem`/`ask_state_sealer` (MCP durable trust/audit),
//! `CompletionHost::synthesize_completion` (LLM completion, reached only by MCP's sampling bridge). They
//! are GENERICALLY NAMED, so the token-level plane-purity gates (F1/plane-abi-neutrality) are
//! structurally blind to them: the coupling is SEMANTIC (what the method is FOR), not lexical. A NEW
//! single-plane method could be added to the universal trait and no token gate would catch it.
//!
//! ## The mechanical question this gate answers
//!
//! "Is a host capability plane-specific?" becomes a MECHANICAL one: how many of the four plane crates
//! (`busbar-{llm,mcp,a2a,voice}`) call a capability of that name? The gate:
//!   1. ENUMERATES every capability the universal host offers, from BOTH of its spellings — the
//!      `EngineHost` slice supertraits declared in `plane_host/mod.rs` (brace-matched trait bodies;
//!      `fn <name>(` extraction) AND the `Option<…Fn>` slots of `PlaneHostVtable` in
//!      `busbar-plugin/src/hot/host.rs` (brace-matched struct body; `pub <name>: Option<` extraction);
//!   2. COUNTS, per capability, how many DISTINCT plane crates contain a call `.<name>(` to it (comments
//!      stripped, non-test `.rs` only — the same detection discipline as `plane_transport_neutrality.rs`);
//!   3. FAILS if any universal capability is called by EXACTLY ONE plane crate (a single-plane
//!      capability riding the shared ABI) UNLESS it is on [`SINGLE_PLANE_ALLOWLIST`] with a written
//!      reason. Capabilities called by 0 planes (neutral/internal seams the plane path never reaches) or
//!      by ≥2 planes (genuinely shared) PASS with no entry.
//!
//! ## Why it reads the VTABLE as well as the trait
//!
//! The trait is being retired. `busbar-substrate::plane_host` is deleted at P4 cut C-F, and the same
//! capabilities are rebuilt as the `#[repr(C)]` slot list of [`PlaneHostVtable`], which
//! `busbar-plugin/src/hot/host.rs` already carries. A gate whose only input is the trait would, on the
//! day the trait goes, enumerate an EMPTY universe and pass everything — the moment the coupling this
//! file exists to catch becomes invisible again. So the universe is the UNION of the two spellings, and
//! either one may be empty without the gate going quiet, because:
//!
//! **A ZERO-CAPABILITY SCAN IS A REFUSAL, NOT A PASS.** [`Scan::refusal`] is the whole rule: if the
//! trait bodies yield nothing AND the vtable slots yield nothing, the gate has no input and says so
//! loudly rather than reporting no violations. Non-vacuity is not a floor that happens to be set above
//! zero here — it is the gate's first assertion, and `selftest_an_empty_scan_is_a_refusal_not_a_pass`
//! drives the same predicate over empty source to prove it fires.
//!
//! After this lands, adding a NEW single-plane method to the universal `EngineHost` reddens CI until it
//! is either (a) moved to a plane-narrowed slice that is NOT a supertrait of `EngineHost` (the F3 fix,
//! e.g. an `Arc<dyn McpTrustHost>` MCP narrows to), or (b) added to the allowlist with a justification.
//! That is the mechanical backstop for the semantic-coupling class — it does not itself perform the F3
//! refactor (which must not touch `plane_host/mod.rs`); it PINS the debt and blocks new instances.
//!
//! ## Detection limits (name-based, by design)
//!
//! The caller signal is name-based (`.<name>(`), exactly as F3 specifies ("caller-count across plane
//! crates"). Two consequences, both acknowledged: a plane calling a SAME-NAMED method on an unrelated
//! type would over-count (a single-plane host method could look multi-plane) — this only ever RELAXES
//! the gate, never produces a false RED; and a host method reached transitively (a plane calling a
//! neutral wrapper that itself calls the host) counts as 0 planes and PASSES as neutral. The gate is a
//! backstop against the clear case (a single plane directly naming a single-plane host method), not a
//! whole-program call graph.
//!
//! Modelled on the house source-scanning oracle pattern (`plane_transport_neutrality.rs` /
//! `plane_isomorphism.rs` / `capability_equality.rs`): ONE detector drives both the REAL scan and a
//! non-vacuity self-test, so a broken scan that finds nothing fails loudly rather than passing green.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// The host-seam trait definition file. Its slice supertraits + `EngineHost` are one half of the
/// universe scanned. It is the spelling that is being RETIRED (P4 cut C-F deletes it), which is why
/// the vtable below is read beside it rather than after it.
const HOST_TRAIT_FILE: &str = "crates/busbar-substrate/src/plane_host/mod.rs";

/// The host-seam VTABLE file — the `#[repr(C)]` rebuild of the same capabilities, and the half of the
/// universe that OUTLIVES the trait. Read from the moment the slots exist, not from the moment the
/// trait dies, so the day of the deletion is not also the day this gate first tries a new parser.
const HOST_VTABLE_FILE: &str = "crates/busbar-plugin/src/hot/host.rs";

/// The `#[repr(C)]` inbound-capability table inside [`HOST_VTABLE_FILE`]. Its `Option<…Fn>` fields are
/// the slot list: one slot per capability a plane may call back through.
const VTABLE_STRUCT: &str = "PlaneHostVtable";

/// The capability-slice supertraits of `EngineHost`, plus `EngineHost` itself (its provided
/// `run_gauntlet`). A slice added/removed on the universal sum is ONE edit here — and the enumeration
/// floor below bites if this list silently stops matching the trait file.
const SLICE_TRAITS: &[&str] = &[
    "BreakerHost",
    "LanePoolHost",
    "MeteringHost",
    "ClockHost",
    "TelemetryHost",
    "JournalHost",
    "MountHost",
    "RegistryHost",
    "HookConfigHost",
    "BudgetHost",
    "IdentityHost",
    "AdmissionHost",
    "CompletionHost",
    "EngineHost",
];

/// The four PLANE crate source roots — the "how many planes use this capability" universe. A plane
/// that appears/disappears is one edit here.
const PLANE_ROOTS: &[(&str, &str)] = &[
    ("llm", "crates/busbar-llm/src"),
    ("mcp", "crates/busbar-mcp/src"),
    ("a2a", "crates/busbar-a2a/src"),
    ("voice", "crates/busbar-voice/src"),
];

/// THE SINGLE-PLANE ALLOWLIST — `(method, plane, reason)`. Every universal-`EngineHost` method whose
/// ONLY plane-crate caller is a SINGLE plane must appear here with a written reason, or the gate reds.
/// Seeded from a scan of the CURRENT tree so the gate is GREEN today; a NEW single-plane method on the
/// universal trait must justify itself here (or move to a narrowed, non-supertrait slice — the F3 fix).
///
/// The `plane` column is the sole current caller the seed scan found; it is verified against the live
/// scan (a mis-recorded plane, or an allowlist entry for a method that is no longer single-plane-named
/// on the trait, reds too — the allowlist cannot silently rot).
///
/// The F3/F6 entries are the tracked semantic-coupling DEBT this branch exists to extract; the rest are
/// genuinely-neutral capabilities that happen to have exactly one consumer today (generic signature, no
/// foreign-plane vocabulary) — flagged by the mechanical caller-count, cleared by the written reason.
const SINGLE_PLANE_ALLOWLIST: &[(&str, &str, &str)] = &[
    ("admission_check", "llm", "Neutral single-consumer capability: the door's check-and-charge without the finishing record, so the Audit step can be the one terminal; generic signature, no foreign-plane vocabulary. Sole current caller is the LLM plane's admit step; admission_door collapses into it when the plane flips onto the step files. Re-review if a second plane consumes it."),
    ("admission_door", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("any_content_hook", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("approval_redeem", "mcp", "F3/F6 tracked debt: MCP durable trust/audit engine state (drift-quarantine / one-time-approval ledger / ask-state sealer), owner-ruled core-resident today; pending extraction to a narrowed McpTrustHost slice that is NOT a supertrait of EngineHost."),
    ("ask_state_sealer", "mcp", "F3/F6 tracked debt: MCP durable trust/audit engine state (drift-quarantine / one-time-approval ledger / ask-state sealer), owner-ruled core-resident today; pending extraction to a narrowed McpTrustHost slice that is NOT a supertrait of EngineHost."),
    ("audit_record", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("budget_state", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("call_log_emit", "mcp", "F3/F6 tracked debt: MCP durable call-log engine (CallInput carries MCP vocabulary server/tool/tool_digest/pin_generation). Owner-ruled core-resident today; pending extraction to a narrowed McpJournalHost slice that is NOT a supertrait of EngineHost."),
    ("call_log_emit_hostless", "mcp", "F3/F6 tracked debt: MCP durable call-log engine (CallInput carries MCP vocabulary server/tool/tool_digest/pin_generation). Owner-ruled core-resident today; pending extraction to a narrowed McpJournalHost slice that is NOT a supertrait of EngineHost."),
    ("caller_in_hook_groups", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("cost", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("cost_close", "voice", "Neutral single-consumer money-lease (MeteringHost reserve/settle): generic nanodollar signature, no voice-transport vocabulary; sole current caller is the voice D2 live-session lease (see F4 oracle)."),
    ("cost_model_unpriced", "llm", "Neutral single-consumer capability: the Verify step's third guard asks whether a model is unpriced over the same opaque cost handle rate_headroom/budget_state take; generic signature, no foreign-plane vocabulary. Sole current caller is the LLM plane's verify step. Re-review if a second plane prices by model."),
    ("cost_price_usage", "llm", "Neutral single-consumer capability: the Meter step prices what it metered against the card its own sink pinned at the door, over the same opaque cost handle cost_model_unpriced/cost_pricing_enabled take; generic nanodollar signature, no foreign-plane vocabulary. Sole current caller is the LLM plane's meter step. Re-review if a second plane accrues money against a pinned card."),
    ("cost_pricing_enabled", "llm", "Neutral single-consumer capability: the Verify step's third guard asks whether pricing is on at all, over the opaque cost handle; generic signature, no foreign-plane vocabulary. Sole current caller is the LLM plane's verify step. Re-review if a second plane consumes it."),
    ("cost_reserve", "voice", "Neutral single-consumer money-lease (MeteringHost reserve/settle): generic nanodollar signature, no voice-transport vocabulary; sole current caller is the voice D2 live-session lease (see F4 oracle)."),
    ("cost_settle", "voice", "Neutral single-consumer money-lease (MeteringHost reserve/settle): generic nanodollar signature, no voice-transport vocabulary; sole current caller is the voice D2 live-session lease (see F4 oracle)."),
    ("cost_settled", "voice", "Neutral single-consumer money-lease (MeteringHost reserve/settle): generic nanodollar signature, no voice-transport vocabulary; sole current caller is the voice D2 live-session lease (see F4 oracle)."),
    ("default_probe_interval_secs", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("default_probe_timeout_secs", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("destination_guard", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("finish_admitted", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("finish_rejected", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("global_gates", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("governance", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("identity_admit", "mcp", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the MCP plane's identity/registry/failover path."),
    ("identity_audience_binding", "mcp", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the MCP plane's identity/registry/failover path."),
    ("lane_store", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("meter_ledger", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("meter_series", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("plane_audience_bound", "a2a", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the A2A plane (card signing / pool membership / request-finish)."),
    ("plane_pool_members", "a2a", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the A2A plane (card signing / pool membership / request-finish)."),
    ("plane_slot_live", "mcp", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the MCP plane's identity/registry/failover path."),
    ("pool_gates", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("pool_label", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("pool_members_repeatable", "mcp", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the MCP plane's identity/registry/failover path."),
    ("pool_policy", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("pool_rewrites", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("price_usage", "voice", "Neutral single-consumer money-lease (MeteringHost reserve/settle): generic nanodollar signature, no voice-transport vocabulary; sole current caller is the voice D2 live-session lease (see F4 oracle)."),
    ("principal_standing", "mcp", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the MCP plane's identity/registry/failover path."),
    ("quarantine_settle", "mcp", "F3/F6 tracked debt: MCP durable trust/audit engine state (drift-quarantine / one-time-approval ledger / ask-state sealer), owner-ruled core-resident today; pending extraction to a narrowed McpTrustHost slice that is NOT a supertrait of EngineHost."),
    ("rate_headroom", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("request_finished", "a2a", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the A2A plane (card signing / pool membership / request-finish)."),
    ("requested_signals", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("rewrite_hooks", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("run_gauntlet", "mcp", "universal/neutral: the shared gauntlet entry any plane may ride (provided method delegating to the free run_gauntlet). One caller today is incidental, not plane vocabulary."),
    ("secret_resolver", "a2a", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the A2A plane (card signing / pool membership / request-finish)."),
    ("subkey_sign", "a2a", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the A2A plane (card signing / pool membership / request-finish)."),
    ("synthesize_completion", "mcp", "F3 tracked debt: LLM-purposed completion whose sole host caller is MCP's sampling/complete bridge. The documented narrow-to-slice case; already a CompletionHost slice, dropping it as an EngineHost supertrait is the F3 fix."),
    ("tap_hooks", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("tap_hooks_candidate", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("tap_hooks_response", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("tap_hooks_routing", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("telemetry_breaker_trip", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("telemetry_failover", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("telemetry_translation", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("telemetry_upstream_attempt", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("telemetry_upstream_failure", "llm", "Neutral single-consumer capability: generic signature, no foreign-plane vocabulary; sole current caller is the LLM plane's request/metering/telemetry path. Re-review if a second plane consumes it."),
    ("verify_token_test", "llm", "test-only (cfg test/test-support) raw-token verifier for the LLM routing-policy test seam; never linked in a production binary."),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("the repository root must exist")
}

/// Strip line/block comments from one source line, respecting string literals — the exact discipline of
/// `plane_transport_neutrality.rs::strip_comments`: a `//` inside a string is NOT a comment, a token
/// inside a string IS kept. `in_block` persists across lines; string state is per line.
fn strip_comments(line: &str, in_block: &mut bool) -> String {
    let b = line.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        let c2 = if i + 1 < b.len() {
            &b[i..i + 2]
        } else {
            &b[i..]
        };
        if *in_block {
            if c2 == b"*/" {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_str {
            out.push(c as char);
            if c == b'\\' {
                if i + 1 < b.len() {
                    out.push(b[i + 1] as char);
                }
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
            continue;
        }
        if c2 == b"/*" {
            *in_block = true;
            i += 2;
            continue;
        }
        if c2 == b"//" {
            break; // line comment (// /// //!) to EOL
        }
        if c == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    out
}

/// The whole source, comments stripped (block-aware). Used both for trait-body parsing and caller scan.
fn strip_source(src: &str) -> String {
    let mut in_block = false;
    let mut out = String::new();
    for line in src.lines() {
        out.push_str(&strip_comments(line, &mut in_block));
        out.push('\n');
    }
    out
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// The `{…}`-matched body of `pub trait <name>`, and the method names inside it. Both are
/// `common`'s — the same parsers `plane_meter_seam_reachability` reads the host seam with, so the two
/// gates that pin properties of this ABI cannot disagree about what it declares.
fn trait_body<'a>(src: &'a str, name: &str) -> Option<&'a str> {
    common::trait_body(src, name)
}

fn method_names(body: &str) -> BTreeSet<String> {
    common::trait_method_names(body).into_iter().collect()
}

/// The full universal-`EngineHost` method universe: the union of every [`SLICE_TRAITS`] trait's methods.
fn universal_methods(host_src_stripped: &str) -> BTreeSet<String> {
    let mut all = BTreeSet::new();
    for t in SLICE_TRAITS {
        if let Some(body) = trait_body(host_src_stripped, t) {
            all.extend(method_names(body));
        }
    }
    all
}

/// The vtable's capability universe: every `Option<…Fn>` slot of [`VTABLE_STRUCT`].
///
/// The parser is `common::vtable_slot_names`, shared with `plane_meter_seam_reachability` — ONE
/// opinion about what a capability slot is, so the two gates that pin properties of this ABI cannot
/// disagree about which slots it has. `src` is this file's own already-stripped source, so each gate
/// keeps its own comment-stripping discipline and shares only the structure match.
fn vtable_capabilities(vtable_src_stripped: &str) -> BTreeSet<String> {
    common::vtable_slot_names(vtable_src_stripped, VTABLE_STRUCT)
        .into_iter()
        .collect()
}

/// Does `code` (comments stripped) contain a method CALL `.<method>(` — the method as a whole
/// identifier token immediately preceded by `.`, and (after optional whitespace) followed by `(`?
/// Whole-token matching means `.plane_slot(` does NOT match the method `plane_slot_live`, and the `.`
/// guard excludes a path `::plane_slot` or a free-fn call `plane_slot(`.
fn calls_method(code: &str, method: &str) -> bool {
    let chars: Vec<char> = code.chars().collect();
    let m: Vec<char> = method.chars().collect();
    let n = chars.len();
    let mut i = 0;
    while i < n {
        // Find a token boundary start of an identifier.
        if is_ident(chars[i]) && (i == 0 || !is_ident(chars[i - 1])) {
            let start = i;
            let mut j = i;
            while j < n && is_ident(chars[j]) {
                j += 1;
            }
            // Whole-token equality with `method`.
            if j - start == m.len() && chars[start..j] == m[..] {
                // Preceded by `.` (a method call, not `::path` or a free fn).
                let dot = start >= 1 && chars[start - 1] == '.';
                // Not a `..range` (`.` before name, but the char before that is not another `.`).
                let not_range = start < 2 || chars[start - 2] != '.';
                // Followed (after ws) by `(`.
                let mut k = j;
                while k < n && chars[k].is_whitespace() {
                    k += 1;
                }
                let paren = k < n && chars[k] == '(';
                if dot && not_range && paren {
                    return true;
                }
            }
            i = j;
            continue;
        }
        i += 1;
    }
    false
}

/// Every non-test `.rs` under `dir`, recursively (excludes `*/tests/*`, `*_test(s).rs`) — the plane's
/// exported source, not its unit tests (mirrors the shell/`plane_transport_neutrality.rs` scope).
fn plane_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().and_then(|n| n.to_str()) == Some("tests") {
                continue;
            }
            plane_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name.ends_with("_test.rs") || name.ends_with("_tests.rs") {
                continue;
            }
            out.push(path);
        }
    }
}

/// The stripped source of every plane crate, keyed by plane name — read once, scanned for every method.
fn plane_sources(root: &Path) -> BTreeMap<&'static str, Vec<String>> {
    let mut map = BTreeMap::new();
    for (plane, rel) in PLANE_ROOTS {
        let mut files = Vec::new();
        plane_rs_files(&root.join(rel), &mut files);
        let srcs: Vec<String> = files
            .iter()
            .map(|f| {
                let raw = std::fs::read_to_string(f).expect("plane source must be readable");
                strip_source(&raw)
            })
            .collect();
        map.insert(*plane, srcs);
    }
    map
}

/// The DISTINCT plane crates whose (stripped) source calls `.<method>(`.
fn plane_callers(
    method: &str,
    sources: &BTreeMap<&'static str, Vec<String>>,
) -> BTreeSet<&'static str> {
    let mut hit = BTreeSet::new();
    for (plane, srcs) in sources {
        if srcs.iter().any(|s| calls_method(s, method)) {
            hit.insert(*plane);
        }
    }
    hit
}

/// The universe + the per-capability caller-plane sets, computed once from the live tree. `methods` is
/// the UNION the gate judges; `trait_methods` and `vtable_slots` are kept apart so the refusal below can
/// say which spelling went quiet.
struct Scan {
    trait_methods: BTreeSet<String>,
    vtable_slots: BTreeSet<String>,
    methods: BTreeSet<String>,
    callers: BTreeMap<String, BTreeSet<&'static str>>,
}

/// THE REFUSAL. `Some(reason)` when the scan has NO INPUT — neither trait body nor vtable slot — and a
/// gate with no input reports no violations for the same reason an empty ledger reconciles. Kept as a
/// pure function of the two counts so the self-test can drive the identical predicate on numbers the
/// live tree will never produce.
fn empty_scan_refusal(trait_methods: usize, vtable_slots: usize) -> Option<String> {
    (trait_methods == 0 && vtable_slots == 0).then(|| {
        format!(
            "THE UNIVERSAL-HOST SCAN FOUND NOTHING: {trait_methods} method(s) across the \
             {} slice traits in {HOST_TRAIT_FILE} and {vtable_slots} capability slot(s) on \
             `{VTABLE_STRUCT}` in {HOST_VTABLE_FILE}. This gate answers \"how many planes call this \
             capability\" over an enumerated universe; with an EMPTY universe it answers \"no \
             violations\" about nothing, which is how the coupling it exists to catch becomes \
             invisible again. Both spellings gone at once means a file moved, a name changed, or the \
             parse regressed — not that the coupling was resolved. A zero-capability scan is a \
             REFUSAL.",
            SLICE_TRAITS.len()
        )
    })
}

fn run_scan() -> Scan {
    let root = repo_root();
    let host_src = std::fs::read_to_string(root.join(HOST_TRAIT_FILE))
        .expect("the plane_host trait file must be readable");
    let host_stripped = strip_source(&host_src);
    let trait_methods = universal_methods(&host_stripped);

    // The vtable half. Read with the same `expect` discipline as the trait file: a file that cannot be
    // read is a broken gate, not an empty universe.
    let vtable_src = std::fs::read_to_string(root.join(HOST_VTABLE_FILE))
        .expect("the plane-host vtable file must be readable");
    let vtable_stripped = strip_source(&vtable_src);
    let vtable_slots = vtable_capabilities(&vtable_stripped);

    // THE FIRST ASSERTION, BEFORE ANY COUNTING. Not a floor tuned above today's number — the honest
    // zero case, which is what the retirement of the trait would produce if the vtable half were not
    // here to answer beside it.
    assert!(
        empty_scan_refusal(trait_methods.len(), vtable_slots.len()).is_none(),
        "{}",
        empty_scan_refusal(trait_methods.len(), vtable_slots.len()).unwrap_or_default()
    );

    let methods: BTreeSet<String> = trait_methods.union(&vtable_slots).cloned().collect();
    let sources = plane_sources(&root);
    let callers: BTreeMap<String, BTreeSet<&'static str>> = methods
        .iter()
        .map(|m| (m.clone(), plane_callers(m, &sources)))
        .collect();

    // Non-vacuity floor on the plane walk: a broken walk (wrong root, silent read error) would make
    // every method look 0-plane and pass the whole gate green. Assert each plane yielded real source.
    for (_plane, rel) in PLANE_ROOTS {
        let mut files = Vec::new();
        plane_rs_files(&root.join(rel), &mut files);
        assert!(
            files.len() >= 5,
            "plane walk found only {} non-test .rs under {rel} — the scan floor did not bite; a \
             broken walk would pass this gate vacuously",
            files.len()
        );
    }

    Scan {
        trait_methods,
        vtable_slots,
        methods,
        callers,
    }
}

/// THE REAL WITNESS: every universal-`EngineHost` method called by EXACTLY ONE plane crate is on the
/// allowlist with a reason. 0-plane (neutral/internal) and ≥2-plane (shared) methods need no entry.
#[test]
fn no_unjustified_single_plane_method_on_universal_engine_host() {
    let scan = run_scan();

    // ENUMERATION FLOORS, PER SPELLING AND ON THE UNION. Each half is floored ONLY WHILE IT EXISTS:
    // the trait is scheduled for deletion (P4 cut C-F), and a floor that reads "the trait must yield
    // 60 methods" would turn that deletion into a gate edit made in the same commit — which is
    // exactly the commit in which nobody wants to be relaxing this file's floors. Present-but-thin is
    // a parse regression and reds; absent is the retirement and is carried by the other half. Both
    // absent at once is neither, and `run_scan` has already refused it.
    if !scan.trait_methods.is_empty() {
        assert!(
            scan.trait_methods.len() >= 60,
            "the {} slice traits in {HOST_TRAIT_FILE} are still declared but enumerated only {} \
             method(s) — the trait-body parse regressed",
            SLICE_TRAITS.len(),
            scan.trait_methods.len()
        );
    }
    if !scan.vtable_slots.is_empty() {
        assert!(
            scan.vtable_slots.len() >= 30,
            "`{VTABLE_STRUCT}` in {HOST_VTABLE_FILE} is still declared but enumerated only {} \
             capability slot(s) — the struct-body parse regressed",
            scan.vtable_slots.len()
        );
    }
    assert!(
        scan.methods.len() >= 30,
        "enumerated only {} universal host capabilities — {} trait method(s) + {} vtable slot(s); a \
         universe this small cannot be the real host seam, and a broken enumeration would pass this \
         gate vacuously",
        scan.methods.len(),
        scan.trait_methods.len(),
        scan.vtable_slots.len()
    );

    let allow_names: BTreeSet<&str> = SINGLE_PLANE_ALLOWLIST.iter().map(|(m, _, _)| *m).collect();

    // (a) No unjustified single-plane method.
    let mut violations: Vec<String> = Vec::new();
    for (method, callers) in &scan.callers {
        if callers.len() == 1 && !allow_names.contains(method.as_str()) {
            let plane = callers.iter().next().copied().unwrap_or("?");
            violations.push(format!(
                "  {method}  — called by exactly ONE plane ({plane}) yet rides the universal \
                 EngineHost sum-trait, with no SINGLE_PLANE_ALLOWLIST entry"
            ));
        }
    }
    assert!(
        violations.is_empty(),
        "SINGLE-PLANE capability(ies) riding the universal EngineHost sum-trait (finding F3): a method \
         used by exactly one plane crate couples every OTHER plane's compile surface to that plane's \
         vocabulary. Move it to a plane-narrowed slice that is NOT a supertrait of EngineHost (the F3 \
         fix), or add it to SINGLE_PLANE_ALLOWLIST with a written reason:\n{}",
        violations.join("\n")
    );

    // (b) The allowlist cannot rot: every entry names a real universal-trait method, and — while the
    //     method is still single-plane — records the CORRECT sole caller. (A method that grew to ≥2
    //     planes is a GOOD change; its entry is simply dormant, not stale, so it is not flagged.)
    let mut stale: Vec<String> = Vec::new();
    let mut seen: BTreeSet<&str> = BTreeSet::new();
    for (method, plane, reason) in SINGLE_PLANE_ALLOWLIST {
        if !seen.insert(method) {
            stale.push(format!("  {method}  — duplicate allowlist entry"));
        }
        if reason.trim().len() < 20 {
            stale.push(format!("  {method}  — allowlist reason is empty/too thin"));
        }
        match scan.callers.get(*method) {
            None => stale.push(format!(
                "  {method}  — allowlisted but NOT a capability of the universal host in EITHER \
                 spelling: no such method on the {HOST_TRAIT_FILE} slice traits and no such slot on \
                 `{VTABLE_STRUCT}` (renamed/removed?); prune the entry"
            )),
            Some(callers) => {
                if callers.len() == 1 {
                    let sole = callers.iter().next().copied().unwrap_or("?");
                    if sole != *plane {
                        stale.push(format!(
                            "  {method}  — allowlist records plane `{plane}` but the sole caller is \
                             now `{sole}`; correct the entry"
                        ));
                    }
                }
                // callers.len() == 0 or >= 2: dormant entry, allowed (see note above).
            }
        }
    }
    assert!(
        stale.is_empty(),
        "SINGLE_PLANE_ALLOWLIST has stale/incorrect entries — the allowlist must track the live \
         trait+scan, never silently rot:\n{}",
        stale.join("\n")
    );
}

/// SELF-TEST (the detector is NON-VACUOUS): the SAME detector must (1) enumerate the known slice
/// methods, (2) classify a KNOWN single-plane method (`synthesize_completion`) as single-plane, (3)
/// still see a KNOWN ≥2-plane method (`clock_now_secs`) as multi-plane, and (4) a KNOWN 0-plane method
/// (`plane_defs`) as neutral. A broken scan that "finds nothing" (all-0, or all-1) fails HERE loudly,
/// so a green real witness above is meaningful. It also proves `.plane_slot(` ≠ `plane_slot_live`
/// (whole-token matching) via a direct `calls_method` assertion.
///
/// The named methods below are the TRAIT half's, so the parts of this self-test that depend on them
/// run only while the trait is declared — after P4 cut C-F deletes it, `plane_defs` and
/// `clock_now_secs` are not names of anything and asserting on them would be asserting on a memory.
/// The guard is NOT a way for this test to fall silent: `run_scan` refuses an empty universe outright,
/// [`the_vtable_slot_list_is_enumerated_beside_the_trait_bodies`] carries the surviving half
/// unconditionally, and the real witness's per-spelling floors still bite on whichever half exists.
#[test]
fn detector_is_non_vacuous_across_single_multi_and_zero_plane_methods() {
    let scan = run_scan();
    if scan.trait_methods.is_empty() {
        println!(
            "  {HOST_TRAIT_FILE} declares no slice trait; the trait-half samples below are retired \
             with it, and the vtable half is proven in its own test"
        );
        return;
    }

    // (1) Enumeration sees the specific F3 methods + a per-slice sampling — not a vacuous empty set.
    for expect in [
        "synthesize_completion", // CompletionHost
        "call_log_emit",         // JournalHost
        "quarantine_settle",     // IdentityHost
        "clock_now_secs",        // ClockHost
        "breaker_admit",         // BreakerHost
        "run_gauntlet",          // EngineHost provided method
        "plane_defs",            // RegistryHost
    ] {
        assert!(
            scan.methods.contains(expect),
            "enumeration missed `{expect}` — the trait-body parse is broken; the real witness would \
             pass vacuously"
        );
    }

    // (2) A KNOWN single-plane method: `synthesize_completion`. Its ONLY host call site is MCP's
    //     sampling/complete bridge (busbar-llm holds the impl as a free fn, not a host-seam call), so
    //     the caller-count classifies it single-plane — the F3 case this whole gate exists to pin.
    let synth = scan
        .callers
        .get("synthesize_completion")
        .expect("enumerated");
    assert_eq!(
        synth.len(),
        1,
        "detector failed to classify `synthesize_completion` as SINGLE-plane (got callers {synth:?}); \
         a scan that cannot see a single-plane method makes the real witness vacuous"
    );
    assert!(
        synth.contains("mcp"),
        "the sole `synthesize_completion` host caller should be the MCP sampling bridge, got {synth:?}"
    );

    // (3) A KNOWN ≥2-plane method: `clock_now_secs` (mcp + a2a). Proves the detector DISTINGUISHES
    //     shared capabilities — it does not collapse everything to single-plane.
    let clock = scan.callers.get("clock_now_secs").expect("enumerated");
    assert!(
        clock.len() >= 2,
        "detector failed to see `clock_now_secs` as MULTI-plane (got {clock:?}); a broken counter that \
         under-counts would false-RED shared methods"
    );

    // (4) A KNOWN 0-plane method: `plane_defs` (A2A's card path names it, but not via `.plane_defs(`
    //     directly in these crates today) — proves the detector's neutral (0-plane) class is reachable,
    //     so it is not the case that every method scans as ≥1.
    let defs = scan.callers.get("plane_defs").expect("enumerated");
    assert_eq!(
        defs.len(),
        0,
        "expected `plane_defs` to scan as 0-plane (neutral), got {defs:?}"
    );

    // (5) Whole-token call matching: `.plane_slot(` must NOT match the longer method `plane_slot_live`,
    //     and a `::path`/free-fn form must NOT count as a `.`-call.
    assert!(
        calls_method("host.plane_slot(key)", "plane_slot"),
        "calls_method missed a plain `.plane_slot(` call"
    );
    assert!(
        !calls_method("host.plane_slot_live(key)", "plane_slot"),
        "calls_method wrongly matched `plane_slot` inside `.plane_slot_live(` — token boundary broken"
    );
    assert!(
        !calls_method(
            "busbar_substrate::plane_host::plane_slot(key)",
            "plane_slot"
        ),
        "calls_method wrongly matched a `::path` form as a `.`-method call"
    );
    assert!(
        calls_method("a.b .synthesize_completion (x)", "synthesize_completion"),
        "calls_method missed a whitespace-before-paren call"
    );
}

/// THE VTABLE HALF IS REAL. The slot parser is proven on the live table (it finds the specific slots
/// the retirement map assigns to each core file being rebuilt), proven to EXCLUDE the table's own
/// non-capability scalars, and proven to be the reason the universe survives the trait: the union is
/// strictly larger than the trait alone, so a capability that exists only as a slot is already judged
/// today rather than from the day the trait is deleted.
#[test]
fn the_vtable_slot_list_is_enumerated_beside_the_trait_bodies() {
    let scan = run_scan();

    // (1) The slot list is found at all, and is the size the table actually is (40+ slots today).
    assert!(
        scan.vtable_slots.len() >= 30,
        "enumerated only {} `{VTABLE_STRUCT}` slot(s) from {HOST_VTABLE_FILE} — the struct-body \
         parse regressed. When the trait is deleted this half is the ONLY half, so a parse that \
         quietly under-reads here is the gate going quiet on a schedule: {:?}",
        scan.vtable_slots.len(),
        scan.vtable_slots
    );

    // (2) It finds the named slots, one per capability family the vtable rebuild takes over — the
    //     egress, journal, trust, breaker, govern, guard, identity and pipe halves.
    for expect in [
        "egress_open",
        "egress_write",
        "journal_append",
        "journal_append_scoped",
        "trust_evaluate",
        "breaker_admit",
        "breaker_admit_reason",
        "govern_admit",
        "meter_charge",
        "guard_url",
        "auth_resolve",
        "approval_redeem",
        "subkey_sign",
        "pipe_read",
        "cost_reserve",
        "cost_settle",
    ] {
        assert!(
            scan.vtable_slots.contains(expect),
            "the slot scan missed `{expect}` on `{VTABLE_STRUCT}`; found {:?}",
            scan.vtable_slots
        );
    }

    // (3) The table's own scalars are NOT capabilities. `abi`/`size`/`version` are the frozen preamble
    //     and the sized-struct guard; counting them would put three names into the caller-count that
    //     no plane can call and that no allowlist entry could ever honestly justify.
    for scalar in ["abi", "size", "version"] {
        assert!(
            !scan.vtable_slots.contains(scalar),
            "the slot scan counted the table's own `{scalar}` scalar as a capability — the \
             `Option<` discriminator is not doing its job"
        );
    }

    // (4) The union is strictly larger than the trait alone: at least one capability is known ONLY as
    //     a slot. That is the property that makes reading the vtable worth doing BEFORE the trait
    //     dies rather than in the same commit that deletes it.
    let slot_only: BTreeSet<&String> = scan.vtable_slots.difference(&scan.trait_methods).collect();
    assert!(
        !slot_only.is_empty(),
        "every vtable slot is also a trait method, so the vtable half adds nothing and this gate \
         would still enumerate an empty universe the day the trait goes"
    );
    println!(
        "  trait methods: {}   vtable slots: {}   union: {}   slot-only: {}",
        scan.trait_methods.len(),
        scan.vtable_slots.len(),
        scan.methods.len(),
        slot_only.len()
    );
}

/// THE REFUSAL FIRES. A scan that enumerated nothing must FAIL, not report "no violations". Driven on
/// the same [`empty_scan_refusal`] predicate the real scan asserts on, and on synthetic source through
/// the same two parsers, so the proof is of the shipped code path and not of a restatement of it.
#[test]
fn selftest_an_empty_scan_is_a_refusal_not_a_pass() {
    // (1) The predicate itself: zero AND zero refuses; anything else does not.
    assert!(
        empty_scan_refusal(0, 0).is_some(),
        "a scan with no trait methods and no vtable slots was treated as a PASS — that is the \
         failure mode this gate is being repointed to avoid"
    );
    assert!(
        empty_scan_refusal(0, 44).is_none(),
        "the trait alone being gone must NOT refuse: the vtable is the destination, and the whole \
         point of reading it is that the gate keeps its input across the retirement"
    );
    assert!(
        empty_scan_refusal(75, 0).is_none(),
        "the vtable alone being absent must NOT refuse while the trait still declares the universe"
    );

    // (2) The parsers really do return empty on source that declares neither — so the refusal above is
    //     reachable from real input, not only from hand-written zeros.
    let neither = strip_source(
        "pub struct SomethingElse { pub a: Option<u8> }\npub trait NotAHost { fn x(&self); }\n",
    );
    assert!(
        universal_methods(&neither).is_empty(),
        "the trait parser found methods in source that declares none of the slice traits"
    );
    assert!(
        vtable_capabilities(&neither).is_empty(),
        "the slot parser found slots in source that declares no `{VTABLE_STRUCT}`"
    );
    assert!(
        empty_scan_refusal(
            universal_methods(&neither).len(),
            vtable_capabilities(&neither).len()
        )
        .is_some(),
        "source declaring neither spelling did not produce the refusal"
    );

    // (3) And a table that IS present is read: the same parser, one slot, comments and a non-Option
    //     scalar around it.
    let one_slot = strip_source(
        "#[repr(C)]\npub struct PlaneHostVtable {\n    // a comment naming pub not_a_slot: Option<X>\n    pub size: u32,\n    /// doc\n    pub govern_admit: Option<GovernAdmitFn>,\n}\n",
    );
    let slots = vtable_capabilities(&one_slot);
    assert_eq!(
        slots.len(),
        1,
        "expected exactly the one `Option` slot, got {slots:?}"
    );
    assert!(slots.contains("govern_admit"), "got {slots:?}");
}
