//! `cargo xtask gate plane-purity` — THE ENFORCEMENT GATE FOR THE PLANE ABI, converted from
//! `scripts/plane-purity-lint.sh` plus `scripts/g6-freeze-witness.sh`.
//!
//! WHY IT EXISTS. A protocol plane must be a self-contained plugin merely compiled in for
//! convenience: turn its feature off, or delete its crate, and the NEUTRAL crates must still
//! compile and serve no protocol. That was the requirement on day one and it eroded, for one
//! reason above all — THERE WAS NO GATE. A boundary with no instrument watching it drifts.
//!
//! THE INVARIANT. The plane ABI is the ONE surface across which core and a plane communicate.
//! Every side channel is a violation to REMOVE, not to gate, and each is its own ledger row:
//!
//! | row | the side channel |
//! | --- | --- |
//! | [`ROW_PATH_INCLUDE`] | a `#[path]` or `include!` dual-compile of plane source into a neutral crate |
//! | [`ROW_SYMBOL`] | a `busbar_<plane>::` path, `extern crate`, or `use … as` alias |
//! | [`ROW_TYPE`] | a plane record type, or any plane-/dialect-prefixed type name |
//! | [`ROW_KEY`] | a concrete plane key as a bare token |
//! | [`ROW_DIALECT`] | one of the six dialect names as a bare token |
//! | [`ROW_BACKWARDS`] | a plane crate reaching BACK past the contract — the kernel, its workflow crates, any crate [`crate::gates::kind_isolation::plane_wall_crates`] derives |
//! | [`ROW_FREEZE`] | core still naming a concrete LLM-family IR type (the G6 freeze witness) |
//! | [`ROW_SEGMENT_DEBT`] | a dialect written as an identifier segment (`PROTO_GEMINI`) that `qa/segment-debt.toml` does not list, or a listed row that matches no live hit |
//!
//! and two rows in front of all of them, because **the gate cannot pass by scanning nothing**:
//! [`ROW_ROOTS`] (a listed root that is not on disk is scanned as zero files, and zero is the
//! passing answer to every ban) and [`ROW_DENOMINATOR`] (a scan that opened zero `.rs` files
//! reports zero violations, which is indistinguishable from a clean tree).
//!
//! THE FROZEN-WIRE CARVE-OUT is the one documented exception and it is per-line, not per-rule: a
//! neutral source line may carry `// plane-purity: frozen-wire <reason>` and be exempt from the
//! VOCABULARY rows (TYPE/KEY/DIALECT) only. It never launders PATH-INCLUDE or SYMBOL, a trailing
//! pragma never bleeds onto the next line, and **a marker with no reason is not a pragma** — the
//! reason is the entire reviewability of the carve-out. All four properties have their own selftest
//! case below.
//!
//! **THE REASON IS A CLAIM, AND THE CLAIM IS CHECKED** ([`ROW_FROZEN_WIRE_CLAIM`], see [`claims`]).
//! A frozen-wire pragma must state `frozen since X.Y.Z` and name its wire key(s) as `key:`, and the
//! config fingerprint at tag `vX.Y.Z` must carry every one. Eleven pragmas once exempted 1.6.0-new
//! `mcp:`/`tools:`/`agents:` names as "frozen since 1.5.3" when neither 1.5.3 nor 1.5.5 had them.

pub mod claims;
pub mod freeze;
#[cfg(test)]
mod q128_tests;
pub mod scanner;
pub mod segment_debt;
pub mod strict;
pub mod vocab;
#[cfg(test)]
mod w18_tests;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use crate::ctx::{Ctx, Edit, Overlay, SourceFile, WalkSpec};
use crate::gates::{
    prove_green, prove_red, prove_rows_green, Case, Expect, Gate, LegacyRun, Report,
};
use crate::ledger::{Row, Verdict};

use scanner::{Hit, Mode};
use vocab::Vocab;

pub const ROW_ROOTS: &str = "plane-purity:roots";
pub const ROW_DENOMINATOR: &str = "plane-purity:scan-denominator";
pub const ROW_PATH_INCLUDE: &str = "plane-purity:path-include";
pub const ROW_SYMBOL: &str = "plane-purity:symbol";
pub const ROW_TYPE: &str = "plane-purity:type";
pub const ROW_KEY: &str = "plane-purity:key";
pub const ROW_DIALECT: &str = "plane-purity:dialect";
pub const ROW_BACKWARDS: &str = "plane-purity:backwards";
pub const ROW_FREEZE: &str = "plane-purity:core-llm-family-freeze";
pub const ROW_FROZEN_WIRE_CLAIM: &str = "plane-purity:frozen-wire-claim";
pub const ROW_SEGMENT_DEBT: &str = "plane-purity:segment-debt";

/// The row id for one strict category, e.g. `plane-purity-strict:category:SYMBOL`.
pub fn strict_category_row(category: &str) -> String {
    format!("plane-purity-strict:category:{category}")
}

/// THE TEST-REACH ROW: every plane crate's own test code reaching past the contract, each against
/// its `[test-reach]` ceiling. ONE row over the DERIVED plane population
/// ([`crate::gates::kind_isolation::plane_kind_src_roots`]), because the owed set is static and the
/// population is not: it held one row per legacy-engine key (`planes::PLANE_KEYS`, today `llm`
/// alone), so `busbar-plane-llm` and every pinned plane had no row at all. The detail names every
/// crate, its key and its count.
pub const ROW_STRICT_REACH: &str = "plane-purity-strict:test-reach";

/// A plane crate's `[test-reach]` key: its directory with the `busbar-` prefix off
/// (`crates/busbar-llm/src` -> `llm`, `crates/busbar-plane-mcp/src` -> `plane-mcp`), so the legacy
/// engine keeps the key it always had.
pub fn reach_key(root: &str) -> String {
    let dir = root.strip_suffix("/src").unwrap_or(root);
    let dir = dir.rsplit('/').next().unwrap_or(dir);
    dir.strip_prefix("busbar-").unwrap_or(dir).to_string()
}

/// Where a caller OUTSIDE this process asks for the hit artefact to be written.
///
/// The construction gate used to be that caller, through `scripts/construction-gate.sh`; it is now
/// linked into the same binary and reads [`check_hits_artefact`] directly, so nothing in the tree
/// sets this today. The env var stays because it is the seam for a consumer that CANNOT be a
/// function call — a script, another process — and because the two paths render the same bytes
/// from the same derivation, which is what keeps them from drifting if one appears.
pub const HITS_OUT_ENV: &str = "PLANE_PURITY_HITS_OUT";

/// THE NEUTRAL WALK'S FLOOR: the `.rs` files the derived neutral population held on dev, measured
/// (1134 on f49c8bf98c; Law 8 shape 2: "a denominator with no floor is a denominator that can be reduced to one without
/// anybody noticing"; Law 9: a census floor pins at today's measured value). The freeze walk reads
/// the same population and is held to the same floor. It was `== 0` here and `1` on the freeze
/// walk, so a neutral scan that fell to one file passed every ban. Raised as the neutral crates
/// grow; lowered only in a reviewed diff that names the files that legitimately left.
///
/// RE-PINNED 1134 -> 1109 at the merge of dev 6d6bd2b0b0, today's measured value (Law 9). The walk
/// did not shrink; the population did, by deletion on dev (34 files gone, 9 added; renames net to
/// zero), each in a reviewed commit:
/// * `busbar-contract/src/abi/hot/{host,mod,pod}.rs`, `abi/hot/tests/{host,pod}_tests.rs` —
///   299e7688ad (abi/hot deleted, status row 84);
/// * `busbar-core-admin/src/{posture.rs,tests/posture_tests.rs}` — cf163d3ef3 (#77(9)), and
///   `admin_codec/meta.rs` — a70a10b242 (admin surface on the claim table);
/// * `busbar-kernel/src/plane/approvals.rs`, `plane/tests/approvals_tests.rs` — 99f0713a4a;
/// * `busbar-kernel/src/plane_host/{creds,dispatch,egress,egress_tests,identity_admit,journal,
///   pipe,pipe_tests,session_meter,slots_through,vtable}.rs` and `plane_host/tests/{creds,dispatch,
///   identity_admit,journal,session_meter}_tests.rs` — e6fc4808fb, e71b06180e, f63d116d01,
///   2156f67b9a, 299e7688ad (status rows 82, 84);
/// * `busbar-kernel/src/trust/{declared,verify}.rs` and `trust/tests/{declared,genericity,
///   lifecycle,verify_edge,verify}_tests.rs`, `trust/tests/reverify.rs` — 941d19f67f (Q128 p8).
///
/// Added: `contract/src/abi/sdk/{hmac.rs,tests/hmac_tests.rs}`, `core-admin/src/v1/json/tests/
/// named_map_tests.rs`, `kernel-wal/src/tests/quarantine_numbering.rs`, `kernel/src/auth/{admit.rs,
/// tests/admit_tests.rs}`, `kernel/src/plane_driver/slots.rs`, `kernel/src/tests/clock_tests.rs`,
/// `kernel/src/tests/members/wal/store_debt_tests.rs`. 1134 - 34 + 9 = 1109.
///
/// HELD at 1109: the walk's measure of this branch merged with dev ed49b64120 (ModernCI gates on
/// 8729b322bf/b68455c852, `neutral_files=1109`). A floor of 1110 over that tree reds every row the
/// floor guards; the floor pins at today's measure (Law 9) and rises with it.
///
/// RE-PINNED 1109 -> 1108 at the merge of dev 13c06298f5, today's measured value (ModernCI gates on
/// this branch merged with dev e76e736ce8: `neutral_files=1108`; `git ls-tree` of the neutral
/// kinds' `src/*.rs` counts 1109 on dev b9c4eda7dc and 1108 on 13c06298f5). The walk did not
/// shrink; the population did, by deletion on dev (3 files gone, 2 added since b9c4eda7dc), each
/// in a reviewed commit:
/// * `busbar-contract/src/transport/driver.rs` — 0b74624007 (the second inbound seam deleted,
///   Q128 contract, #1201);
/// * `busbar-kernel/src/failover/{mod.rs,tests/failover_tests.rs}` — efa6e2478d (D2, the kernel's
///   failover module deleted with its last rider, status row 82, #1299).
///
/// Added: `kernel/src/test_support/operator_double.rs` (3c6eca3201, #1327) and
/// `kernel/src/test_support/tests/ranking_double_tests.rs` (9fa1dacdf8, #1237).
/// 1109 - 3 + 2 = 1108.
pub const NEUTRAL_FLOOR: usize = 1108;

/// THE PLANE WALK'S FLOOR: the `.rs` files the plane population (in-tree and pinned planes) held on
/// dev, measured (606 on f49c8bf98c, the RED branch's `plane_files`). Same rule as
/// [`NEUTRAL_FLOOR`].
///
/// RE-PINNED 606 -> 488 at the merge of dev 1ed9f8995d (#1161), today's measured value (Law 9; lowered,
/// never raised). The walk did not shrink; the population did, by deletion of the retired engine
/// crate in a reviewed commit (#1161). 606 was 247 (`busbar-plane-llm`) + 85 (`busbar-plane-mcp`) +
/// 22 (`busbar-plane-decisions`) + 83 (`busbar-plane-a2a`) + 50 (`busbar-plane-streaming`) + 119
/// (`busbar-llm`); 488 is the same five planes with `busbar-plane-llm` at 248 (+1,
/// `exchange/catalog.rs` added). The 119 files that legitimately left, all `.rs` under `crates/busbar-llm/src`:
/// * `busbar-llm/src/{arrival.rs, lib.rs, native_ingress.rs, openai_responses_webhook.rs}`;
/// * `busbar-llm/src/engine/attempt/{assemble.rs, buffered.rs, classify.rs, mod.rs, respond.rs, send.rs}`;
/// * `busbar-llm/src/engine/attempt/tests/{assemble.rs, failed_generation.rs}`;
/// * `busbar-llm/src/engine/{build_runtime.rs, credential.rs, egress.rs, health.rs, hooks.rs, lazy_body.rs, mod.rs, pipeline.rs, response_body.rs, select.rs, tables.rs, usage.rs, wire.rs}`;
/// * `busbar-llm/src/engine/engine_tests/{crossproto_delivery_billing_tests.rs, future_size_probe.rs, inject_include_usage_tests.rs, nonstream_drop_billing_tests.rs, send_envelope_tests.rs, stream_deadline_tests.rs}`;
/// * `busbar-llm/src/engine/exhaustion/{fallback.rs, least_bad.rs, mod.rs, queue.rs}`;
/// * `busbar-llm/src/engine/tests/{alloc_gate_tests.rs, attempt_identity_tests.rs, attempt_timeout_precedence_tests.rs, auth_dispatch_tests.rs, auth_native_envelope_tests.rs, auth_style_tests.rs, client_header_forwarding_tests.rs, dial_refusal_failover_tests.rs, dialect_registry_facts_tests.rs, egress_differential_tests.rs, egress_dropped_controls_audit_tests.rs, egress_target_tests.rs, engine_identity_witness_tests.rs, forward_once_pool_cell_tests.rs, forward_pool_integration_tests.rs, gate_policy_503_literals_tests.rs, health_tests.rs, hook_access_tests.rs, hook_non_chat_projection_tests.rs, hook_opt_in_projection_tests.rs, hook_seam_tests.rs, hook_seat_order_tests.rs, hook_system_turn_tests.rs, ingress_indistinguishability_tests.rs, ingress_integration_tests.rs, ingress_reject_response_tests.rs, lane_availability_proptest_tests.rs, lane_caps_config_tests.rs, lazy_body_tests.rs, ledger_100_tests.rs, legacy_forward_once.rs, mid_stream_error_tests.rs, multi_candidate_degrade_tests.rs, on_exhausted_tests.rs, ordered_walk_tests.rs, plane_attempt_parity_tests.rs, plane_reply_parity_tests.rs, pool_upstream_creds_tests.rs, probe_guard_tests.rs, probe_release_owner_tests.rs, provider_keys_drift_tests.rs, request_short_circuit_tests.rs, rerank_search_units_tests.rs, reroute_pool_tests.rs, responses_ingress_stream_tests.rs, route_deadline_tests.rs, runtime_carry_tests.rs, scrape_queued_depth_tests.rs, signal_catalog_tests.rs, stop_sequence_cap_degrade_tests.rs, stream_no_usage_bills_zero_tests.rs, translate_offload_tests.rs, unreadable_usage_floor_tests.rs, usage_tap_tests.rs, view_parity_tests.rs, wire_tests.rs}`;
/// * `busbar-llm/src/testkit/{mod.rs, shell.rs}`;
/// * `busbar-llm/src/tests/{arrival_tests.rs, plane_decl_identity_tests.rs, webhook_tests.rs}`;
/// * `busbar-llm/src/unit/{admit.rs, approve.rs, arrival.rs, audit.rs, authenticate.rs, chain.rs, decode.rs, meter.rs, mod.rs, node.rs, route.rs, verify.rs, walk.rs}`;
/// * `busbar-llm/src/unit/tests/{admit.rs, approve.rs, arrival.rs, audit.rs, authenticate.rs, chain.rs, decode.rs, meter.rs, route.rs, verify.rs}`;
pub const PLANE_FLOOR: usize = 488;

/// THE KINDS THAT MAKE UP THE PLANE ABI'S NEUTRAL SIDE. The population is the census's
/// (`kind_isolation::neutral_census`), read off the kind table, so a crate seated under one of these
/// kinds is scanned the day it lands; this is kind vocabulary (Law 1: core hard-codes the kinds),
/// not a roster of crates. The neutral-family kinds NOT here are excluded for the reason
/// `planes::neutral_src_roots` gave by hand: `root` constructs planes by name (THE DESIGN §1, "the
/// only place that names which crates exist and wires them at boot"; its source is held to zero by
/// `kind-isolation:law0`), and `store`/`secret`/`auth`/`hooks`/`export` are plugin instances, which
/// name their own protocol by definition (Law 5).
pub const NEUTRAL_KINDS: &[&str] = &["kernel", "contract", "plugin-tooling", "cleanliness"];

/// The measurement both the `--check` gate and the `--strict` ratchet are built from: one walk,
/// one scanner, four passes, and the accounting the zero-file guard reports.
pub struct Measurement {
    pub neutral_roots: Vec<String>,
    /// THE NEUTRAL WALK ITSELF: every `.rs` under the present neutral roots, as the forward scan
    /// read it. The freeze witness measures the same population, so it reads this list rather than
    /// walking the same roots a second time on every run.
    pub neutral: Vec<SourceFile>,
    pub plane_roots: Vec<String>,
    /// `(crates/<dir>, why)` for every crate the census cannot classify: in no population, so in no
    /// scan, and RED on [`ROW_ROOTS`].
    pub unclassified: Vec<(String, String)>,
    pub neutral_files: usize,
    pub plane_files: usize,
    /// Forward hits in PRODUCTION scope — the scan `--check` judges.
    pub prod_forward: Vec<Hit>,
    /// Forward hits in TEST scope — what `--strict` adds, never double-counted against the above.
    pub test_forward: Vec<Hit>,
    pub prod_reverse: Vec<Hit>,
    pub test_reverse: Vec<Hit>,
    /// Every reasoned frozen-wire pragma in the neutral crates — the claims [`claims::row`] checks.
    pub pragmas: Vec<claims::Pragma>,
    /// The instance vocabulary the forward scan used, DERIVED from this tree (see [`vocab`]).
    pub vocab: Vocab,
    /// The freeze witness's needles, derived from the LLM plane's IR declarations
    /// ([`freeze::derive_types`]), and how many declarations the derivation read.
    pub ir_types: Vec<String>,
    pub ir_declared: usize,
    /// The segment-debt rows (`qa/segment-debt.toml`) and, per row, whether a live hit of THIS
    /// scan matched it. The listed segment-only hits are already gone from the forward lists above.
    pub segment_debt: Vec<segment_debt::Debt>,
    pub segment_debt_matched: Vec<bool>,
    /// The rows of the list this change wrote over the base's copy ([`segment_debt::minted`]), or
    /// why no base could be read.
    pub segment_debt_minted: Result<Vec<String>, String>,
}

impl Measurement {
    /// The `--check` hit list, in the order the shell wrote it: the forward scan, then the reverse.
    pub fn check_hits(&self) -> Vec<&Hit> {
        self.prod_forward.iter().chain(&self.prod_reverse).collect()
    }

    /// The `#SCAN` provenance line the artefact is prefixed with, so the downstream consumer of the
    /// hit COUNT can tell "clean" from "scanned nothing" without re-deriving the file list.
    pub fn scan_line(&self) -> String {
        format!(
            "#SCAN\tneutral_files={}\tneutral_roots={}\tplane_files={}\tplane_roots={}",
            self.neutral_files,
            self.neutral_roots.len(),
            self.plane_files,
            self.plane_roots.len()
        )
    }
}

/// THE DELEGATED SCAN'S ARTEFACT: the `#SCAN` denominator line, then one TSV row per hit.
///
/// One derivation with two readers. `run` writes it to [`HITS_OUT_ENV`] for a caller outside this
/// process, and the construction gate's `neutral-no-dialect` rule — which does not re-implement
/// dialect policy, it reads this gate's answer — asks [`check_hits_artefact`] for the same bytes
/// without a subprocess. A count read out of a file and a count read out of a return value must be
/// the same count, so they come from the same place.
pub fn hits_artefact(m: &Measurement, hits: &[&Hit]) -> String {
    let mut text = m.scan_line();
    text.push('\n');
    for h in hits {
        text.push_str(&h.tsv());
        text.push('\n');
    }
    text
}

/// The `--check` hit artefact for `cx`, derived in this process.
///
/// This is what replaced `scripts/plane-purity-lint.sh`. The construction gate used to shell out to
/// that script and read the file it left behind; the script is gone, this gate is what it became,
/// and a gate that is already linked into the same binary does not need to be spawned to be asked.
/// The failure mode it removes is the one this rule actually hit: a delegated scan whose SCRIPT had
/// been deleted reported "no hits file" — which is indistinguishable, to a reader of the row, from
/// a scan that ran and found nothing.
pub fn check_hits_artefact(cx: &Ctx) -> Result<String, String> {
    let m = measure(cx)?;
    let hits = m.check_hits();
    Ok(hits_artefact(&m, &hits))
}

/// Every listed root that is not present. A listed root that does not exist is scanned as zero
/// files, and zero is the passing answer to every ban — so a crate that is legitimately gone leaves
/// the set by being DELETED from [`crate::planes`] in a reviewed diff, never by its directory
/// quietly ceasing to exist under a stale entry.
fn missing_roots(cx: &Ctx, roots: &[String]) -> Vec<String> {
    roots
        .iter()
        .filter(|r| !root_present(cx, r))
        .cloned()
        .collect()
}

/// A source root is PRESENT when it is on disk (or laid by the base layer), or when the context's
/// overlay plants a file under it — a crate a selftest or a test lands is a crate of the tree for
/// every rule, and [`Ctx::exists`] answers only for paths the overlay names exactly.
fn root_present(cx: &Ctx, root: &str) -> bool {
    let removed = cx.overlay().is_some_and(|ov| {
        ov.changes()
            .any(|(p, c)| matches!(c, crate::ctx::Change::Absent) && p.as_path() == Path::new(root))
    });
    !removed
        && (cx.exists(root)
            || cx.overlay().is_some_and(|ov| {
                ov.changes().any(|(p, c)| {
                    matches!(c, crate::ctx::Change::Content(_)) && p.starts_with(root)
                })
            }))
}

fn measure(cx: &Ctx) -> Result<Measurement, String> {
    // THE NEUTRAL POPULATION COMES FROM THE KIND TABLE TOO (Law 8: "a roster maintained by hand is
    // a defect with a date on it"). It was `planes::neutral_src_roots`, a thirteen-entry list a new
    // kernel crate joined only when somebody remembered it.
    let census = crate::gates::kind_isolation::neutral_census(cx)?;
    let neutral_roots: Vec<String> = census
        .neutral
        .iter()
        .filter(|r| {
            census
                .kind_of
                .get(r.as_str())
                .is_some_and(|k| NEUTRAL_KINDS.contains(k))
        })
        .cloned()
        .collect();
    // THE PLANE POPULATION COMES FROM THE KIND TABLE, not from a list in `planes`: see
    // `kind_isolation::plane_kind_src_roots`. `busbar-plane-*` was plane-kind and in no scan, and
    // after the dialect split every `busbar-plane-<p>-<d>` crate would have had to be added by hand
    // — a plane crate nobody added is a plane crate the backwards rule scans zero files of.
    let plane_roots = crate::gates::kind_isolation::plane_kind_src_roots(cx)?;
    let present: Vec<String> = neutral_roots
        .iter()
        .filter(|r| root_present(cx, r))
        .cloned()
        .collect();
    // `allow_empty`, because THIS GATE REFUSES THE EMPTY SCAN ITSELF, by name, in
    // [`ROW_DENOMINATOR`]. Left to the walk, a zero-file scan came back as an error and every row
    // read "the tree could not be scanned" — true, but it is not the row that owns the finding.
    let neutral: Vec<SourceFile> = cx
        .walk(&WalkSpec::new(present).ext("rs").allow_empty())
        .map_err(|e| e.to_string())?;
    let present: Vec<String> = plane_roots
        .iter()
        .filter(|r| root_present(cx, r))
        .cloned()
        .collect();
    let plane: Vec<SourceFile> = cx
        .walk(&WalkSpec::new(present).ext("rs").allow_empty())
        .map_err(|e| e.to_string())?;
    // THE WORDS COME FROM THE TREE BEING SCANNED. Derived after the plane walk because the planes
    // declare their own keys and dialects in the files that walk just read.
    let mut vocab = vocab::derive(cx, &plane_roots, &plane);
    // THE REVERSE NEEDLES COME FROM THE TREE: every crate past the plane's wall, by its identifier.
    // An empty answer is refused on the denominator row, beside the other empty classes.
    vocab.wall_idents = crate::gates::kind_isolation::plane_wall_crates(cx)
        .map(|names| names.iter().map(|n| n.replace('-', "_")).collect())
        .unwrap_or_default();
    let (ir_types, ir_declared) = freeze::derive_types(&plane);
    let (prod_forward, test_forward) = scanner::scan(&neutral, Mode::Forward, &vocab);
    let (prod_reverse, test_reverse) = scanner::scan(&plane, Mode::Reverse, &vocab);
    // LISTED SEGMENT DEBT IS NOT COUNTED; UNLISTED SEGMENT HITS ARE. Every count downstream (the
    // DIALECT row, the strict ceilings, the construction gate's hit artefact) reads these lists, so
    // the debt is drained out of them once, here, and a segment hit nobody listed stays in as the
    // DIALECT hit it is.
    let segment_debt = segment_debt::load(cx)?;
    let segment_debt_minted = segment_debt::minted(cx, &segment_debt);
    let mut segment_debt_matched = vec![false; segment_debt.len()];
    let prod_forward =
        segment_debt::drain_listed(&segment_debt, &mut segment_debt_matched, prod_forward);
    let test_forward =
        segment_debt::drain_listed(&segment_debt, &mut segment_debt_matched, test_forward);
    Ok(Measurement {
        neutral_files: neutral.len(),
        plane_files: plane.len(),
        prod_forward,
        test_forward,
        prod_reverse,
        test_reverse,
        neutral_roots,
        plane_roots,
        unclassified: census.unclassified,
        pragmas: claims::collect(&neutral),
        neutral,
        vocab,
        ir_types,
        ir_declared,
        segment_debt,
        segment_debt_matched,
        segment_debt_minted,
    })
}

/// The category rows, built from a hit list. Shared by [`PlanePurityGate::run`] and by the parity
/// adapter, which builds the SAME rows out of the legacy script's own hit artefact — so identical
/// rows means identical HIT SETS, not two prose parsers agreeing with each other.
fn category_rows(hits: &[&Hit]) -> Vec<Row> {
    let mut out = Vec::new();
    for (category, id) in [
        ("PATH-INCLUDE", ROW_PATH_INCLUDE),
        ("SYMBOL", ROW_SYMBOL),
        ("TYPE", ROW_TYPE),
        ("KEY", ROW_KEY),
        ("DIALECT", ROW_DIALECT),
        ("BACKWARDS", ROW_BACKWARDS),
    ] {
        let sites: Vec<String> = hits
            .iter()
            .filter(|h| h.category == category)
            .map(|h| h.site())
            .collect();
        let detail = if sites.is_empty() {
            "0 hit(s)".to_string()
        } else {
            format!("{} hit(s): {}", sites.len(), sites.join(" "))
        };
        out.push(if sites.is_empty() {
            Row::pass(id, category_title(category), detail)
        } else {
            Row::fail(id, category_title(category), detail)
        });
    }
    out
}

fn category_title(category: &str) -> &'static str {
    match category {
        "PATH-INCLUDE" => "no plane source is dual-compiled into a neutral crate",
        "SYMBOL" => "no neutral crate binds a plane crate under any spelling",
        "TYPE" => "no neutral crate names a plane or dialect type",
        "KEY" => "no neutral crate names a concrete plane key",
        "DIALECT" => "no neutral crate names a dialect",
        _ => "no plane crate reaches past the contract into the kernel or another neutral crate",
    }
}

fn roots_row(
    neutral_roots: usize,
    plane_roots: usize,
    missing: &[String],
    unclassified: &[(String, String)],
) -> Row {
    let detail = format!("neutral_roots={neutral_roots} plane_roots={plane_roots}");
    if !unclassified.is_empty() {
        return Row::fail(
            ROW_ROOTS,
            "a crate the census cannot classify is in no scan",
            format!(
                "{detail} — unclassified: {}. A crate in no population is a crate in no gate; seat \
                 it in the kind table.",
                unclassified
                    .iter()
                    .map(|(d, why)| format!("{d} ({why})"))
                    .collect::<Vec<_>>()
                    .join("; ")
            ),
        );
    }
    if missing.is_empty() {
        Row::pass(
            ROW_ROOTS,
            "every listed source root is present on disk",
            detail,
        )
    } else {
        Row::fail(
            ROW_ROOTS,
            "a listed source root is not present on disk",
            format!(
                "{detail} — missing: {}. A listed root that does not exist is scanned as ZERO \
                 files, and zero passes every ban; delete the entry in a reviewed diff instead.",
                missing.join(" ")
            ),
        )
    }
}

/// The denominator: the files the scan opened, AND the words it had to scan them with. A scan with
/// no plane keys, no transports or no dialects answers "clean" about that class whatever the tree
/// says, which is the same false zero as a scan of no files — so the derived vocabulary is refused
/// here, by class, beside the file counts. `vocab` is `None` only for the legacy half, which never
/// had a vocabulary to report.
fn denominator_row(neutral_files: usize, plane_files: usize, vocab: Option<&Vocab>) -> Row {
    let mut detail = format!("neutral_files={neutral_files} plane_files={plane_files}");
    let empty = vocab.map(Vocab::empty_classes).unwrap_or_default();
    if let Some(v) = vocab {
        detail.push_str(&format!(" vocabulary: {}", v.summary()));
    }
    if neutral_files < NEUTRAL_FLOOR || plane_files < PLANE_FLOOR {
        Row::fail(
            ROW_DENOMINATOR,
            "the scan opened files to answer with",
            format!(
                "{detail} — below its floor (neutral {NEUTRAL_FLOOR}, plane {PLANE_FLOOR}): a \
                 shrunken scan reports fewer violations, which is indistinguishable from a cleaner \
                 tree"
            ),
        )
    } else if !empty.is_empty() {
        Row::fail(
            ROW_DENOMINATOR,
            "the scan derived words to answer with",
            format!(
                "{detail} — the tree yielded NO {} to scan for, and a ban with no words bans \
                 nothing. The vocabulary is derived from the instance crates and their \
                 declarations; if they moved, fix the derivation, never hand-type a list here.",
                empty.join(", no ")
            ),
        )
    } else {
        Row::pass(
            ROW_DENOMINATOR,
            "the scan opened files to answer with",
            detail,
        )
    }
}

/// `plane-purity:segment-debt`: RED for (i) a segment-only dialect hit in the production neutral
/// scope that no row of `qa/segment-debt.toml` lists, and (ii) a listed row that matches no live
/// hit of the neutral scan (stale: the debt was paid, strike the row).
fn segment_debt_row(m: &Measurement) -> Row {
    let unlisted: Vec<String> = m
        .prod_forward
        .iter()
        .filter(|h| h.category == "DIALECT" && h.segment)
        .map(|h| format!("{} `{}`", h.site(), h.code))
        .collect();
    // Only a row whose file sits under a root THIS scan walks can be judged stale here; the rest
    // belong to the other population (kind-isolation's vendor scan) and are judged there.
    let stale: Vec<String> = m
        .segment_debt
        .iter()
        .zip(&m.segment_debt_matched)
        .filter(|(d, matched)| {
            !**matched
                && m.neutral_roots
                    .iter()
                    .any(|r| d.file.starts_with(&format!("{r}/")))
        })
        .map(|(d, _)| format!("{} `{}`", d.site(), d.text))
        .collect();
    let (minted, no_base) = match &m.segment_debt_minted {
        Ok(rows) => (rows.clone(), None),
        Err(e) => (Vec::new(), Some(e.clone())),
    };
    let title = "no neutral crate names a dialect as an identifier segment beyond the listed debt";
    if unlisted.is_empty() && stale.is_empty() && minted.is_empty() && no_base.is_none() {
        return Row::pass(
            ROW_SEGMENT_DEBT,
            title,
            format!(
                "{} listed row(s), each matching a live hit",
                m.segment_debt.len()
            ),
        );
    }
    let mut detail = Vec::new();
    if !unlisted.is_empty() {
        detail.push(format!(
            "{} unlisted segment-only hit(s) (the list is drain-only; name the dialect in its \
             plane, never in a neutral crate): {}",
            unlisted.len(),
            unlisted.join("; ")
        ));
    }
    if !stale.is_empty() {
        detail.push(format!(
            "{} stale row(s) in {} matching no live hit — strike it: {}",
            stale.len(),
            segment_debt::SEGMENT_DEBT_TOML,
            stale.join("; ")
        ));
    }
    if !minted.is_empty() {
        detail.push(format!(
            "{} MINTED row(s) — written by this change beside the hit they forgive; the list is \
             drain-only, so name the dialect in its plane instead: {}",
            minted.len(),
            minted.join("; ")
        ));
    }
    if let Some(e) = no_base {
        detail.push(e);
    }
    Row::fail(ROW_SEGMENT_DEBT, title, detail.join(" | "))
}

fn freeze_row(f: &freeze::Freeze) -> Row {
    let detail = format!("count={} defs={} uprefs={}", f.count, f.defs, f.uprefs);
    if f.count == 0 {
        Row::pass(
            ROW_FREEZE,
            "core names zero concrete LLM-family IR type",
            detail,
        )
    } else {
        Row::fail(
            ROW_FREEZE,
            "core still names a concrete LLM-family IR type",
            format!("{detail} — the freeze is not met while core reads the request as a family"),
        )
    }
}

// ── the `--check` gate ────────────────────────────────────────────────────────────────────────

pub struct PlanePurityGate;

impl Gate for PlanePurityGate {
    fn name(&self) -> &'static str {
        "plane-purity"
    }

    fn owed(&self) -> Vec<String> {
        [
            ROW_ROOTS,
            ROW_DENOMINATOR,
            ROW_PATH_INCLUDE,
            ROW_SYMBOL,
            ROW_TYPE,
            ROW_KEY,
            ROW_DIALECT,
            ROW_BACKWARDS,
            ROW_FREEZE,
            ROW_FROZEN_WIRE_CLAIM,
            ROW_SEGMENT_DEBT,
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let m = match measure(cx) {
            Ok(m) => m,
            Err(e) => return Verdict::of(unscannable(&self.owed(), &e)),
        };
        let missing: Vec<String> = missing_roots(cx, &m.neutral_roots)
            .into_iter()
            .chain(missing_roots(cx, &m.plane_roots))
            .collect();
        let denominator = denominator_row(m.neutral_files, m.plane_files, Some(&m.vocab));
        let scanned_nothing = denominator.status != crate::ledger::Status::Pass;
        let mut rows = vec![
            roots_row(
                m.neutral_roots.len(),
                m.plane_roots.len(),
                &missing,
                &m.unclassified,
            ),
            denominator,
        ];
        let hits = m.check_hits();
        // A CATEGORY ROW OVER A ZERO-FILE SCAN IS NOT A PASS. Every rule here answers a question
        // about a file list, and every one of those answers is "clean" when the list is empty.
        if scanned_nothing {
            for id in [
                ROW_PATH_INCLUDE,
                ROW_SYMBOL,
                ROW_TYPE,
                ROW_KEY,
                ROW_DIALECT,
                ROW_BACKWARDS,
            ] {
                rows.push(Row::fail(
                    id,
                    "the rule was not applied to anything",
                    format!(
                        "neutral_files={} plane_files={} — zero hits over zero files is not a \
                         clean tree",
                        m.neutral_files, m.plane_files
                    ),
                ));
            }
            rows.push(Row::fail(
                ROW_FROZEN_WIRE_CLAIM,
                "the rule was not applied to anything",
                format!(
                    "neutral_files={} — zero pragmas over zero files is not a verified set",
                    m.neutral_files
                ),
            ));
            rows.push(Row::fail(
                ROW_SEGMENT_DEBT,
                "the rule was not applied to anything",
                format!(
                    "neutral_files={} — zero segment hits over zero files is not a clean tree",
                    m.neutral_files
                ),
            ));
        } else {
            rows.extend(category_rows(&hits));
            rows.push(claims::row(cx, ROW_FROZEN_WIRE_CLAIM, &m.pragmas, &m.vocab));
            rows.push(segment_debt_row(&m));
        }

        // The hit artefact, for the one delegated consumer that reads hit COUNTS out of it. Written
        // only when asked for by name, and prefixed with its own denominator.
        if let Some(path) = std::env::var_os(HITS_OUT_ENV) {
            let _ = std::fs::write(PathBuf::from(path), hits_artefact(&m, &hits));
        }

        // Every PRESENT neutral root: a missing one is `ROW_ROOTS`'s finding, and handing it to
        // the walk would turn this row into "could not be scanned" instead of the count it owns.
        // THE FREEZE WALKS THE SAME DERIVED POPULATION AND IS HELD TO THE SAME FLOOR. It was `1`.
        // It is the forward scan's own walk (the present neutral roots, `.rs`, empty allowed), read
        // once in `measure`: walking the same roots again here doubled every run's reads.
        let core: &[SourceFile] = &m.neutral;
        if m.ir_declared < freeze::DECLARED_FLOOR {
            rows.push(Row::fail(
                ROW_FREEZE,
                "the LLM IR family could not be derived",
                format!(
                    "declared={} — below its floor {}: the LLM plane's codec/ir/ module yielded \
                     fewer type declarations than it held, so the needle set is short and a zero \
                     over it is not a freeze met",
                    m.ir_declared,
                    freeze::DECLARED_FLOOR
                ),
            ));
        } else if core.len() < NEUTRAL_FLOOR {
            rows.push(Row::fail(
                ROW_FREEZE,
                "core could not be scanned for concrete LLM-family types",
                format!(
                    "files={} — below its floor {NEUTRAL_FLOOR}: a count of zero over a shrunken \
                     walk is not a freeze met",
                    core.len()
                ),
            ));
        } else {
            let homonyms = freeze::neutral_homonyms(core, &m.neutral_roots, &m.ir_types);
            let needles: Vec<String> = m
                .ir_types
                .iter()
                .filter(|t| !homonyms.contains(t))
                .cloned()
                .collect();
            let mut row = freeze_row(&freeze::measure(core, &m.neutral_roots, &needles));
            if !homonyms.is_empty() {
                row.detail.push_str(&format!(
                    " homonyms={} (bound by the neutral set itself, not counted)",
                    homonyms.join(",")
                ));
            }
            rows.push(row);
        }
        Verdict::of(rows)
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        let owed: Vec<String> = self.owed();
        let all: Vec<&str> = owed.iter().map(String::as_str).collect();

        // EVERY CASE BELOW IS ASKED OVER A BASELINE WHOSE ROWS ARE GREEN (1.6.0 item 89). The
        // tree carries standing reds on some of these rows — `symbol` and `dialect` on the day this
        // was written — and a plant into a row that is ALREADY red proves nothing: `prove_red`
        // scores it PROOF IMPOSSIBLE, correctly, and the rule it names could be deleted with no
        // case noticing. So the files the unplanted tree's hits sit in are set aside (blanked in
        // the overlay) ONCE, and every plant is layered on top of that. The real tree is untouched
        // and stays RED on `cargo xtask gate plane-purity`; what changes is that each case now has
        // a green row to move. The set-aside is DERIVED from the gate's own hits, so a standing red
        // that is drained shrinks it and a new one grows it — nothing here names a file.
        //
        // The set-aside is laid over `cx` with its base PINNED to `HEAD`: the segment-debt row
        // compares the list with the base's copy, and a detached battery checkout has no other.
        let pinned = crate::gates::construction::ceilings::with_head_pin(cx);
        let base = pinned.with_overlay(layered(&pinned).layered(&standing_red_set_aside(cx)));
        let cx: &Ctx = &base;

        report.push(prove_green(
            cx,
            self,
            "with the standing-red sites set aside, every row is green — the gate does not fire \
             on everything",
            &all,
        ));

        // Every RED case plants into the FIRST neutral root, so the plant is inside the walk the
        // gate actually performs rather than beside it.
        // The populations are the gate's own derivation, read off the same measurement.
        let (neutral, plane_roots): (Vec<String>, Vec<String>) = match measure(cx) {
            Ok(m) => (
                m.neutral_roots
                    .into_iter()
                    .filter(|r| root_present(cx, r))
                    .collect(),
                m.plane_roots
                    .into_iter()
                    .filter(|r| root_present(cx, r))
                    .collect(),
            ),
            Err(e) => {
                report.note_infra_failure(format!(
                    "plane-purity: the tree could not be measured: {e}"
                ));
                return report;
            }
        };
        if neutral.is_empty() || plane_roots.is_empty() {
            report.note_infra_failure(
                "plane-purity: the derived neutral or plane population is empty on disk"
                    .to_string(),
            );
            return report;
        }
        let plant_at = format!("{}/planted_plane_purity.rs", neutral[0]);
        let plane_at = format!("{}/planted_plane_purity.rs", plane_roots[0]);

        report.push(create(
            cx,
            self,
            "a #[path] dual-compile of plane source into a neutral crate",
            &[ROW_PATH_INCLUDE],
            &plant_at,
            "#[path = \"../../../busbar-plane-mcp/src/witness.rs\"]\nmod mcp_witness;\n",
            &[ROW_PATH_INCLUDE, "planted_plane_purity.rs:1"],
        ));

        // The OTHER dual-compile spelling. It used to fall through to the vocabulary rules, which
        // sit BELOW the pragma gate — so one trailing comment spliced a plane's source into a
        // neutral crate under a clean report. The pragma is on the fixture on purpose. Its target
        // is a plane directory the tree still derives (the one the `#[path]` case above proves
        // live): the instance directories are derived, so a plant naming a deleted crate
        // (`busbar-a2a/`, gone with the a2a extraction) names no plane and proves nothing.
        report.push(create(
            cx,
            self,
            "an include! dual-compile, carrying a pragma that must not launder it",
            &[ROW_PATH_INCLUDE],
            &plant_at,
            "include!(\"../../../busbar-plane-mcp/src/witness.rs\"); // plane-purity: frozen-wire abuse\n",
            &[ROW_PATH_INCLUDE, "planted_plane_purity.rs:1"],
        ));

        report.push(create(
            cx,
            self,
            "a busbar_<plane>:: symbol path in a neutral crate",
            &[ROW_SYMBOL],
            &plant_at,
            "use busbar_plane_a2a::TaskThing;\n",
            &[ROW_SYMBOL, "planted_plane_purity.rs:1"],
        ));

        report.push(create(
            cx,
            self,
            "the two symbol spellings that carry no :: on the line",
            &[ROW_SYMBOL],
            &plant_at,
            "extern crate busbar_mcp;\nuse busbar_plane_a2a as plane_alias;\n",
            &[ROW_SYMBOL, "planted_plane_purity.rs:2"],
        ));

        report.push(create(
            cx,
            self,
            "a plane record type in a neutral crate",
            &[ROW_TYPE],
            &plant_at,
            "pub struct McpFoo;\n",
            &[ROW_TYPE, "planted_plane_purity.rs:1"],
        ));

        report.push(create(
            cx,
            self,
            "the screaming-acronym type spellings",
            &[ROW_TYPE],
            &plant_at,
            "pub struct MCPCallRecord;\npub struct OpenAIClient;\npub struct LLMRouter;\n",
            &[ROW_TYPE, "planted_plane_purity.rs:3"],
        ));

        report.push(create(
            cx,
            self,
            "a bare plane key as a token in a neutral crate",
            &[ROW_KEY],
            &plant_at,
            "fn route() { let plane_key = \"mcp\"; }\n",
            &[ROW_KEY, "planted_plane_purity.rs:1"],
        ));

        report.push(create(
            cx,
            self,
            "a dialect name as a token in a neutral crate",
            &[ROW_DIALECT],
            &plant_at,
            "fn d() { let dialect = \"anthropic\"; }\n",
            &[ROW_DIALECT, "planted_plane_purity.rs:1"],
        ));

        // A MARKER WITH NO REASON IS NOT A PRAGMA. "One pragma per excused line, each justifying
        // itself in the diff" is the entire reviewability of the carve-out; a bare marker excusing
        // a line names no contract and cannot be reviewed. The reasoned form of the SAME line is
        // the green control immediately after, so this case proves the reason, not the tokens.
        report.push(create(
            cx,
            self,
            "a frozen-wire marker with no reason excuses nothing",
            &[ROW_KEY, ROW_TYPE],
            &plant_at,
            "pub(crate) mcp: McpEndpointSection, // plane-purity: frozen-wire\n",
            &[ROW_KEY, ROW_TYPE],
        ));

        report.push(green_with(
            cx,
            self,
            "a reasoned frozen-wire pragma exempts the vocabulary rows on its line only",
            &[ROW_KEY, ROW_TYPE, ROW_DIALECT],
            &plant_at,
            "pub(crate) mcp: McpEndpointSection, // plane-purity: frozen-wire DeployCfg mcp: key \
             + snapshot type\n",
        ));

        // THE CLAIM IS CHECKED AGAINST THE TAG IT NAMES (item 2). Each of the three refusals is its
        // own case, because a single plant that tripped all three would let any one of them be
        // deleted with the selftest still green; the true claim beside them is the control that
        // proves the row reads the tag rather than refusing every pragma. The plants name no plane
        // or dialect, so no vocabulary row moves and the case is about the claim alone.
        report.push(create(
            cx,
            self,
            "a frozen-since claim naming a key absent at that tag is refused",
            &[ROW_FROZEN_WIRE_CLAIM],
            &plant_at,
            "pub const K: u8 = 0; // plane-purity: frozen-wire the `brand_new_key:` wire key \
             (frozen since 1.5.3)\n",
            &[
                ROW_FROZEN_WIRE_CLAIM,
                "planted_plane_purity.rs:1",
                "brand_new_key:",
            ],
        ));

        report.push(create(
            cx,
            self,
            "a frozen-wire pragma stating no frozen-since release is refused",
            &[ROW_FROZEN_WIRE_CLAIM],
            &plant_at,
            "pub const K: u8 = 0; // plane-purity: frozen-wire the `protocol:` wire key\n",
            &[
                ROW_FROZEN_WIRE_CLAIM,
                "planted_plane_purity.rs:1",
                "no `frozen since X.Y.Z`",
            ],
        ));

        report.push(create(
            cx,
            self,
            "a frozen-since claim naming a tag that does not resolve is refused",
            &[ROW_FROZEN_WIRE_CLAIM],
            &plant_at,
            "pub const K: u8 = 0; // plane-purity: frozen-wire the `protocol:` wire key \
             (frozen since 9.9.9)\n",
            &[ROW_FROZEN_WIRE_CLAIM, "planted_plane_purity.rs:1", "v9.9.9"],
        ));

        report.push(green_with(
            cx,
            self,
            "a frozen-since claim whose key the tag carries is honoured",
            &[ROW_FROZEN_WIRE_CLAIM],
            &plant_at,
            "pub const K: u8 = 0; // plane-purity: frozen-wire the omitted-`protocol:` default \
             (frozen since 1.5.3)\n",
        ));

        report.push(create(
            cx,
            self,
            "a plane crate reaching past the contract into the kernel, under all three spellings",
            &[ROW_BACKWARDS],
            &plane_at,
            "use busbar_kernel::plane_host::EngineHost;\nextern crate busbar_kernel_ledger;\nuse busbar_core_admin as c;\n",
            &[
                ROW_BACKWARDS,
                "planted_plane_purity.rs:1",
                "planted_plane_purity.rs:2",
                "planted_plane_purity.rs:3",
            ],
        ));

        // A STRING IS NOT A REACH, AND A STRING THAT ENDS DOES NOT HIDE THE CODE AFTER IT. The
        // continuation lines of a multi-line `"…"` and of a raw `r#"…"#` are literal text, so the
        // crate words in their prose bind nothing; the `use … as` on the line after each closes is
        // code and is still the reach it always was. Lines 5 and 9 must be named; the green control
        // below plants the strings alone and must name nothing.
        report.push(create(
            cx,
            self,
            "a backwards reach on the line after a multi-line string and a raw string closes",
            &[ROW_BACKWARDS],
            &plane_at,
            "pub const H: &str =\n    \"serve on stdin\n        busbar as a child process\n        busbar_kernel::teller as t\";\nuse busbar_kernel as k;\npub const R: &str = r#\"a \" quote\n        busbar as a child process\n        busbar_kernel::teller::run_unit\"#;\nuse busbar_kernel_ledger as l;\n",
            &[
                ROW_BACKWARDS,
                "planted_plane_purity.rs:5",
                "planted_plane_purity.rs:9",
            ],
        ));

        // ITS CONTROL: the same strings with no code after them are no reach at all.
        report.push(green_with(
            cx,
            self,
            "crate words inside a multi-line string and a raw string are not a backwards reach",
            &[ROW_BACKWARDS],
            &plane_at,
            "pub const H: &str =\n    \"serve on stdin\n        busbar as a child process\n        busbar_kernel::teller as t\";\npub const R: &str = r#\"a \" quote\n        busbar as a child process\n        busbar_kernel::teller::run_unit\"#;\n",
        ));

        // THE CONTROL: the contract is the one crate a plane may name. A rule that fired on every
        // `busbar_*` path would pass every case above and forbid the ABI itself.
        report.push(green_with(
            cx,
            self,
            "a plane crate naming the contract is not a backwards reach",
            &[ROW_BACKWARDS],
            &plane_at,
            "use busbar_contract::abi::plane::PlaneDecl;\n",
        ));

        // THE WALL IS THE KIND TABLE'S. A kernel crate seated tomorrow is past the wall tomorrow:
        // no word of this plant is in this gate's source.
        report.push(create_many(
            cx,
            self,
            "a NEW kernel crate is past the wall: a plane naming it is a backwards reach",
            &[ROW_BACKWARDS],
            &[
                (
                    "crates/busbar-kernel-quux/Cargo.toml",
                    "[package]\nname = \"busbar-kernel-quux\"\nversion = \"0.0.0\"\n",
                ),
                ("crates/busbar-kernel-quux/src/lib.rs", "pub struct Q;\n"),
                (&plane_at, "use busbar_kernel_quux::Q;\n"),
            ],
            &[ROW_BACKWARDS, "planted_plane_purity.rs:1"],
        ));

        // AND THE NEUTRAL SIDE IS THE KIND TABLE'S. The same new kernel crate is in the forward
        // scan the day it lands.
        report.push(create_many(
            cx,
            self,
            "a NEW kernel crate is in the neutral scan: a plane symbol in it is a SYMBOL hit",
            &[ROW_SYMBOL],
            &[
                (
                    "crates/busbar-kernel-quux/Cargo.toml",
                    "[package]\nname = \"busbar-kernel-quux\"\nversion = \"0.0.0\"\n",
                ),
                (
                    "crates/busbar-kernel-quux/src/lib.rs",
                    "use busbar_plane_a2a::TaskThing;\n",
                ),
            ],
            &[ROW_SYMBOL, "busbar-kernel-quux/src/lib.rs:1"],
        ));

        // THE POPULATION IS THE KIND TABLE'S, AND THIS IS THE CRATE THAT PROVES IT. `busbar-plane-*`
        // is plane-kind by every rule the tree has and was in NO scan: the literal root list held
        // the four `busbar-<key>` crates and the four codec halves, so a backwards reach planted
        // here was scanned by nobody and the gate said "no plane crate reaches back". Delete the
        // kind-derived population and this case goes green while every case above stays red — which
        // is the whole of the difference, and the shape the dialect split multiplies by one crate
        // per dialect.
        report.push(create(
            cx,
            self,
            "a backwards reach in a busbar-plane-* crate, which no literal root list scanned",
            &[ROW_BACKWARDS],
            "crates/busbar-plane-mcp/src/planted_plane_kind.rs",
            "use busbar_kernel::teller::run_unit;\n",
            &[ROW_BACKWARDS, "planted_plane_kind.rs:1"],
        ));

        // The two guards in front of every rule above, because each of them answers "clean" about
        // a tree it never read. They get separate fixtures on purpose: a root that VANISHED and a
        // root that is present but EMPTY are different failures, and a single case that happened to
        // trip both would let either one be deleted with the selftest still green.
        let mut ov = layered(cx);
        ov.remove(&neutral[0]);
        report.push(prove_red(
            cx,
            self,
            "a listed neutral root that is not on disk",
            &[ROW_ROOTS],
            ov,
            &[ROW_ROOTS, &neutral[0]],
        ));

        let mut ov = layered(cx);
        for root in neutral.iter().chain(plane_roots.iter()) {
            for f in cx
                .walk(&WalkSpec::new([root.clone()]).ext("rs"))
                .unwrap_or_default()
            {
                ov.remove(&f.rel);
            }
        }
        report.push(prove_red(
            cx,
            self,
            "roots that are present but opened no files",
            &[ROW_DENOMINATOR],
            ov,
            &[ROW_DENOMINATOR, "neutral_files=0"],
        ));

        // ONE UNDER EACH FLOOR (Law 8 shape 2). Zero is not the only shrunken scan: each walk is
        // cut to one file below its floor, and the row that owns it must refuse. The freeze walk
        // reads the neutral population and is held to the same floor, so it is its own case.
        let shrunk = |roots: &[String], floor: usize| {
            let mut ov = layered(cx);
            let files = cx
                .walk(&WalkSpec::new(roots.to_vec()).ext("rs").allow_empty())
                .unwrap_or_default();
            let cut = (files.len() + 1).saturating_sub(floor);
            for f in files.iter().rev().take(cut) {
                ov.remove(&f.rel);
            }
            ov
        };
        report.push(prove_red(
            cx,
            self,
            "a neutral scan one file under its floor",
            &[ROW_DENOMINATOR],
            shrunk(&neutral, NEUTRAL_FLOOR),
            &[ROW_DENOMINATOR, "below its floor"],
        ));
        report.push(prove_red(
            cx,
            self,
            "a freeze walk one file under its floor",
            &[ROW_FREEZE],
            shrunk(&neutral, NEUTRAL_FLOOR),
            &[ROW_FREEZE, "below its floor"],
        ));
        report.push(prove_red(
            cx,
            self,
            "a plane scan one file under its floor",
            &[ROW_DENOMINATOR],
            shrunk(&plane_roots, PLANE_FLOOR),
            &[ROW_DENOMINATOR, "below its floor"],
        ));

        // THE FREEZE'S WORDS ARE THE LLM PLANE'S DECLARATIONS. An IR type the hand list never held
        // is counted, and so is one the plane declares tomorrow.
        report.push(create(
            cx,
            self,
            "an LLM IR type off the hand list, named in core",
            &[ROW_FREEZE],
            &format!("{}/planted_freeze_witness.rs", neutral[0]),
            "pub fn f(_: IrWebSearch) {}\n",
            &[ROW_FREEZE, "count=1"],
        ));
        report.push(create_many(
            cx,
            self,
            "a NEW IR type the LLM plane declares, named in core",
            &[ROW_FREEZE],
            &[
                (
                    "crates/busbar-plane-llm/src/codec/ir/planted_ir.rs",
                    "pub struct IrZephyrine;\n",
                ),
                (
                    &format!("{}/planted_freeze_witness.rs", neutral[0]),
                    "pub fn f(_: IrZephyrine) {}\n",
                ),
            ],
            &[ROW_FREEZE, "count=1"],
        ));

        // THE CLAIM COVERS WHAT THE LINE CARRIES (Law 10). `providers:` is a real 1.5.5 key; the
        // type on the line is not it.
        report.push(create(
            cx,
            self,
            "a frozen-wire claim naming a real key does not cover a type it never names",
            &[ROW_FROZEN_WIRE_CLAIM],
            &plant_at,
            "pub struct S { pub mcp_v2: McpV2Cfg, } // plane-purity: frozen-wire the `providers:` \
             key (frozen since 1.5.5)\n",
            &[
                ROW_FROZEN_WIRE_CLAIM,
                "planted_plane_purity.rs:1",
                "McpV2Cfg",
            ],
        ));

        // Core still naming a concrete LLM-family IR type.
        report.push(create(
            cx,
            self,
            "core names a concrete LLM-family IR type",
            &[ROW_FREEZE],
            &format!("{}/planted_freeze_witness.rs", neutral[0]),
            "pub fn f(_: IrStreamEvent) {}\n",
            // The row's detail is the COUNTED table and nothing else, because that is all the
            // legacy witness prints and `--parity` compares this row against it. A named site here
            // would be a row the legacy half cannot produce, i.e. a parity diff by construction.
            &[ROW_FREEZE, "count=1"],
        ));

        // THE FREEZE WALKS THE WHOLE NEUTRAL SET (1.6.0 item 218). The same concrete type moved
        // into another neutral crate's `ir/` module is still core naming the family — it walked the
        // kernel alone, so the move declared the freeze met. Planted in the LAST neutral root so
        // the case is not the kernel case above in a different file.
        report.push(create(
            cx,
            self,
            "a concrete LLM-family IR type moved into another neutral crate's ir/ module",
            &[ROW_FREEZE],
            &format!(
                "{}/ir/planted_freeze_witness.rs",
                neutral[neutral.len() - 1]
            ),
            "pub fn f(_: IrStreamEvent) {}\n",
            &[ROW_FREEZE, "count=1 defs=1"],
        ));

        // ── THE VOCABULARY IS THE TREE'S (1.6.0 item 3) ──────────────────────────────────────
        //
        // Before the derivation, a new plane, a new transport and a new dialect named in core moved
        // ZERO rows: the scanner only knew the words somebody had typed into it. Each case below
        // lands a NEW instance the way the tree would — a crate, or a declaration inside a plane —
        // and names it in a neutral crate. No word in any of them appears anywhere in this gate's
        // source, so the only way any of them can go red is that the gate READ it off the tree.
        report.push(create_many(
            cx,
            self,
            "a NEW plane crate is in the vocabulary: its key in a neutral crate is a KEY hit",
            &[ROW_KEY],
            &[
                (
                    "crates/busbar-plane-quux/Cargo.toml",
                    "[package]\nname = \"busbar-plane-quux\"\nversion = \"0.0.0\"\n",
                ),
                (
                    "crates/busbar-plane-quux/src/lib.rs",
                    "pub struct QuuxPlane;\n",
                ),
                (&plant_at, "fn route() { let plane_key = \"quux\"; }\n"),
            ],
            &[ROW_KEY, "planted_plane_purity.rs:1"],
        ));

        report.push(create_many(
            cx,
            self,
            "a NEW transport crate is in the vocabulary: binding it from a neutral crate is a \
             SYMBOL hit",
            &[ROW_SYMBOL, ROW_KEY],
            &[
                (
                    "crates/busbar-transport-quic/Cargo.toml",
                    "[package]\nname = \"busbar-transport-quic\"\nversion = \"0.0.0\"\n",
                ),
                (
                    &plant_at,
                    "use busbar_transport_quic::Dialer;\nfn pick() { let t = \"transport_quic\"; }\n",
                ),
            ],
            &[ROW_SYMBOL, ROW_KEY, "planted_plane_purity.rs:1", "planted_plane_purity.rs:2"],
        ));

        report.push(create_many(
            cx,
            self,
            "a NEW dialect a plane declares is in the vocabulary: naming it in a neutral crate is a \
             DIALECT hit",
            &[ROW_DIALECT],
            &[
                (
                    "crates/busbar-plane-llm/src/planted_dialect.rs",
                    "pub const PLANTED: Dialect = Dialect {\n    name: \"zephyrine\",\n};\n",
                ),
                (&plant_at, "fn d() { let dialect = \"zephyrine\"; }\n"),
            ],
            &[ROW_DIALECT, "planted_plane_purity.rs:1"],
        ));

        // ── THE SEGMENT-DEBT LIST (`qa/segment-debt.toml`) ───────────────────────────────────
        //
        // A dialect written as an identifier SEGMENT (`PROTO_ANTHROPIC`) is invisible to the
        // whole-word rule. Each of the three cases below moves the row for its own reason: a new
        // segment hit nobody listed, a listed row whose line is gone, and the listed hit itself.
        let seg_line = "fn d() { let k = \"PROTO_ANTHROPIC\"; }";
        report.push(create(
            cx,
            self,
            "a dialect named as an identifier segment, listed nowhere, is refused",
            &[ROW_SEGMENT_DEBT, ROW_DIALECT],
            &plant_at,
            &format!("{seg_line}\n"),
            &[
                ROW_SEGMENT_DEBT,
                "planted_plane_purity.rs:1",
                "PROTO_ANTHROPIC",
            ],
        ));

        let debt_now = segment_debt::load(cx).unwrap_or_default();
        let stale_row = segment_debt::Debt {
            file: format!("{}/planted_stale_row.rs", neutral[0]),
            line: 1,
            text: "fn paid_off() { let k = \"PROTO_ANTHROPIC\"; }".to_string(),
            dialect: "anthropic".to_string(),
            owner: "kernel-neutrality lane".to_string(),
        };
        let mut ov = layered(cx);
        let mut rows = debt_now.clone();
        rows.push(stale_row);
        ov.set(segment_debt::SEGMENT_DEBT_TOML, segment_debt::render(&rows));
        report.push(prove_red(
            cx,
            self,
            "a listed segment-debt row that matches no live hit is stale and refused",
            &[ROW_SEGMENT_DEBT],
            ov,
            &[ROW_SEGMENT_DEBT, "planted_stale_row.rs:1", "strike it"],
        ));

        // ROW BY ROW: two identical segment lines against ONE row leave the second unlisted.
        let mut ov = layered(cx);
        let mut rows = debt_now.clone();
        rows.push(segment_debt::Debt {
            file: plant_at.clone(),
            line: 1,
            text: seg_line.to_string(),
            dialect: "anthropic".to_string(),
            owner: "kernel-neutrality lane".to_string(),
        });
        ov.set(segment_debt::SEGMENT_DEBT_TOML, segment_debt::render(&rows));
        if Edit::Create(format!("{seg_line}\n{seg_line}\n"))
            .apply(cx, &plant_at, &mut ov)
            .is_ok()
        {
            report.push(prove_red(
                cx,
                self,
                "a second identical segment line beyond the listed row count is refused",
                &[ROW_SEGMENT_DEBT],
                ov,
                &[ROW_SEGMENT_DEBT, "planted_plane_purity.rs:2"],
            ));
        }

        // THE LIST AGAINST ITS BASE (Law 9). The same listed hit, twice: once with its row on the
        // base's copy of the list too (debt the base already carried: green), and once with the row
        // written by this change alone (a new dialect segment forgiven by a data edit: RED).
        let mut rows = debt_now;
        rows.push(segment_debt::Debt {
            file: plant_at.clone(),
            line: 1,
            text: seg_line.to_string(),
            dialect: "anthropic".to_string(),
            owner: "kernel-neutrality lane".to_string(),
        });
        let listed = segment_debt::render(&rows);
        let unlisted = segment_debt::render(&rows[..rows.len() - 1]);
        let on_base = |was: &str| {
            let mut ov =
                layered(cx).layered(&crate::gates::construction::ceilings::synthetic_base(
                    "zz-segment-debt-base",
                    segment_debt::SEGMENT_DEBT_TOML,
                    was,
                ));
            ov.set(segment_debt::SEGMENT_DEBT_TOML, listed.clone());
            Edit::Create(format!("{seg_line}\n"))
                .apply(cx, &plant_at, &mut ov)
                .ok()
                .map(|()| ov)
        };
        if let Some(ov) = on_base(&listed) {
            report.push(prove_rows_green(
                cx,
                self,
                "a listed segment-only hit is debt, not a DIALECT hit: both rows stay green",
                &[ROW_SEGMENT_DEBT, ROW_DIALECT],
                ov,
            ));
        }
        if let Some(ov) = on_base(&unlisted) {
            report.push(prove_red(
                cx,
                self,
                "a segment-debt row the base's list does not carry is MINTED, and refused",
                &[ROW_SEGMENT_DEBT],
                ov,
                &[ROW_SEGMENT_DEBT, "MINTED", "planted_plane_purity.rs"],
            ));
        }

        // AN EMPTY DERIVATION IS REFUSED. With every dialect declaration gone the scanner has no
        // dialect to scan for, and the dialect row would read "clean" about a tree it could not
        // judge — the same false zero as a scan of no files, and refused on the same row.
        let mut ov = layered(cx);
        let plane_roots =
            crate::gates::kind_isolation::plane_kind_src_roots(cx).unwrap_or_default();
        for f in cx
            .walk(&WalkSpec::new(plane_roots).ext("rs").allow_empty())
            .unwrap_or_default()
        {
            if f.text.contains("Dialect") {
                ov.set(&f.rel, "");
            }
        }
        report.push(prove_red(
            cx,
            self,
            "a tree that yields no dialect to scan for is refused, not scanned as clean",
            &[ROW_DENOMINATOR],
            ov,
            &[ROW_DENOMINATOR, "dialects=0"],
        ));

        report
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_companions(&self) -> Vec<Vec<String>> {
        vec![vec!["scripts/g6-freeze-witness.sh".to_string()]]
    }

    fn legacy_env(&self, scratch: &Path) -> Vec<(String, String)> {
        vec![(
            HITS_OUT_ENV.to_string(),
            scratch.join("legacy-hits.tsv").display().to_string(),
        )]
    }

    fn legacy_rows(&self, _cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        Some(legacy_check_rows(runs))
    }
}

/// Build the legacy half's rows out of what the two scripts MEASURED: the hit artefact (with its
/// `#SCAN` denominator line) and the freeze witness's counted table. Never out of their prose.
fn legacy_check_rows(runs: &[LegacyRun]) -> Result<Vec<Row>, String> {
    let [lint, witness] = runs else {
        return Err(format!(
            "parity: expected the lint and the freeze witness, got {} run(s)",
            runs.len()
        ));
    };
    let path = lint.scratch.join("legacy-hits.tsv");
    let text = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "parity: {} wrote no hit artefact to {} ({e}). stderr: {}",
            lint.argv.join(" "),
            path.display(),
            lint.stderr.trim()
        )
    })?;

    let mut neutral_files = None;
    let mut neutral_roots = None;
    let mut plane_files = None;
    let mut plane_roots = None;
    let mut hits: Vec<Hit> = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.first() == Some(&"#SCAN") {
            for field in &cols[1..] {
                let Some((k, v)) = field.split_once('=') else {
                    continue;
                };
                let n = v.parse::<usize>().ok();
                match k {
                    "neutral_files" => neutral_files = n,
                    "neutral_roots" => neutral_roots = n,
                    "plane_files" => plane_files = n,
                    "plane_roots" => plane_roots = n,
                    _ => {}
                }
            }
            continue;
        }
        if cols.len() < 3 {
            continue;
        }
        let category = scanner::CATEGORIES
            .iter()
            .find(|c| **c == cols[0])
            .ok_or_else(|| format!("parity: the legacy hit list carried category `{}`", cols[0]))?;
        let (file, line_no) = cols[1]
            .rsplit_once(':')
            .ok_or_else(|| format!("parity: the legacy hit list carried site `{}`", cols[1]))?;
        hits.push(Hit {
            category,
            file: file.to_string(),
            line: line_no.parse().unwrap_or(0),
            code: cols[2].to_string(),
            segment: false,
        });
    }

    let (Some(nf), Some(nr), Some(pf), Some(pr)) =
        (neutral_files, neutral_roots, plane_files, plane_roots)
    else {
        return Err(format!(
            "parity: the legacy hit artefact carried no complete #SCAN provenance line, so the \
             legacy side has no denominator to compare. stderr: {}",
            lint.stderr.trim()
        ));
    };

    // The legacy script ABORTS before writing the artefact when a root is missing, so an artefact
    // that exists at all is a run whose roots were all present. The rows say so explicitly rather
    // than leaving the reader to infer it.
    let mut rows = vec![roots_row(nr, pr, &[], &[]), denominator_row(nf, pf, None)];
    rows.extend(category_rows(&hits.iter().collect::<Vec<_>>()));
    rows.push(freeze_row(&parse_freeze_witness(witness)?));
    Ok(rows)
}

/// The freeze witness's three counted lines. It has no artefact, so its own table is the
/// measurement; the numbers are read positionally off the labels it prints.
fn parse_freeze_witness(run: &LegacyRun) -> Result<freeze::Freeze, String> {
    let mut count = None;
    let mut defs = None;
    let mut uprefs = None;
    for line in run.stdout.lines() {
        let Some((label, value)) = line.rsplit_once(':') else {
            continue;
        };
        let Ok(n) = value.trim().parse::<usize>() else {
            continue;
        };
        if label.contains("references to concrete LLM-family IR types") {
            count = Some(n);
        } else if label.contains("in ir/") {
            defs = Some(n);
        } else if label.contains("OUTSIDE ir/") {
            uprefs = Some(n);
        }
    }
    let (Some(count), Some(defs), Some(uprefs)) = (count, defs, uprefs) else {
        return Err(format!(
            "parity: {} printed no counted freeze table (exit {:?}). stderr: {}",
            run.argv.join(" "),
            run.code,
            run.stderr.trim()
        ));
    };
    Ok(freeze::Freeze {
        sites: Vec::new(),
        count,
        defs,
        uprefs,
    })
}

// ── the `--strict` ratchet ────────────────────────────────────────────────────────────────────

/// The strict ratchet is its own registered gate rather than a flag on the one above, because the
/// two are different questions with different owed sets: `plane-purity` asks whether PRODUCTION
/// code carries a side channel (a yes/no the every-push job blocks on), and `plane-purity-strict`
/// asks whether TEST-scope debt has risen above a hand-lowered ceiling. Collapsing them onto a
/// boolean is exactly what `docs/design/BUSBAR-1.6.0.md` Part 1 ("What this means for the gates") risk 5.2 warns about — and a boolean read
/// from the environment is how a floor becomes overridable downward.
/// The two counted tables `--strict` decides against: the six categories, and the per-plane-crate
/// test-reach. Named as a pair because they are always measured, compared and refused together —
/// one of them missing is the short-ledger failure the shell had to be taught out of.
pub type StrictTables = (BTreeMap<String, u64>, BTreeMap<String, u64>);

pub struct PlanePurityStrictGate;

impl PlanePurityStrictGate {
    fn ceilings(cx: &Ctx) -> Result<BTreeMap<String, strict::Ceiling>, String> {
        cx.read(strict::STRICT_TOML)
            .map(|t| strict::parse_ceilings(&t))
    }

    /// The two measured tables: the six categories over production+test scope combined, and the
    /// BACKWARDS class broken out per plane crate over test scope only — one entry per crate of the
    /// DERIVED plane population, keyed by [`reach_key`].
    fn counts(m: &Measurement) -> StrictTables {
        let mut cats: BTreeMap<String, u64> = BTreeMap::new();
        for c in scanner::CATEGORIES {
            let n = if c == "BACKWARDS" {
                (m.prod_reverse.len() + m.test_reverse.len()) as u64
            } else {
                m.prod_forward.iter().filter(|h| h.category == c).count() as u64
                    + m.test_forward.iter().filter(|h| h.category == c).count() as u64
            };
            cats.insert(c.to_string(), n);
        }
        let mut reach: BTreeMap<String, u64> = BTreeMap::new();
        for root in &m.plane_roots {
            let prefix = format!("{}/", root.strip_suffix("/src").unwrap_or(root));
            *reach.entry(reach_key(root)).or_default() += m
                .test_reverse
                .iter()
                .filter(|h| h.file.starts_with(&prefix))
                .count() as u64;
        }
        (cats, reach)
    }
}

/// The base comparison as the rows read it: `Ok((base, raises))`, or why no base could be read.
type BaseCheck = Result<(String, Vec<strict::Raise>), String>;

/// A row's verdict: its measured decisions, then the base. A raise over the base on any key the row
/// owns is RED whatever the measurement says, and a base that could not be read is RED.
fn strict_row(
    id: String,
    title: String,
    decided: Vec<String>,
    red: bool,
    keys: &dyn Fn(&str) -> bool,
    base: &BaseCheck,
) -> Row {
    let mut detail = decided.join("; ");
    let mut red = red;
    match base {
        Ok((sha, raises)) => {
            let mine: Vec<String> = raises
                .iter()
                .filter(|r| keys(&r.key))
                .map(|r| {
                    format!(
                        "{} = {} raised over the base {sha}'s {}",
                        r.key, r.now, r.was
                    )
                })
                .collect();
            if !mine.is_empty() {
                red = true;
                detail.push_str(&format!(
                    " — ceiling raised in this change (Law 9: a ceiling refuses every rise): {}",
                    mine.join("; ")
                ));
            }
        }
        Err(e) => {
            red = true;
            detail.push_str(&format!(" — {e}"));
        }
    }
    Row::new(
        if red {
            crate::ledger::Status::Fail
        } else {
            crate::ledger::Status::Pass
        },
        id,
        title,
        detail,
    )
}

fn strict_rows(
    ceilings: &BTreeMap<String, strict::Ceiling>,
    cats: &BTreeMap<String, u64>,
    reach: &BTreeMap<String, u64>,
    base: &BaseCheck,
) -> Vec<Row> {
    let mut rows = Vec::new();
    for c in scanner::CATEGORIES {
        let id = strict_category_row(c);
        // AN UNMEASURED ROW IS NOT A MET CEILING. The shell's two `while read` loops ran zero
        // times over a ledger written with `cp … || true` and printed every ceiling met.
        let Some(measured) = cats.get(c) else {
            rows.push(Row::fail(
                id,
                format!("the {c} category was measured"),
                "no measurement for this category — an uncompared row reads as a ceiling met"
                    .to_string(),
            ));
            continue;
        };
        let d = strict::decide(ceilings, c, *measured);
        rows.push(strict_row(
            id,
            format!("{c} is within its ceiling"),
            vec![d.detail()],
            d.red(),
            &|k| k == c,
            base,
        ));
    }
    // ONE ROW OVER EVERY PLANE CRATE. An empty table is a population that measured nothing, and is
    // refused rather than read as every crate within its ceiling.
    if reach.is_empty() {
        rows.push(Row::fail(
            ROW_STRICT_REACH,
            "every plane crate's test-reach was measured",
            "no plane crate was measured — an uncompared row reads as a ceiling met".to_string(),
        ));
        return rows;
    }
    let mut decided = Vec::new();
    let mut red = false;
    for (k, measured) in reach {
        let d = strict::decide(ceilings, k, *measured);
        red |= d.red();
        decided.push(format!("{k}: {}", d.detail()));
    }
    rows.push(strict_row(
        ROW_STRICT_REACH.to_string(),
        "every plane crate's own test code reaches past the contract within its ceiling"
            .to_string(),
        decided,
        red,
        &|k| !scanner::CATEGORIES.contains(&k),
        base,
    ));
    rows
}

impl Gate for PlanePurityStrictGate {
    fn name(&self) -> &'static str {
        "plane-purity-strict"
    }

    fn owed(&self) -> Vec<String> {
        scanner::CATEGORIES
            .iter()
            .map(|c| strict_category_row(c))
            .chain([ROW_STRICT_REACH.to_string()])
            .collect()
    }

    fn run(&self, cx: &Ctx) -> Verdict {
        let text = match cx.read(strict::STRICT_TOML) {
            Ok(t) => t,
            Err(e) => {
                return Verdict::of(unscannable(
                    &self.owed(),
                    &format!("{}: {e}", strict::STRICT_TOML),
                ))
            }
        };
        let ceilings = strict::parse_ceilings(&text);
        let m = match measure(cx) {
            Ok(m) => m,
            Err(e) => return Verdict::of(unscannable(&self.owed(), &e)),
        };
        let (cats, reach) = Self::counts(&m);
        let base = strict::against_base(cx, &text);
        Verdict::of(strict_rows(&ceilings, &cats, &reach, &base))
    }

    fn selftest<'a>(&'a self, cx: &'a Ctx) -> Report<'a> {
        let mut report = Report::new();
        let owed = self.owed();
        let committed = cx.read(strict::STRICT_TOML).unwrap_or_default();

        // THE BASELINE IS A CEILING FIXTURE, NOT THE COMMITTED FILE. A ratchet is green when the
        // measurement is AT its ceiling, and proving that against whatever the committed ceilings
        // happen to be today would make every case report on the tree's debt rather than on the
        // ratchet — a row already over its committed ceiling cannot be proven red-able by any
        // plant. So every case is asked over a context whose ceilings are the measured counts AND
        // whose base is a SYNTHETIC one carrying the same file, so the base comparison is about the
        // case, never about this checkout's history.
        let measured = match measure(cx) {
            Ok(m) => (Self::counts(&m), m.plane_roots),
            Err(e) => {
                report.note_infra_failure(format!(
                    "plane-purity-strict: the tree could not be measured: {e}"
                ));
                return report;
            }
        };
        let ((cats, reach), plane_roots) = &measured;
        let fixture = ceilings_at(&committed, cats, reach);
        let based = cx.with_overlay(at_base(&fixture));
        let cx: &Ctx = &based;

        report.push(prove_green(
            cx,
            self,
            "a measurement AT its ceiling is green — the ratchet is not a fixed gate",
            &owed.iter().map(String::as_str).collect::<Vec<_>>(),
        ));

        // A QUOTED CEILING. TOML accepts `SYMBOL = "5"`; the shell's `[ n -gt '"5"' ]` was an
        // ERROR that `if` read as "not over the ceiling", so the row stopped enforcing in silence.
        let mut ov = layered(cx);
        ov.set(
            strict::STRICT_TOML,
            fixture.replace("SYMBOL = ", "SYMBOL = \"") + "\n",
        );
        report.push(prove_red(
            cx,
            self,
            "a quoted ceiling is refused, not compared",
            &[&strict_category_row("SYMBOL")],
            ov,
            &["not a bare integer"],
        ));

        // A CEILING RAISED IN THE SAME CHANGE (Law 9). The measurement sits at its fixture ceiling,
        // so only the base comparison can turn the row: the base's copy is the fixture, and the
        // tree raises DIALECT by one over it.
        if let Some(n) = cats.get("DIALECT") {
            let mut ov = layered(cx);
            ov.set(
                strict::STRICT_TOML,
                fixture.replace(
                    &format!("DIALECT = {n}\n"),
                    &format!("DIALECT = {}\n", n + 1),
                ),
            );
            report.push(prove_red(
                cx,
                self,
                "a ceiling raised over the base's copy is refused",
                &[&strict_category_row("DIALECT")],
                ov,
                &["DIALECT", "raised over the base"],
            ));
        }

        // ONE MORE HIT THAN THE CEILING ALLOWS is the ratchet doing its job, and it is planted as a
        // real violation in test scope rather than as a lowered number — a case that only edits the
        // ceilings file proves the comparison, never the scan that feeds it. Each row gets its OWN
        // fixture: floors exercised only together can have all but one deleted with the selftest
        // still green, which is exactly how three of the shell self-tests went blind.
        for (name, id, naming, plant_in, content) in strict_plants(cx, plane_roots) {
            let mut ov = layered(cx);
            if Edit::Create(content.to_string())
                .apply(cx, &plant_in, &mut ov)
                .is_err()
            {
                report.push(Case {
                    name: format!("{name}: one hit more than its ceiling allows"),
                    covers: vec![id],
                    expected: Expect::Red {
                        naming: vec![naming],
                    },
                    got: Expect::Skipped,
                });
                continue;
            }
            report.push(prove_red(
                cx,
                self,
                format!("{name}: one hit more than its ceiling allows"),
                &[&id],
                ov,
                &[&naming, "> ceiling"],
            ));
        }
        report
    }

    fn has_legacy_adapter(&self) -> bool {
        true
    }

    fn legacy_rows(&self, cx: &Ctx, runs: &[LegacyRun]) -> Option<Result<Vec<Row>, String>> {
        Some(legacy_strict_rows(cx, runs))
    }
}

/// `ceilings` laid as the tree's file AND as the copy a synthetic base carries: the base
/// comparison sees no raise, so every other case is about the measurement alone.
fn at_base(ceilings: &str) -> Overlay {
    const SHA: &str = "zz-plane-purity-strict-base";
    let mut ov = Overlay::new();
    ov.set(strict::STRICT_TOML, ceilings.to_string());
    ov.set_command(crate::gates::construction::ceilings::BASE_PIN_KEY, SHA);
    ov.set_command(format!("git-ref:{SHA}"), "1");
    ov.set_command(
        format!("git-show:{SHA}:{}", strict::STRICT_TOML),
        ceilings.to_string(),
    );
    ov
}

/// Rewrite every ceiling to the count measured beside it. A key the file does not carry is
/// APPENDED rather than skipped: a fixture that silently omits a row would prove the row's absence
/// green, which is the very failure the shell's short-ledger floor exists for.
fn ceilings_at(base: &str, cats: &BTreeMap<String, u64>, reach: &BTreeMap<String, u64>) -> String {
    let mut out = String::new();
    let mut written: Vec<&str> = Vec::new();
    for line in base.lines() {
        let key = line.split('=').next().map(str::trim).unwrap_or("");
        if let Some(n) = cats.get(key).or_else(|| reach.get(key)) {
            out.push_str(&format!("{key} = {n}\n"));
            written.push(key);
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    for (k, n) in cats.iter().chain(reach.iter()) {
        if !written.contains(&k.as_str()) {
            out.push_str(&format!("{k} = {n}\n"));
        }
    }
    out
}

/// One plant per strict row: the case's name, the row, the string the red row must carry (the
/// category's row id, or ` <key>: ` in the reach row's per-crate detail), the TEST-SCOPE file to
/// create, and the single line that adds exactly one hit to that row's class. The paths all sit
/// under a `/tests/` segment, which is what puts them in the scope `--strict` adds and `--check`
/// deliberately does not see. The reach plant goes into EVERY plane crate on disk, each its own
/// case, so a crate the population drops is a case that stops going red.
type StrictPlant = (String, String, String, String, &'static str);

fn strict_plants(cx: &Ctx, plane_roots: &[String]) -> Vec<StrictPlant> {
    let neutral_test = |leaf: &str| format!("crates/busbar-kernel/src/tests/{leaf}");
    let cat = |c: &str| (c.to_string(), strict_category_row(c));
    let mut out: Vec<StrictPlant> = Vec::new();
    for (c, leaf, content) in [
        (
            "PATH-INCLUDE",
            "planted_strict_path.rs",
            "#[path = \"../../../busbar-plane-mcp/src/witness.rs\"]\nmod w;\n",
        ),
        (
            "SYMBOL",
            "planted_strict_symbol.rs",
            "use busbar_plane_a2a::TaskThing;\n",
        ),
        ("TYPE", "planted_strict_type.rs", "pub struct McpFoo;\n"),
        (
            "KEY",
            "planted_strict_key.rs",
            "fn k() { let _ = \"mcp\"; }\n",
        ),
        (
            "DIALECT",
            "planted_strict_dialect.rs",
            "fn d() { let _ = \"anthropic\"; }\n",
        ),
    ] {
        let (name, id) = cat(c);
        out.push((name, id.clone(), id, neutral_test(leaf), content));
    }
    let on_disk: Vec<&String> = plane_roots.iter().filter(|r| root_present(cx, r)).collect();
    if let Some(first) = on_disk.first() {
        let (name, id) = cat("BACKWARDS");
        out.push((
            name,
            id.clone(),
            id,
            format!("{first}/tests/planted_strict_backwards.rs"),
            "fn b() { let _ = busbar_kernel::teller::run_unit; }\n",
        ));
    }
    for root in on_disk {
        let key = reach_key(root);
        out.push((
            format!("test-reach {key}"),
            ROW_STRICT_REACH.to_string(),
            format!(" {key}: "),
            format!("{root}/tests/planted_strict_reach.rs"),
            "fn r() { let _ = busbar_kernel::teller::run_unit; }\n",
        ));
    }
    out
}

/// The strict half's legacy rows. `--strict --baseline` prints both counted tables and always
/// exits 0; the ceilings are then applied HERE by the same `decide`, so what parity compares is the
/// MEASUREMENT the two scanners made, which is the only half a rewrite can get wrong.
fn legacy_strict_rows(cx: &Ctx, runs: &[LegacyRun]) -> Result<Vec<Row>, String> {
    let [run] = runs else {
        return Err(format!(
            "parity: expected one legacy run, got {}",
            runs.len()
        ));
    };
    let ceilings = PlanePurityStrictGate::ceilings(cx)?;
    let text = cx.read(strict::STRICT_TOML)?;
    let plane_keys: Vec<String> = crate::gates::kind_isolation::plane_kind_src_roots(cx)?
        .iter()
        .map(|root| reach_key(root))
        .collect();
    let (cats, reach) = parse_strict_tables(run, &plane_keys)?;
    Ok(strict_rows(
        &ceilings,
        &cats,
        &reach,
        &strict::against_base(cx, &text),
    ))
}

/// Scrape the two fixed-format `  <NAME>   <n>` tables the strict report prints. The category
/// names are fixed; the test-reach rows are the DERIVED plane population's (`plane_keys`, one
/// [`reach_key`] per crate of `plane_kind_src_roots`), and the table must carry EXACTLY those: one
/// row per key, no key missing. A short table compared against ceilings reads as every ceiling met,
/// so "not empty" is no floor; the count is the population's. A name that appears twice is a
/// refusal.
fn parse_strict_tables(run: &LegacyRun, plane_keys: &[String]) -> Result<StrictTables, String> {
    let mut cats: BTreeMap<String, u64> = BTreeMap::new();
    let mut reach: BTreeMap<String, u64> = BTreeMap::new();
    for line in run.stdout.lines() {
        let mut it = line.split_whitespace();
        let (Some(name), Some(value), None) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        let Ok(n) = value.parse::<u64>() else {
            continue;
        };
        if scanner::CATEGORIES.contains(&name) {
            if cats.insert(name.to_string(), n).is_some() {
                return Err(format!(
                    "parity: the strict report named category {name} twice"
                ));
            }
        } else if plane_keys.iter().any(|k| k == name)
            && reach.insert(name.to_string(), n).is_some()
        {
            return Err(format!(
                "parity: the strict report named plane {name} twice"
            ));
        }
    }
    if cats.len() != scanner::CATEGORIES.len()
        || plane_keys.is_empty()
        || reach.len() != plane_keys.len()
    {
        return Err(format!(
            "parity: the strict report carried {} of {} categories and {} of {} plane crate(s) \
             (exit {:?}). A short table compared against ceilings reads as every ceiling met. \
             stderr: {}",
            cats.len(),
            scanner::CATEGORIES.len(),
            reach.len(),
            plane_keys.len(),
            run.code,
            run.stderr.trim()
        ));
    }
    Ok((cats, reach))
}

// ── selftest helpers ──────────────────────────────────────────────────────────────────────────

/// Every owed row FAILs with the same reason when the tree could not be read. A gate that cannot
/// see its subject reports UNPROVEN, never the passing answer to a ban it never applied.
fn unscannable(owed: &[String], why: &str) -> Vec<Row> {
    owed.iter()
        .map(|id| Row::fail(id, "the tree could not be scanned", why.to_string()))
        .collect()
}

/// Plant a NEW file inside a scanned root and require RED naming the plant.
fn create<'a>(
    cx: &Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    path: &str,
    content: &str,
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    create_many(cx, gate, name, covers, &[(path, content)], naming)
}

/// [`create`] for a plant that needs more than one NEW file — a crate and the neutral line that
/// names it. Every file must be new; one that already exists makes the whole case SKIPPED, never a
/// plant over real source.
fn create_many<'a>(
    cx: &Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    files: &[(&str, &str)],
    naming: &[&str],
) -> crate::gates::CasePlan<'a> {
    let mut ov = layered(cx);
    let planted = files.iter().try_for_each(|(path, content)| {
        Edit::Create((*content).to_string()).apply(cx, path, &mut ov)
    });
    if planted.is_err() {
        return Case {
            name: name.to_string(),
            covers: covers.iter().map(|s| (*s).to_string()).collect(),
            expected: Expect::Red {
                naming: naming.iter().map(|s| (*s).to_string()).collect(),
            },
            got: Expect::Skipped,
        }
        .into();
    }
    prove_red(cx, gate, name, covers, ov, naming)
}

/// The overlay a plant starts from: whatever the case's context already carries — the standing-red
/// set-aside, in this selftest — so a plant ADDS to the baseline it is judged against rather than
/// replacing it (`Ctx::with_overlay` replaces).
fn layered(cx: &Ctx) -> Overlay {
    cx.overlay().cloned().unwrap_or_default()
}

/// THE STANDING-RED SET-ASIDE: every file the unplanted tree's `--check` hits sit in, blanked.
///
/// Blanked rather than removed, and that is load-bearing: a plant is judged against this baseline,
/// and `prove_red` refuses a plant that REMOVES a path the baseline has already removed — so a
/// removal here would turn every plant layered on it into an inert one. A blank file is present,
/// counted in the denominator, and carries no hit.
fn standing_red_set_aside(cx: &Ctx) -> Overlay {
    let mut ov = Overlay::new();
    if let Ok(m) = measure(cx) {
        let mut blanked: Vec<&str> = Vec::new();
        for h in m.check_hits() {
            ov.set(&h.file, "");
            blanked.push(&h.file);
        }
        // A debt row whose file is blanked would read stale, and the baseline is meant to be green:
        // the rows of the set-aside files are set aside with them.
        if !blanked.is_empty() && !m.segment_debt.is_empty() {
            let kept: Vec<segment_debt::Debt> = m
                .segment_debt
                .iter()
                .filter(|d| !blanked.contains(&d.file.as_str()))
                .cloned()
                .collect();
            ov.set(segment_debt::SEGMENT_DEBT_TOML, segment_debt::render(&kept));
        }
    }
    ov
}

/// The control arm: the SAME shape planted with its excuse in place must be GREEN, or the RED case
/// beside it proves only that the rule fires on everything.
fn green_with<'a>(
    cx: &Ctx,
    gate: &'a dyn Gate,
    name: &str,
    covers: &[&str],
    path: &str,
    content: &str,
) -> crate::gates::CasePlan<'a> {
    let mut ov = layered(cx);
    if Edit::Create(content.to_string())
        .apply(cx, path, &mut ov)
        .is_err()
    {
        return Case {
            name: name.to_string(),
            covers: covers.iter().map(|s| (*s).to_string()).collect(),
            expected: Expect::Green,
            got: Expect::Skipped,
        }
        .into();
    }
    // NARROWED TO THE ROWS THE CONTROL IS ABOUT. A control proves that ONE rule does not fire on
    // the excused shape; demanding every other row stay green as well held it hostage to rows it
    // says nothing about — the frozen-wire-claim row, which judges the same pragma's back-compat
    // claim, has its own green control.
    prove_rows_green(cx, gate, name, covers, ov)
}
