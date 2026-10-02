//! THE CONSTRUCTION GATE'S VERDICT, PINNED ON A KNOWN-BAD TREE.
//!
//! The gate was made fast: its rules run concurrently and their rows are taken back in the order
//! they are listed, `Tree::grep` asks its files across the cores and its memo once per call, the
//! `rx` matcher skips subjects that hold none of a pattern's mandatory literals and start bytes no
//! match can begin with, the delegated plane-purity scan reads its files in parallel, and `loc`
//! re-buckets a test module's lines instead of parsing the file a second time. None of that may
//! move a row. This tree plants a forged token mint in every spelling the families scan (and in a
//! raw string, a quoted string, a comment and a test module), a pricing call outside the homes, a
//! fee read, a plane naming money, a plane depending on the ledger, and a secret carrier deriving
//! `Debug`, under a ceilings file frozen here with four rule tables and none of the rest. The
//! gate's measured rows and its problems (one per rule whose table is absent, in rule order) are
//! pinned exactly as the serial gate produced them before the change. The tree's own path is
//! written `<root>`, and `ceiling-rose`'s detail, which is git's own refusal to read a directory
//! that is not a repository, is pinned by its id, status and title only.

use std::path::{Path, PathBuf};

use xtask::ctx::Ctx;
use xtask::gates::construction::ConstructionGate;

const TREE: &[(&str, &str)] = &[
    (
        "crates/busbar-kernel-ledger/src/cost/mod.rs",
        r#"pub fn list_price(e: &[LedgerEntry]) -> u64 {
    apply_tier(e)
}
"#,
    ),
    (
        "crates/busbar-kernel/src/lib.rs",
        r#"pub mod teller;
pub fn admit(x: u8) -> Pass {
    Pass::mint(x)
}
"#,
    ),
    (
        "crates/busbar-kernel/src/teller.rs",
        r#"pub fn settle(e: &[LedgerEntry]) -> u64 {
    busbar_kernel_ledger::cost::list_price(e)
}
"#,
    ),
    (
        "crates/busbar-plane-x/Cargo.toml",
        r#"[package]
name = "busbar-plane-x"
version = "0.1.0"

[dependencies]
busbar-kernel-ledger = { path = "../busbar-kernel-ledger" }
"#,
    ),
    (
        "crates/busbar-plane-x/src/lib.rs",
        r#"// RateCard in a comment is not money.
use busbar_kernel_ledger::cost::Card;
pub struct RateCard;
pub fn elapsed(t: &T) -> u64 {
    t.as_nanos() + t.wall_nanos()
}
pub fn label() -> &'static str {
    "priced"
}
pub fn unpriced() -> bool {
    is_unpriced()
}
"#,
    ),
    (
        "crates/busbar-store-x/src/lib.rs",
        r##"#[cfg(test)]
mod tests;
// A comment naming Pass::mint( is not a site.
/* nor is a block comment: Grant::mint( */
pub fn forge(x: u8) {
    let _a = Pass::mint(x);
    let _b = Grant::<Dial>::mint_bound(x, y);
    let _c = <Grant<Dial>>::mint(x);
    let _d = KernelSeal::acquire_for_kernel(x);
    let _e = a::b::CallId::seal(x);
    let _f = SecretOnce::mint(x);
    let _g = Grant::<busbar_contract::caps::Admittance>::mint(x);
    let _s = r#"Pass::mint( inside a "raw" literal"#;
    let _t = "escaped \" Pass::mint( in a string";
    let _u = notPass::mint(x);
}
pub fn price(e: &[LedgerEntry]) -> u64 {
    busbar_kernel_ledger::cost::apply_tier(e) + cost_price_usage(e)
}
pub fn fee(cfg: &Cfg) -> u64 {
    cfg.per_request_fee
}
#[derive(Debug, Clone)]
pub struct Credential(Vec<u8>);
#[derive(Clone)]
pub struct KeyMaterial(Vec<u8>);
"##,
    ),
    (
        "crates/busbar-store-x/src/tests/mod.rs",
        r#"#[test]
fn forged_in_a_test() {
    let _ = Pass::mint(1);
}
"#,
    ),
    (
        "qa/construction.toml",
        r#"[gate]
scan_roots = ["crates/*/src", "crates/*/tests"]
plane_crates = ["busbar-plane-x"]
test_path_fragments = ["/tests/", "_tests.rs", "_test.rs", "/tests.rs"]

[rules.token-sealed]
patterns = ["Pass::mint(", "Grant::<WriteMoney>::mint(", "Grant::<Consumption>::mint(", "Grant::<Exit>::mint("]
pattern_families = [
  '(?<![A-Za-z0-9_])Pass::<[^<>]*>::mint(_bound)?\(',
  '(?<![A-Za-z0-9_])Grant::<[^<>]*>::mint(_bound)?\(',
  '(?<![A-Za-z0-9_])(Pass|Grant)::mint_bound\(',
  '(?<![A-Za-z0-9_])Grant::mint\(',
  '<(Grant|Pass)<[^<>]*>>::mint(_bound)?\(',
  '(?<![A-Za-z0-9_])(UnitToken|TrustToken|UsageToken|LedgerToken|DurabilityToken|EgressAuthToken|TransportKeyToken|AdminToken|RecoveryToken|ExitToken)::mint(_bound)?\(',
  '(?<![A-Za-z0-9_])(?:[A-Za-z0-9_]+::)*CallId>?::seal(_bound)?\(',
  '(?<![A-Za-z0-9_])(?:[A-Za-z0-9_]+::)*Origin>?::seal(_bound)?\(',
  '(?<![A-Za-z0-9_])(?:[A-Za-z0-9_]+::)*SessionId>?::mint(_bound)?\(',
  '(?<![A-Za-z0-9_])(?:[A-Za-z0-9_]+::)*IdempotencyKey>?::mint(_bound)?\(',
  '(?<![A-Za-z0-9_])(?:[A-Za-z0-9_]+::)*UnitEnd>?::seal(_bound)?\(',
]
allowed_root = "crates/busbar-kernel/src"
max_sites = 0
exclude_files = []
kernel_seal_pattern = 'KernelSeal::acquire_for_kernel\('
kernel_seal_subject = "`KernelSeal::acquire_for_kernel(`"
admit_token_mint_pattern = '(?<![A-Za-z0-9_])(Grant::<([A-Za-z0-9_]+::)*Admittance>|AdmitToken)::mint(_bound)?\('
admit_token_mint_subject = "the arrival-hold mint (`Grant::<Admittance>::mint[_bound](`, and its pre-#73 name `AdmitToken::mint(`)"
kernel_root = "crates/busbar-kernel/src"
max_kernel_seal_sites = 0
max_admit_token_mint_sites = 0
secret_once_mint_pattern = '(?<![A-Za-z0-9_])(?:[A-Za-z0-9_]+::)*SecretOnce>?::mint(_bound)?\('
secret_once_mint_subject = "the one-time secret placeholder mint (`SecretOnce::mint(`, both the capability and the destination type of that name)"
secret_once_root = "crates/busbar-core-admin/src"
max_secret_once_mint_sites = 0

[rules.one-pricing-site]
scope_note = "production code only; a test may price whatever it likes to prove the arithmetic"
entry_verbs = ["cost_price_usage"]
entry_path_patterns = ['busbar_kernel_ledger::cost::[A-Za-z0-9_:]*price', 'busbar_kernel_ledger::cost::apply_tier']
wrapper_home = "cost-unit"
wrapper_inputs = ["LedgerEntry"]
wrapper_reaches = ['(?<![A-Za-z0-9_])Tally::']
max_extra_sites = 0
fee_fields = ["per_request_fee", "per_request_fee_cents", "fee_cents"]
fee_reader_crates = ["busbar-kernel-ledger", "busbar-kernel", "busbar-core-admin"]
max_fee_readers = 0
[rules.one-pricing-site.fee_allowed.amend-rate-history]
path = "crates/busbar/src/root/units_admin/mod.rs"
max = 4
because = "fixture"
[rules.one-pricing-site.allowed.cost-unit]
path = "crates/busbar-kernel-ledger/src/cost/"
because = "fixture"
[rules.one-pricing-site.allowed.root-wiring]
path = "crates/busbar/src/root/"
because = "fixture"
[rules.one-pricing-site.allowed.kernel-exit]
path = "crates/busbar-kernel/src/teller.rs"
because = "fixture"
[rules.one-pricing-site.allowed.kernel-sweep]
path = "crates/busbar-kernel/src/tick.rs"
because = "fixture"
[rules.one-pricing-site.allowed.kernel-recovery]
path = "crates/busbar-kernel/src/recovery.rs"
because = "fixture"

[rules.plane-no-money]
scope_globs = [
  "crates/busbar-plane-*/src/*",
  "crates/busbar-llm/src/unit/*",
  "crates/busbar-mcp/src/*",
  "crates/busbar-a2a/src/*",
]
symbols = ["RateCard", "Pricer", "per_request_fee", "fee_cents", "price_", "priced",
           "CostHandle", "CostModel", "Nanos", "_nanos"]
allowed_vocabulary = [
  "fee_count", "pricing_enabled", "cost_pricing_enabled", "is_unpriced", "cost_model_unpriced",
  "unpriced_message", "unpriced_classes", "Unpriced", "unpriced",
  "as_nanos", "elapsed_nanos", "monotonic_nanos", "latency_nanos",
]
forbidden_module_paths = ["busbar_kernel_ledger::cost::", "busbar_kernel::cost::", "busbar_kernel::plane_host::cost_host"]
forbidden_deps = ["busbar-kernel-ledger"]
max_hits = 0
[rules.plane-no-money.allowlist]

[rules.secret-carrier-debug]
carriers = ["Credential", "SecretValue", "CredentialSecret", "KeyMaterial", "UpstreamAddress", "SecretOnce", "LaneInput"]
max_derived = 0

"#,
    ),
];

/// `Row::tsv` of every measured row, in order, as the serial gate printed it over [`TREE`].
const PINNED_ROWS: &str = r#"token-sealed	FAIL	the Teller's tokens are minted only inside the Teller	7 token constructor(s) spelled outside crates/busbar-kernel/src (ceiling 0): `Pass::mint(` at crates/busbar-store-x/src/lib.rs:6; `Pass::mint(` at crates/busbar-store-x/src/lib.rs:13; `Pass::mint(` at crates/busbar-store-x/src/lib.rs:14; `Pass::mint(` at crates/busbar-store-x/src/tests/mod.rs:3; `Grant::<Dial>::mint_bound(` at crates/busbar-store-x/src/lib.rs:7; `<Grant<Dial>>::mint(` at crates/busbar-store-x/src/lib.rs:8; `a::b::CallId::seal(` at crates/busbar-store-x/src/lib.rs:10
token-sealed:kernel-seal	FAIL	`KernelSeal::acquire_for_kernel(` is spelled only inside crates/busbar-kernel/src	1 call site(s) of `KernelSeal::acquire_for_kernel(` outside crates/busbar-kernel/src (ceiling 0): crates/busbar-store-x/src/lib.rs:9
token-sealed:admit-token-mint	FAIL	the arrival-hold mint (`Grant::<Admittance>::mint[_bound](`, and its pre-#73 name `AdmitToken::mint(`) is spelled only inside crates/busbar-kernel/src	1 call site(s) of the arrival-hold mint (`Grant::<Admittance>::mint[_bound](`, and its pre-#73 name `AdmitToken::mint(`) outside crates/busbar-kernel/src (ceiling 0): crates/busbar-store-x/src/lib.rs:12
token-sealed:secret-once-mint	FAIL	the one-time secret placeholder mint (`SecretOnce::mint(`, both the capability and the destination type of that name) is spelled only inside crates/busbar-core-admin/src	1 call site(s) of the one-time secret placeholder mint (`SecretOnce::mint(`, both the capability and the destination type of that name) outside crates/busbar-core-admin/src (ceiling 0): crates/busbar-store-x/src/lib.rs:11
secret-carrier-debug	FAIL	a type carrying secret bytes hand-rolls its Debug	1 secret carrier(s) with a derived Debug (ceiling 0): `Credential` derives Debug at crates/busbar-store-x/src/lib.rs:24
plane-no-money	FAIL	a plane names usage classes and quantities, never a price	5 money symbol(s) in the plane crates, plane codecs and plane unit modules (ceiling 0): `busbar_kernel_ledger::cost::` at crates/busbar-plane-x/src/lib.rs:2; `RateCard` at crates/busbar-plane-x/src/lib.rs:3; `wall_nanos` at crates/busbar-plane-x/src/lib.rs:5; `priced` at crates/busbar-plane-x/src/lib.rs:8; busbar-plane-x/Cargo.toml depends on `busbar-kernel-ledger`; scope glob(s) matching no file yet (not a finding): crates/busbar-llm/src/unit/*, crates/busbar-mcp/src/*, crates/busbar-a2a/src/*
one-pricing-site	FAIL	only the root's meter/admission wiring and the kernel's settle sites price a unit	2 pricing-entry call site(s) outside the reviewed homes ['cost-unit', 'kernel-exit', 'kernel-recovery', 'kernel-sweep', 'root-wiring'] (ceiling 0): `cost_price_usage(` at crates/busbar-store-x/src/lib.rs:18; `busbar_kernel_ledger::cost::apply_tier` at crates/busbar-store-x/src/lib.rs:18; reviewed sites seen: `busbar_kernel_ledger::cost::list_price` at crates/busbar-kernel/src/teller.rs:2 (kernel-exit); entries under another name: none
one-pricing-site:fee-fields	FAIL	the per-request fee is read only where the card lives	2 production read(s) of ['per_request_fee', 'per_request_fee_cents', 'fee_cents'] outside ['busbar-core-admin', 'busbar-kernel', 'busbar-kernel-ledger'] (ceiling 0) and the reviewed fee homes [amend-rate-history 0/4]: crates/busbar-store-x/src/lib.rs:21; [rules.one-pricing-site.fee_allowed.amend-rate-history] grants a reviewed fee home that reads no fee on this tree — a dead grant, to be deleted or repointed
surface-ceiling:contract	FAIL	the contract crate's plugin-visible surface (caps folded in, #37/#38) stays under its ceiling	cargo xtask loc could not measure the tree: qa/loc.toml: toml_doc: <root>/qa/loc.toml: No such file or directory (os error 2)
surface-ceiling:grammar	FAIL	the closed JSON span grammar's surface stays under its ceiling	cargo xtask loc could not measure the tree: qa/loc.toml: toml_doc: <root>/qa/loc.toml: No such file or directory (os error 2)
ceiling-census	FAIL	every rule table, plane crate and kind glob is still counted	qa/construction.toml has no [gate.census] table. That table is the count of how many rule tables, plane crates and kind globs this gate is supposed to be reading, and without it a rule table can be deleted together with the ceiling it holds and nothing is short of anything. A census that is absent is not a census that passed.
ceiling-rose	FAIL	no ceiling in a qa ceilings file is higher than it is at the base	<git>
ceiling-slack	FAIL	every ratcheted ceiling is pinned to today's measurement	7 ceiling(s) or reservation(s) are not a measured, named room — point each at its row or strike it: loc-ceilings:kernel, loc-ceilings:caps-contract, loc-ceilings:unit-total, loc-ceilings:union, legacy-reach, ports-only:busbar-plane-x, ports-only-tests:busbar-plane-x
"#;

/// The gate's problems, in rule order: one per rule whose table the frozen ceilings file lacks.
const PINNED_PROBLEMS: &[&str] = &[
    "one-attempt-seam: qa/construction.toml has no [rules.one-attempt-seam] table",
    "request-path-fn-size: qa/construction.toml has no [rules.request-path-fn-size] table",
    "ports-only: qa/construction.toml has no [rules.ports-only] table",
    "no-uninstalled-seam: qa/construction.toml has no [rules.no-uninstalled-seam] table",
    "neutral-no-dialect: qa/construction.toml has no [rules.neutral-no-dialect] table",
    "single-terminal: qa/construction.toml has no [rules.single-terminal] table",
    "duplicate-dispatch: qa/construction.toml has no [rules.duplicate-dispatch] table",
    "teller-step-order: qa/construction.toml has no [rules.teller-step-order] table",
    "one-teller-loop: qa/construction.toml has no [rules.one-teller-loop] table",
    "no-response-escapes-audit: qa/construction.toml has no [rules.no-response-escapes-audit] table",
    "terminal-doors-in-audit-step: qa/construction.toml has no [rules.terminal-doors-in-audit-step] table",
    "one-pick-site: qa/construction.toml has no [rules.one-pick-site] table",
    "loc-ceilings: qa/construction.toml has no [rules.loc-ceilings] table",
    "manifest-allowlist: qa/construction.toml has no [rules.manifest-allowlist] table",
    "source-denylist: qa/construction.toml has no [rules.source-denylist] table",
    "lean-core: qa/construction.toml has no [rules.lean-core] table",
    "no-default-bodies: qa/construction.toml has no [rules.no-default-bodies] table",
    "sealed-unit-traits: qa/construction.toml has no [rules.sealed-unit-traits] table",
    "hold-discipline: qa/construction.toml has no [rules.hold-discipline] table",
    "hold-escapes: qa/construction.toml has no [rules.hold-escapes] table",
    "seal-sites: qa/construction.toml has no [rules.seal-sites] table",
    "kernel-seal-impls: qa/construction.toml has no [rules.kernel-seal-impls] table",
    "forbid-unsafe: qa/construction.toml has no [rules.forbid-unsafe] table",
    "no-escaped-newline-doc-comment: qa/construction.toml has no [rules.no-escaped-newline-doc-comment] table",
    "unit-no-wall-clock: qa/construction.toml has no [rules.unit-no-wall-clock] table",
    "unit-no-finding-ids: qa/construction.toml has no [rules.unit-no-finding-ids] table",
    "legacy-reach: qa/construction.toml has no [rules.legacy-reach] table",
    "no-test-doubles-in-production: qa/construction.toml has no [rules.no-test-doubles-in-production] table",
];

fn plant(root: &Path) {
    for (rel, text) in TREE {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().expect("a planted file has a parent"))
            .expect("the planted tree's directories are creatable");
        std::fs::write(&path, text).expect("the planted file is writable");
    }
}

fn scratch_root() -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("xtask-construction-verdict-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn the_construction_verdict_on_a_known_bad_tree_is_pinned_row_for_row() {
    let root = scratch_root();
    plant(&root);
    let cx = Ctx::at(&root, root.join(".scratch")).expect("the planted tree opens");
    let (rows, problems) = ConstructionGate::measure(&cx).expect("the frozen ceilings file reads");
    let shown = root.to_string_lossy().into_owned();
    let got: String = rows
        .iter()
        .map(|r| {
            let mut row = r.to_row();
            if row.id == "ceiling-rose" {
                row.detail = "<git>".to_string();
            }
            format!("{}\n", row.tsv().replace(&shown, "<root>").trim_end())
        })
        .collect();
    let _ = std::fs::remove_dir_all(&root);
    assert_eq!(
        got, PINNED_ROWS,
        "a construction row moved over the known-bad tree"
    );
    assert_eq!(
        problems, PINNED_PROBLEMS,
        "the construction gate's problems moved"
    );
}
