//! THE SHIP CRITERION'S VERDICT, PINNED ON A KNOWN-BAD TREE.
//!
//! `ship-ready` now runs the two gates that own its evidence — `construction` and
//! `kind-isolation-ship` — at the same time instead of one after the other. That may change how long
//! the gate takes and nothing else: this tree forges token mints, prices outside the homes, names
//! money in a plane and derives `Debug` on a secret carrier, under a construction ceilings file
//! frozen here with four rule tables and no kind registry at all, so every one of ship-ready's four
//! rows is red for a reason it names. The rows are pinned as the serial gate printed them, for a
//! `qa` posture. The tree's own path is written `<root>`, and `ship-ready:ceiling-rose`'s detail —
//! git's own refusal to read a directory that is not a repository — is pinned by id, status and title.

use std::path::PathBuf;

use xtask::ctx::Ctx;
use xtask::gates::execute;
use xtask::gates::ship_ready::ShipReadyGate;

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

/// `Row::tsv` of every row, in order, as the serial gate printed it over [`TREE`] for `qa`.
const PINNED_ROWS: &str = r#"ship-ready:standing-reds	FAIL	a shipping line inherits no standing reds	target `qa` is a shipping line and 19 construction row(s) are still standing red: (did not run) ceiling-census: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) construction:ceilings-unreadable: owed but no row was recorded — DID NOT RUN, which is not a pass, (did not run) one-pricing-site: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) one-pricing-site:fee-fields: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) plane-no-money: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) secret-carrier-debug: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) token-sealed: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) token-sealed:admit-token-mint: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) token-sealed:kernel-seal: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) token-sealed:secret-once-mint: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., ceiling-census, one-pricing-site, one-pricing-site:fee-fields, plane-no-money, secret-carrier-debug, token-sealed, token-sealed:admit-token-mint, token-sealed:kernel-seal, token-sealed:secret-once-mint — of which 19 NOT on the written-down list: (did not run) ceiling-census: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) construction:ceilings-unreadable: owed but no row was recorded — DID NOT RUN, which is not a pass, (did not run) one-pricing-site: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) one-pricing-site:fee-fields: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) plane-no-money: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) secret-carrier-debug: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) token-sealed: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) token-sealed:admit-token-mint: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) token-sealed:kernel-seal: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., (did not run) token-sealed:secret-once-mint: a row nobody owes. Nothing diffs it, so a FAIL here would be written into the ledger and exited 0 through. Declare it in the gate's owed set or stop emitting it., ceiling-census, one-pricing-site, one-pricing-site:fee-fields, plane-no-money, secret-carrier-debug, token-sealed, token-sealed:admit-token-mint, token-sealed:kernel-seal, token-sealed:secret-once-mint. A standing red is a rule this tree BREAKS, written down so the dev line can keep moving while it is drained. Promoting it does not drain it — it promotes the breakage and retires the record of it. Drain each row, or do not ship.
ship-ready:ship-twin	FAIL	the ship twin is not zero	`kind-isolation-ship` is not green: kind-isolation:name (the kind registry file did not read); kind-isolation:deps (the kind registry file did not read); kind-isolation:closure (the kind registry file did not read); kind-isolation:registry (the kind registry file did not read); kind-isolation:matrix (the kind registry file did not read); kind-isolation:vocab (the crate source walk could not run or collapsed below its floor); kind-isolation:plane-steps (the strict step list could not be read); kind-isolation:transport-registration (no transport crate reached the registration rule); kind-isolation:control-path (no control surface reached the control-path rule); kind-isolation:shape (the kind registry file did not read); kind-isolation:testkit (the kind registry file did not read). Each of these is a kind whose ship criterion this tree does not meet yet.
"#;

fn planted_root() -> PathBuf {
    let root =
        std::env::temp_dir().join(format!("xtask-ship-ready-verdict-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    for (rel, text) in TREE {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().expect("a planted file has a parent"))
            .expect("the planted tree's directories are creatable");
        std::fs::write(&path, text).expect("the planted file is writable");
    }
    // The tree is its own workspace: the two evidence gates owe the rows ITS ceilings file names.
    std::fs::create_dir_all(root.join("xtask")).expect("xtask/ is creatable");
    std::fs::write(root.join("xtask/Cargo.toml"), "").expect("xtask/Cargo.toml is writable");
    root
}

#[test]
fn the_ship_ready_verdict_on_a_known_bad_tree_is_pinned_row_for_row() {
    let root = planted_root();
    // One test in this binary, so the process-wide root and posture are this test's alone.
    xtask::ctx::set_root_override(root.clone());
    std::env::set_var("XTASK_SHIP_TARGET", "qa");
    std::env::remove_var("XTASK_CEILING_BASE");
    let cx = Ctx::new(&root).expect("the planted tree opens with a writable scratch dir");
    let verdict = execute(&ShipReadyGate, &cx);
    let shown = root.to_string_lossy().into_owned();
    let got: String = verdict
        .rows
        .iter()
        .map(|r| {
            let mut row = r.clone();
            if row.id == "ship-ready:ceiling-rose" {
                row.detail = "<git>".to_string();
            }
            format!("{}\n", row.tsv().replace(&shown, "<root>").trim_end())
        })
        .collect();
    let _ = std::fs::remove_dir_all(&root);
    assert!(verdict.red, "the known-bad tree must be red");
    assert_eq!(
        got, PINNED_ROWS,
        "a ship-ready row moved over the known-bad tree"
    );
}
