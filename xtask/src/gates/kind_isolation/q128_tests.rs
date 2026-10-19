//! THE Q128 AUDIT'S CASES ON THIS GATE, one per finding, each asked of the rule it is about over the
//! real tree with one plant laid on top (`cargo test` runs these; the selftest battery carries the
//! gate's own plants).
//!
//! * The class table may not grant `kernel -> plugin-tooling`: "The kernel never names the loader"
//!   (BUSBAR-1.6.0.md THE DESIGN, l.322).
//! * Nor `root -> legacy` / `legacy -> contract`: the legacy engine is no crate of the release
//!   (THE DESIGN §9, l.1148-1150), and "The ship check admits only the classes the architecture
//!   allows" (Part 1, l.1939-1940).
//! * A `tcb` edge this branch introduced is refused against the merge-base like a `not-allowed`
//!   one (Law 9, l.2081-2085; Part 1, l.1937-1938: `tcb` is never an opinion a row grants itself).
//! * `--write` lowers a count that fell (its own contract, "it lowers a row to what the tree
//!   measures").
//! * A `testkit`-named dev-dependency runs no battery (Part 2 #33: "There is NO `testkit`").

use super::*;
use crate::gates::construction::ceilings::BASE_PIN_KEY;
use crate::ledger::Status;

/// The workspace as the gate reads it: the pinned checkouts mounted beneath ([`pinned`]).
fn ws() -> Ctx {
    pinned::with_pinned(&Ctx::workspace().expect("the workspace opens"))
}

/// `plant` over the workspace, with the mount laid back beneath it as [`KindIsolationGate::run`]
/// does.
fn planted(plant: Overlay) -> Ctx {
    pinned::with_pinned(&ws().with_overlay(plant))
}

/// The census exactly as [`KindIsolationGate::run`] builds it.
fn crates_of(cx: &Ctx) -> Vec<CrateInfo> {
    let mut crates = census(&pinned::with_pinned(cx)).expect("the census reads");
    let (planes, ports) = vocabularies(&crates);
    assign_instances(&mut crates, &planes, &ports);
    crates
}

fn deps_row(cx: &Ctx, half: Half, ship: bool) -> Row {
    let crates = crates_of(cx);
    let reg = load_registry(cx).expect("the registry reads");
    rule_deps(cx, &crates, &reg, half, ship)
}

/// The merge-base pinned to this checkout's own HEAD: a commit whose manifests every plant below
/// adds to, and one a shallow clone carries.
fn head_pin(ov: &mut Overlay) {
    let head = Ctx::workspace()
        .expect("the workspace opens")
        .git(&["rev-parse", "HEAD"])
        .expect("HEAD resolves");
    ov.set_command(BASE_PIN_KEY, head.trim());
}

// ── finding 1 (HIGH): the kernel never names the loader ──────────────────────────────────────

#[test]
fn the_kernel_naming_the_loader_is_no_class_the_architecture_grants() {
    let class = ("kernel".to_string(), "plugin-tooling".to_string());
    assert_ne!(
        verdict_for(&class),
        "allowed",
        "BUSBAR-1.6.0.md l.322: \"The kernel never names the loader\""
    );
    assert!(
        !ARCHITECTURE_TCB.contains(&("kernel", "plugin-tooling")),
        "the kernel is not the trusted computing base"
    );
}

#[test]
fn the_ship_twin_refuses_a_kernel_crate_naming_the_loader() {
    let cx = planted(manifest_plant(
        "crates/busbar-kernel-planted",
        "busbar-kernel-planted",
        &["busbar-contract", "busbar-plugin-loader"],
    ));
    let row = deps_row(&cx, Half::Shipped, true);
    assert!(
        row.detail.contains(
            "ship-edge\tkernel -> plugin-tooling\tbusbar-kernel-planted -> busbar-plugin-loader"
        ),
        "the ship twin passed a kernel crate naming the loader: {}",
        row.detail
    );
}

// ── finding 2 (MEDIUM): the retiring legacy engine is no class the release keeps ─────────────

#[test]
fn the_legacy_engine_is_no_class_the_architecture_grants() {
    for (from, to) in [("root", "legacy"), ("legacy", "contract")] {
        assert_ne!(
            verdict_for(&(from.to_string(), to.to_string())),
            "allowed",
            "`{from} -> {to}`: BUSBAR-1.6.0.md §9 holds 14 crates and the legacy engine is not one"
        );
    }
}

#[test]
fn the_ship_twin_refuses_the_root_linking_the_legacy_engine() {
    let cx = ws();
    let crates = crates_of(&cx);
    let measured = measure_edges(&crates, Half::Shipped);
    let row = deps_row(&cx, Half::Shipped, true);
    let mut asked = 0;
    for e in measured.iter().filter(|e| {
        (e.class.0 == "root" && e.class.1 == "legacy")
            || (e.class.0 == "legacy" && e.class.1 == "contract")
    }) {
        asked += 1;
        let want = format!("{} -> {} is `", e.from, e.to);
        assert!(
            row.detail.contains(&want),
            "the ship twin passed `{} -> {}` ({} -> {}): {}",
            e.from,
            e.to,
            e.class.0,
            e.class.1,
            row.detail
        );
    }
    // The retirement removes the edges; until then the case is asked of every one of them.
    if crates.iter().any(|c| c.kind == Some("legacy")) {
        assert!(
            asked > 0,
            "a legacy crate is in the census and nothing links it"
        );
    }
}

// ── finding 3 (MEDIUM): a new `tcb` edge is refused against the merge-base ───────────────────

#[test]
fn a_tcb_edge_this_branch_introduced_is_refused_whatever_its_row_says() {
    let cx = ws();
    let mut ov = loader_reaches_kernel(&cx);
    let reg = cx.read(REGISTRY_FILE).expect("the registry reads");
    ov.set(
        REGISTRY_FILE,
        format!(
            "{}\n\n[[dep]]\nfrom    = \"busbar-plugin-loader\"\nto      = \"busbar-kernel-ledger\"\n\
             half    = \"shipped\"\ncount   = \"1\"\nverdict = \"tcb\"\ncite    = \"planted by \
             the self-test\"\nwhy     = \"a row written in the same change as its edge\"\n\
             drain   = \"none\"\n",
            reg.trim_end()
        ),
    );
    head_pin(&mut ov);
    let row = deps_row(&planted(ov), Half::Shipped, false);
    assert!(
        row.detail
            .contains("new-forbidden-edge\tplugin-tooling -> kernel")
            && row
                .detail
                .contains("busbar-plugin-loader -> busbar-kernel-ledger is `tcb`"),
        "a tcb edge the merge-base never had went through on a row written beside it: {}",
        row.detail
    );
}

// ── part 25 finding 1 (HIGH): the mint rule reads the ledger the way the loader does ─────────

/// `[[ cell ]]` is the loader's `[[cell]]` (it trims the header), so the mint rule's reader must
/// see the row too: a row the loader grants and the mint rule never sees is an allowance minted in
/// the same change as its coupling (base.rs header; Law 9, l.2081-2085).
#[test]
fn the_mint_reader_reads_a_spaced_header_as_the_loader_does() {
    let text = "[[ cell ]]\ncrate = \"busbar-kernel\"\nkind = \"plane\"\n";
    let loaded = parse_registry(text);
    assert!(
        loaded
            .matrix_cells
            .iter()
            .any(|c| c.krate == "busbar-kernel" && c.kind == "plane"),
        "the loader reads `[[ cell ]]` as a cell row"
    );
    let keys = super::base::row_keys(text, "cell", &["crate", "kind"]);
    assert!(
        keys.contains("busbar-kernel \u{d7} plane"),
        "the mint rule did not see a row the loader grants: {keys:?}"
    );
}

/// A row that names its identity key twice is refused at load, so no reader has to guess which
/// value it meant: the loader took the first and the mint rule the last, and a new row hid behind
/// the identity of one the base already had.
#[test]
fn a_row_that_repeats_a_key_is_refused_at_load() {
    let text = "[[cell]]\ncrate = \"busbar-kernel-minted\"\ncrate = \"busbar-kernel\"\n\
                kind = \"plane\"\n";
    let loaded = parse_registry(text);
    assert!(
        loaded
            .errors
            .iter()
            .any(|e| e.starts_with("duplicate-field\t")),
        "a repeated `crate` loaded: {:?}",
        loaded.errors
    );
    assert!(
        loaded.matrix_cells.is_empty(),
        "a row with two `crate` values granted a cell"
    );
}

// ── finding 4 (MEDIUM): `--write` lowers a count that fell ───────────────────────────────────

#[test]
fn write_lowers_a_row_that_stands_above_the_measurement() {
    let cx = ws();
    let (from, to) = ("busbar-kernel", "busbar-contract");
    let anchor = dep_anchor(&cx, from, to).expect("the row is in the ledger");
    let now: i64 = anchor
        .rsplit("count   = \"")
        .next()
        .and_then(|s| s.strip_suffix('"'))
        .and_then(|s| s.parse().ok())
        .expect("the row's count reads");
    let slack = now + 1;
    let text = cx.read(REGISTRY_FILE).expect("the registry reads");
    let mut ov = Overlay::new();
    ov.set(
        REGISTRY_FILE,
        text.replacen(&anchor, &dep_row(from, to, &slack.to_string()), 1),
    );
    head_pin(&mut ov);
    let verdict = KindIsolationGate::write().run(&planted(ov));
    let row = verdict
        .rows
        .iter()
        .find(|r| r.id == ROW_WRITE)
        .expect("the write row is emitted");
    assert_eq!(
        row.status,
        Status::Pass,
        "--write refused a row one above its measurement: {}",
        row.detail
    );
    assert!(
        row.detail.contains(&format!(
            "[[dep]] {from} -> {to} (shipped) {slack} -> {now}"
        )),
        "--write did not lower the row: {}",
        row.detail
    );
}

// ── finding 5 (MEDIUM): a `testkit` dev-dependency runs no battery ───────────────────────────

#[test]
fn a_testkit_named_dev_dependency_is_not_a_battery() {
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-store-kitonly/Cargo.toml",
        "[package]\nname = \"busbar-store-kitonly\"\nversion = \"0.0.0\"\n\n\
         [dependencies]\nbusbar-contract = { workspace = true }\n\n\
         [dev-dependencies]\nacme-testkit = \"1\"\n",
    );
    ov.set(
        "crates/busbar-store-kitonly/src/lib.rs",
        "pub struct P;\nimpl Store for P {}\n",
    );
    let cx = planted(ov);
    let crates = crates_of(&cx);
    let idx = index_sources(&cx).expect("the source index reads");
    let row = rule_testkit(&crates, &idx);
    assert!(
        row.detail.contains("not-run\tcrates/busbar-store-kitonly")
            || row.detail.contains("no-battery\tkind:store"),
        "a crate with no conformance file ran its kind's battery on a `testkit` dev-dependency: {}",
        row.detail
    );
}

// ── finding 6 (LOW): the gRPC library exemption blanks spans, not lines ──────────────────────

fn streaming_hits(text: &str) -> usize {
    let rel = "crates/busbar-transport-q128/src/lib.rs";
    let lines = vocab_lines(rel, text);
    let banned = vec![(
        "streaming".to_string(),
        "a PLANE instance named inside a transport",
    )];
    vocab_banned_hits(rel, text, &lines, &banned).len()
}

#[test]
fn a_plane_path_beside_a_tonic_spelling_is_still_a_hit() {
    assert_eq!(
        streaming_hits("pub fn f() {\n    let s = streaming::Session::open().streaming(cfg);\n}\n"),
        1,
        "the `streaming::` path shares its line with `.streaming(`, and the plane is still named"
    );
    assert_eq!(
        streaming_hits(
            "pub fn f() {\n    let b = builder.streaming(true).max_concurrent_streams(8);\n}\n"
        ),
        0,
        "tonic's own spellings name no plane"
    );
}

// ── finding 7 (LOW): `test-support` reached through another crate's feature table ────────────

fn ts_findings(ov: Overlay) -> Vec<String> {
    let cx = planted(ov);
    let crates = crates_of(&cx);
    test_support_ships(&cx, &crates)
}

fn kit_crate(ov: &mut Overlay) {
    ov.set(
        "crates/busbar-store-q128kit/Cargo.toml",
        "[package]\nname = \"busbar-store-q128kit\"\nversion = \"0.0.0\"\n\n\
         [features]\nx = [\"test-support\"]\ntest-support = []\n",
    );
}

#[test]
fn a_shipped_feature_that_reaches_test_support_through_the_dependency_is_found() {
    let mut ov = Overlay::new();
    kit_crate(&mut ov);
    ov.set(
        "crates/busbar-store-q128user/Cargo.toml",
        "[package]\nname = \"busbar-store-q128user\"\nversion = \"0.0.0\"\n\n\
         [dependencies]\nbusbar-store-q128kit = { path = \"../busbar-store-q128kit\", features = \
         [\"x\"] }\n",
    );
    let found = ts_findings(ov);
    assert!(
        found.iter().any(|f| f
            .starts_with("test-support-ships\tcrates/busbar-store-q128user/Cargo.toml\t")
            && f.contains("busbar-store-q128kit/x -> busbar-store-q128kit/test-support")),
        "a shipped `features = [\"x\"]` whose `x` turns on `test-support` was not found: {found:?}"
    );
}

#[test]
fn a_default_dep_feature_that_reaches_test_support_is_found() {
    let mut ov = Overlay::new();
    kit_crate(&mut ov);
    ov.set(
        "crates/busbar-store-q128dflt/Cargo.toml",
        "[package]\nname = \"busbar-store-q128dflt\"\nversion = \"0.0.0\"\n\n\
         [dependencies]\nbusbar-store-q128kit = { path = \"../busbar-store-q128kit\" }\n\n\
         [features]\ndefault = [\"busbar-store-q128kit/x\"]\n",
    );
    let found = ts_findings(ov);
    assert!(
        found.iter().any(|f| f
            .starts_with("test-support-ships\tcrates/busbar-store-q128dflt/Cargo.toml\t")
            && f.contains("`default` feature set reaches")),
        "`default = [\"dep/x\"]` whose `x` turns on `test-support` was not found: {found:?}"
    );
}

#[test]
fn the_real_tree_ships_no_test_support() {
    let cx = ws();
    let crates = crates_of(&cx);
    let found = test_support_ships(&cx, &crates);
    assert!(found.is_empty(), "{found:?}");
}

// ── part 24 finding 4 (LOW): a git pin the row reader cannot read is refused ─────────────────

#[test]
fn a_base_kind_pin_no_row_names_is_refused() {
    let p = pinned::Pinned {
        name: "busbar-transport-q128".to_string(),
        dir: std::path::PathBuf::from("/nonexistent"),
        source: "git+https://example.invalid/busbar-transport-q128?rev=0".to_string(),
    };
    assert!(
        pinned::unread_pin(std::slice::from_ref(&p), &[]).is_some(),
        "a transport cargo resolves from git and no row names is lost from every base"
    );
    let named = [("busbar-transport-q128".to_string(), "0".to_string())];
    assert!(pinned::unread_pin(std::slice::from_ref(&p), &named).is_none());
    let store = pinned::Pinned {
        name: "busbar-store-q128".to_string(),
        ..p
    };
    assert!(
        pinned::unread_pin(&[store], &[]).is_none(),
        "a store is no base kind"
    );
}

// ── part 24 finding 3 (LOW): one list of the plugin kinds ─────────────────────────────────────

#[test]
fn the_pinned_mount_reads_the_one_list_of_plugin_kinds() {
    assert!(std::ptr::eq(pinned::PLUGIN_KINDS, truths::PLUGIN_KINDS));
}
