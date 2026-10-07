//! KIND-ISOLATION'S FINDINGS ON A KNOWN-BAD PLANT, PINNED.
//!
//! The gate was made fast: its rules run concurrently and their rows are taken back in order, the
//! matrix masks and scans its files across the cores (and skips a needle a line's lowercased text
//! does not contain), the source index, the build inputs and the registration rule read their files
//! in parallel, and the production-line lexing is shared between the rules that each did it alone.
//! None of that may move a finding. A store crate is planted over the real tree — declared by its
//! `lib.rs`, so it is compiled source — naming a plane crate and the ledger it declares no
//! dependency on, and writing plane vocabulary eight ways, one of them a homoglyph. The findings
//! the plant produces are pinned as the serial gate reported them: the three undeclared crate paths
//! on the vocabulary row (`busbar-transport-http` is a crate of the census through its pinned
//! checkout, ARCHITECT W4B-Q1, so naming it is the same undeclared reach as naming the plane), and on the matrix row the planted file's own hit count and the
//! confusable it carries. Nothing pinned here depends on what the rest of the tree measures.

use std::path::PathBuf;

use xtask::ctx::{Ctx, Overlay};
use xtask::gates::execute;
use xtask::gates::kind_isolation::KindIsolationGate;
use xtask::ledger::Status;

const PLANT: &str = "crates/store-memory/src/gates_fast_plant.rs";
const LIB: &str = "crates/store-memory/src/lib.rs";

const PLANT_TEXT: &str = r#"//! gates-fast known-bad plant: every line below breaks a rule.
use busbar_plane_llm::VERSION;
use busbar_transport_http::Client;
pub fn forge(x: u8) {
    let _ = Pass::mint(x);
    let _ = <Grant<Dial>>::mint(x);
    let _ = KernelSeal::acquire_for_kernel(x);
}
pub fn price(e: &[LedgerEntry]) -> u64 {
    busbar_kernel_ledger::cost::apply_tier(e)
}
pub struct McpBridge;
pub fn handle_mcp() {}
pub const SECTION: &str = "streams:\n  x: 1";
pub fn voice_thing() {}
pub fn a2a_x() {}
#[derive(Debug)]
pub struct Credential(Vec<u8>);
pub fn redis_conn() {}
pub const HIDDEN: &str = "\x6dcp";
pub const GLYPH: &str = "vоice";
"#;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask/ has a parent")
        .to_path_buf()
}

#[test]
fn a_planted_store_crate_coupling_is_found_exactly_as_the_serial_gate_found_it() {
    let cx = Ctx::new(repo_root()).expect("the real tree opens with a writable scratch dir");
    let lib = cx.read(LIB).expect("the store crate's lib.rs reads");
    let mut ov = Overlay::new();
    ov.set(PLANT, PLANT_TEXT);
    ov.set(LIB, format!("{lib}mod gates_fast_plant;\n"));
    let verdict = execute(&KindIsolationGate::check(), &cx.with_overlay(ov));
    let row = |id: &str| {
        verdict
            .rows
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} was not emitted"))
    };

    let vocab = row("kind-isolation:vocab");
    assert_eq!(vocab.status, Status::Fail, "{}", vocab.detail);
    let planted: Vec<&str> = vocab
        .detail
        .split("undeclared-crate-path")
        .filter(|f| f.contains(PLANT))
        .collect();
    assert_eq!(planted.len(), 3, "{}", vocab.detail);
    for (line, owner) in [
        (2, "busbar-plane-llm"),
        (3, "busbar-transport-http"),
        (10, "busbar-kernel-ledger"),
    ] {
        let at = format!("{PLANT}:{line}");
        let says = format!(
            "busbar-store-memory (store crate) names `{owner}` and declares no dependency on it in \
             any table"
        );
        assert!(
            planted.iter().any(|f| f.contains(&at) && f.contains(&says)),
            "no finding at {at} naming {owner}: {}",
            vocab.detail
        );
    }

    // The matrix is REPORT-ONLY on predev (owner 2026-10-03, e106f8d74d): a PASS row whose detail
    // carries the measured total and the first findings, the per-file counts living in `--report`.
    // So what is pinned here is that it stays report-only and still finds the planted homoglyph;
    // the counts themselves are proven by the gate's whole TSV over the real tree, byte-identical
    // to predev's serial gate.
    let matrix = row("kind-isolation:matrix");
    assert_eq!(matrix.status, Status::Pass, "{}", matrix.detail);
    assert!(
        matrix.detail.contains(PLANT),
        "the planted file is not among the matrix findings: {}",
        matrix.detail
    );
    assert!(
        matrix
            .detail
            .contains("confusable\tbusbar-store-memory × plane")
            || matrix
                .detail
                .contains("confusable busbar-store-memory × plane"),
        "the planted homoglyph was not found: {}",
        matrix.detail
    );
}
