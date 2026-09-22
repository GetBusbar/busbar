//! Crate-level test suite for the admin surface's declarations.
//!
//! Inline (`#[cfg(test)] mod tests` from `mod.rs`) rather than an external `tests/` integration
//! crate, because the table-driven tests need this module's own `pub(crate)` verb table to state
//! their expectations without hand-duplicating it.
//!
//! WHAT IS NOT TESTED HERE ANY MORE, AND WHY. This file used to drive a `Plane` entry face:
//! `decode_ingress` over the pinned fixture's 66 operations, `encode_refusal`, `encode_response`'s
//! arena pass-through, and a determinism walk. The face is gone — a `Plane` is how TRAFFIC enters
//! the dispatch loop and the admin surface serves operators (#3/#5/#83 def 11) — and nothing
//! dispatched through it even while it existed: an admin request arrives on `admin_listen`, is
//! matched against `verbs::resolve`, and walks the loop as the admin units. So the coverage moved
//! to where the behaviour is:
//!
//! * the 66/34/32 fixture walk is `tests/verbs.rs`'s
//!   `every_1_5_5_fixture_operation_resolves_to_the_right_verb_and_scope`, which reads the same
//!   pinned document through `find_verb` — the lookup the live path runs;
//! * the frozen error envelope is `tests/refusal.rs`, through `envelope_of` — the function the
//!   administrative listener's every error answer is actually built with;
//! * the walk itself (a real verb, through the real mount, past the loop's steps, onto the audit
//!   chain) is `crates/busbar/src/root/units_admin/tests/admin_path_without_plane_face.rs`.

use busbar_contract::plane::PlaneMeta;

use crate::admin_codec::verbs::{self, VERB_COUNT};
use crate::admin_codec::AdminPlane;

// ── the closed table ───────────────────────────────────────────────────────────────────────────

/// The generated table declares exactly the pinned 34/32 split.
#[test]
fn generated_table_has_the_pinned_read_only_full_split() {
    let rows = &crate::admin_codec::generated::verb_table_1_5_5::VERB_TABLE_1_5_5;
    assert_eq!(rows.len(), 66);
    let read_only = rows.iter().filter(|(_, _, _, ro)| *ro).count();
    assert_eq!(read_only, 34);
    assert_eq!(rows.len() - read_only, 32);
}

/// The combined table (66 generated + 18 money-governance + 5 ledger views) has exactly the rows
/// its count declares, and no duplicate verb name.
#[test]
fn combined_table_has_unique_verb_names() {
    let all = verbs::table();
    assert_eq!(all.len(), VERB_COUNT);
    let mut names: Vec<&str> = all.iter().map(|e| e.verb).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(
        names.len(),
        before,
        "a verb name repeats in the combined table"
    );
}

// ── what the surface declares about itself ─────────────────────────────────────────────────────

/// `AdminPlane` has no fields — asserted structurally, not just by comment. It is a NAME the boot
/// registry holds the admin surface under, and there is nothing about one operator's request for it
/// to carry across calls.
#[test]
fn admin_plane_carries_no_fields() {
    assert_eq!(std::mem::size_of::<AdminPlane>(), 0);
}

/// The registry only requires `SessionPlane` when a claimed transport declares itself session
/// shaped; this surface's one claim is over `"http"`, and its `PlaneMeta` row carries a `CLAIMS`
/// slice of length one, matching `claims::CLAIMS`.
#[test]
fn declares_exactly_one_claim_over_http() {
    let claims = <AdminPlane as PlaneMeta>::CLAIMS;
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].transport, "http");
}

// ── the entry face is gone, and this is what says so ───────────────────────────────────────────

/// **THE CANARY FOR THIS WHOLE REMOVAL.** No shipped source file of this crate implements the
/// plane entry face.
///
/// `kind-isolation:faces` asks exactly this question across the tree and is the gate of record; this
/// asserts it in the crate itself, where an author re-adding the impl sees it fail in seconds rather
/// than at the next gate run. The rule it enforces: `busbar-core-admin` is kind `core` — a
/// compiled-in cleanliness crate, one-way dep, off the hot path (#5) — and `Plane` is the entry face
/// of kind `plane`. A trait implementation is a claim made to the COMPILER, and when it disagrees
/// with the crate's kind the compiler's claim is the one that runs.
///
/// SHIPPED SOURCE ONLY, which is the same cut the gate makes: a `tests/` file naming the trait (this
/// one does, twice, to state the rule) is not a claim the compiler acts on.
#[test]
fn no_shipped_source_of_this_crate_implements_the_plane_entry_face() {
    // Spelled in two pieces on purpose: a whole one would be the very literal this test scans for,
    // and this file lives inside the tree it walks.
    let needle = concat!("impl ", "Plane for");
    let qualified = concat!("impl busbar_contract::plane::", "Plane for");
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    walk(&src_dir, &mut |path, text| {
        if !is_shipped_source(path) {
            return;
        }
        for (n, line) in text.lines().enumerate() {
            if line.contains(needle) || line.contains(qualified) {
                offenders.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "a core crate implements the plane entry face again: {offenders:?}"
    );
}

/// The scan above is a filter and not a wall: it sees the shape it forbids when that shape is put
/// in front of it, and it does not see `PlaneMeta`, which is a DECLARATION and stays.
#[test]
fn the_entry_face_scan_sees_the_impl_it_forbids_and_not_the_declaration() {
    let sees = |line: &str| {
        line.contains(concat!("impl ", "Plane for"))
            || line.contains(concat!("impl busbar_contract::plane::", "Plane for"))
    };
    assert!(sees(concat!("impl ", "Plane for AdminPlane {")));
    assert!(sees(concat!(
        "impl busbar_contract::plane::",
        "Plane for AdminPlane {"
    )));
    assert!(!sees(concat!("impl ", "PlaneMeta for AdminPlane {")));
    assert!(!sees("use busbar_contract::plane::PlaneMeta;"));
}

/// Shipped source, as opposed to a fixture or a test — the same cut `kind-isolation:faces` makes.
fn is_shipped_source(path: &std::path::Path) -> bool {
    let rel = path.to_string_lossy().replace('\\', "/");
    !rel.contains("/tests/")
        && !rel.ends_with("/tests.rs")
        && !rel.ends_with("_test.rs")
        && !rel.ends_with("_tests.rs")
}

// ── no section-sign or parity-binding literals anywhere in this crate ──────────────────────────

#[test]
fn source_cites_the_design_in_words_not_in_symbols() {
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut offenders = Vec::new();
    walk(&src_dir, &mut |path, text| {
        for (n, line) in text.lines().enumerate() {
            if line.contains('\u{00a7}') {
                offenders.push(format!("{}:{}: section sign", path.display(), n + 1));
            }
            if cites_a_binding(line) {
                offenders.push(format!("{}:{}: binding identifier", path.display(), n + 1));
            }
        }
    });
    assert!(
        offenders.is_empty(),
        "section-sign or parity-binding literal found: {offenders:?}"
    );
}

/// Whether a line cites a parity binding by its identifier rather than in words.
///
/// The window is four bytes wide, so the last position it can start at is four from the end. An
/// exclusive bound of `len - 4` stops one position short of that, which makes the gate blind to a
/// citation that ENDS a line — the one place a comment naturally puts one.
fn cites_a_binding(line: &str) -> bool {
    let bytes = line.as_bytes();
    (0..bytes.len().saturating_sub(3)).any(|i| {
        bytes[i] == b'P'
            && bytes[i + 1] == b'B'
            && bytes[i + 2] == b'-'
            && bytes[i + 3].is_ascii_digit()
    })
}

/// The citations here are spelled in two pieces on purpose: a whole one would be the very literal
/// the gate above forbids, and this file is inside the tree it walks.
#[test]
fn the_binding_scan_sees_a_citation_that_ends_a_line() {
    assert!(
        cites_a_binding(concat!("// the admin-listener exemption, P", "B-7")),
        "a citation four bytes from the end is the shape a comment ends on"
    );
    assert!(cites_a_binding(concat!(
        "P",
        "B-60 is checked after Authenticate"
    )));
    assert!(!cites_a_binding("nothing here cites anything"));
    assert!(!cites_a_binding(concat!("P", "B- with no number")));
}

fn walk(dir: &std::path::Path, f: &mut impl FnMut(&std::path::Path, &str)) {
    let entries = std::fs::read_dir(dir).expect("src dir is readable");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, f);
        } else if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).expect("source file is readable");
            f(&path, &text);
        }
    }
}
