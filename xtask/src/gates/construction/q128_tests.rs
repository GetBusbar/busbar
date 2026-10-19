//! Q128 AUDIT (xtask parts 3, 7 and 14): the construction gate's ratchets, waivers and census,
//! each driven over a planted copy of the real tree. Every test here plants the edit the audit
//! named and asserts the row it should have turned RED.

use super::*;
use crate::ctx::Overlay;
use crate::ledger::Status;

/// The synthetic base every planted ceilings file is compared against.
const BASE: &str = "zz-q128-base";

fn workspace() -> Ctx {
    Ctx::workspace().expect("workspace")
}

fn ceilings_text(cx: &Ctx) -> String {
    cx.read(CEILINGS).expect("the ceilings file")
}

/// `ov` with the ceilings file set to `now` and the base pinned to a synthetic commit whose copy
/// of the ceilings file is `was`.
fn based(mut ov: Overlay, now: &str, was: &str) -> Overlay {
    ov.set(CEILINGS, now.to_string());
    ov.set_command(ceilings::BASE_PIN_KEY, BASE);
    ov.set_command(format!("git-show:{BASE}:{CEILINGS}"), was.to_string());
    ov
}

fn load(cx: &Ctx) -> (Cfg, Tree) {
    let cfg = ConstructionGate::cfg(cx).expect("ceilings");
    let tree = Tree::load(
        cx,
        &cfg.scan_roots().expect("scan roots"),
        &cfg.test_path_fragments().expect("fragments"),
    )
    .expect("tree");
    (cfg, tree)
}

fn row<'r>(rows: &'r [CRow], id: &str) -> &'r CRow {
    rows.iter()
        .find(|r| r.id == id)
        .unwrap_or_else(|| panic!("no `{id}` row among {:?}", ids(rows)))
}

fn ids(rows: &[CRow]) -> Vec<&str> {
    rows.iter().map(|r| r.id.as_str()).collect()
}

fn census_row(cx: &Ctx) -> CRow {
    let cfg = ConstructionGate::cfg(cx).expect("ceilings");
    census::ceiling_census(cx, &cfg).remove(0)
}

/// p7 HIGH 1. A census floor BELOW what its kind glob matches lets the kind shrink to the floor
/// unseen (Law 9: a census floor pins at TODAY'S MEASURED VALUE). The plane floor is planted one
/// below the plane count; base and tree carry the same file, so only the measurement can see it.
#[test]
fn q128_a_census_floor_below_its_measurement_is_red() {
    let cx = workspace();
    let cfg = ConstructionGate::cfg(&cx).expect("ceilings");
    let n = dirs_for_globs(&cx, &cfg.kind_globs("plane").expect("plane kind")).len() as i64;
    assert!(
        n >= 2,
        "the control needs at least two plane crates, found {n}"
    );
    let planted = ceilings::set_int(
        &ceilings_text(&cx),
        "gate.census.plugin_kinds",
        "plane",
        n - 1,
    )
    .expect("the plane floor");
    let pcx = cx.with_overlay(based(Overlay::new(), &planted, &planted));
    let r = census_row(&pcx);
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
    assert!(r.detail.contains("plane"), "{}", r.detail);
}

/// p14 HIGH 1. A crate added to the unsafe-code debt list in the change that strips its attribute.
/// The forbid-unsafe row reads the debt list from the tree under judgement, so it is green; the
/// list must be held to the base, where the crate is not debt.
#[test]
fn q128_an_unsafe_debt_entry_minted_in_the_change_is_red() {
    let cx = workspace();
    let lib = "crates/busbar-plane-llm/src/lib.rs";
    let text = cx.read(lib).expect("the plane's root");
    assert!(
        text.contains("#![forbid(unsafe_code)]"),
        "the control needs the attribute"
    );
    let was = ceilings_text(&cx);
    let now = ceilings::add_to_list(
        &was,
        "rules.forbid-unsafe",
        "known_missing_forbid",
        &["busbar-plane-llm".to_string()],
    )
    .expect("the forbid debt list");
    let mut ov = Overlay::new();
    ov.set(lib, text.replace("#![forbid(unsafe_code)]", ""));
    let pcx = cx.with_overlay(based(ov, &now, &was));
    let r = census_row(&pcx);
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
    assert!(r.detail.contains("known_missing_forbid"), "{}", r.detail);
    assert!(r.detail.contains("busbar-plane-llm"), "{}", r.detail);
}

/// p7 MEDIUM 2. Every count ratchet is exact: a ceiling above its measurement is headroom for the
/// next site, and the drain ratchets the ceiling down (Law 9). Each figure is planted one above
/// what the tree measures.
#[test]
fn q128_a_count_ratchet_above_its_measurement_is_red() {
    let cx = workspace();
    let (cfg, tree) = load(&cx);
    let gauntlet = rules::one_teller_loop(&tree, &cfg).expect("one-teller-loop");
    let legacy = row(&gauntlet, "one-teller-loop:run_gauntlet").current;
    let ports = rules::ports_only(&tree, &cfg).expect("ports-only");
    let plane = cfg.plane_crates().expect("plane crates")[0].clone();
    let prod = row(&ports, &format!("ports-only:{plane}")).current;
    let test = row(&ports, &format!("ports-only-tests:{plane}")).current;

    let mut text = ceilings_text(&cx);
    text = ceilings::set_int(
        &text,
        "rules.one-teller-loop",
        "max_legacy_sites",
        legacy + 1,
    )
    .expect("max_legacy_sites");
    text = ceilings::set_int(&text, "rules.ports-only.max_per_crate", &plane, prod + 1)
        .expect("ports-only figure");
    text = ceilings::set_int(
        &text,
        "rules.ports-only-tests.max_per_crate",
        &plane,
        test + 1,
    )
    .expect("ports-only-tests figure");
    let mut ov = Overlay::new();
    ov.set(CEILINGS, text);
    let pcx = cx.with_overlay(ov);
    let (cfg, tree) = load(&pcx);
    let rows = rules::one_teller_loop(&tree, &cfg).expect("one-teller-loop");
    let r = row(&rows, "one-teller-loop:run_gauntlet");
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
    let rows = rules::ports_only(&tree, &cfg).expect("ports-only");
    for id in [
        format!("ports-only:{plane}"),
        format!("ports-only-tests:{plane}"),
    ] {
        let r = row(&rows, &id);
        assert_eq!(r.status, Status::Fail, "{id}: {}", r.detail);
    }
}

/// p7 MEDIUM 3. A plugin naming a KERNEL-SIDE crate is RED whatever the review lists say: the
/// kernel sub-crates were "unreviewed" (excused by one `reviewed_extra` line), and a
/// `known_red_deps` line excused even `busbar-kernel`.
#[test]
fn q128_a_plugin_naming_a_kernel_side_crate_is_red_whatever_the_lists_say() {
    let cx = workspace();
    let manifest = "crates/busbar-plane-llm/Cargo.toml";
    let text = cx.read(manifest).expect("the plane's manifest");
    assert!(
        text.contains("\n[dependencies]\n"),
        "the control needs a [dependencies] table"
    );
    let base = ceilings_text(&cx);
    for (dep, table) in [
        (
            "busbar-kernel-ledger",
            "rules.manifest-allowlist.reviewed_extra",
        ),
        ("busbar-kernel", "rules.manifest-allowlist.known_red_deps"),
    ] {
        let mut ov = Overlay::new();
        ov.set(
            manifest,
            text.replacen(
                "\n[dependencies]\n",
                &format!("\n[dependencies]\n{dep} = {{ path = \"../{dep}\" }}\n"),
                1,
            ),
        );
        let lists = ceilings::add_to_list(&base, table, "busbar-plane-llm", &[dep.to_string()])
            .expect("the review list");
        ov.set(CEILINGS, lists);
        let pcx = cx.with_overlay(ov);
        let (cfg, tree) = load(&pcx);
        let rows = rules2::manifest_allowlist(&pcx, &tree, &cfg).expect("manifest-allowlist");
        let r = row(&rows, "manifest-allowlist:busbar-plane-llm");
        assert_eq!(r.status, Status::Fail, "{dep} via {table}: {}", r.detail);
        assert!(r.detail.contains(dep), "{}", r.detail);
    }
}

/// p7 MEDIUM 4. A reviewed WHOLE FILE absorbed any number of new escapes uncounted: a new
/// `mem::forget` in `router.rs` (a reviewed money-path file) stayed green.
#[test]
fn q128_a_new_escape_in_a_reviewed_file_is_red() {
    let cx = workspace();
    let router = "crates/busbar-kernel/src/router.rs";
    let text = cx.read(router).expect("router.rs");
    let mut ov = Overlay::new();
    ov.set(
        router,
        format!("pub fn zz_planted_forget(h: u8) {{\n    std::mem::forget(h);\n}}\n{text}"),
    );
    let pcx = cx.with_overlay(ov);
    let (cfg, tree) = load(&pcx);
    let rows = rules2::hold_escapes(&pcx, &tree, &cfg).expect("hold-escapes");
    let r = row(&rows, "hold-escapes");
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
    assert!(r.detail.contains("router.rs"), "{}", r.detail);
}

/// p7 MEDIUM 4. An entry that suppresses nothing is a dead waiver for the next site at its path,
/// on all three waiver lists.
#[test]
fn q128_a_waiver_that_matches_nothing_is_red() {
    let cx = workspace();
    let base = ceilings_text(&cx);
    for rule in ["hold-escapes", "seal-sites", "kernel-seal-impls"] {
        let dead = format!(
            "crates/busbar-kernel/src/zz_dead_{}.rs",
            rule.replace('-', "_")
        );
        let planted = ceilings::add_to_list(
            &base,
            &format!("rules.{rule}"),
            "known_sites",
            std::slice::from_ref(&dead),
        )
        .expect("the known_sites list");
        let mut ov = Overlay::new();
        ov.set(CEILINGS, planted);
        let pcx = cx.with_overlay(ov);
        let (cfg, tree) = load(&pcx);
        let rows = match rule {
            "hold-escapes" => rules2::hold_escapes(&pcx, &tree, &cfg),
            "seal-sites" => rules2::seal_sites(&pcx, &tree, &cfg),
            _ => rules2::kernel_seal_impls(&tree, &cfg),
        }
        .expect("the rule runs");
        let r = row(&rows, rule);
        assert_eq!(r.status, Status::Fail, "{rule}: {}", r.detail);
        assert!(r.detail.contains(&dead), "{rule}: {}", r.detail);
    }
}

/// p7 MEDIUM 4. A directory entry on hold-escapes excuses every file under it, present and
/// future. Planted over a directory with no escape in it today.
#[test]
fn q128_a_directory_entry_on_hold_escapes_is_red() {
    let cx = workspace();
    let dir = "crates/busbar-kernel-scope/src/".to_string();
    let planted = ceilings::add_to_list(
        &ceilings_text(&cx),
        "rules.hold-escapes",
        "known_sites",
        std::slice::from_ref(&dir),
    )
    .expect("the known_sites list");
    let mut ov = Overlay::new();
    ov.set(CEILINGS, planted);
    let pcx = cx.with_overlay(ov);
    let (cfg, tree) = load(&pcx);
    let rows = rules2::hold_escapes(&pcx, &tree, &cfg).expect("hold-escapes");
    let r = row(&rows, "hold-escapes");
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
    assert!(r.detail.contains(&dir), "{}", r.detail);
}

/// p7 LOW 6. `use std::mem::{forget}` then `forget(hold)` spells `mem::forget` nowhere.
#[test]
fn q128_a_grouped_import_of_an_escape_is_seen() {
    let cx = workspace();
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-kernel-scope/src/zz_planted_grouped.rs",
        "use std::mem::{forget};\n\npub fn zz_planted(h: u8) {\n    forget(h);\n}\n",
    );
    let pcx = cx.with_overlay(ov);
    let (cfg, tree) = load(&pcx);
    let rows = rules2::hold_escapes(&pcx, &tree, &cfg).expect("hold-escapes");
    let r = row(&rows, "hold-escapes");
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
    assert!(r.detail.contains("zz_planted_grouped.rs"), "{}", r.detail);
}

/// p7 LOW 6. hold-discipline (a) read only the FIRST take and the FIRST settle: a second take
/// followed by `?` before its own settle went unread.
#[test]
fn q128_an_early_exit_after_a_second_take_is_seen() {
    let cx = workspace();
    let mut ov = Overlay::new();
    ov.set(
        "crates/busbar-kernel-scope/src/zz_planted_pair.rs",
        "pub fn zz_planted_pair(cell: &Cell, t: Token) -> Result<(), E> {\n    \
         let a = cell.take(t);\n    a.settle(t);\n    let b = cell.take(t);\n    \
         let _ = fallible()?;\n    b.settle(t);\n    Ok(())\n}\n",
    );
    let pcx = cx.with_overlay(ov);
    let (cfg, tree) = load(&pcx);
    let rows = rules2::hold_discipline(&pcx, &tree, &cfg).expect("hold-discipline");
    let r = row(&rows, "hold-discipline:no-early-exit");
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
    assert!(r.detail.contains("zz_planted_pair"), "{}", r.detail);
}

/// p7 LOW 5. A configured verb that names no production function is a subject that vanished,
/// not zero sites: the lane-pick verb and the loop verb.
#[test]
fn q128_a_verb_that_resolves_nothing_is_red() {
    let cx = workspace();
    let mut text = ceilings_text(&cx);
    text = text.replacen("verb = \"pick_among\"", "verb = \"zz_no_such_pick\"", 1);
    text = text.replacen(
        "loop_verb = \"run_unit\"",
        "loop_verb = \"zz_no_such_loop\"",
        1,
    );
    let mut ov = Overlay::new();
    ov.set(CEILINGS, text);
    let pcx = cx.with_overlay(ov);
    let (cfg, tree) = load(&pcx);
    let rows = rules::one_pick_site(&tree, &cfg).expect("one-pick-site");
    let r = row(&rows, "one-pick-site");
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
    assert!(r.detail.contains("zz_no_such_pick"), "{}", r.detail);
    let rows = rules::one_teller_loop(&tree, &cfg).expect("one-teller-loop");
    let r = row(&rows, "one-teller-loop");
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
    assert!(r.detail.contains("zz_no_such_loop"), "{}", r.detail);
}

/// p7 LOW 5. One configured secret carrier that is declared nowhere dropped out of the count.
#[test]
fn q128_a_secret_carrier_declared_nowhere_is_red() {
    let cx = workspace();
    let planted = ceilings::add_to_list(
        &ceilings_text(&cx),
        "rules.secret-carrier-debug",
        "carriers",
        &["ZzNoSuchCarrier".to_string()],
    )
    .expect("the carriers list");
    let mut ov = Overlay::new();
    ov.set(CEILINGS, planted);
    let pcx = cx.with_overlay(ov);
    let (cfg, tree) = load(&pcx);
    let rows = rules2::secret_carrier_debug(&tree, &cfg).expect("secret-carrier-debug");
    let r = row(&rows, "secret-carrier-debug");
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
    assert!(r.detail.contains("ZzNoSuchCarrier"), "{}", r.detail);
}

/// p7 LOW 5. A purity artefact with no scan-count line is a scan that did not report running.
#[test]
fn q128_a_purity_answer_with_no_scan_count_is_red() {
    let cx = workspace();
    let cfg = ConstructionGate::cfg(&cx).expect("ceilings");
    let rows = rules::neutral_no_dialect(&cfg, Some("")).expect("neutral-no-dialect");
    let r = row(&rows, "neutral-no-dialect");
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
}

/// p7 LOW 7. A review verdict that is neither `real` nor `double` waived its site from both rows.
#[test]
fn q128_a_test_double_review_with_an_unknown_verdict_is_red() {
    let cx = workspace();
    let file = "crates/busbar/src/root/zz_planted_double.rs";
    let mut ov = Overlay::new();
    ov.set(file, "pub fn zz_planted() {\n    let _ = NullShipper;\n}\n");
    let text = format!(
        "{}\n[rules.no-test-doubles-in-production.known_sites.zz-planted]\nfile = \"{file}\"\n\
         symbol = \"NullShipper\"\nverdict = \"dobule\"\nbecause = \"planted\"\n",
        ceilings_text(&cx)
    );
    ov.set(CEILINGS, text);
    let pcx = cx.with_overlay(ov);
    let (cfg, tree) = load(&pcx);
    let rows = rules2::no_test_doubles_in_production(&tree, &cfg).expect("no-test-doubles");
    let r = row(&rows, "no-test-doubles-in-production");
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
    assert!(r.detail.contains("dobule"), "{}", r.detail);
}

/// p7 LOW 7. A review of (file, symbol) excused every later construction of that symbol in the
/// file: a second `NullShipper` beside the reviewed one stayed green.
#[test]
fn q128_a_second_construction_beside_a_reviewed_one_is_red() {
    let cx = workspace();
    let file = "crates/busbar/src/root/kernel.rs";
    let text = cx.read(file).expect("kernel.rs");
    let mut ov = Overlay::new();
    ov.set(
        file,
        format!("pub fn zz_planted_second() {{\n    let _ = NullShipper;\n}}\n{text}"),
    );
    let pcx = cx.with_overlay(ov);
    let (cfg, tree) = load(&pcx);
    let rows = rules2::no_test_doubles_in_production(&tree, &cfg).expect("no-test-doubles");
    let r = row(&rows, "no-test-doubles-in-production");
    assert_eq!(r.status, Status::Fail, "{}", r.detail);
    assert!(r.detail.contains("kernel.rs"), "{}", r.detail);
}

/// p3 LOW 7. A string literal continued over a line end (`"…\`) is still a literal on the next
/// line: its braces are not code, and its `//` is not a comment.
#[test]
fn q128_a_continued_literal_is_not_read_as_code() {
    let lexer = tree::Lexer::new().expect("the lexer");
    let src = "pub fn a() {\n    let s = \"one {\\\n        two // three\";\n}\n\n\
               #[cfg(test)]\nmod tests {\n    fn t() {}\n}\n\npub fn after() {}\n";
    let lines = tree::scan_text(&lexer, "crates/x/src/lib.rs", src, &[]);
    assert!(
        lines[2].code.contains("// three"),
        "the `//` inside the literal was stripped as a comment: {:?}",
        lines[2].code
    );
    assert_eq!(
        lines[1].blank.matches('{').count(),
        0,
        "a brace inside the continued literal was read as code: {:?}",
        lines[1].blank
    );
    let after = lines
        .iter()
        .find(|l| l.code.contains("fn after"))
        .expect("after");
    assert!(
        !after.intest,
        "the line after the test module was filed as test code"
    );
    let fns = tree::find_fns(&lexer, "crates/x/src/lib.rs", &lines);
    let a = fns.iter().find(|f| f.name == "a").expect("fn a");
    assert_eq!(a.end, 4, "fn a's extent ran past its closing brace");
}
