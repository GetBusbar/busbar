//! `cargo xtask ledger-merge`: fixture triplets (base, ours, theirs) for every rule, a RED arm for
//! every refusal (driven through [`main`] where the promise is "ours is left untouched"), and the
//! committed ledger itself for the byte-identical round trip.

use super::*;

const HEAD: &str = "# qa/kind-isolation.toml (fixture)\n\n";

fn ledger(rows: &[String]) -> String {
    format!("{HEAD}{}", rows.join("\n"))
}

fn law0(krate: &str, axis: &str, count: &str, cite: &str) -> String {
    format!(
        "[[law0]]\ncrate = \"{krate}\"\naxis  = \"{axis}\"\ncount = \"{count}\"\ncite  = \"{cite}\"\n"
    )
}

fn dep(count: &str, verdict: &str, why: &str, drain: &str) -> String {
    format!(
        "[[dep]]\nfrom    = \"busbar\"\nto      = \"busbar-a2a\"\nhalf    = \"shipped\"\n\
         count   = \"{count}\"\nverdict = \"{verdict}\"\ncite    = \"BUSBAR-1.6.0.md THE DESIGN, \
         §1\"\nwhy     = \"{why}\"\ndrain   = \"{drain}\"\n"
    )
}

fn why(n: u32) -> String {
    format!("busbar names busbar-a2a: {n} declaration(s) at this commit, exact in both directions")
}

fn refusals(b: &str, o: &str, t: &str) -> String {
    match merge(b, o, t) {
        Ok(text) => panic!("expected a refusal, got a merge:\n{text}"),
        Err(e) => e.join("\n"),
    }
}

/// Run the driver the way git does — three files, OURS rewritten in place — and hand back the exit
/// code and what OURS holds afterwards.
fn drive(name: &str, b: &str, o: &str, t: &str) -> (i32, String) {
    let dir =
        std::env::temp_dir().join(format!("xtask-ledger-merge-{name}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let paths = [dir.join("base"), dir.join("ours"), dir.join("theirs")];
    for (p, text) in paths.iter().zip([b, o, t]) {
        std::fs::write(p, text).unwrap();
    }
    let args: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    let code = main(&args);
    let after = std::fs::read_to_string(&paths[1]).unwrap();
    // OURS is the only file the driver may write: base and theirs are as they were, and nothing
    // else appeared beside them.
    assert_eq!(std::fs::read_to_string(&paths[0]).unwrap(), b);
    assert_eq!(std::fs::read_to_string(&paths[2]).unwrap(), t);
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 3);
    let _ = std::fs::remove_dir_all(&dir);
    (code, after)
}

fn committed_ledger() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join(LEDGER);
    std::fs::read_to_string(path).unwrap()
}

/// `text` with the `count` of the first `[[table]]` row moved by `delta`.
fn move_first_count(text: &str, table: &str, delta: i64) -> String {
    let at = text.find(&format!("[[{table}]]")).unwrap();
    let key = at + text[at..].find("\ncount").unwrap();
    let open = key + text[key..].find('"').unwrap() + 1;
    let close = open + text[open..].find('"').unwrap();
    let n: i64 = text[open..close].parse().unwrap();
    format!("{}{}{}", &text[..open], n + delta, &text[close..])
}

// ------------------------------------------------------------------------------------------------
// GREEN: what settles
// ------------------------------------------------------------------------------------------------

const KERNEL_BASE_CITE: &str = "measured on predev f830faa691 (ARCHITECT 2026-10-07, Law 9); the \
drain is THE DESIGN §1 / DoD item 2: core names no instance; LOWERED 288 -> 286, predev \
9c0a394771's measure: the drain landed without giving its row back (Law 9: the ceiling ratchets \
down); LOWERED 286 -> 285 by GetBusbar/busbar#570: the kernel's auth proof no longer cites the \
root's stdio-served proof";
const KERNEL_THEIRS_CLAUSE: &str =
    "; LOWERED 285 -> 284 by row 157: the hit drained with the same deletion";
const KERNEL_OURS_CLAUSE_TAIL: &str = " (-17), the verbatim listener serve loop moved out of \
busbar-kernel into the root (#710), paired with busbar x transport 208 -> 225 (+17) so the law0 \
total does not rise (ARCHITECT RULING 2026-10-10, \
https://github.com/GetBusbar/busbar/pull/710#issuecomment-6096420101; BUSBAR-1.6.0.md l.475-483 \
INBOUND-LISTEN: the root's stream hand-up)";

#[test]
fn the_kernel_transport_row_both_lanes_moved_settles_at_theirs_plus_ours_minus_base() {
    // #741 against #798, as it was settled by hand: base 285, predev lowered it to 284 (row 157),
    // the lane rebalanced it to 268 (-17, a ruled move). Both deltas are real: 284 - 17 = 267.
    // The lane's paired row (busbar × transport 208 -> 225) moved on its side only.
    let measured = "measured on predev f830faa691";
    let base = ledger(&[
        law0("busbar", "transport", "208", measured),
        law0("busbar-kernel", "transport", "285", KERNEL_BASE_CITE),
    ]);
    let theirs = ledger(&[
        law0("busbar", "transport", "208", measured),
        law0(
            "busbar-kernel",
            "transport",
            "284",
            &format!("{KERNEL_BASE_CITE}{KERNEL_THEIRS_CLAUSE}"),
        ),
    ]);
    let busbar_ours = law0(
        "busbar",
        "transport",
        "225",
        &format!("{measured}; REBALANCED 208 -> 225 (+17) from busbar-kernel (#710)"),
    );
    let ours = ledger(&[
        busbar_ours.clone(),
        law0(
            "busbar-kernel",
            "transport",
            "268",
            &format!("{KERNEL_BASE_CITE}; REBALANCED 285 -> 268{KERNEL_OURS_CLAUSE_TAIL}"),
        ),
    ]);
    let want = ledger(&[
        busbar_ours,
        law0(
            "busbar-kernel",
            "transport",
            "267",
            &format!(
                "{KERNEL_BASE_CITE}{KERNEL_THEIRS_CLAUSE}; REBALANCED 284 -> 267{KERNEL_OURS_CLAUSE_TAIL}"
            ),
        ),
    ]);
    assert_eq!(merge(&base, &ours, &theirs).unwrap(), want);
    let (code, after) = drive("kernel-transport", &base, &ours, &theirs);
    assert_eq!(code, 0);
    assert_eq!(
        after, want,
        "OURS is rewritten in place with the settled file"
    );
}

#[test]
fn a_row_changed_on_one_side_only_takes_that_sides_text_verbatim() {
    let base = ledger(&[law0("busbar", "auth", "10", "measured")]);
    let moved = ledger(&[law0(
        "busbar",
        "auth",
        "9",
        "measured;   LOWERED 10 -> 9, spacing and all",
    )]);
    assert_eq!(merge(&base, &moved, &base).unwrap(), moved);
    assert_eq!(merge(&base, &base, &moved).unwrap(), moved);
}

#[test]
fn a_change_both_sides_made_identically_is_kept_once() {
    let base = ledger(&[dep("1", "allowed", &why(1), "none")]);
    let both = ledger(&[dep("1", "allowed", &why(1), "none: the class is granted")]);
    assert_eq!(merge(&base, &both, &both).unwrap(), both);
}

#[test]
fn different_rows_changed_on_each_side_both_land() {
    let base = ledger(&[
        law0("busbar", "auth", "10", "measured"),
        law0("busbar", "export", "15", "measured"),
    ]);
    let ours = ledger(&[
        law0("busbar", "auth", "9", "measured; LOWERED 10 -> 9"),
        law0("busbar", "export", "15", "measured"),
    ]);
    let theirs = ledger(&[
        law0("busbar", "auth", "10", "measured"),
        law0("busbar", "export", "14", "measured; LOWERED 15 -> 14"),
    ]);
    let want = ledger(&[
        law0("busbar", "auth", "9", "measured; LOWERED 10 -> 9"),
        law0("busbar", "export", "14", "measured; LOWERED 15 -> 14"),
    ]);
    assert_eq!(merge(&base, &ours, &theirs).unwrap(), want);
}

#[test]
fn a_why_that_carries_the_count_follows_the_merged_count() {
    let base = ledger(&[dep("2", "allowed", &why(2), "none")]);
    let ours = ledger(&[dep("4", "allowed", &why(4), "none")]);
    let theirs = ledger(&[dep("3", "allowed", &why(3), "none")]);
    assert_eq!(
        merge(&base, &ours, &theirs).unwrap(),
        ledger(&[dep("5", "allowed", &why(5), "none")])
    );
}

#[test]
fn a_row_added_on_one_side_keeps_its_place() {
    let a = |n: &str| law0("busbar", "auth", n, "measured");
    let x = law0("busbar", "hooks", "1", "measured: new on this lane");
    let c = law0("busbar", "secret", "3", "measured");
    let base = ledger(&[a("10"), c.clone()]);
    let ours = ledger(&[a("10"), x.clone(), c.clone()]);
    let theirs = ledger(&[a("11"), c.clone()]);
    assert_eq!(
        merge(&base, &ours, &theirs).unwrap(),
        ledger(&[a("11"), x.clone(), c.clone()])
    );
    // The same row added by both sides, byte for byte, is kept once.
    assert_eq!(
        merge(&base, &ours, &ours).unwrap(),
        ledger(&[a("10"), x, c])
    );
}

#[test]
fn a_row_deleted_on_one_side_and_untouched_on_the_other_is_deleted() {
    let a = |n: &str| law0("busbar", "auth", n, "measured");
    let c = law0("busbar", "secret", "3", "measured");
    let base = ledger(&[a("10"), c.clone()]);
    assert_eq!(
        merge(&base, &ledger(&[a("10")]), &ledger(&[a("9"), c.clone()])).unwrap(),
        ledger(&[a("9")])
    );
    assert_eq!(
        merge(&base, &ledger(&[a("9"), c]), &ledger(&[a("10")])).unwrap(),
        ledger(&[a("9")])
    );
}

#[test]
fn nothing_conflicting_round_trips_the_committed_ledger_byte_for_byte() {
    let real = committed_ledger_row_by_row();
    assert_eq!(merge(&real, &real, &real).unwrap(), real);
    let theirs = move_first_count(&real, "law0", -1);
    let ours = move_first_count(&real, "dep", 1);
    assert_eq!(merge(&real, &real, &theirs).unwrap(), theirs);
    assert_eq!(merge(&real, &ours, &real).unwrap(), ours);
    assert_eq!(
        merge(&real, &ours, &theirs).unwrap(),
        move_first_count(&ours, "law0", -1)
    );
}

/// The committed ledger, with every row it holds named by an identity the gate keys it by.
fn committed_ledger_row_by_row() -> String {
    let real = committed_ledger();
    let parsed = parse(&real, "committed").unwrap_or_else(|e| panic!("{}", e.join("\n")));
    let headers = real
        .lines()
        .filter(|l| l.trim().starts_with("[[") && l.trim().ends_with("]]"))
        .count();
    assert_eq!(parsed.records.len(), headers);
    real
}

// ------------------------------------------------------------------------------------------------
// RED: every refusal, and ours untouched
// ------------------------------------------------------------------------------------------------

#[test]
fn both_sides_moving_a_count_to_the_same_number_is_refused_and_ours_is_untouched() {
    // #741 and #800 both carried the E1 listener move 285 -> 268: theirs + ours - base would
    // count one change twice. Not guessed: refused.
    let base = ledger(&[law0("busbar-kernel", "transport", "285", "measured")]);
    let ours = ledger(&[law0(
        "busbar-kernel",
        "transport",
        "268",
        "measured; REBALANCED 285 -> 268 (-17)",
    )]);
    let theirs = ledger(&[law0(
        "busbar-kernel",
        "transport",
        "268",
        "measured; REBALANCED 285 -> 268 (-17), E1",
    )]);
    let why = refusals(&base, &ours, &theirs);
    assert!(
        why.contains("both sides moved [[law0]] crate = \"busbar-kernel\", axis = \"transport\" from 285 to the same count 268 — a shared change or a coincidence; settle by hand (take theirs if it is the same change)"),
        "{why}"
    );
    // Identical text on both sides is the same refusal: the count moved on both.
    assert!(refusals(&base, &ours, &ours).contains("the same count 268"));
    let (code, after) = drive("same-count", &base, &ours, &theirs);
    assert_eq!(code, 1);
    assert_eq!(after, ours);
}

#[test]
fn a_row_added_on_both_sides_with_different_text_is_refused_and_ours_is_untouched() {
    let base = ledger(&[law0("busbar", "auth", "10", "measured")]);
    let ours = ledger(&[
        law0("busbar", "auth", "10", "measured"),
        law0("busbar", "hooks", "3", "measured on the lane"),
    ]);
    let theirs = ledger(&[
        law0("busbar", "auth", "10", "measured"),
        law0("busbar", "hooks", "4", "measured on predev"),
    ]);
    assert!(refusals(&base, &ours, &theirs).contains("added on both sides with different text"));
    let (code, after) = drive("added-both", &base, &ours, &theirs);
    assert_eq!(code, 1);
    assert_eq!(after, ours);
}

#[test]
fn a_row_deleted_on_one_side_and_changed_on_the_other_is_refused() {
    let a = law0("busbar", "auth", "10", "measured");
    let c = |n: &str| law0("busbar", "secret", n, "measured");
    let base = ledger(&[a.clone(), c("3")]);
    let deleted = ledger(std::slice::from_ref(&a));
    let changed = ledger(&[a, c("2")]);
    assert!(
        refusals(&base, &deleted, &changed).contains("ours deleted the row and theirs changed it")
    );
    assert!(
        refusals(&base, &changed, &deleted).contains("theirs deleted the row and ours changed it")
    );
    let (code, after) = drive("deleted-changed", &base, &deleted, &changed);
    assert_eq!(code, 1);
    assert_eq!(after, deleted);
}

#[test]
fn a_non_count_field_changed_differently_on_both_sides_is_refused_by_row_and_field() {
    let base = ledger(&[dep("1", "allowed", &why(1), "none")]);
    let ours = ledger(&[dep("2", "tcb", &why(2), "none")]);
    let theirs = ledger(&[dep("3", "not-allowed", &why(3), "none")]);
    let why = refusals(&base, &ours, &theirs);
    assert!(
        why.contains("[[dep]] from = \"busbar\", to = \"busbar-a2a\", half = \"shipped\": verdict: changed differently on both sides"),
        "{why}"
    );
    let (code, after) = drive("verdict", &base, &ours, &theirs);
    assert_eq!(code, 1);
    assert_eq!(after, ours);
}

#[test]
fn a_negative_result_is_refused() {
    let base = ledger(&[law0("busbar", "auth", "5", "measured")]);
    let ours = ledger(&[law0("busbar", "auth", "0", "measured; LOWERED 5 -> 0")]);
    let theirs = ledger(&[law0("busbar", "auth", "3", "measured; LOWERED 5 -> 3")]);
    assert!(
        refusals(&base, &ours, &theirs).contains("= -2, and a measured count is never negative")
    );
    let (code, after) = drive("negative", &base, &ours, &theirs);
    assert_eq!(code, 1);
    assert_eq!(after, ours);
}

#[test]
fn a_count_that_is_not_an_integer_is_refused() {
    let base = ledger(&[law0("busbar", "auth", "5", "measured")]);
    let ours = ledger(&[law0("busbar", "auth", "five", "measured")]);
    let theirs = ledger(&[law0("busbar", "auth", "4", "measured")]);
    assert!(refusals(&base, &ours, &theirs).contains("not an integer"));
}

#[test]
fn a_cite_ours_rewrote_rather_than_extended_is_refused() {
    let base = ledger(&[law0("busbar", "auth", "10", "measured on X")]);
    let ours = ledger(&[law0(
        "busbar",
        "auth",
        "8",
        "measured on Y; LOWERED 10 -> 8",
    )]);
    let theirs = ledger(&[law0(
        "busbar",
        "auth",
        "9",
        "measured on X; LOWERED 10 -> 9",
    )]);
    assert!(refusals(&base, &ours, &theirs).contains("cite: ours rewrote base's text"));
}

#[test]
fn a_cite_whose_first_move_is_not_the_rows_is_refused() {
    let base = ledger(&[law0("busbar", "auth", "10", "measured")]);
    let ours = ledger(&[law0("busbar", "auth", "8", "measured; LOWERED 9 -> 8")]);
    let theirs = ledger(&[law0("busbar", "auth", "9", "measured; LOWERED 10 -> 9")]);
    assert!(refusals(&base, &ours, &theirs)
        .contains("first reads `9 -> 8`, not this row's move `10 -> 8`"));
}

#[test]
fn header_text_changed_differently_on_both_sides_is_refused() {
    let row = law0("busbar", "auth", "10", "measured");
    let base = format!("# head\n\n{row}");
    let ours = format!("# head, ours\n\n{row}");
    let theirs = format!("# head, theirs\n\n{row}");
    assert!(refusals(&base, &ours, &theirs).contains("the comment above it: changed differently"));
    let base = format!("{row}\n# tail\n");
    let ours = format!("{row}\n# tail, ours\n");
    let theirs = format!("{row}\n# tail, theirs\n");
    assert!(refusals(&base, &ours, &theirs).contains("the text after the last row"));
}

#[test]
fn a_table_the_gate_does_not_read_is_refused() {
    let base = ledger(&[law0("busbar", "auth", "10", "measured")]);
    let odd = format!("{base}\n[[nosuch]]\ncrate = \"busbar\"\n");
    assert!(refusals(&base, &odd, &base).contains("`[[nosuch]]` is not a table"));
    let twice = ledger(&[
        law0("busbar", "auth", "10", "measured"),
        law0("busbar", "auth", "10", "measured"),
    ]);
    assert!(refusals(&base, &twice, &base).contains("appears twice"));
}

#[test]
fn the_arguments_are_three_paths_and_an_unreadable_one_could_not_run() {
    assert_eq!(main(&[]), 2);
    assert_eq!(main(&["a".to_string(), "b".to_string()]), 2);
    let missing = std::env::temp_dir()
        .join(format!("xtask-ledger-merge-missing-{}", std::process::id()))
        .to_string_lossy()
        .into_owned();
    assert_eq!(main(&[missing.clone(), missing.clone(), missing]), 3);
    let six: Vec<String> = (0..6).map(|i| i.to_string()).collect();
    assert_eq!(main(&six), 2);
}

#[test]
fn gits_optional_path_and_marker_size_are_accepted_after_the_three_paths() {
    let base = ledger(&[law0("busbar", "auth", "10", "measured")]);
    let ours = ledger(&[law0("busbar", "auth", "9", "measured; LOWERED 10 -> 9")]);
    let dir = std::env::temp_dir().join(format!(
        "xtask-ledger-merge-placeholders-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let paths = [dir.join("base"), dir.join("ours"), dir.join("theirs")];
    for (p, text) in paths.iter().zip([&base, &base, &ours]) {
        std::fs::write(p, text).unwrap();
    }
    let mut args: Vec<String> = paths
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    args.push(LEDGER.to_string());
    args.push("7".to_string());
    assert_eq!(main(&args), 0);
    assert_eq!(std::fs::read_to_string(&paths[1]).unwrap(), ours);
    let _ = std::fs::remove_dir_all(&dir);
}

/// THE IDENTITY TABLE IS THE GATE'S: every table `kind_isolation::push_row` reads has a row in
/// [`IDENTITY`], and [`IDENTITY`] names no table it does not read.
#[test]
fn every_table_the_gate_reads_has_an_identity_and_no_other() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gates/kind_isolation.rs"),
    )
    .unwrap();
    let at = src.find("is not a table this gate reads").unwrap();
    let end = at + src[at..].find("and nothing else").unwrap();
    let mut read: Vec<&str> = src[at..end]
        .split("`[[")
        .skip(1)
        .filter_map(|s| s.split_once("]]`").map(|(name, _)| name))
        .collect();
    read.sort_unstable();
    let mut ours: Vec<&str> = IDENTITY.iter().map(|(t, _)| *t).collect();
    ours.sort_unstable();
    assert_eq!(read, ours);
}
