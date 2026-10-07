// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

fn cx() -> Ctx {
    Ctx::workspace().expect("workspace context")
}

/// AUDIT xtask-X3 #11: THE ZERO IS A VALUE. Every spelling below evaluates to zero; every control
/// does not.
#[test]
fn a_zero_default_is_decided_by_value() {
    for zero in [
        "0",
        "0u16",
        "0_i16",
        "0i16 as i64",
        "0.0",
        "0.",
        "0e0",
        "00",
        "0x0",
        "0f64",
        "u64::MIN",
        "usize::MIN",
        "Default::default()",
        "u64::default()",
        "Default::default",
        "u64::default",
        "|| 0",
        "|| 0u16",
        "|| Default::default()",
        "{ 0 }",
        "(0)",
    ] {
        assert!(is_zero_value(zero), "`{zero}` is a zero");
    }
    for not_zero in [
        "1",
        "idx",
        "idx as u64",
        "i64::MIN",
        "0.5",
        "10",
        "|| 1",
        "n",
        "",
    ] {
        assert!(!is_zero_value(not_zero), "`{not_zero}` is not a zero");
    }
}

/// Every default SHAPE that substitutes a zero is a hit; a propagating read and a named non-zero
/// default are not.
#[test]
fn every_zero_default_shape_is_a_hit() {
    let src = "fn a(v: &V) -> u64 { v.as_u64().unwrap_or(0u16 as u64) }\n\
               fn b(v: &V) -> u64 { v.as_u64().unwrap_or(u64::MIN) }\n\
               fn c(v: &V) -> u64 { v.as_u64().unwrap_or_else(Default::default) }\n\
               fn d(v: &V) -> u64 { v.as_u64().map_or(0, |n| n * 2) }\n\
               fn e(v: &V) -> u64 { v.as_u64().map_or_else(|| 0, |n| n) }\n\
               fn f(v: &V) -> u64 { if let Some(n) = v.as_u64() { n } else { 0 } }\n\
               fn g(v: &V) -> Option<u64> { v.as_u64() }\n\
               fn h(v: &V, k: u64) -> u64 { v.as_u64().map_or(k, |n| n) }\n\
               fn i(v: &V) -> u64 { if let Some(n) = v.as_u64() { n } else { 9 } }\n";
    let lines: Vec<usize> = read_count_hits(src).iter().map(|h| h.line).collect();
    assert_eq!(lines, vec![1, 2, 3, 4, 5, 6]);
}

/// AUDIT xtask-X3 #7: a read is anchored to the INNERMOST `fn` around it.
#[test]
fn a_read_is_anchored_to_its_innermost_fn() {
    let src = "fn outer(v: &V) -> u64 {\n    fn inner(v: &V) -> u64 {\n        v.as_u64().unwrap_or(0)\n    }\n    let x = |w: &V| w.as_u64().unwrap_or(0);\n    inner(v) + x(v)\n}\ntrait T { fn decl(&self) -> u64; }\nfn after() {}\n";
    let items = fn_items(src);
    assert_eq!(enclosing_fn(&items, 3), "inner");
    assert_eq!(enclosing_fn(&items, 5), "outer");
    assert_eq!(enclosing_fn(&items, 9), "after");
    assert!(
        !items.iter().any(|(n, _, _)| n == "decl"),
        "a body-less declaration is not an item: {items:?}"
    );
}

/// Every allowance names an item that is THERE, in its file, on the real tree.
#[test]
fn every_allowance_names_a_fn_in_its_file() {
    let cx = cx();
    for a in ALLOWED_COUNT_READS {
        let text = cx
            .read(a.file)
            .unwrap_or_else(|e| panic!("{}: {e}", a.file));
        assert!(
            fn_items(&text).iter().any(|(n, _, _)| n == a.item),
            "{}: no `fn {}`",
            a.file,
            a.item
        );
        assert!(a.reads > 0, "{} `fn {}` states no read", a.file, a.item);
    }
}

/// An allowance matching nothing, and one matching a different count, are both drift.
#[test]
fn an_allowance_out_of_step_is_drift() {
    let exact: std::collections::BTreeMap<usize, usize> = ALLOWED_COUNT_READS
        .iter()
        .enumerate()
        .map(|(i, a)| (i, a.reads))
        .collect();
    assert!(allowance_drift(&exact).is_empty());
    let mut none = exact.clone();
    none.remove(&0);
    assert!(allowance_drift(&none)[0].contains("matched NO"));
    let mut more = exact;
    *more.get_mut(&0).expect("row 0") += 1;
    assert!(allowance_drift(&more)[0].contains("where the allowance states"));
}

/// AUDIT xtask-X3 #8: TEST SCOPE IS THE DECLARATION. A test-shaped name declared without the gate is
/// production; a plain name declared under it is a test; a module a test module declares is a test;
/// `#[cfg(not(test))]` is production.
#[test]
fn test_scope_is_decided_by_the_declaring_mod() {
    let files = [
        (
            "c/src/lib.rs",
            "pub mod money_tests;\n#[cfg(test)]\nmod fixture;\n#[cfg(test)]\n#[path = \"tests/x.rs\"]\nmod x;\n#[cfg(not(test))]\nmod live;\npub mod tests;\n#[cfg(test)] mod tree;\n",
        ),
        ("c/src/money_tests.rs", ""),
        ("c/src/fixture.rs", ""),
        ("c/src/tests/x.rs", "mod helper;\n"),
        ("c/src/tests/x/helper.rs", ""),
        ("c/src/live.rs", ""),
        ("c/src/tests.rs", ""),
        ("c/src/tree/mod.rs", "mod leaf;\n"),
        ("c/src/tree/leaf.rs", ""),
    ];
    let test = scan::cfg_test_module_files(files.iter().map(|(r, t)| ((*r).to_string(), *t)));
    for want in [
        "c/src/fixture.rs",
        "c/src/tests/x.rs",
        "c/src/tests/x/helper.rs",
        "c/src/tree/mod.rs",
        "c/src/tree/leaf.rs",
    ] {
        assert!(test.contains(want), "{want} is test scope: {test:?}");
    }
    for prod in [
        "c/src/money_tests.rs",
        "c/src/live.rs",
        "c/src/tests.rs",
        "c/src/lib.rs",
    ] {
        assert!(!test.contains(prod), "{prod} is production: {test:?}");
    }
}

/// AUDIT xtask-X3 #12: THE DERIVED CENSUS CLEARS ITS FLOOR ON THE REAL TREE, and it holds the
/// files the hand list could never reach.
#[test]
fn the_persisted_record_census_clears_its_floor() {
    let cx = cx();
    let all = cx
        .walk(&WalkSpec::new([PERSISTED_CENSUS_ROOT]).ext("rs"))
        .expect("the census walk");
    let homes = persisted_record_homes(all);
    let rels: Vec<String> = homes.iter().map(|f| f.rel_str()).collect();
    eprintln!("persisted-record census: {} home(s)", rels.len());
    assert!(
        rels.len() >= PERSISTED_CENSUS_FLOOR,
        "{} < {PERSISTED_CENSUS_FLOOR}",
        rels.len()
    );
    for want in [
        "crates/busbar-contract/src/records.rs",
        "crates/busbar-plane-mcp/src/record.rs",
    ] {
        assert!(rels.iter().any(|r| r == want), "{want} is not a home");
    }
    assert!(persisted_record_homes(Vec::new()).is_empty());
}
