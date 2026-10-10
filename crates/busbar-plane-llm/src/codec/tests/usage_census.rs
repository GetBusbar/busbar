// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE USAGE CENSUS HARNESS (MONEY-AUDIT A-F1): what every dialect's census test reads its wire
//! lock and its ledgered units through, so each census measures the same projections the same way.

use busbar_contract::billing::TokenUsage;

use crate::codec::ir::open_class::{OPEN_CLASSES, OPEN_CLASS_COUNT};

/// How many classes a [`Ledgered`] reading holds: the four token tiers and every open class.
pub(crate) const CLASSES: usize = 4 + OPEN_CLASS_COUNT;

/// The ledgered units, in this order: input, output, cache read, cache write, then every open
/// class in [`OPEN_CLASSES`] order (`search_units` first, at index 4) (owner LEDGER-100: every
/// reported unit is a ledger line, so the census reads every class the plane declares).
pub(crate) type Ledgered = [i64; CLASSES];

/// The index of the input tier in a [`Ledgered`] reading.
pub(crate) const IN: usize = 0;
/// The index of the output tier.
pub(crate) const OUT: usize = 1;
/// The index of the cache-read tier.
pub(crate) const CR: usize = 2;
/// The index of the cache-write tier.
pub(crate) const CW: usize = 3;
/// A reading that moves nothing.
pub(crate) const NONE: Ledgered = [0; CLASSES];

/// The index of open class `class` in a [`Ledgered`] reading; a class the plane does not declare
/// fails the build.
pub(crate) const fn slot(class: &str) -> usize {
    let mut k = 0;
    while k < OPEN_CLASSES.len() {
        let (a, b) = (OPEN_CLASSES[k].0.as_bytes(), class.as_bytes());
        if a.len() == b.len() {
            let mut i = 0;
            while i < a.len() && a[i] == b[i] {
                i += 1;
            }
            if i == a.len() {
                return 4 + k;
            }
        }
        k += 1;
    }
    panic!("not a declared open class")
}

/// A reading that moves `n` at `slot` and nothing else.
pub(crate) const fn at(slot: usize, n: i64) -> Ledgered {
    let mut out = NONE;
    out[slot] = n;
    out
}

/// The sum of two readings.
pub(crate) const fn plus(a: Ledgered, b: Ledgered) -> Ledgered {
    let mut out = a;
    let mut i = 0;
    while i < CLASSES {
        out[i] += b[i];
        i += 1;
    }
    out
}

/// The count members the pinned wire lock of `dialect`
/// (`testing/llm-conformance/wire/<dialect>.wire.json`) declares under `prefix` in `section`: every
/// integer- or number-typed member below it (a dotted path, no list member).
pub(crate) fn lock_counts(dialect: &str, section: &str, prefix: &str) -> Vec<String> {
    let lock_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../testing/llm-conformance/wire/{dialect}.wire.json"
    ));
    let lock: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&lock_path).expect("the pinned wire lock"))
            .expect("wire lock json");
    lock[section]
        .as_object()
        .expect("wire lock paths")
        .iter()
        .filter(|(_, v)| {
            v["type"]
                .as_str()
                .is_some_and(|t| t.split('|').any(|t| t == "integer" || t == "number"))
        })
        .filter_map(|(k, _)| k.strip_prefix(prefix))
        .filter(|f| !f.contains('['))
        .map(String::from)
        .collect()
}

/// The one ledgered reading of a usage, through BOTH projections a ledger row is built from (the
/// governance ledger's `tier_usage` and the plane's `Units`); they must agree, class for class, and
/// neither may hold a class the plane does not declare.
pub(crate) fn ledgered(u: &TokenUsage) -> Ledgered {
    let n = |x: u64| i64::try_from(x).expect("small fixture");
    let map = crate::codec::wire_shim::tier_usage(u).usage_units;
    let units = crate::exchange::reply::Units::of(Some(u), Default::default());
    let mut tiers = NONE;
    let mut plane = NONE;
    for (i, class) in [
        busbar_contract::records::UNIT_INPUT,
        busbar_contract::records::UNIT_OUTPUT,
        busbar_contract::records::UNIT_CACHE_READ,
        busbar_contract::records::UNIT_CACHE_WRITE,
    ]
    .into_iter()
    .enumerate()
    {
        tiers[i] = n(map.get(class).copied().unwrap_or(0));
    }
    plane[IN] = n(units.tokens_in);
    plane[OUT] = n(units.tokens_out);
    plane[CR] = n(units.cache_read);
    plane[CW] = n(units.cache_write);
    for (k, (class, _)) in OPEN_CLASSES.iter().enumerate() {
        tiers[4 + k] = n(map.get(*class).copied().unwrap_or(0));
        plane[4 + k] = n(units.open.get(*class).copied().unwrap_or(0));
    }
    let declared = |c: &String| {
        busbar_contract::records::RESERVED_UNITS.contains(&c.as_str())
            || OPEN_CLASSES.iter().any(|(o, _)| o == c)
    };
    assert!(map.keys().all(declared), "an undeclared class: {map:?}");
    assert!(
        units.open.keys().all(declared),
        "an undeclared class: {:?}",
        units.open
    );
    assert_eq!(tiers, plane, "the two ledger projections disagree");
    tiers
}

/// Add `by` to the count at a dotted `path` under `usage` (an absent count reads 0).
pub(crate) fn bump(usage: &mut serde_json::Value, path: &str, by: u64) {
    let mut at = usage;
    let mut parts = path.split('.').peekable();
    while let Some(part) = parts.next() {
        if parts.peek().is_none() {
            let was = at[part].as_u64().unwrap_or(0);
            at[part] = serde_json::json!(was + by);
        } else {
            at = &mut at[part];
        }
    }
}

/// The class a census table gives `field`, or a panic naming the lock member nobody classed.
pub(crate) fn class_of<B: Copy>(table: &[(&str, B)], field: &str, census: &str) -> B {
    table
        .iter()
        .find(|(f, _)| *f == field)
        .map(|(_, c)| *c)
        .unwrap_or_else(|| panic!("`{census}.{field}` is in the wire lock with no meter class"))
}

/// The move from `before` to `after`.
pub(crate) fn moved(after: Ledgered, before: Ledgered) -> Ledgered {
    std::array::from_fn(|i| after[i] - before[i])
}
