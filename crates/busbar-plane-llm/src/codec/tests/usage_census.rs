// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE USAGE CENSUS HARNESS (MONEY-AUDIT A-F1): what every dialect's census test reads its wire
//! lock and its ledgered units through, so each census measures the same projections the same way.

use busbar_contract::billing::TokenUsage;

/// The ledgered units, in this order: input, output, cache read, cache write, `search_units`.
pub(crate) type Ledgered = [i64; 5];

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
/// governance ledger's `tier_usage` and the plane's `Units`); they must agree.
pub(crate) fn ledgered(u: &TokenUsage) -> Ledgered {
    let n = |x: u64| i64::try_from(x).expect("small fixture");
    let search = crate::codec::ir::rerank::SEARCH_UNITS_CLASS;
    let map = crate::codec::wire_shim::tier_usage(u).usage_units;
    let class = |c: &str| n(map.get(c).copied().unwrap_or(0));
    let tiers = [
        class(busbar_contract::records::UNIT_INPUT),
        class(busbar_contract::records::UNIT_OUTPUT),
        class(busbar_contract::records::UNIT_CACHE_READ),
        class(busbar_contract::records::UNIT_CACHE_WRITE),
        class(search),
    ];
    let units = crate::exchange::reply::Units::of(Some(u), Default::default());
    let plane = [
        n(units.tokens_in),
        n(units.tokens_out),
        n(units.cache_read),
        n(units.cache_write),
        n(units.open.get(search).copied().unwrap_or(0)),
    ];
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
