// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE ADMIN CRATE'S MONEY SIGNATURES NAME THE KERNEL'S FACADE. The usage read's derivations and
//! the dated-history seam take and return the money types by `busbar_kernel::cost`, the path the
//! kernel re-exports the ledger's own items under. This file is the compile-level witness: every
//! binding below spells its type through `busbar_kernel::cost`, so a signature that drifted to any
//! other path, or to a second type of the same name, stops compiling here. The one figure test
//! pins that the dated read and the current-card read agree on a card the history opened with.

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_core_admin::v1::contract::UsageBreakdown;
use busbar_core_admin::v1::service::{
    derive_spend_micros_row, derive_spend_micros_row_at_card, derive_spend_micros_row_classes,
    derive_spend_micros_row_classes_at_card, UsageRateHistory,
};
use busbar_kernel::cost::{self, CostModel};

/// The dated-history seam's one method answers the facade's `History`.
struct Pinned(Arc<cost::History>);

impl UsageRateHistory for Pinned {
    fn history(&self) -> Option<Arc<cost::History>> {
        Some(Arc::clone(&self.0))
    }
}

#[test]
fn the_usage_read_signatures_name_the_kernel_cost_facade() {
    type Spend = Result<i64, cost::MoneyError>;
    type Classes = BTreeMap<String, u64>;
    type DatedClasses = fn(
        &cost::HistoryView<'_>,
        u64,
        &cost::RateCard,
        &CostModel,
        &str,
        &UsageBreakdown,
        &Classes,
    ) -> Spend;
    let _: fn(&CostModel, &str, &UsageBreakdown) -> Spend = derive_spend_micros_row;
    let _: fn(&CostModel, &str, &UsageBreakdown, &Classes) -> Spend =
        derive_spend_micros_row_classes;
    let _: fn(
        &cost::HistoryView<'_>,
        u64,
        &cost::RateCard,
        &CostModel,
        &str,
        &UsageBreakdown,
    ) -> Spend = derive_spend_micros_row_at_card;
    let _: DatedClasses = derive_spend_micros_row_classes_at_card;
    // `CostModel::card` hands back the facade's `RateCard`: the kernel's card IS the ledger's.
    let _: fn(&CostModel) -> &cost::RateCard = CostModel::card;
}

#[test]
fn the_dated_read_through_the_facade_prices_the_opening_card_as_the_current_read_does() {
    let model = CostModel::flat(7);
    let row = UsageBreakdown {
        requests: 3,
        ..UsageBreakdown::default()
    };
    let seam = Pinned(Arc::new(cost::History::opening(model.card().clone(), 0)));
    let history = seam.history().expect("the pinned history");
    let view: cost::HistoryView<'_> = history.current();
    let (_, card) = view.card_at(0).expect("the opening card is in force at 0");
    let head: Option<cost::HistorySeq> = history.head();
    assert!(head.is_some(), "an opened history has a head");

    let current = derive_spend_micros_row(&model, "m-facade", &row);
    let dated = derive_spend_micros_row_at_card(&view, 0, card, &model, "m-facade", &row);
    assert!(
        matches!(current, Ok(n) if n > 0),
        "the flat fee posts: {current:?}"
    );
    assert_eq!(current, dated, "one card, one figure, whichever read asks");
}
