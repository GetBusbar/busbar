// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::BTreeMap;
use std::sync::Arc;

use busbar_core_admin::v1::contract::UsageBreakdown;
use busbar_core_admin::v1::service::{
    derive_spend_micros_row, derive_spend_micros_row_at_card, derive_spend_micros_row_classes,
    derive_spend_micros_row_classes_at_card,
};
use busbar_kernel::cost::{self, CostModel};

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

    let _: fn() -> Option<Arc<cost::History>> = busbar_kernel::rate_apply::dated_history;

    let _: fn(&CostModel) -> &cost::RateCard = CostModel::card;
}

#[test]
fn the_dated_read_through_the_facade_prices_the_opening_card_as_the_current_read_does() {
    let model = CostModel::flat(7);
    let row = UsageBreakdown {
        requests: 3,
        ..UsageBreakdown::default()
    };
    let history = Arc::new(cost::History::opening(model.card().clone(), 0));
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
