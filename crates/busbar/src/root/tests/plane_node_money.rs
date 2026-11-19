// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The node's money seam: native units' ends land their money while the node's book is held.

use super::*;

const EPOCH: u64 = 1_700_000_000;

fn native_budget() -> busbar_kernel::persistence::journal::runtime::BufferBudget {
    busbar_kernel::persistence::journal::runtime::BufferBudget {
        records: 4096,
        bytes: 32 * 1024 * 1024,
    }
}

fn native_node_book() -> crate::root::durability::NodeBook {
    let core = native_ready(crate::root::real_store::core());
    let journal = native_ready(
        busbar_kernel::persistence::journal::runtime::RuntimeJournal::open(
            core,
            busbar_kernel::door::op_id().counter(),
            native_budget(),
        ),
    )
    .expect("native journal opens");
    native_ready(crate::root::durability::node_book(journal, native_budget()))
        .expect("native node book opens")
}

fn native_ready<T>(future: impl std::future::Future<Output = T>) -> T {
    futures::executor::block_on(future)
}

fn node_and_post(book: &crate::root::durability::NodeBook) -> (Arc<Node>, NodeEndPost) {
    let node = Arc::new(Node::new());
    node.bind_book(Arc::clone(&book.durability));
    let post = NodeEndPost::new(Arc::clone(&node));
    (node, post)
}

#[test]
fn concurrent_unit_ends_land_their_money_while_the_book_is_held() {
    use busbar_contract::abi::plane::UnitCount;
    use busbar_contract::measurement::UNITS_REPORTED;
    use busbar_kernel::plane_driver::{FeeRefund, MoneySeam, PlaneMoney, UnitMoney};
    const UNITS: u64 = 8;
    let book = native_node_book();
    let (node, post) = node_and_post(&book);
    let gov = Arc::new(
        native_ready(busbar_kernel::governance::GovState::new_with_core(
            native_ready(crate::root::real_store::core()),
            None,
            None,
        ))
        .expect("governance builds"),
    );
    let money = Arc::new(PlaneMoney::new(Arc::clone(&gov), Arc::new(post)));
    let rates = std::collections::BTreeMap::from([(
        "m".to_string(),
        busbar_kernel::config::RateEntryCfg {
            input_utok: 1.0,
            ..Default::default()
        },
    )]);
    let cost = Arc::new(busbar_kernel::cost::CostModel::resolve_parts(
        Some(&rates),
        0,
        &std::collections::BTreeMap::new(),
    ));
    let key = Arc::new(busbar_kernel::governance::VirtualKey {
        id: "vk_unlocked".to_string(),
        generation_hash: "h:vk_unlocked".to_string(),
        name: "unlocked".to_string(),
        enabled: true,
        revision: 1,
        ..Default::default()
    });

    let held = book.durability.lock().unwrap_or_else(|p| p.into_inner());
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let threads: Vec<_> = (1..=UNITS)
        .map(|n| {
            let (money, cost, key, done) = (
                Arc::clone(&money),
                Arc::clone(&cost),
                Arc::clone(&key),
                done_tx.clone(),
            );
            std::thread::spawn(move || {
                let unit = UnitKey::new(n);
                money.open(
                    unit,
                    UnitMoney {
                        key,
                        cost,
                        pool: String::new(),
                        lane: "m".into(),
                        classes: Arc::from(vec!["input".to_string()]),
                        arrived: EPOCH,
                        mode: busbar_kernel::config::groups::ExhaustionMode::FinishUnit,
                        fee: FeeRefund::CallerStatus,
                        charge: Default::default(),
                    },
                );
                let ctx = UnitCtx {
                    call: busbar_contract::caps::CallId::UNBOUND,
                    key: unit,
                    origin: OriginKind::Client,
                    session: None,
                    generation: busbar_kernel::registry::Generation::FIRST,
                    admin_listener: false,
                    kernel_verb_only: false,
                };
                let _ = money.checkpoint(
                    &ctx,
                    &[UnitCount {
                        class: 0,
                        source: UNITS_REPORTED,
                        amount: 100,
                    }],
                );
                money.settle_end(unit, 200);
                done.send(n).expect("the test listens");
            })
        })
        .collect();
    drop(done_tx);
    let mut ended = 0;
    while ended < UNITS {
        done_rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect(
            "a unit's end waited on the node's book: a process-wide lock stands in front of money",
        );
        ended += 1;
    }
    let landed = native_ready(gov.derived_bucket_usage_async(
        &cost,
        &key.id,
        busbar_kernel::governance::WINDOW_TOTAL,
        true,
        EPOCH,
    ))
    .expect("usage reads")
    .tokens;
    assert_eq!(
        landed,
        UNITS * 100,
        "every unit's counts landed while the book was held"
    );
    drop(held);
    for t in threads {
        t.join().expect("no unit panicked");
    }
    drop(node);
}
