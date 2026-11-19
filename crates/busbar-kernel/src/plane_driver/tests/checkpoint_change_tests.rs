// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SP-M2: a unit's running checkpoint is staged only when its counts (or its checkpoint facts)
//! change; an unchanged piece still asks the shared budget whether the stream must be cut.

use busbar_contract::caps::OriginKind;
use busbar_contract::measurement::UNITS_REPORTED;
use busbar_contract::records::{RecordStoreResult, VirtualKey};
use busbar_contract::stage_probe::{Derive, Scope};

use super::*;
use crate::config::groups::{GroupCfg, LimitCfg, LimitMetric, LimitWindow};
use crate::governance::recovery::{RecoveryError, RecoveryEvent, RecoverySink};
use crate::governance::unit_checkpoint::{UnitCheckpoint, UnitCheckpointSink};
use crate::registry::Generation;

const NOW: u64 = 1_700_000_000;

fn ctx(key: u64) -> UnitCtx {
    UnitCtx {
        call: busbar_contract::caps::CallId::UNBOUND,
        key: UnitKey::new(key),
        origin: OriginKind::Client,
        session: None,
        generation: Generation::FIRST,
        admin_listener: false,
        kernel_verb_only: false,
    }
}

fn card_cost(budget_cents: Option<u64>) -> Arc<CostModel> {
    let limits = budget_cents
        .map(|amount| {
            vec![LimitCfg {
                selected: None,
                metric: LimitMetric::Budget,
                amount,
                per: Some(LimitWindow::Month),
                scope: None,
                on_exhaust: None,
                downgrade_to: None,
            }]
        })
        .unwrap_or_default();
    let groups = BTreeMap::from([(
        "g".to_string(),
        GroupCfg {
            enabled: true,
            limits,
            ..Default::default()
        },
    )]);
    let card = BTreeMap::from([(
        "m".to_string(),
        crate::config::RateEntryCfg {
            input_utok: 1.0,
            output_utok: 1.0,
            ..Default::default()
        },
    )]);
    Arc::new(CostModel::resolve_parts(Some(&card), 0, &groups))
}

fn unit(cost: &Arc<CostModel>) -> UnitMoney {
    UnitMoney {
        key: Arc::new(VirtualKey {
            id: "k".into(),
            generation_hash: "h:k".into(),
            name: "k".into(),
            enabled: true,
            group: Some("g".into()),
            revision: 1,
            ..Default::default()
        }),
        cost: Arc::clone(cost),
        pool: String::new(),
        lane: "m".into(),
        classes: Arc::from(vec!["input".to_string(), "output".to_string()]),
        arrived: NOW,
        mode: ExhaustionMode::CutStream,
        fee: FeeRefund::CallerStatus,
        charge: Default::default(),
    }
}

fn reported(amount: u64) -> [UnitCount; 1] {
    [UnitCount {
        class: 0,
        source: UNITS_REPORTED,
        amount,
    }]
}

struct Quiet;
impl EndPost for Quiet {
    fn post(&self, _: &UnitCtx, _: Ended) {}
}

#[derive(Default)]
struct Custody(Mutex<Vec<UnitCheckpoint>>);
#[async_trait::async_trait]
impl UnitCheckpointSink for Custody {
    async fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        *locked(&self.0) = vec![snapshot.clone()];
        Ok(())
    }
    async fn remove(&self, _: &UnitCheckpoint) -> RecordStoreResult<()> {
        locked(&self.0).clear();
        Ok(())
    }
    async fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>> {
        Ok(locked(&self.0).clone())
    }
}

struct Recovery;
#[async_trait::async_trait]
impl RecoverySink for Recovery {
    async fn persist(&self, _: &RecoveryEvent) -> Result<(), RecoveryError> {
        Ok(())
    }
    async fn replay(&self) -> Result<Vec<RecoveryEvent>, RecoveryError> {
        Ok(Vec::new())
    }
}

async fn governor() -> Arc<GovState> {
    Arc::new(
        GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .expect("the real store opens governance"),
    )
}

#[tokio::test]
async fn checkpoint_staged_on_change_only() {
    // A 100-frame session over three turns, under running unit custody.
    let gov = governor().await;
    gov.attach_recovery_sink(Arc::new(Recovery))
        .await
        .expect("usage recovery attaches");
    gov.attach_unit_checkpoint_sink(Arc::new(Custody::default()))
        .await
        .expect("running unit custody attaches");
    let cost = card_cost(None);
    let money = PlaneMoney::new(gov, Arc::new(Quiet));
    money.open(UnitKey::new(1), unit(&cost));
    assert_eq!(money.session_opened(&ctx(1)), Ok(()));

    let scope = Scope::open();
    for frame in 0..100u32 {
        let counted = match frame {
            0..=32 => 30,
            33..=65 => 75,
            _ => 120,
        };
        assert_eq!(
            money.checkpoint(&ctx(1), &reported(counted)),
            Checkpoint::Continue,
            "frame {frame}"
        );
    }
    assert_eq!(
        scope.count(Derive::CheckpointStage),
        3,
        "one staged checkpoint per turn whose counts moved"
    );
    money.session_ended(&ctx(1));
    assert_eq!(
        scope.count(Derive::CheckpointStage),
        4,
        "the session's end still records its terminal state"
    );
    money.settle_end(UnitKey::new(1), 200);
    assert_eq!(money.open_units(), 0);
    drop(scope);

    // A one-cent budget shared by two units: the second unit's settlement drains it, and the
    // first unit's next unchanged piece is still cut mid-session.
    let cost = card_cost(Some(1));
    let money = PlaneMoney::new(governor().await, Arc::new(Quiet));
    money.open(UnitKey::new(1), unit(&cost));
    money.open(UnitKey::new(2), unit(&cost));
    assert_eq!(money.session_opened(&ctx(1)), Ok(()));
    for frame in 0..10u32 {
        assert_eq!(
            money.checkpoint(&ctx(1), &reported(100)),
            Checkpoint::Continue,
            "frame {frame} is within the budget"
        );
    }
    assert_eq!(
        money.checkpoint(&ctx(2), &reported(9_950)),
        Checkpoint::Continue
    );
    money.settle_end(UnitKey::new(2), 200);
    assert_eq!(
        money.checkpoint(&ctx(1), &reported(100)),
        Checkpoint::Cut,
        "an unchanged piece still cuts once another unit drained the shared budget"
    );
}
