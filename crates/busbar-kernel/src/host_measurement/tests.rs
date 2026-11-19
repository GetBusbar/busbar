// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::governance::unit_checkpoint::UnitCheckpointSink;
use busbar_contract::{abi::mechanism::KindCode, records::RecordStoreResult};

#[derive(Default)]
struct MemoryCheckpoint(Mutex<Vec<UnitCheckpoint>>);
#[async_trait::async_trait]
impl UnitCheckpointSink for MemoryCheckpoint {
    async fn persist(&self, snapshot: &UnitCheckpoint) -> RecordStoreResult<()> {
        snapshot.validate()?;
        *self.0.lock().unwrap() = vec![snapshot.clone()];
        Ok(())
    }
    async fn remove(&self, _: &UnitCheckpoint) -> RecordStoreResult<()> {
        self.0.lock().unwrap().clear();
        Ok(())
    }
    async fn replay(&self) -> RecordStoreResult<Vec<UnitCheckpoint>> {
        Ok(self.0.lock().unwrap().clone())
    }
}
struct UnusedRecovery;
#[async_trait::async_trait]
impl crate::governance::recovery::RecoverySink for UnusedRecovery {
    async fn persist(
        &self,
        _: &crate::governance::recovery::RecoveryEvent,
    ) -> Result<(), crate::governance::recovery::RecoveryError> {
        panic!(
            "these bounded staging tests do not settle raw recovery; actual Store tests cover it"
        )
    }
    async fn replay(
        &self,
    ) -> Result<
        Vec<crate::governance::recovery::RecoveryEvent>,
        crate::governance::recovery::RecoveryError,
    > {
        Ok(Vec::new())
    }
}
fn binding(seal: &KernelSeal) -> MeasurementBinding {
    MeasurementBinding {
        caller: Caller::issue(seal, "stand-in".into(), KindCode::Hook),
        statement_digest: [3; 32],
        classes: vec!["work".into(), "items".into()],
    }
}

#[tokio::test]
async fn host_measurement_bounded_revisions_are_atomic_and_cancellation_retains_counts() {
    let seal = crate::seal::acquire();
    let gov = Arc::new(
        GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .unwrap(),
    );
    let sink = Arc::new(MemoryCheckpoint::default());
    gov.attach_recovery_sink(Arc::new(UnusedRecovery))
        .await
        .unwrap();
    gov.attach_unit_checkpoint_sink(sink.clone()).await.unwrap();
    let runtime = MeasurementRuntime::new(&seal, gov.clone(), 1).unwrap();
    let context = MeasurementContext::system(&seal, 99, RawRateEra::default());
    let op = runtime.reserve(&seal, binding(&seal), &context, 7).unwrap();
    assert!(matches!(
        runtime.reserve(&seal, binding(&seal), &context, 7),
        Err(Refusal::Unavailable)
    ));
    op.capture(1, [(0, Count::ONE)]).unwrap();
    op.capture(1, [(0, Count::ONE)]).unwrap();
    assert_eq!(op.capture(1, [(0, Count::ZERO)]), Err(Refusal::Conflict));
    assert_eq!(
        op.capture(
            2,
            [
                (0, Count::from_micros(2_000_000)),
                (1, Count::from_micros(-1))
            ]
        ),
        Err(Refusal::Malformed)
    );
    assert_eq!(
        op.capture(2, [(0, Count::from_micros(2_000_000)), (2, Count::ONE)]),
        Err(Refusal::Malformed)
    );
    assert_eq!(op.revision(), 2);
    assert_eq!(
        op.state.lock().unwrap().snapshot.as_ref().unwrap().units["work"],
        Count::ONE
    );
    op.released(false);
    gov.flush_unit_checkpoints().await.unwrap();
    let report = sink.replay().await.unwrap().pop().unwrap();
    assert_eq!(report.units.len(), 1);
    assert!(report.targets.is_empty());
    assert!(report.audit.is_none());
    assert_eq!(op.revision(), 2);
    op.capture(2, [(0, Count::from_micros(2_000_000))]).unwrap();
    op.released(true);
    op.released(true);
    assert_eq!(op.revision(), 0);
    assert_eq!(op.capture(3, [(0, Count::ONE)]), Err(Refusal::Conflict));
    assert_eq!(
        runtime.pending(),
        1,
        "until the durable settlement ACK, capacity remains occupied"
    );
}

#[tokio::test]
async fn host_measurement_empty_terminal_frees_capacity_and_undeclared_origin_is_refused() {
    let seal = crate::seal::acquire();
    let gov = Arc::new(
        GovState::new_with_core(crate::real_store::core().await, None, None)
            .await
            .unwrap(),
    );
    let runtime = MeasurementRuntime::new(&seal, gov.clone(), 1).unwrap();
    let context = MeasurementContext::system(&seal, 99, RawRateEra::default());
    assert!(matches!(
        runtime.reserve(&seal, binding(&seal), &context, 7),
        Err(Refusal::Unavailable)
    ));
    gov.attach_recovery_sink(Arc::new(UnusedRecovery))
        .await
        .unwrap();
    gov.attach_unit_checkpoint_sink(Arc::new(MemoryCheckpoint::default()))
        .await
        .unwrap();
    let op = runtime.reserve(&seal, binding(&seal), &context, 7).unwrap();
    op.released(true);
    assert_eq!(runtime.pending(), 0);
    let next = runtime.reserve(&seal, binding(&seal), &context, 7).unwrap();
    assert_ne!(op.id, next.id, "new invocation uses a new host incarnation");
    next.capture(1, [(0, Count::ONE)]).unwrap();
    let mut report = next.state.lock().unwrap().snapshot.clone().unwrap();
    assert!(report.validate().is_ok());
    report.targets.push(UnitTarget {
        bucket: "another-user".into(),
        window: 0,
        group: None,
    });
    assert!(report.validate().is_err());
}

/// A measurement checkpoint's evidence as every build since measurements arrived wrote it, read
/// back through the store's own JSON reader. A request-origin one carries numbers (`unit`, each
/// target's `window`) inside the `kind`-tagged origin; a restart must read them.
#[test]
fn stored_request_origin_evidence_decodes_on_restart() {
    let digest = vec!["113"; 32].join(",");
    let request = format!(
        concat!(
            r#"{{"version":1,"plugin_kind":"hook","namespace":"busbar.measurement","#,
            r#""statement_digest":[{digest}],"classes":["work","input"],"#,
            r#""origin":{{"kind":"Request","principal":"original-user","group":"original-group","#,
            r#""targets":[{{"bucket":"original-user","window":0,"group":"original-group"}}],"#,
            r#""unit":73}},"slot":0,"reported_revision":1}}"#
        ),
        digest = digest
    );
    let read: MeasurementEvidence = busbar_contract::json::parse(request.as_bytes())
        .expect("a stored request-origin measurement decodes");
    assert_eq!(
        read.origin,
        Origin::Request {
            principal: "original-user".into(),
            group: "original-group".into(),
            targets: vec![UnitTarget {
                bucket: "original-user".into(),
                window: 0,
                group: Some("original-group".into()),
            }],
            unit: 73,
        }
    );
    assert_eq!(read.reported_revision, 1);
    let written = busbar_contract::json::to_vec(&read).unwrap();
    assert_eq!(
        written,
        request.as_bytes(),
        "written byte for byte as before"
    );
    let again: MeasurementEvidence = busbar_contract::json::parse(&written).unwrap();
    assert_eq!(again, read);

    let system = format!(
        concat!(
            r#"{{"version":1,"plugin_kind":"store","namespace":"busbar.measurement","#,
            r#""statement_digest":[{digest}],"classes":["work"],"#,
            r#""origin":{{"kind":"System"}},"slot":2,"reported_revision":0}}"#
        ),
        digest = digest
    );
    let read: MeasurementEvidence = busbar_contract::json::parse(system.as_bytes()).unwrap();
    assert_eq!(read.origin, Origin::System);
    assert_eq!(
        busbar_contract::json::to_vec(&read).unwrap(),
        system.as_bytes()
    );

    for refused in [
        r#"{"kind":"System","unit":1}"#,
        r#"{"kind":"System","principal":null}"#,
        r#"{"kind":"Request","principal":"p","group":"g","targets":[]}"#,
        r#"{"kind":"Request","principal":"p","group":"g","targets":[],"unit":1,"extra":0}"#,
        r#"{"kind":"Other"}"#,
        r#"{"unit":1}"#,
    ] {
        assert!(
            busbar_contract::json::parse::<Origin>(refused.as_bytes()).is_err(),
            "{refused}"
        );
    }
}
