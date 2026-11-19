// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
struct Count(std::sync::Mutex<Vec<u64>>);
impl AmendSink for Count {
    fn sealed(
        &self,
        amendment: &Amendment,
    ) -> Result<
        busbar_kernel_audit::amend::AmendCommit,
        busbar_kernel_audit::amend::AmendPersistError,
    > {
        self.0.lock().unwrap().push(amendment.seq);
        Ok(Box::pin(async { Ok(()) }))
    }
}
async fn bind_counter(journal: &NodeAmendments) {
    journal
        .bind(
            Some(std::sync::Arc::new(Count(
                std::sync::Mutex::new(Vec::new()),
            ))),
            0,
            &crate::teller::Kernel::new().durability_token(),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn an_access_on_one_nodes_journal_is_not_read_by_another_nodes() {
    let (a, b) = (NodeAmendments::new(), NodeAmendments::new());
    bind_counter(&a).await;
    hook_reads(&a, &["p2-404-hook"], Some("key-a"), "openai", false)
        .await
        .unwrap();
    assert_eq!(
        a.recent().len(),
        1,
        "the access lands on the journal it was sealed on"
    );
    assert!(
        b.recent().is_empty(),
        "a second node's journal read an access it never sealed"
    );

    let c = NodeAmendments::new();
    let token = crate::teller::Kernel::new().durability_token();
    let through = c.restore(a.recent(), &token).expect("a's run verifies");
    assert_eq!(through, 1);
    assert_eq!(c.recent(), a.recent());
    assert!(b.recent().is_empty());
}

#[tokio::test]
async fn a_bound_sink_takes_the_held_tail_then_every_new_amendment() {
    let journal = NodeAmendments::new();
    bind_counter(&journal).await;
    hook_reads(&journal, &["h"], None, "openai", false)
        .await
        .unwrap();
    hook_reads(&journal, &["h"], None, "openai", false)
        .await
        .unwrap();
    let first = journal.recent()[0].seq;
    let sink = std::sync::Arc::new(Count(std::sync::Mutex::new(Vec::new())));
    let token = crate::teller::Kernel::new().durability_token();
    journal
        .bind(
            Some(sink.clone() as std::sync::Arc<dyn AmendSink>),
            first,
            &token,
        )
        .await
        .unwrap();
    export_reads(
        &journal,
        "logs",
        &[(
            std::sync::Arc::from("sink"),
            crate::export::projection::Members::default(),
        )],
    )
    .await
    .unwrap();
    assert_eq!(*sink.0.lock().unwrap(), vec![first + 1, first + 2]);
}

#[tokio::test]
async fn refused_original_stage_leaves_no_amendment_chain_hole() {
    struct Refuse;
    impl AmendSink for Refuse {
        fn sealed(
            &self,
            _: &Amendment,
        ) -> Result<
            busbar_kernel_audit::amend::AmendCommit,
            busbar_kernel_audit::amend::AmendPersistError,
        > {
            Err(busbar_kernel_audit::amend::AmendPersistError)
        }
    }
    let journal = NodeAmendments::new();
    let token = crate::teller::Kernel::new().durability_token();
    journal
        .bind(Some(std::sync::Arc::new(Refuse)), 0, &token)
        .await
        .unwrap();
    assert!(hook_reads(&journal, &["h"], None, "openai", false)
        .await
        .is_err());
    assert!(journal.recent().is_empty());
    bind_counter(&journal).await;
    hook_reads(&journal, &["h"], None, "openai", false)
        .await
        .unwrap();
    assert_eq!(journal.recent()[0].seq, 1);
    journal.verify().unwrap();
}

/// What a sink was handed, kept exactly as it was handed it.
struct Keep(std::sync::Mutex<Vec<Amendment>>);
impl AmendSink for Keep {
    fn sealed(
        &self,
        amendment: &Amendment,
    ) -> Result<
        busbar_kernel_audit::amend::AmendCommit,
        busbar_kernel_audit::amend::AmendPersistError,
    > {
        self.sealed_many(std::slice::from_ref(amendment))
    }
    fn sealed_many(
        &self,
        amendments: &[Amendment],
    ) -> Result<
        busbar_kernel_audit::amend::AmendCommit,
        busbar_kernel_audit::amend::AmendPersistError,
    > {
        self.0.lock().unwrap().extend_from_slice(amendments);
        Ok(Box::pin(async { Ok(()) }))
    }
}

/// A RECORDED READ IS SEALED EXACTLY AS THE CHAIN SEALS ITS BODY. Hook and export reads go through
/// the node journal; what the sink is handed, what the journal holds, and what `AmendChain::append`
/// seals for the same bodies at the same places are one and the same: seq, link, digest, every
/// field. `AmendChain`'s digest is pinned to frozen hex in the audit members tests, so this pins
/// the journal's digests to it. The facts of one call share one reading of the clock.
#[tokio::test]
async fn a_recorded_read_is_sealed_exactly_as_the_chain_seals_its_body() {
    use crate::export::projection::{Members, ProjectedRecord, Projection};
    use busbar_contract::export_calls::codes::ExportField;
    use busbar_contract::export_stream::ExportStream;

    let journal = NodeAmendments::new();
    let sink = std::sync::Arc::new(Keep(std::sync::Mutex::new(Vec::new())));
    journal
        .bind(
            Some(sink.clone() as std::sync::Arc<dyn AmendSink>),
            0,
            &crate::teller::Kernel::new().durability_token(),
        )
        .await
        .unwrap();
    hook_reads(
        &journal,
        &["compress", "redact"],
        Some("pseudonym-1"),
        "openai",
        true,
    )
    .await
    .unwrap();
    hook_reads(&journal, &["h"], None, "anthropic", false)
        .await
        .unwrap();
    let projection = Projection::for_test(
        &[ExportStream::Traces],
        &[ExportField::Ts, ExportField::Pool],
    );
    let mut record = ProjectedRecord::new(projection, ExportStream::Traces);
    record
        .set(ExportField::Ts, 1_700_000_000u64)
        .set(ExportField::Pool, "p");
    let members = record.finish().members;
    let exported: Vec<&str> = members.names().collect();
    assert_eq!(exported.len(), 2, "{exported:?}");
    export_reads(
        &journal,
        "logs",
        &[
            (std::sync::Arc::from("sink-a"), members),
            (std::sync::Arc::from("sink-b"), Members::default()),
        ],
    )
    .await
    .unwrap();

    let handed = sink.0.lock().unwrap().clone();
    let held = journal.recent();
    assert_eq!(
        handed, held,
        "the sink took custody of exactly what the journal holds"
    );
    let principal = Subject::principal("pseudonym-1");
    let expected: [(Reader, &str, &Subject, &str, &[&str]); 5] = [
        (
            Reader::Hook,
            "compress",
            &principal,
            "openai",
            &["content", "identity"],
        ),
        (
            Reader::Hook,
            "redact",
            &principal,
            "openai",
            &["content", "identity"],
        ),
        (
            Reader::Hook,
            "h",
            &Subject::Arrival,
            "anthropic",
            &["content"],
        ),
        (
            Reader::Export,
            "sink-a",
            &Subject::Arrival,
            "logs",
            &exported,
        ),
        (Reader::Export, "sink-b", &Subject::Arrival, "logs", &[]),
    ];
    assert_eq!(held.len(), expected.len());
    let mut chain = busbar_kernel_audit::amend::AmendChain::new();
    let mut walls = Vec::new();
    for (amendment, (reader, name, subject, op, fields)) in held.iter().zip(expected) {
        let AmendBody::Access(access) = &amendment.body else {
            panic!("a read sealed as something other than an access: {amendment:?}");
        };
        assert_eq!(access.reader, reader);
        assert_eq!(access.name, name);
        assert_eq!(&access.subject, subject);
        assert_eq!(access.op_class.as_str(), op);
        assert_eq!(access.fields, fields);
        walls.push(access.wall);
        let sealed = chain.append(amendment.body.clone(), &pass());
        assert_eq!(
            &sealed, amendment,
            "the journal sealed a read differently from the chain"
        );
    }
    assert_eq!(walls[0], walls[1], "one call, one reading");
    assert_eq!(walls[3], walls[4], "one call, one reading");
    assert_eq!(held[0].seq, 1);
    assert_eq!(held[0].prev_hash, "");
    assert_eq!(chain.head(), held[4].hash);
    journal.verify().unwrap();
}

/// W1: a notify fan-out of three content taps is recorded as one set: three amendments with
/// consecutive seqs, handed to the sink as one unit (one `sealed_many`), confirmed by one await.
#[tokio::test]
async fn three_hook_reads_are_one_sealed_unit() {
    struct Units(std::sync::Mutex<Vec<Vec<u64>>>);
    impl AmendSink for Units {
        fn sealed(
            &self,
            amendment: &Amendment,
        ) -> Result<
            busbar_kernel_audit::amend::AmendCommit,
            busbar_kernel_audit::amend::AmendPersistError,
        > {
            self.sealed_many(std::slice::from_ref(amendment))
        }
        fn sealed_many(
            &self,
            amendments: &[Amendment],
        ) -> Result<
            busbar_kernel_audit::amend::AmendCommit,
            busbar_kernel_audit::amend::AmendPersistError,
        > {
            self.0
                .lock()
                .unwrap()
                .push(amendments.iter().map(|a| a.seq).collect());
            Ok(Box::pin(async { Ok(()) }))
        }
    }
    let journal = NodeAmendments::new();
    let units = std::sync::Arc::new(Units(std::sync::Mutex::new(Vec::new())));
    journal
        .bind(
            Some(units.clone() as std::sync::Arc<dyn AmendSink>),
            0,
            &crate::teller::Kernel::new().durability_token(),
        )
        .await
        .unwrap();
    hook_reads(&journal, &["a", "b", "c"], None, "openai", false)
        .await
        .unwrap();
    let units = units.0.lock().unwrap().clone();
    assert_eq!(units.len(), 1, "one unit for the set: {units:?}");
    assert_eq!(units[0].len(), 3);
    assert!(units[0].windows(2).all(|w| w[1] == w[0] + 1));
}
