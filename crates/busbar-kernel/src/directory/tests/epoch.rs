// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use busbar_contract::persistence::{
    BackendInfo, Call, ClockObservation, CommitKey, DatasetId, Decision, Page, PersistenceBackend,
    PreparedCandidate, Read, ReadResult, Scan,
};
use busbar_contract::Secret;
use busbar_plugin_abi::host_side::needs::{DirNeed, NeedErr};
use busbar_plugin_abi::need::dir;
use busbar_plugin_abi::records::{Records, Reply, Writer};
use tokio::sync::Notify;

use super::super::ops::{self, Cx, Sink};
use super::super::store::{self, Committed, Tx, DIR, T_GROUP, T_SUBJECT};
use super::super::{Instance, LogEvents};

const AFTER_SCAN: u8 = 1;
const BEFORE_COMMIT: u8 = 2;

/// Interleave the real directory/CoreStore path without replacing its decisions.
struct Interleave {
    backend: Arc<dyn PersistenceBackend>,
    arm: AtomicU8,
    arrived: Notify,
    resume: Notify,
}

impl Interleave {
    async fn pause(&self, point: u8) {
        if self
            .arm
            .compare_exchange(point, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.arrived.notify_one();
            self.resume.notified().await;
        }
    }

    async fn arrived(&self) {
        tokio::time::timeout(std::time::Duration::from_secs(5), self.arrived.notified())
            .await
            .expect("directory reached the scheduled interleave");
    }
}

impl PersistenceBackend for Interleave {
    fn info(&self) -> BackendInfo {
        self.backend.info()
    }
    fn read(&self, request: Arc<Read>) -> Call<'_, ReadResult> {
        self.backend.read(request)
    }
    fn scan(&self, request: Arc<Scan>) -> Call<'_, Page> {
        Box::pin(async move {
            let page = self.backend.scan(request).await?;
            self.pause(AFTER_SCAN).await;
            Ok(page)
        })
    }
    fn commit(&self, candidate: PreparedCandidate, key: CommitKey) -> Call<'_, Decision> {
        Box::pin(async move {
            self.pause(BEFORE_COMMIT).await;
            self.backend.commit(candidate, key).await
        })
    }
    fn clock(&self, dataset: DatasetId) -> Call<'_, ClockObservation> {
        self.backend.clock(dataset)
    }
}

#[derive(Default)]
struct Answer {
    code: u32,
    bytes: Vec<u8>,
}

impl Sink for Answer {
    fn set(&mut self, a: u64, _b: u64) {
        self.code = a as u32;
    }
    fn put0(&mut self, bytes: &[u8]) -> Result<(), NeedErr> {
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }
    fn pair0(&mut self, _name: &[u8], _value: &[u8]) -> Result<(), NeedErr> {
        panic!("these mutation fixtures do not return pairs")
    }
    fn put1(&mut self, _bytes: &[u8]) -> Result<(), NeedErr> {
        Ok(())
    }
}

struct Fixture {
    core: Arc<crate::persistence::facade::CoreStore>,
    backend: Arc<Interleave>,
    instance: Instance,
}

impl Fixture {
    async fn new() -> Self {
        let backend = Arc::new(Interleave {
            backend: crate::real_store::native_backend().await,
            arm: AtomicU8::new(0),
            arrived: Notify::new(),
            resume: Notify::new(),
        });
        let core = crate::real_store::core_over(backend.clone()).await;
        let mut cfg = super::cfg();
        cfg.link = None;
        let instance = Instance {
            name: "directory".into(),
            scope: store::scope(&core, "fixture", "directory").expect("directory scope"),
            cfg,
            held: None,
            tripped: std::sync::atomic::AtomicU64::new(0),
        };
        Self {
            core,
            backend,
            instance,
        }
    }

    async fn run(&self, need: DirNeed<'_>) -> Result<Answer, NeedErr> {
        let mut answer = Answer::default();
        ops::run(
            &Cx {
                store: &self.core,
                inst: &self.instance,
                now: 1,
                events: &LogEvents,
            },
            need,
            &mut answer,
        )
        .await?;
        Ok(answer)
    }

    async fn create(&self, kind: u32) -> String {
        let answer = self
            .run(DirNeed::Create {
                kind,
                state: if kind == dir::SUBJECT {
                    dir::STATE_ACTIVE
                } else {
                    0
                },
                pull: false,
                document: b"{}",
                indexes: Records::new(&[]),
            })
            .await
            .expect("create");
        assert_eq!(answer.code, dir::OK);
        String::from_utf8(answer.bytes).expect("minted id")
    }

    async fn row(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut tx = Tx::new(&self.instance.scope);
        tx.read(vec![(DIR, key.to_vec())]).await.expect("read row");
        tx.get(DIR, key)
    }

    async fn set_epoch(&self, value: &[u8]) {
        let mut tx = Tx::new(&self.instance.scope);
        tx.put(DIR, b"E".to_vec(), Secret::new(value.to_vec()));
        assert_eq!(tx.commit(&self.core).await, Ok(Committed::Applied));
    }
}

fn delete(id: &str) -> DirNeed<'_> {
    DirNeed::Delete {
        kind: dir::SUBJECT,
        id,
        expected_version: 0,
    }
}

fn add<'a>(group: &'a str, members: &'a Reply) -> DirNeed<'a> {
    DirNeed::Apply {
        kind: dir::GROUP,
        id: group,
        expected_version: 0,
        apply: 0,
        state: 0,
        document: &[],
        indexes: Records::new(&[]),
        members: Records::new(members.as_bytes()),
    }
}

fn member(id: &str) -> Reply {
    let mut members = Reply::new();
    members.put_text(dir::DM_ADD, id).expect("member record");
    members
}

#[tokio::test]
async fn delete_rescans_when_apply_adds_an_unseen_membership() {
    let f = Fixture::new().await;
    let subject = f.create(dir::SUBJECT).await;
    let group = f.create(dir::GROUP).await;
    let members = member(&subject);
    f.backend.arm.store(AFTER_SCAN, Ordering::SeqCst);
    let (deleted, ()) = tokio::join!(f.run(delete(&subject)), async {
        f.backend.arrived().await;
        assert_eq!(
            f.run(add(&group, &members)).await.expect("apply").code,
            dir::OK
        );
        f.backend.resume.notify_one();
    });
    assert_eq!(deleted.expect("delete").code, dir::OK);
    assert!(f
        .row(&store::record_key(T_SUBJECT, &subject))
        .await
        .is_none());
    assert!(f.row(&store::record_key(T_GROUP, &group)).await.is_some());
    assert!(f.row(&store::member_key(&group, &subject)).await.is_none());
    assert!(f.row(&store::member_count_key(&group)).await.is_none());
    assert_eq!(f.row(b"E").await, Some(4u64.to_be_bytes().to_vec()));
}

#[tokio::test]
async fn apply_rechecks_subject_when_delete_commits_first() {
    let f = Fixture::new().await;
    let subject = f.create(dir::SUBJECT).await;
    let group = f.create(dir::GROUP).await;
    let members = member(&subject);
    f.backend.arm.store(BEFORE_COMMIT, Ordering::SeqCst);
    let (applied, ()) = tokio::join!(f.run(add(&group, &members)), async {
        f.backend.arrived().await;
        assert_eq!(f.run(delete(&subject)).await.expect("delete").code, dir::OK);
        f.backend.resume.notify_one();
    });
    assert_eq!(applied.expect("apply").code, dir::INVALID);
    assert!(f.row(&store::member_key(&group, &subject)).await.is_none());
    assert!(f.row(&store::member_count_key(&group)).await.is_none());
    assert_eq!(f.row(b"E").await, Some(3u64.to_be_bytes().to_vec()));
}

#[tokio::test]
async fn absent_epoch_is_written_once_and_domain_refusal_does_not_advance_it() {
    let f = Fixture::new().await;
    assert!(f.row(b"E").await.is_none());
    assert_eq!(
        f.run(delete("missing")).await.expect("absent").code,
        dir::NOT_FOUND
    );
    assert!(f.row(b"E").await.is_none());
    let subject = f.create(dir::SUBJECT).await;
    assert_eq!(f.row(b"E").await, Some(1u64.to_be_bytes().to_vec()));
    assert_eq!(
        f.run(delete("missing")).await.expect("absent").code,
        dir::NOT_FOUND
    );
    assert_eq!(f.row(b"E").await, Some(1u64.to_be_bytes().to_vec()));
    assert_eq!(f.run(delete(&subject)).await.expect("delete").code, dir::OK);
    assert_eq!(f.row(b"E").await, Some(2u64.to_be_bytes().to_vec()));
}

#[tokio::test]
async fn concurrent_first_writers_predicate_the_absent_epoch() {
    let f = Fixture::new().await;
    f.backend.arm.store(BEFORE_COMMIT, Ordering::SeqCst);
    let (group, subject) = tokio::join!(f.create(dir::GROUP), async {
        f.backend.arrived().await;
        let subject = f.create(dir::SUBJECT).await;
        f.backend.resume.notify_one();
        subject
    });
    assert!(f.row(&store::record_key(T_GROUP, &group)).await.is_some());
    assert!(f
        .row(&store::record_key(T_SUBJECT, &subject))
        .await
        .is_some());
    assert_eq!(f.row(b"E").await, Some(2u64.to_be_bytes().to_vec()));
}

#[tokio::test]
async fn guard_release_preserves_directory_epoch() {
    let f = Fixture::new().await;
    f.create(dir::SUBJECT).await;
    ops::release(
        &Cx {
            store: &f.core,
            inst: &f.instance,
            now: 1,
            events: &LogEvents,
        },
        60,
        "admin",
    )
    .await
    .expect("guard release");
    assert_eq!(f.row(b"E").await, Some(1u64.to_be_bytes().to_vec()));
}

#[tokio::test]
async fn malformed_or_exhausted_epoch_refuses_without_domain_effects() {
    for value in [vec![0; 7], vec![0; 9], u64::MAX.to_be_bytes().to_vec()] {
        let f = Fixture::new().await;
        let subject = f.create(dir::SUBJECT).await;
        let before = f.row(&store::record_key(T_SUBJECT, &subject)).await;
        f.set_epoch(&value).await;
        assert!(matches!(
            f.run(delete(&subject)).await,
            Err(NeedErr::Unavailable)
        ));
        assert_eq!(f.row(&store::record_key(T_SUBJECT, &subject)).await, before);
        assert_eq!(f.row(b"E").await, Some(value));
    }
}
