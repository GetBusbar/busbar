// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::{HashMap, VecDeque};
use std::fmt::Write as _;
use std::sync::{Mutex, MutexGuard};

use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::store::{OpRefused, OpResult, Scanned, SyncStore, Tail};
use busbar_contract::abi::store::{OpId, OP_ID_RETENTION_SECS};
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::{
    MeteringDelta, PlaneRecordRef, RecordStore, RecordStoreResult, UsageDelta,
};

use crate::MemoryStore;

busbar_contract::store_door!(MemoryStore, "memory", env!("CARGO_PKG_VERSION"), 1024);

/// What an applied op answered, replayed verbatim.
#[derive(Debug, Clone)]
enum Answer {
    Done,
}

type Body = [u8; 32];

struct Feed(sha2::Sha256);

impl std::fmt::Write for Feed {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        sha2::Digest::update(&mut self.0, s.as_bytes());
        Ok(())
    }
}

fn body(args: std::fmt::Arguments<'_>) -> Body {
    let mut feed = Feed(<sha2::Sha256 as sha2::Digest>::new());

    let _ = feed.write_fmt(args);
    sha2::Digest::finalize(feed.0).into()
}

struct Recorded {
    body: Body,
    answer: Answer,
}

#[derive(Default)]
struct Inner {
    ops: HashMap<OpId, Recorded>,
    /// `(recorded_at, op_id)`, oldest first: the retention sweep's order.
    aged: VecDeque<(u64, OpId)>,
}

/// The v3 state [`MemoryStore`] carries.
#[derive(Default)]
pub(crate) struct State {
    inner: Mutex<Inner>,
}

enum Seen {
    New,
    Replay(Answer),
    Conflict,
}

impl Inner {
    fn seen(&self, op: OpId, body: &Body) -> Seen {
        match self.ops.get(&op) {
            None => Seen::New,
            Some(r) if r.body == *body => Seen::Replay(r.answer.clone()),
            Some(_) => Seen::Conflict,
        }
    }

    fn record(&mut self, now: u64, op: OpId, body: Body, answer: Answer) {
        while let Some(&(at, old)) = self.aged.front() {
            if at.saturating_add(OP_ID_RETENTION_SECS) > now {
                break;
            }
            self.aged.pop_front();
            self.ops.remove(&old);
        }
        self.ops.insert(op, Recorded { body, answer });
        self.aged.push_back((now, op));
    }
}

impl State {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }
}

fn failed(e: busbar_contract::records::RecordStoreError) -> OpRefused {
    OpRefused::Failed(e.0)
}

impl MemoryStore {
    fn deduped(
        &self,
        op: OpId,
        body: Body,
        apply: impl FnOnce(&Self, &mut Inner) -> OpResult<Answer>,
    ) -> OpResult<Answer> {
        let mut inner = self.v3.lock();
        match inner.seen(op, &body) {
            Seen::Replay(a) => Ok(a),
            Seen::Conflict => Err(OpRefused::Conflict),
            Seen::New => {
                let answer = apply(self, &mut inner)?;
                inner.record(self.now(), op, body, answer.clone());
                Ok(answer)
            }
        }
    }
}

impl MemoryStore {
    pub(crate) fn v3_append_plane_record_op(
        &self,
        op: OpId,
        record: PlaneRecordRef<'_>,
    ) -> OpResult<()> {
        let body = body(format_args!("append_plane_record:{:?}", record.to_record()));
        self.deduped(op, body, |s, _| {
            s.append_plane_record(record).map_err(failed)?;
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_record_put(
        &self,
        schema: &str,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), String> {
        let value = RecordBytes::new(value.to_vec())
            .map_err(|n| format!("a record of {n} bytes is over the ceiling"))?;
        self.record_put_at(schema, key, &value);
        Ok(())
    }

    pub(crate) fn v3_record_get(
        &self,
        schema: &str,
        key: &[u8],
    ) -> Result<Option<RecordBytes>, String> {
        Ok(self.record_get_at(schema, key))
    }

    pub(crate) fn v3_record_scan(
        &self,
        schema: &str,
        prefix: &[u8],
        limit: u32,
    ) -> Result<Vec<(Vec<u8>, RecordBytes)>, String> {
        Ok(self.record_scan_at(schema, prefix, limit))
    }

    pub(crate) fn v3_add_usage_batch(
        &self,
        op: OpId,
        cells: &[(&str, u64, UsageDelta)],
    ) -> OpResult<()> {
        let body = body(format_args!("add_usage_batch:{cells:?}"));
        self.deduped(op, body, |s, _| {
            for (bucket, window, delta) in cells {
                s.add_usage(bucket, *window, delta).map_err(failed)?;
            }
            Ok(Answer::Done)
        })
        .map(drop)
    }

    pub(crate) fn v3_add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        let body = body(format_args!("add_metering_batch:{deltas:?}"));
        self.deduped(op, body, |s, _| {
            for d in deltas {
                s.add_metering(d).map_err(failed)?;
            }
            Ok(Answer::Done)
        })
        .map(drop)
    }
}

impl SyncStore for MemoryStore {
    const TAIL: Tail = Tail {
        ephemeral: true,
        durable_plane: false,
        fork_refusal: true,
    };

    fn validate(_settings: &[u8]) -> Result<(), String> {
        Ok(())
    }

    fn open(settings: &[u8], _host: Option<Host>) -> Result<Self, String> {
        let settings: serde_json::Value = serde_json::from_slice(settings).unwrap_or_default();
        if settings
            .get("test_require_secret")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Err("the fixture requires its lent secret".into());
        }
        Ok(Self::new())
    }

    fn open_with_secrets(
        settings: &[u8],
        secrets: &[&[u8]],
        host: Option<Host>,
    ) -> Result<Self, String> {
        let read: serde_json::Value = serde_json::from_slice(settings).unwrap_or_default();
        if read.get("test_require_secret").and_then(|v| v.as_bool()) != Some(true) {
            return <Self as SyncStore>::open(settings, host);
        }
        if read.get("password").is_some() || secrets != [b"hunter2".as_slice()] {
            return Err("the fixture did not receive its declared secret separately".into());
        }
        Ok(Self::new())
    }

    fn append_plane_record_op(&self, op: OpId, record: PlaneRecordRef<'_>) -> OpResult<()> {
        self.v3_append_plane_record_op(op, record)
    }

    fn record_put(&self, schema: &str, key: &[u8], value: &[u8]) -> Result<(), String> {
        self.v3_record_put(schema, key, value)
    }

    fn record_get(&self, schema: &str, key: &[u8]) -> Result<Option<RecordBytes>, String> {
        self.v3_record_get(schema, key)
    }

    fn record_scan(&self, schema: &str, prefix: &[u8], limit: u32) -> Result<Scanned, String> {
        self.v3_record_scan(schema, prefix, limit)
    }

    fn add_usage_batch(&self, op: OpId, cells: &[(&str, u64, UsageDelta)]) -> OpResult<()> {
        self.v3_add_usage_batch(op, cells)
    }

    fn add_metering_batch(&self, op: OpId, deltas: &[MeteringDelta]) -> OpResult<()> {
        self.v3_add_metering_batch(op, deltas)
    }

    fn purge_usage_before(&self, before: u64) -> RecordStoreResult<u64> {
        let mut usage = self.usage();
        let was = usage.len();
        usage.retain(|(_, window_start), _| *window_start == 0 || *window_start >= before);
        Ok((was - usage.len()) as u64)
    }
}
