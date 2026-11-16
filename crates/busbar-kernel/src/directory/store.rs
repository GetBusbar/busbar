// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The directory's store layout and codec (IF §12.29 "Store layout", frozen; this module is its only reader and
//! writer), and [`Tx`]: one optimistic read-decide-commit over it.
//!
//! Scope. One host-private CoreStore scope per provisioning instance, labelled by `dir_ns` =
//! `SHA-256("busbar.dir.v1\0" ‖ stamp name ‖ 0x00 ‖ instance name)[..16]` (hex), so the directory survives
//! restart, reconfigure and replicas and two instances never share a record. Under it, two schemas: [`DIR`] (the
//! keys of the frozen table) and [`HELD`] (`held_ns`: held principal → subject id). They share one scope so a
//! write commits the record, its indexes, counts, guard and hold together. No RECORD Need reaches either: K5's
//! plugin records use their own schemas and labels.

use busbar_contract::Secret;

use crate::persistence::facade::CoreStore;
use crate::persistence::scoped::{self, Expected, Mutation, Predicate, Request, ScopedStore};
use busbar_plugin_abi::host_side::needs::NeedErr;
use busbar_plugin_abi::need::dir;

/// The directory keys (subjects, groups, indexes, memberships, counts, guard).
pub(super) const DIR: &str = "busbar.dir.v1";
/// `held_ns`: an INACTIVE linked subject's principal → its subject id.
pub(super) const HELD: &str = "busbar.held.v1";

pub(super) const T_SUBJECT: u8 = b'S';
pub(super) const T_GROUP: u8 = b'G';
const T_INDEX: u8 = b'I';
pub(super) const T_MEMBER: u8 = b'M';
const T_COUNT: u8 = b'C';
const T_ACTIVE: u8 = b'A';
const T_MEMBERS: u8 = b'N';
const T_GUARD: u8 = b'W';

/// Index name and value caps (dev's contract reference values; `dir` carries the rest).
pub(super) const MAX_INDEX_NAME: usize = 32;
pub(super) const MAX_INDEX_VALUE: usize = 256;
/// Minted ids: 16 random bytes as 32 lowercase hex.
pub(super) const ID_LEN: usize = 32;

/// The scope label of one provisioning instance (`dir_ns`, hex).
pub(super) fn label(plugin: &str, name: &str) -> String {
    let digest = busbar_contract::crypto::sha256_parts(&[
        b"busbar.dir.v1\0",
        plugin.as_bytes(),
        &[0],
        name.as_bytes(),
    ]);
    hex::encode(&digest[..16])
}

pub(super) fn scope(
    store: &std::sync::Arc<CoreStore>,
    plugin: &str,
    name: &str,
) -> Result<ScopedStore, NeedErr> {
    ScopedStore::host_private(
        std::sync::Arc::clone(store),
        &label(plugin, name),
        [DIR.to_string(), HELD.to_string()],
    )
    .map_err(|_| NeedErr::Unavailable)
}

/// `S ‖ id` or `G ‖ id`.
pub(super) fn record_key(tag: u8, id: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + id.len());
    k.push(tag);
    k.extend_from_slice(id.as_bytes());
    k
}

/// `I ‖ kind ‖ name_len ‖ name ‖ value`.
pub(super) fn index_key(kind: u8, name: &str, value: &[u8]) -> Vec<u8> {
    let mut k = Vec::with_capacity(3 + name.len() + value.len());
    k.extend_from_slice(&[T_INDEX, kind, name.len() as u8]);
    k.extend_from_slice(name.as_bytes());
    k.extend_from_slice(value);
    k
}

/// `M ‖ gid_len ‖ gid` (the member prefix of one group).
pub(super) fn members_prefix(gid: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(2 + gid.len() + ID_LEN);
    k.extend_from_slice(&[T_MEMBER, gid.len() as u8]);
    k.extend_from_slice(gid.as_bytes());
    k
}

pub(super) fn member_key(gid: &str, mid: &str) -> Vec<u8> {
    let mut k = members_prefix(gid);
    k.extend_from_slice(mid.as_bytes());
    k
}

/// `C ‖ kind`: records of that kind.
pub(super) fn count_key(kind: u8) -> Vec<u8> {
    vec![T_COUNT, kind]
}

/// `A`: ACTIVE subjects.
pub(super) fn active_key() -> Vec<u8> {
    vec![T_ACTIVE]
}

/// `N ‖ gid`: members of gid.
pub(super) fn member_count_key(gid: &str) -> Vec<u8> {
    let mut k = Vec::with_capacity(1 + gid.len());
    k.push(T_MEMBERS);
    k.extend_from_slice(gid.as_bytes());
    k
}

pub(super) fn guard_key() -> Vec<u8> {
    vec![T_GUARD]
}

/// One decoded subject or group record. Groups carry state 0.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Record {
    pub version: u64,
    pub state: u8,
    pub source: u8,
    pub indexes: Vec<(String, Vec<u8>)>,
    pub document: Vec<u8>,
}

impl Record {
    /// `version u64 BE ‖ state u8 ‖ source u8 ‖ n u8 ‖ (name_len u8 ‖ name ‖ value_len u16 BE ‖ value)×n ‖ document`.
    pub fn encode(&self) -> Secret<Vec<u8>> {
        let size = 11
            + self
                .indexes
                .iter()
                .map(|(n, v)| 3 + n.len() + v.len())
                .sum::<usize>()
            + self.document.len();
        let mut out = Vec::with_capacity(size);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&[self.state, self.source, self.indexes.len() as u8]);
        for (name, value) in &self.indexes {
            out.push(name.len() as u8);
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
            out.extend_from_slice(value);
        }
        out.extend_from_slice(&self.document);
        Secret::new(out)
    }

    /// None = bytes this module never wrote (a store fault, never read as data).
    pub fn decode(raw: &[u8]) -> Option<Self> {
        let version = u64::from_be_bytes(raw.get(..8)?.try_into().ok()?);
        let (&state, rest) = raw.get(8..)?.split_first()?;
        let (&source, rest) = rest.split_first()?;
        let (&n, mut rest) = rest.split_first()?;
        let mut indexes = Vec::with_capacity(usize::from(n));
        for _ in 0..n {
            let (&name_len, tail) = rest.split_first()?;
            let (name, tail) = tail.split_at_checked(usize::from(name_len))?;
            let (len, tail) = tail.split_at_checked(2)?;
            let len = usize::from(u16::from_be_bytes([len[0], len[1]]));
            let (value, tail) = tail.split_at_checked(len)?;
            indexes.push((core::str::from_utf8(name).ok()?.to_string(), value.to_vec()));
            rest = tail;
        }
        Some(Self {
            version,
            state,
            source,
            indexes,
            document: rest.to_vec(),
        })
    }

    pub fn index(&self, name: &str) -> Option<&[u8]> {
        self.indexes
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_slice())
    }
}

/// The guard row `W`: `window_start_s u64 BE ‖ moved u32 BE ‖ released_until_s u64 BE`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GuardRow {
    pub window_start_s: u64,
    pub moved: u32,
    pub released_until_s: u64,
}

impl GuardRow {
    pub(super) fn encode(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(20);
        out.extend_from_slice(&self.window_start_s.to_be_bytes());
        out.extend_from_slice(&self.moved.to_be_bytes());
        out.extend_from_slice(&self.released_until_s.to_be_bytes());
        out
    }
    pub(super) fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() != 20 {
            return None;
        }
        Some(Self {
            window_start_s: u64::from_be_bytes(raw[..8].try_into().ok()?),
            moved: u32::from_be_bytes(raw[8..12].try_into().ok()?),
            released_until_s: u64::from_be_bytes(raw[12..].try_into().ok()?),
        })
    }
}

/// The kind byte of a record kind (`dir::SUBJECT` / `dir::GROUP`).
pub(super) fn kind_tag(kind: u32) -> Option<u8> {
    match kind {
        dir::SUBJECT => Some(T_SUBJECT),
        dir::GROUP => Some(T_GROUP),
        _ => None,
    }
}

/// One optimistic attempt: every address read is pinned (`Exact` or `Absent`) by the one commit, so a concurrent
/// writer of any of them turns the commit into a ConditionConflict and the op decides again.
pub(super) struct Tx<'s> {
    scope: &'s ScopedStore,
    seen: Vec<(&'static str, Vec<u8>, Option<Secret<Vec<u8>>>)>,
    writes: Vec<(&'static str, Vec<u8>, Option<Secret<Vec<u8>>>)>,
    ranges: Vec<Mutation>,
}

impl<'s> Tx<'s> {
    pub fn new(scope: &'s ScopedStore) -> Self {
        Self {
            scope,
            seen: Vec::new(),
            writes: Vec::new(),
            ranges: Vec::new(),
        }
    }

    /// Read every address not read yet, in one coherent store read.
    pub async fn read(&mut self, keys: Vec<(&'static str, Vec<u8>)>) -> Result<(), NeedErr> {
        let fresh: Vec<(&'static str, Vec<u8>)> = keys
            .into_iter()
            .filter(|(s, k)| !self.seen.iter().any(|(ss, kk, _)| ss == s && kk == k))
            .collect();
        if fresh.is_empty() {
            return Ok(());
        }
        let addrs: Vec<(&str, &[u8])> = fresh.iter().map(|(s, k)| (*s, k.as_slice())).collect();
        let values = self.scope.read(&addrs).await.map_err(unavailable)?;
        if values.len() != fresh.len() {
            return Err(NeedErr::Unavailable);
        }
        for ((schema, key), value) in fresh.into_iter().zip(values) {
            self.seen.push((schema, key, value));
        }
        Ok(())
    }

    /// The value at an address as this attempt sees it: its own write first, else what it read.
    pub fn get(&self, schema: &str, key: &[u8]) -> Option<Vec<u8>> {
        let seal = crate::seal::lend();
        if let Some((_, _, v)) = self
            .writes
            .iter()
            .find(|(s, k, _)| *s == schema && k == key)
        {
            return v.as_ref().map(|v| v.expose(&seal).clone());
        }
        self.seen
            .iter()
            .find(|(s, k, _)| *s == schema && k == key)
            .and_then(|(_, _, v)| v.as_ref().map(|v| v.expose(&seal).clone()))
    }

    pub fn put(&mut self, schema: &'static str, key: Vec<u8>, value: Secret<Vec<u8>>) {
        self.set(schema, key, Some(value));
    }

    pub fn del(&mut self, schema: &'static str, key: Vec<u8>) {
        self.set(schema, key, None);
    }

    fn set(&mut self, schema: &'static str, key: Vec<u8>, value: Option<Secret<Vec<u8>>>) {
        match self
            .writes
            .iter_mut()
            .find(|(s, k, _)| *s == schema && *k == key)
        {
            Some(slot) => slot.2 = value,
            None => self.writes.push((schema, key, value)),
        }
    }

    /// Delete every key of exactly `exact_len` bytes under `prefix` in DIR.
    pub fn del_range(&mut self, prefix: Vec<u8>, exact_len: usize) {
        self.ranges.push(Mutation::DeleteRange {
            schema: DIR.to_string(),
            prefix,
            exact_key_length: exact_len as u64,
        });
    }

    /// A `u64 BE` counter (absent = 0).
    pub fn count(&self, key: &[u8]) -> u64 {
        self.get(DIR, key)
            .and_then(|v| v.try_into().ok().map(u64::from_be_bytes))
            .unwrap_or(0)
    }

    /// Move a counter (read first) by `delta`; a counter at 0 is deleted.
    pub fn add(&mut self, key: Vec<u8>, delta: i64) {
        let next = self.count(&key).saturating_add_signed(delta);
        if next == 0 {
            self.del(DIR, key);
        } else {
            self.put(DIR, key, Secret::new(next.to_be_bytes().to_vec()));
        }
    }

    pub fn writes_anything(&self) -> bool {
        !self.writes.is_empty() || !self.ranges.is_empty()
    }

    /// Ok(true) = applied; Ok(false) = another writer moved something this attempt read; Err(TOO_MANY marker) =
    /// the store refused the commit's size.
    pub async fn commit(self, store: &CoreStore) -> Result<Committed, NeedErr> {
        let op_id = store.next_id().map_err(|_| NeedErr::Unavailable)?.operation;
        let request = Request {
            op_id,
            predicates: self
                .seen
                .iter()
                .map(|(schema, key, raw)| Predicate {
                    schema: (*schema).to_string(),
                    key: key.clone(),
                    expected: raw.clone().map_or(Expected::Absent, Expected::Exact),
                })
                .collect(),
            mutations: self
                .writes
                .into_iter()
                .map(|(schema, key, value)| match value {
                    Some(value) => Mutation::Put {
                        schema: schema.to_string(),
                        key,
                        value,
                    },
                    None => Mutation::Delete {
                        schema: schema.to_string(),
                        key,
                    },
                })
                .chain(self.ranges)
                .collect(),
        };
        let mut outcome = match self.scope.conditional_native(&request).await {
            Ok(outcome) => outcome,
            // An over-budget commit is refused before it reaches the store: nothing was written.
            Err(scoped::Error::Invalid) => return Ok(Committed::TooLarge),
            Err(e) => return Err(unavailable(e)),
        };
        for _ in 0..IN_DOUBT_RETRIES {
            match outcome {
                scoped::Outcome::Pending(id) | scoped::Outcome::Busy(Some(id)) => {
                    outcome = self.scope.retry(id).await.map_err(unavailable)?;
                }
                _ => break,
            }
        }
        match outcome {
            scoped::Outcome::Applied => Ok(Committed::Applied),
            scoped::Outcome::ConditionConflict => Ok(Committed::Conflict),
            _ => Err(NeedErr::Unavailable),
        }
    }
}

/// How many times an in-doubt commit is driven again before the op answers Unavailable.
const IN_DOUBT_RETRIES: usize = 2;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Committed {
    Applied,
    Conflict,
    TooLarge,
}

pub(super) fn unavailable(_: scoped::Error) -> NeedErr {
    NeedErr::Unavailable
}
