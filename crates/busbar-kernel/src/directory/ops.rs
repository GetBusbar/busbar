// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The seven DIRECTORY ops and the mass-deprovision guard (IF §12.29 "Each op is one read and one commit").
//! Reads answer from one store read (SCAN: pages). A write reads every address it depends on, decides, and sends
//! one commit pinning all of them; a ConditionConflict re-reads and re-decides, at most MAX_ATTEMPTS times.

use std::sync::atomic::Ordering;

use busbar_contract::Secret;
use busbar_plugin_abi::host_side::needs::{DirNeed, NeedErr, NeedOut};
use busbar_plugin_abi::need::dir;
use busbar_plugin_abi::records::{tag, Records};

use crate::persistence::facade::CoreStore;
use crate::persistence::scoped::ScopedStore;

use super::events::{DirEvent, DirectoryEvents};
use super::store::{
    self, active_key, count_key, guard_key, index_key, kind_tag, member_count_key, member_key,
    members_prefix, record_key, Committed, GuardRow, Record, Tx, DIR, HELD, ID_LEN, MAX_INDEX_NAME,
    MAX_INDEX_VALUE, T_GROUP, T_MEMBER, T_SUBJECT,
};
use super::{Instance, MAX_ATTEMPTS, MAX_HELD};

/// Where an op writes its answer: a/b, data0 (records), then data1 (`DirFacts`).
pub(super) trait Sink: Send {
    fn set(&mut self, a: u64, b: u64);
    fn put0(&mut self, bytes: &[u8]) -> Result<(), NeedErr>;
    fn pair0(&mut self, name: &[u8], value: &[u8]) -> Result<(), NeedErr>;
    fn put1(&mut self, bytes: &[u8]) -> Result<(), NeedErr>;
}

impl Sink for NeedOut<'_> {
    fn set(&mut self, a: u64, b: u64) {
        NeedOut::set(self, a, b);
    }
    fn put0(&mut self, bytes: &[u8]) -> Result<(), NeedErr> {
        NeedOut::put0(self, bytes)
    }
    fn pair0(&mut self, name: &[u8], value: &[u8]) -> Result<(), NeedErr> {
        NeedOut::pair0(self, name, value)
    }
    fn put1(&mut self, bytes: &[u8]) -> Result<(), NeedErr> {
        NeedOut::put1(self, bytes)
    }
}

/// Everything one op needs.
pub(super) struct Cx<'a> {
    pub store: &'a CoreStore,
    pub inst: &'a Instance,
    pub now: u64,
    pub events: &'a dyn DirectoryEvents,
}

impl Cx<'_> {
    fn scope(&self) -> &ScopedStore {
        &self.inst.scope
    }
    fn link(&self) -> Option<&str> {
        self.inst.cfg.link.as_ref().map(|l| &*l.index)
    }
    /// A subject's linked principal: its value under `link.index`.
    fn linked(&self, tag: u8, rec: &Record) -> Option<Vec<u8>> {
        if tag != T_SUBJECT {
            return None;
        }
        self.link()
            .and_then(|name| rec.index(name))
            .map(<[u8]>::to_vec)
    }
}

/// One op's answer before it is written.
struct Decision {
    code: u32,
    index: u32,
    b: u64,
    state: u32,
    id: Option<String>,
    /// This replica's `held_ns` change: (principal, held).
    hold: Option<(Vec<u8>, bool)>,
}

impl Decision {
    fn domain(code: u32) -> Self {
        Self {
            code,
            index: 0,
            b: 0,
            state: 0,
            id: None,
            hold: None,
        }
    }
    fn conflict(index: usize) -> Self {
        Self {
            index: u32::try_from(index).unwrap_or(u32::MAX),
            ..Self::domain(dir::CONFLICT)
        }
    }
}

pub(super) async fn run(cx: &Cx<'_>, n: DirNeed<'_>, out: &mut impl Sink) -> Result<(), NeedErr> {
    match n {
        DirNeed::Get { kind, id } => get(cx, kind, id, out).await,
        DirNeed::Lookup { kind, index, value } => lookup(cx, kind, index, value, out).await,
        DirNeed::Scan {
            kind,
            scope,
            after,
            limit,
        } => scan(cx, kind, scope, after, limit, out).await,
        DirNeed::Count { kind, scope } => count(cx, kind, scope, out).await,
        DirNeed::Create { .. } | DirNeed::Apply { .. } | DirNeed::Delete { .. } => {
            write(cx, n, out).await
        }
    }
}

/// `code | index << 32`, b, then the 16-byte `DirFacts` (state u32, more u32, active u64).
fn answer(
    out: &mut impl Sink,
    code: u32,
    index: u32,
    b: u64,
    state: u32,
    more: u32,
    active: u64,
) -> Result<(), NeedErr> {
    out.set(u64::from(code) | (u64::from(index) << 32), b);
    let mut facts = [0u8; 16];
    facts[..4].copy_from_slice(&state.to_ne_bytes());
    facts[4..8].copy_from_slice(&more.to_ne_bytes());
    facts[8..].copy_from_slice(&active.to_ne_bytes());
    out.put1(&facts)
}

fn domain(out: &mut impl Sink, code: u32) -> Result<(), NeedErr> {
    answer(out, code, 0, 0, 0, 0, 0)
}

/// One record (head, body, zero padding to 8) into data0.
fn record0(out: &mut impl Sink, rec_tag: u16, body: &[u8]) -> Result<(), NeedErr> {
    let len = u32::try_from(body.len()).map_err(|_| NeedErr::Limit)?;
    let mut framed = Vec::with_capacity(8 + body.len() + 7);
    framed.extend_from_slice(&rec_tag.to_ne_bytes());
    framed.extend_from_slice(&0u16.to_ne_bytes());
    framed.extend_from_slice(&len.to_ne_bytes());
    framed.extend_from_slice(body);
    framed.resize(framed.len().next_multiple_of(8), 0);
    out.put0(&framed)
}

fn text_ok(bytes: &[u8], max: usize) -> bool {
    !bytes.is_empty()
        && bytes.len() <= max
        && core::str::from_utf8(bytes).is_ok_and(|s| !s.chars().any(char::is_control))
}

fn id_ok(id: &str) -> bool {
    text_ok(id.as_bytes(), dir::MAX_ID as usize)
}

/// The Need's PAIR* index list. Err = the domain code (INVALID, TOO_MANY).
fn indexes(list: Records<'_>) -> Result<Vec<(String, Vec<u8>)>, u32> {
    let mut out: Vec<(String, Vec<u8>)> = Vec::new();
    for rec in list {
        let rec = rec.map_err(|_| dir::INVALID)?;
        if rec.tag != tag::PAIR {
            return Err(dir::INVALID);
        }
        let (name, value) = rec.pair().map_err(|_| dir::INVALID)?;
        if !text_ok(name.as_bytes(), MAX_INDEX_NAME)
            || !text_ok(value, MAX_INDEX_VALUE)
            || out.iter().any(|(n, _)| n == name)
        {
            return Err(dir::INVALID);
        }
        if out.len() == dir::MAX_INDEXES as usize {
            return Err(dir::TOO_MANY);
        }
        out.push((name.to_string(), value.to_vec()));
    }
    Ok(out)
}

/// The Need's DM_* member list.
fn members(list: Records<'_>) -> Result<Vec<(u16, &str)>, u32> {
    let mut out = Vec::new();
    for rec in list {
        let rec = rec.map_err(|_| dir::INVALID)?;
        if !matches!(rec.tag, dir::DM_ADD | dir::DM_REMOVE | dir::DM_REPLACE) {
            return Err(dir::INVALID);
        }
        let id = rec.text().map_err(|_| dir::INVALID)?;
        if !id_ok(id) {
            return Err(dir::INVALID);
        }
        if out.len() == dir::MAX_MEMBERS_PER_APPLY as usize {
            return Err(dir::TOO_MANY);
        }
        out.push((rec.tag, id));
    }
    Ok(out)
}

fn mint() -> Result<String, NeedErr> {
    busbar_contract::crypto::random::<16>()
        .map(hex::encode)
        .map_err(|_| NeedErr::Unavailable)
}

fn decoded(raw: &[u8]) -> Result<Record, NeedErr> {
    Record::decode(raw).ok_or(NeedErr::Unavailable)
}

async fn get(cx: &Cx<'_>, kind: u32, id: &str, out: &mut impl Sink) -> Result<(), NeedErr> {
    let Some(t) = kind_tag(kind).filter(|_| id_ok(id)) else {
        return domain(out, dir::INVALID);
    };
    let raw = cx
        .scope()
        .get(DIR, &record_key(t, id))
        .await
        .map_err(store::unavailable)?;
    let Some(raw) = raw else {
        return domain(out, dir::NOT_FOUND);
    };
    let rec = decoded(raw.expose(&crate::seal::lend()))?;
    record0(out, dir::ID, id.as_bytes())?;
    record0(out, dir::DOC, &rec.document)?;
    for (name, value) in &rec.indexes {
        out.pair0(name.as_bytes(), value)?;
    }
    answer(out, dir::OK, 0, rec.version, u32::from(rec.state), 0, 0)
}

async fn lookup(
    cx: &Cx<'_>,
    kind: u32,
    index: &str,
    value: &[u8],
    out: &mut impl Sink,
) -> Result<(), NeedErr> {
    let Some(t) = kind_tag(kind)
        .filter(|_| text_ok(index.as_bytes(), MAX_INDEX_NAME) && text_ok(value, MAX_INDEX_VALUE))
    else {
        return domain(out, dir::INVALID);
    };
    let owner = cx
        .scope()
        .get(DIR, &index_key(t, index, value))
        .await
        .map_err(store::unavailable)?;
    let Some(owner) = owner else {
        return domain(out, dir::NOT_FOUND);
    };
    let id = String::from_utf8(owner.expose(&crate::seal::lend()).clone())
        .map_err(|_| NeedErr::Unavailable)?;
    let raw = cx
        .scope()
        .get(DIR, &record_key(t, &id))
        .await
        .map_err(store::unavailable)?;
    let Some(raw) = raw else {
        return domain(out, dir::NOT_FOUND);
    };
    let rec = decoded(raw.expose(&crate::seal::lend()))?;
    out.put0(id.as_bytes())?;
    answer(out, dir::OK, 0, rec.version, u32::from(rec.state), 0, 0)
}

async fn scan(
    cx: &Cx<'_>,
    kind: u32,
    group: &str,
    after: &str,
    limit: u32,
    out: &mut impl Sink,
) -> Result<(), NeedErr> {
    let limit = if limit == 0 || limit > dir::MAX_SCAN {
        dir::MAX_SCAN
    } else {
        limit
    };
    let (prefix, docs) = match kind {
        dir::SUBJECT => (vec![T_SUBJECT], true),
        dir::GROUP => (vec![T_GROUP], true),
        dir::MEMBER if id_ok(group) => (members_prefix(group), false),
        _ => return domain(out, dir::INVALID),
    };
    if kind == dir::MEMBER
        && cx
            .scope()
            .get(DIR, &record_key(T_GROUP, group))
            .await
            .map_err(store::unavailable)?
            .is_none()
    {
        return domain(out, dir::NOT_FOUND);
    }
    let mut rows = 0u32;
    let mut more = 0u32;
    let mut cursor = None;
    'pages: loop {
        let page = match cx.scope().page(DIR, &prefix, cursor.as_ref()).await {
            Ok(page) => page,
            // The namespace moved under a continued scan: answer the rows so far, the plugin continues from
            // the last id it saw.
            Err(_) if rows > 0 => {
                more = 1;
                break;
            }
            Err(e) => return Err(store::unavailable(e)),
        };
        let seal = crate::seal::lend();
        for (key, raw) in &page.rows {
            let Some(rid) = key.get(prefix.len()..) else {
                return Err(NeedErr::Unavailable);
            };
            if !after.is_empty() && rid <= after.as_bytes() {
                continue;
            }
            if rows == limit {
                more = 1;
                break 'pages;
            }
            let written = if docs {
                let rec = decoded(raw.expose(&seal))?;
                out.pair0(rid, &rec.document)
            } else {
                out.pair0(rid, &[])
            };
            match written {
                Ok(()) => rows += 1,
                Err(NeedErr::Limit) => {
                    more = 1;
                    break 'pages;
                }
                Err(e) => return Err(e),
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => break,
        }
    }
    answer(out, dir::OK, 0, u64::from(rows), 0, more, 0)
}

async fn count(cx: &Cx<'_>, kind: u32, group: &str, out: &mut impl Sink) -> Result<(), NeedErr> {
    let keys: Vec<Vec<u8>> = match kind {
        dir::SUBJECT => vec![count_key(T_SUBJECT), active_key()],
        dir::GROUP => vec![count_key(T_GROUP)],
        dir::MEMBER if id_ok(group) => vec![member_count_key(group), record_key(T_GROUP, group)],
        _ => return domain(out, dir::INVALID),
    };
    let addrs: Vec<(&str, &[u8])> = keys.iter().map(|k| (DIR, k.as_slice())).collect();
    let values = cx.scope().read(&addrs).await.map_err(store::unavailable)?;
    let seal = crate::seal::lend();
    let num = |i: usize| -> u64 {
        values
            .get(i)
            .and_then(Option::as_ref)
            .and_then(|v| <[u8; 8]>::try_from(v.expose(&seal).as_slice()).ok())
            .map_or(0, u64::from_be_bytes)
    };
    if kind == dir::MEMBER && values.get(1).is_none_or(Option::is_none) {
        return domain(out, dir::NOT_FOUND);
    }
    let active = if kind == dir::SUBJECT { num(1) } else { 0 };
    answer(out, dir::OK, 0, num(0), 0, 0, active)
}

async fn write(cx: &Cx<'_>, n: DirNeed<'_>, out: &mut impl Sink) -> Result<(), NeedErr> {
    for _ in 0..MAX_ATTEMPTS {
        let mut tx = Tx::new(cx.scope());
        let epoch = tx.read_epoch().await?;
        let d = match n {
            DirNeed::Create {
                kind,
                state,
                pull,
                document,
                indexes,
            } => create(cx, &mut tx, kind, state, pull, document, indexes).await?,
            DirNeed::Apply {
                kind,
                id,
                expected_version,
                apply,
                state,
                document,
                indexes,
                members,
            } => {
                let a = ApplyNeed {
                    kind,
                    id,
                    expected_version,
                    apply,
                    state,
                    document,
                    indexes,
                    members,
                };
                apply_op(cx, &mut tx, a).await?
            }
            DirNeed::Delete {
                kind,
                id,
                expected_version,
            } => delete(cx, &mut tx, kind, id, expected_version).await?,
            _ => return Err(NeedErr::Invalid),
        };
        if d.code != dir::OK || !tx.writes_anything() {
            return emit(out, d);
        }
        tx.advance_epoch(epoch)?;
        match tx.commit(cx.store).await? {
            Committed::Applied => {
                if let (Some((principal, held)), Some(set)) = (&d.hold, &cx.inst.held) {
                    if let Ok(principal) = core::str::from_utf8(principal) {
                        set.local(principal, *held);
                    }
                }
                return emit(out, d);
            }
            Committed::Conflict => continue,
            Committed::TooLarge => return domain(out, dir::TOO_MANY),
        }
    }
    cx.events.event(DirEvent::Contended {
        instance: &cx.inst.name,
    });
    Err(NeedErr::Unavailable)
}

fn emit(out: &mut impl Sink, d: Decision) -> Result<(), NeedErr> {
    if d.code == dir::OK {
        if let Some(id) = &d.id {
            out.put0(id.as_bytes())?;
        }
    }
    answer(out, d.code, d.index, d.b, d.state, 0, 0)
}

/// The guard (IF §12.29): `moves` linked principals leave ACTIVE in this write. `W` must be in the read.
fn guard(cx: &Cx<'_>, tx: &mut Tx<'_>, moves: u32) -> Option<Decision> {
    if moves == 0 {
        return None;
    }
    let g = cx.inst.cfg.guard;
    let mut row = tx
        .get(DIR, &guard_key())
        .and_then(|raw| GuardRow::decode(&raw))
        .unwrap_or_default();
    if cx.now < row.released_until_s {
        return None;
    }
    if cx.now >= row.window_start_s.saturating_add(g.window_s) {
        row.window_start_s = cx.now;
        row.moved = 0;
    }
    if u64::from(row.moved) + u64::from(moves) > u64::from(g.max) {
        cx.events.event(DirEvent::Guard {
            instance: &cx.inst.name,
            would_move: moves,
        });
        let window = row.window_start_s.saturating_add(1);
        if cx.inst.tripped.swap(window, Ordering::Relaxed) != window {
            cx.events.event(DirEvent::GuardTripped {
                instance: &cx.inst.name,
            });
        }
        return Some(Decision::domain(dir::GUARD));
    }
    row.moved += moves;
    tx.put(DIR, guard_key(), Secret::new(row.encode()));
    None
}

/// MAX_HELD: a write that would hold one more than the cap answers TOO_MANY.
fn held_full(cx: &Cx<'_>) -> Option<Decision> {
    let full = cx.inst.held.as_ref().is_some_and(|s| s.len() >= MAX_HELD);
    if full {
        cx.events.event(DirEvent::HeldFull {
            instance: &cx.inst.name,
        });
        return Some(Decision::domain(dir::TOO_MANY));
    }
    None
}

async fn create(
    cx: &Cx<'_>,
    tx: &mut Tx<'_>,
    kind: u32,
    state: u32,
    pull: bool,
    document: &[u8],
    list: Records<'_>,
) -> Result<Decision, NeedErr> {
    let Some(t) = kind_tag(kind) else {
        return Ok(Decision::domain(dir::INVALID));
    };
    let state = match (t, state) {
        (T_GROUP, 0) => 0,
        (T_SUBJECT, 0 | dir::STATE_ACTIVE) => dir::STATE_ACTIVE,
        (T_SUBJECT, dir::STATE_INACTIVE) => dir::STATE_INACTIVE,
        _ => return Ok(Decision::domain(dir::INVALID)),
    };
    if document.len() > dir::MAX_DOCUMENT as usize {
        return Ok(Decision::domain(dir::INVALID));
    }
    let idx = match indexes(list) {
        Ok(idx) => idx,
        Err(code) => return Ok(Decision::domain(code)),
    };
    let id = mint()?;
    let rec = Record {
        version: 1,
        state: state as u8,
        source: if pull { 2 } else { 1 },
        indexes: idx,
        document: document.to_vec(),
    };
    let linked = cx.linked(t, &rec);
    let held = state == dir::STATE_INACTIVE && linked.is_some();
    let mut keys = vec![(DIR, record_key(t, &id)), (DIR, count_key(t))];
    keys.extend(rec.indexes.iter().map(|(n, v)| (DIR, index_key(t, n, v))));
    if state == dir::STATE_ACTIVE {
        keys.push((DIR, active_key()));
    }
    if held {
        keys.push((DIR, guard_key()));
    }
    tx.read(keys).await?;
    if tx.get(DIR, &record_key(t, &id)).is_some() {
        // A minted id collided: never overwrite a record.
        return Err(NeedErr::Unavailable);
    }
    for (i, (n, v)) in rec.indexes.iter().enumerate() {
        if tx.get(DIR, &index_key(t, n, v)).is_some() {
            return Ok(Decision::conflict(i));
        }
    }
    if let Some(d) = guard(cx, tx, u32::from(held)) {
        return Ok(d);
    }
    let mut hold = None;
    if let (true, Some(principal)) = (held, linked) {
        if let Some(d) = held_full(cx) {
            return Ok(d);
        }
        tx.put(HELD, principal.clone(), Secret::new(id.as_bytes().to_vec()));
        hold = Some((principal, true));
    }
    for (n, v) in &rec.indexes {
        tx.put(DIR, index_key(t, n, v), Secret::new(id.as_bytes().to_vec()));
    }
    tx.add(count_key(t), 1);
    if state == dir::STATE_ACTIVE {
        tx.add(active_key(), 1);
    }
    tx.put(DIR, record_key(t, &id), rec.encode());
    Ok(Decision {
        code: dir::OK,
        index: 0,
        b: 1,
        state: if t == T_SUBJECT { state } else { 0 },
        id: Some(id),
        hold,
    })
}

struct ApplyNeed<'a> {
    kind: u32,
    id: &'a str,
    expected_version: u64,
    apply: u32,
    state: u32,
    document: &'a [u8],
    indexes: Records<'a>,
    members: Records<'a>,
}

const APPLY_ALL: u32 =
    dir::APPLY_DOCUMENT | dir::APPLY_INDEXES | dir::APPLY_STATE | dir::APPLY_REPLACE_MEMBERS;

async fn apply_op(cx: &Cx<'_>, tx: &mut Tx<'_>, a: ApplyNeed<'_>) -> Result<Decision, NeedErr> {
    let invalid = Ok(Decision::domain(dir::INVALID));
    let Some(t) = kind_tag(a.kind).filter(|_| id_ok(a.id)) else {
        return invalid;
    };
    let ops = match members(a.members) {
        Ok(ops) => ops,
        Err(code) => return Ok(Decision::domain(code)),
    };
    let replace = a.apply & dir::APPLY_REPLACE_MEMBERS != 0;
    if a.apply & !APPLY_ALL != 0
        || (t == T_SUBJECT && (replace || !ops.is_empty()))
        || (t == T_GROUP && a.apply & dir::APPLY_STATE != 0)
        || ops
            .iter()
            .any(|(tag, _)| (*tag == dir::DM_REPLACE) != replace)
    {
        return invalid;
    }
    let key = record_key(t, a.id);
    tx.read(vec![(DIR, key.clone())]).await?;
    let Some(raw) = tx.get(DIR, &key) else {
        return Ok(Decision::domain(dir::NOT_FOUND));
    };
    let old = decoded(&raw)?;
    if a.expected_version != 0 && a.expected_version != old.version {
        return Ok(Decision::domain(dir::PRECONDITION));
    }
    let mut new = old.clone();
    new.version = old.version.saturating_add(1);
    if a.apply & dir::APPLY_DOCUMENT != 0 {
        if a.document.len() > dir::MAX_DOCUMENT as usize {
            return invalid;
        }
        new.document = a.document.to_vec();
    }
    if a.apply & dir::APPLY_INDEXES != 0 {
        new.indexes = match indexes(a.indexes) {
            Ok(idx) => idx,
            Err(code) => return Ok(Decision::domain(code)),
        };
    }
    if a.apply & dir::APPLY_STATE != 0 {
        new.state = match a.state {
            dir::STATE_ACTIVE | dir::STATE_INACTIVE => a.state as u8,
            _ => return invalid,
        };
    }
    let linked = cx.linked(t, &old);
    if linked != cx.linked(t, &new) {
        // The link value of a subject never changes (dev's contract).
        return invalid;
    }
    let was = u32::from(old.state) == dir::STATE_ACTIVE;
    let is = u32::from(new.state) == dir::STATE_ACTIVE;
    let deactivates = t == T_SUBJECT && was && !is && linked.is_some();
    // Group membership: what to read.
    let existing = if replace {
        members_of(cx, a.id).await?
    } else {
        Vec::new()
    };
    let mut keys: Vec<(&'static str, Vec<u8>)> = new
        .indexes
        .iter()
        .map(|(n, v)| (DIR, index_key(t, n, v)))
        .collect();
    if t == T_SUBJECT && was != is {
        keys.push((DIR, active_key()));
    }
    if deactivates {
        keys.push((DIR, guard_key()));
    }
    if t == T_GROUP && (replace || !ops.is_empty()) {
        keys.push((DIR, member_count_key(a.id)));
        for (tag, mid) in &ops {
            keys.push((DIR, member_key(a.id, mid)));
            if *tag != dir::DM_REMOVE {
                keys.push((DIR, record_key(T_SUBJECT, mid)));
            }
        }
        keys.extend(existing.iter().map(|mid| (DIR, member_key(a.id, mid))));
    }
    tx.read(keys).await?;
    for (i, (n, v)) in new.indexes.iter().enumerate() {
        match tx.get(DIR, &index_key(t, n, v)) {
            Some(owner) if owner == a.id.as_bytes() => {}
            Some(_) => return Ok(Decision::conflict(i)),
            None => tx.put(
                DIR,
                index_key(t, n, v),
                Secret::new(a.id.as_bytes().to_vec()),
            ),
        }
    }
    for (n, v) in &old.indexes {
        if new.index(n) != Some(v.as_slice()) {
            tx.del(DIR, index_key(t, n, v));
        }
    }
    if let Some(d) = guard(cx, tx, u32::from(deactivates)) {
        return Ok(d);
    }
    let mut hold = None;
    if t == T_SUBJECT && was != is {
        tx.add(active_key(), if is { 1 } else { -1 });
        if let Some(principal) = linked {
            if is {
                tx.del(HELD, principal.clone());
                hold = Some((principal, false));
            } else {
                if let Some(d) = held_full(cx) {
                    return Ok(d);
                }
                tx.put(
                    HELD,
                    principal.clone(),
                    Secret::new(a.id.as_bytes().to_vec()),
                );
                hold = Some((principal, true));
            }
        }
    }
    if t == T_GROUP && (replace || !ops.is_empty()) {
        let mut delta = 0i64;
        let mut wanted: Vec<&str> = Vec::new();
        for (tag, mid) in &ops {
            let at = member_key(a.id, mid);
            let present = tx.get(DIR, &at).is_some();
            if *tag == dir::DM_REMOVE {
                if present {
                    tx.del(DIR, at);
                    delta -= 1;
                }
                continue;
            }
            if tx.get(DIR, &record_key(T_SUBJECT, mid)).is_none() {
                // Every member must be an existing subject.
                return invalid;
            }
            wanted.push(mid);
            if !present {
                tx.put(DIR, at, Secret::new(Vec::new()));
                delta += 1;
            }
        }
        for mid in existing.iter().filter(|m| !wanted.contains(&m.as_str())) {
            tx.del(DIR, member_key(a.id, mid));
            delta -= 1;
        }
        tx.add(member_count_key(a.id), delta);
    }
    tx.put(DIR, key, new.encode());
    Ok(Decision {
        code: dir::OK,
        index: 0,
        b: new.version,
        state: u32::from(new.state),
        id: None,
        hold,
    })
}

/// Every member id of group `gid` (paged).
async fn members_of(cx: &Cx<'_>, gid: &str) -> Result<Vec<String>, NeedErr> {
    let prefix = members_prefix(gid);
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let page = cx
            .scope()
            .page(DIR, &prefix, cursor.as_ref())
            .await
            .map_err(store::unavailable)?;
        for (key, _) in &page.rows {
            let mid = key
                .get(prefix.len()..)
                .and_then(|m| core::str::from_utf8(m).ok())
                .ok_or(NeedErr::Unavailable)?;
            out.push(mid.to_string());
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => return Ok(out),
        }
    }
}

/// Every (gid) whose membership names subject `id` (a scan of every `M` key: the layout keeps no reverse index).
async fn groups_of(cx: &Cx<'_>, id: &str) -> Result<Vec<String>, NeedErr> {
    let mut out = Vec::new();
    let mut cursor = None;
    loop {
        let page = cx
            .scope()
            .page(DIR, &[T_MEMBER], cursor.as_ref())
            .await
            .map_err(store::unavailable)?;
        for (key, _) in &page.rows {
            let Some((&len, rest)) = key.get(1..).and_then(<[u8]>::split_first) else {
                return Err(NeedErr::Unavailable);
            };
            let Some((gid, mid)) = rest.split_at_checked(usize::from(len)) else {
                return Err(NeedErr::Unavailable);
            };
            if mid == id.as_bytes() {
                out.push(String::from_utf8(gid.to_vec()).map_err(|_| NeedErr::Unavailable)?);
            }
        }
        match page.next {
            Some(next) => cursor = Some(next),
            None => return Ok(out),
        }
    }
}

async fn delete(
    cx: &Cx<'_>,
    tx: &mut Tx<'_>,
    kind: u32,
    id: &str,
    expected_version: u64,
) -> Result<Decision, NeedErr> {
    let Some(t) = kind_tag(kind).filter(|_| id_ok(id)) else {
        return Ok(Decision::domain(dir::INVALID));
    };
    let key = record_key(t, id);
    tx.read(vec![(DIR, key.clone())]).await?;
    let Some(raw) = tx.get(DIR, &key) else {
        return Ok(Decision::domain(dir::NOT_FOUND));
    };
    let rec = decoded(&raw)?;
    if expected_version != 0 && expected_version != rec.version {
        return Ok(Decision::domain(dir::PRECONDITION));
    }
    let active = t == T_SUBJECT && u32::from(rec.state) == dir::STATE_ACTIVE;
    let linked = cx.linked(t, &rec);
    let groups = if t == T_SUBJECT {
        groups_of(cx, id).await?
    } else {
        Vec::new()
    };
    let mut keys = vec![(DIR, count_key(t))];
    if active {
        keys.push((DIR, active_key()));
        if linked.is_some() {
            keys.push((DIR, guard_key()));
        }
    }
    for gid in &groups {
        keys.push((DIR, member_key(gid, id)));
        keys.push((DIR, member_count_key(gid)));
    }
    tx.read(keys).await?;
    // Deleting an ACTIVE linked subject moves its principal (a mass delete is caught too).
    if let Some(d) = guard(cx, tx, u32::from(active && linked.is_some())) {
        return Ok(d);
    }
    let mut hold = None;
    if let (false, true, Some(principal)) = (active, t == T_SUBJECT, linked) {
        // DELETE releases the hold (§16.188).
        tx.del(HELD, principal.clone());
        hold = Some((principal, false));
    }
    for (n, v) in &rec.indexes {
        tx.del(DIR, index_key(t, n, v));
    }
    tx.add(count_key(t), -1);
    if active {
        tx.add(active_key(), -1);
    }
    for gid in &groups {
        if tx.get(DIR, &member_key(gid, id)).is_some() {
            tx.del(DIR, member_key(gid, id));
            tx.add(member_count_key(gid), -1);
        }
    }
    if t == T_GROUP {
        tx.del_range(members_prefix(id), 2 + id.len() + ID_LEN);
        tx.del(DIR, member_count_key(id));
    }
    tx.del(DIR, key);
    Ok(Decision {
        code: dir::OK,
        index: 0,
        b: 0,
        state: 0,
        id: None,
        hold,
    })
}

/// The guard as the admin API shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuardView {
    pub max: u32,
    pub window_s: u64,
    pub window_start_s: u64,
    pub moved: u32,
    pub released_until_s: u64,
}

fn view(inst: &Instance, row: GuardRow) -> GuardView {
    GuardView {
        max: inst.cfg.guard.max,
        window_s: inst.cfg.guard.window_s,
        window_start_s: row.window_start_s,
        moved: row.moved,
        released_until_s: row.released_until_s,
    }
}

pub(super) async fn guard_view(cx: &Cx<'_>) -> Result<GuardView, NeedErr> {
    let raw = cx
        .scope()
        .get(DIR, &guard_key())
        .await
        .map_err(store::unavailable)?;
    let row = match raw {
        Some(raw) => {
            GuardRow::decode(raw.expose(&crate::seal::lend())).ok_or(NeedErr::Unavailable)?
        }
        None => GuardRow::default(),
    };
    Ok(view(cx.inst, row))
}

/// Release the guard for `for_s` seconds (60..=86,400): `moved` = 0, `released_until_s` = now + for_s.
pub(super) async fn release(cx: &Cx<'_>, for_s: u64, admin: &str) -> Result<GuardView, NeedErr> {
    if !(60..=86_400).contains(&for_s) {
        return Err(NeedErr::Invalid);
    }
    for _ in 0..MAX_ATTEMPTS {
        let mut tx = Tx::new(cx.scope());
        tx.read(vec![(DIR, guard_key())]).await?;
        let mut row = tx
            .get(DIR, &guard_key())
            .and_then(|raw| GuardRow::decode(&raw))
            .unwrap_or_default();
        row.moved = 0;
        row.released_until_s = cx.now.saturating_add(for_s);
        tx.put(DIR, guard_key(), Secret::new(row.encode()));
        if tx.commit(cx.store).await? == Committed::Applied {
            cx.events.event(DirEvent::GuardReleased {
                instance: &cx.inst.name,
                admin,
                for_s,
            });
            return Ok(view(cx.inst, row));
        }
    }
    cx.events.event(DirEvent::Contended {
        instance: &cx.inst.name,
    });
    Err(NeedErr::Unavailable)
}
