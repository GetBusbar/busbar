// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store's sweep: what the plane's clock task runs to retire lapsed records. It runs off the
//! request path (the plane's sweeper calls it once per tick), a sibling of the marked `shared`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use busbar_contract::host_records::conditional::{Decision, Expected, Predicate};
use busbar_kernel::persistence::scoped;
use oauth_as::store::StorageError;
use serde::de::DeserializeOwned;

use crate::shared::{
    atomic_schema, authority_body, bucket_holds, decode, digest, failed, kind, now_secs, secs_of,
    tombstone, Bucket, Cell, FamilyBar, IndexRow, Indexed, ReplayRow, SessionRow, Shared, StakeRow,
    SubjectIndex, Swap, INDEX_GRACE_SECS, LOST_REPLAY, LOST_ROW, RETIRE_AFTER_SECS, SUBJECT_INDEX,
    SWAP_ATTEMPTS,
};

impl Shared {
    async fn sweep_claims(&self) -> Result<(), StorageError> {
        for name in ["replay", "spent", "shown"] {
            self.store
                .register_claims(&kind(name))
                .map_err(|error| failed("register claim cleanup", error))?;
        }
        let mut failure = None;
        for _ in 0..3 {
            match self.store.sweep_claims().await {
                Ok(
                    None
                    | Some(
                        scoped::ClaimSweepOutcome::Complete
                        | scoped::ClaimSweepOutcome::Page { .. }
                        | scoped::ClaimSweepOutcome::Contended,
                    ),
                ) => {}
                Ok(Some(outcome)) => {
                    failure
                        .get_or_insert_with(|| failed("claim sweep remains unresolved", outcome));
                }
                Err(error) => {
                    failure.get_or_insert_with(|| failed("claim sweep", error));
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }

    pub(crate) async fn sweep_expired(&self, now: SystemTime) -> Result<u64, StorageError> {
        let s = self;
        if let Err(error) = s.sweep_claims().await {
            tracing::warn!(%error,"oauth_as: native claim cleanup remains owned for the next tick");
        }

        let mut removed = 0u64;
        let now_s = secs_of(now);
        let cells = s.list::<Cell<Bucket>>("bucket").await?;
        for mut cell in cells.into_iter().filter(|cell| !cell.b.id.is_empty()) {
            let acts = match sweep_bucket(&mut cell.b, cell.at, now) {
                Swap::Keep(_) => false,
                Swap::Write(_) => true,
                Swap::Retire(_, changed) => {
                    changed || now_s.saturating_sub(cell.at) > RETIRE_AFTER_SECS
                }
            };
            if !acts {
                continue;
            }

            let swept = s
                .update(&cell.b.id, |b, at| Ok(sweep_bucket(b, at, now)))
                .await;
            match swept {
                Ok(n) => removed += n,
                Err(e) => {
                    tracing::warn!(error = %e, "oauth_as: a client's records were not swept this tick; the next tick tries them again");
                    continue;
                }
            }
        }

        match s.sweep_family_barriers(now).await {
            Ok(n) => removed += n,
            Err(e) => {
                tracing::warn!(error = %e, "oauth_as: lapsed family barriers were not swept this tick")
            }
        }
        let replays = s.sweep_rows::<ReplayRow>("replay", now_s, LOST_REPLAY, |r| (r.until, &r.id));
        match replays.await {
            Ok(n) => removed += n,
            Err(e) => {
                tracing::warn!(error = %e, "oauth_as: lapsed replay rows were not swept this tick")
            }
        }
        let reclaimed = [
            s.sweep_user_codes().await,
            s.sweep_indexes().await,
            s.sweep_subjects().await,
            s.sweep_rows::<SessionRow>("session", now_s, LOST_ROW, |r| (r.until, &r.id))
                .await
                .map(drop),
            s.sweep_rows::<StakeRow>("stake", now_s, LOST_ROW, |r| (r.until, &r.id))
                .await
                .map(drop),
        ];
        for r in reclaimed {
            if let Err(e) = r {
                tracing::warn!(error = %e, "oauth_as: lapsed store rows were not reclaimed this tick");
            }
        }
        Ok(removed)
    }
}

fn sweep_bucket(b: &mut Bucket, at: u64, now: SystemTime) -> Swap<u64> {
    fn lapse<V>(map: &mut BTreeMap<String, V>, mut live: impl FnMut(&V) -> bool) -> u64 {
        let before = map.len();
        map.retain(|_, v| live(v));
        (before - map.len()) as u64
    }
    let mut n = lapse(&mut b.devices, |g| now < g.expires_at);
    n += lapse(&mut b.codes, |c| now < c.expires_at);
    n += lapse(&mut b.pushed, |p| now < p.expires_at);
    n += lapse(&mut b.tokens, |t| now < t.expires_at);
    n += lapse(&mut b.refresh, |r| r.expires_at.is_none_or(|exp| now < exp));
    if b.client_barrier.is_some_and(|t| now >= t.until) {
        b.client_barrier = None;
        n += 1;
    }
    n += lapse(&mut b.consent_barriers, |t| now < t.until);

    if b.client.as_ref().is_some_and(|c| c.registration.is_some())
        && b.idle()
        && secs_of(now).saturating_sub(at) > crate::policy::REGISTERED_CLIENT_IDLE.as_secs()
    {
        b.client = None;
        n += 1;
    }
    if b.holds_nothing() {
        Swap::Retire(n, n > 0)
    } else {
        Swap::when(n != 0, n)
    }
}

impl Shared {
    async fn sweep_family_barriers(&self, now: SystemTime) -> Result<u64, StorageError> {
        let mut removed = 0u64;
        for cell in self.list::<Cell<FamilyBar>>("family").await? {
            if cell.b.id.is_empty() || cell.b.times.is_some_and(|t| now < t.until) {
                continue;
            }

            let swept = self.cas_cell::<FamilyBar, u64>("family", &cell.b.id, |bar, _| {
                Ok(match bar.times {
                    Some(t) if now >= t.until => {
                        bar.times = None;
                        Swap::Retire(1, true)
                    }
                    Some(_) => Swap::Keep(0),
                    None => Swap::Retire(0, false),
                })
            });
            match swept.await {
                Ok(n) => removed += n,
                Err(e) => {
                    tracing::warn!(error = %e, "oauth_as: a lapsed family barrier was not swept this tick");
                }
            }
        }
        Ok(removed)
    }

    async fn sweep_user_codes(&self) -> Result<(), StorageError> {
        for cell in self.list::<Cell<Option<String>>>("uc").await? {
            if cell.id.is_empty() || cell.b.is_some() {
                continue;
            }
            let retired = self.cas_cell::<Option<String>, ()>("uc", &cell.id, |held, _| {
                Ok(if held.is_none() {
                    Swap::Retire((), false)
                } else {
                    Swap::Keep(())
                })
            });
            if let Err(e) = retired.await {
                tracing::warn!(error = %e, "oauth_as: a released user code was not retired this tick");
            }
        }
        Ok(())
    }

    async fn sweep_indexes(&self) -> Result<(), StorageError> {
        let mut buckets: BTreeMap<String, Option<Bucket>> = BTreeMap::new();
        let now_s = now_secs();
        for ix in ["tok", "rt", "code", "par", "dev", "cons", "fam"] {
            let name = format!("ix.{ix}");
            for row in self.list::<IndexRow>(&name).await? {
                if row.key.is_empty() || now_s.saturating_sub(row.at) <= INDEX_GRACE_SECS {
                    continue;
                }
                if !buckets.contains_key(&row.client) {
                    let bucket = self.bucket(&row.client).await.inspect_err(|e| {
                        tracing::warn!(error = %e, "oauth_as: a client's index rows were not swept this tick");
                    });
                    buckets.insert(row.client.clone(), bucket.ok());
                }
                let Some(b) = &buckets[&row.client] else {
                    continue;
                };
                let held = bucket_holds(b, ix, &row.key);
                if !held {
                    let retired = async {
                        let raw = self.authority(&name, &row.key).await?;
                        let Some(body) = raw.as_deref().map(authority_body).transpose()?.flatten()
                        else {
                            return Ok::<_, StorageError>(());
                        };
                        let current: IndexRow = decode(&name, body)?;

                        if current.at != row.at || current.client != row.client {
                            return Ok(());
                        }
                        let bucket_id = digest(&row.client);
                        let bucket = self.authority("bucket", &bucket_id).await?;

                        let current_bucket: Option<Cell<Bucket>> = bucket
                            .as_deref()
                            .map(authority_body)
                            .transpose()?
                            .flatten()
                            .map(|body| decode("bucket", body))
                            .transpose()?;
                        let held = current_bucket
                            .as_ref()
                            .is_some_and(|c| bucket_holds(&c.b, ix, &row.key));
                        if held {
                            return Ok(());
                        }
                        let mut request =
                            Self::candidate(&atomic_schema(&name), &row.key, raw, tombstone()?);
                        Arc::make_mut(&mut request).predicates.push(Predicate {
                            schema: atomic_schema("bucket"),
                            key: bucket_id.into_bytes(),
                            expected: bucket.map_or(Expected::Absent, Expected::Bytes),
                        });
                        self.submit(request).await.map(drop)
                    }
                    .await;
                    if let Err(e) = retired {
                        tracing::warn!(error = %e, "oauth_as: an index row was not reclaimed this tick");
                    }
                }
            }
        }
        Ok(())
    }

    async fn sweep_subjects(&self) -> Result<(), StorageError> {
        self.sweep_subjects_at(now_secs()).await
    }

    async fn sweep_subjects_at(&self, now_s: u64) -> Result<(), StorageError> {
        let mut buckets: BTreeMap<String, Option<Bucket>> = BTreeMap::new();
        for cell in self.list::<Cell<SubjectIndex>>(SUBJECT_INDEX).await? {
            if cell.id.is_empty() {
                continue;
            }
            let mut gone: BTreeMap<String, Indexed> = BTreeMap::new();
            for (client, indexed) in &cell.b.clients {
                if now_s.saturating_sub(indexed.at) <= INDEX_GRACE_SECS {
                    continue;
                }
                if !buckets.contains_key(client) {
                    let bucket = self.bucket(client).await.inspect_err(|e| {
                        tracing::warn!(error = %e, "oauth_as: a client's subject index entries were not swept this tick");
                    });
                    buckets.insert(client.clone(), bucket.ok());
                }
                let held = buckets[client]
                    .as_ref()
                    .is_none_or(|b| b.consents.values().any(|c| digest(&c.subject) == cell.id));
                if !held {
                    gone.insert(client.clone(), *indexed);
                }
            }
            if gone.is_empty() && !cell.b.clients.is_empty() {
                continue;
            }
            let swept = self.sweep_subject(&cell.id, &gone);
            if let Err(e) = swept.await {
                tracing::warn!(error = %e, "oauth_as: a subject's index was not swept this tick");
            }
        }
        Ok(())
    }

    async fn sweep_subject(
        &self,
        id: &str,
        gone: &BTreeMap<String, Indexed>,
    ) -> Result<(), StorageError> {
        let now = now_secs();
        for attempt in 0..SWAP_ATTEMPTS {
            let raw = self.authority(SUBJECT_INDEX, id).await?;
            let cell: Option<Cell<SubjectIndex>> = raw
                .as_deref()
                .map(authority_body)
                .transpose()?
                .flatten()
                .map(|body| decode(SUBJECT_INDEX, body))
                .transpose()?;
            let Some(mut cell) = cell else {
                return Ok(());
            };
            let mut guards = Vec::new();
            let mut changed = false;
            for (client, indexed) in gone {
                if cell.b.clients.get(client) != Some(indexed) {
                    continue;
                }
                let bucket_id = digest(client);
                let snapshot = match self.authority("bucket", &bucket_id).await {
                    Ok(raw) => raw,
                    Err(e) => {
                        tracing::warn!(error = %e, "oauth_as: a client's subject entry could not be rejudged");
                        continue;
                    }
                };
                let bucket: Option<Cell<Bucket>> = match snapshot
                    .as_deref()
                    .map(authority_body)
                    .transpose()?
                    .flatten()
                    .map(|body| decode("bucket", body))
                    .transpose()
                {
                    Ok(bucket) => bucket,
                    Err(e) => {
                        tracing::warn!(error = %e, "oauth_as: a client's subject entry could not be rejudged");
                        continue;
                    }
                };
                if bucket.is_some_and(|b| b.b.consents.values().any(|c| digest(&c.subject) == id)) {
                    continue;
                }
                cell.b.clients.remove(client);
                changed = true;
                guards.push(Predicate {
                    schema: atomic_schema("bucket"),
                    key: bucket_id.into_bytes(),
                    expected: snapshot.map_or(Expected::Absent, Expected::Bytes),
                });
            }
            let retired =
                cell.b.clients.is_empty() && now.saturating_sub(cell.at) > RETIRE_AFTER_SECS;
            if !changed && !retired {
                return Ok(());
            }
            let value = if retired {
                tombstone()?
            } else {
                cell.v = cell.v.checked_add(1).ok_or_else(|| {
                    StorageError::new("oauth_as store: subject index version exhausted")
                })?;
                cell.at = now;
                cell.id.clear();
                cell.id.push_str(id);
                encode(SUBJECT_INDEX, &cell)?
            };
            let mut request = Self::candidate(&atomic_schema(SUBJECT_INDEX), id, raw, value);
            Arc::make_mut(&mut request).predicates.extend(guards);
            match self.submit(request).await? {
                Decision::Applied => return Ok(()),
                Decision::ConditionConflict => {
                    tokio::time::sleep(Duration::from_millis(u64::from(attempt.min(20)))).await
                }
            }
        }
        Err(StorageError::new(
            "oauth_as store: subject sweep repeatedly conflicted",
        ))
    }

    async fn sweep_rows<R: DeserializeOwned>(
        &self,
        kind_name: &str,
        now_s: u64,
        lost: &str,
        of: impl Fn(&R) -> (u64, &String),
    ) -> Result<u64, StorageError> {
        let mut removed = 0u64;
        for row in self.list::<R>(kind_name).await? {
            let (until, id) = of(&row);
            if until > now_s || id.is_empty() {
                continue;
            }
            match self.delete(kind_name, id).await {
                Ok(()) => removed += 1,
                Err(e) => tracing::warn!(error = %e, "{lost}"),
            }
        }
        Ok(removed)
    }
}
