// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! UPGRADE ATTEMPTS (MIGRATE-ON-BOOT §A6 "Attempts", r17, r32). An unstamped boot that is about to
//! write config.yaml records `attempt/<digest>/<nonce>` under IMPORT (5S, [`begin`]): the plan
//! digest, a fresh nonce per session, when it expires, and the SHA-256 of the document it will
//! write. 5C ([`complete`]) consumes it with MIGRATION_COMPLETED once config.yaml is renamed into
//! place; a refusal consumes it with MIGRATION_REFUSED ([`refuse`]). Every session settles the
//! others ([`settle`]): an attempt this directory finished but did not complete (a crash between
//! 5d and 5C) completes now; one past its expiry is MIGRATION_ABANDONED; any other is left (another
//! node's upgrade in progress). So every attempt ends COMPLETED, REFUSED or ABANDONED, and no path
//! writes MIGRATION_COMPLETED for an attempt whose config.yaml was not renamed into place.

use busbar_contract::persistence::cells::{self, Cell, IMPORT_NS};
use busbar_contract::secure::SecureVec;

use super::{Audit, Candidate, Committed, RecordStore, Refusal, ATTEMPT_PREFIX, PAGE};

/// How long an attempt stays in progress before another session abandons it.
pub const EXPIRY_SECS: u64 = 600;

/// One attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attempt {
    /// The plan's digest (SHA-256 of the 1.5.5 config.yaml).
    pub digest: [u8; 32],
    /// The session's nonce.
    pub nonce: [u8; 16],
    /// Unix seconds after which it is abandoned.
    pub expires_at: u64,
    /// SHA-256 of the stamped document the session writes.
    pub written_sha256: [u8; 32],
}

/// How an attempt ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Settled {
    /// config.yaml was renamed into place: MIGRATION_COMPLETED.
    Completed {
        /// The plan digest.
        digest: [u8; 32],
        /// The session nonce.
        nonce: [u8; 16],
    },
    /// The session refused: MIGRATION_REFUSED with its text.
    Refused {
        /// The plan digest.
        digest: [u8; 32],
        /// The session nonce.
        nonce: [u8; 16],
        /// The refusal.
        text: String,
    },
    /// Planned, never seen stamped by its node within its expiry: MIGRATION_ABANDONED.
    Abandoned {
        /// The plan digest.
        digest: [u8; 32],
        /// The session nonce.
        nonce: [u8; 16],
    },
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

fn unhex<const N: usize>(text: &str) -> Option<[u8; N]> {
    let mut out = [0u8; N];
    if text.len() != 2 * N {
        return None;
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

impl Attempt {
    /// Its key under IMPORT: `attempt/<digest hex>/<nonce hex>`.
    #[must_use]
    pub fn key(&self) -> Vec<u8> {
        let mut key = ATTEMPT_PREFIX.to_vec();
        key.extend_from_slice(hex(&self.digest).as_bytes());
        key.push(b'/');
        key.extend_from_slice(hex(&self.nonce).as_bytes());
        key
    }

    fn value(&self) -> SecureVec {
        SecureVec::from(cells::value(&[
            Cell::Int(i64::try_from(self.expires_at).unwrap_or(i64::MAX)),
            Cell::Blob(&self.written_sha256),
        ]))
    }

    fn decode(key: &[u8], value: &[u8]) -> Option<Self> {
        let rest = std::str::from_utf8(key.strip_prefix(ATTEMPT_PREFIX)?).ok()?;
        let (digest, nonce) = rest.split_once('/')?;
        match cells::decode(value).ok()?.as_slice() {
            [Cell::Int(expires_at), Cell::Blob(written)] => Some(Self {
                digest: unhex(digest)?,
                nonce: unhex(nonce)?,
                expires_at: u64::try_from(*expires_at).ok()?,
                written_sha256: (*written).try_into().ok()?,
            }),
            _ => None,
        }
    }
}

/// 5S: record the attempt, with `absent` (a fresh nonce never overwrites another session's).
///
/// # Errors
/// VERIFY when the key exists; STORE for a store fault.
pub fn begin(store: &dyn RecordStore, attempt: &Attempt) -> Result<(), Refusal> {
    let mut c = Candidate::default();
    c.absent.push((IMPORT_NS, attempt.key()));
    c.put.push((IMPORT_NS, attempt.key(), attempt.value()));
    match store.commit(c)? {
        Committed::Applied => Ok(()),
        Committed::Conflict => Err(Refusal::Verify(
            "this upgrade attempt's key is already recorded; nothing was written".to_owned(),
        )),
        other => Err(other.unapplied("the upgrade attempt's record")),
    }
}

/// Consume `attempt` with `settled`'s audit record. `false` when another session settled it first.
fn consume(store: &dyn RecordStore, attempt: &Attempt, settled: Settled) -> Result<bool, Refusal> {
    let mut c = Candidate::default();
    c.exact.push((IMPORT_NS, attempt.key(), attempt.value()));
    c.delete.push((IMPORT_NS, attempt.key()));
    c.audit.push(Audit::Attempt(settled));
    match store.commit(c)? {
        Committed::Applied => Ok(true),
        Committed::Conflict => Ok(false),
        other => Err(other.unapplied("the upgrade attempt's settlement")),
    }
}

/// 5C: config.yaml is renamed into place; MIGRATION_COMPLETED, the attempt consumed.
///
/// # Errors
/// STORE for a store fault (the next session's [`settle`] completes it).
pub fn complete(store: &dyn RecordStore, attempt: &Attempt) -> Result<bool, Refusal> {
    let settled = Settled::Completed {
        digest: attempt.digest,
        nonce: attempt.nonce,
    };
    consume(store, attempt, settled)
}

/// A refusal after 5S: MIGRATION_REFUSED with `text`, the attempt consumed.
///
/// # Errors
/// STORE for a store fault (the attempt then expires and is abandoned).
pub fn refuse(store: &dyn RecordStore, attempt: &Attempt, text: &str) -> Result<bool, Refusal> {
    let settled = Settled::Refused {
        digest: attempt.digest,
        nonce: attempt.nonce,
        text: text.to_owned(),
    };
    consume(store, attempt, settled)
}

/// What this directory shows of its own upgrade.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Local {
    /// config.yaml carries the stamp.
    pub stamped: bool,
    /// The nonce in `<config>.busbar-attempt`, the attempt whose 5d ran here.
    pub nonce: Option<[u8; 16]>,
    /// SHA-256 of config.yaml now.
    pub config_sha256: [u8; 32],
}

/// Settle every recorded attempt: complete this directory's finished one, abandon the expired,
/// leave the rest. A lost predicate means a peer settled it first.
///
/// # Errors
/// STORE for a store fault; UNKNOWN for an attempt key that is not one.
pub fn settle(store: &dyn RecordStore, local: &Local, now: u64) -> Result<Vec<Settled>, Refusal> {
    let mut settled = Vec::new();
    let mut after = ATTEMPT_PREFIX.to_vec();
    after.pop();
    loop {
        let page = store.scan(IMPORT_NS, Some(&after), PAGE)?;
        for (key, value) in &page.rows {
            if !key.starts_with(ATTEMPT_PREFIX) {
                continue;
            }
            let attempt = Attempt::decode(key, value).ok_or_else(|| {
                Refusal::Unknown("an upgrade attempt record under IMPORT is malformed".to_owned())
            })?;
            let mine = local.stamped
                && local.nonce == Some(attempt.nonce)
                && local.config_sha256 == attempt.written_sha256;
            let outcome = if mine {
                Settled::Completed {
                    digest: attempt.digest,
                    nonce: attempt.nonce,
                }
            } else if now >= attempt.expires_at {
                Settled::Abandoned {
                    digest: attempt.digest,
                    nonce: attempt.nonce,
                }
            } else {
                continue;
            };
            if consume(store, &attempt, outcome.clone())? {
                settled.push(outcome);
            }
        }
        match super::continuation(&page)? {
            Some(next) => after = next,
            None => break,
        }
    }
    Ok(settled)
}
