// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KERNEL'S OWN CLAIMS (`BUSBAR-1.6.0.md` THE DESIGN, host services): a claim on `(op, key)`
//! an instance holds for a time, won by exactly one claimant, handed over with a higher epoch.
//!
//! * **Scope.** Every claim lives under a label the kernel derives from the calling instance's own
//!   label ([`reserved_label`]), never from a string the caller supplies: an instance only ever
//!   contends with itself.
//! * **Winning** epoch `e + 1` is exactly one put-if-absent of the token [`win_token`] through the
//!   store's single-use redemption; whoever the store took is the winner, and the holder record
//!   `(epoch, until, extends, ttl)` is written only after that redemption won.
//! * **Extending.** The holder names the epoch it won; it extends only while
//!   `now < until - guard`, through a put-if-absent of a per-extend token `(epoch, extends + 1)`,
//!   and only while the record still names its epoch. A claimant attempts `e + 1` only once
//!   `now >= until + guard`. Between those two points both are Taken, so a late extend and an early
//!   claimant never both hold. The times are the kernel's clock: correct while node clocks agree
//!   within the guard band.
//! * **Fail closed.** A store that does not answer, a record that does not decode, or an answer
//!   that arrives after the caller's deadline is Taken, never a Won.

use busbar_contract::ids::RecordSchemaId;
use busbar_contract::kinds::RecordBytes;
use busbar_contract::records::RecordStore;

use crate::host_records::{record_key, RecordRows};

/// What a claim answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// The caller holds `epoch` until `until_ns`.
    Won {
        /// The claim's epoch: one more than the last holder's.
        epoch: u64,
        /// When it lapses, in nanoseconds on the kernel's clock.
        until_ns: u64,
    },
    /// Another claimant holds it, until `until_ns` as far as the kernel knows.
    Taken {
        /// When the current hold lapses; `0` when nothing more is known.
        until_ns: u64,
    },
}

/// A kernel-internal service answer: now, or later through the call's own callback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer<T> {
    /// Answered.
    Now(T),
    /// The answer comes through the callback.
    Later,
}

/// Where a pended claim's answer goes, once.
pub type ClaimLater = Box<dyn FnOnce(Claim) + Send>;

/// The record kind every claim holder record is kept under.
pub const CLAIM_SCHEMA: RecordSchemaId = RecordSchemaId::new("kernel-claim");

/// The least guard band, one second.
pub const GUARD_MIN_NS: u64 = 1_000_000_000;

/// The guard band of a claim that stands `ttl_ns`: a tenth of it, at least [`GUARD_MIN_NS`].
#[must_use]
pub fn guard_ns(ttl_ns: u64) -> u64 {
    (ttl_ns / 10).max(GUARD_MIN_NS)
}

/// The label the claims of the instance labelled `instance` live under. It begins with a control
/// character, which no admitted label holds, so it never names an instance.
#[must_use]
pub fn reserved_label(instance: &str) -> String {
    format!("\u{1}claim\u{1}{instance}")
}

/// The token whose one redemption wins `epoch` of `(op, key)` under `label`.
#[must_use]
pub fn win_token(label: &str, op: &str, key: &[u8], epoch: u64) -> String {
    crate::host_services::claim_token(label, op, &[key, b"\0w", &epoch.to_be_bytes()].concat())
}

/// The token whose one redemption is extend `n` of `epoch`.
#[must_use]
pub fn extend_token(label: &str, op: &str, key: &[u8], epoch: u64, n: u64) -> String {
    let at = [key, b"\0x", &epoch.to_be_bytes(), &n.to_be_bytes()].concat();
    crate::host_services::claim_token(label, op, &at)
}

/// One holder record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Held {
    epoch: u64,
    until_ns: u64,
    extends: u64,
    ttl_ns: u64,
}

impl Held {
    fn bytes(self) -> Vec<u8> {
        [self.epoch, self.until_ns, self.extends, self.ttl_ns]
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect()
    }

    fn read(b: &[u8]) -> Option<Self> {
        let w = |i: usize| {
            Some(u64::from_be_bytes(
                b.get(i * 8..i * 8 + 8)?.try_into().ok()?,
            ))
        };
        (b.len() == 32).then_some(())?;
        Some(Self {
            epoch: w(0)?,
            until_ns: w(1)?,
            extends: w(2)?,
            ttl_ns: w(3)?,
        })
    }
}

/// One claim, as the pool job runs it.
pub struct Ask<'a> {
    /// The reserved label.
    pub label: &'a str,
    /// The operation.
    pub op: &'a str,
    /// The key.
    pub key: &'a [u8],
    /// How long a win or an extend stands.
    pub ttl_ns: u64,
    /// The epoch the caller holds, for an extend.
    pub held: Option<u64>,
    /// Now, on the kernel's clock.
    pub now_ns: u64,
}

fn secs_after(ns: u64) -> u64 {
    ns.div_ceil(1_000_000_000)
}

/// THE CLAIM RULE, run off the caller's thread: read the holder record, win or extend by one
/// redemption, and write the record only after the redemption won.
pub fn decide(rows: &dyn RecordRows, tokens: &dyn RecordStore, ask: &Ask<'_>) -> Claim {
    let taken = |until_ns| Claim::Taken { until_ns };
    let at = record_key(ask.label, &[ask.op.as_bytes(), b"\0", ask.key].concat());
    let read = |rows: &dyn RecordRows| match rows.record_get(CLAIM_SCHEMA, &at) {
        Ok(None) => Ok(None),
        Ok(Some(v)) => Held::read(v.as_slice()).map(Some).ok_or(()),
        Err(_) => Err(()),
    };
    let Ok(current) = read(rows) else {
        return taken(0);
    };
    let Some(until_ns) = ask.now_ns.checked_add(ask.ttl_ns) else {
        return taken(0);
    };
    let now_s = ask.now_ns / 1_000_000_000;
    let write = |h: Held| {
        RecordBytes::new(h.bytes())
            .ok()
            .and_then(|v| rows.record_put(CLAIM_SCHEMA, &at, &v).ok())
            .is_some()
    };
    match ask.held {
        Some(epoch) => {
            let Some(h) = current.filter(|h| h.epoch == epoch) else {
                return taken(current.map_or(0, |h| h.until_ns));
            };
            if ask.now_ns >= h.until_ns.saturating_sub(guard_ns(h.ttl_ns)) {
                return taken(h.until_ns);
            }
            let token = extend_token(ask.label, ask.op, ask.key, epoch, h.extends + 1);
            let expires = secs_after(until_ns.saturating_add(guard_ns(ask.ttl_ns)));
            if !matches!(
                tokens.redeem_plane_token(ask.label, &token, expires, now_s),
                Ok(true)
            ) {
                return taken(h.until_ns);
            }
            let next = Held {
                until_ns,
                extends: h.extends + 1,
                ttl_ns: ask.ttl_ns,
                ..h
            };
            if write(next) {
                Claim::Won { epoch, until_ns }
            } else {
                taken(h.until_ns)
            }
        }
        None => {
            if let Some(h) = current {
                if ask.now_ns < h.until_ns.saturating_add(guard_ns(h.ttl_ns)) {
                    return taken(h.until_ns);
                }
            }
            let epoch = current.map_or(0, |h| h.epoch) + 1;
            let token = win_token(ask.label, ask.op, ask.key, epoch);
            let expires = secs_after(until_ns.saturating_add(guard_ns(ask.ttl_ns)));
            if !matches!(
                tokens.redeem_plane_token(ask.label, &token, expires, now_s),
                Ok(true)
            ) {
                return taken(match read(rows) {
                    Ok(Some(h)) => h.until_ns,
                    _ => until_ns,
                });
            }
            let won = Held {
                epoch,
                until_ns,
                extends: 0,
                ttl_ns: ask.ttl_ns,
            };
            if write(won) {
                Claim::Won { epoch, until_ns }
            } else {
                taken(until_ns)
            }
        }
    }
}
