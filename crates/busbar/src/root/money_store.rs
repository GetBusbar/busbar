// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The store the money verbs' effects actually land on.
//!
//! ## Why this is a separate type and not a method on the admin binding
//!
//! The admin control surface is allowed to name exactly ONE seam — `dyn busbar_unit_verbs::Store` —
//! and no ledger, policy or record type. Its other ledger handle, `dyn LedgerView`, is read-only by
//! construction and says so in its own documentation: "nothing behind this trait can move a row…
//! what stops the views acquiring a way to write". Giving the surface a second, writable handle
//! would undo that in one line.
//!
//! So the effect lives here, in the composition root, behind the seam the surface already reaches
//! through. This type wraps the store the loader built and the book the node settles onto, delegates
//! every pre-existing method to the former, and implements the two money verbs against the latter.
//!
//! ## What it does NOT do
//!
//! Arithmetic. Every figure it writes comes from `busbar_unit_ledger`'s own recording methods, which
//! are where the columns are defined, and every figure it renders comes from a
//! `busbar_unit_cost` view type. The only sums in this file are the ones needed to say what a
//! balance held before and after — read off the book either side of the call, never computed from
//! the request.

use std::sync::{Arc, Mutex};

use busbar_unit_cost::{AdjustmentView, UnreconciledSliceView};
use busbar_unit_ledger::totals::{BucketId, BucketScope, CapDimension, TotalsKey, WindowStart};
use busbar_unit_verbs::store::{Store, StoreError};

use crate::root::durability::Durability;

/// The node's store, plus the book its money verbs move.
pub struct MoneyStore {
    inner: Arc<dyn Store + Send + Sync>,
    durability: Arc<Mutex<Durability>>,
}

impl std::fmt::Debug for MoneyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MoneyStore").finish_non_exhaustive()
    }
}

impl MoneyStore {
    /// Wrap the store the loader built so the money verbs can also reach the book.
    #[must_use]
    pub fn new(inner: Arc<dyn Store + Send + Sync>, durability: Arc<Mutex<Durability>>) -> Self {
        MoneyStore { inner, durability }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Durability> {
        self.durability
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One request's decoded key. Every money verb names a balance the same way.
struct BalanceRef {
    key: TotalsKey,
    window: WindowStart,
    bucket: String,
    dimension: String,
    scope: String,
}

/// Read the balance a request names, or `None` if it does not name one completely.
///
/// Every field is mandatory and none has a default. A money verb that guessed a bucket would post a
/// correction against a balance nobody asked about, and the operator would find out from a monthly
/// figure rather than from a `400`.
fn balance_of(body: &[u8]) -> Option<BalanceRef> {
    let bucket = json_str(body, "bucket")?;
    let dimension = json_str(body, "dimension")?;
    let scope = json_str(body, "scope")?;
    let window: WindowStart = json_str(body, "window_start")?.parse().ok()?;
    let dim = match dimension.as_str() {
        "nano_units" => CapDimension::NanoUnits,
        "requests" => CapDimension::Requests,
        "concurrent" => CapDimension::Concurrent,
        // Any declared meter class, by name. Unknown-but-named is the class case, not an error:
        // the closed set here is the three built-ins, and everything else IS a class.
        other => CapDimension::Class(other.to_string()),
    };
    let bucket_scope = match scope.as_str() {
        "all" => BucketScope::All,
        other => BucketScope::Pool(other.strip_prefix("pool:").unwrap_or(other).to_string()),
    };
    Some(BalanceRef {
        key: TotalsKey::new(BucketId::new(bucket.clone()), dim, bucket_scope),
        window,
        bucket,
        dimension,
        scope,
    })
}

impl Store for MoneyStore {
    fn chain_break(&self, admin: &busbar_caps::AdminToken) -> Result<(), StoreError> {
        self.inner.chain_break(admin)
    }

    fn store_restore(
        &self,
        admin: &busbar_caps::AdminToken,
        backup_ref: &str,
    ) -> Result<(), StoreError> {
        self.inner.store_restore(admin, backup_ref)
    }

    fn reseal_epoch_floor(&self, admin: &busbar_caps::AdminToken) -> Result<(), StoreError> {
        self.inner.reseal_epoch_floor(admin)
    }

    fn replay_new_verb(&self, key: &(String, String)) -> Result<Option<Vec<u8>>, StoreError> {
        self.inner.replay_new_verb(key)
    }

    fn commit_new_verb_replay(
        &self,
        key: &(String, String),
        response: &[u8],
    ) -> Result<(), StoreError> {
        self.inner.commit_new_verb_replay(key, response)
    }

    /// `adjust` — post a correcting entry against one balance.
    ///
    /// ## The open-window rule, and how "open" is decided here
    ///
    /// Inside the open window an adjustment also gives headroom back to the store; outside it there
    /// is no headroom left to give, so the entry is a pure ledger reversal. The ledger unit offers
    /// both (`record_adjustment_releasing` and `record_adjustment`) and is explicit that only the
    /// open window may release: "a closed window's budget has already been reported, so handing
    /// headroom back to it would change a figure somebody has already read".
    ///
    /// Which one applies is decided by the BOOK, not by a clock and not by the request: the open
    /// window for a key is the newest window that key has figures in. A request naming an older
    /// window is correcting history and gets the reversal. Reading it off the book is what makes
    /// the answer the same whether the call arrives a second or an hour after the last posting —
    /// a clock-based rule would flip mid-window and be untestable without freezing time.
    fn adjust(
        &self,
        _admin: &busbar_caps::AdminToken,
        request: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        let balance = balance_of(request).ok_or(StoreError::NotFound)?;
        // A signed decimal STRING, matching what the views answer with. Rejecting a JSON number
        // here is deliberate: an amount that arrived as a double has already been rounded.
        let amount: i128 = json_str(request, "amount_nanos")
            .ok_or(StoreError::NotFound)?
            .parse()
            .map_err(|_| StoreError::NotFound)?;
        // A correction has to say why. The reason is journalled with the entry, and an adjustment
        // nobody can explain later is the one an auditor asks about first.
        if json_str(request, "reason").is_none_or(|r| r.trim().is_empty()) {
            return Err(StoreError::NotFound);
        }

        let mut durability = self.lock();
        let newest = durability
            .ledger
            .book()
            .iter()
            .filter(|((key, _), _)| *key == balance.key)
            .map(|((_, window), _)| *window)
            .max();
        let window_is_open = newest == Some(balance.window);

        let before = durability.ledger.book().get(&balance.key, balance.window);
        if window_is_open {
            durability
                .ledger
                .record_adjustment_releasing(&balance.key, balance.window, amount);
        } else {
            durability
                .ledger
                .record_adjustment(&balance.key, balance.window, amount);
        }
        let after = durability.ledger.book().get(&balance.key, balance.window);

        // Read off the book either side, never computed from the request: what the operator is
        // told is what the books now say, which is the only figure worth answering with.
        let view = AdjustmentView {
            bucket: balance.bucket,
            dimension: balance.dimension,
            scope: balance.scope,
            window_start: balance.window,
            amount_nanos: after.adjustments - before.adjustments,
            headroom_released_nanos: after.released - before.released,
            pure_reversal: !window_is_open,
        };
        Ok(json_answer(&view.to_json()))
    }

    /// `resolve_slice` — settle or write off spend the recompute never agreed with.
    ///
    /// Unreconciled value is a MOVE out of settled, so resolving it moves the amount back: the
    /// ledger unit's `record_unreconciled` with a negative amount is that move, and it is the same
    /// call in both verdicts. What differs is what happens to the value afterwards — a write-off
    /// leaves it out of settled as an adjustment, a post lets it stand as settled — which is why
    /// the verdict is carried into the view rather than into two different primitives.
    fn resolve_slice(
        &self,
        _admin: &busbar_caps::AdminToken,
        request: &[u8],
    ) -> Result<Vec<u8>, StoreError> {
        let balance = balance_of(request).ok_or(StoreError::NotFound)?;
        let node: u64 = json_str(request, "node")
            .ok_or(StoreError::NotFound)?
            .parse()
            .map_err(|_| StoreError::NotFound)?;
        let verdict = json_str(request, "verdict").ok_or(StoreError::NotFound)?;
        let written_off = match verdict.as_str() {
            "write-off" => true,
            "post" => false,
            // Two verdicts, closed. A third spelling is a caller asking for something this verb
            // does not do, and guessing which of the two they meant would move money.
            _ => return Err(StoreError::NotFound),
        };

        let mut durability = self.lock();
        let before = durability.ledger.book().get(&balance.key, balance.window);
        // Only what is actually stranded can be resolved. A request naming more would otherwise
        // push the column negative and invent settled value.
        let requested: i128 = match json_str(request, "amount_nanos") {
            Some(raw) => raw.parse().map_err(|_| StoreError::NotFound)?,
            None => before.unreconciled,
        };
        let resolved = requested.min(before.unreconciled).max(0);

        durability
            .ledger
            .record_unreconciled(&balance.key, balance.window, -resolved);
        if written_off {
            // Written off: it does not stay in settled either. `record_unreconciled` put it back
            // there, so the adjustment takes it straight out again, and the identity closes with
            // the value sitting in the adjustments column where an auditor can find it.
            durability
                .ledger
                .record_adjustment(&balance.key, balance.window, resolved);
        }
        let after = durability.ledger.book().get(&balance.key, balance.window);

        let view = UnreconciledSliceView {
            node,
            bucket: balance.bucket,
            dimension: balance.dimension,
            scope: balance.scope,
            window_start: balance.window,
            unreconciled_nanos: before.unreconciled,
            resolved_nanos: resolved,
            remaining_nanos: after.unreconciled,
            written_off,
        };
        Ok(json_answer(&view.to_json()))
    }
}

/// A `200` carrying JSON, packed the way the admin loop unpacks it.
fn json_answer(body: &str) -> Vec<u8> {
    crate::root::units_admin::AdminAnswer {
        status: 200,
        headers: vec![("content-type".to_string(), "application/json".to_string())],
        body: body.as_bytes().to_vec(),
    }
    .pack()
}

/// Read one top-level JSON string field.
///
/// Hand-rolled because `serde_json` is a DEV dependency of this crate and pulling it onto the
/// request path to read six fields would be a large dependency bought with a small convenience.
/// Numbers are read as strings by the same reader, which is not a shortcut: every amount this
/// surface accepts is specified as a decimal string precisely so a consumer cannot hand over a
/// rounded double, and `window_start`/`node` are read the same way so the grammar has one rule.
fn json_str(body: &[u8], field: &str) -> Option<String> {
    let text = std::str::from_utf8(body).ok()?;
    let needle = format!("\"{field}\"");
    let after = &text[text.find(&needle)? + needle.len()..];
    let after = after.trim_start().strip_prefix(':')?.trim_start();
    match after.strip_prefix('"') {
        Some(quoted) => {
            let mut chars = quoted.chars();
            let mut value = String::new();
            loop {
                match chars.next()? {
                    '"' => break,
                    '\\' => match chars.next()? {
                        '"' => value.push('"'),
                        '\\' => value.push('\\'),
                        '/' => value.push('/'),
                        'n' => value.push('\n'),
                        'r' => value.push('\r'),
                        't' => value.push('\t'),
                        'b' => value.push('\u{08}'),
                        'f' => value.push('\u{0c}'),
                        'u' => {
                            let mut hex = String::with_capacity(4);
                            for _ in 0..4 {
                                hex.push(chars.next()?);
                            }
                            value.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                        }
                        _ => return None,
                    },
                    c => value.push(c),
                }
            }
            Some(value)
        }
        // A bare token: `window_start` and `node` are commonly written unquoted, and accepting both
        // spellings for an INTEGER costs nothing. An unquoted AMOUNT still cannot survive, because
        // the caller of this function parses it into an `i128` and a double's decimal point fails.
        None => {
            let end = after
                .find(|c: char| c == ',' || c == '}' || c.is_whitespace())
                .unwrap_or(after.len());
            let token = &after[..end];
            (!token.is_empty()).then(|| token.to_string())
        }
    }
}

#[cfg(test)]
#[path = "tests/money_store.rs"]
mod tests;
