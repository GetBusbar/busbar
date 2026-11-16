// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! One R0 row in, one native record out (§A4 tables, §A6 conversion): pure, so the read-only pass
//! and the page conversion read every row the same way. Counts arrive in 1.5.5 whole units. Token
//! counts leave in scale 6 through [`scale6`] (the native usage units); request counts stay whole,
//! as the native ledger keeps them. Every sum is `checked_add`. Overflow is BOUNDS, never a wrap
//! or a saturate.

use busbar_contract::abi::sdk::store::cells::{self, table, Cell, HEADLESS};
use busbar_contract::records::{
    CredentialMeta, CredentialSecret, ScopeRef, SecretForm, VirtualKey,
};
use busbar_contract::secure::SecureString;

use super::{AuditRow, Metering, Native, Refusal, Seal, SelfId, Units, UsageCell};

/// The largest 1.5.5 whole-unit counter 1.6.0 stores: `u64::MAX / 10^6`.
pub const MAX_WHOLE_UNITS: u64 = u64::MAX / 1_000_000;

/// The 1.5.5 recoverable envelope.
const PLAIN: &str = "v1:plain:";

/// A 1.5.5 whole-unit counter in scale 6, or `None` when it is negative or does not fit.
#[must_use]
pub fn scale6(v: i64) -> Option<u64> {
    u64::try_from(v).ok()?.checked_mul(1_000_000)
}

/// One converted row.
pub(super) struct Row {
    pub(super) native: Native,
    /// `fold(row)`: what the row counts toward `source_rows` (a usage cell: its head, if read,
    /// plus its model entries; every other row: 1).
    pub(super) fold: u64,
    /// A recoverable credential stored in the clear.
    pub(super) plain: bool,
    /// A self-serve-looking key that could not be verified.
    pub(super) self_unverified: bool,
}

/// The cells of one row, read by column.
struct Cols<'a> {
    tag: u8,
    cells: Vec<Cell<'a>>,
}

impl<'a> Cols<'a> {
    fn unknown(&self, what: &str) -> Refusal {
        Refusal::Unknown(format!(
            "an IMPORT row of R0 table {} is not what 1.5.5 reads: {what}",
            self.tag
        ))
    }

    fn get(&self, i: usize) -> Result<Cell<'a>, Refusal> {
        self.cells
            .get(i)
            .copied()
            .ok_or_else(|| self.unknown("a column is missing"))
    }

    fn text(&self, i: usize) -> Result<&'a str, Refusal> {
        match self.get(i)? {
            Cell::Text(t) => Ok(t),
            _ => Err(self.unknown("a text column holds another type")),
        }
    }

    fn opt_text(&self, i: usize) -> Result<Option<&'a str>, Refusal> {
        match self.get(i)? {
            Cell::Null => Ok(None),
            Cell::Text(t) => Ok(Some(t)),
            _ => Err(self.unknown("a text column holds another type")),
        }
    }

    fn int(&self, i: usize) -> Result<i64, Refusal> {
        match self.get(i)? {
            Cell::Int(v) => Ok(v),
            _ => Err(self.unknown("an integer column holds another type")),
        }
    }

    fn opt_int(&self, i: usize) -> Result<Option<i64>, Refusal> {
        match self.get(i)? {
            Cell::Null => Ok(None),
            Cell::Int(v) => Ok(Some(v)),
            _ => Err(self.unknown("an integer column holds another type")),
        }
    }

    /// A time or revision: 1.5.5 never stores a negative one.
    fn time(&self, i: usize) -> Result<u64, Refusal> {
        u64::try_from(self.int(i)?).map_err(|_| self.unknown("a time or revision is negative"))
    }

    fn opt_time(&self, i: usize) -> Result<Option<u64>, Refusal> {
        self.opt_int(i)?
            .map(|v| u64::try_from(v).map_err(|_| self.unknown("a time is negative")))
            .transpose()
    }

    /// A counter in scale 6; BOUNDS names the table, the row and the field.
    fn units(&self, i: usize, field: &str, at: &str) -> Result<u64, Refusal> {
        let v = self.int(i)?;
        scale6(v).ok_or_else(|| bounds(self.tag, field, v, at))
    }

    /// A request count: whole, as the native ledger keeps it (1.5.5 never stores a negative one).
    fn whole(&self, i: usize) -> Result<u64, Refusal> {
        u64::try_from(self.int(i)?).map_err(|_| self.unknown("a request count is negative"))
    }

    /// The six counters starting at column `i` (requests, billable, 4 token fields).
    fn six(&self, i: usize, at: &str) -> Result<Units, Refusal> {
        Ok(Units {
            requests: self.whole(i)?,
            billable_requests: self.whole(i + 1)?,
            tokens_input: self.units(i + 2, "tokens_input", at)?,
            tokens_output: self.units(i + 3, "tokens_output", at)?,
            tokens_cache_read: self.units(i + 4, "tokens_cache_read", at)?,
            tokens_cache_write: self.units(i + 5, "tokens_cache_write", at)?,
        })
    }
}

fn bounds(tag: u8, field: &str, v: i64, at: &str) -> Refusal {
    Refusal::Bounds(format!(
        "R0 table {tag}: 1.5.5 counter `{field}` = {v} at {at} exceeds what 1.6 stores (≤ \
         {MAX_WHOLE_UNITS} whole units); nothing native was written"
    ))
}

/// `a + b` for a total the native encoders form, or BOUNDS.
fn sum(tag: u8, field: &str, at: &str, a: u64, b: u64) -> Result<u64, Refusal> {
    a.checked_add(b).ok_or_else(|| {
        Refusal::Bounds(format!(
            "R0 table {tag}: the total of `{field}` at {at} exceeds what 1.6 stores; nothing \
             native was written"
        ))
    })
}

/// Convert one IMPORT row. `seal` is `None` in the read-only pass (credentials are counted, not
/// sealed); `self_id` is the self-serve key derivation, when a signing key is configured.
pub(super) fn row(
    key: &[u8],
    value: &[u8],
    seal: Option<Seal<'_>>,
    self_id: Option<SelfId<'_>>,
) -> Result<Row, Refusal> {
    let tag = cells::tag_of(key).unwrap_or(0);
    let cols = Cols {
        tag,
        cells: cells::decode(value).map_err(|_| {
            Refusal::Unknown(format!("an IMPORT row of R0 table {tag} is malformed"))
        })?,
    };
    let plain = |native| Row {
        native,
        fold: 1,
        plain: false,
        self_unverified: false,
    };
    match tag {
        table::KEY => {
            let (key, unverified) = key_row(&cols, self_id)?;
            Ok(Row {
                self_unverified: unverified,
                ..plain(Native::Key(key))
            })
        }
        table::CREDENTIAL => credential(&cols, seal),
        table::REVISION => Ok(plain(Native::Revision(cols.time(0)?))),
        table::DENY => Ok(plain(Native::Deny {
            sub: cols.text(0)?.to_owned(),
            reason: cols.text(1)?.to_owned(),
            created_at: cols.time(2)?,
        })),
        table::USAGE => usage(&cols),
        table::METERING => {
            let at = format!(
                "bucket {}, key {}, provider {}, model {}",
                cols.text(0)?,
                cols.text(1)?,
                cols.text(2)?,
                cols.text(3)?
            );
            Ok(plain(Native::Metering(Metering {
                bucket: cols.text(0)?.to_owned(),
                key_id: cols.text(1)?.to_owned(),
                provider: cols.text(2)?.to_owned(),
                model: cols.text(3)?.to_owned(),
                key_group_at_use: cols.text(4)?.to_owned(),
                pricing_version: cols.text(5)?.to_owned(),
                units: cols.six(6, &at)?,
            })))
        }
        table::AUDIT => Ok(plain(Native::Audit(AuditRow {
            seq: cols.int(0)?,
            ts: cols.int(1)?,
            action: cols.text(2)?.to_owned(),
            resource: cols.text(3)?.to_owned(),
            outcome: cols.text(4)?.to_owned(),
            principal: cols.text(5)?.to_owned(),
            prev_hash: cols.text(6)?.to_owned(),
            hash: cols.text(7)?.to_owned(),
        }))),
        _ => Err(cols.unknown("its table tag is unknown")),
    }
}

/// A KEY row (sqlite v1.0.6 `keys` order), carried as a 1.5.5 key; then [`super::self_keys`].
fn key_row(cols: &Cols<'_>, self_id: Option<SelfId<'_>>) -> Result<(VirtualKey, bool), Refusal> {
    let pools = cols
        .opt_text(3)?
        .map(|json| {
            busbar_contract::json::parse_str::<Vec<String>>(json)
                .map_err(|_| cols.unknown("allowed_pools is not a JSON array of names"))
        })
        .transpose()?;
    let labels = busbar_contract::json::parse_str(cols.text(4)?)
        .map_err(|_| cols.unknown("labels is not a JSON object of text"))?;
    let enabled = match cols.int(5)? {
        0 => false,
        1 => true,
        _ => return Err(cols.unknown("enabled is not 0 or 1")),
    };
    let mut key = VirtualKey {
        id: cols.text(0)?.to_owned(),
        name: cols.text(1)?.to_owned(),
        group: cols.opt_text(2)?.map(str::to_owned),
        allowed_scopes: pools.map(|names| names.into_iter().map(ScopeRef::pool).collect()),
        labels,
        enabled,
        generation_hash: cols.text(6)?.to_owned(),
        created_at: cols.time(7)?,
        expires_at: cols.opt_time(9)?,
        deleted_at: cols.opt_time(10)?,
        revision: cols.time(11)?,
        migrated_from: Some("1.5.5".to_owned()),
        ..VirtualKey::default()
    };
    // 1.5.5's `updated_at` (column 8) has no 1.6.0 field: it is read so a malformed row refuses.
    cols.time(8)?;
    let verdict = super::self_keys::convert(&mut key, self_id);
    Ok((key, verdict == super::self_keys::Verdict::Unverified))
}

/// A CREDENTIAL row (sqlite v1.0.6 `credentials` order). A recoverable secret is the 1.5.5
/// envelope `v1:plain:<secret>`; it is written sealed, never plain.
fn credential(cols: &Cols<'_>, seal: Option<Seal<'_>>) -> Result<Row, Refusal> {
    let form = match cols.text(6)? {
        "none" => SecretForm::None,
        "recoverable" => SecretForm::Recoverable,
        "digest" => SecretForm::Digest,
        _ => return Err(cols.unknown("secret_form is not none, recoverable or digest")),
    };
    let slot = u8::try_from(cols.int(3)?)
        .ok()
        .filter(|s| *s <= 1)
        .ok_or_else(|| cols.unknown("slot is not 0 or 1"))?;
    let meta = CredentialMeta {
        id: cols.text(0)?.to_owned(),
        key_id: cols.text(1)?.to_owned(),
        kind: cols.text(2)?.to_owned(),
        slot,
        public_id: cols.text(4)?.to_owned(),
        secret_form: form,
        created_at: cols.time(7)?,
        updated_at: cols.time(8)?,
        expires_at: cols.opt_time(9)?,
        revoked_at: cols.opt_time(10)?,
        revoke_reason: cols.opt_text(11)?.map(str::to_owned),
        revision: cols.time(12)?,
    };
    let stored = cols.opt_text(5)?;
    if (form == SecretForm::None) != stored.is_none() {
        return Err(cols.unknown("secret is NULL exactly when secret_form is not none"));
    }
    let plain_secret = match (form, stored) {
        (SecretForm::Recoverable, Some(s)) => Some(
            s.strip_prefix(PLAIN)
                .ok_or_else(|| cols.unknown("a recoverable secret is not a v1:plain: envelope"))?,
        ),
        _ => None,
    };
    let secret = match (plain_secret, seal) {
        (Some(s), Some(seal)) => seal(&meta, s.as_bytes()).map_err(|text| {
            Refusal::Config(format!(
                "the boot's at-rest key did not seal a 1.5.5 credential ({text}); nothing of this \
                 page was written"
            ))
        })?,
        // The read-only pass (no seal) only counts it; a stored digest needs no seal.
        _ => stored.unwrap_or_default().to_owned(),
    };
    Ok(Row {
        native: Native::Credential(CredentialSecret {
            meta,
            secret: SecureString::from(secret),
        }),
        fold: 1,
        plain: plain_secret.is_some(),
        self_unverified: false,
    })
}

/// A USAGE cell: flags, bucket, window_start, the head, then 7 cells per model.
fn usage(cols: &Cols<'_>) -> Result<Row, Refusal> {
    let tag = table::USAGE;
    let flags = cols.int(0)?;
    let headless = flags & HEADLESS != 0;
    if flags & !HEADLESS != 0 {
        return Err(cols.unknown("its flags carry an unknown bit"));
    }
    let bucket = cols.text(1)?;
    let window_start = cols.int(2)?;
    let at = format!("bucket {bucket}, window {window_start}");
    let head = Units {
        requests: cols.whole(3)?,
        billable_requests: cols.whole(4)?,
        ..Units::default()
    };
    let rest = cols.cells.len().saturating_sub(5);
    if !rest.is_multiple_of(7) {
        return Err(cols.unknown("a model entry is not 7 cells"));
    }
    let mut models = Vec::with_capacity(rest / 7);
    let mut total = Units::default();
    for m in 0..rest / 7 {
        let i = 5 + 7 * m;
        let model = cols.text(i)?;
        let at = format!("{at}, model {model}");
        let units = cols.six(i + 1, &at)?;
        for (field, into, add) in [
            ("tokens_input", &mut total.tokens_input, units.tokens_input),
            (
                "tokens_output",
                &mut total.tokens_output,
                units.tokens_output,
            ),
            (
                "tokens_cache_read",
                &mut total.tokens_cache_read,
                units.tokens_cache_read,
            ),
            (
                "tokens_cache_write",
                &mut total.tokens_cache_write,
                units.tokens_cache_write,
            ),
            ("requests", &mut total.requests, units.requests),
            (
                "billable_requests",
                &mut total.billable_requests,
                units.billable_requests,
            ),
        ] {
            *into = sum(tag, field, &at, *into, add)?;
        }
        models.push((model.to_owned(), units));
    }
    let fold = u64::from(!headless) + models.len() as u64;
    Ok(Row {
        native: Native::Usage(UsageCell {
            bucket: bucket.to_owned(),
            window_start,
            headless,
            head,
            models,
        }),
        fold,
        plain: false,
        self_unverified: false,
    })
}
