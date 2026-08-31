// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The neutral GOVERNANCE value families a plane crate names without reaching into `busbar-core`:
//! the busbar-signed token crypto (`signing`), the mint-parameter struct (`NewKeySpec`), and the
//! metering-bucket time base (`metering_bucket` + `METERING_BUCKET_SECS`). Pure data and pure
//! arithmetic — no `App`, no `Store`, no engine reach. Core re-exports each from its old
//! `busbar_core::governance::…` path so its own call sites are unchanged.

pub mod signing;

/// Parameters for minting a new virtual key (from the management API) - PURE AUTH: identity,
/// pool grants, at most one group binding, labels. No limits: they live on the bound group.
///
/// `Default` (1.6.0) is a construction convenience so a call site names the fields it cares about and
/// leaves the 1.6.0 provenance/mode additions (`minted_by`/`binding_mode`) at `None` via
/// `..Default::default()` — an omitted-provenance mint is byte-identical to a pre-1.6.0 one.
#[derive(Default)]
pub struct NewKeySpec {
    pub name: String,
    /// Pool grants with the intent carried intact: `None` = the mint body OMITTED
    /// `allowed_pools` = ALL pools; `Some(list)` = exactly those; `Some([])` = NO pools.
    pub allowed_pools: Option<Vec<String>>,
    /// Optional `groups:` binding (validated to exist at mint).
    pub group: Option<String>,
    /// Optional mint-time labels echoed onto metrics (never interpreted by enforcement).
    pub labels: std::collections::BTreeMap<String, String>,
    /// PROVENANCE (1.6.0): the principal that minted this key, recorded on
    /// [`busbar_api::VirtualKey::minted_by`]. `Some` for an APP/service token minted through the
    /// admin API by a (possibly delegated) admin — the token OUTLIVES its minter (review H2/H3), and
    /// this enables "list tokens minted-by X" re-attestation + mint-ceiling accounting. `None` leaves
    /// the field unset (byte-identical to a pre-1.6.0 mint).
    pub minted_by: Option<String>,
    /// The BINDING MODE (1.6.0, wire spelling) recorded on [`busbar_api::VirtualKey::binding_mode`].
    /// `Some("time-bound")` for an admin-minted app/service token (bounded by `exp`, no IdP tie);
    /// `None` leaves it unset.
    pub binding_mode: Option<String>,
}

/// Seconds in a metering day bucket. Metering is a TIME SERIES in fixed UTC-day buckets —
/// deliberately decoupled from the per-key budget windows the enforcement counters use, so
/// per-model aggregation ACROSS keys has one well-defined time base.
pub const METERING_BUCKET_SECS: u64 = 86_400;

/// Floor an epoch to its UTC-day metering bucket start.
pub fn metering_bucket(now: u64) -> u64 {
    now - (now % METERING_BUCKET_SECS)
}
