// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A LIVE SESSION'S METERING — the streaming plane's per-class counts, handed to the kernel.
//!
//! A live voice carrier cannot be billed after the fact alone: the session must be HARD-CLOSED
//! mid-stream the moment the caller's budget is dry. OWNER RULING Q21b settles how, and it is the
//! same way every other plane is governed. Each closed turn's raw counts per declared class
//! (`busbar_plane_streaming::session::class_counts` — the plane's one reading of a turn) go to the
//! kernel's [`SessionAccount`], which appends them to the ledger through the one metering path and
//! answers [`TurnVerdict::Live`] or [`TurnVerdict::MustClose`] off the kernel's own budget view. The
//! session is priced at READ, against the `streams` plane's card (#47, #71); nothing here names a
//! rate, a price or a stored figure (#43).
//!
//! The D2 lease this replaces (reserve an estimate, price each turn through the flat llm card into
//! nanodollars, settle and hard-close at a cap read once at the open) is deleted; the snapshot is
//! under `~/Downloads/busbar-1.6.0-snapshots/P2-voice/`.

pub use busbar_kernel::plane_host::session_meter::{BudgetRefused, SessionAccount, TurnVerdict};
use busbar_kernel::plane_host::EngineHost;
use busbar_plane_streaming::session::{class_counts, TurnCounters};
use busbar_substrate_values::billing::Usage;
use std::sync::Arc;

/// THE PRESENTING KEY a live session is metered for, before the session opens: the live host, the
/// resolved key, the front-door pool its buckets are filtered by, and the provider label its series
/// row carries. Built at the governed open (where the key and the host are both in hand); `None` on an
/// ungoverned deployment, which has no key to attribute anything to.
pub struct TurnMeter {
    host: Arc<dyn EngineHost>,
    key: busbar_api::VirtualKey,
    pool: &'static str,
    provider: &'static str,
}

impl TurnMeter {
    /// Bind the attribution over a live host + resolved key.
    #[must_use]
    pub fn new(
        host: Arc<dyn EngineHost>,
        key: busbar_api::VirtualKey,
        pool: &'static str,
        provider: &'static str,
    ) -> Self {
        TurnMeter {
            host,
            key,
            pool,
            provider,
        }
    }

    /// OPEN the session's account at the kernel, for turns of `model`. `Err` is a chain the kernel's
    /// budget view already reads dry — the session must not open. `Ok(None)` is a host with
    /// governance off: nothing is ledgered and nothing closes the session on budget.
    ///
    /// The ledger lane is `voice` + U+001F + the model (the provider label when the session names no
    /// model), so the view prices it with the `streams` card and never with the llm plane's flat one.
    pub fn open(self, model: &str) -> Result<Option<SessionMetering>, BudgetRefused> {
        let name = if model.is_empty() {
            self.provider
        } else {
            model
        };
        let lane = format!(
            "{}{}{name}",
            crate::PLANE_KEY,
            busbar_kernel::governance::PLANE_LANE_SEP
        );
        let account =
            SessionAccount::open(Arc::clone(&self.host), Some(&self.key), self.pool, lane)?;
        Ok(account.map(|account| SessionMetering {
            account,
            model: model.to_string(),
            meter: self,
        }))
    }
}

/// ONE OPEN SESSION'S METERING, plane-side: the kernel account its turns are reported to, and the
/// attribution its per-model series row is written under.
pub struct SessionMetering {
    account: SessionAccount,
    model: String,
    meter: TurnMeter,
}

impl SessionMetering {
    /// Report ONE closed turn — `usage` is the upstream's report (`None` for a turn that ended on an
    /// error or with the session), `counters` the plane's own bookkeeping — to the kernel account,
    /// which ledgers its raw counts per class and answers whether the carrier stays open. A reported
    /// turn also writes its series row (the admin usage report's per-model request count), exactly as
    /// before.
    pub fn report_turn(
        &self,
        usage: Option<&crate::ir::usage::IrDuplexUsage>,
        counters: TurnCounters,
    ) -> TurnVerdict {
        let m = &self.meter;
        if let (Some(pin), Some(_)) = (m.host.meter_pin(), usage) {
            let now = m.host.clock_now_secs();
            m.host
                .meter_series(pin.gov(), &m.key.id, &self.model, m.provider, None, now);
        }
        self.account.report_turn(&plane_counts(usage, counters))
    }
}

/// A closed turn's raw counts per class, as the streaming plane reads them, on the neutral carrier
/// the ledger takes.
#[must_use]
pub fn plane_counts(
    usage: Option<&crate::ir::usage::IrDuplexUsage>,
    counters: TurnCounters,
) -> Usage {
    Usage {
        usage_units: class_counts(usage, counters)
            .into_iter()
            .map(|(class, n)| (class.as_str().to_string(), n))
            .collect(),
    }
}
