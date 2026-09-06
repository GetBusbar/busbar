// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The first boot after an upgrade: what the previous release already holds, sealed as the ledger's
//! opening figures.
//!
//! ## Where this runs in the boot order, and why exactly there
//!
//! Immediately AFTER the durability branch — the step that builds the journal and constructs the
//! ledger dual-writing onto the previous release's rows — and BEFORE the transport-key unit
//! provisions a listener, which is the step before anything binds an address.
//!
//! Both edges are load-bearing.
//!
//! It cannot run earlier: the opening is a checkpoint the ledger seals, and there is no ledger until
//! the durability step has built one. It cannot run later: the first accepted connection can settle,
//! and a settlement posted before the opening was sealed would be measured from a checkpoint that
//! did not exist when it happened — the residual would be off by the whole of the previous release's
//! history, on a deployment where that history is the entire point.
//!
//! The store adapter is already in hand by then, because the durability step took its shipper and
//! its legacy-rows path from it. So this step adds no new dependency to the boot; it adds one read
//! and one seal between two steps that already exist.
//!
//! ## Where the marker goes
//!
//! On the journal, beside the opening checkpoint it is a marker for. It used to go into the store
//! adapter's node-local shim, which was the honest place for it while there was nowhere else — but
//! the shim holds it for the life of a process only, so a node with a data directory re-read the
//! previous release's rows on every single boot and the one record that says "this deployment has
//! already opened its balances" was the one record with nowhere durable to live.
//!
//! It still does not go into the rows that were READ. Those may be on a read-only replica, and a
//! marker written beside somebody else's data is a migration that has quietly taken ownership of a
//! schema it does not own. The journal is this release's own record, which is exactly what the
//! ledger unit's records seam asked for.
//!
//! ## What the root decides and what it does not
//!
//! The root decides WHICH rows are read, because it is the only thing that has both the loaded store
//! and the resolved configuration: the key rows name their own buckets, and the configured group
//! buckets and the metering days come off the config. Everything after that — what an opening figure
//! is, how it folds into a balance, what the marker says — belongs to the ledger unit, and this
//! module does not have an opinion about any of it.
//!
//! ## It does not refuse
//!
//! A store that will not list its key rows costs the migration the buckets it would have discovered
//! there; it is reported and the boot continues over what the configuration named. A store with
//! nothing in it at all seals an opening at zero. The one outcome a migration may not produce is a
//! configuration that worked yesterday failing to boot today, so the only errors that come back here
//! are the ones where continuing would be worse: the opening could not be signed, the ledger's own
//! records could not be read or written, or the figures do not fit in a ledger figure.

use busbar_plugin_loader::store_adapter::{LegacyReadPlan, StoreAdapter};
use busbar_unit_ledger::checkpoint::CheckpointSecret;
use busbar_unit_ledger::migration::{
    migrate, LegacyLedgerRows, MigrationError, MigrationRecords, Outcome,
};

/// What the root reads out of configuration to decide which of the previous release's rows to read.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MigrationConfig {
    /// Which node is sealing.
    pub node: u64,
    /// The window in force for the key buckets, as its opening instant in whole seconds.
    pub window: u64,
    /// The configured group buckets and the window each is on. Not discoverable from the store —
    /// a budget group is a configuration fact — so the root names them.
    pub group_buckets: Vec<(String, u64)>,
    /// The metering days to read.
    pub metering_days: Vec<u64>,
    /// The card version the opening entries are priced under.
    pub rate_card_version: u64,
}

/// What the migration step did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Migration {
    /// Whether this boot sealed the opening, and what it sealed.
    pub outcome: Outcome,
    /// Why the key rows could not be listed, if they could not. The buckets they would have named
    /// are missing from the opening, so the fact is carried rather than swallowed.
    pub key_rows_unreadable: Option<String>,
}

impl Migration {
    /// Whether this boot did the sealing, as opposed to finding a marker already there.
    #[must_use]
    pub fn sealed_now(&self) -> bool {
        self.outcome.sealed_now()
    }
}

/// Read the previous release's rows through the store adapter and seal the opening.
///
/// The rows are read through the adapter — they are the previous release's and nobody else has them
/// — but WHERE the marker goes is the CALLER'S, and it is an argument rather than a default for that
/// reason. On a node built by [`crate::root::durability::build_for_node`] it goes on the one journal,
/// beside the opening checkpoint it is a marker for. There was a default once, the store adapter's
/// node-local shim, and it is what made a second boot on a node with a data directory re-read the
/// previous release's rows anyway.
///
/// # Errors
///
/// The opening could not be signed, the ledger's own records were not usable, or the figures read do
/// not fit. A store that would not answer for some rows is NOT an error — see this module's preamble.
pub fn run(
    adapter: &StoreAdapter,
    records: &mut dyn MigrationRecords,
    cfg: &MigrationConfig,
    wall: u64,
    secret: Option<&dyn CheckpointSecret>,
) -> Result<Migration, MigrationError> {
    let (plan, key_rows_unreadable) =
        match adapter.key_bucket_plan(cfg.window, &cfg.group_buckets, &cfg.metering_days) {
            Ok(plan) => (plan, None),
            // The key rows are where the per-key buckets come from. Without them the migration
            // opens over what the configuration named and says why the rest is missing, which is
            // strictly better than either refusing to boot or reporting a complete opening that is
            // not one.
            Err(e) => (
                LegacyReadPlan {
                    windows: cfg.group_buckets.clone(),
                    days: cfg.metering_days.clone(),
                },
                Some(e.to_string()),
            ),
        };

    let rows = adapter.legacy_ledger_rows(plan);
    let outcome = seal_opening(&rows, records, cfg, wall, secret)?;
    Ok(Migration {
        outcome,
        key_rows_unreadable,
    })
}

/// THE BOOT STEP: seal the opening on the node's own book, in the one slot the preamble names.
///
/// [`run`] takes the two seams; this takes the two objects the boot has — the store adapter and the
/// node's one book — and joins them, which is the composition root's job and not the ledger unit's.
/// Splitting it out from `run` is what lets the ordering rule be exercised over the real journal
/// while `run` stays testable against a records double.
///
/// The marker goes on the journal under the metering step, because sealing the opening IS a
/// metering-side write: it is the balance every later meter reading is measured from.
///
/// # Errors
///
/// As [`run`]. A degraded read is NOT an error and never refuses a boot — it comes back on
/// [`Migration::key_rows_unreadable`]. What does come back here is the small set where continuing
/// would be worse than stopping: the opening could not be signed, the ledger's own records could
/// not be read or written, or the previous release's figures do not fit in a ledger figure. A node
/// that served on any of those would be measuring its reconciliation identity from a checkpoint it
/// never sealed, and the identity would report every row as out for the life of the deployment.
pub fn at_boot(
    adapter: &StoreAdapter,
    book: &std::sync::Arc<std::sync::Mutex<crate::root::durability::Durability>>,
    token: &busbar_caps::DurabilityToken,
    cfg: &MigrationConfig,
    wall: u64,
    secret: Option<&dyn CheckpointSecret>,
) -> Result<Migration, MigrationError> {
    let mut durability = book.lock().unwrap_or_else(|p| p.into_inner());
    let mut records = durability.migration_records(token, busbar_caps::StepName::Meter);
    run(adapter, &mut records, cfg, wall, secret)
}

/// The seal itself, over the two seams and nothing else.
///
/// Separate from [`run`] because [`run`]'s job is to decide what gets read and this one's job is to
/// hand two objects to the ledger unit. Splitting them is what lets the ordering rule be tested
/// against the real traits without a loaded store plugin in the way.
///
/// # Errors
///
/// As [`run`].
pub fn seal_opening(
    rows: &dyn LegacyLedgerRows,
    records: &mut dyn MigrationRecords,
    cfg: &MigrationConfig,
    wall: u64,
    secret: Option<&dyn CheckpointSecret>,
) -> Result<Outcome, MigrationError> {
    migrate(rows, records, cfg.node, wall, cfg.rate_card_version, secret)
}

#[cfg(test)]
#[path = "tests/migration.rs"]
mod tests;
