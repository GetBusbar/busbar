// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin AUDIT log's MOUNT in this crate. The record, its chain impl and the bounded ring are the
//! audit unit's (`busbar_unit_audit::legacy::entry`) — one definition, read directly by every
//! reader that needs the type. What lives here is only what this crate alone can supply: the clock the
//! ring reads and the durable seam it feeds, bound ONCE into the process-wide static every admin
//! mutation records through.
//!
//! ## Where durability lives — the ONE durable path, and it is not in this crate
//!
//! `AUDIT.record_by` is the ONE place an admin mutation is recorded, and the record it seals goes
//! down ONE durable path: a kernel-held record leg, whose store reach the composition root owns.
//! This crate cannot build that leg — a leg is admitted by the kernel and lands on the published
//! store protocol, and neither is this crate's to name — so what lives here is the SLOT the root
//! installs its seam into, and the ring the same root seeds from the durable tail at boot.
//!
//! An UNINSTALLED slot is a deployment with no durable audit at all: the ring still records, still
//! chains and still serves reads, and nothing is persisted. That is the in-memory behaviour stated
//! honestly rather than a failure — and it is why the emit is a lookup with a `None` arm
//! rather than an `expect`.
//!
//! **Sharing the mechanism is not sharing the buffer, and the difference is load-bearing.** This log
//! is admin-MUTATION-ONLY and its working set is a bounded ring of [`MAX_AUDIT_ENTRIES`]. An admin
//! mutation is operator-rate; a tool call is REQUEST-rate. Pouring one into the other means a busy
//! afternoon of tool calls evicts every admin row, so "who changed this registration" stops being
//! answerable at exactly the moment an incident makes somebody ask — and the loss is silent, because
//! a ring that pruned looks identical to a ring that was never written to.
//!
//! Audit is process-wide state (NOT config-derived), so it lives as a global rather than on the
//! swappable `App` snapshot — it survives a config apply naturally.

use std::sync::LazyLock;

use busbar_unit_audit::legacy::{AuditLog, Clock, DurableSeam};

/// The outcome tokens this stream uses, re-exported from the ONE audit vocabulary in
/// [`crate::audit::vocab`]. They are core's, not the admin surface's: the ruling put the whole
/// vocabulary in core so a fourth stream inherits it instead of inventing a fourth spelling. The
/// re-export keeps the existing import path for the hundred-odd call sites that name them.
pub use crate::audit::vocab::{OUTCOME_APPLIED, OUTCOME_DEGRADED, OUTCOME_REJECTED};

/// How many entries the in-memory ring retains. Bounds RAM, not history — the durable leg keeps the
/// full log.
/// It is the ring's own cap, re-exported so `crate::admin::audit::MAX_AUDIT_ENTRIES` (and the test
/// asking for "every matching row that can exist") still resolves.
pub use busbar_unit_audit::legacy::MAX_AUDIT_ENTRIES;

/// The clock the ring seals a mutation under: the store's, read ONCE per mutation inside the ring so
/// the sealed record and the durable emit carry the same second.
struct StoreClock;

impl Clock for StoreClock {
    fn now(&self) -> u64 {
        busbar_substrate::store::now()
    }
}

/// THE INSTALLED DURABLE PATH. One slot, set once at boot by the composition root, holding the
/// record leg the sealed mutation is persisted through.
///
/// A `OnceLock` and not a swappable handle: the durable path is a chain, and a chain whose sink can
/// be replaced mid-process is a chain that can be forked by whoever replaces it. It is also why
/// there is no uninstall — the way to stop persisting is to boot without a store, which leaves this
/// empty from the start rather than emptying it halfway through.
static DURABLE: std::sync::OnceLock<Box<dyn DurableSeam>> = std::sync::OnceLock::new();

/// INSTALL the durable path, once, at boot.
///
/// Returns whether this call is the one that installed it. A second call is refused rather than
/// ignored: two seams over one log is the fork the `OnceLock` exists to prevent, and a caller that
/// thought it had installed one needs to be told it had not.
pub fn install_durable(seam: Box<dyn DurableSeam>) -> bool {
    DURABLE.set(seam).is_ok()
}

/// THE CHOKEPOINT FEED onto whatever the root installed. `record_by` is the ONE place an admin
/// mutation is recorded, so this ONE call — with the SAME `ts` the ring sealed — is the durable
/// write.
///
/// Fire-and-forget: it NEVER fails the mutation it records. A gateway whose control plane stops
/// when its audit backend blinks has converted an observability dependency into an availability
/// one, and losing the ability to change configuration while a store is unreachable is worse than a
/// gap in a log that is already being alarmed on.
struct InstalledSeam;

impl DurableSeam for InstalledSeam {
    fn emit(&self, ts: u64, action: &str, resource: &str, outcome: &str, principal: &str) {
        if let Some(seam) = DURABLE.get() {
            seam.emit(ts, action, resource, outcome, principal);
        }
    }
}

/// The process-wide admin audit log: the unit's ring, bound to this crate's clock and to the slot
/// the root installs its record leg into.
pub static AUDIT: LazyLock<AuditLog> =
    LazyLock::new(|| AuditLog::with(Box::new(StoreClock), Box::new(InstalledSeam)));
