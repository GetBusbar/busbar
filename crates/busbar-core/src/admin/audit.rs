// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The admin AUDIT log's MOUNT in this crate. The record, its chain impl and the bounded ring are the
//! audit unit's (`busbar_unit_audit::legacy::entry`) — one definition, read directly by every
//! reader that needs the type. What lives here is only what this crate alone can supply: the clock the
//! ring reads and the durable seam it feeds, bound ONCE into the process-wide static every admin
//! mutation records through.
//!
//! ## Where durability lives — the ONE durable path
//!
//! Durability is the neutral journal seam's ([`crate::plane::auditlog`]): `AUDIT.record_by` is the
//! ONE place an admin mutation is recorded, and the seam bound below carries that mutation onto the
//! store-backed durable seam, which persists the hash-chained record into `plane_records`, seeds the
//! read-model ring `GET /audit` serves, and is restored + verified at boot. The ring itself keeps NO
//! durable state: it is ephemeral by construction (started fresh on every boot), retained for the
//! in-process tamper-evidence checks the audit unit tests assert on.
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

/// How many entries the in-memory ring retains. Bounds RAM, not history — the durable seam keeps the
/// full log. It is the ring's own cap, so the read-model ring the seam seeds
/// ([`crate::plane::auditlog`]) is bounded by the SAME number as the ring `record_by` fills;
/// re-exported so `crate::admin::audit::MAX_AUDIT_ENTRIES` (and the test asking for "every matching
/// row that can exist") still resolves.
pub use busbar_unit_audit::legacy::MAX_AUDIT_ENTRIES;

/// The clock the ring seals a mutation under: the store's, read ONCE per mutation inside the ring so
/// the sealed record and the durable emit carry the same second.
struct StoreClock;

impl Clock for StoreClock {
    fn now(&self) -> u64 {
        busbar_substrate::store::now()
    }
}

/// THE CHOKEPOINT FEED onto the durable journal seam. `record_by` is the ONE place an admin mutation
/// is recorded, so this ONE call — with the SAME `ts` the ring sealed — is the durable write.
/// Fire-and-forget: it NEVER fails the mutation it records (see
/// `plane::auditlog::emit_admin_hostless`), and the seam's own seq/prev_hash/hash are minted
/// independently of the in-process ring's (both continue the same persisted chain).
struct JournalSeam;

impl DurableSeam for JournalSeam {
    fn emit(&self, ts: u64, action: &str, resource: &str, outcome: &str, principal: &str) {
        crate::plane::auditlog::emit_admin_hostless(ts, action, resource, outcome, principal);
    }
}

/// The process-wide admin audit log: the unit's ring, bound to this crate's clock and seam.
pub static AUDIT: LazyLock<AuditLog> =
    LazyLock::new(|| AuditLog::with(Box::new(StoreClock), Box::new(JournalSeam)));
