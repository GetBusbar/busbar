// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The durable push queue behind plane PUSH intents (IF §12.9). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K8A fills it.

use busbar_plugin_abi::host_side::caller::{BoxFut, Caller};

use crate::plugin_records::RecordsDenied;

/// Plane PUSH intents. Durable (CoreStore, rows keyed by (who.plugin, who.name), never the runtime id),
/// at-least-once, deliveries through the connector's fetch with the live instance of that name as Caller
/// (the connector's guard judges every new connection, §12.1), retries via RetryPolicy(PlanePush), dropped and audited after ttl_s or when no
/// instance of that name is configured. The plane learns nothing back (it may record its own bookkeeping).
/// Round 16: a plane that must refuse a bad callback **when the client sets it** (plane-a2a's push config) asks
/// first with the JUDGE intent (§8.6, §12.1 `PlaneJudge`) and refuses in its own protocol; the delivery-time judge
/// here still applies to every attempt (DNS can change between the two).
pub trait PushQueue: Send + Sync + 'static {
    fn enqueue<'a>(
        &'a self,
        who: &'a Caller<'_>,
        ttl_s: u64,
        recs: &'a [u8],
    ) -> BoxFut<'a, Result<(), RecordsDenied>>;
}
