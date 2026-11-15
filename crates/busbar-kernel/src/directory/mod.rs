// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel directory behind DIRECTORY Needs, and the CA-5 hold index (IF §12.29). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K6P fills it.

use core::future::Future;
use std::sync::Arc;

use busbar_plugin_abi::host_side::caller::Caller;
use busbar_plugin_abi::host_side::needs::{DirNeed, NeedErr, NeedOut};

/// K6p (`busbar-kernel/src/directory/`). Passed to `HostNeeds::new` (§13). Round 30: `linked_state` is withdrawn;
/// the hold is `Holds` below.
pub trait PluginDirectory: Send + Sync + 'static {
    /// The whole DIRECTORY Need. Writes a/b, data0 and the 16-byte `DirFacts` into `res` (§10.3 `Needs::directory`).
    /// Err(NeedErr::Denied) = the instance has no `provisioning:` block; Err(Unavailable) = store fault or the
    /// write lost the optimistic race MAX_ATTEMPTS times. Domain outcomes (dir::NOT_FOUND..=GUARD) are Ok.
    fn apply(
        &self,
        who: &Caller<'_>,
        n: DirNeed<'_>,
        res: &mut NeedOut<'_>,
    ) -> impl Future<Output = Result<(), NeedErr>> + Send;
}
/// K6p. One write's optimistic attempts before Unavailable (audited `directory_contended`). Not RetryPolicy: a
/// ConditionConflict is not a failure.
pub const MAX_ATTEMPTS: u32 = 4;
/// K6p. Held principals per provisioning instance. A write that would hold more answers dir::TOO_MANY, writes
/// nothing, audits and alerts `provisioning_held_full`.
pub const MAX_HELD: u32 = 262_144;

/// K6p, the CA-5 index. Built per config generation from every `provisioning.link`. K8p resolves `for_inbound`
/// once per generation and keeps the answer beside the inbound auth port; the request path never calls it.
pub struct Holds {
    // W0-ABI: private field (inbound auth instance id -> Box<[Arc<HoldSet>]>; only instances named in some
    // link.auth) lands with W1-K6P.
    _stub: (),
}
impl Holds {
    /// None = no provisioning instance links `inbound`: K8p makes no probe for it at all.
    pub fn for_inbound(&self, inbound: u64) -> Option<&[Arc<HoldSet>]> {
        let _ = (&self._stub, inbound);
        todo!()
    }
}
/// One provisioning instance's held principals (the `link.index` values of its INACTIVE subjects).
pub struct HoldSet {
    // W0-ABI: private fields (len: AtomicU32, set: ArcSwap<HashSet<Box<str>, foldhash::fast::RandomState>>, wake:
    // Notify, generation: AtomicU64) land with W1-K6P.
    _stub: (),
}
impl HoldSet {
    /// true = `principal` is held. Sync, no allocation, no lock, no await: one Relaxed load of `len` (0 = false);
    /// otherwise one `ArcSwap::load` (2 RMWs on the caller's own debt slot, §0 I5's fourth exception) and one
    /// foldhash probe of the principal bytes. B-HOLD (§14).
    pub fn holds(&self, principal: &str) -> bool {
        let _ = (&self._stub, principal);
        todo!()
    }
}
