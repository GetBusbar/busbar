// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel directory behind DIRECTORY Needs, and the CA-5 hold index (IF §12.29). W0-ABI stub: frozen signatures, `todo!()` bodies; W1-K6P fills it.

use core::future::Future;

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

/// The CA-5 index and one provisioning instance's held principals live in `crate::holds` (W2-K8P owns
/// `holds/**`, WBS §3); the directory names them here, as IF §12.29 does.
pub use crate::holds::{HoldSet, Holds};
