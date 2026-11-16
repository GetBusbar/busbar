// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! JUDGE (IF §8.6 round 16, §12.1 `PlaneJudge`): "judge this destination for me". One process-wide judge over the
//! deployment's one [`DestJudge`], the same guard the old `dest.judge` service ran (host_services.rs
//! `dest_judge`) minus `DEST_EXPLAIN` and the address list: no plane dials, so no pin set is handed back, and the
//! plane never learns a resolved address, the matched rule or another destination's state.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use busbar_plugin_abi::plane::{
    DEST_ALLOWED, DEST_INTERNAL, DEST_NO_HOST, DEST_UNRESOLVABLE, JUDGE_REFUSE_PRIVATE,
    JUDGE_RESOLVE,
};

use crate::diagnostics::PLANE_JUDGE_UNAVAILABLE;
use crate::host_services::{Admitted, DestJudge};

/// The longest destination text a plane may ask about; longer answers `DEST_NO_HOST` without a lookup.
pub const MAX_DESTINATION: usize = 2_048;

/// The judge of a plane's JUDGE intents.
#[derive(Clone)]
pub struct PlaneJudge {
    judge: Option<Arc<dyn DestJudge>>,
}

impl PlaneJudge {
    #[must_use]
    pub fn new(judge: Arc<dyn DestJudge>) -> Self {
        Self { judge: Some(judge) }
    }

    /// No `DestJudge` installed: every destination answers `DEST_INTERNAL` (fail closed).
    #[must_use]
    pub fn unavailable() -> Self {
        Self { judge: None }
    }

    /// The `JudgeAns` verdict (`DEST_*`) for `dest` in egress `class` under `flags` (`JUDGE_RESOLVE`,
    /// `JUDGE_REFUSE_PRIVATE`). Pends only on DNS (`JUDGE_RESOLVE`), bounded by `deadline`: past it the answer is
    /// `DEST_UNRESOLVABLE`. Never fails.
    pub async fn judge(&self, dest: &str, class: u32, flags: u32, deadline: Instant) -> u32 {
        let Some(judge) = &self.judge else {
            tracing::warn!("plane_judge_unavailable: no destination judge is installed");
            return DEST_INTERNAL;
        };
        if dest.len() > MAX_DESTINATION {
            return DEST_NO_HOST;
        }
        let refuse_private = flags & JUDGE_REFUSE_PRIVATE != 0;
        match judge.judge_name(dest, class, refuse_private) {
            Err(verdict) => return verdict_of(verdict),
            Ok(()) if flags & JUDGE_RESOLVE == 0 => return DEST_ALLOWED,
            Ok(()) => {}
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        let done = Box::new(move |admitted: Admitted| {
            let _ = tx.send(admitted);
        });
        let admitted = match judge.judge(dest, class, refuse_private, done) {
            Some(admitted) => admitted,
            None => {
                let wait = deadline.saturating_duration_since(Instant::now());
                match tokio::time::timeout(wait, rx).await {
                    Ok(Ok(admitted)) => admitted,
                    _ => return DEST_UNRESOLVABLE,
                }
            }
        };
        match admitted {
            Ok(_) => DEST_ALLOWED,
            Err(refused) => verdict_of(refused.verdict),
        }
    }
}

/// BUSBAR-7108, once per process: later answers are the same condition and log at debug.
fn warn_unavailable() {
    static LOGGED: AtomicBool = AtomicBool::new(false);
    if LOGGED.swap(true, Ordering::Relaxed) {
        busbar_contract::diag_debug!(
            PLANE_JUDGE_UNAVAILABLE,
            "no destination judge is installed: JUDGE answers internal"
        );
    } else {
        busbar_contract::diag_warn!(
            PLANE_JUDGE_UNAVAILABLE,
            "no destination judge is installed: every plane JUDGE answers internal"
        );
    }
}

/// A verdict this wire does not number is refused as internal, never allowed.
fn verdict_of(verdict: u64) -> u32 {
    u32::try_from(verdict).unwrap_or(DEST_INTERNAL)
}

#[cfg(test)]
#[path = "tests/plane_judge_tests.rs"]
mod tests;
