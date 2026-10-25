// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! DISCOVERY AT BOOT (ARCHITECT 2026-10-02): the host's side of the mechanism's optional `ready`
//! (`busbar_contract::abi::mechanism::lifecycle`, READY).
//!
//! A plugin that must reach the network before it serves states `ready` on its door. After its
//! `open` answered READY the host submits `ready` on a REAL ticket of the dispatcher that adopted
//! the instance — so it may pend and is resumed after its wake like any op — with the host tables
//! `open` was handed, and the caller (the boot, before any listener binds) waits for the answer:
//! READY serves; anything else refuses the boot with the plugin's own text. Lazy discovery on the
//! first op is refused by the same ruling: nothing here runs on a request.
//!
//! A door without `ready` is not called: [`Plugin::ready`] answers `Ok` without a crossing, so such
//! a plugin boots exactly as before.

use std::time::Duration;

use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot, ReadyIn};

use super::{in_head, out_head, Dispatcher, Frame, Kind, Plugin};

/// How long boot waits for one instance's `ready`: the lifecycle budget
/// ([`super::Budgets::lifecycle`]'s default). At the deadline the dispatcher cancels the op and it
/// answers the kind's timeout outcome.
pub const READY_DEADLINE: Duration = Duration::from_secs(30);

/// How long past the deadline the caller waits for the cancel's answer before it stops waiting.
const CANCEL_GRACE: Duration = Duration::from_secs(5);

impl<K: Kind> Plugin<K> {
    /// Whether the door states `ready`.
    pub fn has_ready(&self) -> bool {
        self.inner.has_ready()
    }

    /// AWAIT `ready` on `dispatcher`, within `deadline`: `Ok` at once for a door without one;
    /// otherwise the op is submitted on a real ticket (it may pend and is resumed after its wake)
    /// and this thread waits for its answer. Call it after `open` answered READY and before any
    /// listener binds.
    ///
    /// # Errors
    /// The operator's text when `ready` did not answer READY: `plugin '<name>' ready failed:
    /// <reason>`, the reason being the plugin's own error text, else the outcome.
    pub fn ready(&self, dispatcher: &Dispatcher, deadline: Duration) -> Result<(), String> {
        if !self.has_ready() {
            return Ok(());
        }
        let failed = |reason: String| format!("plugin '{}' ready failed: {reason}", self.name());
        let _ = dispatcher;
        let frame = Frame::new(
            ReadyIn {
                head: in_head(),
                host: std::ptr::null(),
            },
            out_head(),
        );
        let ran = super::call::wait(
            super::call::call(
                &self.shared(),
                slot::READY,
                frame,
                std::sync::Arc::new(()),
                super::call::Opts {
                    class: DeadlineClass::Call,
                    deadline: Some(std::time::Instant::now() + deadline),
                    watch: Duration::ZERO,
                    leave: false,
                    lane: None,
                },
                &mut |_| None,
            ),
            deadline + CANCEL_GRACE,
        );
        let done = match ran {
            Some(super::call::Ran::Answered { called, .. }) => called,
            Some(super::call::Ran::TimedOut { .. }) => {
                return Err(failed(format!("{:?}", K::TIMEOUT)));
            }
            Some(super::call::Ran::NoTicket) => return Err(failed("no ticket is free".into())),
            None => return Err(failed(format!("no answer within {deadline:?}"))),
        };
        match (done.outcome, done.error) {
            (Outcome::Ready, _) => Ok(()),
            (_, Some(text)) if !text.is_empty() => {
                Err(failed(String::from_utf8_lossy(&text).into_owned()))
            }
            (o, _) => Err(failed(format!("{o:?}"))),
        }
    }
}

/// The ready witnesses, compiled in (`tests/fixtures/ready_plugins.rs`).
#[cfg(test)]
#[path = "../../tests/fixtures/ready_plugins.rs"]
pub(crate) mod ready_plugins;

#[cfg(test)]
#[path = "../tests/ready_tests.rs"]
mod tests;
