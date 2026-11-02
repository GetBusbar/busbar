// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::time::Duration;

use busbar_contract::abi::mechanism::call::{DeadlineClass, Outcome};
use busbar_contract::abi::mechanism::lifecycle::{slot, ReadyIn};

use super::lifecycle::AnswerLease;
use super::{in_head, now_ns, out_head, Dispatcher, Frame, Kind, Plugin};

pub const READY_DEADLINE: Duration = Duration::from_secs(30);

const CANCEL_GRACE: Duration = Duration::from_secs(5);

impl<K: Kind> Plugin<K> {
    pub fn has_ready(&self) -> bool {
        self.inner.has_ready()
    }

    pub fn ready(&self, dispatcher: &Dispatcher, deadline: Duration) -> Result<(), String> {
        if !self.has_ready() {
            return Ok(());
        }
        let failed = |reason: String| format!("plugin '{}' ready failed: {reason}", self.name());
        let ticket = dispatcher
            .mint(0)
            .ok_or_else(|| failed("no ticket is free".into()))?;
        let frame = Frame::new(
            ReadyIn {
                head: in_head(),
                host: std::ptr::null(),
            },
            out_head(),
        );
        let until = now_ns().saturating_add(u64::try_from(deadline.as_nanos()).unwrap_or(u64::MAX));
        let reply = dispatcher.submit(self, ticket, slot::READY, frame, DeadlineClass::Call, until);
        let done = reply.wait(deadline + CANCEL_GRACE);

        drop(reply);
        dispatcher.recycle(ticket);
        let Some(done) = done else {
            return Err(failed(format!("no answer within {deadline:?}")));
        };
        let _lease = AnswerLease::new(self, done.lease);
        match (done.outcome, done.error) {
            (Outcome::Ready, _) => Ok(()),
            (_, Some(text)) if !text.is_empty() => {
                Err(failed(String::from_utf8_lossy(&text).into_owned()))
            }
            (o, _) => Err(failed(format!("{o:?}"))),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/fixtures/ready_plugins.rs"]
pub(crate) mod ready_plugins;

#[cfg(test)]
#[path = "../tests/ready_tests.rs"]
mod tests;
