// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST SERVICES, AS THE HOST'S TWO HALVES SHARE THEM (`BUSBAR-1.6.0.md` THE DESIGN, host
//! services): the [`HostServices`] trait the kernel implements and the plugin loader dispatches
//! into, and the result types that cross between them. The kernel names this, the loader names
//! this, and neither names the other. The ABI a plugin sees is `abi::host::service`; nothing here
//! crosses the plugin boundary.

use std::sync::Arc;

use crate::abi::host::service::ItemSpan;
use crate::abi::mechanism::call::Outcome;
use crate::abi::mechanism::KindCode;

/// Who called a service: the opened instance, by the label the host configured for it, the plugin
/// it is an instance of, and its kind. The loader states it at bind. The kernel keys every
/// per-instance fact it holds by `instance`, never by `plugin`: two instances of one plugin share a
/// Statement name and never a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Caller {
    /// The host's label for this opened instance, unique per instance.
    pub instance: Arc<str>,
    /// The plugin's Statement name.
    pub plugin: Arc<str>,
    /// Its kind.
    pub kind: KindCode,
}

/// A reading of the kernel's one clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reading {
    /// Nanoseconds since the Unix epoch.
    pub wall_ns: u64,
    /// Nanoseconds since the clock's fixed origin.
    pub mono_ns: u64,
}

/// Where a pended service's result goes: called once, from any thread. The mechanism stores the
/// result under the call's handle and wakes its ticket.
pub type Later = Box<dyn FnOnce(Stored) + Send>;

/// THE HOST SERVICES, as the kernel implements them. The dispatcher holds one for every instance it
/// adopts; each slot validates the caller's `in`, applies the mechanism's rules, and calls in here
/// at most once per completion handle.
pub trait HostServices: Send + Sync {
    /// `clock.now`: the kernel's one clock. Never pends.
    fn now(&self) -> Reading;

    /// `dest.judge`: judge `dest` against egress class `class`'s rules; `resolve` = the caller set
    /// `DEST_RESOLVE`. Answers [`Ran::Now`] with a `DEST_*` verdict (or REFUSED for an unknown
    /// class), or hands `later` on and answers [`Ran::Later`]. `later` is `None` only for a call
    /// that may not pend, which never reaches here for this service.
    fn dest_judge(&self, dest: &str, class: u32, resolve: bool, later: Option<Later>) -> Ran;
}

/// One service result, as the host stores it under its handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stored {
    /// The outcome.
    pub outcome: Outcome,
    /// The scalar answer.
    pub value: u64,
    /// The bytes.
    pub bytes: Vec<u8>,
    /// The spans over them.
    pub spans: Vec<ItemSpan>,
    /// The reason, for FAILED/REFUSED.
    pub error: &'static str,
}

impl Stored {
    /// READY with `value` and no buffer.
    #[must_use]
    pub fn ready(value: u64) -> Self {
        Self {
            outcome: Outcome::Ready,
            value,
            bytes: Vec::new(),
            spans: Vec::new(),
            error: "",
        }
    }

    /// REFUSED for `why`.
    #[must_use]
    pub fn refused(why: &'static str) -> Self {
        Self {
            outcome: Outcome::Refused,
            error: why,
            ..Self::ready(0)
        }
    }
}

/// What a service body did.
#[derive(Debug)]
pub enum Ran {
    /// Finished.
    Now(Stored),
    /// Handed its [`Later`] on; the answer pends.
    Later,
}
