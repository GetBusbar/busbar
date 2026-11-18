// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Host-side plugin port vocabulary and wire codecs (IF §8.8, §11.3).
//! Loading, adapter error construction and kernel policy live in their owning crates.
//!
//! Every port is dyn-compatible and boxes **once** per async call (the adapter's `async` body, which contains
//! the proxy's unboxed step loop). Sync port methods never box. Header lists cross as `&[abi::Pair<'_>]`, which
//! core builds once per request from its `HeaderMap` and shares between auth, plane and hooks (no per-port copy).

#![forbid(unsafe_code)]
#![doc(test(attr(forbid(unsafe_code))))]

pub mod auth;
pub mod clock;
pub mod export;
pub mod hook;
pub mod network;
pub mod plane;
pub mod secret;
pub mod store;
pub mod transport;

use busbar_plugin_abi::fail::CallError;
use busbar_plugin_abi::host_side::caller::CallStack;
use busbar_plugin_abi::records::Records;

/// `stack` is the host call stack outside this call; the adapter copies it into Caller.stack. Kernel
/// callers start with `CallStack::default()`; custody passes `who.stack.push(who.instance)` (§12.2).
#[derive(Clone, Copy, Debug)]
pub struct CallCx {
    pub deadline: std::time::Instant,
    pub request_id: u64,
    pub stack: CallStack,
}

/// `text` is always the scrubbed plugin text (§12.16) and is for operators and audit only. `code` may be a
/// kind code; core maps it before any client sees it (§12.15). Round 21: `Failed.retry_after_s` and
/// `backend_status` are `Answer::fail_fact(FACT_RETRY_AFTER_S / FACT_BACKEND_STATUS)` of the FAILED answer
/// (§4.1, §10.2), filled by the one shared builder for every kind; None when the plugin stated none, and always
/// None for `Call`. They are facts: `RetryPolicy` (§12.3) and the login outage page (§8.3) decide with them.
/// Round 34 (PLUGIN-ERROR-CODES): `error` is `Answer::fail_error` resolved through the instance's `ErrorBook`
/// (§11.2) by the same shared builder; display only (§12.3 never reads it, ARC-2). On STREAM_CONTENT `deliver`
/// and every `confirm` it is always None (§8.5). Its `Display` writes core's words and the code only; the text
/// is a separate field (§12.16).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortError {
    Refused {
        code: u32,
        text: Box<str>,
        error: Option<PluginCode>,
    },
    Failed {
        code: u32,
        text: Box<str>,
        retry_after_s: Option<u64>,
        backend_status: Option<u64>,
        error: Option<PluginCode>,
    },
    Call(CallError),
}

#[derive(Clone, Debug, PartialEq)]
pub enum FactVal {
    U(u64),
    Text(Box<str>),
}

pub type Facts = Vec<(u32, FactVal)>;

#[derive(Clone, Copy, Debug)]
pub enum FactRef<'o> {
    U(u64),
    Text(&'o str),
}

/// Round 31: the optional settled part of an `open` answer (§8.8 `settled::decode_settled`), borrowed from the
/// answer buffer. core_cfg = the CORE_CFG records (CoreCfgRec + name + value), validated by the decoder.
pub struct SettledOut<'o> {
    pub config: &'o [u8],
    pub core_cfg: Records<'o>,
}

pub mod binder;
pub mod codec;

/// The resolved code, `Copy` over `&'static`, so carrying it does no refcount RMW (B-SYNC REFUSED arm unchanged).
/// `Display` = `BUSBAR-{plugin}-{number:04}`; it always matches `^BUSBAR-[a-z][a-z0-9-]{0,63}-[0-9]{4}$` and can
/// never start like a core `BUSBAR-[0-9]{4}` code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PluginCode {
    pub plugin: &'static str,
    pub number: u16,
}

impl core::fmt::Display for PluginCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BUSBAR-{}-{:04}", self.plugin, self.number)
    }
}
