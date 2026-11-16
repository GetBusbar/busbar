// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT-SECURITY GATE of every OPEN, STARTTLS and FETCH Need (TRANSPORT-SECURITY-POLICY
//! 3, IF 13). One call to [`busbar_plugin_abi::host_side::caller::transport_verdict`] with the
//! caller's core-held `Accept`, made before the pool lookup and before any DNS. It reads no kind,
//! module, loopback name, `destinations[].plaintext`, `plaintext_admitted`, `limits.plaintext` or
//! `kind_default`: the verdict is a function of the acceptance, the TLS mode and the destination
//! text alone. A refusal reaches the plugin as `NeedErr::Denied` with no text (I2) and is audited
//! here with the full reason.

use std::collections::HashSet;
use std::sync::{Mutex, PoisonError};

use busbar_plugin_abi::host_side::caller::{transport_verdict, Accept, Caller, Verdict};
use busbar_plugin_abi::host_side::needs::NeedErr;
use busbar_plugin_abi::need::need_flag::TLS_NONE;

/// The audit action of a Need refused by the transport-security gate.
pub const REFUSED_ACTION: &str = "egress.insecure_transport_refused";

/// The most (instance, endpoint) pairs the once-per-endpoint log remembers.
const REMEMBERED: usize = 4096;

/// What the gate admitted a Need as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Admit {
    /// A TLS dial verified against the roots and anchors in force (the default).
    Verified,
    /// A TLS dial the instance accepted unverified (`accept: unverified_tls`): the connector's
    /// unverified client config, and the PoolKey `verify` bit set.
    Waived,
    /// A plaintext dial the instance accepted (`accept: plaintext`).
    Plain,
}

impl Admit {
    /// The PoolKey `verify` bit: set exactly for a waived dial, so a waived conn never serves an
    /// instance that did not accept the waiver.
    #[must_use]
    pub fn waived(self) -> bool {
        self == Admit::Waived
    }
}

/// The gate for an OPEN (`tls` = the Need's TLS mode bits, `dest` = `host:port` or `unix:/path`).
///
/// # Errors
/// `NeedErr::Denied` when the verdict is `Refuse`.
pub fn admit_open(accept: Accept, tls: u32, dest: &str) -> Result<Admit, NeedErr> {
    admit(transport_verdict(accept, tls, dest))
}

/// The gate for a FETCH: the URL's scheme is the mode (`https://` secured, `http://` plaintext).
///
/// # Errors
/// `NeedErr::Denied` when the verdict is `Refuse`.
pub fn admit_fetch(accept: Accept, url: &str) -> Result<Admit, NeedErr> {
    admit(transport_verdict(accept, TLS_NONE, url))
}

fn admit(v: Verdict) -> Result<Admit, NeedErr> {
    match v {
        Verdict::Verify => Ok(Admit::Verified),
        Verdict::WaiveVerify => Ok(Admit::Waived),
        Verdict::Plain => Ok(Admit::Plain),
        Verdict::Refuse => Err(NeedErr::Denied),
    }
}

/// The destination as an audit record or log line may name it: no scheme userinfo, path or query.
fn shown(dest: &str) -> &str {
    let t = dest.split_once("://").map_or(dest, |(_, r)| r);
    let t = t.rsplit_once('@').map_or(t, |(_, h)| h);
    let t = t.split(['/', '?', '#']).next().unwrap_or(t);
    t.char_indices().nth(256).map_or(t, |(at, _)| &t[..at])
}

/// The resource text of the audit row.
fn resource(who: &Caller<'_>, dest: &str) -> String {
    format!("dest:{}:{}", shown(dest), who.name)
}

/// The once-per-(instance, endpoint) memory of the ERROR line a lazy dial refusal writes after
/// `open` (the audit row is written every time; the log line once).
#[derive(Debug, Default)]
pub struct Reported {
    seen: Mutex<HashSet<(u64, Box<str>)>>,
}

impl Reported {
    /// Whether this is the first refusal of `dest` for `instance`: true once, then false.
    pub fn first(&self, instance: u64, dest: &str) -> bool {
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        if seen.len() >= REMEMBERED {
            seen.clear();
        }
        seen.insert((instance, shown(dest).into()))
    }

    /// An instance is gone: forget its endpoints.
    pub fn forget(&self, instance: u64) {
        self.seen
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(i, _)| *i != instance);
    }
}

/// Audit one refusal (`egress.insecure_transport_refused`) and, once per instance and endpoint,
/// log it at ERROR. The log line and the audit row name the instance by its configured name, the
/// destination without userinfo, and nothing else.
#[cold]
pub fn refused(who: &Caller<'_>, reported: &Reported, dest: &str) {
    busbar_kernel::audit_ring::AUDIT.record_by(
        REFUSED_ACTION,
        &resource(who, dest),
        busbar_kernel::audit_ring::OUTCOME_REJECTED,
        "system",
    );
    if reported.first(who.instance, dest) {
        tracing::error!(
            instance = %who.name,
            kind = ?who.kind,
            dest = %shown(dest),
            "outbound connection refused: the destination is not verified TLS and `insecure_transport.accept` does not admit it"
        );
    }
}

#[cfg(test)]
#[path = "../tests/need_policy_tests.rs"]
mod tests;
