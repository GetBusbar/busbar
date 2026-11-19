// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connection table's cold text (`crate::conns`, with its `endpoint` check): the refusal
//! reasons, refusal values and once-per-instance diagnostics it builds only on the rare path that
//! refuses, called out of line.

use std::fmt::Display;

use busbar_contract::conn::{ConnCause, InstanceId, NeedRefusal};

use crate::conns::compose::Failure;
use crate::conns::Verdict;

/// A guard verdict on the target (or, with `proxy`, the operator's egress proxy) as a reason: a
/// name that did not resolve is the path, never policy.
#[cold]
pub(crate) fn verdict_reason(v: Verdict, proxy: bool) -> NeedRefusal {
    let text = crate::conns::verdict_text(v);
    match (crate::conns::unresolved_here(v), proxy) {
        (true, false) => NeedRefusal::Unreached(text.to_owned()),
        (true, true) => NeedRefusal::ProxyUnreached(text.to_owned()),
        (false, false) => NeedRefusal::Policy(text),
        (false, true) => NeedRefusal::ProxyPolicy(text),
    }
}

/// A dial's failure on the target (or, with `proxy`, the hop to the operator's egress proxy) as a
/// reason: always the path, whatever the failure says.
#[cold]
pub(crate) fn unreached(f: &Failure, proxy: bool) -> NeedRefusal {
    let text = match f {
        Failure::Refused(t) | Failure::Failed(t) => t.clone(),
        Failure::Timeout => "the dial timed out".to_owned(),
        Failure::Closed | Failure::Pending => "the connection closed during the dial".to_owned(),
    };
    if proxy {
        NeedRefusal::ProxyUnreached(text)
    } else {
        NeedRefusal::Unreached(text)
    }
}

/// A plan's refusal, naming what refused it.
#[cold]
pub(crate) fn refused(e: &impl Display) -> Failure {
    Failure::Refused(format!("{e}"))
}

/// Audit a dial of `target` the trust store refused.
#[cold]
pub(crate) fn trust_refused(target: &str, refusal: &impl Display) {
    crate::conns::egress_audit::dial_refused(target, None, &format!("{refusal}"), None, &mut None);
}

/// A dial that failed at the operator's egress proxy, as its reason: the line's own cause.
#[cold]
pub(crate) fn proxy_unreached(cause: Option<ConnCause>) -> NeedRefusal {
    let text = match cause {
        Some(c) if c.stage == busbar_contract::conn::codes::CAUSE_DEADLINE => {
            "the deadline passed before the proxy opened the tunnel".to_owned()
        }
        Some(c) if !c.text.is_empty() => c.text,
        _ => "the connection closed during the dial".to_owned(),
    };
    NeedRefusal::ProxyUnreached(text)
}

/// The first time `owner` meets the ABI rule `diag`: its one coded line and its one audit record.
#[cold]
pub(crate) fn flag_first(
    owner: InstanceId,
    diag: &busbar_contract::diagnostic::Diagnostic,
    refusal: busbar_kernel::audit::auditlog::PluginRefusal,
    what: &str,
) {
    busbar_kernel::diagnostics::diag_warn!(diag, instance = owner.0, "{what}");
    busbar_kernel::audit::auditlog::record_plugin_refusal(
        refusal,
        "plugin",
        &format!("instance-{}", owner.0),
        &diag.banner().to_string(),
    );
}

/// Why an operator-infrastructure need over the framed `transport` that names no
/// config-declared target is refused.
#[cold]
pub(crate) fn untargeted_infrastructure(transport: &str) -> String {
    format!(
        "an operator-infrastructure need over the framed transport `{transport}` names no \
         config-declared target (`target_from`); the class is a property of a target the \
         operator configured, never a plugin's choice, so the need is refused"
    )
}

/// Why an upgrade offering `offered` for a dial to `dialled` is refused.
#[cold]
pub(crate) fn offered_name_refused(offered: &str, dialled: &str) -> String {
    format!(
        "upgrade_secure offered the name `{offered}` for a dial to `{dialled}`; the offered \
         name must be the dialled host (any name only for a dial to an IP literal), so the \
         upgrade is refused"
    )
}

/// Protocol bytes that are not UTF-8, as text (each bad sequence replaced).
#[cold]
pub(crate) fn lossy(bytes: &[u8]) -> String {
    format!("{}", String::from_utf8_lossy(bytes))
}
