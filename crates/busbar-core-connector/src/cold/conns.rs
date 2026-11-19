// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The connection table's cold text (`crate::conns`, with its `endpoint` check): the refusal
//! reasons, refusal values and once-per-instance diagnostics it builds only on the rare path that
//! refuses, called out of line.

use std::fmt::Display;

use busbar_contract::conn::{InstanceId, NeedRefusal};

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

/// Audit a dial of `target` the trust store refused.
#[cold]
pub(crate) fn trust_refused(target: &str, refusal: &impl Display) {
    crate::conns::egress_audit::dial_refused(target, None, &format!("{refusal}"), None, &mut None);
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

/// A native dial that did not begin, as its reason: its own cause.
#[cold]
pub(crate) fn native_unreached(failure: &crate::native_dial::NativeFailure) -> NeedRefusal {
    NeedRefusal::Unreached(format!("{failure}"))
}

/// A native open whose destination's carrier no transport image carries in this build: one line naming it.
#[cold]
#[inline(never)]
pub(crate) fn no_native_carrier(carrier: u32) {
    tracing::warn!(
        carrier,
        "an upstream dial was refused: this build assigns no transport image the destination's carrier"
    );
}

/// A native open refused because the operator's egress proxy selects its destination.
#[cold]
#[inline(never)]
pub(crate) fn native_proxy_refused(authority: &str) {
    crate::conns::egress_audit::dial_refused(
        authority,
        None,
        "the egress proxy selects this destination and a native dial does not go through a proxy",
        None,
        &mut None,
    );
}
