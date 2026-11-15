// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COLD MODULE (LINT-RULES LR-167): the cold code the request-path modules beside it need,
//! called out of line: refusal text, spelled only when a request or a unit is refused, and the
//! first-sight paths that key a name once and then share it. Every fn is `#[cold]`; none holds a
//! loop or sweeps request data.

use foldhash::HashMap;

/// `egress_ports`: a configured pool's depth cell, keyed once, on its first queued wait.
#[cold]
pub(crate) fn first_queued(depths: &mut HashMap<String, i64>, pool: &str, depth: i64) {
    depths.insert(pool.to_owned(), depth);
}

/// `exports`: no linked or loaded export plugin answers to `module`.
#[cold]
pub(crate) fn no_export_plugin(module: &str) -> String {
    format!("no `kind: export` plugin answers to '{module}'")
}

/// `observe`: a plugin's observation owner and its name, made and shared once, on its first
/// observation.
#[cold]
pub(crate) fn first_observed(
    owners: &mut crate::root::observe::Owners,
    plugin: &str,
) -> (
    busbar_kernel::snapshot::observe::ObservationOwner,
    std::sync::Arc<str>,
) {
    let name: std::sync::Arc<str> = std::sync::Arc::from(plugin);
    let known = (
        busbar_kernel::snapshot::observe::ObservationOwner::default(),
        name.clone(),
    );
    owners.insert(name, known.clone());
    known
}

/// `observe`: the audit code of a plugin bind the host's connection table refused.
#[cold]
pub(crate) fn need_refusal_code(need: u32, reason: &str) -> String {
    format!("need.{need}.{reason}")
}

/// `inbound`: a listener registration's stream policy for one published generation, built once,
/// on the registration's first use of that generation, then cached: fresh line ids, each line's
/// minted auth reference, and the policy extensions encoded once.
#[cold]
pub(crate) fn listener_stream_policy(
    owner: u64,
    listener_id: u64,
    generation: u64,
    selected: &busbar_kernel::inbound::Listener,
) -> Option<crate::root::loader::dispatch::auth_handle::StreamPolicy> {
    use crate::root::loader::dispatch::auth_handle::{self, StreamPolicy};
    use busbar_contract::abi::mechanism::extensions;
    use busbar_contract::abi::transport::guest_policy::{self, GuestLine, Identity, Policy};
    let mut listener = selected.clone();
    listener.ids = listener
        .guests
        .lines()
        .iter()
        .map(|_| auth_handle::next_ref_id(auth_handle::RefSpace::Line))
        .collect();
    let lines = listener
        .specs()
        .into_iter()
        .zip(listener.guests.lines())
        .map(|(spec, line)| {
            Some(GuestLine {
                line: spec.line,
                points: spec.points,
                auth: auth_handle::mint_auth_ref(owner, generation, spec.auth)?,
                body_limit: spec.body_limit,
                methods: line.route.methods,
                path_form: line.route.path_form,
                path: line.route.path.clone(),
                fields: line.route.fields.clone(),
                rung: line.route.rung,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    let policy = std::sync::Arc::new(Policy {
        listener: listener_id,
        generation,
        lines,
    });
    let bytes = guest_policy::encode(listener_id, generation, &policy.lines).ok()?;
    let identity = Identity {
        listener: listener_id,
        generation,
    }
    .encode()
    .ok()?;
    Some(StreamPolicy {
        policy,
        full: extensions::encode(&[(guest_policy::EXT_GUEST_POLICY, &bytes)]).into(),
        current: extensions::encode(&[(guest_policy::EXT_GUEST_CURRENT, &identity)]).into(),
    })
}

/// `inbound`: the line ids of the kernel table a listener registration installs, once per
/// published generation.
#[cold]
pub(crate) fn installed_line_ids(
    policy: &crate::root::loader::dispatch::auth_handle::StreamPolicy,
) -> Vec<u64> {
    policy
        .policy
        .lines
        .iter()
        .map(|line| line.auth.id)
        .collect()
}

/// `listener::framed`: the reason a failed body piece hands its reader, once, as the stream ends.
#[cold]
pub(crate) fn failed_piece_reason(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `model_egress`: the name of a pool outside the plan, which has no breaker ladder to share
/// a name from, copied once per held probe.
#[cold]
pub(crate) fn unplanned_cell_name(cell: &str) -> std::sync::Arc<str> {
    std::sync::Arc::from(cell)
}

/// `plane_node`: a registered lane's name, keyed once, on its first resolve.
#[cold]
pub(crate) fn first_resolved(
    resolved: &mut HashMap<String, busbar_contract::LaneId>,
    name: &str,
    lane: busbar_contract::LaneId,
) {
    resolved.insert(name.to_owned(), lane);
}

/// `plane_node`: the native journal refused a held flush.
#[cold]
pub(crate) fn native_journal_refused(error: &dyn std::fmt::Debug) -> String {
    format!("native journal: {error:?}")
}

/// `plane_node`: a unit's terminal audit could not be confirmed durable (its test-only late body).
#[cfg(test)]
#[cold]
pub(crate) fn terminal_audit_unconfirmed(error: &dyn std::fmt::Debug) -> String {
    format!("terminal audit is unconfirmed: {error:?}")
}

/// `plane_node`: the usage line a lost unit is sealed with, gathered only when the tick sweeps a
/// unit that lost its owner.
#[cold]
pub(crate) fn lost_unit_lines(
    line: busbar_kernel_audit::UsageLine,
) -> Vec<busbar_kernel_audit::UsageLine> {
    busbar_kernel::Registration::meter_class(line.class.as_str())
        .filter(|class| *class != busbar_kernel::teller::KERNEL_ACCRUAL_CLASS)
        .map(|class| busbar_kernel_audit::UsageLine { class, ..line })
        .into_iter()
        .collect()
}

impl crate::root::plane_node::Node {
    /// `plane_node`: the tick's sweep of the units marked lost, run only when a unit lost its
    /// owner since the last sweep.
    #[cold]
    pub(crate) fn sweep_marked(&self, now: crate::root::plane_node::Arrived) -> usize {
        let mut swept = 0;
        for slot in self.inflight.snapshot() {
            if self.sweep_slot(slot, now) {
                swept += 1;
            }
        }
        swept
    }
}

/// `serve::serve_datagram`: the claim door refused an association.
#[cold]
pub(crate) fn association_refused(error: &dyn std::fmt::Debug) -> String {
    format!("the claim door refused the association: {error:?}")
}

/// `serve::serve_datagram`: the session book refused a unit's pairing.
#[cold]
pub(crate) fn session_book_refused(error: &dyn std::fmt::Debug) -> String {
    format!("the session book refused the unit: {error:?}")
}

/// `serve`'s framed and neutral callers: the status words of a unit cut short mid-emit, kept until
/// its stream returns from the plugin.
#[cold]
pub(crate) fn cut_short_status(message: &[u8], details: &[u8]) -> (Vec<u8>, Vec<u8>) {
    (message.to_vec(), details.to_vec())
}
