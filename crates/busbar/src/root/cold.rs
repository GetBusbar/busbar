// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COLD MODULE (LINT-RULES LR-167): the cold code the request-path modules beside it need,
//! called out of line: refusal text, spelled only when a request or a unit is refused, and the
//! first-sight paths that key a name once and then share it. Every fn is `#[cold]`; none holds a
//! loop or sweeps request data.

use foldhash::HashMap;

/// `observe`: the audit code of a plugin bind the host's connection table refused.
#[cold]
pub(crate) fn need_refusal_code(need: u32, reason: &str) -> String {
    format!("need.{need}.{reason}")
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

/// `plane_node`: a unit's terminal audit could not be confirmed durable.
#[cold]
pub(crate) fn terminal_audit_unconfirmed(error: &dyn std::fmt::Debug) -> String {
    format!("terminal audit is unconfirmed: {error:?}")
}

/// Staging refused the terminal original, so no confirmation can authorize success.
#[cold]
pub(crate) fn terminal_audit_stage_failed(error: &dyn std::fmt::Debug) -> String {
    metrics::counter!(busbar_kernel::snapshot::AUDIT_STAGE_FAILURES_TOTAL).increment(1);
    busbar_kernel::diagnostics::diag_error!(
        busbar_kernel::diagnostics::TERMINAL_AUDIT_STAGE_FAILED,
        "terminal audit staging failed; the request cannot report success"
    );
    terminal_audit_unconfirmed(error)
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
            if self.sweep_slot(&slot, now) {
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

/// `serve::serve_datagram`: caller input that arrived before the caller's channel opened, held as
/// its own copy until the channel is ready.
#[cold]
pub(crate) fn early_input(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

/// `serve`: the refusal of a media offer on a carrier no listener is configured for, naming the
/// setting to set: `<section>.<target>.listen` when an inbound need names the carrier, else the
/// carrier's own `listen`.
#[cold]
pub(crate) fn media_unlistened(section: &str, target: Option<&str>, carrier: &str) -> String {
    let setting = match target {
        Some(target) => format!("{section}.{target}.listen"),
        None => format!("the `{carrier}` listener's `listen`"),
    };
    format!(
        "this deployment serves no media for the offer: no listener is configured for its \
         `{carrier}` carrier (set `{setting}`)"
    )
}

/// `serve`: the refusal of a media offer its claim door could not open.
#[cold]
pub(crate) fn media_unopened(why: &str) -> String {
    format!("the offer cannot open a media session: {why}")
}

/// `serve`: a pool name a plane decoded that is not UTF-8, replaced lossily.
#[cold]
pub(crate) fn lossy_name(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `serve`: a datagram admission refused with its fixed reason, in the admission callback's owned
/// error.
#[cold]
pub(crate) fn admission_refused(reason: &'static str) -> String {
    reason.to_owned()
}

/// `auth_bindings`: the planned config's `plugins:` block does not read as the current block, so
/// the operator credential cannot be judged from it.
#[cold]
pub(crate) fn upgraded_plugins_unreadable(e: &busbar_contract::yaml::Error) -> String {
    format!("the upgraded `plugins:` block does not read: {e}")
}
