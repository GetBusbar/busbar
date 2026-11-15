// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COLD MODULE (LINT-RULES LR-167): the cold code the kernel's request-path modules need,
//! called out of line: refusal text, spelled only when a request, a unit or a definition is
//! refused, and the first-sight paths that key a name once and then share it. Every fn is
//! `#[cold]` or `#[inline(never)]`; none holds a loop or sweeps request data (BP17). Each section
//! is named for the request-path module it serves.

// --- hooks ---

/// `hooks`: the owned refusal text a load-bearing rewrite hook's failed call refuses the request
/// with (the contract's `TransformOutcome::Reject` carries an owned message).
#[cold]
pub(crate) fn required_hook_unavailable() -> String {
    crate::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE.to_owned()
}

/// `hooks::text_cut`: a plugin's name, keyed once on its first cut text and shared from then on.
#[cold]
pub(crate) fn first_text_cut(
    warned: &mut foldhash::HashMap<std::sync::Arc<str>, u8>,
    plugin: &str,
    bits: u8,
) -> std::sync::Arc<str> {
    let name: std::sync::Arc<str> = std::sync::Arc::from(plugin);
    warned.insert(std::sync::Arc::clone(&name), bits);
    name
}

// --- hooks::gate ---

/// `hooks::gate`: a gate's refusal in fixed words, naming the refusing gate.
#[cold]
pub(crate) fn gate_refused(
    status: u16,
    message: &'static str,
    hook: &str,
) -> crate::hooks::gate::GateVerdict {
    crate::hooks::gate::GateVerdict::Reject {
        status,
        message: message.to_owned(),
        hook: hook.to_owned(),
    }
}

/// `hooks::gate`: a gate's own rejection of the request, naming the gate.
#[cold]
pub(crate) fn gate_rejected(
    status: u16,
    message: String,
    hook: &str,
) -> crate::hooks::gate::GateVerdict {
    crate::hooks::gate::GateVerdict::Reject {
        status,
        message,
        hook: hook.to_owned(),
    }
}

/// `hooks::gate`: the name of a door tool-call member the screened document did not carry.
#[cold]
pub(crate) fn door_member(name: &'static str) -> String {
    name.to_owned()
}
// Sections as submodules (cold/<section>.rs), so the slices that fill them do not collide.
pub(crate) mod auth;
pub(crate) mod governance;
pub(crate) mod host;
