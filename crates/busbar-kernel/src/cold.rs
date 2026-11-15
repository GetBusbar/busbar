// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE COLD MODULE (LINT-RULES LR-167): the cold code the kernel's request-path modules need,
//! called out of line: refusal text, spelled only when a request, a unit or a definition is
//! refused, and the first-sight paths that key a name once and then share it. Every fn is
//! `#[cold]` or `#[inline(never)]`; none holds a loop or sweeps request data (BP17). Each section
//! is named for the request-path module it serves.

// --- plane_driver::hooks (mod.rs, gated.rs, policy.rs) ---

/// `plane_driver::hooks`: a refusal by a named hook, which names it.
#[cold]
pub(crate) fn hooks_veto_by(
    status: u16,
    text: impl Into<String>,
    hook: &str,
) -> crate::plane_driver::hooks::Stopped {
    crate::plane_driver::hooks::Stopped::Veto(crate::plane_driver::hooks::Veto {
        status: u32::from(status),
        text: text.into(),
        hook: Some(hook.to_owned()),
    })
}

/// `plane_driver::hooks`: a `(policy, pool)` pair, keyed once, the first time its window opens.
#[cold]
pub(crate) fn hooks_pair_first_seen(
    window: &mut crate::plane_driver::hooks::PairWindow,
    policy: &str,
    pool: &str,
) {
    if let Some(pools) = window.get_mut(policy) {
        pools.insert(pool.to_owned());
        return;
    }
    let mut pools = foldhash::HashSet::default();
    pools.insert(pool.to_owned());
    window.insert(policy.to_owned(), pools);
}

/// `plane_driver::hooks`: a session stage stopped because the content access audit is unconfirmed.
#[cold]
pub(crate) fn hooks_audit_unconfirmed() -> String {
    "content access audit is unconfirmed".to_owned()
}

/// `plane_driver::hooks`: a session stage stopped by an unavailable required gate.
#[cold]
pub(crate) fn hooks_required_unavailable() -> String {
    crate::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE.to_owned()
}

/// `plane_driver::hooks`: scanned content that is not UTF-8, as its wiped lossy text.
#[cold]
pub(crate) fn hooks_lossy_content(content: &[u8]) -> busbar_contract::secure::SecureString {
    busbar_contract::secure::SecureString::from(String::from_utf8_lossy(content).into_owned())
}

/// `plane_driver::hooks::gated`: a rewrite the plane could not apply, refused in the fault words.
#[cold]
pub(crate) fn hooks_project_fault_words() -> String {
    busbar_contract::abi::plane::PROJECT_FAULT_MESSAGE.to_owned()
}

/// `plane_driver::hooks::gated`: a refusal's words, kept as they came.
#[cold]
pub(crate) fn hooks_owned_words(words: &str) -> String {
    words.to_owned()
}

/// `plane_driver::hooks::policy`: a hook past its deadline.
#[cold]
pub(crate) fn hook_policy_deadline_exceeded(budget: std::time::Duration) -> String {
    format!("hook plugin deadline ({budget:?}) exceeded")
}

/// `plane_driver::hooks::policy`: a hook that could not answer.
#[cold]
pub(crate) fn hook_policy_could_not_answer(name: &str, error: Option<String>) -> String {
    format!(
        "hook {name} could not answer: {}",
        error.unwrap_or_default()
    )
}

// --- plane_driver::far_end ---

/// `plane_driver::far_end`: a provider's credential refusal, keyed once, on its first refusal.
#[cold]
pub(crate) fn far_end_first_refusal(
    last: &mut foldhash::HashMap<String, busbar_contract::conn::ConnError>,
    provider: &str,
    err: busbar_contract::conn::ConnError,
) {
    last.insert(provider.to_owned(), err);
}
