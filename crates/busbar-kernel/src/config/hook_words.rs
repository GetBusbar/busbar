// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOOK WORDS THIS BUILD'S HOOK ROWS DECLARE: every `MARK_WORD_HOOK` mark of a linked or
//! dropped-in `kind: hook` row's Statement, folded in by the composition root before the first
//! configuration is parsed, exactly as the plane registrations are (arch u29; OWNER LAW 2026-09-27,
//! BUSBAR-1.6.0.md l.4215: "Pool-strategy words (cheapest, fastest, least_busy, usage) are aliases
//! declared by the ranking plugin, not kernel grammar"). The pool `hooks:` grammar reads a bare word
//! as a strategy when a row declares it, and the hook-name word space reserves the declared words;
//! the kernel spells none of them.
//!
//! Data only: a word list, never a function pointer (R6). Replaced whole by each install, so a
//! plugins reload that rescans the directory can hand in the rows it found.

use std::sync::RwLock;

/// The installed words; `None` until the composition root installs them.
static DECLARED: RwLock<Option<Vec<String>>> = RwLock::new(None);

/// The words a reader sees: the installed ones, else (a test build has no root) the words the test
/// build's stand-in hook doors declare, else none.
fn with_words<T>(f: impl FnOnce(&[String]) -> T) -> T {
    let guard = DECLARED
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match guard.as_deref() {
        Some(words) => f(words),
        None => f(stand_in()),
    }
}

/// A test build's stand-in words: what its stand-in hook doors declare.
#[cfg(any(test, feature = "test-support"))]
fn stand_in() -> &'static [String] {
    static WORDS: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();
    WORDS.get_or_init(|| {
        busbar_plugin_loader::hook_door::declared_words(crate::preflight::STAND_IN_HOOK_DOORS, None)
    })
}

/// A production build declares no word until its root installs them.
#[cfg(not(any(test, feature = "test-support")))]
fn stand_in() -> &'static [String] {
    &[]
}

/// Fold in the hook words this build's hook rows declare, in declaration order (linked rows first,
/// then the dropped-in ones), each once. Replaces any earlier install.
pub fn install_declared_hook_words(words: Vec<String>) {
    let mut seen: Vec<String> = Vec::with_capacity(words.len());
    for word in words {
        if !word.is_empty() && !seen.contains(&word) {
            seen.push(word);
        }
    }
    *DECLARED
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(seen);
}

/// Whether a hook row of this build declares `word`.
#[must_use]
pub fn is_declared_hook_word(word: &str) -> bool {
    with_words(|words| words.iter().any(|w| w == word))
}

/// The declared hook words, in declaration order.
#[must_use]
pub fn declared_hook_words() -> Vec<String> {
    with_words(<[String]>::to_vec)
}
