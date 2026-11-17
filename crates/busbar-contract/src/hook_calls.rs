// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! What the host knows of a hook image without calling it: the facts a hook Statement states, and
//! the admitted native hook images' facts config validation reads. The hook calls themselves are
//! the native bindings' (`busbar_ports::hook::HookPort`).

/// What a hook plugin states about itself: its Statement name and its kind tail's facts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HookFacts {
    /// The Statement's name.
    pub name: String,
    /// [`crate::abi::hook::CLASS_GATE`] | [`crate::abi::hook::CLASS_TAP`].
    pub class: u32,
    /// The prompt access the plugin declares: [`crate::abi::hook::PROMPT_NO`] | `_RO` | `_RW`.
    pub prompt: u32,
    /// The user access the plugin declares: [`crate::abi::hook::USER_NO`] | `_RO`.
    pub user: u32,
    /// Whether the plugin declares itself infallible.
    pub infallible: bool,
    /// The hook words the plugin declares (its Statement's `MARK_WORD_HOOK` word marks).
    pub words: Vec<String>,
}

/// THE NATIVE HOOK IMAGES' FACTS, as config validation asks them (WP3 hook step). Native hooks open only in the
/// serving walk and bind to native planes there; validation reads only what the admitted images declare.
pub trait HookImageFacts: Send + Sync {
    /// Whether an admitted hook image answers to `module` (its identity, a name or an alias).
    fn answers(&self, module: &str) -> bool;

    /// Whether `module` names a hook image this build LINKS (as opposed to one dropped in).
    fn linked(&self, module: &str) -> bool;

    /// Whether some admitted hook image declares `word` (a D_WORD item): a pool ranking strategy's spelling.
    fn declares_word(&self, word: &str) -> bool;
}
