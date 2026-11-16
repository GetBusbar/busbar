// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pool strategy words (IF §12.25): a pool's ranking strategy is operator vocabulary resolved once at config load,
//! after every image is described, against the words hook images declare (`Registry::hook_words`). Core keeps no
//! word table of its own.

use crate::path_claims::ConfigRefused;

/// K8. Resolved once per config load, for each pool that names a strategy word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategyBinding {
    pub word: Box<str>,
    /// The configured or implicit instance name.
    pub instance: Box<str>,
    pub implicit: bool,
}

/// `configured_hooks` = (configured instance name, image identity) for every configured hook instance; `words` =
/// (image identity, the D_WORD words it declares) for every admitted hook image.
pub fn resolve_strategy(
    word: &str,
    configured_hooks: &[(&str, &str)],
    words: &[(&str, Vec<&str>)],
) -> Result<StrategyBinding, ConfigRefused> {
    let _ = (word, configured_hooks, words);
    todo!()
}

#[cfg(test)]
#[path = "tests/strategy_tests.rs"]
mod tests;
