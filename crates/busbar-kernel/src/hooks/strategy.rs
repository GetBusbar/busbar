// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Pool strategy words (IF §12.25): a pool's ranking strategy is operator vocabulary resolved once at config load,
//! after every image is described, against the words hook images declare (`Registry::hook_words`). Core keeps no
//! word table of its own.

/// K8. Resolved once per config load, for each pool that names a strategy word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrategyBinding<'w> {
    /// The configured or implicit instance name: the strategy word itself, as the pool spells it.
    pub instance: &'w str,
    pub implicit: bool,
}

/// Why a pool's strategy word does not resolve: CONFIG is refused with this, in its `Display` words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrategyRefused<'w> {
    /// A configured hook instance carries the word's name, and its image does not declare the word.
    NotDeclared(&'w str),
    /// No admitted hook image declares the word.
    NoPlugin(&'w str),
    /// Several admitted hook images declare the word and no configured instance settles it.
    Several(&'w str),
}

impl std::fmt::Display for StrategyRefused<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StrategyRefused::NotDeclared(word) => write!(
                f,
                "hook instance `{word}` does not declare the strategy word `{word}`"
            ),
            StrategyRefused::NoPlugin(word) => {
                write!(f, "ranking strategy `{word}` has no admitted hook plugin")
            }
            StrategyRefused::Several(word) => write!(
                f,
                "ranking strategy `{word}` is declared by several hook plugins; configure \
                 `hooks.{word}` with a `module:`"
            ),
        }
    }
}

/// `configured_hooks` = (configured instance name, image identity) for every configured hook instance; `words` =
/// (image identity, the D_WORD words it declares) for every admitted hook image.
///
/// 1. A configured hook instance named `word` serves the pool if its image declares the word; else CONFIG is
///    refused. 2. Else the unique admitted image declaring it serves through one implicit instance named after
///    the word (bag `{}`; the open checks its D_SCHEMA accepts that). 3. None or several: CONFIG is refused.
pub fn resolve_strategy<'w>(
    word: &'w str,
    configured_hooks: &[(&str, &str)],
    words: &[(&str, Vec<&str>)],
) -> Result<StrategyBinding<'w>, StrategyRefused<'w>> {
    let declares = |identity: &str| {
        words
            .iter()
            .any(|(image, ws)| *image == identity && ws.contains(&word))
    };
    if let Some((_, identity)) = configured_hooks.iter().find(|(name, _)| *name == word) {
        return match declares(identity) {
            true => Ok(StrategyBinding {
                instance: word,
                implicit: false,
            }),
            false => Err(StrategyRefused::NotDeclared(word)),
        };
    }
    let mut declaring = words.iter().filter(|(_, ws)| ws.contains(&word));
    match (declaring.next(), declaring.next()) {
        (Some(_), None) => Ok(StrategyBinding {
            instance: word,
            implicit: true,
        }),
        (None, _) => Err(StrategyRefused::NoPlugin(word)),
        (Some(_), Some(_)) => Err(StrategyRefused::Several(word)),
    }
}

#[cfg(test)]
#[path = "tests/strategy_tests.rs"]
mod tests;
