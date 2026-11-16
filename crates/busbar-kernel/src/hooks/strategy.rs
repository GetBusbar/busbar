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
///
/// 1. A configured hook instance named `word` serves the pool if its image declares the word; else CONFIG is
///    refused. 2. Else the unique admitted image declaring it serves through one implicit instance named after
///    the word (bag `{}`; the open checks its D_SCHEMA accepts that). 3. None or several: CONFIG is refused.
pub fn resolve_strategy(
    word: &str,
    configured_hooks: &[(&str, &str)],
    words: &[(&str, Vec<&str>)],
) -> Result<StrategyBinding, ConfigRefused> {
    let declares = |identity: &str| {
        words
            .iter()
            .any(|(image, ws)| *image == identity && ws.contains(&word))
    };
    if let Some((_, identity)) = configured_hooks.iter().find(|(name, _)| *name == word) {
        return match declares(*identity) {
            true => Ok(binding(word, false)),
            false => Err(text(&[
                "hook instance `",
                word,
                "` does not declare the strategy word `",
                word,
                "`",
            ])),
        };
    }
    let mut declaring = words.iter().filter(|(_, ws)| ws.contains(&word));
    match (declaring.next(), declaring.next()) {
        (Some(_), None) => Ok(binding(word, true)),
        (None, _) => Err(text(&[
            "ranking strategy `",
            word,
            "` has no admitted hook plugin",
        ])),
        (Some(_), Some(_)) => Err(text(&[
            "ranking strategy `",
            word,
            "` is declared by several hook plugins; configure `hooks.",
            word,
            "` with a `module:`",
        ])),
    }
}

fn owned(s: &str) -> Box<str> {
    let mut out = String::with_capacity(s.len());
    out.push_str(s);
    out.into_boxed_str()
}

fn binding(word: &str, implicit: bool) -> StrategyBinding {
    StrategyBinding {
        word: owned(word),
        instance: owned(word),
        implicit,
    }
}

fn text(parts: &[&str]) -> ConfigRefused {
    let mut out = String::with_capacity(parts.iter().map(|p| p.len()).sum());
    for part in parts {
        out.push_str(part);
    }
    ConfigRefused(out)
}

#[cfg(test)]
#[path = "tests/strategy_tests.rs"]
mod tests;
