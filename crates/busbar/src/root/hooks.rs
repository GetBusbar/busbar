// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The native hook images' facts, as config validation reads them (WP3 hook step).
//!
//! Native hooks open only in the serving walk (`min3_boot`, `min3_hooks`) and bind to native planes there; the
//! kernel opens no hook. What validation asks of hooks (which names and aliases a hook image answers to, which are
//! linked, and the D_WORD words that spell the pool ranking strategies) is read from the admitted images, published
//! by the stage that prepared them (`FileImages::publish_hooks`), the same source the serving walk binds from.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use busbar_contract::hook_calls::HookImageFacts;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::instance::Images;

/// The admitted native hook images, as they declare themselves.
struct Admitted {
    /// Every identity, name and alias of an admitted hook image, with its identity.
    names: BTreeMap<String, String>,
    /// The identities of the linked (compiled-in) hook images.
    linked: BTreeSet<String>,
    /// Every D_WORD an admitted hook image declares.
    words: BTreeSet<String>,
}

/// The native hook facts: one per process ([`NATIVE`]).
pub(crate) struct NativeHooks {
    admitted: ArcSwapOption<Admitted>,
}

/// The process's native hook facts, installed as `RootInstall.hook_facts`.
pub(crate) static NATIVE: NativeHooks = NativeHooks {
    admitted: ArcSwapOption::const_empty(),
};

impl NativeHooks {
    /// Publish the hook facts of `images`. `linked` names the identities of the linked images.
    pub(crate) fn publish_images<'a>(
        &self,
        images: &Images,
        aliases: &[(String, String)],
        linked: impl Iterator<Item = &'a str>,
    ) {
        let hooks: BTreeSet<&str> = images
            .identities()
            .filter(|identity| {
                images
                    .described(identity)
                    .is_some_and(|described| described.kind == KindCode::Hook)
            })
            .collect();
        let mut names = BTreeMap::new();
        for identity in &hooks {
            names.insert((*identity).to_owned(), (*identity).to_owned());
            for name in images.names(identity) {
                names.insert(name.to_owned(), (*identity).to_owned());
            }
        }
        for (identity, alias) in aliases {
            if hooks.contains(identity.as_str()) && !alias.is_empty() {
                names.insert(alias.clone(), identity.clone());
            }
        }
        let linked = linked
            .filter(|identity| hooks.contains(identity))
            .map(str::to_owned)
            .collect();
        let words = images
            .hook_words()
            .into_iter()
            .flat_map(|(_, words)| words.into_iter().map(str::to_owned))
            .collect();
        self.admitted.store(Some(Arc::new(Admitted {
            names,
            linked,
            words,
        })));
    }

    fn identity(&self, module: &str) -> Option<String> {
        self.admitted
            .load()
            .as_ref()
            .and_then(|admitted| admitted.names.get(module).cloned())
    }
}

impl HookImageFacts for NativeHooks {
    fn answers(&self, module: &str) -> bool {
        self.identity(module).is_some()
    }

    fn linked(&self, module: &str) -> bool {
        let Some(identity) = self.identity(module) else {
            return false;
        };
        self.admitted
            .load()
            .as_ref()
            .is_some_and(|admitted| admitted.linked.contains(&identity))
    }

    fn declares_word(&self, word: &str) -> bool {
        self.admitted
            .load()
            .as_ref()
            .is_some_and(|admitted| admitted.words.contains(word))
    }
}
