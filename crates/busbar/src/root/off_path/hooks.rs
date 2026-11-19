// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The native hook images' facts, as config validation reads them (WP3 hook step).
//!
//! Native hooks open only in the serving walk (`min3_boot`, `min3_hooks`) and bind to native planes there; the
//! kernel opens no hook. What validation asks of hooks (which names and aliases a hook image answers to, which are
//! linked, and the D_WORD words that spell the pool ranking strategies) is read from the admitted images, published
//! by the stage that prepared them (`FileImages::publish_hooks`), the same source the serving walk binds from.
//!
//! Off the request path (`off_path`): [`publish_images`] runs once per image preparation
//! (`boot::images`, the start and every config apply), and the [`HookImageFacts`] answers are read by
//! the kernel's configuration validation (`preflight`: hook references, ranking words, linked
//! hooks), never by a request.

use std::collections::{BTreeMap, BTreeSet};

use busbar_kernel::preflight::HookImageFacts;
use busbar_plugin_abi::types::KindCode;
use busbar_plugin_loader::instance::Images;

/// The process's native hook facts, installed as `RootInstall.hook_facts`.
pub(crate) static NATIVE: HookImageFacts = HookImageFacts::new();

/// Publish the hook facts of `images` into [`NATIVE`]. `linked` names the identities of the linked
/// images.
pub(crate) fn publish_images<'a>(
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
    NATIVE.publish(names, linked, words);
}
