// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET-SHORTHAND-BOOT MR-B2: a generation's grammar covers everything the generation reads.
//! A persisted definition is read under the grammar of the read it joins and is refused, never
//! skipped, when that grammar no longer declares its word (§3.11, R11). A read that does not fetch
//! names the `plugins.fetch` files it could not see (§3.9, R18).
//!
//! This binary installs a phase 1 double: a module declaring `fixture-word` is admissible exactly
//! when the read's `plugins.dir` holds `fixture-secret.tar.gz`.

use std::collections::BTreeMap;

use busbar_contract::abi::mechanism::door::REWRITE_SUGAR;
use busbar_contract::secret_ref::context::UNDECLARED_MARKER;
use busbar_contract::secret_ref::Sugars;
use busbar_kernel::config::grammar::{Grammar, GrammarRefusal, PhaseOneIn};
use busbar_kernel::config::EnvSubst;

const WORD: &str = "fixture-word";
const FILE: &str = "fixture-secret.tar.gz";

fn phase_one(input: &PhaseOneIn<'_>) -> Result<Grammar, GrammarRefusal> {
    let mut sugars = Sugars::default();
    if input.plugins.enabled && input.dir.join(FILE).exists() {
        sugars
            .declare(
                "fixture-secret",
                &[(REWRITE_SUGAR, WORD.into(), "slot".into())],
            )
            .expect("one module declares one word");
    }
    Ok(Grammar::new(sugars, BTreeMap::new(), Vec::new()))
}

struct Reader;
impl busbar_kernel::appbuild::RootRules for Reader {
    fn check(&self, _: &busbar_kernel::config::RootCfg) -> Result<(), String> {
        Ok(())
    }
    fn grammar(&self, input: &PhaseOneIn<'_>) -> Result<Grammar, GrammarRefusal> {
        phase_one(input)
    }
}

/// A scratch deployment: `config.yaml` (with `body` after a minimal document) and an empty
/// `plugins` directory beside it.
fn scratch(tag: &str, body: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "busbar-grammar-generation-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("plugins")).expect("scratch dir");
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!("providers: {{}}\nmodels: {{}}\nauth:\n  admin_auth: []\n{body}"),
    )
    .expect("config");
    config
}

/// R18 (§3.9, option a): a module that only `plugins.fetch` delivers cannot declare a word at the
/// first boot, because the boot fetch runs after the configuration is read. The refusal of its word
/// names the pending file and the remedies, so the operator is not left with "not declared".
#[test]
fn fetch_only_module_at_first_boot_is_refused_naming_the_fetch() {
    let config = scratch("fetch-limit", "");
    let plugins = config.parent().expect("scratch dir").join("plugins");
    let mut text = std::fs::read_to_string(&config).expect("config");
    text.push_str(&format!(
        "  signing_key: {{{WORD}: signing}}\nplugins:\n  enabled: true\n  dir: {plugins:?}\n  \
         fetch:\n    - url: https://fixtures.example/{FILE}\n      sha256: \"{}\"\n",
        "0".repeat(64)
    ));
    std::fs::write(&config, text).expect("config");
    let refused = busbar_kernel::appbuild::load_config_from_disk_judged(
        &config,
        None,
        false,
        EnvSubst::Lenient,
        &Reader,
    )
    .map(|_| ())
    .expect_err("the word's module is not in plugins.dir yet");
    assert!(
        refused.contains(UNDECLARED_MARKER) && refused.contains(WORD),
        "the word is refused as undeclared: {refused}"
    );
    assert!(
        refused.contains(&format!(
            "plugins.fetch lists \"{FILE}\", not yet in plugins.dir: the boot fetch runs after the \
             configuration is read"
        )),
        "the refusal names the file the fetch would deliver: {refused}"
    );
    let _ = std::fs::remove_dir_all(config.parent().expect("scratch dir"));
}

/// R11 (§3.11): a persisted identity-provider definition whose word no module the reload's block
/// admits declares refuses the reload, naming the section, the entry and the word. Skipping it
/// would serve a generation without it, silently.
#[test]
fn persisted_identity_provider_with_a_removed_word_refuses_reload() {
    let config = scratch("persisted-removed-word", "");
    let mut loaded = busbar_kernel::appbuild::load_config_from_disk_judged(
        &config,
        None,
        false,
        EnvSubst::Lenient,
        &Reader,
    )
    .expect("the document reads: it uses no word");
    let mut doc = busbar_kernel::config::overlay::OverlayDoc::default();
    doc.named_maps.insert(
        "identity-providers".into(),
        BTreeMap::from([(
            "stale".to_owned(),
            serde_json::json!({ "module": "keys", "token": { WORD: "signing" } }),
        )]),
    );
    loaded.overlay_doc = Some(doc);
    let refused = loaded
        .disk_candidate()
        .map(|_| ())
        .expect_err("the stored definition's word is no longer declared");
    assert!(
        refused.contains("identity-providers.stale")
            && refused.contains(UNDECLARED_MARKER)
            && refused.contains(WORD),
        "the refusal names the section, the entry and the word: {refused}"
    );
    let _ = std::fs::remove_dir_all(config.parent().expect("scratch dir"));
}

/// G10 (§3.8, hooks and root settings): the Store overlay's hook settings and root `store`
/// settings are read with the generation they join, so a word they write joins that read's used
/// set: the grammar pin compares it at admission (BUSBAR-3170), and a module whose declaration
/// changed between the read and admission refuses the generation instead of silently re-reading
/// the bag under another grammar.
#[test]
fn overlay_hook_and_root_settings_words_join_the_reads_used_set() {
    let config = scratch("overlay-bags", "");
    let plugins = config.parent().expect("scratch dir").join("plugins");
    std::fs::write(plugins.join(FILE), b"declares the word").expect("fixture file");
    let mut text = std::fs::read_to_string(&config).expect("config");
    text.push_str(&format!("plugins:\n  enabled: true\n  dir: {plugins:?}\n"));
    std::fs::write(&config, text).expect("config");
    let mut loaded = busbar_kernel::appbuild::load_config_from_disk_judged(
        &config,
        None,
        false,
        EnvSubst::Lenient,
        &Reader,
    )
    .expect("the document reads under its own block");
    let mut doc = busbar_kernel::config::overlay::OverlayDoc::default();
    doc.hooks.insert(
        "fixture-gate".to_owned(),
        serde_json::from_value(serde_json::json!({
            "kind": "gate",
            "module": "fixture-hook",
            "timeout_ms": 5,
            "on_error": "weighted",
            "settings": { "endpoint": { WORD: "hook-slot" } },
        }))
        .expect("a stored hook reads"),
    );
    doc.root = Some(
        serde_json::from_value(serde_json::json!({
            "store": { "module": "fixture-store", "settings": { "dsn": { WORD: "store-slot" } } },
        }))
        .expect("stored root settings read"),
    );
    assert!(
        !loaded
            .deploy
            .grammar
            .used()
            .expect("the read is bound")
            .words
            .contains(WORD),
        "config.yaml itself writes no word"
    );
    busbar_kernel::config::overlay::apply_root_to_deploy(&mut loaded.deploy, &doc)
        .expect("the overlay applies under the read's grammar");
    assert!(
        loaded
            .deploy
            .grammar
            .used()
            .expect("the read is bound")
            .words
            .contains(WORD),
        "the stored hook and root settings bags join the read's used words"
    );
    let _ = std::fs::remove_dir_all(config.parent().expect("scratch dir"));
}
