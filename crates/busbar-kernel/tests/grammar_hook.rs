// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! SECRET-SHORTHAND-BOOT MR-B (§3.3, §3.4): every configuration read computes its grammar through
//! the root's phase 1 (`RootRules::grammar`) from that read's own `plugins:` block, and the typed
//! document carries it. This binary installs a phase 1 double: a module declaring `fixture-word`
//! is admissible exactly when the block enables `plugins.dir` = `fixture-plugins`.

use busbar_contract::abi::mechanism::door::REWRITE_SUGAR;
use busbar_contract::secret_ref::context::UNDECLARED_MARKER;
use busbar_contract::secret_ref::Sugars;
use busbar_kernel::config::grammar::{Grammar, GrammarRefusal, PhaseOneIn};
use busbar_kernel::config::EnvSubst;

const WORD: &str = "fixture-word";
const DIR: &str = "fixture-plugins";
const SKIP: &str = "\"fixture-other.tar.gz\" (kind secret) was not admitted: unsigned";

fn phase_one(input: &PhaseOneIn<'_>) -> Result<Grammar, GrammarRefusal> {
    if input.plugins.enabled && input.dir == std::path::Path::new(DIR) {
        let mut sugars = Sugars::default();
        sugars
            .declare(
                "fixture-secret",
                &[(REWRITE_SUGAR, WORD.into(), "slot".into())],
            )
            .expect("one module declares one word");
        return Ok(Grammar::new(sugars, Default::default(), Vec::new()));
    }
    Ok(Grammar::new(
        Sugars::default(),
        Default::default(),
        vec![SKIP.to_owned()],
    ))
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

fn scratch(tag: &str, body: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("busbar-grammar-hook-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let config = dir.join("config.yaml");
    std::fs::write(
        &config,
        format!("providers: {{}}\nmodels: {{}}\nauth:\n  admin_auth: []\n  signing_key: {{{WORD}: signing}}\n{body}"),
    )
    .expect("config");
    config
}

/// A read whose own block admits the declaring module reads the word, and the typed document and
/// its resolved configuration carry that read's grammar.
#[test]
fn a_read_parses_under_the_grammar_its_own_block_admits() {
    let config = scratch(
        "admits",
        &format!("plugins:\n  enabled: true\n  dir: {DIR}\n"),
    );
    let loaded = busbar_kernel::appbuild::load_config_from_disk_judged(
        &config,
        None,
        false,
        EnvSubst::Lenient,
        &Reader,
    )
    .expect("the read's own block admits the word's module");
    let grammar = loaded
        .deploy
        .grammar
        .get()
        .expect("the read binds its grammar");
    assert!(grammar.sugars.get(WORD).is_some());
    let cfg = busbar_kernel::config::resolve(&loaded.deploy, &loaded.defs)
        .expect("the document resolves");
    assert_eq!(
        cfg.grammar(),
        Ok(grammar),
        "resolve carries the read's grammar"
    );
    let _ = std::fs::remove_dir_all(config.parent().expect("scratch dir"));
}

/// A read whose own block does not admit it refuses the word, and the refusal carries the read's
/// report: the file its module would have come from and why it was not admitted.
#[test]
fn a_refused_word_names_what_the_read_did_not_admit() {
    let config = scratch("refuses", "");
    let refused = busbar_kernel::appbuild::load_config_from_disk_judged(
        &config,
        None,
        false,
        EnvSubst::Lenient,
        &Reader,
    )
    .map(|_| ())
    .expect_err("no block admits the word's module");
    assert!(
        refused.contains(UNDECLARED_MARKER) && refused.contains(SKIP),
        "the refusal names the word and carries the read's report: {refused}"
    );
    let _ = std::fs::remove_dir_all(config.parent().expect("scratch dir"));
}
