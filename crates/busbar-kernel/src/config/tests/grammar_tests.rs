// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

/// G23: a configuration decoded without a grammar refuses when its grammar is read; it never
/// defaults to one.
#[test]
fn an_unbound_grammar_refuses_on_read() {
    let refused = GrammarField::default()
        .get()
        .expect_err("the default field is unbound");
    assert!(refused.0.contains("decoded without a grammar"), "{refused}");
    let bound = GrammarField::bound(Grammar::empty());
    assert_eq!(bound.get(), Ok(&Grammar::empty()));
}

/// A refusal carries the read's report lines, one per file the scan did not admit.
#[test]
fn a_refusal_carries_the_report() {
    let grammar = Grammar::new(
        Sugars::default(),
        BTreeMap::new(),
        vec!["\"fixture.tar.gz\" (kind secret) was not admitted: unsigned".into()],
    );
    assert_eq!(
        grammar.with_report("refused"),
        "refused\n  - \"fixture.tar.gz\" (kind secret) was not admitted: unsigned"
    );
}

/// With no composition root (this test binary), a read that loads no plugin admits nothing, and a
/// read that would scan `plugins.dir` is refused rather than read under a smaller grammar.
#[test]
fn without_a_root_only_a_read_that_loads_no_plugin_has_a_grammar() {
    let off = PluginsCfg::default();
    assert_eq!(grammar_for(&PhaseOneIn::of(&off)), Ok(Grammar::empty()));
    let on = PluginsCfg {
        enabled: true,
        ..PluginsCfg::default()
    };
    let refused = grammar_for(&PhaseOneIn::of(&on)).expect_err("nothing can scan the directory");
    assert!(refused.0.contains("no composition root"), "{refused}");
}
