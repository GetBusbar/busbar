// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use busbar_kernel::appbuild::RootRules;
use busbar_kernel::config::grammar::{Grammar, GrammarRefusal, PhaseOneIn};

struct Reader(&'static str);
impl RootRules for Reader {
    fn check(&self, _: &busbar_kernel::config::RootCfg) -> Result<(), String> {
        Ok(())
    }
    fn grammar(&self, _: &PhaseOneIn<'_>) -> Result<Grammar, GrammarRefusal> {
        Ok(Grammar::new(
            Default::default(),
            Default::default(),
            vec![self.0.into()],
        ))
    }
}

#[test]
fn separate_readers_keep_their_owned_grammar_context() {
    let plugins = busbar_kernel::config::PluginsCfg::default();
    let input = PhaseOneIn::of(&plugins);
    let first = Reader("first process");
    let second = Reader("second process");
    assert_eq!(
        busbar_kernel::config::grammar::grammar_for(&input, &first)
            .unwrap()
            .report(),
        &["first process"]
    );
    assert_eq!(
        busbar_kernel::config::grammar::grammar_for(&input, &second)
            .unwrap()
            .report(),
        &["second process"]
    );
    assert_eq!(
        busbar_kernel::config::grammar::grammar_for(&input, &first)
            .unwrap()
            .report(),
        &["first process"]
    );
}
