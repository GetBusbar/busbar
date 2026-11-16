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
    assert_eq!(
        grammar_for(&PhaseOneIn::of(&off), &crate::appbuild::AcceptAll),
        Ok(Grammar::empty())
    );
    let on = PluginsCfg {
        enabled: true,
        ..PluginsCfg::default()
    };
    let refused = grammar_for(&PhaseOneIn::of(&on), &crate::appbuild::AcceptAll)
        .expect_err("nothing can scan the directory");
    assert!(refused.0.contains("no composition root"), "{refused}");
}

const WORD: &str = "fixture-word";

fn declaring(setting: &str) -> Sugars {
    let mut sugars = Sugars::default();
    sugars
        .declare(
            "fixture-secret",
            &[(
                busbar_contract::abi::mechanism::door::REWRITE_SUGAR,
                WORD.into(),
                setting.into(),
            )],
        )
        .expect("one module declares one word");
    sugars
}

fn owned(version: &str) -> BTreeMap<String, Owner> {
    BTreeMap::from([(
        "fixture-secret".to_owned(),
        Owner {
            version: version.into(),
            origin: format!("fixture-secret-{version}.tar.gz"),
            trust: "first-party".into(),
        },
    )])
}

fn using(word: &str) -> Used {
    Used {
        words: BTreeSet::from([word.to_owned()]),
        ..Used::default()
    }
}

/// G5 (§3.8): the word's module replaced between the read and admission by a version declaring a
/// different setting refuses with BUSBAR-3170, naming both files and both settings. A new version
/// with an equal declaration never refuses, and neither does a word the configuration does not use.
#[test]
fn a_used_word_whose_declaration_changed_refuses_naming_both_files() {
    let read = Grammar::new(declaring("name"), owned("1.6.0"), Vec::new());
    let changed = Grammar::new(declaring("var"), owned("1.7.0"), Vec::new());
    let refused = pin(&read, &changed, &using(WORD), Pin::Admission)
        .expect_err("the used word's declaration changed");
    for part in [
        "BUSBAR-3170",
        "fixture-secret-1.6.0.tar.gz",
        "fixture-secret-1.7.0.tar.gz",
        "setting `name`",
        "setting `var`",
        "plugins.dir changed after the configuration was read",
    ] {
        assert!(refused.contains(part), "{part}: {refused}");
    }
    let upgraded = Grammar::new(declaring("name"), owned("1.7.0"), Vec::new());
    assert_eq!(pin(&read, &upgraded, &using(WORD), Pin::Admission), Ok(()));
    assert_eq!(
        pin(&read, &changed, &Used::default(), Pin::Admission),
        Ok(())
    );
}

/// G7 (§3.8): a word that appears only at admission, used inside a plugin settings bag, would turn
/// that map into a reference after the read: the parse records bag words, and the pin refuses.
#[test]
fn a_bag_word_only_admission_declares_refuses() {
    let read = Grammar::empty();
    let deploy = crate::config::deploy_from_yaml_str(
        "providers: {}\nmodels: {}\nstore:\n  module: fixture-store\n  settings:\n    path: \
         {fixture-word: db}\n    other: 1\n",
        &read,
    )
    .expect("a settings bag holds any map");
    let used = deploy.grammar.used().expect("the read is bound");
    assert!(used.words.contains(WORD), "{used:?}");
    let admitted = Grammar::new(declaring("slot"), owned("1.6.0"), Vec::new());
    let refused = pin(&read, &admitted, used, Pin::Admission)
        .expect_err("admission declares a word the read did not");
    assert!(
        refused.contains("BUSBAR-3170") && refused.contains("no admitted secret module"),
        "{refused}"
    );
}

/// G11 (§3.7): at boot, the Store's pins selecting a different declaration than config.yaml's own
/// block refuses, naming the offline recovery (no server runs to call).
#[test]
fn the_boot_pin_names_the_offline_recovery() {
    let start = Grammar::new(declaring("name"), owned("1.7.0"), Vec::new());
    let pinned = Grammar::new(declaring("var"), owned("1.6.0"), Vec::new());
    let refused = pin(&start, &pinned, &using(WORD), Pin::Store).expect_err("the pin changes it");
    assert!(
        refused.contains("--ignore-overlay") && refused.contains("plugins/rollback"),
        "{refused}"
    );
    let refused =
        pin(&start, &pinned, &using(WORD), Pin::NextBoot).expect_err("so would the next start");
    assert!(
        refused.contains("the next restart would refuse it"),
        "{refused}"
    );
}

/// §3.6: a section or style compares its module, image and standing; a plane replaced in place
/// counts (restart-to-apply) and refuses nothing, a removed one is refused with its cause.
#[test]
fn process_lifetime_items_compare_and_refuse_by_standing() {
    let item = |standing: Standing, image: &str| Item {
        kind: ItemKind::Section,
        name: "fixture-plane".into(),
        module: "fixture-plane-module".into(),
        image: image.into(),
        standing,
    };
    let running = Grammar::empty().with_items(vec![item(Standing::Counts, "a")]);
    let replaced = Grammar::empty().with_items(vec![item(Standing::Replaced, "a")]);
    let removed = Grammar::empty().with_items(vec![item(
        Standing::NotAdmitted("\"fixture-plane.tar.gz\" is no longer in plugins.dir".into()),
        "a",
    )]);
    assert_eq!(
        running.item_refusal(ItemKind::Section, "fixture-plane"),
        None
    );
    assert_eq!(
        replaced.item_refusal(ItemKind::Section, "fixture-plane"),
        None
    );
    assert_eq!(replaced.replaced().count(), 1);
    let refused = removed
        .item_refusal(ItemKind::Section, "fixture-plane")
        .expect("a removed plane's section is refused");
    assert!(refused.contains("is no longer in plugins.dir"), "{refused}");
    let used = Used {
        sections: BTreeSet::from(["fixture-plane".to_owned()]),
        ..Used::default()
    };
    assert_eq!(pin(&running, &replaced, &used, Pin::Admission), Ok(()));
    let refused = pin(&running, &removed, &used, Pin::Admission)
        .expect_err("the section's standing changed between the read and admission");
    assert!(refused.contains("BUSBAR-3170"), "{refused}");
}

/// R18 (§3.9): a `plugins.fetch` file not yet in the read's directory gets one line, naming the
/// file only; a file already there gets none.
#[test]
fn a_pending_fetch_file_gets_one_line() {
    let dir = std::env::temp_dir().join(format!("busbar-grammar-fetch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    let plugins: PluginsCfg = busbar_contract::yaml::from_str(&format!(
        "enabled: true\ndir: {dir:?}\nfetch:\n  - url: https://fixtures.example/pending.tar.gz\n  \
         - url: https://fixtures.example/present.tar.gz\n"
    ))
    .expect("a plugins block");
    std::fs::write(dir.join("present.tar.gz"), b"staged").expect("stage a file");
    let lines = pending_fetch_lines(&plugins, &dir);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].starts_with("plugins.fetch lists \"pending.tar.gz\""),
        "{lines:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
