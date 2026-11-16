// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! 1t, the template rule (MIGRATE-ON-BOOT §A3 1t): the chain converts the template, a moved value
//! keeps its `${VAR}`, a value a pass must compute from a template slot refuses, an unset variable
//! refuses as 1.5.5 refused to boot, and proof two catches a lost quote.

use busbar_contract::yaml::ValueExt;

use super::*;
use crate::scratch::{accept, facts, Scratch};
use crate::{plan, write, Facts, Inputs, Written};

fn env(name: &str) -> Option<String> {
    match name {
        "P" => Some("8080".to_owned()),
        "RATE" => Some("3".to_owned()),
        "ADMIN" => Some("127.0.0.1:8081".to_owned()),
        _ => None,
    }
}

fn with_env() -> Facts {
    Facts { env, ..facts() }
}

/// A `${VAR}` the chain does not touch stays a reference in the written file; the boot's parse
/// reads the interpolated document, never a resolved value written to disk.
#[test]
fn a_template_slot_is_kept_as_written_and_the_parse_reads_it_interpolated() {
    let scratch = Scratch::new();
    let path = scratch.deployment("admin_listen: '${ADMIN}'\nlisten: x\n");
    let seen = std::cell::RefCell::new(String::new());
    let check = |text: &str, _: Option<&str>| -> Result<(), String> {
        seen.borrow_mut().push_str(text);
        Ok(())
    };
    let facts = with_env();
    let planned = plan(&Inputs::new(&path, &facts, &check)).expect("planned");
    assert!(
        seen.borrow().contains("admin_listen: '127.0.0.1:8081'"),
        "{}",
        seen.borrow()
    );
    assert_eq!(write(&planned, &accept), Ok(Written::Stamped));
    let written = std::fs::read_to_string(&path).unwrap();
    assert!(written.contains("admin_listen: '${ADMIN}'\n"), "{written}");
    assert!(!written.contains("127.0.0.1:8081"), "{written}");
}

/// A pass that must compute a new value from a template slot refuses CONFIG naming the path, and
/// quotes no value.
#[test]
fn a_value_computed_from_a_template_slot_is_refused() {
    let scratch = Scratch::new();
    let path = scratch
        .deployment("rate_card:\n  claude: {input_utok: '${RATE}'}\nstore: {module: sqlite}\n");
    let facts = Facts {
        open_units: vec!["cache_write_30m".to_owned()],
        ..with_env()
    };
    let refused = plan(&Inputs::new(&path, &facts, &accept)).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    let text = refused.to_string();
    assert!(
        text.contains("`rate_card.claude.input_utok` uses `${VAR}`"),
        "{text}"
    );
    assert!(
        !text.contains("input_utok: 3"),
        "no resolved value is quoted: {text}"
    );
    assert_eq!(scratch.names(), ["config.yaml", "providers.yaml"]);
}

#[test]
fn templated_write_rate_refusal_names_only_missing_units_and_the_selected_source() {
    for (rates, source, existing) in [
        ("input_utok: '${RATE}'", "input_utok", ""),
        (
            "input_utok: 1, cache_write_utok: '${RATE}'",
            "cache_write_utok",
            ", units: {cache_write_12h: 7}",
        ),
    ] {
        let scratch = Scratch::new();
        let original =
            format!("rate_card:\n  model: {{{rates}{existing}}}\nstore: {{module: sqlite}}\n");
        let path = scratch.deployment(&original);
        let facts = Facts {
            open_units: vec!["cache_write_30m".to_owned(), "cache_write_12h".to_owned()],
            ..with_env()
        };
        let refused = plan(&Inputs::new(&path, &facts, &accept)).unwrap_err();
        assert_eq!(refused.word(), "CONFIG");
        let text = refused.to_string();
        assert!(
            text.contains("`rate_card.model.units.cache_write_30m`"),
            "{text}"
        );
        assert_eq!(
            text.contains("`rate_card.model.units.cache_write_12h`"),
            existing.is_empty(),
            "{text}"
        );
        assert!(
            text.contains(&format!("same rate as `rate_card.model.{source}`")),
            "{text}"
        );
        assert!(text.contains("quoted decimal reference"), "{text}");
        assert!(
            !text.contains("${RATE}"),
            "the authored value is not quoted: {text}"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), original);
        assert_eq!(scratch.names(), ["config.yaml", "providers.yaml"]);
    }
}

/// An unset variable refuses with the interpolation's own text, as 1.5.5 refused to boot.
#[test]
fn an_unset_variable_refuses() {
    let scratch = Scratch::new();
    let path = scratch.deployment("listen: '${NOT_SET}'\nstore: {module: sqlite}\n");
    let refused = plan(&Inputs::new(&path, &with_env(), &accept)).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(refused.to_string().contains("NOT_SET"), "{refused}");
    assert_eq!(scratch.names(), ["config.yaml", "providers.yaml"]);
}

/// Proof two: `"${P}"` and `${P}` are one template string; only the interpolated reading differs
/// (a string and an integer). A patch that lost the quote is refused VERIFY naming the path.
#[test]
fn proof_two_catches_a_lost_quote() {
    let template = Template::read("port: \"${P}\"\nname: x\n", env, "config.yaml").unwrap();
    let after = template.tree().clone();
    template
        .parity("port: \"${P}\"\nname: x\n", &after, env, "config.yaml")
        .expect("the same text reads the same");
    let refused = template
        .parity("port: ${P}\nname: x\n", &after, env, "config.yaml")
        .unwrap_err();
    assert_eq!(refused.word(), "VERIFY");
    assert!(refused.to_string().contains("`port`"), "{refused}");
    assert!(is_template(template.tree().at("port")));
    assert!(!is_template(template.tree().at("name")));
}
