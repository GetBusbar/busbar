// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Decision 16: settings that name the retired carrier modules `tcp` and `stdio` are accepted and ignored, with
//! one report line per carrier; a `transport:` section that names anything else is judged as it always was.

use busbar_contract::yaml::{self, Value, ValueExt};

use super::*;

fn tree(text: &str) -> Value {
    yaml::from_str(text).expect("fixture parses")
}

/// The pass on `source` (no template slots: the template tree and the interpolated document are the same).
fn dropped(source: &str) -> (Value, Vec<String>) {
    let resolved = tree(source);
    let mut after = resolved.clone();
    let mut report = Vec::new();
    drop_retired(
        after.as_mapping_mut().expect("a mapping"),
        &resolved,
        &mut report,
    );
    (after, report)
}

#[test]
fn every_spelling_of_the_two_modules_is_a_retired_carrier_and_nothing_else_is() {
    for word in ["tcp", "transport-tcp", "busbar-transport-tcp"] {
        assert_eq!(retired(word), Some("busbar-transport-tcp"), "{word}");
    }
    for word in ["stdio", "transport-stdio", "busbar-transport-stdio"] {
        assert_eq!(retired(word), Some("busbar-transport-stdio"), "{word}");
    }
    for word in [
        "",
        "http",
        "ws",
        "grpc",
        "webrtc",
        "TCP",
        "tcp ",
        "tcps",
        "stdio2",
        "busbar-transport",
    ] {
        assert_eq!(retired(word), None, "{word:?}");
    }
}

#[test]
fn a_section_of_only_retired_carriers_is_accepted_and_any_other_is_not() {
    for accepted in [
        "transport:\n  tcp: {module: tcp}\n",
        "transport:\n  wire: {module: tcp}\n  pipes: {module: stdio, max_line_bytes: 1048576}\n",
        "transport:\n  wire: tcp\n",
        "listen: \"127.0.0.1:8080\"\ntransport:\n  a: {module: busbar-transport-stdio}\n",
    ] {
        assert!(only_retired(&tree(accepted)), "{accepted}");
    }
    for judged in [
        "listen: \"127.0.0.1:8080\"\n",
        "transport: {}\n",
        "transport: tcp\n",
        "transport:\n  - {module: tcp}\n",
        "transport:\n  web: {module: http}\n",
        "transport:\n  wire: {module: tcp}\n  web: {module: http}\n",
        "transport:\n  wire: {settings: {}}\n",
        "transport:\n  wire: {module: 7}\n",
    ] {
        assert!(!only_retired(&tree(judged)), "{judged}");
    }
}

#[test]
fn the_entries_are_removed_with_one_line_per_carrier_and_the_section_goes_with_its_last_entry() {
    let (after, report) = dropped(
        "listen: \"127.0.0.1:8080\"\n\
         transport:\n  wire: {module: tcp}\n  pipes: {module: stdio, max_line_bytes: 1048576}\n  wire2: {module: tcp}\n\
         store: {module: memory}\n",
    );
    assert_eq!(
        after,
        tree("listen: \"127.0.0.1:8080\"\nstore: {module: memory}\n"),
        "the section is gone and every other key keeps its place"
    );
    assert_eq!(report.len(), 2, "{report:?}");
    assert!(
        report[0].starts_with(
            "transport.wire removed: the `busbar-transport-tcp` plugin is retired in 1.6.0 and its settings \
             are accepted and ignored. "
        ),
        "{}",
        report[0]
    );
    assert!(
        report[1].starts_with("transport.pipes removed: the `busbar-transport-stdio` plugin"),
        "{}",
        report[1]
    );
    assert!(report[1].contains("4 MiB"), "{}", report[1]);
    for line in &report {
        assert!(
            !line.contains("1048576"),
            "a report line never quotes a setting: {line}"
        );
    }
}

#[test]
fn a_living_transport_beside_a_retired_one_keeps_the_section() {
    let (after, report) = dropped("transport:\n  wire: {module: tcp}\n  web: {module: http}\n");
    assert_eq!(after, tree("transport:\n  web: {module: http}\n"));
    assert_eq!(report.len(), 1);
}

#[test]
fn a_document_that_names_neither_is_untouched_and_reports_nothing() {
    for source in [
        "listen: \"127.0.0.1:8080\"\n",
        "transport:\n  web: {module: http}\n",
        "transport: {}\n",
        "transport: tcp\n",
    ] {
        let (after, report) = dropped(source);
        assert_eq!(after, tree(source), "{source}");
        assert!(report.is_empty(), "{source}: {report:?}");
    }
}

#[test]
fn the_pass_is_a_fixed_point() {
    let (once, _) = dropped("transport:\n  wire: {module: tcp}\nstore: {module: memory}\n");
    let text = yaml::to_string(&once).expect("the tree prints");
    let (twice, report) = dropped(&text);
    assert_eq!(twice, once);
    assert!(report.is_empty());
}

/// The whole upgrade step, over a deployment's files (decision 16, end to end inside the migration): a config
/// that 1.5.5-era tooling left naming both retired modules is PLANNED, never refused; the planned text holds no
/// `transport:` section; the boot's report says so once per carrier. A section that names a living transport
/// is refused CONFIG exactly as before.
#[test]
fn an_upgrade_plans_a_config_that_names_the_retired_carriers_and_reports_each_once() {
    use crate::scratch::{accept, facts, Scratch};
    use crate::{plan, Inputs};

    let scratch = Scratch::new();
    let path = scratch.config(
        "listen: x\n\
         transport:\n  wire: {module: tcp}\n  pipes: {module: stdio}\n  wire2: {module: tcp}\n\
         store: {module: sqlite}\n",
    );
    let planned = plan(&Inputs::new(&path, &facts(), &accept)).unwrap_or_else(|refusal| {
        panic!("decision 16: accepted and ignored, never refused: {refusal}")
    });
    assert!(
        !planned.planned().contains("transport"),
        "the planned config holds no transport section:\n{}",
        planned.planned()
    );
    let lines: Vec<&String> = planned
        .report()
        .iter()
        .filter(|line| line.contains("accepted and ignored"))
        .collect();
    assert_eq!(
        lines.len(),
        2,
        "one line per carrier: {:?}",
        planned.report()
    );
    assert!(lines[0].contains("busbar-transport-tcp"), "{}", lines[0]);
    assert!(lines[1].contains("busbar-transport-stdio"), "{}", lines[1]);

    let living = Scratch::new();
    let path =
        living.config("listen: x\ntransport:\n  web: {module: http}\nstore: {module: sqlite}\n");
    let refused = plan(&Inputs::new(&path, &facts(), &accept)).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(refused.to_string().contains("`transport:`"), "{refused}");
}
