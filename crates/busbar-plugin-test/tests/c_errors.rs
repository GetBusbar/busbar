// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! C-ERRORS (ABI-MIN3-INTERFACE §14 round 34; T1, run in every plugin's dev CI): a repository's
//! `docs/diagnostics.json` against its binary, through `busbar_plugin_test::errors`. The file arms are W1-T1's.
//! Holding the file against describe's D_ERRORS, the stamp name through `scan::error_identity` and every number
//! seen on ERROR or `log_error` needs a registry (W1-L2, after W1-L1's `error_identity`).
//!
//! WBS rule 10: each ignored arm waits for the task that lands the last piece it needs; that task writes the
//! arm's body and un-ignores it in its own MR (red first, then green). Arms of tasks merged before W1-T1 run now.

use busbar_plugin_test::errors::{diagnostics, same_numbers};

const FILE: &[u8] = br#"[{"code": "BUSBAR-busbar-hook-ranking-0003", "number": 3, "plugin": "busbar-hook-ranking",
  "slug": "no-candidates", "title": "No candidates", "summary": "Nothing to rank.", "action": "Check the pool.",
  "since": "1.6.0"}]"#;

#[test]
fn a_repository_with_no_d_errors_and_no_file_passes() {
    assert_eq!(same_numbers(&[], &[], &[]), Ok(()));
}

#[test]
fn the_file_is_checked_against_the_stamp_name() {
    assert_eq!(diagnostics(FILE, "busbar-hook-ranking"), Ok(vec![3]));
    assert!(diagnostics(FILE, "busbar-hook-webrequest").is_err());
    assert_eq!(same_numbers(&[3], &[3], &[3]), Ok(()));
    assert!(same_numbers(&[3], &[3], &[4]).is_err());
}

/// L2's arm over the probe image (`fixture-second-b`, D_ERRORS 12 and 7070): its `docs/diagnostics.json` passes
/// for the stamp name `scan::error_identity` reads, its live numbers equal describe's D_ERRORS, and every number
/// the suite saw (on an ERROR record of a refused `open` and a failed `resolve`, on a `log_error` line, and every
/// number the registry found undeclared) is declared.
#[test]
fn the_file_matches_describe_and_every_number_the_suite_saw() {
    use std::time::{Duration, Instant};

    use busbar_plugin_abi::host_side::caller::CallStack;
    use busbar_plugin_abi::records::tag;
    use busbar_plugin_loader::admit::admit_header;
    use busbar_plugin_loader::ports::{CallCx, PortError};
    use busbar_plugin_loader::scan::error_identity;
    use busbar_plugin_test::fake_needs::FakeNeeds;
    use busbar_plugin_test::suites::harness::{plugin_code, Harness};

    use crate::min3_second::{self as fx, PROBE};

    const PROBE_FILE: &[u8] = br#"[
      {"code": "BUSBAR-fixture-second-b-0012", "number": 12, "plugin": "fixture-second-b", "slug": "backend-failed",
       "title": "Backend failed", "summary": "The fixture backend failed.", "action": "Retry.", "since": "1.6.0"},
      {"code": "BUSBAR-fixture-second-b-0031", "number": 31, "plugin": "fixture-second-b", "slug": "old-number",
       "title": "Old number", "summary": "Retired.", "action": "None.", "since": "1.6.0", "retired": true},
      {"code": "BUSBAR-fixture-second-b-7070", "number": 7070, "plugin": "fixture-second-b", "slug": "declared-log",
       "title": "Declared log", "summary": "A declared log line.", "action": "None.", "since": "1.6.0"}
    ]"#;
    let cx = |id: u64| CallCx {
        deadline: Instant::now() + Duration::from_secs(10),
        request_id: id,
        stack: CallStack::default(),
    };

    let admitted = admit_header(fx::probe::PLUGIN.plugin()).unwrap_or_else(|r| panic!("{r:?}"));
    let stamp = error_identity(&admitted.stamp.name)
        .unwrap_or_else(|f| panic!("the stamp name forms codes: {f:?}"))
        .to_owned();
    assert_eq!(stamp, PROBE);
    let file = diagnostics(PROBE_FILE, &stamp).unwrap_or_else(|e| panic!("{e}"));

    let h = Harness::admit(fx::probe::PLUGIN.plugin(), FakeNeeds::new())
        .unwrap_or_else(|r| panic!("{r:?}"));
    let described = h
        .registry()
        .described(PROBE)
        .unwrap_or_else(|| panic!("the probe image is described"));
    assert!(described.error_codes_refused.is_none());
    let declared: Vec<u16> = described
        .items
        .iter()
        .filter(|(t, _)| *t == tag::D_ERRORS)
        .flat_map(|(_, body)| {
            body.chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect::<Vec<_>>()
        })
        .collect();

    let mut seen: Vec<u32> = Vec::new();
    let refused = h
        .open_secret(
            "errors-refused",
            br#"{"tag":"errors-refused","refuse":true}"#,
        )
        .err()
        .unwrap_or_else(|| panic!("the refusing config is refused"));
    seen.extend(plugin_code(&refused).map(|c| u32::from(c.number)));
    let port = h
        .open_secret("errors", br#"{"tag":"errors"}"#)
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert!(h
        .block_on(port.resolve(cx(1), br#"{"name":"log"}"#))
        .is_ok());
    match h.block_on(port.resolve(cx(2), br#"{"name":"fail"}"#)).err() {
        Some(PortError::Failed { error, .. }) => seen.extend(error.map(|c| u32::from(c.number))),
        other => panic!("the fail reference answers FAILED: {other:?}"),
    }
    let prefix = format!("BUSBAR-{PROBE}-");
    for line in h.logs() {
        if let Some(number) = line.code.strip_prefix(&prefix) {
            seen.push(
                number
                    .parse()
                    .unwrap_or_else(|_| panic!("a code: {}", line.code)),
            );
        }
    }
    for number in h.undeclared() {
        seen.push(u32::try_from(number).unwrap_or(u32::MAX));
    }

    assert!(
        seen.contains(&u32::from(fx::OPEN_ERROR)),
        "an ERROR number was seen: {seen:?}"
    );
    assert!(
        seen.contains(&u32::from(fx::LOG_ERROR)),
        "a log number was seen: {seen:?}"
    );
    assert_eq!(same_numbers(&file, &declared, &seen), Ok(()));
}
