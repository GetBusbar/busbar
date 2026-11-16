// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MIGRATE-ON-BOOT r41 §9 C1 red (d): a 1.4 and a 1.5.0 config are refused UNSUPPORTED with the
//! markers v1.5.5's own boot reported, word for word (the expected texts below are copied from tag
//! v1.5.5 `crates/busbar/src/config/migrate.rs` `detect_legacy_markers`, the `global_hooks:` one
//! without the clause naming the retired migration flag), then `UPGRADE_FIRST`; nothing is planned
//! or written. A top-level `transport:` section is refused CONFIG.

use busbar_contract::yaml::Value;

use super::*;
use crate::scratch::{facts, Scratch};
use crate::{plan, Inputs, UPGRADE_FIRST};

const CONFIG_1_4: &str = "\
governance:
  db_path: busbar-governance.db
auth:
  mode: token
  group_map:
    eng: {allowed_pools: []}
pools:
  fast:
    members:
      - target: claude
    on_exhausted: {action: reject}
";

const MARKERS_1_4: [&str; 6] = [
    "`governance:` block (dissolved into store / rate_card / per_request_fee / groups / advanced / auth)",
    "`auth.mode:` (replaced by auth.chain / auth.upstream_credentials)",
    "`auth.group_map:` (replaced by auth.role_bindings, NESTED BY MODULE; its rate/budget caps move to a groups: entry)",
    "`auth.group_map:` (replaced by auth.role_bindings, NESTED BY MODULE)",
    "`pools.fast.members[].target:` (renamed to model)",
    "`pools.fast.on_exhausted.action:` (the action wrapper is gone; use a bare `reject`/`least_bad` or `{ fallback_pool: <pool> }`)",
];

const CONFIG_1_5_0: &str = "\
global_hooks: [audit]
observability:
  otlp_url: http://collector:4318
admin_insecure: true
export:
  prometheus: {settings: {buffer_seconds: 10}}
";

const MARKERS_1_5_0: [&str; 4] = [
    "top-level `global_hooks:` (removed 1.5.3 → the reserved `pools.hooks:` all-pools attach list)",
    "top-level `observability:` block (DELETED 1.5.3 → an `export:` instance with `module: otlp` and `settings.url`); all telemetry egress is now the single `export:` surface",
    "top-level `admin_insecure:` (retired 1.5.3 → admin_require_mtls (INVERTED: `admin_insecure: true` ⇒ `admin_require_mtls: false`))",
    "top-level `export:` is TYPE-KEYED (retired 1.5.3 → a NAMED map `<name>: { module, settings }`, so the same module can back several instances)",
];

fn tree(text: &str) -> Value {
    busbar_contract::yaml::from_str(text).expect("fixture parses")
}

#[test]
fn the_markers_are_v1_5_5s_word_for_word() {
    assert_eq!(detect(&tree(CONFIG_1_4)), MARKERS_1_4);
    assert_eq!(detect(&tree(CONFIG_1_5_0)), MARKERS_1_5_0);
    assert!(detect(&tree("listen: x\nstore: {module: sqlite}\n")).is_empty());
    // 1.5.3 hook definitions are not a registry; a `webhook:` entry is.
    assert!(detect(&tree("hooks:\n  audit: {module: ranking}\n")).is_empty());
    assert_eq!(
        detect(&tree("hooks:\n  audit: {webhook: http://x}\n")).len(),
        1
    );
}

/// (d): each fixture is refused UNSUPPORTED before the boot's parse runs, with every marker and
/// `UPGRADE_FIRST`; the directory holds only what it held.
#[test]
fn a_1_4_and_a_1_5_0_config_are_unsupported() {
    for (config, markers) in [
        (CONFIG_1_4, &MARKERS_1_4[..]),
        (CONFIG_1_5_0, &MARKERS_1_5_0[..]),
    ] {
        let scratch = Scratch::new();
        let path = scratch.deployment(config);
        let never = |_: &str, _: Option<&str>| -> Result<(), String> {
            panic!("1a refuses before the parse")
        };
        let refused = plan(&Inputs::new(&path, &facts(), &never)).unwrap_err();
        assert_eq!(refused.word(), "UNSUPPORTED", "{refused}");
        let text = refused.to_string();
        let listed = format!("\n  - {}\n", markers.join("\n  - "));
        assert!(text.contains(&listed), "{text}");
        assert!(text.ends_with(UPGRADE_FIRST), "{text}");
        assert!(!text.contains("--migrate-config"), "{text}");
        assert_eq!(scratch.names(), ["config.yaml", "providers.yaml"]);
    }
}

/// Round 12 C-RETIRE: no 1.5.5 config held a transport instance.
#[test]
fn an_unstamped_transport_section_is_refused() {
    let refused = refuse(&tree("transport:\n  tcp: {module: tcp}\n")).unwrap_err();
    assert_eq!(refused.word(), "CONFIG");
    assert!(refused.to_string().contains("`transport:`"), "{refused}");
    assert!(refused.to_string().ends_with(UPGRADE_FIRST), "{refused}");
}
