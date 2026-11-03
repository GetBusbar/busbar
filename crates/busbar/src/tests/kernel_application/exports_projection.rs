// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[test]
fn a_producerless_stream_fails_the_boot_validate_pipeline() {
    crate::dist_root_install::install();

    let base = r#"
listen: "0.0.0.0:8080"
auth:
  chain: [keys]
  signing_key: { env: BUSBAR_SIGNING_KEY }
  admin_auth: []
  role_bindings:
    keys:
      platform:
        allowed_pools: [main]
        group: eng
providers: {}
models: {}
pools:
  main:
    members: []
groups:
  eng:
    limits:
      - { requests: 500, per: minute }
store:
  module: memory
"#;
    let defs = std::collections::HashMap::new();

    let control: busbar_kernel::config::DeployCfg =
        serde_yaml::from_str(base).expect("fixture parses");
    if let Err(errors) = busbar_kernel::config::resolve(&control, &defs) {
        panic!("the fixture without `export:` must resolve; errors were: {errors:#?}");
    }
    let yaml = format!(
        "{base}export:\n  siem:\n    module: request-log-webhook\n    streams: [prompts]\n    \
         settings:\n      url: https://siem.example.com/l\n"
    );
    let deploy: busbar_kernel::config::DeployCfg =
        serde_yaml::from_str(&yaml).expect("fixture parses");
    let errors = busbar_kernel::config::resolve(&deploy, &defs)
        .expect_err("a producerless stream must make the whole config fail to resolve");
    assert!(
        errors
            .iter()
            .any(|error| ["prompts", "NO PRODUCER", "later release"]
                .iter()
                .all(|word| error.contains(word))),
        "no error mentioned all of prompts/NO PRODUCER/later release; errors were: {errors:#?}"
    );
}
