// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! ADMIN-API-1.6 §5.3 (C4): a 1.5.5 config that uses one instance name in two sections, or a core
//! instance id, is refused at validate with the design's message, byte for byte.

use super::*;

/// A 1.5.5 operator file: 1.5.5 allowed an exporter and an identity provider to share a name, and
/// had no reserved core instance ids.
const CONFIG_1_5_5: &str = "\
providers: {}
models: {}
identity-providers:
  main:
    module: oidc
export:
  main:
    module: prometheus
  routing:
    module: request-log
";

fn root() -> RootCfg {
    let deploy =
        crate::config::deploy_from_yaml_str(CONFIG_1_5_5, &crate::config::Grammar::empty())
            .expect("the 1.5.5 file parses");
    crate::config::resolve(&deploy, &HashMap::new()).expect("the 1.5.5 file resolves")
}

#[test]
fn instance_id_collision_rejected_at_validate() {
    let cfg = root();
    let collision = "instance id \"main\" is used by both identity-providers.main and \
                     export.main; instance ids are unique across the deployment in 1.6, rename one";
    let reserved = "instance id \"routing\" is reserved for the core instance core/routing; \
                    rename export.routing";
    assert_eq!(
        instance_id_collisions(&cfg),
        vec![collision.to_string(), reserved.to_string()],
    );
    let refused = validate(&cfg).expect_err("validate refuses the shared and reserved ids");
    for message in [collision, reserved] {
        assert!(
            refused.iter().any(|e| e == message),
            "validate names `{message}`: {refused:?}"
        );
    }
}

#[test]
fn distinct_instance_ids_are_accepted() {
    let deploy = crate::config::deploy_from_yaml_str(
        "providers: {}\nmodels: {}\nidentity-providers:\n  corp:\n    module: oidc\nexport:\n  \
         metrics:\n    module: prometheus\n",
        &crate::config::Grammar::empty(),
    )
    .expect("parses");
    let cfg = crate::config::resolve(&deploy, &HashMap::new()).expect("resolves");
    assert!(instance_id_collisions(&cfg).is_empty());
    assert_eq!(CORE_INSTANCES.len(), 9);
}
