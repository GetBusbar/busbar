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

/// An export axis that links every module and accepts any settings: the kernel has no root to link
/// the exporters the 1.5.5 file names, and these tests judge instance ids, not exporters.
struct AcceptsEveryExporter;

impl busbar_contract::export_calls::ExportAxis for AcceptsEveryExporter {
    fn probe(
        &self,
        _: &str,
        _: &str,
        _: &busbar_contract::plugin_settings::ResolvedSettings,
    ) -> Option<busbar_contract::export_calls::Probed> {
        Some((Some(Vec::new()), Vec::new(), None))
    }
    fn check(
        &self,
        _: &str,
        _: u32,
        _: &[(String, &busbar_contract::plugin_settings::ResolvedSettings)],
    ) -> Option<Vec<String>> {
        Some(Vec::new())
    }
    fn open(
        &self,
        module: &str,
        _: &str,
        _: &busbar_contract::export_calls::PreparedExport,
    ) -> Result<std::sync::Arc<dyn busbar_contract::export_calls::ExportCalls>, String> {
        Err(format!("{module} opens nothing here"))
    }
    fn linked(&self, _: &str) -> bool {
        true
    }
    fn first_party(&self, _: &str) -> bool {
        true
    }
}

static AXIS: AcceptsEveryExporter = AcceptsEveryExporter;

fn publish_axis() {
    crate::preflight::publish_root_rows(crate::preflight::RootInstall {
        export_axis: Some(&AXIS),
        ..Default::default()
    });
}

fn root() -> RootCfg {
    publish_axis();
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
    publish_axis();
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
