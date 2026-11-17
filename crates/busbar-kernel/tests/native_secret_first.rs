// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WP3 step 2 (the secret kind's native cutover), red first: the kernel's secret resolver resolves a reference
//! through the native secret image its resolver carries, ahead of the installed axis that answers the same
//! module. The axis is process-global, so this test owns its own binary and publishes one there.

use std::sync::Arc;

use busbar_contract::json;
use busbar_contract::plugin_settings::Settings;
use busbar_contract::redacted::Secret;
use busbar_contract::secret::{SecretAxis, SecretBytes, SecretCalls, SecretRefused, SecretResolve};
use busbar_contract::secret_ref::{SecretRef, Sugars};
use busbar_kernel::config::secret::SecretResolver;

const MODULE: &str = "test-native-first";

/// The installed axis's instance: what a resolver with a native source of its own does not reach.
struct Installed;
impl SecretCalls for Installed {
    fn resolve(&self, _settings: &[u8]) -> Result<Secret<Vec<u8>>, SecretRefused> {
        Ok(Secret::new(b"from-the-axis".to_vec()))
    }
}

struct InstalledAxis;
impl SecretAxis for InstalledAxis {
    fn sugars(&self) -> Sugars {
        Sugars::default()
    }
    fn answers(&self, module: &str) -> bool {
        module == MODULE
    }
    fn linked(&self, module: &str) -> bool {
        module == MODULE
    }
    fn shared(&self, _module: &str) -> Result<Arc<dyn SecretCalls>, String> {
        Ok(Arc::new(Installed))
    }
    fn open(
        &self,
        _module: &str,
        _settings: Option<&Settings>,
        _resolve: &dyn Fn(&SecretRef) -> Result<SecretBytes, String>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        Ok(Arc::new(Installed))
    }
}

static INSTALLED_AXIS: InstalledAxis = InstalledAxis;

fn publish() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        busbar_kernel::preflight::publish_root_rows(busbar_kernel::preflight::RootInstall {
            secret_axis: Some(&INSTALLED_AXIS),
            ..Default::default()
        });
    });
}

/// The native secret image answering `MODULE`, as the root's custody resolver presents it to the kernel.
fn native() -> SecretResolver {
    SecretResolver::with_scoped_plugin(Box::new(|module, _settings, _scope| {
        assert_eq!(
            module, MODULE,
            "the native image is asked for its own module"
        );
        Ok(Secret::new(b"from-the-native-image".to_vec()))
    }))
}

fn reference() -> SecretRef {
    json::from_value(&json::json!({"module": MODULE, "settings": {"name": "x"}}))
        .expect("a canonical source reference")
}

#[test]
fn a_reference_resolves_through_the_native_image_not_the_door() {
    publish();
    let text = SecretResolve::resolve_string(&native(), &reference())
        .expect("the native image resolves the reference");
    assert_eq!(text, Secret::new("from-the-native-image".to_string()));
}

/// A resolver bound to no source of its own resolves through the kernel's one secret seam, the installed axis
/// (in a build, the root's native secret axis).
#[test]
fn a_resolver_with_no_source_of_its_own_resolves_through_the_axis() {
    publish();
    let text = SecretResolve::resolve_string(&SecretResolver::builtins_only(), &reference())
        .expect("the axis answers the module");
    assert_eq!(text, Secret::new("from-the-axis".to_string()));
}
