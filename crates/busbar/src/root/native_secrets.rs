// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The kernel's one secret seam ([`SecretAxis`]) over native (MIN-3) secret images (WP3 step 2).
//!
//! Two facts feed it, each published where it is decided:
//! - the native secret grammar of the admitted images (their names, aliases, shorthand and reference schemas, and
//!   which are linked), published by `boot::images::prepare`, the one source of truth for secret words;
//! - the custody prefix of the opened secret instances, published by `BootSecrets::resolver`.
//!
//! A reference resolves through custody: the plugin sees the reference's settings only (I2). Nothing here opens
//! an instance; the boot walk opens every configured and shorthand instance.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use arc_swap::ArcSwapOption;
use busbar_contract::plugin_settings::Settings;
use busbar_contract::redacted::Secret;
use busbar_contract::secret::{SecretAxis, SecretBytes, SecretCalls, SecretRefused};
use busbar_contract::secret_ref::{SecretRef, SourceReference, Sugars};
use busbar_kernel::config::grammar::SecretSource;

use crate::root::secret_custody::BootSecrets;

/// The admitted native secret images, as their grammar states them.
struct Admitted {
    sugars: Sugars,
    /// Every name and alias of an admitted secret image, with its identity and reference schema.
    sources: BTreeMap<String, SecretSource>,
    /// The names and aliases of the linked (compiled-in) secret images.
    linked: BTreeSet<String>,
}

/// The opened secret instances and the executor their synchronous readers dispatch onto.
struct Opened {
    prefix: Arc<BootSecrets>,
    runtime: tokio::runtime::Handle,
}

/// The native secret axis: one per process ([`NATIVE`]).
pub(crate) struct NativeSecrets {
    admitted: ArcSwapOption<Admitted>,
    opened: ArcSwapOption<Opened>,
}

/// The process's native secret axis, installed as `RootInstall.secret_axis`.
pub(crate) static NATIVE: NativeSecrets = NativeSecrets {
    admitted: ArcSwapOption::const_empty(),
    opened: ArcSwapOption::const_empty(),
};

impl NativeSecrets {
    /// Publish the native secret grammar the images prepare judged. `linked` names the identities of the linked
    /// images; every name a grammar source carries for one of them is linked.
    pub(crate) fn publish_images<'a>(
        &self,
        grammar: &busbar_kernel::config::Grammar,
        linked: impl Iterator<Item = &'a str>,
    ) {
        let linked: BTreeSet<&str> = linked.collect();
        let names = grammar
            .secret_sources
            .iter()
            .filter(|(_, source)| linked.contains(source.identity.as_str()))
            .map(|(name, _)| name.clone())
            .collect();
        self.admitted.store(Some(Arc::new(Admitted {
            sugars: grammar.sugars.clone(),
            sources: grammar.secret_sources.clone(),
            linked: names,
        })));
    }

    /// Publish the custody prefix of the opened secret instances, with the executor resolution runs on.
    pub(crate) fn publish_opened(
        &self,
        prefix: &Arc<BootSecrets>,
        runtime: tokio::runtime::Handle,
    ) {
        self.opened.store(Some(Arc::new(Opened {
            prefix: Arc::clone(prefix),
            runtime,
        })));
    }

    /// The shorthand the admitted native secret images declare.
    pub(crate) fn sugars(&self) -> Sugars {
        self.admitted
            .load()
            .as_ref()
            .map(|admitted| admitted.sugars.clone())
            .unwrap_or_default()
    }

    /// Every admitted native secret source by name and alias, as the start stage published them (empty before).
    /// A shorthand resolves through its source (01149013b8), so every grammar that carries [`Self::sugars`]
    /// carries these too.
    pub(crate) fn sources(&self) -> BTreeMap<String, SecretSource> {
        self.admitted
            .load()
            .as_ref()
            .map(|admitted| admitted.sources.clone())
            .unwrap_or_default()
    }

    fn source(&self, module: &str) -> Option<SecretSource> {
        self.admitted
            .load()
            .as_ref()
            .and_then(|admitted| admitted.sources.get(module).cloned())
    }
}

impl SecretAxis for NativeSecrets {
    fn sugars(&self) -> Sugars {
        NativeSecrets::sugars(self)
    }

    fn answers(&self, module: &str) -> bool {
        self.source(module).is_some()
    }

    fn linked(&self, module: &str) -> bool {
        self.admitted
            .load()
            .as_ref()
            .is_some_and(|admitted| admitted.linked.contains(module))
    }

    /// A reference's settings against the image's reference schema (D_REF_SCHEMA), before anything resolves.
    fn check(&self, module: &str, settings: &Settings) -> Result<(), Vec<String>> {
        let Some(source) = self.source(module) else {
            return Ok(());
        };
        let check = busbar_contract::json::SchemaCheck::new(source.ref_schema.as_bytes()).map_err(
            |_| {
                vec![format!(
                    "secret module '{module}' has an invalid reference schema"
                )]
            },
        )?;
        let encoded = settings
            .encode()
            .map_err(|_| vec!["the reference settings could not be encoded".to_owned()])?;
        let seal = busbar_kernel::seal::lend();
        if check.is_valid(encoded.expose(&seal)) {
            Ok(())
        } else {
            Err(vec![format!(
                "the settings do not match secret module '{module}''s reference schema"
            )])
        }
    }

    fn shared(&self, module: &str) -> Result<Arc<dyn SecretCalls>, String> {
        if self.source(module).is_none() {
            return Err(format!(
                "secret module '{module}' is not an admitted native secret image"
            ));
        }
        let opened = self.opened.load_full().ok_or_else(|| {
            format!("secret module '{module}' is admitted but no secret instance is open yet")
        })?;
        Ok(Arc::new(Calls {
            module: module.to_owned(),
            opened,
        }))
    }

    /// A native secret image is configured under `secrets:` and opened by the boot walk, never per reference:
    /// with no module-level settings this is the module's open instance.
    fn open(
        &self,
        module: &str,
        settings: Option<&Settings>,
        _resolve: &dyn Fn(&SecretRef) -> Result<SecretBytes, String>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        if settings.is_some_and(|settings| !settings.is_empty()) {
            return Err(format!(
                "secret module '{module}' is a native secret image: configure it under `secrets:`, which the \
                 boot opens; it is not opened per reference"
            ));
        }
        self.shared(module)
    }
}

/// One module's resolution through custody.
struct Calls {
    module: String,
    opened: Arc<Opened>,
}

impl SecretCalls for Calls {
    fn resolve(&self, settings: &[u8]) -> Result<Secret<Vec<u8>>, SecretRefused> {
        let settings: Settings =
            busbar_contract::json::parse(settings).map_err(|_| SecretRefused {
                error_kind: busbar_contract::secret::codes::ERROR_KIND_INVALID,
                text: "the reference settings are not a JSON object".to_owned(),
            })?;
        let reference = SecretRef::Source(SourceReference {
            module: self.module.clone(),
            settings,
        });
        self.opened
            .prefix
            .resolve_blocking(&self.opened.runtime, reference)
    }
}

/// The native secret axis over this build's linked images alone, published once: what a test reads its references
/// through (the shorthand the linked secret images declare).
#[cfg(test)]
pub(crate) fn linked_for_tests() -> &'static NativeSecrets {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let process = crate::root::boot::images::process().expect("the process plugin resources");
        let images = crate::root::boot::images::fixture(
            &process,
            &busbar_kernel::config::PluginsCfg {
                enabled: false,
                ..Default::default()
            },
        )
        .expect("the linked images describe");
        images.publish_secrets();
    });
    &NATIVE
}

#[cfg(test)]
#[path = "tests/native_secrets.rs"]
mod tests;
