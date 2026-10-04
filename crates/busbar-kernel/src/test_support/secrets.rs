// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE STAND-IN SECRET AXIS: a test build has no composition root, so the shipped secret sources'
//! own `resolve` stands in for the root's axis, called in process (the one-dispatcher path is the
//! loader's `secret_calls` tests and the root's). They answer by their module alias, as linked rows.

use std::sync::Arc;

use busbar_contract::redacted::Redacted;
use busbar_contract::secret::{SecretAxis, SecretCalls, SecretRefused, SecretResult};
use busbar_contract::secret_ref::{SecretRef, SECRET_MODULE_ENV, SECRET_MODULE_FILE};

type Resolve = fn(&serde_json::Map<String, serde_json::Value>) -> SecretResult<Vec<u8>>;

/// The stand-in axis.
pub struct SecretsStandIn;

struct Source(
    Resolve,
    fn(&[u8]) -> SecretResult<serde_json::Map<String, serde_json::Value>>,
);

fn source(module: &str) -> Option<Source> {
    match module {
        SECRET_MODULE_ENV => Some(Source(
            fixture_secret_env::resolve,
            fixture_secret_env::settings_of,
        )),
        SECRET_MODULE_FILE => Some(Source(
            fixture_secret_file::resolve,
            fixture_secret_file::settings_of,
        )),
        _ => None,
    }
}

impl SecretCalls for Source {
    fn resolve(&self, settings: &[u8]) -> Result<Redacted<Vec<u8>>, SecretRefused> {
        (self.1)(settings)
            .and_then(|s| (self.0)(&s))
            .map(Redacted::new)
            .map_err(|e| SecretRefused {
                error_kind: fixture_secret_env::error_kind(e.kind),
                text: e.message,
            })
    }
}

impl SecretAxis for SecretsStandIn {
    fn answers(&self, module: &str) -> bool {
        source(module).is_some()
    }

    fn linked(&self, module: &str) -> bool {
        source(module).is_some()
    }

    fn shared(&self, module: &str) -> Result<Arc<dyn SecretCalls>, String> {
        source(module)
            .map(|s| Arc::new(s) as Arc<dyn SecretCalls>)
            .ok_or_else(|| format!("no linked secret module answers to '{module}'"))
    }

    fn open(
        &self,
        module: &str,
        _: &serde_json::Value,
        _: &dyn Fn(&SecretRef) -> Result<Vec<u8>, String>,
    ) -> Result<Arc<dyn SecretCalls>, String> {
        self.shared(module)
    }
}
