// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::secret::SecretCalls;
use busbar_plugin_loader::dispatch::kinds::secret::Secret;
use busbar_plugin_loader::dispatch::{
    load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
};
use busbar_plugin_loader::secret_calls::LoadedSecret;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

fn product(variable: &str, cell: &'static OnceLock<Arc<LoadedSecret>>) -> Arc<LoadedSecret> {
    Arc::clone(cell.get_or_init(|| {
        let path = PathBuf::from(std::env::var_os(variable).expect(variable));
        let stated = rendering_of_library(&path)
            .expect("the actual Secret image renders")
            .expect("the actual Secret image carries a door");
        let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
        let plugin = load_dropped::<Secret>(
            &path,
            &stated,
            Bind {
                instance: Arc::from(variable),
                max_inflight_cap: 1024,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("the actual Secret image loads");
        Arc::new(
            LoadedSecret::open(plugin, dispatcher, b"{}", &[])
                .expect("the actual Secret product opens"),
        )
    }))
}

pub(crate) fn resolver() -> SecretResolver {
    SecretResolver::with_scoped_plugin(Box::new(|module, settings, scope| {
        static ENV: OnceLock<Arc<LoadedSecret>> = OnceLock::new();
        static FILE: OnceLock<Arc<LoadedSecret>> = OnceLock::new();
        let calls = match module {
            SECRET_MODULE_ENV => product("BUSBAR_TEST_SECRET_ENV_CDYLIB", &ENV),
            SECRET_MODULE_FILE => product("BUSBAR_TEST_SECRET_FILE_CDYLIB", &FILE),
            _ => {
                let settings = serde_json::from_str(settings).expect("reference settings JSON");
                return SecretResolver::builtins_only().resolve_with(
                    &SecretRef {
                        module: module.into(),
                        settings,
                    },
                    scope,
                );
            }
        };
        match scope {
            Some(scope) => calls.resolve_at_config(settings.as_bytes(), scope),
            None => calls.resolve(settings.as_bytes()),
        }
    }))
}
