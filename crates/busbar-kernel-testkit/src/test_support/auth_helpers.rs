// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! In-process fixture construction over the kernel's normal authentication constructors.

use busbar_contract::auth::AuthModule;
use busbar_contract::auth_calls::AuthCalls;
use busbar_kernel::auth::{AdminModule, AuthMiddleware};
use std::sync::Arc;

fn inbound_style() -> Vec<String> {
    if busbar_kernel::preflight::linked_auth_names().is_empty() {
        super::outbound_auth::double_inbound_style()
    } else {
        busbar_kernel::preflight::root_rows()
            .auth_axis
            .and_then(|open| busbar_kernel::preflight::linked().ok().map(open))
            .and_then(|axis| axis.default_inbound_style().ok())
            .unwrap_or_default()
    }
}

pub fn new_builtin(cfg: &busbar_kernel::config::AuthCfg) -> AuthMiddleware {
    super::root::ensure();
    let style = inbound_style();
    let names: Vec<&str> = style.iter().map(String::as_str).collect();
    AuthMiddleware::new(
        cfg,
        &super::rows::empty(),
        &busbar_kernel::config::secret::SecretResolver::builtins_only(),
    )
    .expect("builtin-only auth chain never fails to construct")
    .with_fallback_test_metadata(&names, Some(super::issued::double()))
}

pub fn from_doors_for_test(chain: Vec<(String, Arc<dyn AuthCalls>)>) -> AuthMiddleware {
    let style = inbound_style();
    let names: Vec<&str> = style.iter().map(String::as_str).collect();
    AuthMiddleware::from_calls_for_test(chain, &names)
}

pub fn in_process(module: Box<dyn AuthModule>) -> AdminModule {
    AdminModule {
        calls: Arc::new(super::auth_stand_in::InProcessAuth::new(module)),
    }
}
