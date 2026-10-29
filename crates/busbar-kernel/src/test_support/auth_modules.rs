// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TEST AUTH MODULES: in-process `kind: auth` modules a test chain names, answered by the test
//! build's auth axis ([`super::outbound_auth::stand_in`], and around a root test binary's own
//! opener, [`super::install_root_auth_axis`]) and exempt from the plugin pre-flight through the
//! install record's [`crate::preflight::RootInstall::in_process_auth`]. Production names none of
//! them: a chain entry naming one opens through the axis like any other module.

use crate::auth::{AuthModule, AuthVerdict, Principal};

/// `grp:<g>` identifies as `test:<g>` carrying exactly that group; anything else defers (`Pass`).
pub const TEST_GROUPS_MODULE: &str = "test-groups-module";

/// The admin chain's group module: the same credential grammar as [`TEST_GROUPS_MODULE`], so the
/// e2e suite reaches group-mapped, NON-full admin principals (unreachable with the operator
/// credential alone).
pub const TEST_SCOPE_MODULE: &str = "test-scope-module";

/// A stand-in for an operator's OIDC auth plugin: it identifies ANY non-empty credential and asks
/// nothing about audience, exactly as the plugin ABI forces a real one to. Without a module of this
/// shape no test can tell an audience check that runs from one that does not.
pub const TEST_IDP_MODULE: &str = "test-idp-module";

/// The role the [`TEST_IDP_MODULE`] stand-in asserts for every principal it identifies: a
/// deployed IdP's role is one the operator bound under `role_bindings` (`TestApp::idp_chain`).
pub const TEST_IDP_ROLE: &str = "idp-user";

/// Whether `module` is one of the test auth modules (the install record's `in_process_auth`).
#[must_use]
pub fn answers(module: &str) -> bool {
    matches!(
        module,
        TEST_GROUPS_MODULE | TEST_SCOPE_MODULE | TEST_IDP_MODULE
    )
}

/// The test auth module named `module`, opened in process.
#[must_use]
pub fn open(module: &str) -> Option<Box<dyn AuthModule>> {
    match module {
        TEST_GROUPS_MODULE => Some(Box::new(Groups(TEST_GROUPS_MODULE))),
        TEST_SCOPE_MODULE => Some(Box::new(Groups(TEST_SCOPE_MODULE))),
        TEST_IDP_MODULE => Some(Box::new(Idp)),
        _ => None,
    }
}

/// `grp:<g>` -> `test:<g>` carrying the group `g`; anything else `Pass`.
struct Groups(&'static str);

impl AuthModule for Groups {
    fn name(&self) -> &'static str {
        self.0
    }
    fn authenticate(&self, candidate: Option<&str>) -> AuthVerdict {
        match candidate.and_then(|t| t.strip_prefix("grp:")) {
            Some(group) => {
                let mut p = Principal::from_id(format!("test:{group}"));
                p.roles = vec![group.to_string()];
                AuthVerdict::Identify(p)
            }
            None => AuthVerdict::Pass,
        }
    }
}

/// Any non-empty credential -> `idp:subject` carrying [`TEST_IDP_ROLE`]; none `Pass`.
struct Idp;

impl AuthModule for Idp {
    fn name(&self) -> &'static str {
        TEST_IDP_MODULE
    }
    fn authenticate(&self, candidate: Option<&str>) -> AuthVerdict {
        match candidate.filter(|c| !c.is_empty()) {
            Some(_) => {
                let mut p = Principal::from_id("idp:subject".to_string());
                p.roles = vec![TEST_IDP_ROLE.to_string()];
                AuthVerdict::Identify(p)
            }
            None => AuthVerdict::Pass,
        }
    }
}

/// `inner` with the test auth modules answered and opened in process ahead of its rows: the auth
/// axis a test build reads (the stand-in's, or a root test binary's own opener's).
#[must_use]
pub fn around(
    inner: std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis>,
) -> std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis> {
    std::sync::Arc::new(Around(inner))
}

/// See [`around`].
struct Around(std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis>);

impl busbar_contract::auth_calls::AuthAxis for Around {
    fn linked_names(&self) -> Vec<String> {
        self.0.linked_names()
    }
    fn answers(&self, module: &str) -> bool {
        answers(module) || self.0.answers(module)
    }
    fn linked(&self, module: &str) -> bool {
        self.0.linked(module)
    }
    fn operator(&self) -> Option<(String, String)> {
        self.0.operator()
    }
    fn open(
        &self,
        module: &str,
        label: &str,
        settings: &serde_json::Value,
    ) -> Result<std::sync::Arc<dyn busbar_contract::auth_calls::AuthCalls>, String> {
        match open(module) {
            Some(m) => Ok(std::sync::Arc::new(
                crate::auth::stand_in::InProcessAuth::new(m),
            )),
            None => self.0.open(module, label, settings),
        }
    }
    fn credential_readers(&self) -> Vec<String> {
        self.0.credential_readers()
    }
    fn issued_credential(&self) -> Option<(String, busbar_contract::auth_calls::IssuedShape)> {
        self.0.issued_credential()
    }
    fn carriers(&self, module: &str) -> Vec<String> {
        self.0.carriers(module)
    }
    fn default_inbound_style(&self) -> Result<Vec<String>, String> {
        self.0.default_inbound_style()
    }
    fn serving(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Option<busbar_contract::auth_calls::OutboundServing>, String> {
        self.0.serving(style, settings)
    }
    fn serving_presenting(
        &self,
        style: &str,
        settings: &serde_json::Value,
        endpoint_basic: Option<&[u8]>,
    ) -> Result<Option<busbar_contract::auth_calls::OutboundServing>, String> {
        self.0.serving_presenting(style, settings, endpoint_basic)
    }
    fn check_outbound(
        &self,
        style: &str,
        credential: &[u8],
        settings: &serde_json::Value,
    ) -> Result<Vec<String>, String> {
        self.0.check_outbound(style, credential, settings)
    }
    fn outbound_styles(&self) -> Vec<busbar_contract::auth_calls::DeclaredStyle> {
        self.0.outbound_styles()
    }
}
