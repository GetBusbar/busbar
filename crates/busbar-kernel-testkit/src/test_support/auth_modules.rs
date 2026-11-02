// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use crate::auth::{AuthModule, AuthVerdict, Principal};

pub const TEST_GROUPS_MODULE: &str = "test-groups-module";

pub const TEST_SCOPE_MODULE: &str = "test-scope-module";

pub const TEST_IDP_MODULE: &str = "test-idp-module";

pub const TEST_IDP_ROLE: &str = "idp-user";

#[must_use]
pub fn answers(module: &str) -> bool {
    matches!(
        module,
        TEST_GROUPS_MODULE | TEST_SCOPE_MODULE | TEST_IDP_MODULE
    )
}

#[must_use]
pub fn open(module: &str) -> Option<Box<dyn AuthModule>> {
    match module {
        TEST_GROUPS_MODULE => Some(Box::new(Groups(TEST_GROUPS_MODULE))),
        TEST_SCOPE_MODULE => Some(Box::new(Groups(TEST_SCOPE_MODULE))),
        TEST_IDP_MODULE => Some(Box::new(Idp)),
        _ => None,
    }
}

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

#[must_use]
pub fn around(
    inner: std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis>,
) -> std::sync::Arc<dyn busbar_contract::auth_calls::AuthAxis> {
    std::sync::Arc::new(Around(inner))
}

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
                crate::test_support::auth_stand_in::InProcessAuth::new(m),
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

    fn inbound_style(&self, module: &str) -> Option<busbar_contract::auth_calls::InboundStyle> {
        self.0.inbound_style(module)
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
