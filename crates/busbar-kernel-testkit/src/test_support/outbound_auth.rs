// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_contract::auth_calls::{
    AuthAxis, AuthCalls, AuthField, Fielding, Fields, FieldsRequest, OutboundAuth, OutboundServing,
};
use busbar_contract::plugin_rows::{PluginRows, Row};
use busbar_contract::redacted::Secret;
use busbar_kernel_identity::operator::LinkedAuth;

#[must_use]
pub fn double_inbound_style() -> Vec<String> {
    ["authorization", "x-api-key", "x-goog-api-key"]
        .map(String::from)
        .to_vec()
}

#[must_use]
pub fn double_operator_carriers() -> Vec<String> {
    ["authorization", "x-admin-token"]
        .map(String::from)
        .to_vec()
}

#[must_use]
pub fn double_outbound_styles() -> Vec<busbar_contract::auth_calls::DeclaredStyle> {
    use busbar_contract::abi::auth::{
        ranked, STYLE_CALLER_CREDENTIAL, STYLE_ENDPOINT_FROM_CREDENTIAL, STYLE_ENDPOINT_TOKEN_URL,
    };
    let style = |name: &str, flags: u32| busbar_contract::auth_calls::DeclaredStyle {
        name: name.to_string(),
        flags,
    };
    busbar_contract::auth_calls::listed_styles([
        style("bearer", STYLE_CALLER_CREDENTIAL | ranked(1)),
        style("api-key", STYLE_CALLER_CREDENTIAL | ranked(2)),
        style("x-double-mint", STYLE_ENDPOINT_TOKEN_URL),
        style("jwt-bearer", STYLE_ENDPOINT_FROM_CREDENTIAL | ranked(3)),
        style(
            "oauth-client-credentials",
            STYLE_ENDPOINT_TOKEN_URL | ranked(4),
        ),
    ])
}

#[must_use]
pub fn axis() -> Arc<dyn AuthAxis> {
    Arc::new(DoubleAxis)
}

#[must_use]
pub fn stand_in(registry: Arc<dyn PluginRows>) -> Arc<dyn AuthAxis> {
    super::auth_modules::around(Arc::new(StandIn { registry }))
}

const AUTH: &str = busbar_contract::abi::mechanism::kind::AUTH;

pub const NO_DOOR: &str = "it speaks the 1.5.5 JSON auth contract, which this host does not load — rebuild the plugin against the 1.6.0 SDK";

/// What a linked auth door is, in process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KitDoor {
    /// The operator-credential double ([`super::operator_double`]).
    Operator,
    /// A door the test kit has no in-process double for.
    Unknown,
}

fn kit_door(door: busbar_contract::abi::mechanism::door::DoorFn) -> KitDoor {
    if super::operator_double::is_door(door) {
        KitDoor::Operator
    } else {
        KitDoor::Unknown
    }
}

#[must_use]
pub fn declares_chain_module(door: busbar_contract::abi::mechanism::door::DoorFn) -> bool {
    kit_door(door) == KitDoor::Operator
}

/// One LINKED auth row: the key config names it by (and every refusal prints), every word it
/// answers to, and what its door is in process.
#[derive(Clone, Debug)]
struct LinkedAuthRow {
    key: String,
    words: Vec<String>,
    door: busbar_contract::abi::mechanism::door::DoorFn,
}

impl LinkedAuthRow {
    fn of_table(row: &LinkedAuth) -> Self {
        let mut words = vec![row.0.to_string(), row.1.to_string()];
        words.extend(crate::config::migration_table::former_names(row.0));
        Self {
            key: row.0.to_string(),
            words,
            door: row.2,
        }
    }

    fn answers(&self, module: &str) -> bool {
        self.words.iter().any(|w| w == module)
    }

    fn kit_door(&self) -> KitDoor {
        kit_door(self.door)
    }
}

enum AuthRow {
    Linked(LinkedAuthRow),

    Dropped(Row),
}

struct StandIn {
    registry: Arc<dyn PluginRows>,
}

impl StandIn {
    fn linked_rows(&self) -> Vec<LinkedAuthRow> {
        let mut rows: Vec<LinkedAuthRow> = busbar_kernel_identity::operator::linked()
            .iter()
            .map(LinkedAuthRow::of_table)
            .collect();
        if let Some(double) = self.registry.as_any().downcast_ref::<super::rows::Rows>() {
            for (row, words, door) in double.linked_doors() {
                let held = rows
                    .iter()
                    .any(|r| r.key == row.key && std::ptr::fn_addr_eq(r.door, door));
                if row.kind == AUTH && !held {
                    rows.push(LinkedAuthRow {
                        key: row.key,
                        words,
                        door,
                    });
                }
            }
        }
        rows
    }

    fn row(&self, module: &str) -> Option<AuthRow> {
        self.linked_rows()
            .into_iter()
            .find(|r| r.answers(module))
            .map(AuthRow::Linked)
            .or_else(|| {
                self.registry
                    .resolve(module)
                    .filter(|r| r.kind == AUTH && !r.linked)
                    .map(AuthRow::Dropped)
            })
    }

    fn inbound_styles(&self) -> Vec<(String, Vec<String>)> {
        self.registry
            .as_any()
            .downcast_ref::<super::rows::Rows>()
            .map(super::rows::Rows::inbound_styles)
            .unwrap_or_default()
    }

    fn row_carriers(&self, module: &str) -> Vec<String> {
        match self.row(module) {
            Some(AuthRow::Linked(r)) if r.kit_door() == KitDoor::Operator => {
                super::operator_double::carriers()
            }
            Some(AuthRow::Linked(r)) => self
                .inbound_styles()
                .into_iter()
                .find(|(key, _)| *key == r.key)
                .map(|(_, lines)| lines)
                .unwrap_or_default(),
            _ => Vec::new(),
        }
    }
}

impl AuthAxis for StandIn {
    fn linked_names(&self) -> Vec<String> {
        self.linked_rows().into_iter().map(|r| r.key).collect()
    }

    fn answers(&self, module: &str) -> bool {
        self.row(module).is_some()
    }

    fn linked(&self, module: &str) -> bool {
        self.linked_rows().iter().any(|r| r.answers(module))
    }

    fn operator(&self) -> Option<(String, String)> {
        self.linked_rows()
            .into_iter()
            .find(|r| r.kit_door() == KitDoor::Operator)
            .map(|r| (r.key, super::operator_double::principal().to_string()))
    }

    fn open(
        &self,
        module: &str,
        _label: &str,
        settings: &serde_json::Value,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        match self.row(module) {
            None => Err(format!("no `kind: auth` plugin answers to '{module}'")),
            Some(AuthRow::Linked(row)) if row.kit_door() == KitDoor::Operator => {
                super::operator_double::open_in_process(module, settings)
            }
            Some(AuthRow::Linked(row)) => Err(format!(
                "auth plugin '{}': a test build has no loader, and the test kit has no in-process \
                 double for this door; the composition root's tests open it",
                row.key
            )),
            Some(AuthRow::Dropped(row)) => Err(format!("auth plugin '{}': {NO_DOOR}", row.key)),
        }
    }

    fn credential_readers(&self) -> Vec<String> {
        Vec::new()
    }

    fn carriers(&self, module: &str) -> Vec<String> {
        let rows = self.row_carriers(module);
        if rows.is_empty() && module == crate::config::operator_provider() {
            return double_operator_carriers();
        }
        rows
    }

    fn default_inbound_style(&self) -> Result<Vec<String>, String> {
        let stating = self.inbound_styles();
        match stating.as_slice() {
            [] => Ok(double_inbound_style()),
            [(_, lines)] => Ok(lines.clone()),
            many => Err(format!(
                "more than one auth plugin states the default inbound style ({}): at most one may; \
                 remove all but one",
                many.iter()
                    .map(|(key, _)| key.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    fn serving(
        &self,
        style: &str,
        settings: &serde_json::Value,
    ) -> Result<Option<OutboundServing>, String> {
        DoubleAxis.serving(style, settings)
    }

    fn outbound_styles(&self) -> Vec<busbar_contract::auth_calls::DeclaredStyle> {
        double_outbound_styles()
    }
}

struct DoubleAxis;

impl AuthAxis for DoubleAxis {
    fn linked_names(&self) -> Vec<String> {
        Vec::new()
    }

    fn answers(&self, _module: &str) -> bool {
        false
    }

    fn linked(&self, _module: &str) -> bool {
        false
    }

    fn operator(&self) -> Option<(String, String)> {
        None
    }

    fn open(
        &self,
        module: &str,
        _label: &str,
        _settings: &serde_json::Value,
    ) -> Result<Arc<dyn AuthCalls>, String> {
        Err(format!("no `kind: auth` plugin answers to '{module}'"))
    }

    fn serving(
        &self,
        _style: &str,
        _settings: &serde_json::Value,
    ) -> Result<Option<OutboundServing>, String> {
        Ok(Some(OutboundServing {
            auth: Arc::new(Double::default()),
            flags: busbar_contract::abi::auth::STYLE_CALLER_CREDENTIAL,
            points: busbar_contract::abi::auth::POINT_HEAD,
        }))
    }

    fn outbound_styles(&self) -> Vec<busbar_contract::auth_calls::DeclaredStyle> {
        double_outbound_styles()
    }
}

/// One double instance: its bindings' credentials, by handle.
#[derive(Default)]
struct Double {
    bound: Mutex<HashMap<u64, Vec<u8>>>,
}

fn bearer(credential: &[u8]) -> Fields {
    if credential.is_empty() {
        return Fields::Ready(Vec::new());
    }
    let mut value = b"Bearer ".to_vec();
    value.extend_from_slice(credential);
    Fields::Ready(vec![AuthField {
        name: b"authorization".to_vec(),
        value: Secret::new(value),
        sensitive: false,
        query: false,
        require_secure: false,
    }])
}

impl OutboundAuth for Double {
    fn open_outbound(
        &self,
        _style: &str,
        credential: &[u8],
        _settings: &serde_json::Value,
    ) -> Result<u64, String> {
        let mut bound = self.bound.lock().unwrap_or_else(|p| p.into_inner());
        let handle = bound.len() as u64 + 1;
        bound.insert(handle, credential.to_vec());
        Ok(handle)
    }

    fn fields_now(&self, handle: u64, request: &FieldsRequest) -> Option<Fields> {
        if let Some(caller) = &request.caller_credential {
            return Some(bearer(caller.expose(&crate::seal::lend())));
        }
        let bound = self.bound.lock().unwrap_or_else(|p| p.into_inner());
        Some(bound.get(&handle).map_or(Fields::Refused, |c| bearer(c)))
    }

    fn fields(&self, handle: u64, request: FieldsRequest, _deadline_ns: u64) -> Box<dyn Fielding> {
        Box::new(Settled(self.fields_now(handle, &request)))
    }
}

struct Settled(Option<Fields>);

impl std::future::Future for Settled {
    type Output = Fields;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Fields> {
        std::task::Poll::Ready(self.0.take().unwrap_or(Fields::Failed))
    }
}

impl Fielding for Settled {
    fn settled(&mut self) -> Option<Fields> {
        self.0.take()
    }
}
