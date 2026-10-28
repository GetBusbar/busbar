// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE KIND-NEUTRAL OUTBOUND AUTH DOUBLE a test build binds lane credentials on (BUSBAR-1.6.0.md
//! THE DESIGN §1, "Kernel tests use kind-neutral doubles"): a test binary has no composition root,
//! so no auth plugin is linked, and a lane's credential binds here instead. It serves EVERY style,
//! and presents a bound credential (or, for a passthrough request, the caller's) as
//! `authorization: Bearer <credential>`; an empty credential presents nothing. It is not any style's
//! bytes: each style's real bytes are its plugin's, proven by that plugin's conformance suite and
//! by the composition root's tests, which link the real plugins.
//!
//! THE INBOUND HALF ([`stand_in`]) answers the build's LINKED auth rows
//! (`busbar_kernel_identity::operator::linked`, and any linked auth row a test's rows double holds,
//! [`super::rows::Rows::with_linked`]) IN PROCESS, with no loader (BUSBAR-1.6.0.md THE
//! DESIGN l.322): a row whose door is one of the kit's own auth doubles is answered by that double
//! called directly — today the operator-credential double ([`super::operator_double`], a
//! `VerifyPlugin`). What the stand-in states for the rows mirrors what the loader's auth rows
//! (`AuthRows`, `crates/plugin-loader/src/auth_axis.rs`) state for the same doors: the linked
//! rows' keys, the operator row (`FACT_OPERATOR` and its principal), each row's carriers, no
//! credential reader (the double states none), and the default inbound style of the one linked row
//! a test's rows double states it for ([`super::rows::Rows::with_linked_style`]). A linked door the
//! kit has no double for, and a dropped-in auth row (a test's rows double carries no image), is
//! a row that "will not load here": it answers, states nothing, and its open is refused naming it.
//! How the loader binds and crosses a real auth door is the loader's and the root's to prove
//! (`crates/plugin-loader`, `crates/busbar/tests`).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use busbar_contract::auth_calls::{
    AuthAxis, AuthCalls, AuthField, Fielding, Fields, FieldsRequest, OutboundAuth, OutboundServing,
};
use busbar_contract::plugin_rows::{PluginRows, Row};
use busbar_contract::redacted::Secret;
use busbar_kernel_identity::operator::LinkedAuth;

/// THE DOUBLE'S DEFAULT INBOUND STYLE: the carrier marks a test binary's stand-in axis answers
/// when no linked row states `FACT_DEFAULT_INBOUND_STYLE` (a test binary links no auth plugin), in
/// the 1.5.5 precedence order the linked header auth states them. Test data, never shipped: the
/// shipped lines are that plugin's Statement's, proven by the composition root's tests.
#[must_use]
pub fn double_inbound_style() -> Vec<String> {
    ["authorization", "x-api-key", "x-goog-api-key"]
        .map(String::from)
        .to_vec()
}

/// THE DOUBLE'S OPERATOR CARRIERS: what the stand-in axis answers for the operator credential's
/// row when no linked row answers it, in the order the linked operator plugin states them.
#[must_use]
pub fn double_operator_carriers() -> Vec<String> {
    ["authorization", "x-admin-token"]
        .map(String::from)
        .to_vec()
}

/// The double's axis: answers no inbound module, serves every outbound style.
#[must_use]
pub fn axis() -> Arc<dyn AuthAxis> {
    Arc::new(DoubleAxis)
}

/// A test build's AUTH AXIS over `registry` (installed in place of the root's opener,
/// [`crate::test_support::install_root_auth_axis`]): the build's linked auth rows answered in process, the
/// registry's dropped-in auth rows refused at their open, and this double for every outbound style
/// (see the module doc).
#[must_use]
pub fn stand_in(registry: Arc<dyn PluginRows>) -> Arc<dyn AuthAxis> {
    Arc::new(StandIn { registry })
}

/// The auth kind's word in a row (`kind: auth`).
const AUTH: &str = busbar_contract::abi::mechanism::kind::AUTH;

/// Why a dropped-in auth row does not open here: it states no door the test kit can call (the
/// loader's `NO_DOOR` for a row that states none, verbatim; a test's rows double carries no image).
pub const NO_DOOR: &str = "it speaks the 1.5.5 JSON auth contract, which this host does not load — rebuild the plugin against the 1.6.0 SDK";

/// What a linked auth door is, in process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KitDoor {
    /// The operator-credential double ([`super::operator_double`]).
    Operator,
    /// A door the test kit has no in-process double for.
    Unknown,
}

/// Which of the kit's auth doubles `door` is (compared by fn address).
fn kit_door(door: busbar_contract::abi::mechanism::door::DoorFn) -> KitDoor {
    if super::operator_double::is_door(door) {
        KitDoor::Operator
    } else {
        KitDoor::Unknown
    }
}

/// THE KIT'S READING of a linked auth door's Statement (`RootInstall::auth_chain_module`): whether
/// it declares an INBOUND auth-chain module — an inbound capability, and not a host-held
/// credentials' verifier (the loader's `declares_chain_module`,
/// `crates/plugin-loader/src/dispatch/kinds/auth.rs`). The operator double states `CAP_INBOUND`
/// (`verify_tail`) and `FACT_OPERATOR` alone, so it is one; a door the kit has no double for is read
/// as none, as the loader reads a door whose Statement does not read as an auth Statement.
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
    /// The build's table entry `(key, canonical, door)`: its key, its canonical name and the former
    /// names the root migration table gives its key (the loader's `Manifest::answers_to` over a linked
    /// row).
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

/// One auth row the stand-in answers.
enum AuthRow {
    /// A row this build links.
    Linked(LinkedAuthRow),
    /// A dropped-in row of the registry.
    Dropped(Row),
}

/// THE STAND-IN AXIS over one build's registry.
struct StandIn {
    registry: Arc<dyn PluginRows>,
}

impl StandIn {
    /// The linked auth rows, in registration order: the build's table
    /// (`busbar_kernel_identity::operator::linked`), then any linked auth row the registry holds
    /// with a door of its own (a test's rows double, [`super::rows::Rows::with_linked`]) that the
    /// table does not already link.
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

    /// The auth row config names by `module`: a linked row first, then the registry's dropped-in
    /// `kind: auth` row.
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

    /// The linked rows of a test's rows double that state the default inbound style
    /// ([`super::rows::Rows::with_linked_style`]): each row's key and its lines.
    fn inbound_styles(&self) -> Vec<(String, Vec<String>)> {
        self.registry
            .as_any()
            .downcast_ref::<super::rows::Rows>()
            .map(super::rows::Rows::inbound_styles)
            .unwrap_or_default()
    }

    /// What the stand-in states for `module`'s row: its own carriers (a row stating the default
    /// inbound style states its lines). A row that will not load here states none.
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

    /// The first linked row the operator double answers, under its key, and the principal the
    /// double states. A dropped-in row will not load here and states nothing.
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

    /// No row the stand-in answers states `FACT_READS_CREDENTIALS` (the operator double does not).
    fn credential_readers(&self) -> Vec<String> {
        Vec::new()
    }

    /// The row's own; where no row answers the operator credential, the double's operator carriers.
    fn carriers(&self, module: &str) -> Vec<String> {
        let rows = self.row_carriers(module);
        if rows.is_empty() && module == crate::config::operator_provider() {
            return double_operator_carriers();
        }
        rows
    }

    /// The lines of the one linked row stating `FACT_DEFAULT_INBOUND_STYLE`
    /// ([`super::rows::Rows::with_linked_style`]); where no row states it, the double's default
    /// inbound style.
    ///
    /// # Errors
    /// Two or more rows state it, in the loader's words (`auth_axis::two_default_inbound_styles`).
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

/// An answer already in hand.
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
