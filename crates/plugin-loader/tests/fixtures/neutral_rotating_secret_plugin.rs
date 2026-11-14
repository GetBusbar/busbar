// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Rotating-credential secret-kind witness: a NEUTRAL fixture (no external state, no real source)
//! whose Statement lends one secret reference, `credential`. It exists for the host's re-lend and
//! open lifecycle, and is deliberately separate from the shared secret witness, whose Statement
//! other cells pin.
//!
//! - `open` refuses a lent credential equal to `refuse`; with settings `open: pending` its open
//!   pends once before it is READY.
//! - `resolve` answers `held:<hex sha256 of the credential this instance holds>`, so a cell can
//!   tell which material answered without the material itself.
//! - `refresh` per settings `refresh`: `adopt` (default) takes the re-lent credential in place,
//!   `refuse` refuses it, `none` answers the SDK's not-refreshed refusal (a plugin with no refresh).
//! - `tick` asks to be ticked every 5 ms and counts its ticks.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use busbar_contract::abi::mechanism::call::{AbiStr, OutHead, Outcome};
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::life::{Held, Life, Opening, Refreshed, Refusal, NOT_REFRESHED};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::secret::{cancel, CheckIn, ResolveIn, ResolveOut};

pub const NAME: &str = "neutral-rotating-secret";
pub const CREDENTIAL: &str = "credential";
const SECRET_REFS: &[AbiStr] = &[abi_str(CREDENTIAL)];

/// Opens that reached READY, process-wide (per loaded image).
pub static OPENED: AtomicU64 = AtomicU64::new(0);
/// Ticks answered, process-wide (per loaded image).
pub static TICKED: AtomicU64 = AtomicU64::new(0);

pub struct Rotating {
    held: Mutex<Vec<u8>>,
    refresh: String,
    pending: bool,
}

fn setting(settings: &[u8], key: &str) -> String {
    serde_json::from_slice::<serde_json::Value>(settings)
        .ok()
        .and_then(|v| v.get(key).and_then(|v| v.as_str()).map(str::to_string))
        .unwrap_or_default()
}

/// What `resolve` answers for `credential`.
#[must_use]
pub fn answer_for(credential: &[u8]) -> String {
    let digest = busbar_contract::abi::sdk::digest::sha256(credential);
    let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
    format!("held:{hex}")
}

impl Life for Rotating {
    type Kind = busbar_contract::plugin::markers::SecretKind;
    const CANCEL: u32 = cancel::ABORTED;

    fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        let credential = secrets.first().copied().unwrap_or_default();
        if credential == b"refuse" {
            return Err(Refusal::failed("the witness refuses this credential"));
        }
        Ok(Self {
            held: Mutex::new(credential.to_vec()),
            refresh: setting(settings, "refresh"),
            pending: setting(settings, "open") == "pending",
        })
    }

    fn opening(
        &self,
        _: Option<&busbar_contract::abi::sdk::conn::Host<Self::Kind>>,
        _: Ticket,
        parked: Option<Box<dyn std::any::Any + Send + Sync>>,
    ) -> Opening {
        if self.pending && parked.is_none() {
            return Opening::Pending {
                wake_at_ns: 1,
                parked: Box::new(()),
            };
        }
        OPENED.fetch_add(1, Ordering::SeqCst);
        Opening::Ready
    }

    fn refresh(&self, _: &[u8], secrets: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        match self.refresh.as_str() {
            "none" => Err(Refusal::refused(NOT_REFRESHED)),
            "refuse" => Err(Refusal::refused(
                "the witness refuses the rotated credential",
            )),
            _ => {
                *self.held.lock().unwrap_or_else(|e| e.into_inner()) =
                    secrets.first().copied().unwrap_or_default().to_vec();
                Ok(Refreshed::default())
            }
        }
    }

    fn tick(&self, now_ns: u64) -> u64 {
        TICKED.fetch_add(1, Ordering::SeqCst);
        now_ns + 5_000_000
    }
}

pub struct Resolve;
impl SafeSlot for Resolve {
    type Kind = busbar_contract::plugin::markers::SecretKind;
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Rotating>;
    fn call(
        instance: Instance<'_, Self::State, Self::Kind>,
        input: Lent<'_, ResolveIn>,
        mut out: Out<'_, ResolveOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        let answer = answer_for(&held.life().held.lock().unwrap_or_else(|e| e.into_inner()));
        busbar_contract::abi::sdk::cred::resolved(
            input,
            &mut out,
            busbar_contract::abi::sdk::cred::Held::new(answer.into_bytes()),
        )
    }
}

pub struct Check;
impl SafeSlot for Check {
    type Kind = busbar_contract::plugin::markers::SecretKind;
    type In = CheckIn;
    type Out = OutHead;
    type State = Held<Rotating>;
    fn call(
        _: Instance<'_, Self::State, Self::Kind>,
        _: Lent<'_, CheckIn>,
        _: Out<'_, OutHead>,
    ) -> Outcome {
        Outcome::Ready
    }
}

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::secret::Ops,
    statement: busbar_contract::abi::mechanism::door::Statement {
        secret_refs: SECRET_REFS.as_ptr(),
        secret_refs_len: SECRET_REFS.len(),
        ..busbar_contract::abi::sdk::door::statement(NAME, "1.6.0", 16)
    },
    lifecycle: life(Rotating),
    kind_ops: {
        resolve: busbar_contract::abi::sdk::Safe<Resolve>,
        check: busbar_contract::abi::sdk::Safe<Check>,
    },
}
