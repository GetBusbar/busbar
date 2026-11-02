// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::marker::PhantomData;
use std::sync::Mutex;

use busbar_contract::abi::hook::*;
use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome, BLOB_OCTETS};
use busbar_contract::abi::sdk::door::{AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::{settings_object, Held, Life, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};

pub const NAME: &str = "hook-checkpoint-fixture";
const KEY: &str = "hook.configure_checkpoint.v1";
type ConfigureDrop = (
    std::sync::mpsc::Sender<()>,
    std::sync::mpsc::Receiver<()>,
    std::sync::mpsc::Sender<()>,
);
pub static DROP_CONFIGURE: Mutex<Option<ConfigureDrop>> = Mutex::new(None);
pub static BLOCK_CONFIGURE: Mutex<
    Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
> = Mutex::new(None);
pub struct Gate {
    applied: Mutex<(u64, u64, u64)>,
    mode: String,
}

impl Life for Gate {
    const CANCEL: u32 = cancel::ABORTED;

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        let settings = settings_object(settings)?;
        let limit = settings
            .get("reject_over_messages")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| Refusal::failed("settings: limit must be a number"))?;
        Ok(Self {
            applied: Mutex::new((limit, 0, 0)),
            mode: settings
                .get("checkpoint_mode")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("valid")
                .to_owned(),
        })
    }
}

pub struct Decide;
impl SafeSlot for Decide {
    type In = DecideIn;
    type Out = DecideOut;
    type State = Held<Gate>;
    fn call(
        instance: Instance<'_, Self::State>,
        input: Lent<'_, Self::In>,
        mut out: Out<'_, Self::Out>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        let over = held.life().applied.lock().unwrap().0;
        if input.request.message_count > over {
            out.set(|o| &o.verbs, VERB_REJECT | VERB_HAS_REJECT_STATUS);
            out.set(|o| &o.reject_status, 429);
        } else {
            out.set(|o| &o.verbs, VERB_ABSTAIN);
        }
        Outcome::Ready
    }
}

pub struct Configure;
impl SafeSlot for Configure {
    type In = ConfigureIn;
    type Out = ConfigureOut;
    type State = Held<Gate>;
    fn call(
        instance: Instance<'_, Self::State>,
        input: Lent<'_, Self::In>,
        mut out: Out<'_, Self::Out>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        let settings = match settings_object(input.field(|i| &i.settings).bytes()) {
            Ok(settings) => settings,
            Err(error) => return out.fail(error),
        };
        let drop_block = if held.life().mode == "block_drop" {
            DROP_CONFIGURE.lock().unwrap().take()
        } else {
            None
        };
        let committed = if let Some((entered, released, committed)) = drop_block {
            entered.send(()).unwrap();
            released
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
            Some(committed)
        } else {
            None
        };
        let block = if held.life().mode == "block_replay" {
            BLOCK_CONFIGURE.lock().unwrap().take()
        } else {
            None
        };
        if let Some((entered, released)) = block {
            entered.send(()).unwrap();
            released
                .recv_timeout(std::time::Duration::from_secs(5))
                .unwrap();
        }
        let mut current = held.life().applied.lock().unwrap();
        if input.version >= current.1 {
            let next = match settings.get("reject_over_messages") {
                None | Some(serde_json::Value::Null) => current.0,
                Some(value) => match value.as_u64() {
                    Some(value) => value,
                    None => return out.fail(Refusal::failed("limit must be a number")),
                },
            };
            *current = (next, input.version, current.2 + 1);
        }
        if held.life().mode != "none" {
            let mut value = current.2.to_le_bytes().to_vec();
            value.extend_from_slice(&current.1.to_le_bytes());
            value.extend_from_slice(
                serde_json::json!({"reject_over_messages": current.0})
                    .to_string()
                    .as_bytes(),
            );
            let mut bytes = busbar_contract::abi::mechanism::extensions::encode(&[(KEY, &value)]);
            if held.life().mode == "malformed" {
                bytes.pop();
            }
            out.lease_secret(|o| &o.head.extensions, held.leases(), bytes, BLOB_OCTETS);
        }
        out.set(|o| &o.acked_version, input.version);
        if let Some(committed) = committed {
            let _ = committed.send(());
        }
        Outcome::Ready
    }
}

pub struct Refuse<I, O>(PhantomData<(I, O)>);
impl<I: AbiIn, O: AbiOut> SafeSlot for Refuse<I, O> {
    type In = I;
    type Out = O;
    type State = Held<Gate>;
    fn call(_: Instance<'_, Self::State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}

pub struct Notify;
impl SafeSlot for Notify {
    type In = NotifyIn;
    type Out = OutHead;
    type State = Held<Gate>;
    fn call(
        instance: Instance<'_, Self::State>,
        _: Lent<'_, Self::In>,
        mut out: Out<'_, Self::Out>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        if held.life().mode == "cap_timeout" {
            return Outcome::Pending;
        }
        let bytes =
            busbar_contract::abi::mechanism::extensions::encode(&[("fixture.notify", b"retained")]);
        out.lease_secret(|o| &o.extensions, held.leases(), bytes, BLOB_OCTETS);
        Outcome::Ready
    }
}

pub struct Status;
impl SafeSlot for Status {
    type In = InHead;
    type Out = StatusOut;
    type State = Held<Gate>;
    fn call(
        instance: Instance<'_, Self::State>,
        _: Lent<'_, Self::In>,
        mut out: Out<'_, Self::Out>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        let bytes = serde_json::json!({"held": held.leases().held()})
            .to_string()
            .into_bytes();
        out.lease(
            |o| &o.status,
            held.leases(),
            bytes,
            busbar_contract::abi::mechanism::call::BLOB_JSON,
        );
        Outcome::Ready
    }
}

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::hook::Ops,
    statement: busbar_contract::abi::sdk::hook::statement_with_tail(
        busbar_contract::abi::sdk::door::statement(NAME, "1.6.0", 8),
        &busbar_contract::abi::sdk::hook::tail(CLASS_GATE, PROMPT_NO, USER_NO),
    ),
    lifecycle: life(Gate),
    kind_ops: {
        decide: busbar_contract::abi::sdk::Safe<Decide>,
        transform: busbar_contract::abi::sdk::Safe<Refuse<DecideIn, TransformOut>>,
        notify: busbar_contract::abi::sdk::Safe<Notify>,
        configure: busbar_contract::abi::sdk::Safe<Configure>,
        status: busbar_contract::abi::sdk::Safe<Status>,
        describe: busbar_contract::abi::sdk::Safe<Refuse<InHead, DescribeOut>>,
        serve: busbar_contract::abi::sdk::Safe<Refuse<ServeIn, ServeOut>>,
    },
}
