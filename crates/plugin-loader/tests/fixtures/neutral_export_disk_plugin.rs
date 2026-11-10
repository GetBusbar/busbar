// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A disk-service ABI witness; it forwards opaque bytes and reports host result flags.
use busbar_contract::abi::export::{self, CheckIn, CheckOut, DeliverIn, ExportStream, Tail};
use busbar_contract::abi::mechanism::call::{OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::export::{NoScrape, Quiet};
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};
use busbar_contract::plugin::markers::ExportKind;

pub struct Witness;
impl Life for Witness {
    type Kind = ExportKind;
    const CANCEL: u32 = export::cancel::ABORTED;
    fn validate(bytes: &[u8]) -> Result<(), Refusal> {
        let value = busbar_contract::abi::sdk::life::settings_value(bytes)?;
        if value.get("reject").is_some() {
            Err(Refusal::refused("witness settings refused"))
        } else {
            Ok(())
        }
    }
    fn open(bytes: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Self::validate(bytes)?;
        Ok(Self)
    }
    fn refresh(&self, bytes: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Self::validate(bytes)?;
        Ok(Refreshed::default())
    }
}
pub struct Check;
impl SafeSlot for Check {
    type Kind = ExportKind;
    type In = CheckIn;
    type Out = CheckOut;
    type State = Held<Witness>;
    fn call(
        _: Instance<'_, Self::State, ExportKind>,
        _: Lent<'_, CheckIn>,
        _: Out<'_, CheckOut>,
    ) -> Outcome {
        Outcome::Ready
    }
}

use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::export::NoServe;
use std::task::Poll;
const TAIL: Tail = busbar_contract::abi::sdk::export::tail(&[ExportStream::Logs as u8], &[]);
const IDS: &[busbar_contract::abi::mechanism::call::AbiStr] =
    &[abi_str("BUSBAR-9902"), abi_str("BUSBAR-9903")];
const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    diag_ids: IDS.as_ptr(),
    diag_ids_len: IDS.len(),
    ..statement("neutral-export-disk-witness", "1.6.0", 64)
};
pub struct Deliver;
impl SafeSlot for Deliver {
    type Kind = ExportKind;
    type In = DeliverIn;
    type Out = OutHead;
    type State = Held<Witness>;
    fn call(
        instance: Instance<'_, Self::State, ExportKind>,
        input: Lent<'_, DeliverIn>,
        mut out: Out<'_, OutHead>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        let Some(host) = held.host() else {
            return Outcome::Refused;
        };
        match host
            .connector(instance.ticket())
            .disk_append("output", input.field(|i| &i.batch).bytes())
        {
            Poll::Pending => Outcome::Pending,
            Poll::Ready(Ok(result)) => {
                if result.rotated & busbar_contract::abi::host::service::DISK_ROTATED != 0 {
                    out.diag(0, 0, "witness host rotated");
                }
                Outcome::Ready
            }
            Poll::Ready(Err(error)) => {
                out.diag(
                    1,
                    1,
                    format!("BUSBAR-9903 witness host refused: {:?}", error.why),
                );
                Outcome::Ready
            }
        }
    }
}
busbar_contract::plugin_door! { ops: busbar_contract::abi::export::Ops, statement: STATEMENT, lifecycle: life(Witness), kind_ops: {
    deliver: Safe<Deliver>, scrape: Safe<NoScrape<Witness>>, status: Safe<Quiet<Witness>>, check: Safe<Check>, serve: Safe<NoServe<Witness>>,
} }
