// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A route/lifetime ABI witness. Its constant response has no exporter format.
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

use busbar_contract::abi::export::{Route, ServeIn, ServeOut, ROUTE_AUTH_KEY};
use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_INBOUND};
use busbar_contract::abi::mechanism::call::BLOB_OCTETS;
use busbar_contract::abi::sdk::door::abi_str;
pub const BODY: &[u8] = b"neutral route witness";
const ROUTES: &[Route] = &[
    Route {
        path: abi_str("/capture"),
        method: abi_str("GET"),
        auth: ROUTE_AUTH_KEY,
        _reserved: 0,
    },
    Route {
        path: abi_str("/retained"),
        method: abi_str("GET"),
        auth: ROUTE_AUTH_KEY,
        _reserved: 0,
    },
];
const TAIL: Tail = busbar_contract::abi::sdk::export::tail(&[ExportStream::Logs as u8], ROUTES);
const NEEDS: &[Need] = &[Need {
    direction: DIRECTION_INBOUND,
    transport: abi_str("http"),
    target_from: abi_str("listen"),
    ..Need::EMPTY
}];
busbar_contract::statement_extensions!(EXTENSIONS: [
    (busbar_contract::export_calls::EXT_PUBLIC_ROUTES, br#"["/capture","/retained"]"#),
    (busbar_contract::export_calls::EXT_PERSISTENT_ROUTES, br#"["/retained"]"#),
]);
const STATEMENT: Statement = Statement {
    kind_tail: (&TAIL as *const Tail).cast::<KindTailHead>(),
    needs: NEEDS.as_ptr(),
    needs_len: NEEDS.len(),
    extensions: EXTENSIONS,
    ..statement("neutral-export-routes-witness", "1.6.0", 64)
};
pub struct Deliver;
impl SafeSlot for Deliver {
    type Kind = ExportKind;
    type In = DeliverIn;
    type Out = OutHead;
    type State = Held<Witness>;
    fn call(
        _: Instance<'_, Self::State, ExportKind>,
        _: Lent<'_, DeliverIn>,
        _: Out<'_, OutHead>,
    ) -> Outcome {
        Outcome::Ready
    }
}
pub struct Serve;
impl SafeSlot for Serve {
    type Kind = ExportKind;
    type In = ServeIn;
    type Out = ServeOut;
    type State = Held<Witness>;
    fn call(
        instance: Instance<'_, Self::State, ExportKind>,
        input: Lent<'_, ServeIn>,
        mut out: Out<'_, ServeOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Refused;
        };
        if !matches!(
            input.field(|i| &i.path).as_str(),
            Ok("/capture" | "/retained")
        ) {
            return Outcome::Refused;
        }
        out.set(|o| &o.status_code, 200);
        out.lease(|o| &o.body, held.leases(), BODY.to_vec(), BLOB_OCTETS);
        Outcome::Ready
    }
}
busbar_contract::plugin_door! { ops: busbar_contract::abi::export::Ops, statement: STATEMENT, lifecycle: life(Witness), kind_ops: {
    deliver: Safe<Deliver>, scrape: Safe<NoScrape<Witness>>, status: Safe<Quiet<Witness>>, check: Safe<Check>, serve: Safe<Serve>,
} }
