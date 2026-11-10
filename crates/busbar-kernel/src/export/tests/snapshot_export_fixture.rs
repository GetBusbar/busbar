// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A synthetic export door that reports the scope and count of a real host snapshot.
//! It exercises service authority without owning any product's wire grammar.

use busbar_contract::abi::export::{CheckIn, CheckOut, ServeIn, ServeOut, StatusOut};
use busbar_contract::abi::host::service::{SNAPSHOT_SCOPE_HOOKS, SNAPSHOT_SCOPE_WHOLE};
use busbar_contract::abi::mechanism::call::{InHead, Outcome, BLOB_OCTETS};
use busbar_contract::abi::mechanism::ticket::CompletionHandle;
use busbar_contract::abi::sdk::door::abi_str;
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot, ServiceError};
use busbar_contract::plugin::markers::ExportKind;
use std::task::Poll;

pub const WHOLE: &str = "/test-snapshot";
pub const HOOKS: &str = "/test-auxiliary";

pub struct Reader;

impl Life for Reader {
    type Kind = ExportKind;
    const CANCEL: u32 = 0;

    fn open(_: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        Ok(Self)
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }
}

pub struct Quiet<I, O>(std::marker::PhantomData<(I, O)>);

impl<I: busbar_contract::abi::sdk::door::AbiIn, O: busbar_contract::abi::sdk::door::AbiOut> SafeSlot
    for Quiet<I, O>
{
    type Kind = ExportKind;
    type In = I;
    type Out = O;
    type State = Held<Reader>;

    fn call(_: Instance<'_, Held<Reader>, ExportKind>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Ready
    }
}

pub struct Read;

impl SafeSlot for Read {
    type Kind = ExportKind;
    type In = ServeIn;
    type Out = ServeOut;
    type State = Held<Reader>;

    fn call(
        instance: Instance<'_, Held<Reader>, ExportKind>,
        input: Lent<'_, ServeIn>,
        mut out: Out<'_, ServeOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return Outcome::Fault;
        };
        let scope = match input.field(|i| &i.path).as_str() {
            Ok(WHOLE) => SNAPSHOT_SCOPE_WHOLE,
            Ok(HOOKS) => SNAPSHOT_SCOPE_HOOKS,
            _ => return out.fail(Refusal::refused("unknown fixture route")),
        };
        let Some(services) = held.host().and_then(|host| host.services()) else {
            return out.fail(Refusal::failed("missing host services"));
        };
        let handle = CompletionHandle {
            ticket: instance.ticket(),
            seq: 0,
            ..CompletionHandle::ZERO
        };
        let mut buffer = zeroize::Zeroizing::new(vec![0_u64; 8192]);
        let answer = match services.snapshot_read(handle, scope, &mut buffer) {
            Poll::Ready(Err(ServiceError::Short { bytes, .. })) if bytes <= 1024 * 1024 => {
                buffer = zeroize::Zeroizing::new(vec![0; (bytes as usize).div_ceil(8)]);
                services.snapshot_read(handle, scope, &mut buffer)
            }
            answer => answer,
        };
        let families = match answer {
            Poll::Pending => return Outcome::Pending,
            Poll::Ready(Ok(Some(families))) => families,
            Poll::Ready(Ok(None)) => return out.fail(Refusal::refused("snapshot not ready")),
            Poll::Ready(Err(_)) => return out.fail(Refusal::refused("snapshot read refused")),
        };
        let mut body = Vec::with_capacity(12);
        body.extend(scope.to_le_bytes());
        body.extend((families.len() as u64).to_le_bytes());
        out.set(|o| &o.status_code, 200);
        out.lease_secret(|o| &o.body, held.leases(), body, BLOB_OCTETS);
        Outcome::Ready
    }
}

const ROUTES: &[busbar_contract::abi::export::Route] = &[
    busbar_contract::abi::export::Route {
        path: abi_str(WHOLE),
        method: abi_str("GET"),
        auth: busbar_contract::abi::export::ROUTE_AUTH_KEY,
        _reserved: 0,
    },
    busbar_contract::abi::export::Route {
        path: abi_str(HOOKS),
        method: abi_str("GET"),
        auth: busbar_contract::abi::export::ROUTE_AUTH_KEY,
        _reserved: 0,
    },
];
const TAIL: busbar_contract::abi::export::Tail =
    busbar_contract::abi::sdk::export::tail(&[], ROUTES);
const STATEMENT: busbar_contract::abi::mechanism::door::Statement =
    busbar_contract::abi::mechanism::door::Statement {
        kind_tail: (&TAIL as *const busbar_contract::abi::export::Tail).cast(),
        ..busbar_contract::abi::sdk::door::statement("snapshot-reader-witness", "0", 4)
    };

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::export::Ops,
    statement: STATEMENT,
    lifecycle: life(Reader),
    kind_ops: {
        status: Safe<Quiet<InHead, StatusOut>>,
        check: Safe<Quiet<CheckIn, CheckOut>>,
        serve: Safe<Read>,
    },
}
