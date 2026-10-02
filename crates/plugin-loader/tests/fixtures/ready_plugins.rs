// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE READY WITNESSES (discovery at boot, ARCHITECT 2026-10-02): a secret kind on the SDK's
//! generic lifecycle whose `ready` ([`Life::ready`]) is driven by its settings, stated on its door
//! (`lifecycle: life(L, ready)`), and the same lifecycle WITHOUT `ready` on its door.
//!
//! Settings: `err:<text>` — `ready` refuses with `<text>`; `pend` — the first `ready` answers
//! PENDING and wakes its ticket from another thread a moment later, and the resume answers READY;
//! anything else — READY at once. A settings blob that is a JSON string is read as its text.
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::conn::Host;
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::secret::{ResolveIn, ResolveOut};

/// The witness's state: its settings, and whether its `ready` has pended once.
pub struct Discovers {
    settings: String,
    pended: AtomicBool,
}

impl Life for Discovers {
    const CANCEL: u32 = 0;

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        // A settings block that is a JSON string (the boot's settings blob) is read as its text.
        let raw = String::from_utf8_lossy(settings).into_owned();
        Ok(Self {
            settings: serde_json::from_str::<String>(&raw).unwrap_or(raw),
            pended: AtomicBool::new(false),
        })
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }

    fn ready(&self, host: &Host, ticket: Ticket) -> Poll<Result<(), Refusal>> {
        if let Some(text) = self.settings.strip_prefix("err:") {
            return Poll::Ready(Err(Refusal::failed(text.to_owned())));
        }
        if self.settings == "pend" && !self.pended.swap(true, Ordering::AcqRel) {
            // The answer arrives later, as a discovery exchange's would: the wake resumes it.
            let host = *host;
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                host.wake(ticket);
            });
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
}

/// `resolve`: never reached by the witnesses.
pub struct Resolve;
impl SafeSlot for Resolve {
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Discovers>;
    fn call(
        _: Instance<'_, Held<Discovers>>,
        _: Lent<'_, ResolveIn>,
        _: Out<'_, ResolveOut>,
    ) -> Outcome {
        Outcome::Refused
    }
}

/// The door that states `ready`.
pub mod with_ready {
    /// Its Statement name.
    pub const NAME: &str = "ready-witness";

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(NAME, "0", 4),
        lifecycle: life(super::Discovers, ready),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

/// The same lifecycle, its door stating no `ready`.
pub mod without_ready {
    /// Its Statement name.
    pub const NAME: &str = "no-ready-witness";

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(NAME, "0", 4),
        lifecycle: life(super::Discovers),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

/// An AUTH door that states `ready` over the same lifecycle (the shape busbar-auth-oidc takes:
/// discovery before it serves). Every auth op refuses: the witnesses are about boot.
pub mod auth {
    use std::marker::PhantomData;

    use busbar_contract::abi::auth::{
        BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut, IdentifyOut,
        OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, VerifyIn,
    };
    use busbar_contract::abi::mechanism::call::Outcome;
    use busbar_contract::abi::sdk::door::{AbiIn, AbiOut};
    use busbar_contract::abi::sdk::life::Held;
    use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};

    /// Its Statement name.
    pub const NAME: &str = "ready-auth-witness";

    /// An auth op this witness does not serve.
    pub struct Refuses<I, O>(PhantomData<(I, O)>);
    impl<I: AbiIn, O: AbiOut> SafeSlot for Refuses<I, O> {
        type In = I;
        type Out = O;
        type State = Held<super::Discovers>;
        fn call(_: Instance<'_, Self::State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
            Outcome::Refused
        }
    }

    type R<I, O> = busbar_contract::abi::sdk::Safe<Refuses<I, O>>;

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::auth::Ops,
        statement: busbar_contract::abi::sdk::door::statement(NAME, "0", 4),
        lifecycle: life(super::Discovers, ready),
        kind_ops: {
            verify: R<VerifyIn, IdentifyOut>,
            begin_login: R<BeginLoginIn, BeginLoginOut>,
            complete_login: R<CompleteLoginIn, IdentifyOut>,
            open_outbound: R<OpenOutboundIn, OpenOutboundOut>,
            outbound_ready: R<OutboundReadyIn, OutboundReadyOut>,
            fields: R<FieldsIn, FieldsOut>,
        },
    }
}
