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

/// The AUTH witnesses (the shape busbar-auth-oidc takes): `auth` states `ready` over
/// [`Discovers`]; `auth_secret` declares the secret reference `client_secret` and opens only when
/// it is handed exactly that secret, resolved, and its settings no longer carry the reference.
/// Every auth op refuses: the witnesses are about boot.
pub mod auth {
    use std::marker::PhantomData;

    use busbar_contract::abi::auth::{
        AuthPoints, AuthTail, BeginLoginIn, BeginLoginOut, CompleteLoginIn, FieldsIn, FieldsOut,
        IdentifyOut, OpenOutboundIn, OpenOutboundOut, OutboundReadyIn, OutboundReadyOut, VerifyIn,
    };
    use busbar_contract::abi::sdk::auth_door::{verify_tail, with_tail};
    use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
    use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
    use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};

    /// The `ready` witness's Statement name.
    pub const NAME: &str = "ready-auth-witness";
    /// The secret witness's Statement name.
    pub const SECRET_NAME: &str = "secret-auth-witness";
    /// The settings key the secret witness declares as a secret reference.
    pub const SECRET_KEY: &str = "client_secret";
    /// The bytes the secret witness must be handed.
    pub const SECRET: &[u8] = b"s3cret";

    const SECRET_REFS: &[AbiStr] = &[abi_str(SECRET_KEY)];

    /// The kind tail every auth Statement states (train/14's auth door refuses a Statement with
    /// none): inbound at `Head`, no facts. The witnesses serve no op; the tail only admits them.
    const TAIL: &AuthTail = &verify_tail(0, AuthPoints::HEAD);

    /// An auth op the witnesses do not serve.
    pub struct Refuses<L, I, O>(PhantomData<(L, I, O)>);
    impl<L: Life, I: AbiIn, O: AbiOut> SafeSlot for Refuses<L, I, O> {
        type In = I;
        type Out = O;
        type State = Held<L>;
        fn call(_: Instance<'_, Self::State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
            Outcome::Refused
        }
    }

    type R<L, I, O> = busbar_contract::abi::sdk::Safe<Refuses<L, I, O>>;

    /// The secret witness's state: it opens only over its resolved secret.
    pub struct NeedsSecret;

    impl Life for NeedsSecret {
        const CANCEL: u32 = 0;

        fn open(settings: &[u8], secrets: &[&[u8]], _: u64) -> Result<Self, Refusal> {
            if secrets != [SECRET] {
                return Err(Refusal::failed(format!(
                    "{} secret(s) handed, not the resolved {SECRET_KEY}",
                    secrets.len()
                )));
            }
            if String::from_utf8_lossy(settings).contains(SECRET_KEY) {
                return Err(Refusal::failed("the secret reference reached the settings"));
            }
            Ok(Self)
        }

        fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
            Ok(Refreshed::default())
        }
    }

    macro_rules! auth_door {
        ($life:ty, $statement:expr, $($ready:ident)?) => {
            busbar_contract::plugin_door! {
                ops: busbar_contract::abi::auth::Ops,
                statement: $statement,
                lifecycle: life($life $(, $ready)?),
                kind_ops: {
                    verify: R<$life, VerifyIn, IdentifyOut>,
                    begin_login: R<$life, BeginLoginIn, BeginLoginOut>,
                    complete_login: R<$life, CompleteLoginIn, IdentifyOut>,
                    open_outbound: R<$life, OpenOutboundIn, OpenOutboundOut>,
                    outbound_ready: R<$life, OutboundReadyIn, OutboundReadyOut>,
                    fields: R<$life, FieldsIn, FieldsOut>,
                },
            }
        };
    }

    /// The `ready` witness.
    pub mod with_ready {
        use super::*;
        auth_door!(
            super::super::Discovers,
            with_tail(statement(NAME, "0", 4), TAIL),
            ready
        );
    }

    /// The secret witness.
    pub mod with_secret {
        use super::*;
        auth_door!(
            NeedsSecret,
            with_tail(
                busbar_contract::abi::mechanism::door::Statement {
                    secret_refs: SECRET_REFS.as_ptr(),
                    secret_refs_len: SECRET_REFS.len(),
                    ..statement(SECRET_NAME, "0", 4)
                },
                TAIL
            ),
        );
    }
}
