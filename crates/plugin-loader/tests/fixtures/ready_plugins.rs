// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};
use busbar_contract::abi::secret::{ResolveIn, ResolveOut};

pub struct Discovers<
    K: busbar_contract::plugin::KindMarker = busbar_contract::plugin::markers::SecretKind,
> {
    kind: std::marker::PhantomData<K>,
    settings: String,
    pended: AtomicBool,
}

impl<K: busbar_contract::plugin::KindMarker> Life for Discovers<K> {
    type Kind = K;
    const CANCEL: u32 = 0;

    fn open(settings: &[u8], _: &[&[u8]], _: u64) -> Result<Self, Refusal> {
        let raw = String::from_utf8_lossy(settings).into_owned();
        Ok(Self {
            settings: serde_json::from_str::<String>(&raw).unwrap_or(raw),
            pended: AtomicBool::new(false),
            kind: std::marker::PhantomData,
        })
    }

    fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
        Ok(Refreshed::default())
    }

    fn ready(
        &self,
        host: &busbar_contract::abi::sdk::conn::Host<Self::Kind>,
        ticket: Ticket,
    ) -> Poll<Result<(), Refusal>> {
        self.ready_with(host, ticket)
    }
}
impl<K: busbar_contract::plugin::KindMarker> Discovers<K> {
    fn ready_with<H: busbar_contract::plugin::KindMarker>(
        &self,
        host: &busbar_contract::abi::sdk::conn::Host<H>,
        ticket: Ticket,
    ) -> Poll<Result<(), Refusal>> {
        if let Some(text) = self.settings.strip_prefix("err:") {
            return Poll::Ready(Err(Refusal::failed(text.to_owned())));
        }
        if self.settings == "pend" && !self.pended.swap(true, Ordering::AcqRel) {
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

pub struct Resolve;
impl SafeSlot for Resolve {
    type Kind = busbar_contract::plugin::markers::SecretKind;
    type In = ResolveIn;
    type Out = ResolveOut;
    type State = Held<Discovers>;
    fn call(
        _: Instance<'_, Held<Discovers>, Self::Kind>,
        _: Lent<'_, ResolveIn>,
        _: Out<'_, ResolveOut>,
    ) -> Outcome {
        Outcome::Refused
    }
}

pub mod with_ready {

    pub const NAME: &str = "ready-witness";

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(NAME, "0", 4),
        lifecycle: life(super::Discovers, ready),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

pub mod without_ready {

    pub const NAME: &str = "no-ready-witness";

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::secret::Ops,
        statement: busbar_contract::abi::sdk::door::statement(NAME, "0", 4),
        lifecycle: life(super::Discovers),
        kind_ops: { resolve: busbar_contract::abi::sdk::Safe<super::Resolve> },
    }
}

pub mod export {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;

    use busbar_contract::abi::export::{
        CheckIn, CheckOut, DeliverIn, ScrapeIn, ScrapeOut, ServeIn, ServeOut, StatusOut,
    };
    use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
    use busbar_contract::abi::mechanism::ticket::Ticket;
    type Host = busbar_contract::abi::sdk::conn::Host<busbar_contract::plugin::markers::ExportKind>;
    use busbar_contract::abi::sdk::life::{Held, Life, Refreshed, Refusal};
    use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};

    pub static READIES: AtomicUsize = AtomicUsize::new(0);

    pub struct Exports(super::Discovers);

    impl Life for Exports {
        type Kind = busbar_contract::plugin::markers::ExportKind;
        const CANCEL: u32 = 0;

        fn open(settings: &[u8], secrets: &[&[u8]], generation: u64) -> Result<Self, Refusal> {
            let text = serde_json::from_slice::<serde_json::Value>(settings)
                .ok()
                .and_then(|v| v.get("ready").and_then(|r| r.as_str()).map(str::to_owned))
                .unwrap_or_default();
            super::Discovers::open(text.as_bytes(), secrets, generation).map(Self)
        }

        fn refresh(&self, _: &[u8], _: &[&[u8]], _: u64) -> Result<Refreshed, Refusal> {
            Ok(Refreshed::default())
        }

        fn ready(&self, host: &Host, ticket: Ticket) -> Poll<Result<(), Refusal>> {
            READIES.fetch_add(1, Ordering::SeqCst);
            self.0.ready_with(host, ticket)
        }
    }

    pub struct Answers<I, O>(std::marker::PhantomData<(I, O)>);
    impl<I: busbar_contract::abi::sdk::door::AbiIn, O: busbar_contract::abi::sdk::door::AbiOut>
        SafeSlot for Answers<I, O>
    {
        type Kind = busbar_contract::plugin::markers::ExportKind;
        type In = I;
        type Out = O;
        type State = Held<Exports>;
        fn call(
            _: Instance<'_, Held<Exports>, Self::Kind>,
            _: Lent<'_, I>,
            _: Out<'_, O>,
        ) -> Outcome {
            Outcome::Ready
        }
    }

    pub const NAME: &str = "ready-export-witness";

    const STREAMS: &[u8] = &[busbar_contract::export_stream::ExportStream::Logs as u8];

    const TAIL: busbar_contract::abi::export::Tail = busbar_contract::abi::export::Tail {
        head: busbar_contract::abi::mechanism::door::KindTailHead {
            size: std::mem::size_of::<busbar_contract::abi::export::Tail>() as u32,
            ..busbar_contract::abi::mechanism::door::KindTailHead::ZERO
        },
        streams: STREAMS.as_ptr(),
        streams_len: STREAMS.len(),
        ..busbar_contract::abi::export::Tail::ZERO
    };

    const STATEMENT: busbar_contract::abi::mechanism::door::Statement =
        busbar_contract::abi::mechanism::door::Statement {
            kind_tail: (&TAIL as *const busbar_contract::abi::export::Tail)
                .cast::<busbar_contract::abi::mechanism::door::KindTailHead>(),
            ..busbar_contract::abi::sdk::door::statement(NAME, "0", 4)
        };

    busbar_contract::plugin_door! {
        ops: busbar_contract::abi::export::Ops,
        statement: STATEMENT,
        lifecycle: life(Exports, ready),
        kind_ops: {
            deliver: busbar_contract::abi::sdk::Safe<Answers<DeliverIn, OutHead>>,
            scrape: busbar_contract::abi::sdk::Safe<Answers<ScrapeIn, ScrapeOut>>,
            status: busbar_contract::abi::sdk::Safe<Answers<InHead, StatusOut>>,
            check: busbar_contract::abi::sdk::Safe<Answers<CheckIn, CheckOut>>,
            serve: busbar_contract::abi::sdk::Safe<Answers<ServeIn, ServeOut>>,
        },
    }
}
