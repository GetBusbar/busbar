// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use busbar_contract::auth_calls::codes::{FIELD_QUERY, FIELD_SENSITIVE};
use busbar_contract::auth_calls::StripPlace;
use busbar_kernel::inbound::{self as kin, Inbound};

use crate::root::loader::dispatch::auth_handle::{
    self, AuthCallAnswer, AuthCallAsk, AuthDone, AuthHandleHost, AuthRan, HandInAsk, HeadCopy,
    RefusalBytes, RefuseAsk, StreamPolicy, UnitSecret,
};

pub(crate) const ROOT_OWNER: u64 = 0;

pub fn host() -> &'static Arc<Inbound> {
    static ONE: OnceLock<Arc<Inbound>> = OnceLock::new();
    ONE.get_or_init(|| {
        Inbound::new(
            kin::Seals {
                mint: Arc::new(|| mint_on(&crate::root::plane_node::node())),
                mac: Arc::new(|t: &kin::UnitTag| {
                    auth_handle::mint_unit_ref(t.secret, t.generation, t.owner, t.line, t.unit)
                        .map(|u| u.mac)
                }),
            },
            Arc::new(|f| match tokio::runtime::Handle::try_current() {
                Ok(rt) => drop(rt.spawn(f)),

                Err(_) => drop(std::thread::spawn(move || {
                    busbar_kernel::rt::current_thread()
                        .enable_all()
                        .build()
                        .map(|rt| rt.block_on(f))
                })),
            }),
            Arc::new(refused),
        )
    })
}

/// A full audit lane stops new identities before the kernel constructs a UnitTag.
/// Existing units can still end and retain their one record for the normal retry tick.
pub(in crate::root) fn mint_on(node: &crate::root::plane_node::Node) -> u64 {
    if node.journal_refusal().is_some() {
        0
    } else {
        node.mint().get()
    }
}

fn refused(r: &kin::RefusedUnit) {
    crate::root::plane_node::node().refused_inbound(r);
    tracing::debug!(
        unit = ?r.unit,
        owner = r.owner,
        line = r.line,
        cause = r.cause,
        status = r.status,
        "inbound refusal"
    );
}

pub(in crate::root) struct LoaderSide(pub(in crate::root) Arc<Inbound>);

fn head_of(h: HeadCopy) -> kin::Head {
    kin::Head {
        method: h.method,
        target: h.target,
        authority: h.authority,
        query: h.query,
        fields: h.fields,
    }
}

fn answer_of(a: kin::Answer) -> AuthCallAnswer {
    AuthCallAnswer {
        flow: a.flow,
        unit: a.unit,
        strips: a
            .strips
            .into_iter()
            .map(|s| {
                let flag = match s.place {
                    StripPlace::Field => FIELD_SENSITIVE,
                    StripPlace::Query => FIELD_QUERY,
                };
                (s.name.into_owned(), flag)
            })
            .collect(),
    }
}

impl AuthHandleHost for LoaderSide {
    fn unit_secret(&self, owner: u64, unit: u64) -> Option<UnitSecret> {
        self.0
            .unit_secret(owner, unit)
            .map(|(secret, generation, line)| UnitSecret {
                secret,
                generation,
                line,
            })
    }

    fn auth_call(&self, ask: AuthCallAsk, done: AuthDone) -> AuthRan {
        let call = kin::Call {
            owner: ask.owner,
            generation: ask.generation,
            auth: ask.auth,
            unit: ask.unit,
            point: ask.point,
            conn: ask.conn,
            stream: ask.stream,
            head: head_of(ask.request),
            body: ask.body,
            deadline: ask
                .deadline
                .map(|d| busbar_core_connector::framer::now() + d),
            framing: ask.framing,
        };
        match self
            .0
            .auth_call(call, Box::new(move |r| done(r.map(answer_of))))
        {
            Some(r) => AuthRan::Now(r.map(answer_of)),
            None => AuthRan::Pending,
        }
    }

    fn hand_in(
        &self,
        ask: HandInAsk,
    ) -> Result<(u32, busbar_contract::abi::host::service::UnitRef), &'static str> {
        self.hand_in_with_deadline(ask, None)
    }

    fn hand_in_with_deadline(
        &self,
        ask: HandInAsk,
        deadline: Option<std::time::Duration>,
    ) -> Result<(u32, busbar_contract::abi::host::service::UnitRef), &'static str> {
        self.0.hand_in_with_deadline(
            kin::HandIn {
                owner: ask.owner,
                generation: ask.generation,
                auth: ask.auth,
                unit: ask.unit,
                line: ask.line,
                conn: ask.conn,
                stream: ask.stream,
                framing: ask.framing,
                head: head_of(ask.request),
            },
            deadline.map(|remaining| busbar_core_connector::framer::now() + remaining),
        )
    }

    fn requires_scope(&self) -> bool {
        true
    }

    // No legacy listener registration exists: native listeners admit through PhysicalListener
    // and never mint a framing id (NATIVE-LISTENER-BINDING-r1). A legacy framing is refused.
    fn framing_started(
        &self,
        _owner: u64,
        _listener: u64,
        _framing: u64,
    ) -> Result<Option<StreamPolicy>, &'static str> {
        Err(kin::NO_LIST)
    }

    fn stream_open(
        &self,
        _owner: u64,
        _listener: u64,
        _framing: u64,
        _stream: u64,
    ) -> Result<StreamPolicy, &'static str> {
        Err(kin::NO_LIST)
    }

    fn stream_ended(&self, owner: u64, framing: u64, stream: u64) {
        self.0.stream_ended(owner, framing, stream);
    }

    fn framing_ready(&self, owner: u64, framing: u64) {
        self.0.framing_ready(owner, framing);
    }

    fn framing_detached(&self, owner: u64, framing: u64) -> Result<(), &'static str> {
        self.0.framing_detached(owner, framing)
    }

    fn framing_adopting(
        &self,
        source: busbar_contract::framing_scope::AdoptionSource,
        owner: u64,
        framing: u64,
    ) -> Result<busbar_contract::framing_scope::SessionTransfer, &'static str> {
        self.0.framing_adopting(source, owner, framing)
    }

    fn framing_adopted(&self, owner: u64, framing: u64, conn: u64) -> Result<(), &'static str> {
        self.0.framing_adopted(owner, framing, conn)
    }

    fn framing_ended(&self, framing: u64) {
        self.0.framing_ended(framing);
    }

    fn refuse(&self, ask: RefuseAsk) -> Result<RefusalBytes, &'static str> {
        self.0
            .refuse(kin::Refuse {
                owner: ask.owner,
                generation: ask.generation,
                unit: ask.unit,
                cause: ask.cause,
                line: ask.line,
                conn: ask.conn,
                stream: ask.stream,
                framing: ask.framing,
                request: Some(head_of(ask.request)),
            })
            .map(|r| RefusalBytes {
                status: r.status,
                fields: r.fields,
                body: r.body,
            })
    }
}

pub fn install(dispatcher: &crate::root::loader::dispatch::Dispatcher) -> bool {
    dispatcher.install_auth_handle(Arc::new(LoaderSide(Arc::clone(host()))))
}

pub(crate) type Staged = (
    busbar_kernel::guest::GuestList,
    Vec<busbar_kernel::plane_routes::PlaneRefusalSpec>,
);

pub(crate) fn staged() -> std::sync::MutexGuard<'static, Option<Staged>> {
    static STAGED: Mutex<Option<Staged>> = Mutex::new(None);
    STAGED.lock().unwrap_or_else(PoisonError::into_inner)
}

pub fn stage(
    guests: busbar_kernel::guest::GuestList,
    refusals: Vec<busbar_kernel::plane_routes::PlaneRefusalSpec>,
) {
    *staged() = Some((guests, refusals));
}

pub use crate::root::off_path::inbound::publish;
