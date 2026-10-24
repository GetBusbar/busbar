// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE INBOUND AUTH HANDLE, GLUED (`BUSBAR-1.6.0.md` THE DESIGN §6, "Auth points and guest lists",
//! step 4, l.938-962; Part 2 #65, #74): the kernel's inbound side ([`busbar_kernel::inbound`])
//! served to the plugin loader's auth-handle slots (`auth.call`, `unit.hand_in`, `unit.refuse`)
//! through the loader's [`AuthHandleHost`]. The kernel names no loader and the loader names no
//! kernel; this file is where the two meet, and it injects what the kernel side is minted with:
//!
//! * the unit mint: the process node's one mint ([`crate::root::plane_node::Node::mint`]), so an
//!   inbound unit's key is a key of the node that drives it;
//! * the unit MAC: the loader's keyed MAC under its boot key
//!   ([`auth_handle::mint_unit_ref`]), the one primitive every instance handle and ticket uses;
//! * the spawner a pended `auth.call` finishes on, and the sink every refusal is reported to.
//!
//! THE LISTENER TABLES. The data listener's guest list is sealed where its door routes are built
//! ([`crate::root::serve::door_mounts`], which stages it here with the door routes' unit-less
//! refusals); [`publish`] installs it with the generation's opened auths, the size gate's limit
//! and the generation's app, and publishes the generation the loader verifies refs against. A
//! listener's table is keyed by THE IDENTITY OF THE TRANSPORT INSTANCE BOUND TO IT (THE DESIGN §6
//! step 2: the connector owns every listener, each bound to one transport), the identity the
//! loader verifies every ref that transport presents for (`auth_handle::verify_auth_ref`): never
//! the root's own (`0`, which no transport presents). A transport is entered with [`serve_under`]
//! when the data listener binds over it; its listener lends each accepted framing the lines
//! [`lending`] reads (each handle minted for that identity at the published generation), through
//! the book [`book`] gives `Listening::lending`. The legacy data door and its own verify are
//! untouched: one serving path at a time.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use busbar_contract::abi::auth::{FIELD_QUERY, FIELD_SENSITIVE};
use busbar_contract::auth_calls::StripPlace;
use busbar_kernel::inbound::{self as kin, Inbound};

use crate::root::loader::dispatch::auth_handle::{
    self, AuthCallAnswer, AuthCallAsk, AuthDone, AuthHandleHost, AuthRan, HandInAsk, HeadCopy,
    RefusalBytes, RefuseAsk, UnitSecret,
};

/// THE PROCESS'S INBOUND SIDE, built once.
pub fn host() -> &'static Arc<Inbound> {
    static ONE: OnceLock<Arc<Inbound>> = OnceLock::new();
    ONE.get_or_init(|| {
        Inbound::new(
            kin::Seals {
                mint: Arc::new(|| crate::root::plane_node::node().mint().get()),
                mac: Arc::new(|t: &kin::UnitTag| {
                    auth_handle::mint_unit_ref(t.secret, t.generation, t.owner, t.line, t.unit)
                        .map(|u| u.mac)
                }),
            },
            Arc::new(|f| match tokio::runtime::Handle::try_current() {
                Ok(rt) => drop(rt.spawn(f)),
                // Off any runtime: a thread of its own drives the call to its end.
                Err(_) => drop(std::thread::spawn(move || {
                    tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .map(|rt| rt.block_on(f))
                })),
            }),
            Arc::new(refused),
        )
    })
}

/// A refusal the kernel answered (THE DESIGN §6 step 4, l.950-951: a 401 is a refused unit,
/// audited, billing nothing, drawing no lease). As a door unit the kernel refuses at admission
/// (`door_steps`, `Admission::Refused` -> `Unauthenticated`, `audit_refused`), nothing is charged
/// and no hold opens; the refusal is recorded here and the unit left the kernel's table.
fn refused(r: &kin::RefusedUnit) {
    tracing::debug!(
        unit = ?r.unit,
        owner = r.owner,
        line = r.line,
        cause = r.cause,
        status = r.status,
        "inbound refusal"
    );
}

/// The kernel side, as the loader's auth-handle slots call it.
struct LoaderSide(Arc<Inbound>);

/// A head the loader copied, as the kernel reads it.
fn head_of(h: HeadCopy) -> kin::Head {
    kin::Head {
        method: h.method,
        target: h.target,
        authority: h.authority,
        query: h.query,
        fields: h.fields,
    }
}

/// The kernel's answer as the transport receives it: the flow, the unit and each NAME with its
/// flag, `FIELD_SENSITIVE` for a field line and `FIELD_QUERY` for a query key (l.942-945).
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
            head: head_of(ask.request),
            body: ask.body,
            deadline: ask.deadline.map(|d| std::time::Instant::now() + d),
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
        self.0.hand_in(kin::HandIn {
            owner: ask.owner,
            generation: ask.generation,
            auth: ask.auth,
            unit: ask.unit,
            line: ask.line,
            conn: ask.conn,
            stream: ask.stream,
            framing: ask.framing,
            head: head_of(ask.request),
        })
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
                request: Some(head_of(ask.request)),
            })
            .map(|r| RefusalBytes {
                status: r.status,
                fields: r.fields,
                body: r.body,
            })
    }
}

/// Serve the kernel's inbound side on `dispatcher`'s auth-handle slots; the first install stands.
pub fn install(dispatcher: &crate::root::loader::dispatch::Dispatcher) -> bool {
    dispatcher.install_auth_handle(Arc::new(LoaderSide(Arc::clone(host()))))
}

/// The data listener's sealed guest list and its door routes' unit-less refusals, staged where
/// they are built, for [`publish`].
type Staged = (
    busbar_kernel::guest::GuestList,
    Vec<busbar_kernel::plane_routes::PlaneRefusalSpec>,
);

fn staged() -> std::sync::MutexGuard<'static, Option<Staged>> {
    static STAGED: Mutex<Option<Staged>> = Mutex::new(None);
    STAGED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Stage the data listener's sealed guest list and its door refusals ([`publish`] installs them),
/// and the door planes' rendering of a kernel-shaped refusal (`refuse_by_path`, the one the
/// router's layers answer through), every listener table rendering through it from then on.
pub fn stage(
    guests: busbar_kernel::guest::GuestList,
    refusals: Vec<busbar_kernel::plane_routes::PlaneRefusalSpec>,
    refuse_by_path: Option<busbar_kernel::plane_routes::PlaneRefuseByPathFn>,
) {
    *door_refuser() = refuse_by_path;
    *staged() = Some((guests, refusals));
}

/// THE DOOR PLANES' RENDERING the data listener's refusals answer through (staged with the list).
fn door_refuser(
) -> std::sync::MutexGuard<'static, Option<busbar_kernel::plane_routes::PlaneRefuseByPathFn>> {
    static REFUSER: Mutex<Option<busbar_kernel::plane_routes::PlaneRefuseByPathFn>> =
        Mutex::new(None);
    REFUSER.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The last generation published.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// THE TRANSPORTS THE DATA LISTENER IS SERVED THROUGH: each one's instance identity, a table
/// installed under it at every generation ([`serve_under`]).
fn owners() -> std::sync::MutexGuard<'static, Vec<u64>> {
    static OWNERS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
    OWNERS.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The app the last generation was published over, for a transport entered after it.
fn published_app() -> std::sync::MutexGuard<'static, Option<Arc<busbar_kernel::state::App>>> {
    static APP: Mutex<Option<Arc<busbar_kernel::state::App>>> = Mutex::new(None);
    APP.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One publish or one entry at a time: a generation's tables are installed whole.
fn installing() -> std::sync::MutexGuard<'static, ()> {
    static ONE: Mutex<()> = Mutex::new(());
    ONE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The refusal of the root's own identity as a listener's transport.
pub const ROOT_IS_NO_TRANSPORT: &str =
    "the root's own identity serves no listener: a listener's table is its transport's";

/// THE DATA LISTENER'S ADMISSION GATE (1.5.5's outermost inbound cap,
/// `limits.max_inbound_concurrent`, `0` = none): one for the process, built at the first install
/// from the limits installed then, as the router's layer is built once at boot, and shared by every
/// generation and every transport the listener is served through, so a slot a request took is
/// given back to the gate it was taken from.
fn admission() -> Option<Arc<kin::AdmissionGate>> {
    static GATE: OnceLock<Option<Arc<kin::AdmissionGate>>> = OnceLock::new();
    GATE.get_or_init(|| {
        kin::admission_gate(busbar_kernel::config::limits::installed().map_or(
            busbar_kernel::config::limits::DEFAULT_MAX_INBOUND_CONCURRENT,
            |l| l.max_inbound_concurrent,
        ))
    })
    .clone()
}

/// INSTALL THE DATA LISTENER'S TABLE under each of `owners` (the instance identities of the
/// transports it is served through) at `generation`: the sealed `guests` with the opened auths
/// their lines name off `app`, the size gate's limit, the door routes' unit-less refusals and each
/// line's handle id from the line half of the shared ref-id space. Nothing is installed under the
/// root's own identity.
///
/// # Errors
///
/// [`ROOT_IS_NO_TRANSPORT`] for an owner `0`; the kernel refused a table.
pub fn install_listeners(
    inbound: &Inbound,
    owners: &[u64],
    generation: u64,
    guests: &busbar_kernel::guest::GuestList,
    door_refusals: &[busbar_kernel::plane_routes::PlaneRefusalSpec],
    app: &Arc<busbar_kernel::state::App>,
) -> Result<(), &'static str> {
    let gate = admission();
    install_gated(
        inbound,
        owners,
        generation,
        guests,
        door_refusals,
        app,
        gate,
    )
}

/// [`install_listeners`] with the admission gate `gate` (the process's one, in production).
fn install_gated(
    inbound: &Inbound,
    owners: &[u64],
    generation: u64,
    guests: &busbar_kernel::guest::GuestList,
    door_refusals: &[busbar_kernel::plane_routes::PlaneRefusalSpec],
    app: &Arc<busbar_kernel::state::App>,
    gate: Option<Arc<kin::AdmissionGate>>,
) -> Result<(), &'static str> {
    if owners.contains(&0) {
        return Err(ROOT_IS_NO_TRANSPORT);
    }
    let body_limit = busbar_kernel::config::limits::installed().map_or(
        busbar_kernel::config::limits::DEFAULT_REQUEST_BODY_MAX_BYTES,
        |l| l.request_body_max_bytes,
    ) as u64;
    for &owner in owners {
        let auths = guests
            .lines()
            .iter()
            .filter_map(|l| match &l.auth {
                busbar_kernel::guest::LineAuth::Chain(names, _) => Some(names),
                busbar_kernel::guest::LineAuth::None | busbar_kernel::guest::LineAuth::Claimant => {
                    None
                }
            })
            .flatten()
            .filter_map(|n| Some((n.clone(), app.auth.position_calls(n)?)))
            .collect();
        // Each line's handle id from the line half of the shared ref-id space: never a binding's.
        let ids = guests
            .lines()
            .iter()
            .map(|_| auth_handle::next_ref_id(auth_handle::RefSpace::Line))
            .collect();
        let listener = kin::Listener {
            guests: guests.clone(),
            auths,
            body_limit,
            app: Arc::clone(app),
            door_refusals: door_refusals.to_vec(),
            ids,
            signed_ingress: kin::signed_by_dialect(),
            admission: gate.clone(),
            door_refuser: door_refuser().clone(),
        };
        inbound.install(owner, generation, listener)?;
    }
    Ok(())
}

/// PUBLISH A GENERATION (THE DESIGN §6 step 8, l.979-985): the staged data listener's list
/// installed under every transport it is served through ([`install_listeners`]) at a new
/// generation over `app` (its opened auths, its mount table, its governance), and the generation
/// published to the loader, so every ref is verified against it. At boot and at each
/// configuration apply. Answers the generation; `None` when no list was staged (a build that
/// serves no door plane) or a table was refused.
pub fn publish(app: &Arc<busbar_kernel::state::App>) -> Option<u64> {
    let (guests, door_refusals) = staged().clone()?;
    let _one = installing();
    let generation = GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    *published_app() = Some(Arc::clone(app));
    let owners = owners().clone();
    if let Err(e) = install_listeners(host(), &owners, generation, &guests, &door_refusals, app) {
        tracing::error!(
            generation,
            error = e,
            "the data listener's inbound table was refused"
        );
        return None;
    }
    auth_handle::publish_generation(generation);
    Some(generation)
}

/// ENTER `owner`, the instance identity of a transport the data listener is bound to (THE DESIGN
/// §6 step 2), as one its table is installed under: at the generation already published, at once,
/// and at every generation [`publish`] publishes from here on. Entering one twice is entering it
/// once.
///
/// # Errors
///
/// [`ROOT_IS_NO_TRANSPORT`] for `0`; the kernel refused the table.
pub fn serve_under(owner: u64) -> Result<(), &'static str> {
    if owner == 0 {
        return Err(ROOT_IS_NO_TRANSPORT);
    }
    let _one = installing();
    {
        let mut owners = owners();
        if !owners.contains(&owner) {
            owners.push(owner);
        }
    }
    let generation = auth_handle::generation();
    let (Some(app), Some((guests, door_refusals))) = (published_app().clone(), staged().clone())
    else {
        // Nothing is published yet: the first publish installs it.
        return Ok(());
    };
    install_listeners(host(), &[owner], generation, &guests, &door_refusals, &app)
}

/// THE STAGED LIST REINSTALLED under `owner` at the published generation behind an admission gate
/// of `slots` (`0` = none): a cell's own small gate, in place of the process's one.
#[cfg(test)]
pub(crate) fn reinstall_gated(owner: u64, slots: usize) -> Result<(), &'static str> {
    let _one = installing();
    let generation = auth_handle::generation();
    let (Some(app), Some((guests, door_refusals))) = (published_app().clone(), staged().clone())
    else {
        return Err(kin::NO_LIST);
    };
    let gate = kin::admission_gate(slots);
    install_gated(
        host(),
        &[owner],
        generation,
        &guests,
        &door_refusals,
        &app,
        gate,
    )
}

/// THE GUEST LIST `owner`'s LISTENER LENDS at `generation`, off `inbound`'s table for that owner:
/// each line as the kernel lends it ([`Inbound::lent`]), its handle MINTED FOR `owner` at
/// `generation` (`auth_handle::mint_auth_ref`), so the ref the transport presents on `auth.call`
/// verifies for the transport that presents it and for no other. `None` = no table is installed
/// under `owner` at `generation`, or no handle could be minted.
#[must_use]
pub fn lending_from(
    inbound: &Inbound,
    owner: u64,
    generation: u64,
) -> Option<busbar_core_connector::framer::GuestLines> {
    let lines = inbound
        .lent(owner, generation)?
        .into_iter()
        .map(|(spec, route)| {
            Some(busbar_core_connector::framer::GuestLine {
                line: spec.line,
                points: spec.points,
                auth: auth_handle::mint_auth_ref(owner, generation, spec.auth)?,
                body_limit: spec.body_limit,
                methods: route.methods,
                path_form: route.path_form,
                path: route.path,
                fields: route.fields,
                rung: route.rung,
            })
        })
        .collect::<Option<Vec<_>>>()?;
    Some(busbar_core_connector::framer::GuestLines::new(lines))
}

/// The lines last lent to each owner, with the generation they were minted at.
type Lent = std::collections::HashMap<u64, (u64, Arc<busbar_core_connector::framer::GuestLines>)>;

fn lent_cache() -> std::sync::MutexGuard<'static, Option<Lent>> {
    static LENT: Mutex<Option<Lent>> = Mutex::new(None);
    LENT.lock().unwrap_or_else(PoisonError::into_inner)
}

/// THE GUEST LIST `owner`'s LISTENER LENDS NOW: [`lending_from`] the process's inbound side at the
/// generation published to the loader, built once per generation and shared by every accept.
#[must_use]
pub fn lending(owner: u64) -> Option<Arc<busbar_core_connector::framer::GuestLines>> {
    let generation = auth_handle::generation();
    let mut cache = lent_cache();
    let cache = cache.get_or_insert_with(Lent::new);
    if let Some((at, lines)) = cache.get(&owner) {
        if *at == generation {
            return Some(Arc::clone(lines));
        }
    }
    let lines = Arc::new(lending_from(host(), owner, generation)?);
    cache.insert(owner, (generation, Arc::clone(&lines)));
    Some(lines)
}

/// THE BOOK the data listener bound over transport `owner` lends from
/// (`busbar_core_connector::listen::Listening::lending`): [`lending`] at each accept.
#[must_use]
pub fn book(owner: u64) -> busbar_core_connector::framer::GuestBook {
    Arc::new(move || lending(owner))
}
