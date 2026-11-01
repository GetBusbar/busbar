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
//! listener's table is keyed by the identity of the instance that serves it: today the data
//! listener is served by the root's own data door (identity `0`, which no plugin presents), so its
//! table is installed under `0`; each accepting transport registration receives the selected
//! physical listener's policy over that same App. The registration and admitted request retain
//! their selected generation while later configuration candidates are checked before publication.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError, Weak};

use busbar_contract::abi::auth::{FIELD_QUERY, FIELD_SENSITIVE};
use busbar_contract::auth_calls::StripPlace;
use busbar_kernel::inbound::{self as kin, Inbound};

use crate::root::loader::dispatch::auth_handle::{
    self, AuthCallAnswer, AuthCallAsk, AuthDone, AuthHandleHost, AuthRan, HandInAsk, HeadCopy,
    RefusalBytes, RefuseAsk, StreamPolicy, UnitSecret,
};

/// The identity the root's own data door serves the data listener under: the composition root's
/// identity on the instance table, never a plugin's.
pub const ROOT_OWNER: u64 = 0;

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
            stream: ask.stream,
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
            deadline.map(|remaining| std::time::Instant::now() + remaining),
        )
    }

    fn requires_scope(&self) -> bool {
        true
    }

    fn framing_started(
        &self,
        owner: u64,
        listener: u64,
        framing: u64,
    ) -> Result<Option<StreamPolicy>, &'static str> {
        let registration = registered(owner, listener).ok_or(kin::NO_LIST)?;
        let policy = registration.policy().ok_or(kin::NO_LIST)?;
        self.0
            .framing_started(owner, listener, framing, policy.policy.generation)?;
        Ok(Some(policy))
    }

    fn stream_open(
        &self,
        owner: u64,
        listener: u64,
        framing: u64,
        stream: u64,
    ) -> Result<StreamPolicy, &'static str> {
        let registration = registered(owner, listener).ok_or(kin::NO_LIST)?;
        loop {
            let policy = registration.policy().ok_or(kin::NO_LIST)?;
            match self
                .0
                .grant_stream(owner, framing, stream, policy.policy.generation)
            {
                Ok(()) => return Ok(policy),
                Err(kin::NO_LIST)
                    if published()
                        .load_full()
                        .is_some_and(|now| now.generation != policy.policy.generation) =>
                {
                    continue
                }
                Err(error) => return Err(error),
            }
        }
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

/// Stage the data listener's sealed guest list and its door refusals ([`publish`] installs them).
pub fn stage(
    guests: busbar_kernel::guest::GuestList,
    refusals: Vec<busbar_kernel::plane_routes::PlaneRefusalSpec>,
) {
    *staged() = Some((guests, refusals));
}

struct Published {
    generation: u64,
    listener: kin::Listener,
}

fn published() -> &'static arc_swap::ArcSwapOption<Published> {
    static ONE: OnceLock<arc_swap::ArcSwapOption<Published>> = OnceLock::new();
    ONE.get_or_init(arc_swap::ArcSwapOption::empty)
}

/// Select one listener's routes from an immutable published generation. The selection must be
/// deterministic for that generation and keep its application snapshot. It runs outside locks.
pub type ListenerPolicy =
    Arc<dyn Fn(&kin::Listener) -> Result<kin::Listener, String> + Send + Sync>;

/// A listener registration shared by its accept loop and live connections.
/// The cache owns only route rows; policy Apps stay with the published snapshot and units.
pub(in crate::root) struct ListenerRegistration {
    owner: u64,
    id: u64,
    select: Option<ListenerPolicy>,
    rows: Mutex<Option<StreamPolicy>>,
    installed: AtomicU64,
}

impl ListenerRegistration {
    pub(in crate::root) fn new(owner: u64, id: u64) -> Arc<Self> {
        Self::with_policy(owner, id, None)
    }

    pub(in crate::root) fn with_policy(
        owner: u64,
        id: u64,
        select: Option<ListenerPolicy>,
    ) -> Arc<Self> {
        let registration = Arc::new(Self {
            owner,
            id,
            select,
            rows: Mutex::new(None),
            installed: AtomicU64::new(0),
        });
        registrations()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert((owner, id), Arc::downgrade(&registration));
        registration
    }

    fn selected(&self, snapshot: &Published) -> Result<kin::Listener, String> {
        match &self.select {
            Some(select) => {
                let listener = select(&snapshot.listener)?;
                if !Arc::ptr_eq(&listener.app, &snapshot.listener.app) {
                    return Err("listener policy changed its published application".into());
                }
                Ok(listener)
            }
            None => Ok(snapshot.listener.clone()),
        }
    }

    pub(in crate::root) fn validate(&self) -> Result<(), String> {
        let snapshot = published()
            .load_full()
            .ok_or_else(|| "listener policy has not been published".to_owned())?;
        self.selected(&snapshot).map(|_| ())
    }

    pub(in crate::root) fn guests(&self) -> Option<Arc<busbar_core_connector::framer::GuestLines>> {
        self.policy().map(|policy| {
            Arc::new(busbar_core_connector::framer::GuestLines::published(
                policy.policy,
            ))
        })
    }

    fn policy(&self) -> Option<StreamPolicy> {
        use busbar_contract::abi::mechanism::extensions;
        use busbar_contract::abi::transport::guest_policy::{self, GuestLine, Identity, Policy};
        loop {
            let snapshot = published().load_full()?;
            let cached = self
                .rows
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .as_ref()
                .filter(|policy| policy.policy.generation == snapshot.generation)
                .cloned();
            let selected = if cached.is_none()
                || self.installed.load(Ordering::Acquire) < snapshot.generation
            {
                Some(self.selected(&snapshot).ok()?)
            } else {
                None
            };
            let candidate = match cached {
                Some(policy) => policy,
                None => {
                    let mut listener = selected.as_ref()?.clone();
                    listener.ids = listener
                        .guests
                        .lines()
                        .iter()
                        .map(|_| auth_handle::next_ref_id(auth_handle::RefSpace::Line))
                        .collect();
                    let lines = listener
                        .specs()
                        .into_iter()
                        .zip(listener.guests.lines())
                        .map(|(spec, line)| {
                            Some(GuestLine {
                                line: spec.line,
                                points: spec.points,
                                auth: auth_handle::mint_auth_ref(
                                    self.owner,
                                    snapshot.generation,
                                    spec.auth,
                                )?,
                                body_limit: spec.body_limit,
                                methods: line.route.methods,
                                path_form: line.route.path_form,
                                path: line.route.path.clone(),
                                fields: line.route.fields.clone(),
                                rung: line.route.rung,
                            })
                        })
                        .collect::<Option<Vec<_>>>()?;
                    let policy = Arc::new(Policy {
                        listener: self.id,
                        generation: snapshot.generation,
                        lines,
                    });
                    let bytes =
                        guest_policy::encode(self.id, snapshot.generation, &policy.lines).ok()?;
                    let identity = Identity {
                        listener: self.id,
                        generation: snapshot.generation,
                    }
                    .encode()
                    .ok()?;
                    StreamPolicy {
                        policy,
                        full: extensions::encode(&[(guest_policy::EXT_GUEST_POLICY, &bytes)])
                            .into(),
                        current: extensions::encode(&[(
                            guest_policy::EXT_GUEST_CURRENT,
                            &identity,
                        )])
                        .into(),
                    }
                }
            };
            let current_generation = published().load_full().map(|now| now.generation);
            if current_generation != Some(snapshot.generation) {
                continue;
            }
            let policy = {
                let mut cache = self.rows.lock().unwrap_or_else(PoisonError::into_inner);
                if cache
                    .as_ref()
                    .is_some_and(|policy| policy.policy.generation > snapshot.generation)
                {
                    continue;
                }
                if let Some(existing) = cache
                    .as_ref()
                    .filter(|policy| policy.policy.generation == snapshot.generation)
                {
                    existing.clone()
                } else {
                    *cache = Some(candidate.clone());
                    candidate
                }
            };
            if self.installed.load(Ordering::Acquire) < snapshot.generation {
                let mut listener = selected?;
                listener.ids = policy
                    .policy
                    .lines
                    .iter()
                    .map(|line| line.auth.id)
                    .collect();
                host()
                    .install_at(self.owner, self.id, snapshot.generation, listener)
                    .ok()?;
                self.installed
                    .fetch_max(snapshot.generation, Ordering::Release);
            }
            if let Some(current) = published().load_full() {
                if current.generation != snapshot.generation {
                    host().retire_before(current.generation);
                    continue;
                }
            }
            return Some(policy);
        }
    }
}

type ListenerRegistrations = Mutex<HashMap<(u64, u64), Weak<ListenerRegistration>>>;

fn registrations() -> &'static ListenerRegistrations {
    static ONE: OnceLock<ListenerRegistrations> = OnceLock::new();
    ONE.get_or_init(Mutex::default)
}

fn registered(owner: u64, listener: u64) -> Option<Arc<ListenerRegistration>> {
    registrations()
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(&(owner, listener))
        .and_then(Weak::upgrade)
}

impl Drop for ListenerRegistration {
    fn drop(&mut self) {
        registrations()
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&(self.owner, self.id));
        host().forget_listener(self.owner, self.id);
    }
}

/// The last generation published.
static GENERATION: AtomicU64 = AtomicU64::new(0);

/// PUBLISH A GENERATION (THE DESIGN §6 step 8, l.979-985): the staged data listener's list
/// installed under [`ROOT_OWNER`] at a new generation over `app` (its opened auths, its mount
/// table, its governance), the size gate's limit, and the generation published to the loader, so
/// every ref is verified against it. At boot and at each configuration apply. Answers the
/// generation; `None` when no list was staged (a build that serves no door plane).
pub fn publish(app: &Arc<busbar_kernel::state::App>) -> Option<u64> {
    let (guests, door_refusals) = staged().clone()?;
    let generation = GENERATION.fetch_add(1, Ordering::AcqRel) + 1;
    let auths = guests
        .lines()
        .iter()
        .filter_map(|l| match &l.auth {
            busbar_kernel::guest::LineAuth::Chain(names, _) => Some(names),
            busbar_kernel::guest::LineAuth::None => None,
        })
        .flatten()
        .filter_map(|n| Some((n.clone(), app.auth.position_calls(n)?)))
        .collect();
    let body_limit = busbar_kernel::config::limits::installed().map_or(
        busbar_kernel::config::limits::DEFAULT_REQUEST_BODY_MAX_BYTES,
        |l| l.request_body_max_bytes,
    ) as u64;
    // Each line's handle id from the line half of the shared ref-id space: never a binding's.
    let ids = guests
        .lines()
        .iter()
        .map(|_| auth_handle::next_ref_id(auth_handle::RefSpace::Line))
        .collect();
    let listener = kin::Listener {
        guests,
        auths,
        body_limit,
        app: Arc::clone(app),
        door_refusals,
        ids,
        signed_ingress: kin::signed_by_dialect(),
        scope: None,
    };
    let snapshot = Arc::new(Published {
        generation,
        listener: listener.clone(),
    });
    if let Err(e) = host().install(ROOT_OWNER, generation, listener) {
        tracing::error!(
            generation,
            error = e,
            "the data listener's inbound table was refused"
        );
        return None;
    }
    let retired = published().swap(Some(snapshot));
    auth_handle::publish_generation(generation);
    host().retire_before(generation);
    drop(retired);
    Some(generation)
}
