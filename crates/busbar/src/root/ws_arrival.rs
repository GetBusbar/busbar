// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! WHERE A DUPLEX PLANE'S DECLARED SURFACE BECOMES SERVED URLS, and why the file that does it names
//! no plane.
//!
//! A plane declares its served sessions as DATA — a [`WireSurface`] of bindings, each with the mount
//! patterns it is addressed at. Everything this module does is read that list and, for each row,
//! register an inbound WS-accept arrival whose accept fn hands the upgraded socket to the ONE
//! composed serving path. The plane's name appears at the composition that supplies the surface, the
//! units and the registry key, and nowhere in this file.
//!
//! ## WHERE ADMISSION HAPPENS, which is the whole of the ordering argument
//!
//! **The Teller loop is served ONCE**, by the unit loop, at the first frame: verify, approve, admit,
//! route, meter, audit. There is no second admission beside it and this module composes none — a
//! gate of its own in front of the upgrade would be an admission built BESIDE the loop, deciding
//! with a different token, against a destination this file cannot see (the leg is sealed INSIDE the
//! loop, by unit zero, with a trust token no composition holds).
//!
//! What runs before the upgrade is the DOOR and only the door: the credential bar the arrival
//! declares ([`WsArrivalSpec::auth`]), recorded verbatim and enforced by the core auth middleware
//! before this fn is ever called. That is AUTHENTICATE, not admission, and it is why an anonymous
//! caller is told the same thing on these URLs it is told on every other plane's.
//!
//! **So the socket is bound before the loop has run, and that is safe for exactly one reason**: what
//! goes out on it before the loop runs is a wire ACKNOWLEDGEMENT and nothing else. The opening frame
//! carries the session's own resolved posture — the configuration the client itself supplied,
//! screened by the operator's gate, echoed back. Nothing dials, nothing charges, no upstream is
//! named, and no byte of anyone else's data is on it. The cell beside this file drives that: an
//! unadmitted session receives its `session.created`, then the plane's refusal terminal, and never
//! dials and never charges.
//!
//! ## The sequence, and why it is in this order
//!
//! 1. **the session opens on the driver** — where the declared bar is checked a second time against
//!    what the upgrade actually published, and where a refusal is still answerable as a status on
//!    the leg underneath rather than as a close code on a socket nobody asked for;
//! 2. **the two operator hops**, gate then tap, across the await, through the driver's own sync
//!    accessors. They are NOT optional: a rejecting gate refuses the open BEFORE the protocol
//!    changes, and a committed rewrite is what the session then runs — and is announced — as;
//! 3. **the upgrade**, through the neutral coded acceptor, which is the only thing this file asks a
//!    socket of;
//! 4. **the opening frames**, written before the pump takes the sink, because the one frame a
//!    session owes before any frame arrives cannot come from a pump that writes when frames arrive;
//! 5. **the pump**, with the leg dialler wrapped around its source so the session's upstream leg is
//!    opened in the gap between two frames and nowhere else.
//!
//! ## What this module is NOT allowed to do, and does not
//!
//! It writes no protocol event: the bytes at step 4 are the PLANE's, rendered from the posture the
//! session resolved to, and this file cannot read them. It decides no destination. It names no
//! dialect: the three rows are three rows of a list.

use std::sync::Arc;

use busbar_contract::transport::session::{SessionBudgets, SessionDriver};
use busbar_contract::transport::surface::WireSurface;
use busbar_contract::wire::CloseReason;
use busbar_contract::TransportError;
use busbar_substrate::ingress::duplex_ws::{
    accept_coded, WsAcceptFuture, WsArrival, WsArrivalSpec,
};
use busbar_substrate::plane_host::EngineHost;
use busbar_transport_ws::mount::{FrameSink, FrameSource};

use crate::root::leg_dial::LegDialing;
use crate::root::registry::WsLegEgress;
use crate::root::session_driver::{DeclaredSessionParams, SessionLoopDriver, SessionUnits};

/// THE COMPOSED SERVING PATH, held for the life of the process.
///
/// Everything a served session runs on, in one borrow: the driver its units are judged by, the
/// egress port its leg is dialled through (which holds the one guard), the surface its bindings are
/// read off, and the two facts the arrival needs about the plane it is mounting. Leaked ONCE by the
/// composition that builds it — the same fixed registration-time term the interned upstream names
/// are — because an accept fn registered into a process-wide registry outlives every frame of every
/// session, and a per-session composition would be a second node.
pub struct MountedStreams<U: SessionUnits + ?Sized + Sync + 'static> {
    /// The one driver. Every session on every declared row opens on it, which is what makes the
    /// node's own tables one node's.
    pub driver: &'static SessionLoopDriver<'static, U>,
    /// The port a sealed leg is dialled through, with the network judge and the breaker cell in
    /// front of it.
    pub egress: &'static WsLegEgress<U>,
    /// The plane's declared surface, as data.
    pub surface: &'static WireSurface,
    /// The plane's registry key — what the core mount resolves the live per-generation slot under,
    /// and what the operator's hooks are filed against. Supplied by the composition; this file does
    /// not know what it spells.
    pub plane_key: &'static str,
    /// The media the declaration names for this plane's frames.
    pub media: &'static str,
    /// The ceilings one session runs under.
    pub budgets: SessionBudgets,
}

impl<U: SessionUnits + ?Sized + Sync + 'static> MountedStreams<U> {
    /// THE ARRIVALS THIS SURFACE DECLARES — one per binding, in declaration order.
    ///
    /// The path is the binding's own first mount pattern and never a string this module spells: the
    /// surface is the published fact, and a second spelling here would be a second opinion about
    /// which URLs this node serves. A binding that declares no mount is skipped rather than
    /// registered at a path nobody declared.
    #[must_use]
    pub fn arrivals(&'static self) -> Vec<WsArrivalSpec> {
        self.surface
            .bindings
            .iter()
            .filter_map(|binding| {
                let path = (*binding.mounts.first()?).to_string();
                Some(WsArrivalSpec {
                    path,
                    // THE DOOR, and the only thing that runs before the upgrade. Recorded on the
                    // spec rather than applied here, so the core auth middleware enforces it before
                    // this fn is called — which is what makes an anonymous caller's answer on these
                    // URLs the ordering 1.5.5 pins for every plane.
                    // Named through the LOADER's re-export, which is how this binary already
                    // reaches every other plugin-ABI wire type: the root takes no second, direct
                    // edge to the ABI crate to spell one enum variant.
                    auth: busbar_plugin_loader::RouteAuth::Key,
                    slot_key: self.plane_key,
                    accept: Arc::new(move |arrival: WsArrival| -> WsAcceptFuture {
                        Box::pin(self.accept(arrival))
                    }),
                })
            })
            .collect()
    }

    /// SERVE ONE UPGRADE on this composition, under the binding it was addressed to.
    async fn accept(&'static self, arrival: WsArrival) -> axum::response::Response {
        // WHICH BINDING THIS UPGRADE NAMED, and what it captured, asked of the SURFACE. The concrete
        // target is matched against the declared mount patterns rather than trusted from the route
        // that was registered, so the binding a session opens on and the captures it publishes are
        // the declarer's own answer about its own surface. A target no declared mount matches is a
        // path that does not exist, and is told so.
        let key = crate::root::registry::WS_TRANSPORT_KEY;
        let Some((binding, bar, captures)) = busbar_contract::transport::surface::duplex_binding_at(
            self.surface,
            key,
            arrival.uri.path(),
        ) else {
            return refused(axum::http::StatusCode::NOT_FOUND);
        };
        let owned = upgrade_facts(&arrival, &captures);
        let published: Vec<(&str, &str)> = owned
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();

        // (1) THE SESSION OPENS ON THE DRIVER, BEFORE THE PROTOCOL CHANGES. A refusal here is one of
        // the eight words and is answerable as a status on the leg underneath; once the pump is
        // running there is no such answer left.
        let session = match self.driver.open(
            busbar_contract::transport::session::SessionOpen {
                facts: &published,
                transport: key,
                chain: TRANSPORT_CHAIN,
                binding: binding.name,
                bar,
            },
            self.surface,
        ) {
            Ok(session) => session,
            // The driver would not open it. WHAT that means is the units' own answer and this file
            // does not translate it into a second vocabulary: the caller is told the door said no.
            Err(_) => return refused(axum::http::StatusCode::FORBIDDEN),
        };

        // (2) THE TWO OPERATOR HOPS, ACROSS THE AWAIT. Rendered SYNC, awaited, adopted SYNC — the
        // only shape available, because the hops are async and `drive` is synchronous by design.
        // They are not optional: §1g's own reading is that a mount which dropped them would be
        // worse than not mounting.
        let host = Arc::clone(&arrival.host);
        let key = arrival
            .gov
            .as_ref()
            .and_then(busbar_api::PlaneRequestCtx::key)
            .map(|k| (k.id.clone(), k.name.clone()));
        if let Some(declared) = self.driver.session_params(session) {
            match self.hooks(&host, key, session, &declared).await {
                Hooks::Proceed => {}
                // A rejecting gate refuses the OPEN, before the protocol changes and before any
                // socket binds. The session the driver opened is released rather than left on the
                // table with nothing ever reading it.
                Hooks::Refused(status) => {
                    self.close(session, CloseReason::Revoked);
                    return refused(status);
                }
            }
        }

        // (3) THE UPGRADE. The neutral coded acceptor is the only socket this file asks for, and it
        // is asked for AFTER the door, the open and the operator gate have all had their answer.
        let driver = self.driver;
        let egress = self.egress;
        let media = self.media;
        let budgets = self.budgets;
        accept_coded(arrival.upgrade, move |stream, sink, _closing| async move {
            let mut sink = ChannelSink(sink);
            // (4) THE FRAMES THE SESSION OWES BEFORE ANY ARRIVES, written before the pump takes the
            // sink. A write that fails means the client is already gone: there is then no session
            // to serve, and the driver is told so rather than left holding one.
            for frame in driver.opening_frames(session) {
                if sink.write_frame(&frame, media).await.is_err() {
                    driver.close(
                        session,
                        busbar_contract::transport::session::SessionEnd {
                            cut: busbar_contract::transport::session::Cut::Client,
                            reason: CloseReason::PeerClosed,
                        },
                    );
                    return;
                }
            }
            // (5) THE PUMP, with the dialler wrapped around its source so the session's upstream leg
            // is opened in the gap between two frames and nowhere else. `pump` calls
            // `SessionDriver::close` exactly once, on every ending including the ugly ones.
            let source = LegDialing::new(ChannelSource(stream), driver, session, egress);
            let _end =
                busbar_transport_ws::mount::pump(driver, session, source, sink, budgets).await;
        })
    }

    /// Release a session this composition opened and then refused, so nothing is left on the
    /// driver's table with no socket under it.
    fn close(&self, session: busbar_contract::transport::session::SessionHandle, why: CloseReason) {
        self.driver.close(
            session,
            busbar_contract::transport::session::SessionEnd {
                cut: busbar_contract::transport::session::Cut::Upstream,
                reason: why,
            },
        );
    }

    /// THE TWO OPERATOR HOPS over one session's declared parameters, in order.
    ///
    /// The container and the method are the PLANE's own, read off the projection the plane rendered
    /// — this file does not know what a deployment files these hooks under, and a second spelling
    /// here would be a gate an operator's configuration silently stopped matching.
    ///
    /// Both run on a blocking thread, because the host runs them on a runtime of its own and a
    /// worker thread parked on one is a worker the node has lost. The PRESENCE CHECK comes first on
    /// each, so a deployment with nothing attached pays for no serialization and — the half that
    /// matters — answers byte-identically to what it answered before either hop existed.
    ///
    /// A join panic is answered differently on the two, and deliberately: the GATE fails CLOSED (a
    /// gate that did not run has not admitted anything), and the TAP fails SAFE and proceeds
    /// unchanged (the gate already admitted, and a rewrite that did not run is no rewrite).
    async fn hooks(
        &self,
        host: &Arc<dyn EngineHost>,
        key: Option<(String, String)>,
        session: busbar_contract::transport::session::SessionHandle,
        declared: &DeclaredSessionParams,
    ) -> Hooks {
        let plane = self.plane_key;
        let container = declared.container;
        let operation = declared.operation;
        let sid = format!("{}", session.0);

        if host.gate_attached(plane, container) {
            let args = declared.declared.clone();
            let (h, k, s) = (Arc::clone(host), key.clone(), sid.clone());
            let outcome = tokio::task::spawn_blocking(move || {
                h.gate_decide(
                    plane,
                    container,
                    0,
                    operation,
                    &args,
                    k.as_ref().map(|(id, name)| (id.as_str(), name.as_str())),
                    Some(s.as_str()),
                )
            })
            .await
            .unwrap_or(busbar_substrate::plane_host::GateOutcome::Reject {
                status: 403,
                message: String::new(),
                hook: String::new(),
            });
            if let busbar_substrate::plane_host::GateOutcome::Reject { status, .. } = outcome {
                return Hooks::Refused(
                    axum::http::StatusCode::from_u16(status)
                        .unwrap_or(axum::http::StatusCode::FORBIDDEN),
                );
            }
        }

        if host.tap_attached(plane, container) {
            let args = declared.declared.clone();
            let (h, k, s) = (Arc::clone(host), key, sid);
            let verdict = tokio::task::spawn_blocking(move || {
                h.transform_over(
                    plane,
                    container,
                    0,
                    operation,
                    &args,
                    k.as_ref().map(|(id, name)| (id.as_str(), name.as_str())),
                    Some(s.as_str()),
                )
            })
            .await
            .unwrap_or(busbar_substrate::plane_host::TransformVerdict::Proceed {
                applied: false,
                args_json: Vec::new(),
            });
            match verdict {
                busbar_substrate::plane_host::TransformVerdict::Proceed { applied, args_json } => {
                    // WHAT A REWRITE COMMITTED IS WHAT THE SESSION RUNS AS, and the plane decides
                    // whether it can read it: a payload it cannot is not adopted and the locked
                    // posture stands. That is the contract's own rule and this file does not
                    // second-guess it.
                    if applied {
                        self.driver.adopt_session_params(session, &args_json);
                    }
                }
                busbar_substrate::plane_host::TransformVerdict::Reject { status, .. } => {
                    return Hooks::Refused(
                        axum::http::StatusCode::from_u16(status)
                            .unwrap_or(axum::http::StatusCode::FORBIDDEN),
                    );
                }
            }
        }
        Hooks::Proceed
    }
}

/// THE DEPLOYMENT'S DECLARED SESSION DEFAULTS, as the plane's projector reads them.
///
/// One key, because the projector asks one question. A plane reads its own posture off the neutral
/// configuration view, and the composition is what puts the deployment's answer behind that view —
/// so this file carries a string it does not parse and the plane parses a string it did not fetch.
pub struct SessionDefaults(pub String);

impl busbar_contract::unit::ConfigView for SessionDefaults {
    fn get_str(&self, key: &str) -> Option<&str> {
        (key == "session_defaults").then_some(self.0.as_str())
    }

    fn get_int(&self, _key: &str) -> Option<i64> {
        None
    }

    fn get_bool(&self, _key: &str) -> Option<bool> {
        None
    }
}

impl std::fmt::Debug for SessionDefaults {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionDefaults").finish_non_exhaustive()
    }
}

/// The composed stack a session on this mount stands on, bottom layer first.
const TRANSPORT_CHAIN: &[&str] = &["http", "ws"];

/// What the two operator hops answered.
enum Hooks {
    /// Nothing was attached, nothing objected, or a rewrite was adopted.
    Proceed,
    /// A gate or a rewrite-gate refused the open, with the status it refused under.
    Refused(axum::http::StatusCode),
}

/// The facts one upgrade publishes, OWNED so they outlive the borrow the arrival is about to be
/// moved out of.
///
/// The reserved keys first and the declared captures last, which is the order the wire's own
/// `published_facts` uses and for its reason: a capture that collides with a reserved key is simply
/// never reached. The credential is pushed only where the upgrade CARRIED one — an absent fact and
/// an empty one are different statements, and a driver handed an empty credential is being told one
/// was presented and is blank.
fn upgrade_facts(
    arrival: &WsArrival,
    captures: &[busbar_contract::transport::surface::Capture<'_>],
) -> Vec<(String, String)> {
    let mut facts = vec![(
        busbar_contract::transport::facts::PATH.to_string(),
        arrival.path.clone(),
    )];
    if let Some(credential) = arrival
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        facts.push((
            busbar_contract::transport::facts::CREDENTIAL.to_string(),
            credential.to_string(),
        ));
    }
    // THE DECLARER'S OWN NAMES, from what the declared pattern captured — not the route registry's,
    // which would be this file deciding what a session is told about where it was opened.
    for capture in captures {
        facts.push((capture.name.to_string(), capture.value.to_string()));
    }
    facts
}

/// A finished refusal with no body: the status is the whole of what a caller is told before the
/// protocol changes, and a body here would be this file writing a protocol event.
fn refused(status: axum::http::StatusCode) -> axum::response::Response {
    axum::response::IntoResponse::into_response(status)
}

/// The inbound half of an accepted socket, as the pump reads it.
///
/// `None` is the peer's orderly end, which is what the neutral acceptor's stream finishing means.
/// There is no error arm because the acceptor does not hand one up: a socket that failed under the
/// read ends the stream, and the pump answers an ended stream as the client's cut.
struct ChannelSource(futures::channel::mpsc::Receiver<Vec<u8>>);

impl FrameSource for ChannelSource {
    async fn next_frame(&mut self) -> Option<Result<Vec<u8>, TransportError>> {
        use futures::StreamExt as _;
        self.0.next().await.map(Ok)
    }
}

/// The outbound half, as the pump writes it.
///
/// The media the declaration names is the WIRE's business and this acceptor has one frame kind, so
/// it is taken and not read — the argument exists because a wire with two kinds must be told which,
/// and dropping it at the seam would be the mount choosing for a wire that has a choice.
struct ChannelSink(futures::channel::mpsc::UnboundedSender<Vec<u8>>);

impl FrameSink for ChannelSink {
    async fn write_frame(&mut self, frame: &[u8], _media: &str) -> Result<(), TransportError> {
        self.0
            .unbounded_send(frame.to_vec())
            .map_err(|_| TransportError::Closed)
    }

    async fn write_close(&mut self, _code: u16) {
        self.0.close_channel();
    }
}

#[cfg(test)]
#[path = "tests/ws_arrival.rs"]
mod tests;
