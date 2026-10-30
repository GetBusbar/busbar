// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A DATAGRAM SESSION, on the data listener.
//!
//! A door plane's claim whose carrier a DATAGRAM framer answers is an HTTP unit whose answer turns
//! it into a duplex session on a host carrier, as an upgrade does for a stream: the request body is
//! the far end's description; the host opens the accepting association over its CLAIM DOOR (the
//! datagram port the transport's inbound need binds) and the association becomes the unit's duplex
//! session, its caller side this file's [`DatagramCaller`] on the driver's one `SessionCaller`
//! path. The answer carries the framer's own description as its body.
//!
//! What the session carries is the association's CHANNELS: their messages are the session's
//! pieces, both ways. Its LINES never reach the session or the plane: the session's
//! [`Pairing`] bridges them with the upstream leg's, which the session's walk opens for the same
//! unit (the connector's session book, keyed by the unit). The session's cleanup closes the pairing
//! once, both legs with it.
//!
//! No noun of any protocol is spelled here: a claim door, an association, a description, lines and
//! channels.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Instant;

use busbar_core_connector::datagram::{
    Across, Answered, DatagramFraming, Leg, LegSink, Pairing, PortAssociations,
};
use busbar_core_connector::framer::Got;
use busbar_core_connector::udp::{ReadyPort, MAX_DATAGRAM};
use busbar_kernel::plane_driver::{CallerEnd, HeadFields, SessionCaller};
use tokio::sync::{mpsc, oneshot, Notify};

use super::Stated;

/// How many channel messages a session's caller side holds before the session ends, either way:
/// for the plane, and from it before the far end opens a channel.
const CALLER_QUEUE: usize = 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// THE CLAIM DOORS, by the claim their datagram framer answers: each one bound port.
#[derive(Debug, Default, Clone)]
pub struct ClaimDoors(HashMap<String, Arc<ClaimDoor>>);

impl ClaimDoors {
    /// Serve `claim`'s associations over `door`.
    pub fn insert(&mut self, claim: &str, door: Arc<ClaimDoor>) {
        self.0.insert(claim.to_owned(), door);
    }

    /// The claim door for `claim`.
    #[must_use]
    pub fn get(&self, claim: &str) -> Option<Arc<ClaimDoor>> {
        self.0.get(claim).cloned()
    }

    /// THE CLAIM DOORS BOOT BINDS: one for every inbound
    /// listener in the one list of listeners whose transport a DATAGRAM framer answers, bound on
    /// the address its `{listen}` block names, its task on the calling worker. A listener over any
    /// other transport is no claim door (the data listener and the stream listeners bind those);
    /// two claim doors for one claim are refused.
    ///
    /// # Errors
    ///
    /// The setting that names an address the port cannot bind (a wildcard included: a claim
    /// door's address is the one candidate its associations advertise), or a claim bound twice.
    pub fn bind(
        binds: &[crate::root::loader::boot::InboundBind],
        framer_for: impl Fn(&str) -> Option<Arc<dyn busbar_core_connector::framer::FramerDoor>>,
    ) -> Result<Self, String> {
        let mut doors = ClaimDoors::default();
        for b in binds {
            if b.transport.is_empty()
                || !framer_for(&b.transport).is_some_and(|d| d.facts().datagram)
            {
                continue;
            }
            if doors.0.contains_key(&b.transport) {
                return Err(format!(
                    "{}: a second claim door for `{}`",
                    b.listen_setting(),
                    b.transport
                ));
            }
            let port = busbar_core_connector::udp::bind(&b.listen.to_string())
                .and_then(ReadyPort::open)
                .map_err(|e| {
                    format!("{}: {} cannot be bound: {e}", b.listen_setting(), b.listen)
                })?;
            doors.insert(&b.transport, ClaimDoor::serve(port));
        }
        Ok(doors)
    }
}

/// ONE CLAIM DOOR: one bound datagram port, every accepted association on it, and each one's
/// session leg.
pub struct ClaimDoor {
    port: ReadyPort,
    assocs: PortAssociations,
    legs: Mutex<HashMap<u64, Arc<CallerLeg>>>,
    /// Woken when an association joins, so the port's task keeps its clock.
    joined: Notify,
}

impl std::fmt::Debug for ClaimDoor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimDoor")
            .field("local", &self.port.local_addr())
            .finish_non_exhaustive()
    }
}

impl ClaimDoor {
    /// A claim door over `port` (already on the worker's reactor), its task spawned on the current
    /// runtime.
    #[must_use]
    pub fn serve(port: ReadyPort) -> Arc<Self> {
        let door = Arc::new(ClaimDoor {
            port,
            assocs: PortAssociations::new(),
            legs: Mutex::new(HashMap::new()),
            joined: Notify::new(),
        });
        tokio::spawn(Arc::clone(&door).run());
        door
    }

    /// The port's own address: the one candidate every association on it advertises.
    #[must_use]
    pub fn local(&self) -> SocketAddr {
        self.port.local_addr()
    }

    /// Send one datagram an association owes the port; a send that would block drops it.
    fn send(&self, to: SocketAddr, d: &[u8]) {
        let _ = self.port.send_to(d, to);
    }

    /// What the port's associations answered, to each one's leg.
    fn answer(&self, answered: Answered, now: Instant) {
        for (id, answer) in answered {
            let leg = lock(&self.legs).get(&id).cloned();
            match (leg, answer) {
                (Some(leg), Ok(y)) => leg.yielded(y.pieces, now),
                (Some(leg), Err(_)) => leg.failed(),
                (None, _) => {}
            }
        }
    }

    /// THE PORT'S TASK: every datagram read and handed to the association it belongs to, the
    /// associations' clock kept, what each yields handed to its leg; until the door is dropped.
    async fn run(self: Arc<Self>) {
        let mut buf = vec![0_u8; MAX_DATAGRAM];
        loop {
            let deadline = self.assocs.deadline();
            let read = std::future::poll_fn(|cx| {
                self.port
                    .poll_recv_from(cx, &mut buf)
                    .map(|r| r.map(|(n, from)| (buf[..n].to_vec(), from)))
            });
            let sleep = async {
                match deadline {
                    Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                    None => std::future::pending::<()>().await,
                }
            };
            enum Woke {
                Read(std::io::Result<(Vec<u8>, SocketAddr)>),
                Clock,
                Joined,
            }
            let woke = tokio::select! {
                got = read => Woke::Read(got),
                () = sleep => Woke::Clock,
                () = self.joined.notified() => Woke::Joined,
            };
            let now = Instant::now();
            let answered = match woke {
                Woke::Read(Ok((datagram, from))) => {
                    self.assocs
                        .datagram(from, &datagram, now, &|to, d| self.send(to, d))
                }
                // A per-datagram error (an unreachable far end reported back): the port stands.
                Woke::Read(Err(_)) | Woke::Joined => Vec::new(),
                Woke::Clock => self.assocs.timeout(now, &|to, d| self.send(to, d)),
            };
            self.answer(answered, now);
        }
    }

    /// Carry `framing` on this door as `leg`'s association; its number.
    fn join(
        &self,
        framing: DatagramFraming,
        leg: &Arc<CallerLeg>,
    ) -> Result<u64, busbar_core_connector::datagram::NotAdded> {
        let id = self.assocs.add(framing)?;
        leg.bind(id);
        lock(&self.legs).insert(id, Arc::clone(leg));
        self.joined.notify_one();
        Ok(id)
    }

    /// Emit on association `id` and flush.
    fn emit(
        &self,
        id: u64,
        stream: u64,
        bytes: &[u8],
        end: bool,
        text: bool,
        now: Instant,
    ) -> bool {
        let (ok, answered) = self
            .assocs
            .emit(id, stream, bytes, end, text, now, &|to, d| self.send(to, d));
        self.answer(answered, now);
        ok
    }

    /// Stop carrying association `id`: its framing finishes as it drops.
    fn leave(&self, id: u64) {
        lock(&self.legs).remove(&id);
        self.assocs.remove(id);
    }
}

/// THE CALLER'S LEG of one datagram session: its association on the claim door, the session's
/// pairing, the channel the session's pieces ride, and the queue the plane reads them from.
pub struct CallerLeg {
    door: Weak<ClaimDoor>,
    id: Mutex<Option<u64>>,
    pairing: Mutex<Option<Arc<Pairing>>>,
    /// The channel a written piece goes to: the first channel the association named.
    channel: Mutex<Option<u64>>,
    /// Pieces the plane wrote before the channel opened, at most `CALLER_QUEUE`; none once the leg
    /// closed.
    held: Mutex<VecDeque<(Vec<u8>, bool)>>,
    to_session: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
}

impl CallerLeg {
    fn new(door: &Arc<ClaimDoor>, to_session: mpsc::Sender<Vec<u8>>) -> Arc<Self> {
        Arc::new(CallerLeg {
            door: Arc::downgrade(door),
            id: Mutex::new(None),
            pairing: Mutex::new(None),
            channel: Mutex::new(None),
            held: Mutex::new(VecDeque::new()),
            to_session: Mutex::new(Some(to_session)),
        })
    }

    fn bind(&self, id: u64) {
        *lock(&self.id) = Some(id);
    }

    /// What the association yielded: through the pairing (its lines go across), then its channels'
    /// heads name the session's channel and their messages go to the session.
    fn yielded(&self, pieces: Vec<Got>, now: Instant) {
        let Some(pairing) = lock(&self.pairing).clone() else {
            return;
        };
        let session = pairing.sort(Leg::Caller, pieces, now);
        self.take(session, now);
    }

    fn take(&self, session: Vec<Got>, now: Instant) {
        for g in session {
            if g.fields {
                if lock(&self.channel).is_none() {
                    *lock(&self.channel) = Some(g.stream);
                    self.release(now);
                }
                continue;
            }
            if g.stream == 0 || g.bytes.is_empty() {
                continue;
            }
            let sent = lock(&self.to_session)
                .as_ref()
                .is_some_and(|tx| tx.try_send(g.bytes).is_ok());
            if !sent {
                // A plane that does not keep up with its caller ends the session.
                self.failed();
                return;
            }
        }
    }

    /// The pieces the plane wrote before the channel opened, now on it.
    fn release(&self, now: Instant) {
        let held: Vec<(Vec<u8>, bool)> = lock(&self.held).drain(..).collect();
        for (bytes, text) in held {
            self.write(&bytes, text, now);
        }
    }

    /// One piece toward the caller, on the session's channel.
    fn write(&self, bytes: &[u8], text: bool, now: Instant) -> bool {
        let channel = *lock(&self.channel);
        let Some(channel) = channel else {
            if lock(&self.to_session).is_none() {
                return false;
            }
            let mut held = lock(&self.held);
            if held.len() < CALLER_QUEUE {
                held.push_back((bytes.to_vec(), text));
                return true;
            }
            drop(held);
            // A far end that opens no channel while the plane writes ends the session.
            self.failed();
            return false;
        };
        let (Some(door), Some(id)) = (self.door.upgrade(), *lock(&self.id)) else {
            return false;
        };
        door.emit(id, channel, bytes, true, text, now)
    }

    /// The association failed or the plane fell behind: the session's pairing closes, this leg
    /// with it.
    fn failed(&self) {
        let pairing = lock(&self.pairing).clone();
        match pairing {
            Some(p) => p.close(),
            None => self.close(),
        }
    }
}

impl LegSink for CallerLeg {
    fn line(&self, across: Across, now: Instant) {
        if let (Some(door), Some(id)) = (self.door.upgrade(), *lock(&self.id)) {
            door.emit(
                id,
                across.stream,
                &across.bytes,
                across.end_of_frame,
                false,
                now,
            );
        }
    }

    fn close(&self) {
        lock(&self.to_session).take();
        lock(&self.held).clear();
        let id = lock(&self.id).take();
        if let (Some(door), Some(id)) = (self.door.upgrade(), id) {
            door.leave(id);
        }
    }
}

/// THE CALLER'S SIDE OF A DATAGRAM SESSION (K6's one `SessionCaller`): its pieces are the
/// association's channel messages; every piece the plane writes is one message on that channel.
/// The plane's head is kept for the unit's answer.
pub(super) struct DatagramCaller {
    leg: Arc<CallerLeg>,
    from: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    head: Mutex<Option<oneshot::Sender<(u32, HeadFields)>>>,
    stated: std::sync::atomic::AtomicU32,
    /// The session's opening piece was read: the association's open, one empty piece before the
    /// caller's first message, so the plane crosses the session once before the open is answered
    /// (the open waits for the head that crossing states).
    opened: std::sync::atomic::AtomicBool,
}

/// THE PLANE'S HEAD for a datagram session's open: the head the plane states on its session's first
/// crossing, waited for within `wait`; `None` when it states none in time (or the session ended
/// without one).
pub(super) async fn plane_head(
    head: oneshot::Receiver<(u32, HeadFields)>,
    wait: std::time::Duration,
) -> Option<(u32, HeadFields)> {
    tokio::time::timeout(wait, head).await.ok()?.ok()
}

impl CallerEnd for DatagramCaller {
    fn head(&self, status: u32, fields: HeadFields) {
        self.stated
            .store(status, std::sync::atomic::Ordering::Release);
        if let Some(tx) = lock(&self.head).take() {
            let _ = tx.send((status, fields));
        }
    }

    async fn write(&self, bytes: &[u8]) -> bool {
        self.leg.write(bytes, false, Instant::now())
    }

    async fn write_text(&self, bytes: &[u8]) -> bool {
        self.leg.write(bytes, true, Instant::now())
    }
}

impl SessionCaller for DatagramCaller {
    async fn read(&self) -> Option<Vec<u8>> {
        if !self.opened.swap(true, std::sync::atomic::Ordering::AcqRel) {
            return Some(Vec::new());
        }
        self.from.lock().await.recv().await
    }
}

impl Stated for DatagramCaller {
    fn stated(&self) -> Option<u32> {
        Some(self.stated.load(std::sync::atomic::Ordering::Acquire)).filter(|s| *s != 0)
    }
}

/// ONE DATAGRAM SESSION'S OPENING, before its unit is admitted: the accepting association over the
/// claim door, settled by the far end's description; its own description (the unit's answer body),
/// the session's caller side, and what joins the door once the unit is admitted ([`Joining`]).
pub(super) struct Opened {
    /// The framer's own description: the unit's answer body.
    pub(super) description: Vec<u8>,
    /// The session's caller side.
    pub(super) caller: DatagramCaller,
    /// The plane's head, once it states one.
    pub(super) head: oneshot::Receiver<(u32, HeadFields)>,
    /// What joins the door once the unit is admitted.
    pub(super) joining: Joining,
}

/// AN ASSOCIATION NOT YET ON ITS DOOR: it joins only once its unit is admitted (an association
/// exists only for a unit admitted at the description's accept). Dropped unjoined, its framing
/// finishes and nothing was ever registered.
pub(super) struct Joining {
    door: Arc<ClaimDoor>,
    framing: DatagramFraming,
    leg: Arc<CallerLeg>,
    pairing: Arc<Pairing>,
}

impl Opened {
    /// Open over `door`: the association `framer` answers, settled by the far end's `description`.
    ///
    /// # Errors
    ///
    /// The framer refused the far end's description (it does not parse, or settles no terms):
    /// the unit is refused before it is admitted.
    pub(super) fn open(
        door: &Arc<ClaimDoor>,
        framer: Arc<dyn busbar_core_connector::framer::FramerDoor>,
        description: &[u8],
    ) -> Result<Self, String> {
        let (mut framing, _) =
            DatagramFraming::accept_minted(framer, door.local()).map_err(|r| r.error)?;
        let now = Instant::now();
        let y = framing.rendezvous(description, now).map_err(|r| r.error)?;
        let (to_session, from) = mpsc::channel(CALLER_QUEUE);
        let leg = CallerLeg::new(door, to_session);
        let pairing = Pairing::new(Arc::clone(&leg) as Arc<dyn LegSink>, door.local());
        *lock(&leg.pairing) = Some(Arc::clone(&pairing));
        let session = pairing.sort(Leg::Caller, y.pieces, now);
        let answer = session
            .iter()
            .find(|g| g.stream == 0 && !g.fields)
            .map(|g| g.bytes.clone())
            .ok_or("the framer answered no description of its own")?;
        let (head_tx, head) = oneshot::channel();
        Ok(Opened {
            description: answer,
            caller: DatagramCaller {
                leg: Arc::clone(&leg),
                from: tokio::sync::Mutex::new(from),
                head: Mutex::new(Some(head_tx)),
                stated: std::sync::atomic::AtomicU32::new(0),
                opened: std::sync::atomic::AtomicBool::new(false),
            },
            head,
            joining: Joining {
                door: Arc::clone(door),
                framing,
                leg,
                pairing,
            },
        })
    }
}

impl Joining {
    /// The unit was admitted: the association joins the claim door, and the session's pairing is
    /// registered under `unit` in the connector's session book before the session runs.
    ///
    /// # Errors
    ///
    /// The door refused the association (its user name is another's), or the book the unit; the
    /// pairing is closed either way.
    pub(super) fn admit(self, unit: u64) -> Result<(), String> {
        let Joining {
            door,
            framing,
            leg,
            pairing,
        } = self;
        if let Err(e) = door.join(framing, &leg) {
            pairing.close();
            return Err(format!("the claim door refused the association: {e:?}"));
        }
        crate::root::connector::the()
            .pair(unit, Arc::clone(&pairing))
            .map_err(|e| {
                pairing.close();
                format!("the session book refused the unit: {e:?}")
            })
    }
}

#[cfg(test)]
#[path = "tests/serve_datagram.rs"]
mod tests;
