//! The generic duplex-session seam — "a transport is a wire, never a plane".
//!
//! The NEW 1.6.0 session/duplex vocabulary both sides of the fourth (streaming) plane name, pinned
//! field-for-field by `docs/design/1.6.0-streaming-model.md` section 9.1 (the implementation appendix). The
//! seam has two opposite halves that never meet each other's crate: the TRANSPORT face
//! ([`DuplexWire`], implemented by `busbar-transport-ws`) and the DRIVER face ([`SessionDriver`],
//! implemented by the composition root over the kernel loop). The root↔plane boundary is BYTES ONLY
//! ([`SessionFrame`]/[`SessionReply`] carry `&[u8]`/`Vec<u8>`): no plane-typed IR crosses here, and no
//! plugin self-KEY/identity appears anywhere in these types — identity is the customer VERB → a fresh
//! random per-startup [`SessionHandle`] (streaming section 1/section 6).
//!
//! Async rulings honoured: session methods box their futures as [`SessionFut`] =
//! `Pin<Box<dyn Future + 'a>>` — the Transport-trait idiom (`transport/mod.rs`'s `Fut`) MINUS `Send`,
//! never `async-trait`. The dropped `Send` is load-bearing (#42): the driving future holds the
//! `&dyn Scratch` arena borrow across the upstream await, so it is `!Send` and runs pinned to one core.

use crate::bounded::Scratch;
use crate::transport::driver::Outcome;
use crate::transport::surface::{Bar, WireSurface};
use crate::transport::wire::{CloseReason, Listener, TransportError};
use core::future::Future;
use core::pin::Pin;

/// The session async-return alias: the Transport idiom `Fut<'a,T>` MINUS `Send`.
///
/// `!Send` is load-bearing (#42): the driving future holds `&dyn Scratch` across the upstream await,
/// so it structurally cannot be the codebase's `Send` `Fut<'a,T>`. Output is the call's own type
/// (already a `Result` where the op can fail), so this alias does not impose transport's
/// `TransportError`.
pub type SessionFut<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// A fresh RANDOM per-process-startup opaque id (#41(2)), stable for the session's life, different
/// next boot. NOT a counter (a counter leaks session count/creation order). Minted by core; the
/// transport holds only this — it carries no plugin name because none exists to hold: it IS the
/// identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionHandle(pub u64);

/// THE TRANSPORT FACE. "A transport is a wire": upgrade a listener into an open session, then pump it.
///
/// Implemented CONCRETELY by a transport plugin (`WsTransport`); never boxed as `dyn DuplexWire` (the
/// associated type makes it non-`dyn`-compatible, and that is intended — the session seam is driven
/// concretely/monomorphized per-core while the registry keeps an `Arc<dyn Transport>` entry for the
/// non-session lookup path). Names no plane, no dialect, no money, NO plugin-identity string. The wire
/// OBJECT is `Send + Sync` (registered once, shared across the N per-core runtimes); its per-session
/// DRIVING FUTURES are `!Send` by design (#42).
pub trait DuplexWire: Send + Sync {
    /// One open, un-pumped session. RAII guard ([`OpenGuard`]): dropped without being consumed by
    /// [`pump_session`](DuplexWire::pump_session), its `Drop` closes the session so `open()`'s
    /// reservation cannot leak. NOT `Send` — it may already own arena/socket state pinned to this
    /// session's core (#42).
    type OpenSession: OpenGuard + 'static;

    /// WAITING HALF: accept + upgrade + [`SessionDriver::open`], stop before pumping. Droppable (race
    /// arm). Boxed and `!Send` (r-arena-D2) — runs on the pinned `LocalSet`, never `async-trait`.
    fn serve_upgrade<'w>(
        &'w self,
        listener: &'w Listener,
        driver: &'w dyn SessionDriver,
        surface: &'w WireSurface,
    ) -> SessionFut<'w, Result<Self::OpenSession, TransportError>>;

    /// MID-SESSION HALF: run one open session to its end, consuming `OpenSession` BY VALUE (disarming
    /// its guard). Guarantees [`SessionDriver::close`] is called exactly once by return. Bounded by
    /// [`SessionBudgets`]. `arena: &dyn Scratch` is the per-turn scratch borrowed across the upstream
    /// await ⇒ the future is `!Send`, which is WHY the boxed future carries no `Send` bound.
    fn pump_session<'w>(
        &'w self,
        open: Self::OpenSession,
        driver: &'w dyn SessionDriver,
        budgets: SessionBudgets,
        arena: &'w dyn Scratch,
    ) -> SessionFut<'w, SessionEnd>;
}

/// The must-close guard [`DuplexWire::OpenSession`] satisfies.
///
/// [`DuplexWire::pump_session`] is the ONLY consumer that disarms it; every other drop path fires
/// [`SessionDriver::close`] with a distinguished abort reason ([`CloseReason::Aborted`]).
pub trait OpenGuard {
    /// The handle this open session carries.
    fn handle(&self) -> SessionHandle;
    /// `pump_session` calls this on entry (it takes over the close-once obligation). A still-armed
    /// `Drop` calls `SessionDriver::close(handle, SessionEnd { cut: Cut::Client, reason:
    /// CloseReason::Aborted })`.
    fn disarm(&mut self) -> SessionHandle;
}

/// THE DRIVER FACE. Implemented by the composition ROOT over the kernel loop; handed to a wire at
/// listen.
///
/// The object is `Send + Sync` (shared); its methods run inside the pinned per-session task and are
/// SYNCHRONOUS (no async here — the awaits live in [`DuplexWire::pump_session`]).
pub trait SessionDriver: Send + Sync {
    /// Open a session: governs-to-admit, mints the handle. `Err(Outcome)` refuses the upgrade.
    fn open(&self, open: SessionOpen<'_>, surface: &WireSurface) -> Result<SessionHandle, Outcome>;
    /// Per-frame, infallible: hand the frame's bytes to the plane and get bytes back.
    fn drive(&self, session: SessionHandle, frame: SessionFrame<'_>) -> SessionReply;
    /// Every ending, exactly once.
    fn close(&self, session: SessionHandle, end: SessionEnd);
}

/// What the wire hands [`SessionDriver::open`].
///
/// Borrowed, verbatim per-connection facts (incl. the captured credential fact, streaming section 2) — NO
/// owned plane state, NO plugin name. The driver extracts what it needs at open and does not retain
/// the borrow.
#[derive(Debug)]
pub struct SessionOpen<'a> {
    /// Includes `tfacts::CREDENTIAL`, `tfacts::PATH`, `tfacts::PEER`.
    pub facts: &'a [(&'a str, &'a str)],
    /// The transport ROW key (e.g. `"ws"`), not a plane name.
    pub transport: &'static str,
    /// The composed-over chain, e.g. `["tcp","tls","http","ws"]`.
    pub chain: &'a [&'static str],
    /// The [`BindingDecl`](crate::transport::surface::BindingDecl)`.name` this arrival matched.
    pub binding: &'static str,
    /// The session's ONE bar (`Bar::Credential` for a keyed session).
    pub bar: Bar,
}

impl SessionOpen<'_> {
    /// Read one per-connection fact by key.
    #[must_use]
    pub fn fact(&self, key: &str) -> Option<&str> {
        self.facts.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    }
}

/// One inbound frame handed to [`SessionDriver::drive`].
///
/// BYTES ONLY — the plane's `Envelope` (plane-local) turns these bytes into its dialect IR; no plane
/// type appears here.
#[derive(Debug)]
pub struct SessionFrame<'a> {
    /// The frame's raw bytes.
    pub payload: &'a [u8],
    /// The frame's monotonic sequence number within the session.
    pub seq: u64,
}

/// What [`SessionDriver::drive`] returns.
///
/// BYTES ONLY out. `media` is the response media type the wire stamps; `close: Some(_)` ends the
/// session after emitting `frames`.
#[derive(Debug)]
pub struct SessionReply {
    /// The response frames to emit, in order.
    pub frames: Vec<Vec<u8>>,
    /// The response media type the wire stamps.
    pub media: String,
    /// The unit outcome this reply settles.
    pub outcome: Outcome,
    /// `Some(_)` ends the session (after emitting `frames`) with this reason.
    pub close: Option<CloseReason>,
}

impl SessionReply {
    /// No frames, stay open.
    #[must_use]
    pub fn quiet(outcome: Outcome) -> Self {
        Self {
            frames: Vec::new(),
            media: String::new(),
            outcome,
            close: None,
        }
    }

    /// No frames, close with `reason`.
    #[must_use]
    pub fn ending(outcome: Outcome, reason: CloseReason) -> Self {
        Self {
            frames: Vec::new(),
            media: String::new(),
            outcome,
            close: Some(reason),
        }
    }

    /// Emit `frames` with `media`, stay open.
    #[must_use]
    pub fn frames(frames: Vec<Vec<u8>>, media: impl Into<String>, outcome: Outcome) -> Self {
        Self {
            frames,
            media: media.into(),
            outcome,
            close: None,
        }
    }
}

/// Which end cut first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Cut {
    /// The client end cut first.
    Client,
    /// The upstream end cut first.
    Upstream,
}

/// How a session ended — the value [`DuplexWire::pump_session`] returns and [`SessionDriver::close`]
/// receives.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct SessionEnd {
    /// Which end cut first.
    pub cut: Cut,
    /// Why the session ended.
    pub reason: CloseReason,
}

/// The whole-session budgets [`DuplexWire::pump_session`] enforces (streaming section 3).
///
/// Two deadlines + bounded renewal so a legitimate long call is not collateral of the slow-trickle
/// DoS fix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, serde::Serialize)]
pub struct SessionBudgets {
    /// Slow-trickle KILL: reset on each COMPLETED turn / inbound activity.
    pub idle_deadline: Option<core::time::Duration>,
    /// Absolute outer ceiling for the whole session (renewal-proof).
    pub total_deadline: Option<core::time::Duration>,
    /// How many times `idle_deadline` may reset before `total_deadline` bites.
    pub max_renewals: u32,
}

impl SessionBudgets {
    /// The common shape: both deadlines set, with `renewals` idle resets allowed.
    #[must_use]
    pub fn within(idle: core::time::Duration, total: core::time::Duration, renewals: u32) -> Self {
        Self {
            idle_deadline: Some(idle),
            total_deadline: Some(total),
            max_renewals: renewals,
        }
    }
}

/// The egress leg: the plane SEALS a destination, the composition dials and hands back this lease so
/// a relayed frame is a WRITE under the open unit's view (never a second unit).
///
/// Non-blocking, backpressure-aware.
pub trait EgressLease: Send {
    /// Offer a frame upstream. `Err` on backpressure or a closed leg; never blocks.
    fn offer(&mut self, frame: &[u8]) -> Result<(), TransportError>;
    /// Finish the leg. Idempotent, infallible.
    fn finish(&mut self);
}
