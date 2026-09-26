// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The loop's dispatch seam: the one place a unit's Route step reaches the surface that already
//! answers it, counted.
//!
//! ## What is not here any more, and why
//!
//! This module used to provision one listener per configured address through the transport-key
//! unit — resolving the data and admin listeners' TLS material, journaling the reads and
//! registering the config into a slot of the TLS transport the boot seal composed. Nothing served
//! through that slot: the listeners bind over the serving path's own connection-security wrap,
//! which resolves the same references for itself. So the root read a deployment's private key a
//! second time, for a listener nothing accepted on, and that second resolution is gone: a root
//! unit has no book step unless it settles onto the book it opened (this module's test).

// ── the loop's dispatch seam ─────────────────────────────────────────────────────────────────────

/// THE ONE SEAM A UNIT'S ROUTE STEP REACHES THE SURFACE THAT ALREADY ANSWERS IT THROUGH.
///
/// Named here because nothing in it is about any one plane. The argument is an
/// [`OpClassId`](busbar_contract::ids::OpClassId), which every plane declares; the answer is the
/// loop's own [`RouteLeg`](busbar_kernel::teller::RouteLeg), which every plane's Route step already
/// hands back. A seam named after a plane would have been a second one
/// beside it the moment a second plane wanted the same thing, and the first thing to differ between
/// the two would have been a difference nobody meant.
///
/// **THE DRIVE IS THE PLANE'S AND IS HANDED IN.** This seam does not know how to execute an
/// operation and must not learn: what a request does is the plane's, and the surface that already
/// answers it is the surface that already answers it. What the seam owns is the fact that the drive
/// happened *here*, once, and nowhere else.
///
/// **THAT IS WHY THE ANSWER IS THE WORK AND NOT THE BYTES.** A status, headers and a byte vector
/// would be the honest answer for a plane whose operations are documents. It is the WRONG answer for
/// a plane whose operations are streams: taking the bytes here means draining the body here, and on
/// the billing planes the instant a body finishes draining is the instant the money is read. A seam
/// that buffered would be deciding when a stream ended, which is a decision that moves money. So the
/// leg is passed through and the bytes never come near this file.
///
/// **THE COUNT IS THE INSTRUMENT, NOT THE STATUS.** What this seam is for is answering "did the
/// engine run for this unit", and a status cannot answer it — a refusal rendered by the loop and an
/// upstream's own 403 read the same on the wire. A unit refused at Authenticate, Verify, Approve or
/// Admit never reaches Route, so it never reaches here, and the count says so.
pub trait PlaneDispatch: Send + Sync {
    /// Drive ONE operation of one unit, and count that it was driven.
    ///
    /// `drive` is the plane's own leg, already built and not yet polled. An implementation returns a
    /// leg that produces the same [`Decision`](busbar_contract::caps::Decision) the one it was handed would
    /// have: this seam chooses WHERE the work happens, never WHAT it answers.
    fn execute<'a>(
        &'a self,
        op: busbar_contract::ids::OpClassId,
        drive: busbar_kernel::teller::RouteLeg<'a>,
    ) -> busbar_kernel::teller::RouteLeg<'a>;

    /// How many units have driven this seam, where the seam keeps count.
    ///
    /// On the trait rather than reached for by downcast, because counting is what this seam is FOR:
    /// a composition that cannot be asked "did anything run" has not got the instrument, and the
    /// honest way to say so is `None` rather than a zero indistinguishable from a node that took no
    /// traffic.
    fn driven(&self) -> Option<u64> {
        None
    }
}

/// The seam's production half: the surface the plane already routes through, counted.
///
/// Deliberately the thinnest thing in the file. It awaits the leg it was handed and returns that
/// leg's own value — no decision is computed here, no byte is touched, and nothing is added to or
/// taken from the answer. **That is what makes byte identity a property of the construction rather
/// than of a measurement**: the future this returns awaits the future it was given.
///
/// The count is taken when the leg is FIRST POLLED and not when it is built, because those are two
/// different facts. A leg built and dropped — a unit whose client hung up between Admit and the
/// first poll — did not drive the engine, and a count taken at construction would say it did.
#[derive(Debug, Default)]
pub struct DrivenOnce {
    /// How many of this node's units have driven the seam, since the node was built.
    driven: std::sync::atomic::AtomicU64,
}

impl DrivenOnce {
    /// A seam that has driven nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// How many units have driven the surface through this seam.
    #[must_use]
    pub fn driven(&self) -> u64 {
        self.driven.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl PlaneDispatch for DrivenOnce {
    fn execute<'a>(
        &'a self,
        _op: busbar_contract::ids::OpClassId,
        drive: busbar_kernel::teller::RouteLeg<'a>,
    ) -> busbar_kernel::teller::RouteLeg<'a> {
        Box::pin(async move {
            self.driven
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            drive.await
        })
    }

    fn driven(&self) -> Option<u64> {
        Some(DrivenOnce::driven(self))
    }
}

// ── the data door on a dropped-in wire ───────────────────────────────────────────────────────────

/// SERVE THE DATA DOOR THROUGH THE WIRE UNDER IT, when that wire came in DROPPED IN
/// (`crate::root::registry::BootRegistry::dropped_door`): the wire binds `bind` itself and every
/// connection it accepts is served by the kernel's own hardened loop over the connection's detached
/// byte stream (`busbar_kernel::tls::serve_wire`), secured by `security` where the listener has a
/// `tls:` block. The same router, the same body bounds, the same drain on `shutdown` as the
/// kernel's socket listener — only who owns the socket differs.
///
/// # Errors
///
/// The wire would not bind `bind`.
pub async fn serve_door(
    wire: std::sync::Arc<dyn busbar_contract::Transport>,
    bind: &str,
    router: axum::Router,
    security: Option<std::sync::Arc<dyn busbar_contract::transport::wire::ConnectionSecurity>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<(), busbar_contract::transport::wire::TransportError> {
    let keys = busbar_contract::TransportKeyHandle::keyless();
    let listener = wire.listen(&Bind(bind), &keys).await?;
    busbar_kernel::tls::serve_wire(wire, listener, router, security, shutdown).await;
    Ok(())
}

/// The data door's address, as the configuration a wire's `listen` reads.
struct Bind<'a>(&'a str);

impl busbar_contract::ConfigView for Bind<'_> {
    fn get_str(&self, _: &str) -> Option<&str> {
        None
    }
    fn get_int(&self, _: &str) -> Option<i64> {
        None
    }
    fn get_bool(&self, _: &str) -> Option<bool> {
        None
    }
}

impl busbar_contract::TransportConfigView for Bind<'_> {
    fn bind(&self) -> Option<&str> {
        Some(self.0)
    }
}

#[cfg(test)]
#[path = "tests/transports.rs"]
mod tests;
