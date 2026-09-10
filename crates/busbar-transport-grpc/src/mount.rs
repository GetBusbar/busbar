// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MOUNTING A DECLARED SURFACE ON THE FRAMED BINDING: any plane's, and none of them by name.
//!
//! ## What is different here, and what is deliberately the same
//!
//! On the document transports an operation is addressed by its target or by a member of the posted
//! document. On this one it is addressed by a SERVICE DESCRIPTOR: a call's target is
//! `/{service}/{method}`, derived by the client from the descriptor rather than chosen, which is why
//! a declaration cannot write the path down and expect it to stay true. So this module owns exactly
//! two things the document mount does not — splitting a call's target into the two names, and
//! answering an unknown one the way this wire answers it — and reuses everything else.
//!
//! Everything else is [`busbar_transport_http::mount`]: the request view a plane reads facts
//! through, the frame, the seam where a mount leaves what arrived for the units that will read it,
//! and the loop drive. Writing a second copy of those here would be a second answer to how a unit is
//! run, and the two would disagree the first time one of them was fixed.
//!
//! ## The status column is the WIRE's, not the protocol's and not the kernel's
//!
//! [`status_of`] maps the driver's CLOSED outcome vocabulary onto this wire's status codes, and it
//! is the same mapping for every plane because it is a statement about what happened to the CALL:
//! nobody answered, the caller was not identified, the caller was identified and not permitted, the
//! node is shedding. It takes the closed vocabulary rather than the loop's own ending because an
//! ending carries a step, a reason code and a posting and this wire has a field for none of them —
//! and because a transport that named the loop's types would be a plugin naming core. A protocol
//! that wants finer words than these puts them in its own answer body, which is the plane's to
//! write and not this file's to know.
//!
//! ## No plane is named here
//!
//! Asserted, not asked for: the kind-isolation gate's vocabulary matrix (`cargo xtask gate
//! kind-isolation`) scans every transport crate's source and manifest for a plane instance's name
//! and ratchets the count; this crate carries no per-crate copy of that scan.

use busbar_contract_transport::driver::Outcome;
use busbar_contract_transport::surface::{resolve_service, Bar, Dispatch, Operation, WireSurface};

/// A framed call's two names, split out of the target it arrived on.
///
/// The target of a framed call is `/{service}/{method}` and nothing else — no query, no extra
/// segments — so a target of any other shape is not a call on this wire and is refused as one rather
/// than being guessed at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CallName<'t> {
    /// The fully-qualified service.
    pub service: &'t str,
    /// The method within it.
    pub method: &'t str,
}

/// Split a framed call's target into the service and the method it names.
///
/// `None` for a target that is not the two-segment shape this wire defines. That is not pedantry: a
/// target with a third segment is a call the descriptor cannot have produced, and answering it as if
/// the extra segment were not there would serve a method the caller did not ask for.
#[must_use]
pub fn split_call(target: &str) -> Option<CallName<'_>> {
    let rest = target.strip_prefix('/')?;
    let (service, method) = rest.split_once('/')?;
    if service.is_empty() || method.is_empty() || method.contains('/') {
        return None;
    }
    Some(CallName { service, method })
}

/// The path a declared framed dispatch is served at.
///
/// Built from the two names rather than read off a declaration, because that is how a client builds
/// it: a declaration that wrote the path down instead would drift from the descriptor the client is
/// reading, and the drift would show up as a method that answers nothing.
#[must_use]
pub fn call_path(service: &str, method: &str) -> String {
    format!("/{service}/{method}")
}

/// What addressing a framed call against a declared surface produced.
#[derive(Clone, Debug)]
pub struct Addressed<'s> {
    /// The operation the descriptor names.
    pub operation: &'s Operation,
    /// The dispatch row that matched.
    pub dispatch: &'s Dispatch,
    /// The credential bar the row declares.
    pub bar: Bar,
}

/// Why a framed call could not be addressed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unaddressed {
    /// The target is not the `/{service}/{method}` shape this wire defines.
    NotACall,
    /// The two names are well formed and the surface declares no such call.
    NoSuchMethod,
}

/// Address one framed call against a declared surface.
///
/// # Errors
///
/// The target is not a call, or names a service and method the declaration does not carry.
pub fn resolve<'s>(surface: &'s WireSurface, target: &str) -> Result<Addressed<'s>, Unaddressed> {
    let call = split_call(target).ok_or(Unaddressed::NotACall)?;
    let (operation, dispatch) =
        resolve_service(surface, call.service, call.method).ok_or(Unaddressed::NoSuchMethod)?;
    Ok(Addressed {
        operation,
        dispatch,
        bar: dispatch.bar(),
    })
}

/// Every framed call one surface declares, as the paths a client will send.
///
/// What a mount registers, and what a boot log can print so an operator can see the served set
/// rather than infer it.
#[must_use]
pub fn declared_calls(surface: &WireSurface) -> Vec<String> {
    let mut out = Vec::new();
    for operation in surface.operations {
        for d in operation.dispatch {
            if let Dispatch::Service {
                service, method, ..
            } = d
            {
                out.push(call_path(service, method));
            }
        }
    }
    out
}

/// This wire's own status for one outcome, in its numbering.
///
/// Eight words in, one code out. The input is the CLOSED vocabulary the driver answers with and not
/// the loop's own ending, for the reason `busbar_contract_transport::driver` gives: an ending
/// carries the step, the reason code and the posting, and this wire has a field for none of the
/// three. A protocol that wants a finer word than these writes it in its answer body, which the
/// plane wrote and this module does not read.
#[must_use]
pub fn status_of(outcome: Outcome) -> u8 {
    /// The call completed.
    const OK: u8 = 0;
    /// The call was ended before an answer existed.
    const CANCELLED: u8 = 1;
    /// A deadline expired.
    const DEADLINE_EXCEEDED: u8 = 4;
    /// What the caller named does not exist.
    const NOT_FOUND: u8 = 5;
    /// The caller is over a rate or a budget.
    const RESOURCE_EXHAUSTED: u8 = 8;
    /// The caller was identified and is not permitted.
    const PERMISSION_DENIED: u8 = 7;
    /// Nothing here can serve the call right now.
    const UNAVAILABLE: u8 = 14;
    /// The caller was not identified.
    const UNAUTHENTICATED: u8 = 16;
    match outcome {
        Outcome::Completed => OK,
        // The two doors that are about WHO is calling, kept apart: this wire spells them with two
        // codes because they send a caller to fix two different things, and collapsing them tells a
        // caller with a bad credential that its permissions are wrong.
        Outcome::Unauthenticated => UNAUTHENTICATED,
        Outcome::Forbidden => PERMISSION_DENIED,
        Outcome::NotFound => NOT_FOUND,
        Outcome::Throttled => RESOURCE_EXHAUSTED,
        Outcome::TimedOut => DEADLINE_EXCEEDED,
        Outcome::Cancelled => CANCELLED,
        Outcome::Unavailable => UNAVAILABLE,
    }
}

/// The status a target this surface does not declare is answered with.
///
/// `UNIMPLEMENTED`, which is what this wire says for a method a server does not carry — and it is
/// the answer for BOTH refusals, a malformed target and a well-formed one naming nothing, because
/// from the caller's side both mean the same thing: there is no such call here.
pub const UNADDRESSED_STATUS: u8 = 12;

#[cfg(test)]
#[path = "tests/mount.rs"]
mod tests;
