// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Where a client credential is carried — read off the declarations the unit is composed with,
//! never off a list of carriers the unit was born knowing.
//!
//! A unit answers one step for every kind there is, so it cannot hold an opinion about any
//! particular wire. WHERE a credential sits is a wire fact, and it belongs to whoever speaks that
//! wire: each dialect declares its own [`CredentialSignature`], the root composes the set for the
//! dialects it actually mounts, and this module walks that set. A dialect the root did not mount
//! contributes no arrival, so a credential in its carrier is unreadable here by the declaration's
//! ABSENCE — there is no name to check and no list to be missing from.
//!
//! ## The order the set is read in, and why it is a wire fact too
//!
//! A SCHEME-WORDED arrival is read before an un-worded one. That is not a ranking of vendors: a
//! value carrying a scheme word says what it is, and a bare header value does not, so the
//! self-describing carrier is the one to believe when both are present. Within each of those two
//! bands the declared order stands, which is the order the root composed the set in.
//!
//! Two details matter and are easy to get wrong:
//!
//! - A present-but-empty header is treated as absent, so a blank header cannot mask a real token
//!   in a later carrier.
//! - A value at a worded arrival that does NOT carry the declared word falls THROUGH to the next
//!   arrival rather than terminating the search. A request signature sitting in the authorization
//!   header is not a bearer token; the dialect that declares a signature declares it as a
//!   signature, and the search for a token continues past it.

use busbar_contract::grammar::ArrivalLocation;
use busbar_contract::kinds::{CredentialArrival, CredentialSignature};
use std::fmt;

/// The request's headers, as this unit needs to read them.
///
/// A trait rather than a concrete map because the unit must not know which transport delivered the
/// request. Names are compared lower-cased; an implementation over a case-insensitive header map
/// satisfies that for free.
pub trait HeaderView {
    /// The value of one header, or `None` when it is absent or not valid text.
    fn header(&self, name: &str) -> Option<&str>;
}

/// The caller's bearer token, carried alongside the unit so a passthrough route can forward it.
///
/// Its `Debug` prints presence and nothing else. A derived one would print the credential the first
/// time anything formatted the structure that holds it, and even the length is a small oracle.
#[derive(Clone, Default)]
pub struct CallerToken(pub Option<String>);

impl fmt::Debug for CallerToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("CallerToken")
            .field(&if self.0.is_some() {
                "<present>"
            } else {
                "<absent>"
            })
            .finish()
    }
}

/// Read the credential at ONE declared arrival, or nothing.
///
/// Only a header arrival is readable from a header view. A signature over the request, a path
/// segment or a body pointer resolves somewhere this unit cannot see, and answering `None` for one
/// is a fall-through to the next declaration, never a refusal.
///
/// The worded form splits on the FIRST space rather than slicing by byte offset, so a malformed
/// value with a multi-byte character where the word belongs cannot land mid-character and panic.
fn read_arrival(headers: &dyn HeaderView, arrival: &CredentialArrival) -> Option<String> {
    let ArrivalLocation::Header(name) = arrival.at else {
        return None;
    };
    let value = headers.header(name).filter(|v| !v.is_empty())?;
    let Some(word) = arrival.prefix else {
        return Some(value.to_string());
    };
    let (spelled, token) = value.split_once(' ')?;
    (spelled.eq_ignore_ascii_case(word) && !token.is_empty()).then(|| token.to_string())
}

/// Read the client credential from whichever declared carrier presented it.
///
/// `mounted` is the set of credential signatures for the dialects the root composed this unit
/// with. Nothing else decides what is read: an arrival nobody declared is an arrival this unit
/// cannot see.
pub fn extract_client_token(
    headers: &dyn HeaderView,
    mounted: &[CredentialSignature],
) -> Option<String> {
    [true, false].into_iter().find_map(|worded| {
        mounted
            .iter()
            .flat_map(|sig| sig.arrivals)
            .filter(|arrival| arrival.prefix.is_some() == worded)
            .find_map(|arrival| read_arrival(headers, arrival))
    })
}
