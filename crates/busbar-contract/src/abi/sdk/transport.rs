// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT SDK: what every transport door wrote alike, stated once.
//!
//! * [`form_codes`] — a door's selector forms, as the codes its Statement carries.
//! * [`not_served!`](crate::not_served) — the stubs a transport fills the slots of the role it does
//!   not play with: REFUSED, naming the op and the role (`abi::transport`).
//! * [`settings_reading`] — a transport's settings as a JSON object, a key it does not read refused.
//! * [`DEFAULT_BODY_MAX`] — the request-body bound's declared default, as a setting declaration
//!   states it.
//! * [`carried`] — a carrier op's instance and its armed host I/O, or the refusal a call on neither
//!   earns.
//! * [`table::Table`] — what an instance holds by token (framings, connections, calls), one lock per
//!   value, none shared between two.
//! * [`sink`] — a framer's sink fill ([`sink::fill`], [`sink::Piece`], [`sink::field_cut`]), over
//!   any frame buffer.
//!
//! The HOT transport lowering that lived here (`export_carrier!`, `export_framer!`, the per-method
//! `#[repr(C)]` slot bridges and the decl a transport cdylib exported as `busbar_transport_decl`) is
//! deleted (row 84): every transport, in this tree and in the fleet, serves its memory-ABI door
//! (`export_door!`), and the loader reads no transport decl.

use crate::abi::sdk::io::Io;
use crate::abi::sdk::life::{settings_object, Held, Life, Refusal};
use crate::abi::sdk::safe::Instance;
use crate::abi::shared::code;
use crate::grammar::SelectorForm;
use crate::transport::DEFAULT_REQUEST_BODY_MAX_BYTES;

pub mod sink;
pub mod table;

/// `forms` as their codes, in declared order.
#[must_use]
pub const fn form_codes<const N: usize>(forms: &[SelectorForm]) -> [u8; N] {
    let mut list = [0_u8; N];
    let mut i = 0;
    while i < N {
        list[i] = code::selector_form(forms[i]);
        i += 1;
    }
    list
}

/// The request-body bound's default ([`DEFAULT_REQUEST_BODY_MAX_BYTES`]) as the decimal text a
/// setting declaration states it in.
pub const DEFAULT_BODY_MAX: &str = "33554432";

/// `text` read as a decimal count.
const fn decimal(text: &str) -> usize {
    let b = text.as_bytes();
    let mut n = 0;
    let mut i = 0;
    while i < b.len() {
        n = n * 10 + (b[i] - b'0') as usize;
        i += 1;
    }
    n
}

// The declared default is the bound the host applies: one fact, held equal.
const _: () = assert!(decimal(DEFAULT_BODY_MAX) == DEFAULT_REQUEST_BODY_MAX_BYTES);

/// A transport's `settings` as the JSON object they must be (`{}` when empty), every key it does not
/// read (one of `reads`) refused: `settings: <key> is not a setting this transport reads`.
///
/// # Errors
/// The settings are not a JSON object, or name a key not in `reads`: FAILED.
pub fn settings_reading(
    settings: &[u8],
    reads: &[&str],
) -> Result<serde_json::Map<String, serde_json::Value>, Refusal> {
    let object = settings_object(settings)?;
    if let Some(key) = object.keys().find(|k| !reads.contains(&k.as_str())) {
        return Err(Refusal::failed(format!(
            "settings: {key} is not a setting this transport reads"
        )));
    }
    Ok(object)
}

/// Carrier op `op`'s open instance and the host's armed I/O for it on the op's ticket.
///
/// # Errors
/// FAILED: `<op>: no open instance`, or `<op>: the host lent this carrier no I/O`.
pub fn carried<'a, L: Life>(
    i: &Instance<'a, Held<L>>,
    op: &str,
) -> Result<(&'a L, Io<'a>), Refusal> {
    let held = i
        .get()
        .ok_or_else(|| Refusal::failed(format!("{op}: no open instance")))?;
    let io = held
        .host()
        .map(|h| h.io(i.ticket()))
        .filter(Io::armed)
        .ok_or_else(|| Refusal::failed(format!("{op}: the host lent this carrier no I/O")))?;
    Ok((held.life(), io))
}

/// THE ROLE STUBS: one [`SafeSlot`](crate::abi::sdk::SafeSlot) per op of the role a transport does
/// not play, over its instance `state`, each answering REFUSED with
/// `<op>: the <role> does not serve this op`, e.g.
/// `not_served! { state: Held<Carried>, role: "tcp carrier"; NoLocate(LocateIn => LocateOut) "locate"; }`.
#[macro_export]
macro_rules! not_served {
    (
        state: $state:ty, role: $role:literal;
        $($(#[$doc:meta])* $name:ident($in:ty => $out:ty) $op:literal;)*
    ) => {$(
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name;
        impl $crate::abi::sdk::SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = $state;
            fn call(
                _: $crate::abi::sdk::Instance<'_, $state>,
                _: $crate::abi::sdk::Lent<'_, $in>,
                mut out: $crate::abi::sdk::Out<'_, $out>,
            ) -> $crate::abi::mechanism::call::Outcome {
                out.fail($crate::abi::sdk::life::Refusal::refused(concat!(
                    $op,
                    ": the ",
                    $role,
                    " does not serve this op"
                )))
            }
        }
    )*};
}

#[cfg(test)]
#[path = "tests/transport_tests.rs"]
mod tests;
