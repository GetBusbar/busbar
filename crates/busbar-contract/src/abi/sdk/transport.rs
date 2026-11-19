// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TRANSPORT SDK: what every transport door wrote alike, stated once.

use crate::abi::mechanism::call::AbiStr;
use crate::abi::sdk::io::Io;
use crate::abi::sdk::life::{Held, Life, Refusal};
use crate::abi::sdk::safe::Instance;
use crate::abi::shared::code;
use crate::abi::transport::SettingDecl;
use crate::grammar::SelectorForm;
use crate::transport::DEFAULT_REQUEST_BODY_MAX_BYTES;

pub mod policy;
pub mod receive;
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

const _: () = assert!(decimal(DEFAULT_BODY_MAX) == DEFAULT_REQUEST_BODY_MAX_BYTES);

/// One setting a transport reads: the ONE source of its Statement's [`SettingDecl`]
/// ([`SettingRow::decl`], [`setting_decls`]) and of what [`settings_reading`] accepts for it. Its
/// strings are `'static` Rust strings, so the SDK reads them safely (a [`SettingDecl`]'s are raw
/// pointers, read only on the plugin's word).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingRow {
    /// The setting's config path, the key its value has in the settings object.
    pub path: &'static str,
    /// `SETTING_*`: what a value of it must be.
    pub kind: u32,
    /// Its default, as text.
    pub default: &'static str,
}

impl SettingRow {
    /// The row as its Statement declares it.
    #[must_use]
    pub const fn decl(&self) -> SettingDecl {
        SettingDecl {
            path: AbiStr::of(self.path),
            kind: self.kind,
            default: AbiStr::of(self.default),
            ..SettingDecl::ZERO
        }
    }
}

/// `rows` as the Statement's setting declarations, in order.
#[must_use]
pub const fn setting_decls<const N: usize>(rows: &[SettingRow; N]) -> [SettingDecl; N] {
    let mut out = [SettingDecl::ZERO; N];
    let mut i = 0;
    while i < N {
        out[i] = rows[i].decl();
        i += 1;
    }
    out
}

/// A transport's `settings` read against its rows, at configure time ([`super::settings`]).
pub use super::settings::settings_reading;

/// Carrier op `$op`'s open instance and the host's armed I/O for it on the op's ticket, e.g.
/// `carried!(i, "flush")`; its refusals are static words, which reach the caller even from a call
/// on no instance (there is no reason buffer to keep an owned text in).
///
/// FAILED: `<op>: no open instance`, or `<op>: the host lent this carrier no I/O`.
#[macro_export]
macro_rules! carried {
    ($i:expr, $op:literal) => {
        $crate::abi::sdk::transport::carried_saying(
            &$i,
            concat!($op, ": no open instance"),
            concat!($op, ": the host lent this carrier no I/O"),
        )
    };
}

/// [`carried!`](crate::carried)'s body: the instance and its armed I/O, or FAILED saying
pub fn carried_saying<'a, L: Life<Kind = crate::plugin::markers::TransportKind>>(
    i: &Instance<'a, Held<L>, crate::plugin::markers::TransportKind>,
    no_instance: &'static str,
    no_io: &'static str,
) -> Result<(&'a L, Io<'a>), Refusal> {
    let held = i.get().ok_or_else(|| Refusal::failed(no_instance))?;
    let io = held
        .host()
        .map(|h| h.io(i.ticket()))
        .filter(Io::armed)
        .ok_or_else(|| Refusal::failed(no_io))?;
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
            type Kind = $crate::plugin::markers::TransportKind;
            type In = $in;
            type Out = $out;
            type State = $state;
            fn call(
                _: $crate::abi::sdk::Instance<'_, $state, $crate::plugin::markers::TransportKind>,
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

