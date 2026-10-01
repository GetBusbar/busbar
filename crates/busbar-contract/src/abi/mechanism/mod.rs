// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHARED MECHANISM (the design's locked plugin ABI: one mechanism, every shape in `abi/`):
//! the one door, the one call shape, the one lifecycle, tickets, completion handles, deadline
//! classes, the extensions blob and the #85 envelope. Every one of the seven kinds rides this; a kind adds only its own operations, its own
//! data shapes and its own version number (`abi/<kind>/`).
//!
//! * [`door`] — the ONE exported symbol [`DOOR_SYMBOL`] returns a [`door::Door`]: magic
//!   [`DOOR_MAGIC`], [`MECHANISM_VERSION`], the kind, the kind's ABI version, a
//!   [`door::Statement`] and the kind's ops table. A compiled-in plugin is a row holding the same
//!   [`door::DoorFn`]; the kernel calls both through the same table.
//! * [`call`] — the ONE call shape [`call::Op`]: `op(instance, in, out)` answering READY, PENDING,
//!   FAILED, REFUSED or FAULT. `extern "C"`, never `"C-unwind"`: a panic that escapes a slot aborts.
//! * [`lifecycle`] — the slot set every kind's table leads with: validate, open, refresh, retire,
//!   tick, drive, cancel, release, close. There is no poll slot: after a wake the host re-invokes the
//!   same op with [`call::FLAG_RESUME`] and the same ticket.
//! * [`ticket`] — tickets `(slot, generation)` with latched, spurious-tolerant wakes, completion
//!   handles `(ticket, seq)`, and the host's `wake`.
//!
//! MEMORY, FOUR CLASSES (the design: plugin-owned memory is valid to its next refresh generation):
//! (i) REQUEST-PATH RESULTS go into HOST-owned buffers the kind's `in`/`out` names as pointer +
//! capacity; the plugin writes at most the capacity and never hands back a pointer for a result.
//! (ii) GENERATION DATA — only data a plugin PUBLISHES at `open`/`refresh` — stays valid until
//! `retire` of that generation. The Door and the Statement (the Door points to it) are `'static`.
//! (iii) PER-CALL `OutHead.error` and the `Envelope` arrays stay valid until the NEXT op on the same
//! ticket. On [`Ticket::NONE`](ticket::Ticket::NONE) they are valid only until the op returns: the
//! host copies them before it makes any other call on that thread. A FAILED `open` or `validate` has
//! no instance to hold its reason, so it writes it into the host's lent reason buffer instead
//! ([`lifecycle::OpenIn::err_buf`], [`lifecycle::ValidateIn::err_buf`]; the same for every kind; an
//! `open` states the length in [`lifecycle::OpenOut::err_len`], a `validate` names the bytes in
//! `head.error`).
//! (iv) OFF-PATH LISTS AND SECRETS are held under a lease until `release(lease)`.
//! SIZES: the plugin writes at most `min(out.size, its own size of the struct)` bytes of an `out`,
//! never reads an `in` beyond `in.size`, and reads an absent tail field as zero.
//! FIXED ELEMENTS: the element layouts of [`call::MetricEntry`], [`call::Diag`],
//! [`door::MetricFamily`] and [`call::AbiStr`] are fixed by [`MECHANISM_VERSION`]; arrays of them
//! carry no stride, so growing one is a mechanism bump.
//!
//! This module states the shapes and their numbers; the one dispatcher
//! (`busbar-plugin-loader`'s `dispatch`) calls every kind through them.

pub mod call;
pub mod check;
pub mod door;
pub mod lifecycle;
pub mod rendering;
pub mod route;
pub mod ticket;

/// The mechanism's version, stamped in every [`door::Door`]. v1.5.5 called it `TRANSPORT_VERSION`
/// and shipped `1`; 1.6.0 ships `2` (the locked plugin ABI: every ABI is its v1.5.5 value + 1).
pub const MECHANISM_VERSION: u32 = 2;

/// ASCII `"BUSBARPL"`, little-endian: a door's first eight bytes. Deliberately not the retired
/// `"BUSPLANE"`, so a pre-1.6.0 artifact can never be read as a door.
pub const DOOR_MAGIC: u64 = u64::from_le_bytes(*b"BUSBARPL");

/// The ONE symbol a plugin exports, NUL-terminated for `dlsym`.
pub const DOOR_SYMBOL: &[u8] = b"busbar_plugin_door\0";

/// The seven kinds, as the number a [`door::Door`] carries in `kind`. Read off the wire with
/// [`KindCode::from_raw`]: an unknown number is a refused load, never a guess.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KindCode {
    /// `abi/store/`.
    Store = 1,
    /// `abi/secret/`.
    Secret = 2,
    /// `abi/auth/`.
    Auth = 3,
    /// `abi/hook/`.
    Hook = 4,
    /// `abi/export/`.
    Export = 5,
    /// `abi/plane/`.
    Plane = 6,
    /// `abi/transport/`.
    Transport = 7,
}

impl KindCode {
    /// Every kind, in code order.
    pub const ALL: [KindCode; 7] = [
        KindCode::Store,
        KindCode::Secret,
        KindCode::Auth,
        KindCode::Hook,
        KindCode::Export,
        KindCode::Plane,
        KindCode::Transport,
    ];

    /// The kind a door's `kind` names, or `None` for a number no kind has.
    #[must_use]
    pub const fn from_raw(raw: u32) -> Option<KindCode> {
        match raw {
            1 => Some(KindCode::Store),
            2 => Some(KindCode::Secret),
            3 => Some(KindCode::Auth),
            4 => Some(KindCode::Hook),
            5 => Some(KindCode::Export),
            6 => Some(KindCode::Plane),
            7 => Some(KindCode::Transport),
            _ => None,
        }
    }

    /// The ONE version of this kind's ABI the host accepts (no legacy loading: older and newer are
    /// both refused).
    #[must_use]
    pub const fn abi_version(self) -> u32 {
        match self {
            KindCode::Store => super::store::ABI_VERSION,
            KindCode::Secret => super::secret::ABI_VERSION,
            KindCode::Auth => super::auth::ABI_VERSION,
            KindCode::Hook => super::hook::ABI_VERSION,
            KindCode::Export => super::export::ABI_VERSION,
            KindCode::Plane => super::plane::ABI_VERSION,
            KindCode::Transport => super::transport::ABI_VERSION,
        }
    }
}
