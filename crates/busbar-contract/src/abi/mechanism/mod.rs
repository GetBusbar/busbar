// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SHARED MECHANISM (the design's locked plugin ABI: one mechanism, every shape in `abi/`):

pub mod call;
pub mod check;
pub mod decl;
pub mod door;
pub mod endpoint;
pub mod extensions;
/// Negotiated generic read-only host observations through main-call extensions.
pub use crate::abi::sdk::inspection_wire as inspection;
pub mod layout;
pub mod lifecycle;
pub mod observe;
pub mod rendering;
pub mod route;
pub mod ticket;

/// The seven kind WORDS: what a signed manifest's `kind` states, one per [`KindCode`]

pub mod kind {
    /// `abi/store/`.
    pub const STORE: &str = "store";
    /// `abi/secret/`.
    pub const SECRET: &str = "secret";
    /// `abi/auth/`.
    pub const AUTH: &str = "auth";
    /// `abi/hook/`.
    pub const HOOK: &str = "hook";
    /// `abi/export/`.
    pub const EXPORT: &str = "export";
    /// `abi/plane/`.
    pub const PLANE: &str = "plane";
    /// `abi/transport/`.
    pub const TRANSPORT: &str = "transport";
}

/// The mechanism's version, stamped in every [`door::Door`]. v1.5.5 called it `TRANSPORT_VERSION`

pub const MECHANISM_VERSION: u32 = 2;

/// ASCII `"BUSBARPL"`, little-endian: a door's first eight bytes. Deliberately not the retired

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

    /// The word a signed manifest's `kind` states for this kind ([`kind`]).
    #[must_use]
    pub const fn word(self) -> &'static str {
        match self {
            KindCode::Store => kind::STORE,
            KindCode::Secret => kind::SECRET,
            KindCode::Auth => kind::AUTH,
            KindCode::Hook => kind::HOOK,
            KindCode::Export => kind::EXPORT,
            KindCode::Plane => kind::PLANE,
            KindCode::Transport => kind::TRANSPORT,
        }
    }

    /// The ONE version of this kind's ABI the host accepts (no legacy loading: older and newer are

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

    /// The ONE layout fingerprint of this kind's ABI the host accepts ([`layout`]): a door stating

    #[must_use]
    pub const fn layout_fingerprint(self) -> u64 {
        match self {
            KindCode::Store => super::store::LAYOUT_FINGERPRINT,
            KindCode::Secret => super::secret::LAYOUT_FINGERPRINT,
            KindCode::Auth => super::auth::LAYOUT_FINGERPRINT,
            KindCode::Hook => super::hook::LAYOUT_FINGERPRINT,
            KindCode::Export => super::export::LAYOUT_FINGERPRINT,
            KindCode::Plane => super::plane::LAYOUT_FINGERPRINT,
            KindCode::Transport => super::transport::LAYOUT_FINGERPRINT,
        }
    }
}
