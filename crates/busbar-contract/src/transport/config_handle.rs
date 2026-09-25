// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The OPAQUE transport-configuration handle: what a transport is given in place of the key
//! material its session layer needs.
//!
//! #40(b) states the end shape in its own words: *"the kernel reads the secret, audits, builds the
//! … config, and hands the transport plugin an OPAQUE config handle it can use but not
//! disassemble."* #36 puts the provisioning kernel-side for the same reason. Before this type
//! existed, the only way for a transport to receive its built config was to implement a sink trait
//! declared BY the provisioning crate, which put that crate — secret reads, access journaling,
//! certificate parsing — in the transport's dependency closure. The seam is now the
//! contract's: the kernel side builds the config, wraps it here, and hands it to the transport
//! through [`TransportConfigSink`], which the transport implements. Neither end names the other.
//!
//! WHAT "OPAQUE" MEANS HERE, stated rather than implied. The handle carries a slot, a
//! [`ConfigRole`], and a type-erased, shared, immutable config value. It exposes no bytes and no
//! accessor that yields key material: the only way to reach the config is [`config`], which returns
//! the value AS the concrete type the kernel built — a type the transport already links for its own
//! session layer and which itself offers no raw-key accessor. The contract names no such type and
//! takes no dependency to name one, so the handle costs a plugin nothing it did not already carry.
//!
//! [`config`]: TransportConfigHandle::config

use std::any::Any;
use std::sync::Arc;

use crate::plugin::KernelSeal;

/// Which end of a connection a configuration is for: the side that LISTENS and accepts, or the side
/// that DIALS out.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ConfigRole {
    /// The accepting side — presented at `listen`, `accept` and every adoption over a listener.
    Listen = 0,
    /// The dialing side — presented at `dial`.
    Dial = 1,
}

/// An opaque, kernel-built configuration for one transport slot.
///
/// Built only on the kernel side — [`issue`](Self::issue) takes a seal, like
/// [`TransportKeyHandle::issue`](crate::TransportKeyHandle::issue) — and consumed by the transport
/// the configuration is for. `Clone` shares the one immutable value; it never copies material.
/// `Debug` prints the slot and the role and never the configuration.
#[repr(C)]
#[derive(Clone)]
pub struct TransportConfigHandle {
    slot: u64,
    role: ConfigRole,
    config: Arc<dyn Any + Send + Sync>,
}

impl TransportConfigHandle {
    /// Wrap a built configuration for `slot`. Kernel only: the seal is what says so, and a transport
    /// holds no seal.
    #[must_use]
    pub fn issue<C: Any + Send + Sync>(
        _token: &dyn KernelSeal,
        slot: u64,
        role: ConfigRole,
        config: Arc<C>,
    ) -> Self {
        Self {
            slot,
            role,
            config,
        }
    }

    /// The node-local slot this configuration is registered under — the same slot number a
    /// [`TransportKeyHandle`](crate::TransportKeyHandle) for the same material carries.
    #[must_use]
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Which end of a connection this configuration is for.
    #[must_use]
    pub fn role(&self) -> ConfigRole {
        self.role
    }

    /// The configuration, as the concrete type the kernel built it as, or `None` when it was built
    /// as a different type. A shared handle to the one immutable value: nothing is copied, and
    /// nothing here yields the material the configuration was built from.
    #[must_use]
    pub fn config<C: Any + Send + Sync>(&self) -> Option<Arc<C>> {
        Arc::clone(&self.config).downcast::<C>().ok()
    }
}

impl std::fmt::Debug for TransportConfigHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportConfigHandle")
            .field("slot", &self.slot)
            .field("role", &self.role)
            .field("config", &"<opaque>")
            .finish()
    }
}

/// Where the kernel side delivers a built [`TransportConfigHandle`]. A transport whose session layer
/// needs a configuration implements this; the provisioning side calls it once per slot and role, at
/// the moment it has resolved the material and journaled the access.
pub trait TransportConfigSink {
    /// Take the configuration for the handle's slot and role, replacing any earlier one for the same
    /// pair.
    fn register_config(&self, handle: TransportConfigHandle);
}
