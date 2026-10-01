// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SERVE PATH'S ONE PRODUCTION COMPOSITION (ARCHITECT ruling, K1 serve path): where the
//! kernel's host services, the process's one dispatcher and the plane drivers are put together,
//! once per process. Every kind's wiring composes here; nothing else builds a `KernelServices`.
//!
//! THE HOST SERVICES ARRIVE LATE, BY DESIGN. The one dispatcher is built as the process's first act,
//! before any configuration is read (the one-dispatcher boot), while the kernel's services are
//! built from the loaded configuration (the egress rules `dest.judge` applies, among others). So the
//! dispatcher is handed a [`LateServices`]: it answers every service REFUSED, as a dispatcher with
//! no services does, until the composition installs the kernel's services, once, after the
//! configuration loads and before any plugin is bound. No plugin crosses before then in a booted
//! process, so none sees the refusal.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use busbar_contract::services::{HostServices, Later, Ran, Reading, Stored};
use busbar_kernel::config::RootCfg;
use busbar_kernel::host_services::{DestRules, KernelServices, SystemResolver};
use busbar_kernel::net_guard::{Denylist, GuardPolicy};

/// The egress class `dest.judge` applies when a plugin names none: the deployment's own stance.
pub const DEFAULT_EGRESS_CLASS: u32 = 0;

/// The kernel's egress rules for the deployment's default class, from its `security` section: the
/// metadata denylist with the operator's additions, carve-outs and override, as the provider SSRF
/// guard states them. A name named inside content is judged by its host (plaintext admitted, as the
/// host was all that was judged there), and a private address is refused: no class a plugin can
/// name relaxes that without a declared class of its own.
#[must_use]
pub fn default_egress_rules(blocked: &[String], allowed: &[String], allow_all: bool) -> DestRules {
    DestRules {
        policy: GuardPolicy {
            allow_plaintext: true,
            ..GuardPolicy::default()
        },
        denylist: Arc::new(Denylist::new(blocked, allowed, allow_all)),
    }
}

/// The kernel's host services for `cfg`: the default egress class and the system resolver. A class
/// not mapped here is refused.
#[must_use]
pub fn kernel_services(cfg: &RootCfg) -> KernelServices {
    KernelServices::new(
        HashMap::from([(
            DEFAULT_EGRESS_CLASS,
            default_egress_rules(
                &cfg.blocked_metadata_hosts,
                &cfg.allow_metadata_hosts,
                cfg.allow_all_metadata,
            ),
        )]),
        Arc::new(SystemResolver),
    )
}

/// THE COMPOSITION, once the configuration loads: the kernel's host services are installed into
/// the dispatcher's [`LateServices`], before any plugin is bound. A second call (a reload) installs
/// nothing.
pub fn compose(cfg: &RootCfg, late: &LateServices) {
    if late.install(Arc::new(kernel_services(cfg))).is_err() {
        tracing::debug!("the kernel's host services were already installed");
    }
}

/// The kernel's host services, installed once after the configuration loads (see the module doc).
pub struct LateServices {
    installed: OnceLock<Arc<dyn HostServices>>,
    /// The clock before the install: the kernel's own, mapping no egress class.
    clock: KernelServices,
}

impl std::fmt::Debug for LateServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LateServices")
            .field("installed", &self.installed.get().is_some())
            .finish()
    }
}

/// Why [`LateServices::install`] would not take a second set of services.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlreadyInstalled;

/// The reason every service answers before the kernel's are installed.
pub const NOT_INSTALLED: &str = "the kernel's host services are not installed yet";

impl LateServices {
    /// No services yet: every service answers REFUSED.
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new(LateServices {
            installed: OnceLock::new(),
            clock: KernelServices::new(HashMap::new(), Arc::new(SystemResolver)),
        })
    }

    /// Install the kernel's services. Once per process: a second install is refused and changes
    /// nothing, so a reload can never swap the services a running instance reaches.
    pub fn install(&self, services: Arc<dyn HostServices>) -> Result<(), AlreadyInstalled> {
        self.installed.set(services).map_err(|_| AlreadyInstalled)
    }

    /// Whether the kernel's services are installed.
    #[must_use]
    pub fn is_installed(&self) -> bool {
        self.installed.get().is_some()
    }
}

impl HostServices for LateServices {
    /// The kernel's clock once installed. `clock.now` has no refusal to answer, so before the
    /// install it is the kernel's own clock with no egress class, started with this value.
    fn now(&self) -> Reading {
        match self.installed.get() {
            Some(s) => s.now(),
            None => self.clock.now(),
        }
    }

    fn dest_judge(&self, dest: &str, class: u32, resolve: bool, later: Option<Later>) -> Ran {
        match self.installed.get() {
            Some(s) => s.dest_judge(dest, class, resolve, later),
            None => Ran::Now(Stored::refused(NOT_INSTALLED)),
        }
    }
}

#[cfg(test)]
#[path = "tests/serve.rs"]
mod tests;
