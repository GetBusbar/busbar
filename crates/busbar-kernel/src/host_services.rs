// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE HOST SERVICES, AS THE KERNEL SERVES THEM (`BUSBAR-1.6.0.md` THE DESIGN, host services): the
//! implementations behind the `HostSlots` table. The plugin loader owns the mechanism (the result
//! stored per completion handle, the short-buffer re-call and its FAULT, the refusal of a may-pend
//! service called with no ticket); it is handed [`KernelServices`] at construction
//! (the dispatcher's `with_services`) and calls in here at most once per handle.
//!
//! * `clock.now` — the kernel's clock: wall time, and monotonic time from an origin fixed when the
//!   services are built.
//! * `dest.judge` — the ONE destination judge, the egress unit's (through `net_guard`): the
//!   metadata denylist, then the refusals the name decides,
//!   answered at once and before any resolution, as 1.5.5 answered them. Asked to resolve
//!   (`DEST_RESOLVE`), a name is resolved off the caller's thread, the call pends, and the address
//!   judgement decides what it answered; not asked, the name's own judgement is the verdict (the
//!   1.5.5 judgement of a destination named in a request argument, which resolved nothing).
//!
//! THE EGRESS CLASS → RULES MAPPING IS THE KERNEL'S. [`KernelServices::new`] takes it whole: the
//! wiring that builds the table decides, per class, the guard policy and the denylist. To keep 1.5.5's
//! answers, the class a plane names for a request-argument judgement admits plaintext (1.5.5 judged
//! only the host there), and its `allow_private` is the target's own setting.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use busbar_contract::abi::host::service as svc;
use busbar_contract::services::{HostServices, Later, Ran, Reading, Stored};

use crate::net_guard::{
    check_structure, pin_answer, split_url, AddressRefusal, Denylist, GuardPolicy, NetworkRefusal,
    Structure,
};

/// The rules `dest.judge` applies for one egress class.
#[derive(Debug, Clone)]
pub struct DestRules {
    /// The guard policy.
    pub policy: GuardPolicy,
    /// The metadata denylist, with the deployment's additions and carve-outs.
    pub denylist: Arc<Denylist>,
}

/// Where one resolution's answer goes: called once, from any thread. `Err` is a resolution failure,
/// not an empty answer.
pub type Resolved = Box<dyn FnOnce(Result<Vec<IpAddr>, String>) + Send>;

/// A resolver that answers off the caller's thread.
pub trait Resolve: Send + Sync {
    /// Resolve `host`, answering through `done` now or later, on any thread; never blocks the caller.
    fn resolve(&self, host: &str, done: Resolved);
}

/// The system resolver, one short-lived thread per resolution, so a slow name never holds a
/// dispatcher worker.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemResolver;

impl Resolve for SystemResolver {
    fn resolve(&self, host: &str, done: Resolved) {
        let cell = Arc::new(Mutex::new(Some(done)));
        let mine = Arc::clone(&cell);
        let host = host.to_string();
        let spawned = std::thread::Builder::new()
            .name("busbar-resolve".into())
            .spawn(move || {
                let answer = (host.as_str(), 0)
                    .to_socket_addrs()
                    .map(|a| a.map(|s| s.ip()).collect())
                    .map_err(|e| e.to_string());
                if let Some(done) = take(&mine) {
                    done(answer);
                }
            });
        if spawned.is_err() {
            if let Some(done) = take(&cell) {
                done(Err("no resolver thread".into()));
            }
        }
    }
}

fn take(cell: &Mutex<Option<Resolved>>) -> Option<Resolved> {
    cell.lock().unwrap_or_else(|e| e.into_inner()).take()
}

/// THE KERNEL'S HOST SERVICES.
pub struct KernelServices {
    origin: Instant,
    classes: HashMap<u32, DestRules>,
    resolver: Arc<dyn Resolve>,
}

impl std::fmt::Debug for KernelServices {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelServices")
            .field("classes", &self.classes.len())
            .finish_non_exhaustive()
    }
}

impl KernelServices {
    /// The services over `classes` (egress class → rules; a class not listed is refused) and
    /// `resolver`.
    #[must_use]
    pub fn new(classes: HashMap<u32, DestRules>, resolver: Arc<dyn Resolve>) -> Self {
        Self {
            origin: Instant::now(),
            classes,
            resolver,
        }
    }
}

impl HostServices for KernelServices {
    fn now(&self) -> Reading {
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| u64::try_from(d.as_nanos()).unwrap_or(u64::MAX));
        Reading {
            wall_ns: wall,
            mono_ns: u64::try_from(self.origin.elapsed().as_nanos()).unwrap_or(u64::MAX),
        }
    }

    fn dest_judge(&self, dest: &str, class: u32, resolve: bool, later: Option<Later>) -> Ran {
        let Some(rules) = self.classes.get(&class) else {
            return Ran::Now(Stored::refused("no such egress class"));
        };
        match check_structure(dest, &[], rules.policy, &rules.denylist) {
            Err(r) => return Ran::Now(Stored::ready(verdict(dest, &r))),
            Ok(Structure::Name { .. }) if resolve => {}
            Ok(_) => return Ran::Now(Stored::ready(svc::DEST_ALLOWED)),
        }
        let Some(later) = later else {
            return Ran::Now(Stored::refused(
                "a service that may pend is callable only inside a ticketed op",
            ));
        };
        // The one judge; the verdict is its answer with the pinned address dropped.
        let answer =
            |v: Result<SocketAddr, u64>| Stored::ready(v.map_or_else(|v| v, |_| svc::DEST_ALLOWED));
        match self.judge_dial(dest, class, Box::new(move |v| later(answer(v)))) {
            Some(v) => Ran::Now(answer(v)),
            None => Ran::Later,
        }
    }
}

/// Where a dial's judgement goes when it pended: the pinned address, or the `DEST_*` verdict that
/// refused it. Called once, from any thread.
pub type Judged = Box<dyn FnOnce(Result<SocketAddr, u64>) + Send>;

impl KernelServices {
    /// THE ONE JUDGE, for a dial: `dest` against egress class `class`'s rules, and the address to
    /// dial — exactly the one the judgement pinned, so nothing resolves the name a second time. A
    /// refusal the name decides, and an IP literal, answer at once (`Some`) before any resolution;
    /// a name is resolved off the caller's thread and `done` gets the pin or the refusal (`None`).
    /// `dest.judge` is this judgement with the address dropped. An unknown class is refused as
    /// naming no usable host.
    pub fn judge_dial(
        &self,
        dest: &str,
        class: u32,
        done: Judged,
    ) -> Option<Result<SocketAddr, u64>> {
        let Some(rules) = self.classes.get(&class) else {
            return Some(Err(svc::DEST_NO_HOST));
        };
        let (host, port, https) = match check_structure(dest, &[], rules.policy, &rules.denylist) {
            Err(r) => return Some(Err(verdict(dest, &r))),
            Ok(Structure::Pinned(p)) => return Some(Ok(p.socket_addr())),
            Ok(Structure::Name { host, port, https }) => (host, port, https),
        };
        let policy = rules.policy;
        let name = host.clone();
        self.resolver.resolve(
            &name,
            Box::new(move |answer| {
                done(match answer {
                    Err(_) => Err(svc::DEST_UNRESOLVABLE),
                    Ok(addrs) => pin_answer(&host, port, https, &addrs, policy)
                        .map(|p| p.socket_addr())
                        .map_err(|r| guard_verdict(&r)),
                });
            }),
        );
        None
    }
}

/// The verdict a refusal answers. A destination naming a scheme the web schemes do not cover reads
/// as a bare authority to the one judge and is refused for its host; its verdict names the scheme,
/// as the refusal it is.
fn verdict(dest: &str, r: &NetworkRefusal) -> u64 {
    let foreign_scheme =
        dest.contains("://") && matches!(split_url(dest), Err(AddressRefusal::Scheme { .. }));
    match r {
        NetworkRefusal::Guard(AddressRefusal::NoHost(_)) if foreign_scheme => svc::DEST_SCHEME,
        NetworkRefusal::MetadataDenied(_) => svc::DEST_METADATA,
        NetworkRefusal::Guard(g) => guard_verdict(g),
        NetworkRefusal::NotAnUpstream => svc::DEST_NO_HOST,
    }
}

fn guard_verdict(r: &AddressRefusal) -> u64 {
    match r {
        AddressRefusal::Scheme { .. } => svc::DEST_SCHEME,
        AddressRefusal::Plaintext { .. } => svc::DEST_PLAINTEXT,
        AddressRefusal::ObfuscatedHost(_) => svc::DEST_OBFUSCATED,
        AddressRefusal::MetadataName(_) | AddressRefusal::CloudMetadataAddress { .. } => {
            svc::DEST_METADATA
        }
        AddressRefusal::LoopbackName(_) | AddressRefusal::InternalAddress { .. } => {
            svc::DEST_INTERNAL
        }
        AddressRefusal::Unresolvable { .. } => svc::DEST_UNRESOLVABLE,
        AddressRefusal::NoAddresses(_) => svc::DEST_NO_ADDRESSES,
        _ => svc::DEST_NO_HOST,
    }
}

#[cfg(test)]
#[path = "tests/host_services_tests.rs"]
mod tests;
