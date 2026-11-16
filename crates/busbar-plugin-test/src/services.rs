// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE SCRIPTED HOST SERVICES (SDK-SAFE-TEST-HOST §3.2: "a safe `impl HostServices` that
//! overrides only what it serves"). Each service a test scripts is one closure; every other one
//! answers what a host that does not back it answers (`Stored::unserved(UNSERVED)`, or the
//! trait's own default), and its name is recorded so a test can assert it was never asked.
//!
//! ```ignore
//! let svc = Arc::new(
//!     Services::new()
//!         .on_now(|| Reading { wall_ns: 1_700_000_000_000_000_000, mono_ns: 7 })
//!         .on_ticket_take(|_caller, _unit| Stored::ready(0)),
//! );
//! let host = Host::new(test_caller_binding()).services(svc.clone());
//! // .. drive the plugin ..
//! assert!(svc.unscripted().is_empty(), "{:?}", svc.unscripted());
//! ```

use std::sync::Mutex;

use busbar_contract::abi::mechanism::ticket::Ticket;
use busbar_contract::services::{
    Caller, DiskDest, HookAsk, HostServices, Later, NestAsk, OutboundAuthorization, Ran, Reading,
    RecordsList, Stored, TrustKeyRef, UNSERVED,
};

/// What an unscripted `clock.now` reads: a fixed instant (2023-11-14T22:13:20Z), one second
/// after the monotonic origin.
pub const CLOCK: Reading = Reading {
    wall_ns: 1_700_000_000_000_000_000,
    mono_ns: 1_000_000_000,
};

fn unserved() -> Stored {
    Stored::unserved(UNSERVED)
}

fn unserved_ran() -> Ran {
    Ran::Now(unserved())
}

// The struct and its `on_*` setters are generated; the `HostServices` impl below is written out,
// because the A3 shape lint (busbar-kernel tests/arch/lints.rs) counts a trait's impls by parsing,
// and an impl a macro writes cannot be counted.
macro_rules! scripted {
    ($($name:ident / $on:ident / $Fn:ident ($($t:ty),*) -> $r:ty;)+) => {
        $(type $Fn = dyn Fn($($t),*) -> $r + Send + Sync;)+

        /// Host services a test scripts one closure at a time; see the module docs.
        #[derive(Default)]
        pub struct Services {
            $($name: Option<Box<$Fn>>,)+
            unscripted: Mutex<Vec<&'static str>>,
        }

        impl Services {
            $(
                #[doc = concat!("Serves `", stringify!($name), "` with `f`.")]
                #[must_use]
                pub fn $on<F>(mut self, f: F) -> Self
                where
                    F: Fn($($t),*) -> $r + Send + Sync + 'static,
                {
                    self.$name = Some(Box::new(f));
                    self
                }
            )+

            fn scripted(&self) -> Vec<&'static str> {
                let mut v = Vec::new();
                $(if self.$name.is_some() { v.push(stringify!($name)); })+
                v
            }
        }
    };
}

scripted! {
    now / on_now / NowFn() -> Reading;
    dest_judge / on_dest_judge / DestJudgeFn(&str, u32, u32, Option<Later>) -> Ran;
    records_get / on_records_get / RecordsGetFn(&Caller, &str, &[u8], Later) -> Ran;
    records_list / on_records_list / RecordsListFn(&Caller, RecordsList, Later) -> Ran;
    records_claim / on_records_claim / RecordsClaimFn(&Caller, &str, &[u8], u64, Later) -> Ran;
    sign / on_sign / SignFn(&Caller, &[u8]) -> Stored;
    trust_sight / on_trust_sight / TrustSightFn(&Caller, &str, &str, Later) -> Ran;
    trust_unreached / on_trust_unreached / TrustUnreachedFn(&Caller, &str) -> Stored;
    trust_sight_item / on_trust_sight_item / TrustSightItemFn(&Caller, &str, &str, &str, Later) -> Ran;
    trust_decide / on_trust_decide / TrustDecideFn(&Caller, Ticket, TrustKeyRef<'_>, Option<&str>, bool, Later) -> Ran;
    trust_state / on_trust_state / TrustStateFn(&Caller, &str) -> Stored;
    trust_serves / on_trust_serves / TrustServesFn(&Caller, &str, Option<&str>, Option<&str>) -> Stored;
    trust_due / on_trust_due / TrustDueFn(&Caller) -> Stored;
    trust_verify / on_trust_verify / TrustVerifyFn(&Caller, &str, &[u8], &[u8]) -> Stored;
    session_emit / on_session_emit / SessionEmitFn(&Caller, u64, &[u8]) -> Stored;
    ticket_mint / on_ticket_mint / TicketMintFn(&Caller, Option<u64>, u64, &[u8], Later) -> Ran;
    outbound_authorize / on_outbound_authorize / OutboundAuthorizeFn(&Caller, Option<u64>, OutboundAuthorization<'_>, Later) -> Ran;
    ticket_take / on_ticket_take / TicketTakeFn(&Caller, Option<u64>) -> Stored;
    random_fill / on_random_fill / RandomFillFn(u64) -> Stored;
    records_secret / on_records_secret / RecordsSecretFn(&str, &str, Later) -> Ran;
    unit_nest / on_unit_nest / UnitNestFn(&Caller, Option<u64>, NestAsk, Later) -> Ran;
    work_open / on_work_open / WorkOpenFn(&Caller, Option<u64>, &str, &[u8], Later) -> Ran;
    work_find / on_work_find / WorkFindFn(&Caller, Option<u64>, &[u8], Later) -> Ran;
    work_status / on_work_status / WorkStatusFn(&Caller, &[u8], Later) -> Ran;
    work_settle / on_work_settle / WorkSettleFn(&Caller, Option<u64>, u64, &[u8], Later) -> Ran;
    work_resume / on_work_resume / WorkResumeFn(&Caller, Option<u64>, u64, Later) -> Ran;
    disk_append / on_disk_append / DiskAppendFn(&DiskDest, Vec<u8>, Later) -> Ran;
    verify_lookup / on_verify_lookup / VerifyLookupFn(&Caller, &[u8], Later) -> Ran;
    verify_store / on_verify_store / VerifyStoreFn(&Caller, &[u8], &[u8], u64) -> Stored;
    content_scan / on_content_scan / ContentScanFn(&Caller, Option<u64>, &[u8], Later) -> Ran;
    hook_call / on_hook_call / HookCallFn(&Caller, Option<u64>, HookAsk, Later) -> Ran;
    snapshot_read / on_snapshot_read / SnapshotReadFn(&Caller, u32, Later) -> Ran;
}

/// Each service runs its scripted closure, or records its name and answers what a host that
/// does not back it answers (the trait default where it has one: `outbound_authorize` and
/// `work_status` refuse).
impl HostServices for Services {
    fn now(&self) -> Reading {
        match &self.now {
            Some(f) => f(),
            None => self.unset("now", CLOCK),
        }
    }

    fn dest_judge(&self, dest: &str, class: u32, flags: u32, later: Option<Later>) -> Ran {
        match &self.dest_judge {
            Some(f) => f(dest, class, flags, later),
            None => self.unset("dest_judge", unserved_ran()),
        }
    }

    fn records_get(&self, caller: &Caller, kind: &str, key: &[u8], later: Later) -> Ran {
        match &self.records_get {
            Some(f) => f(caller, kind, key, later),
            None => self.unset("records_get", unserved_ran()),
        }
    }

    fn records_list(&self, caller: &Caller, list: RecordsList, later: Later) -> Ran {
        match &self.records_list {
            Some(f) => f(caller, list, later),
            None => self.unset("records_list", unserved_ran()),
        }
    }

    fn records_claim(
        &self,
        caller: &Caller,
        kind: &str,
        key: &[u8],
        ttl_ms: u64,
        later: Later,
    ) -> Ran {
        match &self.records_claim {
            Some(f) => f(caller, kind, key, ttl_ms, later),
            None => self.unset("records_claim", unserved_ran()),
        }
    }

    fn sign(&self, caller: &Caller, data: &[u8]) -> Stored {
        match &self.sign {
            Some(f) => f(caller, data),
            None => self.unset("sign", unserved()),
        }
    }

    fn trust_sight(&self, caller: &Caller, counterparty: &str, hash: &str, later: Later) -> Ran {
        match &self.trust_sight {
            Some(f) => f(caller, counterparty, hash, later),
            None => self.unset("trust_sight", unserved_ran()),
        }
    }

    fn trust_unreached(&self, caller: &Caller, counterparty: &str) -> Stored {
        match &self.trust_unreached {
            Some(f) => f(caller, counterparty),
            None => self.unset("trust_unreached", unserved()),
        }
    }

    fn trust_sight_item(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: &str,
        digest: &str,
        later: Later,
    ) -> Ran {
        match &self.trust_sight_item {
            Some(f) => f(caller, counterparty, item, digest, later),
            None => self.unset("trust_sight_item", unserved_ran()),
        }
    }

    fn trust_decide(
        &self,
        caller: &Caller,
        ticket: Ticket,
        key: TrustKeyRef<'_>,
        expected: Option<&str>,
        approve: bool,
        later: Later,
    ) -> Ran {
        match &self.trust_decide {
            Some(f) => f(caller, ticket, key, expected, approve, later),
            None => self.unset("trust_decide", unserved_ran()),
        }
    }

    fn trust_state(&self, caller: &Caller, counterparty: &str) -> Stored {
        match &self.trust_state {
            Some(f) => f(caller, counterparty),
            None => self.unset("trust_state", unserved()),
        }
    }

    fn trust_serves(
        &self,
        caller: &Caller,
        counterparty: &str,
        item: Option<&str>,
        digest: Option<&str>,
    ) -> Stored {
        match &self.trust_serves {
            Some(f) => f(caller, counterparty, item, digest),
            None => self.unset("trust_serves", unserved()),
        }
    }

    fn trust_due(&self, caller: &Caller) -> Stored {
        match &self.trust_due {
            Some(f) => f(caller),
            None => self.unset("trust_due", unserved()),
        }
    }

    fn trust_verify(
        &self,
        caller: &Caller,
        counterparty: &str,
        payload: &[u8],
        signatures: &[u8],
    ) -> Stored {
        match &self.trust_verify {
            Some(f) => f(caller, counterparty, payload, signatures),
            None => self.unset("trust_verify", unserved()),
        }
    }

    fn session_emit(&self, caller: &Caller, session: u64, bytes: &[u8]) -> Stored {
        match &self.session_emit {
            Some(f) => f(caller, session, bytes),
            None => self.unset("session_emit", unserved()),
        }
    }

    fn ticket_mint(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        ttl_secs: u64,
        record: &[u8],
        later: Later,
    ) -> Ran {
        match &self.ticket_mint {
            Some(f) => f(caller, unit, ttl_secs, record, later),
            None => self.unset("ticket_mint", unserved_ran()),
        }
    }

    fn outbound_authorize(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        ask: OutboundAuthorization<'_>,
        later: Later,
    ) -> Ran {
        match &self.outbound_authorize {
            Some(f) => f(caller, unit, ask, later),
            None => self.unset("outbound_authorize", Ran::Now(Stored::refused(UNSERVED))),
        }
    }

    fn ticket_take(&self, caller: &Caller, unit: Option<u64>) -> Stored {
        match &self.ticket_take {
            Some(f) => f(caller, unit),
            None => self.unset("ticket_take", unserved()),
        }
    }

    fn random_fill(&self, len: u64) -> Stored {
        match &self.random_fill {
            Some(f) => f(len),
            None => self.unset("random_fill", unserved()),
        }
    }

    fn records_secret(&self, kind: &str, id: &str, later: Later) -> Ran {
        match &self.records_secret {
            Some(f) => f(kind, id, later),
            None => self.unset("records_secret", unserved_ran()),
        }
    }

    fn unit_nest(&self, caller: &Caller, unit: Option<u64>, ask: NestAsk, later: Later) -> Ran {
        match &self.unit_nest {
            Some(f) => f(caller, unit, ask, later),
            None => self.unset("unit_nest", unserved_ran()),
        }
    }

    fn work_open(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        kind: &str,
        record: &[u8],
        later: Later,
    ) -> Ran {
        match &self.work_open {
            Some(f) => f(caller, unit, kind, record, later),
            None => self.unset("work_open", unserved_ran()),
        }
    }

    fn work_find(&self, caller: &Caller, unit: Option<u64>, reference: &[u8], later: Later) -> Ran {
        match &self.work_find {
            Some(f) => f(caller, unit, reference, later),
            None => self.unset("work_find", unserved_ran()),
        }
    }

    fn work_status(&self, caller: &Caller, reference: &[u8], later: Later) -> Ran {
        match &self.work_status {
            Some(f) => f(caller, reference, later),
            None => self.unset("work_status", Ran::Now(Stored::refused(UNSERVED))),
        }
    }

    fn work_settle(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        handle: u64,
        record: &[u8],
        later: Later,
    ) -> Ran {
        match &self.work_settle {
            Some(f) => f(caller, unit, handle, record, later),
            None => self.unset("work_settle", unserved_ran()),
        }
    }

    fn work_resume(&self, caller: &Caller, unit: Option<u64>, handle: u64, later: Later) -> Ran {
        match &self.work_resume {
            Some(f) => f(caller, unit, handle, later),
            None => self.unset("work_resume", unserved_ran()),
        }
    }

    fn disk_append(&self, dest: &DiskDest, bytes: Vec<u8>, later: Later) -> Ran {
        match &self.disk_append {
            Some(f) => f(dest, bytes, later),
            None => self.unset("disk_append", unserved_ran()),
        }
    }

    fn verify_lookup(&self, caller: &Caller, key: &[u8], later: Later) -> Ran {
        match &self.verify_lookup {
            Some(f) => f(caller, key, later),
            None => self.unset("verify_lookup", unserved_ran()),
        }
    }

    fn verify_store(&self, caller: &Caller, key: &[u8], entry: &[u8], ttl_ms: u64) -> Stored {
        match &self.verify_store {
            Some(f) => f(caller, key, entry, ttl_ms),
            None => self.unset("verify_store", unserved()),
        }
    }

    fn content_scan(
        &self,
        caller: &Caller,
        unit: Option<u64>,
        content: &[u8],
        later: Later,
    ) -> Ran {
        match &self.content_scan {
            Some(f) => f(caller, unit, content, later),
            None => self.unset("content_scan", unserved_ran()),
        }
    }

    fn hook_call(&self, caller: &Caller, unit: Option<u64>, ask: HookAsk, later: Later) -> Ran {
        match &self.hook_call {
            Some(f) => f(caller, unit, ask, later),
            None => self.unset("hook_call", unserved_ran()),
        }
    }

    fn snapshot_read(&self, caller: &Caller, scope: u32, later: Later) -> Ran {
        match &self.snapshot_read {
            Some(f) => f(caller, scope, later),
            None => self.unset("snapshot_read", unserved_ran()),
        }
    }
}

impl Services {
    /// No service scripted: every one answers as a host that does not back it.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The services a plugin asked for that the test did not script, in the order asked
    /// (repeats kept).
    #[must_use]
    pub fn unscripted(&self) -> Vec<&'static str> {
        self.unscripted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Records that `name` was asked unscripted, and gives back `answer`.
    fn unset<T>(&self, name: &'static str, answer: T) -> T {
        self.unscripted
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(name);
        answer
    }
}

impl std::fmt::Debug for Services {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Services")
            .field("scripted", &self.scripted())
            .field("unscripted", &self.unscripted())
            .finish()
    }
}
