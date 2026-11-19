// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Plugin images, the host-side `Instance` and the Need step driver (IF §10.4 generic part, §10.3 decode table,
//! §10.5; W1-H1).
//!
//! UNSAFE-MIN r3.1 (owner-approved, later than the IF) moved every raw entry, the chain token and the
//! instance pointer into busbar-ffi: `Instance<K>`, `Chain<'i, K>` (resumed only under `&mut`, cancelled by its
//! Drop while its token is live) and `OutLease`. So here `ChainGuard` wraps a busbar-ffi `Chain` instead of
//! holding `tok`, `vt_resume`, `vt_cancel` and a `ChainOwner` (the IF §10.5 fields), and keeps the rest of the
//! §10.5 rule exactly: the chain token lives only inside the guard, every step runs inline in the driver's
//! poll, and Drop is (1) cancel inline under the caller's entry/watch scope while the future is parked,
//! (2) `Needs::release` iff the chain made a NEED, (3) the pooled buffers zero themselves and go back.
//!
//! The decode table (§10.3) is `decode_need`: a Need that breaks a row is answered INVALID with no handler run;
//! an op outside the chain's `NeedRow` is FAULT NeedNotAllowed for the whole chain (§6.1 "Allowed Needs").

use core::any::Any;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use busbar_ffi::Kind;
use busbar_ffi::host::{Chain, Instance as LiveInstance, OpenAnswer, OutLease, Resumed, Started};
use zerocopy::FromBytes;

use crate::fail::{CallError, FaultReason};
use crate::host_side::answer::OwnedAnswer;
use crate::host_side::caller::{Caller, InstanceLimits, next_chain};
use crate::host_side::needs::{
    ConnId, DirNeed, FetchNeed, NeedErr, NeedOut, Needs, OpenNeed, RES_FIXED, RecordNeed, TlsMode,
    status_of,
};
use crate::host_side::pool::{ChainBufs, Pool, PooledOut};
use crate::host_side::scrub::Scrub;
use crate::host_side::watch::{self, ENTRY_CANCEL, ENTRY_RESUME};
use crate::need::{NeedRec, dir, egress, need_flag, need_status, op};
use crate::records::{RecDelRec, RecErr, RecPredRec, RecPutRec, Records, TokenRec, commit, tag};
use crate::types::{KindCode, Status, Token};

/// One mapped plugin image. `Linked` = compiled into the binary (never unmapped). `Loaded` owns the dl handle,
/// the staged memfd/temp file and the mapped segments, and is **resident** (I13): it is never `dlclose`d. Its
/// last `Arc` is held by the loader's process-wide image table (`instance.rs`: a cold `Mutex<HashMap<[u8; 32],
/// Arc<Image>>>` touched only by admit, keyed by image SHA-256, so re-admitting identical bytes on a
/// reconfigure or an upgrade-and-back reuses the mapping instead of loading it again); when the last instance of
/// an image goes away the table keeps the handle, and stage.rs retains its memfd (origin/dev `retire_memfd`,
/// stage.rs:520), so its name is never recycled. Cost: one mapping per distinct image admitted during the
/// process's life (gauge `plugin_images_resident`, bytes in `plugin_images_resident_bytes`); a restart reclaims it.
pub enum Image {
    Linked,
    Loaded(LoadedImage),
}

// IF §11.1: the loaded-image payload of `Image::Loaded`.
// W1-L1 (loader admit) fills the fields the W0 stub assigned to it. UNSAFE-MIN r3.1 moved the dl handle and the
// H4 segment check into busbar-ffi (`image::Opened::open` checks the header against the image's segments,
// `Opened::admit` leaks the library, so it is never unloaded), so what the image keeps here is its SHA-256 and
// the loader's stage.rs `Staged` (the sealed memfd or the pinned temp file), held for the life of the process.
pub struct LoadedImage {
    sha256: [u8; 32],
    _staged: Box<dyn core::any::Any + Send + Sync>,
}
impl LoadedImage {
    /// A dropped-in image admit loaded: its SHA-256 and the staged handle its mapping came from.
    pub fn new(sha256: [u8; 32], staged: Box<dyn core::any::Any + Send + Sync>) -> Self {
        LoadedImage {
            sha256,
            _staged: staged,
        }
    }
    /// The SHA-256 of the image's bytes (the key of the loader's resident image table).
    pub fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }
}

/// Round 14: one slot's state word and ceiling row (IF §11.2 `SlotCell`), the watchdog's whole view of an owner.
/// `state` is `(epoch << 32) | st`: the registry's `alloc` bumps the epoch and stores LIVE; quarantine is a CAS from
/// `(epoch, LIVE)`; `is_live` is one Acquire load. `ceilings_us` is the §10.6 row, written by `alloc` (Relaxed,
/// before any lease exists) and read by `watch::scan`. The registry owns the table of cells and hands each
/// instance an `Arc` of its own; this crate owns the cell type because `Instance` (here) reaches it and the
/// loader depends on this crate, not the other way round.
pub struct SlotCell {
    state: AtomicU64,
    ceilings_us: [AtomicU32; 64],
}
impl SlotCell {
    /// st: the slot is serving.
    pub const LIVE: u64 = 0;
    /// st: the watchdog (or the entry guard's FAULT path) took the slot out of service.
    pub const QUARANTINED: u64 = 1;
    /// st: the lease is being released.
    pub const CLOSING: u64 = 2;

    /// A cell in `epoch`, LIVE, with `ceilings` as its row (what `alloc` writes).
    pub fn new(epoch: u32, ceilings: &[u32; 64]) -> SlotCell {
        SlotCell {
            state: AtomicU64::new((u64::from(epoch) << 32) | Self::LIVE),
            ceilings_us: core::array::from_fn(|i| {
                AtomicU32::new(ceilings.get(i).copied().unwrap_or(0))
            }),
        }
    }
    /// `(epoch, LIVE)` is the state word (one Acquire load).
    pub fn is_live(&self, epoch: u32) -> bool {
        self.state.load(Ordering::Acquire) == ((u64::from(epoch) << 32) | Self::LIVE)
    }
    /// CAS `(epoch, LIVE)` to `(epoch, QUARANTINED)`; true when this call made the change. A slot already
    /// quarantined, closing, or re-allocated to a later epoch is left alone.
    pub fn quarantine(&self, epoch: u32) -> bool {
        let live = (u64::from(epoch) << 32) | Self::LIVE;
        self.state
            .compare_exchange(
                live,
                (u64::from(epoch) << 32) | Self::QUARANTINED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
    /// The slot's current epoch (Acquire).
    pub fn epoch(&self) -> u32 {
        (self.state.load(Ordering::Acquire) >> 32) as u32
    }
    /// The §10.6 row.
    pub fn ceilings_us(&self) -> &[AtomicU32; 64] {
        &self.ceilings_us
    }
}

/// What the registry knows about an instance it is about to build (everything but the live plugin instance).
pub struct InstanceParts {
    /// The image the instance runs in; kept mapped until the instance is gone.
    pub image: Arc<Image>,
    pub identity: Arc<str>,
    pub name: Arc<str>,
    pub id: u64,
    /// Watchdog slot (index into the registry's slot table, < 2^24) and the slot's cell and epoch.
    pub slot: u32,
    pub cell: Arc<SlotCell>,
    pub epoch: u32,
    pub limits: InstanceLimits,
    pub max_out: usize,
    pub methods: u64,
    pub facts: u64,
    pub scrub: Arc<Scrub>,
    /// What the registry keeps alive exactly as long as the instance (its slot lease and its config binding):
    /// dropped after the instance has closed and released its image, so the slot is released only after the last
    /// entry that can log under it has returned (IF §10.4, §11.2).
    pub tether: Box<dyn Any + Send + Sync>,
}

/// One live plugin instance as the host holds it (IF §10.4): kind-erased, shared by an `Arc` with every proxy and
/// session handle. UNSAFE-MIN r3.1 moved the instance pointer, the kind table and `close` into busbar-ffi's
/// `Instance<K>` (`Drop` is the only `close`), so this holds that value, erased, and the kind modules' proxies
/// take it back by marker. Field order is drop order: the live instance (which runs `close`) goes before the image
/// that keeps its code mapped, and the slot's cell after both.
pub struct Instance {
    live: Arc<dyn Any + Send + Sync>,
    image: Arc<Image>,
    cell: Arc<SlotCell>,
    epoch: u32,
    pub kind: KindCode,
    /// The verified stamp name.
    pub identity: Arc<str>,
    /// The configured instance name (§10.3 `Caller::name`).
    pub name: Arc<str>,
    pub id: u64,
    /// Watchdog slot (index into the registry's slot table, < 2^24).
    pub slot: u32,
    /// Round 8 (§12.22), copied into every `Caller`.
    pub limits: InstanceLimits,
    pub max_out: usize,
    pub methods: u64,
    pub facts: u64,
    /// This instance's scrub set (§12.16), filled by custody as it resolves secrets for it.
    pub scrub: Arc<Scrub>,
    /// See `InstanceParts::tether`; the last field, so the last to drop.
    _tether: Box<dyn Any + Send + Sync>,
}
impl Instance {
    /// Built by the registry in the same poll that read the INSTANCE record of an `open` answer (§10.4), from
    /// busbar-ffi's `Instance<K>` of that answer. The kind comes from `K`, never from the caller.
    pub fn new<K: Kind>(parts: InstanceParts, live: LiveInstance<K>) -> Arc<Instance> {
        let InstanceParts {
            image,
            identity,
            name,
            id,
            slot,
            cell,
            epoch,
            limits,
            max_out,
            methods,
            facts,
            scrub,
            tether,
        } = parts;
        Arc::new(Instance {
            live: Arc::new(live),
            image,
            cell,
            epoch,
            kind: K::CODE,
            identity,
            name,
            id,
            slot,
            limits,
            max_out,
            methods,
            facts,
            scrub,
            _tether: tether,
        })
    }
    /// The live instance of kind `K`, shared; None when this instance is another kind. The proxies of kind `K`
    /// are the only callers.
    pub fn live<K: Kind>(&self) -> Option<Arc<LiveInstance<K>>> {
        Arc::clone(&self.live).downcast::<LiveInstance<K>>().ok()
    }
    /// One Acquire load of the slot's state word (LIVE in this lease's epoch).
    pub fn is_live(&self) -> bool {
        self.cell.is_live(self.epoch)
    }
    /// Charges this instance for a contract break the host found in one of its answers (§8.6 once rules): the FAULT
    /// sink's instance-owned arm (quarantine, audit `plugin_fault`), exactly as a break the decode finds. Returns
    /// the call error a caller may hand back.
    pub fn charge(&self, reason: FaultReason) -> CallError {
        report_fault(self.slot, false, reason)
    }
    /// CAS (epoch, LIVE) → (epoch, QUARANTINED) on the slot's state word; the watchdog's `SlotTable::hung` and the
    /// entry guard's FAULT path both land here.
    pub fn quarantine(&self) {
        self.cell.quarantine(self.epoch);
    }
    /// The slot's ceiling row (µs; index = kind method bit 0..=55 or ENTRY_*, §10.6).
    pub fn ceilings_us(&self) -> &[AtomicU32; 64] {
        self.cell.ceilings_us()
    }
    pub fn image(&self) -> &Arc<Image> {
        &self.image
    }
}

impl Drop for Instance {
    /// I10 (d), C-CLOSE-LOG: `close` (busbar-ffi's `Drop for Instance<K>`, run when the last `Arc` of the live
    /// instance goes, normally this one) runs inline under the entry guard as this instance's slot and
    /// `ENTRY_CLOSE`, so a line the plugin logs from `close` is attributed to the closing instance and scrubbed
    /// with its own set, and the close is watched. Close has no answer; the lent buffer only satisfies the guard.
    /// The slot lease (`_tether`, the last field) drops after this body, so after the close has returned. With
    /// busbar-ffi's ACTIVE stack full the guard runs nothing and the instance closes unguarded right after.
    fn drop(&mut self) {
        let _migration = crate::host_side::entry::MigrationScope::deny();
        let closed: Arc<dyn Any + Send + Sync> = Arc::new(());
        let mut live = Some(core::mem::replace(&mut self.live, closed));
        let mut out = Pool::global().acquire(self.max_out);
        let _ = crate::host_side::entry::guard(
            self.slot,
            crate::host_side::watch::ENTRY_CLOSE,
            &mut out,
            |_| drop(live.take()),
        );
        drop(live);
    }
}

/// Round 14: built by the adapter per async call (plain stores: `Caller<'a>` is Copy and borrows, §10.3) and
/// borrowed by the proxy future for its whole life (round 15: `drv: &'a mut Driver<'a, N>`, §10.4, exclusive, so
/// no second chain can borrow it); the `ChainGuard` reborrows `&drv.caller` shared, so no field is moved or
/// cloned out of it.
/// **Round 15: one Driver is one chain.** Fields are private and `Driver::new` is the only constructor, so every
/// Driver carries a fresh `caller.chain` (§10.3 `next_chain`), and the proxy methods take `&'a mut Driver`
/// (§10.4), so the borrow checker refuses two concurrent futures on one Driver (two live chains can never share
/// a chain id). The adapter builds one per async call, on its stack or in its port future.
pub struct Driver<'a, N: Needs> {
    needs: &'a N,
    caller: Caller<'a>,
    max_steps: u32,
    row: NeedRow,
    /// An `open` chain: Image-owned (no Instance yet), so a FAULT is audited and refuses, never quarantines.
    open: bool,
    store_migration: Option<Arc<crate::host_side::entry::StoreMigrationAdmission>>,
}
impl<'a, N: Needs> Driver<'a, N> {
    /// Sets `caller.chain = next_chain()` (whatever the adapter wrote is overwritten); `max_steps` = 10,000.
    ///
    /// W1-H1: the Need row is the kind's (§6.1), without DIRECTORY; `for_open` and `with_row` change it.
    pub fn new(needs: &'a N, caller: Caller<'a>) -> Self {
        let mut caller = caller;
        caller.chain = next_chain();
        Driver {
            needs,
            caller,
            max_steps: 10_000,
            row: NeedRow::of(caller.kind, false),
            open: false,
            store_migration: None,
        }
    }
    /// Override the step cap (tests, Image-owned chains); never touches `chain`.
    pub fn with_max_steps(self, max_steps: u32) -> Self {
        Driver { max_steps, ..self }
    }
    pub fn caller(&self) -> &Caller<'a> {
        &self.caller
    }
    /// Authority belongs only to this ordinary Store-open chain, never a serving call.
    pub fn with_store_migration(
        mut self,
        admission: Arc<crate::host_side::entry::StoreMigrationAdmission>,
    ) -> Self {
        if self.open && self.caller.kind == KindCode::Store {
            self.store_migration = Some(admission);
        }
        self
    }
    /// W1-H1: this Driver runs an `open` chain (Image-owned, §10.5 `ChainOwner::Image`): the kind's open row
    /// (§6.1: transport may SECRET in `open` only), and a FAULT is audited and refuses the instance-to-be
    /// instead of quarantining an Instance.
    pub fn for_open(self) -> Self {
        Driver {
            row: NeedRow::of(self.caller.kind, true),
            open: true,
            ..self
        }
    }
    /// W1-H1: replaces the Need row: `NeedRow::EMPTY` for an `F_BLOCKING_FILE` store (§11.3 store lane),
    /// `row.with_directory()` for the `serve`/`refresh` chains of an `FB_PROVISION` auth image (§8.3).
    pub fn with_row(self, row: NeedRow) -> Self {
        Driver { row, ..self }
    }

    /// The step loop (§10.5), one future, no box. `entry` is the first step's watchdog index (the method bit,
    /// or `ENTRY_OPEN`); `req` is the request buffer the caller filled (it becomes `ChainBufs::req` and lives
    /// until the chain ends); `start` makes the first step on the lent out buffer (busbar-ffi's
    /// `Instance::startN` or `Admitted::open`) and may copy `req` into the chain's argument buffers.
    ///
    /// Every step runs inline in this poll, inside the watchdog word; the NEED records are read in place and run
    /// in order through `Needs` (the chain's only awaits; the first failure makes the rest SKIPPED), their
    /// results framed into `ChainBufs::results`, then the chain resumes on the other out buffer. A terminal
    /// OK/REFUSED/FAILED answer is validated (`OwnedAnswer::new`) and returned with, for an `open` chain, the
    /// Instance its INSTANCE record named. FAULT, a broken NEED answer (no or a foreign TOKEN, a tag that is not
    /// NEED or TOKEN, 0 or more than 64 NEEDs) and a Need outside the row are `Err(Fault)`, reported to the fault
    /// sink; the step cap is `Err(Steps)`, the deadline `Err(Deadline)`, and dropping the future mid-chain
    /// cancels it (the guard's Drop). Every chain that made a NEED is released exactly once, however it ended.
    pub async fn run<'i, K, F>(
        &mut self,
        entry: u8,
        max_out: usize,
        req: PooledOut,
        start: F,
    ) -> Result<Finished<K>, CallError>
    where
        K: Kind,
        F: FnOnce(&mut PooledOut, &mut OutLease) -> First<'i, K> + Send,
    {
        let caller = &self.caller;
        let mut guard: ChainGuard<'_, 'i, N, K> = ChainGuard {
            chain: None,
            needs: self.needs,
            caller,
            image_owned: self.open,
            needed: false,
            bufs: ChainBufs {
                req,
                out: [Pool::global().acquire(max_out), PooledOut::default()],
                results: PooledOut::default(),
            },
        };
        let first = {
            let ChainBufs { req, out, .. } = &mut guard.bufs;
            step(
                caller.slot,
                entry,
                self.store_migration.as_ref(),
                &mut out[0],
                |lease| start(req, lease),
            )
        };
        let (mut status, mut instance) = match first {
            None => return Err(CallError::Fault(FaultReason::BadInstance)),
            Some(First::Done(status, instance)) => (status, instance),
            Some(First::Need(chain)) => {
                guard.chain = Some(chain);
                (Status::NEED, None)
            }
        };
        let mut cur = 0usize;
        let mut steps = 0u32;
        while status == Status::NEED {
            steps += 1;
            if steps > self.max_steps {
                return Err(CallError::Steps);
            }
            if Instant::now() > caller.deadline {
                return Err(CallError::Deadline);
            }
            let tok = guard.chain.as_ref().map_or(0, Chain::token);
            let count = match check_need_answer(guard.bufs.out[cur].bytes(), tok, self.row) {
                Ok(count) => count,
                Err(reason) => {
                    guard.cancel();
                    return Err(self.fault(reason));
                }
            };
            guard.needed = true;
            guard.bufs.on_need(max_out);
            {
                let ChainBufs { out, results, .. } = &mut guard.bufs;
                if let Err(reason) = run_needs(
                    self.needs,
                    caller,
                    out[cur].bytes(),
                    results,
                    count,
                    max_out,
                )
                .await
                {
                    guard.cancel();
                    return Err(self.fault(reason));
                }
            }
            let next = 1 - cur;
            let resumed = {
                let results = guard.bufs.results.bytes().to_vec();
                resume_tap(caller.slot, &results);
                let Some(chain) = guard.chain.as_mut() else {
                    return Err(self.fault(FaultReason::MissingToken));
                };
                step(
                    caller.slot,
                    ENTRY_RESUME,
                    self.store_migration.as_ref(),
                    &mut guard.bufs.out[next],
                    |lease| chain.resume(results, lease),
                )
            };
            guard.bufs.out[cur].reset();
            guard.bufs.results.reset();
            cur = next;
            match resumed {
                None => return Err(CallError::Fault(FaultReason::BadInstance)),
                Some(Resumed::Need) => {}
                Some(Resumed::Done(done, opened)) => {
                    status = done;
                    instance = opened;
                    guard.chain = None;
                }
            }
        }
        match status {
            Status::OK | Status::REFUSED | Status::FAILED => {
                let buf = core::mem::take(&mut guard.bufs.out[cur]);
                match OwnedAnswer::new(status, buf) {
                    Ok(answer) => Ok(Finished { answer, instance }),
                    Err(reason) => Err(self.fault(reason)),
                }
            }
            Status::FAULT if has_need(guard.bufs.out[cur].bytes()) => {
                Err(self.fault(FaultReason::MissingToken))
            }
            Status::FAULT => Err(self.fault(FaultReason::Panic)),
            Status(other) => Err(self.fault(FaultReason::BadStatus(other))),
        }
    }

    /// A FAULT this chain met: reported to the fault sink (Instance owner: quarantine + audit `plugin_fault`;
    /// Image owner: audit, the instance-to-be refused) and returned.
    fn fault(&self, reason: FaultReason) -> CallError {
        report_fault(self.caller.slot, self.open, reason)
    }
}

/// W1-H1: where the driver reports a FAULT: `sink(slot, image_owned, reason)`. The registry installs it once
/// (`Registry::new`, W1-L2, beside `set_log_sink`): for an Instance-owned chain it quarantines the slot's
/// instance and audits `plugin_fault`; for an Image-owned (`open`) chain it audits only (the caller refuses the
/// instance-to-be with the returned `CallError::Fault`). Before installation a FAULT is only returned. A second
/// call is ignored. (The IF names the quarantine but no seam for it: `Instance::quarantine` needs the
/// registry's `SlotLease`, which this crate cannot name.)
pub fn set_fault_sink(sink: fn(slot: u32, image_owned: bool, reason: FaultReason)) {
    let _ = FAULT_SINK.set(sink);
}

/// Reports a FAULT to the sink (when one is installed) and returns it as the call's error: the one path every
/// proxy and the driver take.
pub(crate) fn report_fault(slot: u32, image_owned: bool, reason: FaultReason) -> CallError {
    if let Some(sink) = FAULT_SINK.get() {
        sink(slot, image_owned, reason);
    }
    CallError::Fault(reason)
}

static FAULT_SINK: OnceLock<fn(u32, bool, FaultReason)> = OnceLock::new();

/// Installs the process's resume tap: `tap(slot, results)` runs just before a parked chain of `slot` is
/// resumed with `results` (the bytes of its Needs' answers: bytes the engine hands a plugin, so the
/// crossing recorder must see them). A second call is ignored. With none installed a resume pays one load.
pub fn set_resume_tap(tap: fn(slot: u32, results: &[u8])) {
    let _ = RESUME_TAP.set(tap);
}

static RESUME_TAP: OnceLock<fn(u32, &[u8])> = OnceLock::new();

#[inline(always)]
fn resume_tap(slot: u32, results: &[u8]) {
    if let Some(tap) = RESUME_TAP.get() {
        tap(slot, results);
    }
}

/// What the first step of a chain came to: a final status (and, for `open`, the instance its INSTANCE named),
/// or a parked chain on NEED. Built from busbar-ffi's `Started` (kind methods) or `OpenAnswer` (`open`).
pub enum First<'i, K: Kind> {
    Done(Status, Option<LiveInstance<K>>),
    Need(Chain<'i, K>),
}
impl<'i, K: Kind> From<Started<'i, K>> for First<'i, K> {
    fn from(started: Started<'i, K>) -> Self {
        match started {
            Started::Done(status) => First::Done(status, None),
            Started::Need(chain) => First::Need(chain),
        }
    }
}
impl<K: Kind> From<OpenAnswer<K>> for First<'static, K> {
    fn from(answer: OpenAnswer<K>) -> Self {
        match answer {
            OpenAnswer::Done(status, instance) => First::Done(status, instance),
            OpenAnswer::Chain(chain) => First::Need(chain),
        }
    }
}

/// A finished chain: its validated answer and, for an `open` chain answering OK + INSTANCE, the instance (the
/// registry builds its handle in this same poll, §10.4).
pub struct Finished<K: Kind> {
    pub answer: OwnedAnswer,
    pub instance: Option<LiveInstance<K>>,
}

/// The Needs a chain may make (§6.1 "Allowed Needs per kind"), one bit per `op`. Anything else is FAULT
/// `NeedNotAllowed`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NeedRow(u16);
impl NeedRow {
    /// No Need at all: an `F_BLOCKING_FILE` store, every entry (§11.3).
    pub const EMPTY: NeedRow = NeedRow(0);
    const CONN: u16 = (1 << op::OPEN)
        | (1 << op::STARTTLS)
        | (1 << op::WRITE)
        | (1 << op::READ)
        | (1 << op::CLOSE);
    const FETCH: u16 = 1 << op::FETCH;
    const SECRET: u16 = 1 << op::SECRET;
    const RECORD: u16 = 1 << op::RECORD;
    /// The kind's row; `open` = an `open` chain (transport may SECRET there and nowhere else).
    pub const fn of(kind: KindCode, open: bool) -> NeedRow {
        NeedRow(match kind {
            KindCode::Store => Self::CONN | Self::SECRET,
            KindCode::Secret | KindCode::Export => Self::CONN | Self::FETCH | Self::SECRET,
            KindCode::Auth => Self::CONN | Self::FETCH | Self::SECRET | Self::RECORD,
            KindCode::Hook | KindCode::Plane => Self::FETCH | Self::SECRET | Self::RECORD,
            KindCode::Transport if open => Self::SECRET,
            KindCode::Transport => 0,
        })
    }
    /// Adds DIRECTORY: only the `serve` and `refresh` chains of an auth image that declared `FB_PROVISION`.
    pub const fn with_directory(self) -> NeedRow {
        NeedRow(self.0 | (1 << op::DIRECTORY))
    }
    pub const fn allows(self, op: u32) -> bool {
        op < 16 && (self.0 & (1 << op)) != 0
    }
}

/// The host-side owner of a chain (§10.5): the parked busbar-ffi `Chain` (its token never leaves it), the Needs
/// and the caller it reports to, whether it ever made a NEED, and its buffers. Drop: the chain first (busbar-ffi
/// cancels it inline under its caller's owner/watch scope), then `release` iff `needed`, then the buffers
/// (zeroed, pooled). Cancellation faults use the same image/instance sink as other driver entries.
pub(crate) struct ChainGuard<'g, 'i, N: Needs, K: Kind> {
    chain: Option<Chain<'i, K>>,
    needs: &'g N,
    caller: &'g Caller<'g>,
    image_owned: bool,
    needed: bool,
    bufs: ChainBufs,
}

impl<N: Needs, K: Kind> ChainGuard<'_, '_, N, K> {
    fn cancel(&mut self) {
        let _migration = crate::host_side::entry::MigrationScope::deny();
        let Some(chain) = self.chain.take() else {
            return;
        };
        let status = {
            let _owner = crate::host_side::entry::Owning::set(self.caller.slot);
            let _watched = Watched::enter(self.caller.slot, ENTRY_CANCEL);
            chain.cancel()
        };
        match status {
            Status::OK => {}
            Status::FAULT => {
                report_fault(self.caller.slot, self.image_owned, FaultReason::Panic);
            }
            Status(other) => {
                report_fault(
                    self.caller.slot,
                    self.image_owned,
                    FaultReason::BadStatus(other),
                );
            }
        }
    }
}

impl<N: Needs, K: Kind> Drop for ChainGuard<'_, '_, N, K> {
    fn drop(&mut self) {
        self.cancel();
        if self.needed {
            self.needs.release(self.caller);
        }
    }
}

/// The watchdog word for one step: set on entry, restored on return and on unwind.
struct Watched {
    _entry: watch::Entry,
}
impl Watched {
    fn enter(slot: u32, entry: u8) -> Watched {
        Watched {
            _entry: watch::Entry::enter(slot, entry),
        }
    }
}

std::thread_local! {
    /// Entries of this thread now running inside `step`/`step_fixed`, outermost included.
    static ENTRY_DEPTH: core::cell::Cell<u32> = const { core::cell::Cell::new(0) };
}

/// The outermost-exit duty of the entry guard (W1-H1, I11): when the outermost entry of this thread returns or
/// unwinds, everything its `random`/`crypto` answers lent from the thread's arena is zeroed and the arena starts
/// over (`host_vt::reset_arena`). A nested entry's exit resets nothing: its caller's outputs are still lent.
struct Outermost;

impl Outermost {
    fn enter() -> Outermost {
        ENTRY_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Outermost
    }
}

impl Drop for Outermost {
    fn drop(&mut self) {
        let left = ENTRY_DEPTH.with(|depth| {
            let left = depth.get().saturating_sub(1);
            depth.set(left);
            left
        });
        if left == 0 {
            crate::host_side::host_vt::reset_arena();
        }
    }
}

/// One step, inline: the watchdog word around the call, `out` lent to busbar-ffi for it. None: busbar-ffi's
/// ACTIVE stack is full (more nested entries on this thread than busbar-ffi allows; core's own nesting is at most
/// four, §10.3 `CallStack`), which is a host fault, not the plugin's: no sink, no quarantine.
///
/// W1-H1: the entry guard's other duties (`DEPTH`, `OWNER` for log attribution and for the crypto arena, the
/// outermost-exit arena reset) are `entry::guard`'s, owner H0, which the WBS gives no wave-1 owner after H0F;
/// this is the one place the driver enters the plugin, so wrapping it in `entry::guard` is a one-line change.
pub(crate) fn step<R>(
    slot: u32,
    entry: u8,
    migration: Option<&Arc<crate::host_side::entry::StoreMigrationAdmission>>,
    out: &mut PooledOut,
    call: impl FnOnce(&mut OutLease) -> R,
) -> Option<R> {
    let _outermost = Outermost::enter();
    let _migration = crate::host_side::entry::MigrationScope::set(migration.map(Arc::clone));
    let _owner = crate::host_side::entry::Owning::set(slot);
    let _watched = Watched::enter(slot, entry);
    out.lend(call)
}

/// One synchronous entry on caller-owned, fixed output storage. Uses the same owner and watchdog guards
/// as `step`; the loan cannot grow, escape the callback, or transfer the lender's allocation.
pub(crate) fn step_fixed<R>(
    slot: u32,
    entry: u8,
    out: &mut [u8],
    call: impl for<'loan> FnOnce(&mut OutLease<'loan>) -> R,
) -> Option<R> {
    let _outermost = Outermost::enter();
    let _migration = crate::host_side::entry::MigrationScope::deny();
    let _owner = crate::host_side::entry::Owning::set(slot);
    let _watched = Watched::enter(slot, entry);
    OutLease::with_fixed(out, call)
}

/// At most this many Needs in one step (§6.1); more is FAULT.
const MAX_NEEDS: usize = 64;

/// Whether an answer holds a NEED record (a FAULT that came from a NEED answer with no usable TOKEN).
fn has_need(bytes: &[u8]) -> bool {
    Records::new(bytes)
        .filter_map(Result::ok)
        .any(|rec| rec.tag == tag::NEED)
}

/// A NEED answer, before any Need runs: well framed, only NEED and TOKEN records, exactly one TOKEN and it is
/// this chain's, 1..=64 NEEDs, each NEED's op in the row. The NEED count, or the FAULT.
fn check_need_answer(bytes: &[u8], tok: Token, row: NeedRow) -> Result<usize, FaultReason> {
    let mut tokens = 0usize;
    let mut needs = 0usize;
    for rec in Records::new(bytes) {
        let rec = rec.map_err(FaultReason::BadRecords)?;
        match rec.tag {
            tag::TOKEN => {
                let token = rec.pod::<TokenRec>().map_err(FaultReason::BadRecords)?;
                if token.token != tok || tok == 0 {
                    return Err(FaultReason::BadToken);
                }
                tokens += 1;
            }
            tag::NEED => {
                let (need, _) = rec.pod_tail::<NeedRec>().map_err(FaultReason::BadRecords)?;
                if !row.allows(need.op) {
                    return Err(FaultReason::NeedNotAllowed(need.op));
                }
                needs += 1;
            }
            other => return Err(FaultReason::UnknownTag(other)),
        }
    }
    match tokens {
        0 => Err(FaultReason::MissingToken),
        1 if (1..=MAX_NEEDS).contains(&needs) => Ok(needs),
        1 => Err(FaultReason::BadRecords(RecErr::Size)),
        _ => Err(FaultReason::BadToken),
    }
}

/// Runs a checked NEED answer's Needs in order, writing one NEED_RES per Need into `results`. A Need that
/// breaks its decode row is INVALID without running; the first failure makes the rest SKIPPED. Each Need's data
/// cap leaves room for every later Need's fixed part, so every Need gets its record.
async fn run_needs<N: Needs>(
    needs: &N,
    cx: &Caller<'_>,
    answer: &[u8],
    results: &mut PooledOut,
    count: usize,
    max_out: usize,
) -> Result<(), FaultReason> {
    let mut failed = false;
    let mut left = count;
    for rec in Records::new(answer).filter_map(Result::ok) {
        if rec.tag != tag::NEED {
            continue;
        }
        left = left.saturating_sub(1);
        let op = NeedRec::read_from_prefix(rec.body).map_or(0, |(need, _)| need.op);
        let reserved = RES_FIXED.saturating_mul(left + 1);
        let cap = max_out.saturating_sub(results.bytes().len().saturating_add(reserved));
        let mut res =
            NeedOut::begin(results, op, cap).map_err(|_| FaultReason::BadRecords(RecErr::Size))?;
        if failed {
            res.finish(need_status::SKIPPED);
            continue;
        }
        let outcome = match decode_need(rec.body) {
            Ok(need) => run_one(needs, cx, need, &mut res).await,
            Err(err) => Err(err),
        };
        match outcome {
            Ok(()) => res.finish(need_status::OK),
            Err(err) => {
                failed = true;
                res.finish(status_of(err));
            }
        }
    }
    Ok(())
}

async fn run_one<N: Needs>(
    needs: &N,
    cx: &Caller<'_>,
    need: Need<'_>,
    res: &mut NeedOut<'_>,
) -> Result<(), NeedErr> {
    match need {
        Need::Open(n) => needs.open(cx, n, res).await,
        Need::StartTls { conn, tls } => needs.starttls(cx, conn, tls, res).await,
        Need::Write { conn, bytes } => needs.write(cx, conn, bytes, res).await,
        Need::Read { conn, max } => needs.read(cx, conn, max, res).await,
        Need::Close { conn, reusable } => {
            needs.close(cx, conn, reusable).await;
            Ok(())
        }
        Need::Fetch(n) => needs.fetch(cx, n, res).await,
        Need::Secret { handle } => needs.secret(cx, handle, res).await,
        Need::Record(n) => needs.record(cx, n, res).await,
        Need::Directory(n) => needs.directory(cx, n, res).await,
    }
}

/// One decoded Need, exactly what its handler gets (§10.3). Produced only by `decode_need`, so every value is
/// well formed for its row of the decode table.
#[derive(Clone, Copy)]
pub enum Need<'a> {
    Open(OpenNeed<'a>),
    StartTls { conn: ConnId, tls: TlsMode<'a> },
    Write { conn: ConnId, bytes: &'a [u8] },
    Read { conn: ConnId, max: u32 },
    Close { conn: ConnId, reusable: bool },
    Fetch(FetchNeed<'a>),
    Secret { handle: u32 },
    Record(RecordNeed<'a>),
    Directory(DirNeed<'a>),
}

const INVALID: NeedErr = NeedErr::Invalid;

/// Ok when `cond` holds, else INVALID.
fn ensure(cond: bool) -> Result<(), NeedErr> {
    if cond { Ok(()) } else { Err(INVALID) }
}

fn text(bytes: &[u8]) -> Result<&str, NeedErr> {
    core::str::from_utf8(bytes).map_err(|_| INVALID)
}

/// A NEED body split into its Pod and its four arguments (back to back, lengths in `lens`, nothing after).
fn split(body: &[u8]) -> Result<(NeedRec, [&[u8]; 4]), NeedErr> {
    let (rec, mut tail) = NeedRec::read_from_prefix(body).map_err(|_| INVALID)?;
    let mut args: [&[u8]; 4] = [&[]; 4];
    for (arg, &len) in args.iter_mut().zip(rec.lens.iter()) {
        let len = usize::try_from(len).map_err(|_| INVALID)?;
        let (this, rest) = tail.split_at_checked(len).ok_or(INVALID)?;
        *arg = this;
        tail = rest;
    }
    ensure(tail.is_empty())?;
    Ok((rec, args))
}

/// The stated egress class (bits 16..=19), 0..=4.
fn egress_of(flags: u32) -> Result<u32, NeedErr> {
    let class = (flags & need_flag::EGRESS_MASK) >> need_flag::EGRESS_SHIFT;
    ensure(class <= egress::LOOPBACK_ALLOWED)?;
    Ok(class)
}

/// A conn id (`a`): never 0.
fn conn(a: u64) -> Result<ConnId, NeedErr> {
    ensure(a != 0)?;
    Ok(ConnId(a))
}

/// Nested PAIR records, each a well-formed pair.
fn pairs(arg: &[u8], max: usize) -> Result<Records<'_>, NeedErr> {
    let recs = Records::new(arg);
    let mut n = 0usize;
    for rec in recs {
        let rec = rec.map_err(|_| INVALID)?;
        ensure(rec.tag == tag::PAIR)?;
        rec.pair().map_err(|_| INVALID)?;
        n += 1;
    }
    ensure(n <= max)?;
    Ok(recs)
}

/// The decode table of §10.3 (rounds 28, 29) and the wire table of §6.1: a NEED record's body as the value its
/// handler gets, or INVALID. Beyond the table's rows (W1-H1, fail closed): an argument or field the op does not
/// use must be empty or 0 (`a`/`b`, `secret`, `trust`, unused args), a TLS_NONE OPEN names no SNI, ALPN, cert or
/// trust, a REQUIRED mode names no cert, conn ids are never 0, a READ asks for at least one byte, text arguments
/// are UTF-8, FETCH headers are well-formed PAIRs and a COMMIT's records are well formed, predicates first, 1 to
/// `commit::MAX_OPS` of them.
pub fn decode_need(body: &[u8]) -> Result<Need<'_>, NeedErr> {
    let (rec, [a0, a1, a2, a3]) = split(body)?;
    let mode = rec.flags & need_flag::TLS_MASK;
    match rec.op {
        op::OPEN => {
            ensure(rec.flags & !(need_flag::TLS_MASK | need_flag::EGRESS_MASK) == 0)?;
            let egress = egress_of(rec.flags)?;
            ensure(rec.a == 0 && rec.b == 0 && a3.is_empty())?;
            let dest = text(a0)?;
            ensure(!dest.is_empty())?;
            let (sni, alpn) = (text(a1)?, text(a2)?);
            let tls = match mode {
                need_flag::TLS_NONE => {
                    ensure(rec.secret == 0 && rec.trust == 0 && sni.is_empty() && alpn.is_empty())?;
                    TlsMode::None
                }
                need_flag::TLS_REQUIRED => {
                    ensure(rec.secret == 0)?;
                    TlsMode::Required {
                        sni,
                        alpn,
                        trust: rec.trust,
                    }
                }
                need_flag::TLS_MUTUAL if rec.secret != 0 => TlsMode::Mutual {
                    sni,
                    alpn,
                    trust: rec.trust,
                    cert: rec.secret,
                },
                need_flag::TLS_INBAND => TlsMode::Inband {
                    sni,
                    alpn,
                    trust: rec.trust,
                    cert: (rec.secret != 0).then_some(rec.secret),
                },
                _ => return Err(INVALID),
            };
            Ok(Need::Open(OpenNeed { dest, tls, egress }))
        }
        op::STARTTLS => {
            ensure(rec.flags & !need_flag::TLS_MASK == 0)?;
            ensure(rec.b == 0 && a2.is_empty() && a3.is_empty())?;
            let conn = conn(rec.a)?;
            let (sni, alpn) = (text(a0)?, text(a1)?);
            let tls = match mode {
                need_flag::TLS_REQUIRED if rec.secret == 0 => TlsMode::Required {
                    sni,
                    alpn,
                    trust: rec.trust,
                },
                need_flag::TLS_MUTUAL if rec.secret != 0 => TlsMode::Mutual {
                    sni,
                    alpn,
                    trust: rec.trust,
                    cert: rec.secret,
                },
                _ => return Err(INVALID),
            };
            Ok(Need::StartTls { conn, tls })
        }
        op::WRITE => {
            ensure(rec.flags == 0 && rec.b == 0 && rec.secret == 0 && rec.trust == 0)?;
            ensure(a1.is_empty() && a2.is_empty() && a3.is_empty())?;
            Ok(Need::Write {
                conn: conn(rec.a)?,
                bytes: a0,
            })
        }
        op::READ => {
            ensure(rec.flags == 0 && rec.secret == 0 && rec.trust == 0)?;
            ensure(a0.is_empty() && a1.is_empty() && a2.is_empty() && a3.is_empty())?;
            let max = u32::try_from(rec.b).map_err(|_| INVALID)?;
            ensure(max != 0)?;
            Ok(Need::Read {
                conn: conn(rec.a)?,
                max,
            })
        }
        op::CLOSE => {
            ensure(rec.flags & !need_flag::REUSABLE == 0)?;
            ensure(rec.b == 0 && rec.secret == 0 && rec.trust == 0)?;
            ensure(a0.is_empty() && a1.is_empty() && a2.is_empty() && a3.is_empty())?;
            Ok(Need::Close {
                conn: conn(rec.a)?,
                reusable: rec.flags & need_flag::REUSABLE != 0,
            })
        }
        op::FETCH => {
            // Core 3.0: FETCH alone knows one more bit, "status only, discard the body". It selects what
            // is done with the answer and nothing about where the request may go: every check below is
            // the same with and without it.
            const STATUS_ONLY: u32 = crate::vocab::net1::FETCH_STATUS_ONLY;
            ensure(rec.flags & !(need_flag::TLS_MASK | need_flag::EGRESS_MASK | STATUS_ONLY) == 0)?;
            let egress = egress_of(rec.flags)?;
            ensure(rec.a == 0)?;
            let cert = match mode {
                need_flag::TLS_NONE if rec.secret == 0 => None,
                need_flag::TLS_MUTUAL if rec.secret != 0 => Some(rec.secret),
                _ => return Err(INVALID),
            };
            let (method, url) = (text(a0)?, text(a1)?);
            ensure(!method.is_empty() && !url.is_empty())?;
            Ok(Need::Fetch(FetchNeed {
                method,
                url,
                headers: pairs(a2, usize::MAX)?,
                body: a3,
                max_body: rec.b,
                trust: rec.trust,
                cert,
                egress,
                status_only: rec.flags & STATUS_ONLY != 0,
            }))
        }
        op::SECRET => {
            ensure(rec.flags == 0 && rec.a == 0 && rec.b == 0 && rec.trust == 0)?;
            ensure(a0.is_empty() && a1.is_empty() && a2.is_empty() && a3.is_empty())?;
            ensure(rec.secret != 0)?;
            Ok(Need::Secret { handle: rec.secret })
        }
        op::RECORD => decode_record(&rec, [a0, a1, a2, a3]).map(Need::Record),
        op::DIRECTORY => decode_directory(&rec, [a0, a1, a2, a3]).map(Need::Directory),
        _ => Err(INVALID),
    }
}

fn decode_record<'a>(rec: &NeedRec, args: [&'a [u8]; 4]) -> Result<RecordNeed<'a>, NeedErr> {
    let [key, value, a2, a3] = args;
    ensure(rec.secret == 0 && rec.trust == 0 && a2.is_empty() && a3.is_empty())?;
    match rec.flags {
        need_flag::REC_GET | need_flag::REC_DEL => {
            ensure(rec.a == 0 && rec.b == 0 && value.is_empty())?;
            Ok(if rec.flags == need_flag::REC_GET {
                RecordNeed::Get(key)
            } else {
                RecordNeed::Del(key)
            })
        }
        need_flag::REC_PUT => {
            ensure(rec.b == 0)?;
            Ok(RecordNeed::Put(key, value, rec.a))
        }
        need_flag::REC_CLAIM => {
            ensure(rec.b == 0)?;
            Ok(RecordNeed::Claim(key, value, rec.a))
        }
        need_flag::REC_LIST => {
            ensure(rec.a == 0 && value.is_empty())?;
            Ok(RecordNeed::List(
                key,
                u32::try_from(rec.b).map_err(|_| INVALID)?,
            ))
        }
        need_flag::REC_COMMIT => {
            ensure(rec.a == 0 && rec.b == 0 && value.is_empty())?;
            Ok(RecordNeed::Commit(commit_records(key)?))
        }
        _ => Err(INVALID),
    }
}

/// A COMMIT's nested records: REC_PRED* then REC_PUT/REC_DEL, 1..=MAX_OPS, each well formed (§12.5).
fn commit_records(arg: &[u8]) -> Result<Records<'_>, NeedErr> {
    let recs = Records::new(arg);
    let allowed = commit::REC_CALLER;
    let mut n = 0u32;
    let mut mutating = false;
    for rec in recs {
        let rec = rec.map_err(|_| INVALID)?;
        n += 1;
        match rec.tag {
            tag::REC_PRED => {
                ensure(!mutating)?;
                let (head, tail) = rec.pod_tail::<RecPredRec>().map_err(|_| INVALID)?;
                ensure(head.flags & !(commit::PRED_MASK | allowed) == 0)?;
                let key = usize::try_from(head.key_len).map_err(|_| INVALID)?;
                ensure(key <= tail.len())?;
                match head.flags & commit::PRED_MASK {
                    commit::PRED_ABSENT | commit::PRED_PRESENT => ensure(key == tail.len())?,
                    commit::PRED_EQUALS => {}
                    _ => return Err(INVALID),
                }
            }
            tag::REC_PUT => {
                mutating = true;
                let (head, tail) = rec.pod_tail::<RecPutRec>().map_err(|_| INVALID)?;
                ensure(head.flags & !allowed == 0)?;
                ensure(usize::try_from(head.key_len).map_err(|_| INVALID)? <= tail.len())?;
            }
            tag::REC_DEL => {
                mutating = true;
                let (head, _) = rec.pod_tail::<RecDelRec>().map_err(|_| INVALID)?;
                ensure(head.flags & !allowed == 0 && head._r == 0)?;
            }
            _ => return Err(INVALID),
        }
    }
    ensure((1..=commit::MAX_OPS).contains(&n))?;
    Ok(recs)
}

/// An id-shaped argument: non-empty UTF-8 of at most `dir::MAX_ID` bytes.
fn dir_id(arg: &[u8]) -> Result<&str, NeedErr> {
    ensure(!arg.is_empty() && arg.len() <= dir::MAX_ID as usize)?;
    text(arg)
}

/// The decode table's DIRECTORY row (round 29).
fn decode_directory<'a>(rec: &NeedRec, args: [&'a [u8]; 4]) -> Result<DirNeed<'a>, NeedErr> {
    let [a0, a1, a2, a3] = args;
    let flags = rec.flags;
    ensure(flags & !(0xFFFF | dir::PULL) == 0)?;
    ensure(rec.secret == 0 && rec.trust == 0 && rec.b == 0)?;
    let op = flags & dir::OP_MASK;
    let kind = (flags >> dir::KIND_SHIFT) & 0xF;
    let apply = (flags >> dir::APPLY_SHIFT) & 0xF;
    let state = (flags >> dir::STATE_SHIFT) & 0xF;
    let pull = flags & dir::PULL != 0;
    let counts = op == dir::SCAN || op == dir::COUNT;
    ensure(kind == dir::SUBJECT || kind == dir::GROUP || (kind == dir::MEMBER && counts))?;
    ensure(apply == 0 || op == dir::APPLY)?;
    ensure(apply & dir::APPLY_REPLACE_MEMBERS == 0 || kind == dir::GROUP)?;
    ensure(!pull || op == dir::CREATE || op == dir::APPLY)?;
    let live = |s: u32| s == dir::STATE_ACTIVE || s == dir::STATE_INACTIVE;
    match op {
        dir::CREATE if kind == dir::SUBJECT => ensure(live(state))?,
        dir::APPLY if apply & dir::APPLY_STATE != 0 => ensure(kind == dir::SUBJECT && live(state))?,
        _ => ensure(state == 0)?,
    }
    ensure(rec.a == 0 || op == dir::APPLY || op == dir::DELETE || op == dir::SCAN)?;
    let scope = |arg: &'a [u8]| -> Result<&'a str, NeedErr> {
        if kind == dir::MEMBER {
            dir_id(arg)
        } else {
            ensure(arg.is_empty())?;
            Ok("")
        }
    };
    match op {
        dir::GET => {
            ensure(a1.is_empty() && a2.is_empty() && a3.is_empty())?;
            Ok(DirNeed::Get {
                kind,
                id: dir_id(a0)?,
            })
        }
        dir::LOOKUP => {
            ensure(a2.is_empty() && a3.is_empty())?;
            ensure(a1.len() <= dir::MAX_DOCUMENT as usize)?;
            Ok(DirNeed::Lookup {
                kind,
                index: dir_id(a0)?,
                value: a1,
            })
        }
        dir::SCAN => {
            ensure(a2.is_empty() && a3.is_empty() && a1.len() <= dir::MAX_ID as usize)?;
            let limit = match u32::try_from(rec.a) {
                Ok(n) if (1..=dir::MAX_SCAN).contains(&n) => n,
                _ => dir::MAX_SCAN,
            };
            Ok(DirNeed::Scan {
                kind,
                scope: scope(a0)?,
                after: text(a1)?,
                limit,
            })
        }
        dir::COUNT => {
            ensure(a1.is_empty() && a2.is_empty() && a3.is_empty())?;
            Ok(DirNeed::Count {
                kind,
                scope: scope(a0)?,
            })
        }
        dir::CREATE => {
            ensure(a0.is_empty() && a3.is_empty() && a1.len() <= dir::MAX_DOCUMENT as usize)?;
            Ok(DirNeed::Create {
                kind,
                state,
                pull,
                document: a1,
                indexes: pairs(a2, dir::MAX_INDEXES as usize)?,
            })
        }
        dir::APPLY => {
            ensure(a1.len() <= dir::MAX_DOCUMENT as usize)?;
            ensure(apply & dir::APPLY_DOCUMENT != 0 || a1.is_empty())?;
            ensure(apply & dir::APPLY_INDEXES != 0 || a2.is_empty())?;
            ensure(kind == dir::GROUP || a3.is_empty())?;
            Ok(DirNeed::Apply {
                kind,
                id: dir_id(a0)?,
                expected_version: rec.a,
                apply,
                state,
                document: a1,
                indexes: pairs(a2, dir::MAX_INDEXES as usize)?,
                members: members(a3)?,
            })
        }
        dir::DELETE => {
            ensure(a1.is_empty() && a2.is_empty() && a3.is_empty())?;
            Ok(DirNeed::Delete {
                kind,
                id: dir_id(a0)?,
                expected_version: rec.a,
            })
        }
        _ => Err(INVALID),
    }
}

/// An APPLY's member changes: DM_ADD/DM_REMOVE/DM_REPLACE records, each an id, at most MAX_MEMBERS_PER_APPLY.
fn members(arg: &[u8]) -> Result<Records<'_>, NeedErr> {
    let recs = Records::new(arg);
    let mut n = 0u32;
    for rec in recs {
        let rec = rec.map_err(|_| INVALID)?;
        ensure(matches!(
            rec.tag,
            dir::DM_ADD | dir::DM_REMOVE | dir::DM_REPLACE
        ))?;
        dir_id(rec.body)?;
        n += 1;
    }
    ensure(n <= dir::MAX_MEMBERS_PER_APPLY)?;
    Ok(recs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{Reply, Writer};
    use zerocopy::IntoBytes;

    /// A NEED body: the Pod (lens filled in) and its four arguments back to back.
    fn body(
        op: u32,
        flags: u32,
        a: u64,
        b: u64,
        secret: u32,
        trust: u32,
        args: [&[u8]; 4],
    ) -> Vec<u8> {
        let rec = NeedRec {
            op,
            flags,
            a,
            b,
            secret,
            trust,
            lens: args.map(|arg| arg.len() as u32),
        };
        let mut bytes = rec.as_bytes().to_vec();
        for arg in args {
            bytes.extend_from_slice(arg);
        }
        bytes
    }
    const E: &[u8] = &[];

    const DEST: &[u8] = b"db:5432";

    #[test]
    fn open_rows() {
        let ok = |flags: u32, secret: u32, trust: u32, args: [&[u8]; 4]| {
            decode_need_owned(op::OPEN, flags, 0, 0, secret, trust, args)
        };
        let plain = [DEST, E, E, E];
        assert!(matches!(
            ok(0, 0, 0, plain),
            Ok(Shape::Open(TlsKind::None, 0))
        ));
        assert!(matches!(
            ok(1 | (3 << 16), 0, 2, [DEST, &b"db"[..], &b"h2"[..], E]),
            Ok(Shape::Open(TlsKind::Required, 3))
        ));
        assert!(matches!(
            ok(2, 5, 0, plain),
            Ok(Shape::Open(TlsKind::Mutual, 0))
        ));
        assert!(matches!(
            ok(3, 0, 0, plain),
            Ok(Shape::Open(TlsKind::Inband(false), 0))
        ));
        assert!(matches!(
            ok(3, 4, 0, plain),
            Ok(Shape::Open(TlsKind::Inband(true), 0))
        ));
        let bad: [(u32, u32, u32, [&[u8]; 4], &str); 11] = [
            (2, 0, 0, plain, "MUTUAL without a cert"),
            (4, 0, 0, plain, "a mode past INBAND"),
            (5 << 16, 0, 0, plain, "an egress class past 4"),
            (0x200, 0, 0, plain, "the retired unverified bit"),
            (0x100, 0, 0, plain, "REUSABLE is CLOSE's"),
            (0, 1, 0, plain, "a cert on a plaintext dial"),
            (
                0,
                0,
                0,
                [DEST, &b"sni"[..], E, E],
                "SNI on a plaintext dial",
            ),
            (0, 0, 0, [E; 4], "no dest"),
            (0, 0, 0, [&[0xFF][..], E, E, E], "a dest that is not UTF-8"),
            (0, 0, 0, [DEST, E, E, &b"x"[..]], "an unused argument"),
            (1, 3, 0, plain, "a cert on REQUIRED"),
        ];
        for (flags, secret, trust, args, why) in bad {
            assert_eq!(
                ok(flags, secret, trust, args).err(),
                Some(NeedErr::Invalid),
                "{why}"
            );
        }
    }

    #[test]
    fn a_need_whose_lengths_do_not_add_up_is_invalid() {
        let mut bytes = body(op::SECRET, 0, 0, 0, 1, 0, [E; 4]);
        bytes.push(0);
        assert_eq!(
            decode_need(&bytes).err(),
            Some(NeedErr::Invalid),
            "a trailing byte"
        );
        let mut rec = NeedRec::read_from_prefix(&body(op::WRITE, 0, 1, 0, 0, 0, [b"abc", E, E, E]))
            .map(|(rec, _)| rec)
            .expect("pod");
        rec.lens[0] = 9;
        let mut short = rec.as_bytes().to_vec();
        short.extend_from_slice(b"abc");
        assert_eq!(
            decode_need(&short).err(),
            Some(NeedErr::Invalid),
            "an argument past the body"
        );
        assert_eq!(
            decode_need(&[0u8; 8]).err(),
            Some(NeedErr::Invalid),
            "shorter than NeedRec"
        );
        assert_eq!(
            decode_need(&body(0, 0, 0, 0, 0, 0, [E; 4])).err(),
            Some(NeedErr::Invalid),
            "op 0"
        );
        assert_eq!(
            decode_need(&body(10, 0, 0, 0, 0, 0, [E; 4])).err(),
            Some(NeedErr::Invalid),
            "op 10"
        );
    }

    /// Core 3.0, `net1::FETCH_STATUS_ONLY` (bit 24): on a FETCH it decodes to `status_only` and changes no
    /// other field (the stated egress class, the TLS mode, the certificate and the trust are read exactly as
    /// on a full FETCH); on every other op, and for every other stray bit on a FETCH, the Need is INVALID.
    #[test]
    fn a_status_only_fetch_decodes_and_the_bit_is_invalid_everywhere_else() {
        const STATUS_ONLY: u32 = crate::vocab::net1::FETCH_STATUS_ONLY;
        assert_eq!(STATUS_ONLY, 1 << 24);
        const E: &[u8] = &[];
        let args: [&[u8]; 4] = [b"POST", b"https://hooks.test/in", E, b"line"];
        let class = 3 << need_flag::EGRESS_SHIFT;
        let fetch = |flags: u32, secret: u32, trust: u32| {
            let bytes = body(op::FETCH, flags, 0, 0, secret, trust, args);
            match decode_need(&bytes) {
                Ok(Need::Fetch(n)) => Ok((
                    n.status_only,
                    n.egress,
                    n.cert,
                    n.trust,
                    n.max_body,
                    n.method.to_owned(),
                    n.url.to_owned(),
                    n.body.to_vec(),
                )),
                Ok(_) => panic!("a FETCH decodes to a FETCH"),
                Err(e) => Err(e),
            }
        };
        let full = fetch(class, 0, 9).expect("a full FETCH");
        let status = fetch(class | STATUS_ONLY, 0, 9).expect("a status-only FETCH");
        assert!(!full.0 && status.0);
        assert_eq!(
            (
                status.1, status.2, status.3, &status.5, &status.6, &status.7
            ),
            (full.1, full.2, full.3, &full.5, &full.6, &full.7),
            "the bit changes nothing but status_only"
        );
        assert_eq!(status.1, 3, "the stated egress class");
        let mutual = fetch(class | STATUS_ONLY | need_flag::TLS_MUTUAL, 4, 9).expect("mutual");
        assert_eq!((mutual.0, mutual.2), (true, Some(4)));

        // The checks a full FETCH passes still refuse a status-only one.
        for (flags, secret) in [
            // An egress class out of range.
            (STATUS_ONLY | (0xF << need_flag::EGRESS_SHIFT), 0),
            // A certificate without the mutual mode, and the mutual mode without a certificate.
            (STATUS_ONLY | class, 4),
            (STATUS_ONLY | class | need_flag::TLS_MUTUAL, 0),
            // Any other stray bit.
            (STATUS_ONLY | class | (1 << 25), 0),
            (STATUS_ONLY | class | (1 << 20), 0),
            (class | (1 << 25), 0),
        ] {
            assert_eq!(
                fetch(flags, secret, 0).err(),
                Some(NeedErr::Invalid),
                "flags {flags:#x}"
            );
        }
        let no_url = body(op::FETCH, STATUS_ONLY, 0, 0, 0, 0, [b"POST", E, E, E]);
        assert_eq!(decode_need(&no_url).err(), Some(NeedErr::Invalid));
        let with_a = body(op::FETCH, STATUS_ONLY, 1, 0, 0, 0, args);
        assert_eq!(decode_need(&with_a).err(), Some(NeedErr::Invalid));

        // The bit is FETCH's alone.
        let open = body(
            op::OPEN,
            STATUS_ONLY,
            0,
            0,
            0,
            0,
            [b"db.test:5432", E, E, E],
        );
        assert_eq!(decode_need(&open).err(), Some(NeedErr::Invalid));
        let write = body(op::WRITE, STATUS_ONLY, 1, 0, 0, 0, [b"x", E, E, E]);
        assert_eq!(decode_need(&write).err(), Some(NeedErr::Invalid));
        let close = body(op::CLOSE, STATUS_ONLY, 1, 0, 0, 0, [E; 4]);
        assert_eq!(decode_need(&close).err(), Some(NeedErr::Invalid));
        let secret = body(op::SECRET, STATUS_ONLY, 0, 0, 1, 0, [E; 4]);
        assert_eq!(decode_need(&secret).err(), Some(NeedErr::Invalid));
    }

    #[test]
    fn the_need_row_is_the_kind_table() {
        use KindCode::*;
        let row = |kind, open| {
            let r = NeedRow::of(kind, open);
            [
                op::OPEN,
                op::STARTTLS,
                op::WRITE,
                op::READ,
                op::CLOSE,
                op::FETCH,
                op::SECRET,
                op::RECORD,
                op::DIRECTORY,
            ]
            .map(|op| r.allows(op))
        };
        let (y, n) = (true, false);
        assert_eq!(row(Store, false), [y, y, y, y, y, n, y, n, n]);
        assert_eq!(row(Secret, false), [y, y, y, y, y, y, y, n, n]);
        assert_eq!(row(Auth, false), [y, y, y, y, y, y, y, y, n]);
        assert_eq!(row(Hook, false), [n, n, n, n, n, y, y, y, n]);
        assert_eq!(row(Export, false), [y, y, y, y, y, y, y, n, n]);
        assert_eq!(row(Plane, false), [n, n, n, n, n, y, y, y, n]);
        assert_eq!(row(Transport, false), [n; 9]);
        assert_eq!(row(Transport, true), [n, n, n, n, n, n, y, n, n]);
        for kind in KindCode::ALL {
            if kind != Transport {
                assert_eq!(
                    NeedRow::of(kind, true),
                    NeedRow::of(kind, false),
                    "{kind:?}: open uses the kind's row"
                );
            }
        }
        assert!(
            NeedRow::of(Auth, false)
                .with_directory()
                .allows(op::DIRECTORY)
        );
        assert!((0..32).all(|op| !NeedRow::EMPTY.allows(op)));
        assert!(!NeedRow::of(Auth, false).allows(0) && !NeedRow::of(Auth, false).allows(16));
    }

    #[test]
    fn a_need_answer_is_checked_before_any_need_runs() {
        let row = NeedRow::of(KindCode::Secret, false);
        let tok: Token = (1 << 32) | 3;
        let answer = |token: Option<u64>, needs: &[u32], extra: Option<u16>| {
            let mut r = Reply::new();
            for &op in needs {
                r.put(tag::NEED, &body(op, 0, 0, 0, 1, 0, [E; 4]))
                    .expect("need");
            }
            if let Some(token) = token {
                r.put_pod(tag::TOKEN, &TokenRec { token }).expect("token");
            }
            if let Some(t) = extra {
                r.put(t, b"x").expect("extra");
            }
            r.as_bytes().to_vec()
        };
        assert_eq!(
            check_need_answer(&answer(Some(tok), &[op::SECRET; 2], None), tok, row),
            Ok(2)
        );
        assert_eq!(
            check_need_answer(&answer(None, &[op::SECRET], None), tok, row),
            Err(FaultReason::MissingToken)
        );
        assert_eq!(
            check_need_answer(&answer(Some(tok + 1), &[op::SECRET], None), tok, row),
            Err(FaultReason::BadToken),
            "a TOKEN that is not this chain's"
        );
        assert_eq!(
            check_need_answer(&answer(Some(tok), &[op::RECORD], None), tok, row),
            Err(FaultReason::NeedNotAllowed(op::RECORD))
        );
        assert_eq!(
            check_need_answer(&answer(Some(tok), &[], None), tok, row),
            Err(FaultReason::BadRecords(RecErr::Size)),
            "a NEED answer with no NEED"
        );
        assert_eq!(
            check_need_answer(&answer(Some(tok), &[op::SECRET; 65], None), tok, row),
            Err(FaultReason::BadRecords(RecErr::Size)),
            "65 NEEDs"
        );
        assert_eq!(
            check_need_answer(
                &answer(Some(tok), &[op::SECRET], Some(tag::ERROR)),
                tok,
                row
            ),
            Err(FaultReason::UnknownTag(tag::ERROR))
        );
        let mut two = answer(Some(tok), &[op::SECRET], None);
        two.extend(answer(Some(tok), &[], None));
        assert_eq!(
            check_need_answer(&two, tok, row),
            Err(FaultReason::BadToken),
            "two TOKENs"
        );
    }

    #[test]
    fn the_chain_guard_is_send() {
        struct NoNeeds;
        impl Needs for NoNeeds {
            async fn open(
                &self,
                _: &Caller<'_>,
                _: OpenNeed<'_>,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn starttls(
                &self,
                _: &Caller<'_>,
                _: ConnId,
                _: TlsMode<'_>,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn write(
                &self,
                _: &Caller<'_>,
                _: ConnId,
                _: &[u8],
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn read(
                &self,
                _: &Caller<'_>,
                _: ConnId,
                _: u32,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn close(&self, _: &Caller<'_>, _: ConnId, _: bool) {}
            async fn fetch(
                &self,
                _: &Caller<'_>,
                _: FetchNeed<'_>,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn secret(
                &self,
                _: &Caller<'_>,
                _: u32,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn record(
                &self,
                _: &Caller<'_>,
                _: RecordNeed<'_>,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            async fn directory(
                &self,
                _: &Caller<'_>,
                _: DirNeed<'_>,
                _: &mut NeedOut<'_>,
            ) -> Result<(), NeedErr> {
                Err(NeedErr::Denied)
            }
            fn release(&self, _: &Caller<'_>) {}
        }
        fn send<T: Send>() {}
        send::<ChainGuard<'static, 'static, NoNeeds, busbar_ffi::kind::Secret>>();
        send::<First<'static, busbar_ffi::kind::Store>>();
        send::<Finished<busbar_ffi::kind::Plane>>();
    }

    /// The decoded shape, for the row tests above.
    #[derive(Debug)]
    enum TlsKind {
        None,
        Required,
        Mutual,
        Inband(bool),
    }
    #[derive(Debug)]
    enum Shape {
        Open(TlsKind, u32),
    }
    fn decode_need_owned(
        op: u32,
        flags: u32,
        a: u64,
        b: u64,
        secret: u32,
        trust: u32,
        args: [&[u8]; 4],
    ) -> Result<Shape, NeedErr> {
        let bytes = body(op, flags, a, b, secret, trust, args);
        match decode_need(&bytes)? {
            Need::Open(OpenNeed { tls, egress, .. }) => Ok(Shape::Open(
                match tls {
                    TlsMode::None => TlsKind::None,
                    TlsMode::Required { .. } => TlsKind::Required,
                    TlsMode::Mutual { .. } => TlsKind::Mutual,
                    TlsMode::Inband { cert, .. } => TlsKind::Inband(cert.is_some()),
                },
                egress,
            )),
            _ => Err(NeedErr::Invalid),
        }
    }
}
