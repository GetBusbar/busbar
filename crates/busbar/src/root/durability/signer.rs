// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE TWO AUDIT SIGNER THREADS (SEALING-FIX r20 §3.3, §5.3 layer 1).
//!
//! Every audit signature is made on one of two plain detached `std::thread`s, never on a request
//! runtime, never on the control runtime, and never on tokio's blocking pool (a runtime waits for
//! its blocking tasks at shutdown; a detached thread does not, so a hung KMS never hangs exit):
//! - `busbar-notary-signer` owns the [`Notary`] and signs only `live` and `final` pages, one at a
//!   time (a `sync_channel(1)` and a shared `busy` flag);
//! - `busbar-audit-signer` owns the [`BootstrapSigner`] and signs `after_restart` pages, break
//!   notices and unit checkpoint batches, first in first out, at most [`BOOTSTRAP_QUEUE`] queued.
//!
//! The only way to reach either thread is a [`SignerHandle`]: one per submitter, not `Clone`,
//! minted only by [`spawn`]. The job types and the channel senders are private to this module.
//! Owner-approved #392 exception (release !578, 2026-11-17): only the fixed-domain response
//! purpose may be awaited by a request. The general Checkpoint probe remains unchanged.

use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::Arc;
use std::time::Duration;

use busbar_contract::crypto::{PublicKey, SignError};
use busbar_kernel::governance::drain::{Cut, DrainClock};
use busbar_kernel_audit::notary_key::NotaryKeyCertificate;
use busbar_kernel_audit::{BootstrapSigner, BreakNotice, Notary, Stamp, StampSignError};
use tokio::sync::oneshot;
use tokio::time::Instant;

/// The deadline on one sign: 100 times a slow KMS (SEALING-FIX §3.3).
pub(crate) const SIGN_DEADLINE: Duration = Duration::from_secs(2);

/// How many Bootstrap jobs may wait for the Bootstrap signer thread.
pub(crate) const BOOTSTRAP_QUEUE: usize = 64;

/// One KMS round trip, as the deadlines budget it.
const KMS_ROUND_TRIP: Duration = Duration::from_millis(20);

/// The deadline on one Bootstrap job, counted from submission: the queue ahead of it at a slow KMS
/// plus its own sign (≈ 3.3 s).
pub(crate) const JOB_DEADLINE: Duration =
    Duration::from_millis(2_000 + BOOTSTRAP_QUEUE as u64 * 20);

/// How long the checkpoint handle refuses at once after a failed checkpoint job.
pub(crate) const CHECKPOINT_HOLDOFF: Duration = Duration::from_secs(5);

/// The deadline on a checkpoint batch of `n` bodies: [`JOB_DEADLINE`] plus one KMS round trip per
/// body.
#[must_use]
pub(crate) fn checkpoint_deadline(n: usize) -> Duration {
    JOB_DEADLINE + KMS_ROUND_TRIP * u32::try_from(n).unwrap_or(u32::MAX)
}

/// Why a submitted job produced no signature. Every variant is a failure of that job only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SignFailure {
    /// The queue is full, the one live sign is still outstanding, or the checkpoint handle is
    /// backing off after a failure: nothing was queued.
    Busy,
    /// The signer thread is gone (it panicked); every later submit fails the same way.
    Gone,
    /// The job's deadline passed before its reply.
    Deadline,
    /// The signer returned a signature that does not verify (`SignError::InvalidSignature`).
    Invalid,
    /// The signer refused or failed.
    Refused(String),
}

impl std::fmt::Display for SignFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignFailure::Busy => f.write_str("signer busy"),
            SignFailure::Gone => f.write_str("signer thread gone"),
            SignFailure::Deadline => f.write_str("signer deadline passed"),
            SignFailure::Invalid => f.write_str("signer returned an invalid signature"),
            SignFailure::Refused(why) => write!(f, "signer refused: {why}"),
        }
    }
}

fn failure_of_sign(e: SignError) -> SignFailure {
    match e {
        SignError::InvalidSignature => SignFailure::Invalid,
        other => SignFailure::Refused(other.to_string()),
    }
}

fn failure_of_stamp(e: StampSignError) -> SignFailure {
    match e {
        StampSignError::Signer(e) => failure_of_sign(e),
        wrong @ StampSignError::WrongKind(_) => SignFailure::Refused(wrong.to_string()),
    }
}

type Reply<T> = oneshot::Sender<Result<T, SignFailure>>;

/// One live page for the notary signer thread.
struct LiveJob {
    stamp: Stamp,
    reply: Reply<Stamp>,
}

/// One job for the Bootstrap signer thread.
enum Job {
    Restart(Stamp, Reply<Stamp>),
    Break(BreakNotice, Reply<BreakNotice>),
    Checkpoint(Vec<Vec<u8>>, Reply<Vec<Vec<u8>>>),
    Certificate {
        node: u64,
        seq: u64,
        prev: busbar_kernel_audit::Fingerprint,
        key: PublicKey,
        reply: Reply<NotaryKeyCertificate>,
    },
}

/// The notary task's handle: `live` and `final` pages.
pub(crate) struct Live;
/// The boot phase's and the predecessor sealer's handle: restart pages and break notices.
pub(crate) struct Seal;
/// The unit checkpoint adapter's handle: checkpoint batches.
pub(crate) struct Checkpoint;

/// THE ONLY WAY TO A SIGNER THREAD. One per submitter, not `Clone`, minted only by [`spawn`].
pub(crate) struct SignerHandle<K> {
    inner: Inner,
    _kind: PhantomData<fn() -> K>,
}

enum Inner {
    Live {
        tx: SyncSender<LiveJob>,
        busy: Arc<AtomicBool>,
    },
    Boot {
        tx: SyncSender<Job>,
    },
    Checkpoint(CheckpointSubmit),
}

struct CheckpointSubmit {
    tx: SyncSender<Job>,
    /// Monotonic ms (since `epoch`) until which a submit is refused at once; `u64::MAX` after a
    /// failure while the drain clock is armed; 0 when clear.
    fail_until_ms: AtomicU64,
    epoch: Instant,
    /// SHUTDOWN-HANG's drain clock, attached once serving starts.
    clock: Arc<std::sync::OnceLock<Arc<DrainClock>>>,
}

impl<K> std::fmt::Debug for SignerHandle<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self.inner {
            Inner::Live { .. } => "SignerHandle<Live>",
            Inner::Boot { .. } => "SignerHandle<Seal>",
            Inner::Checkpoint(_) => "SignerHandle<Checkpoint>",
        })
    }
}

/// R24 layer 3 (test builds): set by the serving loop around each unit's future. A submit made on
/// the request path is a bug the probe in every `submit` catches.
#[cfg(test)]
tokio::task_local! {
    pub(crate) static ON_REQUEST_PATH: bool;
}

fn probe() {
    #[cfg(test)]
    assert!(
        !ON_REQUEST_PATH.try_with(|on| *on).unwrap_or(false),
        "R24: an audit signature was requested on the request path"
    );
}

impl SignerHandle<Live> {
    /// Whether the one live sign is still outstanding on the thread (its submitter may have given
    /// up at its deadline; the thread clears this before it replies).
    #[must_use]
    pub(crate) fn busy(&self) -> bool {
        match &self.inner {
            Inner::Live { busy, .. } => busy.load(Ordering::Acquire),
            _ => false,
        }
    }

    /// SUBMIT ONE `live` OR `final` PAGE. Never blocks: `Busy` while the previous sign is still on
    /// the thread, `Gone` if the thread has exited. The receiver answers once; the caller applies
    /// [`SIGN_DEADLINE`].
    pub(crate) fn submit(
        &self,
        stamp: Stamp,
    ) -> Result<oneshot::Receiver<Result<Stamp, SignFailure>>, SignFailure> {
        probe();
        let Inner::Live { tx, busy } = &self.inner else {
            return Err(SignFailure::Gone);
        };
        if busy.swap(true, Ordering::AcqRel) {
            return Err(SignFailure::Busy);
        }
        let (reply, rx) = oneshot::channel();
        match tx.try_send(LiveJob { stamp, reply }) {
            Ok(()) => Ok(rx),
            Err(TrySendError::Full(_)) => {
                busy.store(false, Ordering::Release);
                Err(SignFailure::Busy)
            }
            Err(TrySendError::Disconnected(_)) => {
                busy.store(false, Ordering::Release);
                Err(SignFailure::Gone)
            }
        }
    }
}

/// Await `rx` until `deadline`; a dropped sender is a gone thread.
async fn reply_by<T>(
    rx: oneshot::Receiver<Result<T, SignFailure>>,
    deadline: Instant,
) -> Result<T, SignFailure> {
    match tokio::time::timeout_at(deadline, rx).await {
        Ok(Ok(answer)) => answer,
        Ok(Err(_)) => Err(SignFailure::Gone),
        Err(_) => Err(SignFailure::Deadline),
    }
}

fn queue(tx: &SyncSender<Job>, job: Job) -> Result<(), SignFailure> {
    match tx.try_send(job) {
        Ok(()) => Ok(()),
        Err(TrySendError::Full(_)) => Err(SignFailure::Busy),
        Err(TrySendError::Disconnected(_)) => Err(SignFailure::Gone),
    }
}

impl SignerHandle<Seal> {
    /// Certify this boot's public key at an exact chain position on the Bootstrap thread.
    pub(crate) async fn submit_certificate(
        &self,
        node: u64,
        seq: u64,
        prev: busbar_kernel_audit::Fingerprint,
        key: PublicKey,
    ) -> Result<NotaryKeyCertificate, SignFailure> {
        probe();
        let deadline = Instant::now() + JOB_DEADLINE;
        let (reply, rx) = oneshot::channel();
        queue(
            self.boot_tx()?,
            Job::Certificate {
                node,
                seq,
                prev,
                key,
                reply,
            },
        )?;
        reply_by(rx, deadline).await
    }

    fn boot_tx(&self) -> Result<&SyncSender<Job>, SignFailure> {
        match &self.inner {
            Inner::Boot { tx } => Ok(tx),
            _ => Err(SignFailure::Gone),
        }
    }

    /// SIGN ONE `after_restart` PAGE on the Bootstrap thread, under [`JOB_DEADLINE`] counted from
    /// now (queue time included).
    pub(crate) async fn submit_restart(&self, stamp: Stamp) -> Result<Stamp, SignFailure> {
        probe();
        let deadline = Instant::now() + JOB_DEADLINE;
        let (reply, rx) = oneshot::channel();
        queue(self.boot_tx()?, Job::Restart(stamp, reply))?;
        reply_by(rx, deadline).await
    }

    /// SIGN ONE BREAK NOTICE on the Bootstrap thread, under [`JOB_DEADLINE`].
    pub(crate) async fn submit_break(
        &self,
        notice: BreakNotice,
    ) -> Result<BreakNotice, SignFailure> {
        probe();
        let deadline = Instant::now() + JOB_DEADLINE;
        let (reply, rx) = oneshot::channel();
        queue(self.boot_tx()?, Job::Break(notice, reply))?;
        reply_by(rx, deadline).await
    }
}

impl SignerHandle<Checkpoint> {
    /// SIGN ONE BATCH OF CHECKPOINT BODIES (SEALING-FIX §3.3 "Checkpoint signing"): one job for the
    /// whole batch, all or nothing, under [`checkpoint_deadline`]. After a failure the handle
    /// refuses at once for [`CHECKPOINT_HOLDOFF`], so a stalled KMS costs one deadline per hold-off,
    /// not one per unit. Once the drain clock is armed, a failure holds off until exit and every
    /// wait is clamped to C2 (C3 for a job submitted at or after C2).
    pub(crate) async fn sign_checkpoints(
        &self,
        bodies: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, SignFailure> {
        probe();
        let Inner::Checkpoint(submit) = &self.inner else {
            return Err(SignFailure::Gone);
        };
        submit.sign(bodies).await
    }
}

impl CheckpointSubmit {
    fn now_ms(epoch: Instant) -> u64 {
        u64::try_from(epoch.elapsed().as_millis()).unwrap_or(u64::MAX - 1)
    }

    // Private shared bounded job mechanics. Only the typed entry points above reach it.
    async fn sign(&self, bodies: &[&[u8]]) -> Result<Vec<Vec<u8>>, SignFailure> {
        let Self {
            tx,
            fail_until_ms,
            epoch,
            clock,
        } = self;
        let clock = clock.get();
        let armed = clock.and_then(|clock| clock.armed_at());
        let now_ms = Self::now_ms(*epoch);
        let until = fail_until_ms.load(Ordering::Acquire);
        if until == u64::MAX || now_ms < until {
            return Err(SignFailure::Busy);
        }
        let now = Instant::now();
        let mut deadline = now + checkpoint_deadline(bodies.len());
        if let (Some(clock), Some(at)) = (clock, armed) {
            let c2 = clock.limit(at, Cut::Settle);
            let cut = if now < c2 {
                c2
            } else {
                clock.limit(at, Cut::Seal)
            };
            deadline = deadline.min(cut);
        }
        let (reply, rx) = oneshot::channel();
        let job = Job::Checkpoint(bodies.iter().map(|body| body.to_vec()).collect(), reply);
        let answer = match queue(tx, job) {
            Ok(()) => reply_by(rx, deadline).await,
            Err(e) => Err(e),
        };
        match &answer {
            Ok(_) => fail_until_ms.store(0, Ordering::Release),
            Err(_) => {
                let armed_now = clock.is_some_and(|clock| clock.armed_at().is_some());
                let hold = if armed_now {
                    u64::MAX
                } else {
                    Self::now_ms(*epoch)
                        .saturating_add(u64::try_from(CHECKPOINT_HOLDOFF.as_millis()).unwrap_or(0))
                };
                if fail_until_ms.swap(hold, Ordering::AcqRel) == 0 {
                    busbar_kernel::diag_error!(
                        busbar_kernel::diagnostics::AUDIT_STAMP_FAILED,
                        reason = "checkpoint_signer",
                        "unit checkpoint signer failed; checkpoints back off"
                    );
                }
            }
        }
        answer
    }
}

/// The two threads' join handles, for the maintenance tick's panic check.
pub(crate) struct SignerThreads {
    live: std::thread::JoinHandle<()>,
    bootstrap: std::thread::JoinHandle<()>,
}

impl SignerThreads {
    /// Whether the notary signer thread has exited (its channel closed, or it panicked).
    #[must_use]
    pub(crate) fn live_finished(&self) -> bool {
        self.live.is_finished()
    }

    /// Whether the Bootstrap signer thread has exited.
    #[must_use]
    pub(crate) fn bootstrap_finished(&self) -> bool {
        self.bootstrap.is_finished()
    }
}

/// THE HANDLES [`spawn`] MINTS, one per submitter.
pub(crate) struct Signers {
    /// The notary task's.
    pub(crate) live: SignerHandle<Live>,
    /// The own-node boot phase's (then the notary task's boot-job slot).
    pub(crate) boot: SignerHandle<Seal>,
    /// The predecessor sealer's.
    pub(crate) sealer: SignerHandle<Seal>,
    /// The unit checkpoint adapter's.
    pub(crate) checkpoint: SignerHandle<Checkpoint>,
    /// The threads, for the panic check.
    pub(crate) threads: SignerThreads,
}

impl std::fmt::Debug for Signers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signers").finish_non_exhaustive()
    }
}

fn live_thread(notary: Notary, rx: Receiver<LiveJob>, busy: Arc<AtomicBool>) {
    while let Ok(LiveJob { stamp, reply }) = rx.recv() {
        let answer = notary.sign_stamp(stamp).map_err(failure_of_stamp);
        // Clear first: a task woken by the reply never sees a stale `busy`.
        busy.store(false, Ordering::Release);
        let _ = reply.send(answer);
    }
}

fn bootstrap_thread(signer: BootstrapSigner, rx: Receiver<Job>) {
    while let Ok(job) = rx.recv() {
        // A job whose submitter already gave up (its deadline passed) is skipped, so a KMS that
        // recovers does not work through stale jobs.
        match job {
            Job::Certificate {
                node,
                seq,
                prev,
                key,
                reply,
            } => {
                if !reply.is_closed() {
                    let _ = reply.send(
                        signer
                            .sign_notary_key(node, seq, prev, &key)
                            .map_err(failure_of_sign),
                    );
                }
            }
            Job::Restart(stamp, reply) => {
                if !reply.is_closed() {
                    let _ = reply.send(signer.sign_restart_page(stamp).map_err(failure_of_stamp));
                }
            }
            Job::Break(notice, reply) => {
                if !reply.is_closed() {
                    let _ = reply.send(signer.sign_break(notice).map_err(failure_of_sign));
                }
            }
            Job::Checkpoint(bodies, reply) => {
                if !reply.is_closed() {
                    let refs: Vec<&[u8]> = bodies.iter().map(Vec::as_slice).collect();
                    let _ = reply.send(signer.sign_checkpoint(&refs).map_err(failure_of_sign));
                }
            }
        }
    }
}

fn handle<K>(inner: Inner) -> SignerHandle<K> {
    SignerHandle {
        inner,
        _kind: PhantomData,
    }
}

/// START THE TWO SIGNER THREADS and mint the four typed handles. `clock` is the slot SHUTDOWN-HANG's drain
/// clock is attached to once serving starts (the checkpoint handle's armed check); empty, the
/// checkpoint handle applies only its hold-off.
pub(crate) fn spawn(
    notary: Notary,
    bootstrap: BootstrapSigner,
    clock: Arc<std::sync::OnceLock<Arc<DrainClock>>>,
) -> std::io::Result<Signers> {
    let busy = Arc::new(AtomicBool::new(false));
    let (live_tx, live_rx) = sync_channel::<LiveJob>(1);
    let (boot_tx, boot_rx) = sync_channel::<Job>(BOOTSTRAP_QUEUE);
    let live = {
        let busy = Arc::clone(&busy);
        std::thread::Builder::new()
            .name("busbar-notary-signer".into())
            .spawn(move || live_thread(notary, live_rx, busy))?
    };
    let bootstrap = std::thread::Builder::new()
        .name("busbar-audit-signer".into())
        .spawn(move || bootstrap_thread(bootstrap, boot_rx))?;
    Ok(Signers {
        live: handle::<Live>(Inner::Live { tx: live_tx, busy }),
        boot: handle::<Seal>(Inner::Boot {
            tx: boot_tx.clone(),
        }),
        sealer: handle::<Seal>(Inner::Boot {
            tx: boot_tx.clone(),
        }),
        checkpoint: handle::<Checkpoint>(Inner::Checkpoint(CheckpointSubmit {
            tx: boot_tx,
            fail_until_ms: AtomicU64::new(0),
            epoch: Instant::now(),
            clock,
        })),
        threads: SignerThreads { live, bootstrap },
    })
}
