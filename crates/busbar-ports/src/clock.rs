// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! The host's clock, the one thing the engine asks for time (GROUP-time 3.2).
//!
//! A [`Reading`] is taken once, where a wake enters our code, and passed down as a value. A
//! [`Deadline`] is an absolute point on the monotonic clock, made once from a reading. Waits are
//! absolute: [`until`] races work against a deadline, [`HostClock::block_until`] blocks a thread
//! until a deadline; both hand the caller the reading of the wake that ended them. Behind
//! [`HostClock`] sits the engine's one reader of the operating-system clock, [`os`].
//!
//! HOLD (owner, 18 Nov): the design puts that reader in `busbar_plugin_abi::host_side::clock` so the
//! plugins' host table shares its origin; the plugin boundary is frozen, so it lives here until the
//! hold lifts, and the host table keeps its own origin meanwhile.
//!
//! `HostClock` is one concrete type with two modes: the system clock, and (tests only) a manual
//! clock the test advances.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use busbar_contract::work_count::{self, Work};

pub use busbar_contract::services::Reading; // { wall_ns: u64, mono_ns: u64 }, unchanged

mod os {
    //! The engine's one reader of the operating-system clock (GROUP-time 3.2 `host_side::clock`,
    //! held here while the plugin boundary is frozen).

    use std::sync::OnceLock;
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    static ORIGIN: OnceLock<Instant> = OnceLock::new();

    /// The monotonic origin, fixed by the process's first reading.
    pub(crate) fn origin() -> Instant {
        *ORIGIN.get_or_init(Instant::now)
    }

    /// Monotonic nanoseconds since [`origin`]: the clock every deadline is stated in.
    pub(crate) fn mono() -> u64 {
        u64::try_from(origin().elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    /// UTC nanoseconds since the Unix epoch (`0` before it).
    pub(crate) fn wall() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| {
                u64::try_from(since.as_nanos()).unwrap_or(u64::MAX)
            })
    }

    /// Both clocks at one instant, as `(mono_ns, wall_ns)`.
    pub(crate) fn read() -> (u64, u64) {
        (mono(), wall())
    }
}

/// An absolute point on the host's monotonic clock, in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Deadline(u64);

impl Deadline {
    /// A deadline that never arrives.
    pub const NEVER: Deadline = Deadline(u64::MAX);
    /// A deadline that has always passed: a wait on it does not block.
    pub const PAST: Deadline = Deadline(0);

    /// The deadline at `mono_ns` on the host's monotonic clock.
    #[must_use]
    pub const fn at(mono_ns: u64) -> Deadline {
        Deadline(mono_ns)
    }

    /// `wait` after `from`, saturating. The one place a deadline is made.
    #[must_use]
    pub fn after(from: Reading, wait: Duration) -> Deadline {
        let wait = u64::try_from(wait.as_nanos()).unwrap_or(u64::MAX);
        Deadline(from.mono_ns.saturating_add(wait))
    }

    /// The deadline in monotonic nanoseconds.
    #[must_use]
    pub const fn mono_ns(self) -> u64 {
        self.0
    }

    /// Whether the deadline had passed at `at`. Reads nothing.
    #[must_use]
    pub const fn passed(self, at: Reading) -> bool {
        at.mono_ns >= self.0
    }

    /// What is left of it at `at` (zero once passed). Reads nothing.
    #[must_use]
    pub fn left(self, at: Reading) -> Duration {
        Duration::from_nanos(self.0.saturating_sub(at.mono_ns))
    }
}

/// A boxed sleep: completes when its deadline arrives.
pub type Sleep = Pin<Box<dyn Future<Output = ()> + Send>>;
/// How the composition root sleeps until an `Instant` (tokio's `sleep_until`).
pub type SleepFn = fn(Instant) -> Sleep;

/// The host's clock. A concrete type, cheap to clone. Every holder names its handle `clock`.
#[derive(Clone)]
pub struct HostClock {
    mode: Mode,
}

#[derive(Clone)]
enum Mode {
    /// The real clock: the operating system's, through `host_side::clock`.
    System(SleepFn),
    /// A clock the test drives.
    #[cfg(any(test, feature = "test-support"))]
    Manual(Manual),
}

impl core::fmt::Debug for HostClock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.mode {
            Mode::System(_) => f.write_str("HostClock(system)"),
            #[cfg(any(test, feature = "test-support"))]
            Mode::Manual(_) => f.write_str("HostClock(manual)"),
        }
    }
}

impl HostClock {
    /// The real clock. Built once, by the composition root.
    #[must_use]
    pub fn system(sleep: SleepFn) -> HostClock {
        HostClock {
            mode: Mode::System(sleep),
        }
    }

    /// The one reading of an operation that starts now.
    #[must_use]
    pub fn now(&self) -> Reading {
        match &self.mode {
            Mode::System(_) => system_now(),
            #[cfg(any(test, feature = "test-support"))]
            Mode::Manual(manual) => manual.read(),
        }
    }

    /// A sleep that completes when the monotonic clock reaches `at`. `NEVER` never completes
    /// and arms no timer.
    #[must_use]
    pub fn sleep_until(&self, at: Deadline) -> Sleep {
        if at == Deadline::NEVER {
            return Box::pin(std::future::pending());
        }
        match &self.mode {
            Mode::System(sleep) => sleep(self.instant(at)),
            #[cfg(any(test, feature = "test-support"))]
            Mode::Manual(manual) => Box::pin(ManualSleep {
                manual: manual.clone(),
                at: at.mono_ns(),
            }),
        }
    }

    /// Blocks this thread in `wait` until `wait` yields a value or the clock reaches `at`.
    /// `from` is the caller's reading of the wake it is in: the remaining time is `at.left(from)`,
    /// so nothing is read before blocking. `wait(left)` performs one bounded blocking wait (a
    /// channel receive, a condvar wait, a thread sleep) and answers `Some` when its own event woke
    /// it. With a deadline already passed at `from`, `wait` is called once with a zero duration.
    /// Takes one reading, as the wait ends, and hands it back: the next wake's reading.
    pub fn block_until<T>(
        &self,
        from: Reading,
        at: Deadline,
        mut wait: impl FnMut(Duration) -> Option<T>,
    ) -> Blocked<T> {
        match &self.mode {
            Mode::System(_) => {
                let mut r = from;
                loop {
                    let woke = wait(at.left(r));
                    r = system_now();
                    match woke {
                        Some(value) => return Blocked::Woke(value, r),
                        None if at.passed(r) => return Blocked::Due(r),
                        // The operating system ended the wait early: wait again for what is left.
                        None => {}
                    }
                }
            }
            #[cfg(any(test, feature = "test-support"))]
            Mode::Manual(manual) => match wait(Duration::ZERO) {
                Some(value) => Blocked::Woke(value, manual.read()),
                None => {
                    manual.reach(at.mono_ns());
                    Blocked::Due(manual.read())
                }
            },
        }
    }

    /// `block_until` with a plain thread sleep.
    pub fn park_until(&self, from: Reading, at: Deadline) -> Reading {
        self.block_until(from, at, |left| {
            std::thread::sleep(left);
            None::<()>
        })
        .at()
    }

    /// The `Instant` a deadline names, for libraries that take one (arithmetic on
    /// `os::origin()`; reads nothing).
    #[must_use]
    pub fn instant(&self, at: Deadline) -> Instant {
        let origin = os::origin();
        origin
            .checked_add(Duration::from_nanos(at.mono_ns()))
            .or_else(|| origin.checked_add(FAR_FUTURE))
            .unwrap_or(origin)
    }
}

/// Where `instant` puts `NEVER` (and any deadline past what an `Instant` can hold): about 136 years
/// after the origin.
const FAR_FUTURE: Duration = Duration::from_secs(1 << 32);

/// How a blocking wait ended.
#[derive(Debug)]
pub enum Blocked<T> {
    /// `wait` yielded `T`; the reading taken as it did.
    Woke(T, Reading),
    /// The clock reached the deadline; the reading that showed it (`mono_ns >= at`).
    Due(Reading),
}

impl<T> Blocked<T> {
    /// The reading the wait handed back.
    pub fn at(&self) -> Reading {
        match self {
            Blocked::Woke(_, at) | Blocked::Due(at) => *at,
        }
    }
}

/// The system reading, without a handle: for the one place that cannot be handed a clock (a
/// `Framing` driven with no reading lent, section 3.3 shape E). `HostClock::now` calls it in
/// system mode, so it is tallied like every other reading.
#[must_use]
pub fn system_now() -> Reading {
    work_count::tally(Work::ClockRead);
    let (mono_ns, wall_ns) = os::read();
    Reading { wall_ns, mono_ns }
}

/// Work that finished before its deadline, with the reading of the wake that finished it.
#[derive(Debug)]
pub struct Wake<T> {
    pub value: T,
    pub at: Reading,
}

/// The deadline arrived first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expired;

/// Run `work`, giving up when `deadline` arrives. The deadline is polled first, so an expired
/// deadline wins even when the work is also ready, and the work is not polled again after it.
pub async fn until<T>(
    clock: &HostClock,
    deadline: Deadline,
    work: impl Future<Output = T>,
) -> Result<Wake<T>, Expired> {
    let mut sleep = clock.sleep_until(deadline);
    let mut work = std::pin::pin!(work);
    let done = std::future::poll_fn(|cx| {
        if sleep.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(None);
        }
        work.as_mut().poll(cx).map(Some)
    })
    .await;
    match done {
        Some(value) => Ok(Wake {
            value,
            at: clock.now(),
        }),
        None => Err(Expired),
    }
}

#[cfg(any(test, feature = "test-support"))]
pub use manual::Manual;

#[cfg(any(test, feature = "test-support"))]
use manual::ManualSleep;

#[cfg(any(test, feature = "test-support"))]
mod manual {
    use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use super::{Deadline, HostClock, Mode, Reading};

    impl HostClock {
        /// A clock the test drives. Starts at `start`.
        #[must_use]
        pub fn manual(start: Reading) -> (HostClock, Manual) {
            let manual = Manual {
                state: Arc::new(Mutex::new(State {
                    mono_ns: start.mono_ns,
                    wall_ns: start.wall_ns,
                    reads: 0,
                    sleepers: Vec::new(),
                })),
            };
            (
                HostClock {
                    mode: Mode::Manual(manual.clone()),
                },
                manual,
            )
        }
    }

    /// The test's handle on a manual clock.
    #[derive(Clone)]
    pub struct Manual {
        state: Arc<Mutex<State>>,
    }

    struct State {
        mono_ns: u64,
        wall_ns: u64,
        reads: u64,
        /// Pending sleeps: the monotonic time each waits for, and its waker.
        sleepers: Vec<(u64, Waker)>,
    }

    impl Manual {
        fn lock(&self) -> MutexGuard<'_, State> {
            self.state.lock().unwrap_or_else(PoisonError::into_inner)
        }

        /// Move both clocks forward and wake every sleep whose deadline is now reached.
        pub fn advance(&self, by: Duration) {
            let by = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
            let woken = {
                let mut st = self.lock();
                st.mono_ns = st.mono_ns.saturating_add(by);
                st.wall_ns = st.wall_ns.saturating_add(by);
                st.due()
            };
            woken.into_iter().for_each(Waker::wake);
        }

        /// Step the wall clock alone (a clock adjustment).
        pub fn set_wall(&self, wall_ns: u64) {
            self.lock().wall_ns = wall_ns;
        }

        /// How many readings (`now`, and the readings `block_until` and `until` hand back) were taken.
        #[must_use]
        pub fn reads(&self) -> u64 {
            self.lock().reads
        }

        /// One reading: the test's time, counted.
        pub(super) fn read(&self) -> Reading {
            let mut st = self.lock();
            st.reads += 1;
            Reading {
                wall_ns: st.wall_ns,
                mono_ns: st.mono_ns,
            }
        }

        /// A blocking wait that yielded nothing: time jumps to `at` (never backwards).
        pub(super) fn reach(&self, at: u64) {
            let woken = {
                let mut st = self.lock();
                if st.mono_ns < at {
                    let by = at - st.mono_ns;
                    st.mono_ns = at;
                    st.wall_ns = st.wall_ns.saturating_add(by);
                }
                st.due()
            };
            woken.into_iter().for_each(Waker::wake);
        }
    }

    impl State {
        /// Takes the wakers of every sleep the time has reached.
        fn due(&mut self) -> Vec<Waker> {
            let now = self.mono_ns;
            let mut woken = Vec::new();
            self.sleepers.retain(|(at, waker)| {
                if *at <= now {
                    woken.push(waker.clone());
                    false
                } else {
                    true
                }
            });
            woken
        }
    }

    /// A sleep on the manual clock: done once the test's time reaches `at`.
    pub(super) struct ManualSleep {
        pub(super) manual: Manual,
        pub(super) at: u64,
    }

    impl core::future::Future for ManualSleep {
        type Output = ();

        fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            let mut st = self.manual.lock();
            if Deadline::at(self.at).passed(Reading {
                wall_ns: st.wall_ns,
                mono_ns: st.mono_ns,
            }) {
                return Poll::Ready(());
            }
            st.sleepers.push((self.at, cx.waker().clone()));
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests;
