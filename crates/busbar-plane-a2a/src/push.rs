// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! PUSH DELIVERY, IN PLANE MEMORY (`BUSBAR-1.6.0.md`, the a2a plane rulings: push delivery retries
//! at most three times, 250/500 ms ±20 %, on a transport error, 5xx or 429 only, on an async timer,
//! holding no slot, re-running the destination judge on every attempt; event-stream sink delivery
//! through a per-task ordered bounded queue, 64, drop-oldest, counted).
//!
//! Everything here is sans I/O. The instance holds one [`Deliveries`] and one [`Tokens`]:
//!
//! * [`Deliveries::enqueue`] files a notification behind its task's earlier ones; past
//!   [`QUEUE_CAPACITY`] the oldest waiting one is dropped and counted.
//! * [`Deliveries::due`] hands out, per task, only the HEAD of its queue, once its time has come and
//!   while no attempt on it is open, so a task's notifications reach the receiver in the order its
//!   state changed.
//! * Each attempt re-runs the destination judge, then dials the plane's outbound `open-web` need
//!   ([`crate::door::NEED_OPEN_WEB`]) with [`request`]; its end is [`Attempted`].
//! * [`Deliveries::settle`] pops the head, or puts it back with its next time when the end is
//!   retryable and attempts remain. [`Deliveries::next_tick_ns`] is the lifecycle tick's
//!   `next_tick_ns`: nothing waits on a slot or a thread between attempts.
//!
//! Before each dial, [`Deliveries::rebound`] keeps predev's anti-rebinding rule: the destination's
//! fresh addresses must overlap those an earlier delivery to it reached ([`Deliveries::reached`]),
//! a bounded set in plane memory.
//!
//! The caller's webhook credential ([`DeliveryAuth`]) is held here, never persisted and never
//! printed, and joins the request only after the judge has passed. busbar's own callback token
//! ([`Tokens`]) is a capability for one task, minted from the kernel's random bytes, checked in
//! constant time, and never logged or audited.

use std::collections::{BTreeMap, VecDeque};
use std::fmt::Write as _;

use busbar_contract::abi::sdk::exchange::Request;
use busbar_contract::abi::sdk::publish::Keyed;
use busbar_contract::vocab;

use crate::a2a::task::Task;

/// At most this many attempts for one notification: the first and up to two retries.
pub const MAX_ATTEMPTS: u32 = 3;

/// The wait before the 2nd and the 3rd attempt, before jitter, milliseconds.
pub const RETRY_DELAYS_MS: [u64; (MAX_ATTEMPTS - 1) as usize] = [250, 500];

/// The jitter on each wait, in percent either way.
pub const JITTER_PERCENT: u64 = 20;

/// The most notifications one task's queue holds; past it, the oldest waiting one is dropped.
pub const QUEUE_CAPACITY: usize = 64;

/// The most callback tokens one instance holds; past it, no token is minted (and busbar registers
/// no callback of its own with that backend).
pub const MAX_TOKENS: usize = 4096;

/// The random bytes behind one callback token: written as 64 lower-case hex digits after
/// `<task-id>.`, the wire shape of predev's `<task-id>.<hex HMAC-SHA256>`.
pub const TOKEN_BYTES: usize = 32;

/// The scheme busbar's callback token rides on: registered as the config's
/// `authentication.scheme` (its `credentials` = the token), presented back as
/// `Authorization: Bearer <token>`.
pub const TOKEN_SCHEME: &str = "Bearer";

/// The most destinations whose reached addresses one instance holds; past it, the oldest-keyed one
/// is dropped, and its next delivery is judged as a first one (never unjudged).
pub const MAX_DESTINATIONS: usize = 4096;

/// The most reached addresses held for one destination.
pub const MAX_REACHED: usize = 16;

/// The field every delivery carries, and its value.
pub const CONTENT_TYPE: (&str, &str) = ("content-type", "application/json");

/// The field a webhook credential is presented on.
pub const AUTHORIZATION: &str = "authorization";

/// THE A2A PUSH NOTIFICATION BODY: a `StreamResponse` with the task nested under `"task"`, under
/// busbar's ids. Not a JSON-RPC envelope: the receiver is not a JSON-RPC peer and correlates on
/// the task id (A2A 4.3.3). `status.timestamp` is RFC 3339, as every revision types it.
#[must_use]
pub fn notification_body(task: &Task) -> Vec<u8> {
    let doc = serde_json::json!({
        "task": {
            "id": task.task_id,
            "contextId": task.context_id,
            "kind": "task",
            "status": {
                "state": task.state.as_str(),
                "timestamp": busbar_contract::civil::rfc3339_from_secs(task.updated_at),
            },
        }
    });
    serde_json::to_vec(&doc).unwrap_or_default()
}

/// THE CREDENTIAL THE CALLER ASKED BUSBAR TO PRESENT AT ITS WEBHOOK. The caller's own secret for
/// the caller's own receiver: never logged, never echoed on a read verb, never persisted.
#[derive(Clone, PartialEq, Eq)]
pub struct DeliveryAuth {
    /// The HTTP authentication scheme, as the caller wrote it.
    pub scheme: String,
    /// The credential itself.
    pub credentials: String,
}

impl DeliveryAuth {
    /// The `Authorization` value: `<scheme> <credentials>`, or the bare scheme when there are none.
    #[must_use]
    pub fn header_value(&self) -> String {
        if self.credentials.is_empty() {
            self.scheme.clone()
        } else {
            format!("{} {}", self.scheme, self.credentials)
        }
    }
}

/// Written, not derived: the credential never reaches a log line, an assert message or a panic.
impl std::fmt::Debug for DeliveryAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DeliveryAuth {{ scheme: {:?}, credentials: <redacted> }}",
            self.scheme
        )
    }
}

/// How one attempt ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attempted {
    /// The receiver answered 2xx.
    Delivered,
    /// The destination judge refused (its `DEST_*` verdict); nothing went out.
    Judged(u64),
    /// The destination now resolves only to addresses no earlier delivery reached (a rebinding);
    /// nothing went out.
    Moved,
    /// The connection or the exchange failed.
    Transport,
    /// The receiver answered this non-2xx status.
    Status(u16),
}

impl Attempted {
    /// The end of an exchange that reached a receiver.
    #[must_use]
    pub const fn of_status(status: u16) -> Self {
        match status {
            200..=299 => Self::Delivered,
            s => Self::Status(s),
        }
    }

    /// Worth another attempt: a transport error, a 5xx or a 429. A judge refusal or any other 4xx
    /// would answer the same "no" again.
    #[must_use]
    pub const fn retryable(self) -> bool {
        match self {
            Self::Transport | Self::Status(429) => true,
            Self::Status(s) => matches!(s, 500..=599),
            Self::Delivered | Self::Judged(_) | Self::Moved => false,
        }
    }

    /// The task-chain record kind the attempt files: delivered, refused before anything went out,
    /// or failed at the receiver.
    #[must_use]
    pub const fn record_kind(self) -> &'static str {
        match self {
            Self::Delivered => vocab::EV_PUSH_DELIVERED,
            Self::Judged(_) | Self::Moved => vocab::EV_PUSH_REFUSED,
            Self::Transport | Self::Status(_) => vocab::EV_PUSH_FAILED,
        }
    }
}

/// `base_ms` moved by up to ±[`JITTER_PERCENT`], `byte` (a random byte) choosing where: `0` is the
/// low end, `255` the high end.
#[must_use]
pub fn jittered_ms(base_ms: u64, byte: u8) -> u64 {
    let span = 2 * JITTER_PERCENT;
    base_ms * (100 - JITTER_PERCENT + span * u64::from(byte) / 255) / 100
}

/// One notification to deliver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    /// The task it is about.
    pub task_id: String,
    /// The caller's callback URL.
    pub url: String,
    /// The body ([`notification_body`]).
    pub body: Vec<u8>,
    /// The task had reached a terminal state: the last delivery it gets.
    pub terminal: bool,
}

impl Delivery {
    /// The notification for `task`, when it has a callback.
    #[must_use]
    pub fn of(task: &Task) -> Option<Self> {
        Some(Self {
            task_id: task.task_id.clone(),
            url: task.push_callback.clone()?,
            body: notification_body(task),
            terminal: task.state.is_terminal(),
        })
    }
}

/// One queued notification and where its attempts stand.
#[derive(Debug)]
struct Waiting {
    delivery: Delivery,
    attempts: u32,
    not_before_ns: u64,
    open: bool,
}

/// The instance's push book: the queues, the drops, the credentials.
#[derive(Debug, Default)]
struct Book {
    queues: BTreeMap<String, VecDeque<Waiting>>,
    dropped: u64,
    auths: BTreeMap<String, DeliveryAuth>,
    reached: BTreeMap<String, Vec<String>>,
}

/// What [`Deliveries::settle`] did with the head of a task's queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Settled {
    /// It is done (delivered, refused, or out of attempts): the record kind to file.
    Done(&'static str),
    /// It waits for another attempt at this time.
    Retry(u64),
    /// No attempt was open on that task.
    Unknown,
}

/// THE INSTANCE'S DELIVERIES, held in plane memory (never process-global).
#[derive(Debug, Default)]
pub struct Deliveries {
    book: Keyed<(), Book>,
}

impl Deliveries {
    /// None queued.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn with<R>(&self, f: impl FnOnce(&mut Book) -> R) -> R {
        self.book
            .with_all(|m| f(m.entry(()).or_insert_with(Book::default)))
    }

    /// File `delivery` behind its task's earlier ones. Answers whether the oldest waiting one was
    /// dropped (and counted) to make room. An attempt in progress is never the one dropped.
    pub fn enqueue(&self, delivery: Delivery, now_ns: u64) -> bool {
        self.with(|b| {
            let queue = b.queues.entry(delivery.task_id.clone()).or_default();
            let mut dropped = false;
            if queue.len() >= QUEUE_CAPACITY {
                let oldest = usize::from(queue.front().is_some_and(|w| w.open));
                dropped = queue.remove(oldest).is_some();
                b.dropped += u64::from(dropped);
            }
            queue.push_back(Waiting {
                delivery,
                attempts: 0,
                not_before_ns: now_ns,
                open: false,
            });
            dropped
        })
    }

    /// How many notifications were dropped from full queues.
    #[must_use]
    pub fn dropped(&self) -> u64 {
        self.with(|b| b.dropped)
    }

    /// How many notifications `task_id`'s queue holds.
    #[must_use]
    pub fn depth(&self, task_id: &str) -> usize {
        self.with(|b| b.queues.get(task_id).map_or(0, VecDeque::len))
    }

    /// The deliveries to attempt now: each task's head, when its time has come and no attempt on
    /// it is open. Each is marked open until [`Deliveries::settle`].
    #[must_use]
    pub fn due(&self, now_ns: u64) -> Vec<Delivery> {
        self.with(|b| {
            b.queues
                .values_mut()
                .filter_map(VecDeque::front_mut)
                .filter(|w| !w.open && w.not_before_ns <= now_ns)
                .map(|w| {
                    w.open = true;
                    w.attempts += 1;
                    w.delivery.clone()
                })
                .collect()
        })
    }

    /// Settle the open attempt on `task_id`'s head: done, or back in the queue for its next
    /// attempt (`jitter` is a random byte, [`jittered_ms`]). A terminal task's last delivery
    /// forgets its credential.
    pub fn settle(&self, task_id: &str, end: Attempted, now_ns: u64, jitter: u8) -> Settled {
        self.with(|b| {
            let Some(queue) = b.queues.get_mut(task_id) else {
                return Settled::Unknown;
            };
            let Some(head) = queue.front_mut().filter(|w| w.open) else {
                return Settled::Unknown;
            };
            head.open = false;
            if end.retryable() && head.attempts < MAX_ATTEMPTS {
                let wait = jittered_ms(RETRY_DELAYS_MS[(head.attempts - 1) as usize], jitter);
                head.not_before_ns = now_ns.saturating_add(wait.saturating_mul(1_000_000));
                return Settled::Retry(head.not_before_ns);
            }
            let terminal = queue.pop_front().is_some_and(|w| w.delivery.terminal);
            if queue.is_empty() {
                b.queues.remove(task_id);
            }
            if terminal {
                b.auths.remove(task_id);
            }
            Settled::Done(end.record_kind())
        })
    }

    /// When the lifecycle tick is next wanted: the earliest head no attempt is open on; `0` when
    /// none waits.
    #[must_use]
    pub fn next_tick_ns(&self) -> u64 {
        self.with(|b| {
            b.queues
                .values()
                .filter_map(VecDeque::front)
                .filter(|w| !w.open)
                .map(|w| w.not_before_ns.max(1))
                .min()
                .unwrap_or(0)
        })
    }

    /// predev's anti-rebinding rule, before a dial: `fresh` (the addresses the destination `url`
    /// resolves to now, each already judged) must share at least one address with those an earlier
    /// delivery to `url` reached. `None` = nothing reached before (a first delivery, a restart, or a
    /// dropped entry): the judge alone decides. `Some(Attempted::Moved)` = refused, nothing goes out.
    #[must_use]
    pub fn rebound(&self, url: &str, fresh: &[String]) -> Option<Attempted> {
        self.with(|b| {
            let before = b.reached.get(url)?;
            (!fresh.iter().any(|a| before.contains(a))).then_some(Attempted::Moved)
        })
    }

    /// Record the addresses a delivery to `url` reached (after its request went out), replacing the
    /// earlier set, so the next delivery must overlap them. Bounded by [`MAX_REACHED`] per
    /// destination and [`MAX_DESTINATIONS`] in all.
    pub fn reached(&self, url: &str, addrs: &[String]) {
        if addrs.is_empty() {
            return;
        }
        self.with(|b| {
            if !b.reached.contains_key(url) && b.reached.len() >= MAX_DESTINATIONS {
                b.reached.pop_first();
            }
            let kept = addrs.iter().take(MAX_REACHED).cloned().collect();
            b.reached.insert(url.to_string(), kept);
        });
    }

    /// Hold the credential `task_id`'s receiver wants presented; `None` drops the one held (a
    /// replaced config that names none has withdrawn it).
    pub fn remember_auth(&self, task_id: &str, auth: Option<DeliveryAuth>) {
        self.with(|b| match auth {
            Some(a) => b.auths.insert(task_id.to_string(), a),
            None => b.auths.remove(task_id),
        });
    }

    /// The request for `delivery`, its credential attached. Call it only once the destination
    /// judge has passed: no refused destination ever sees the credential.
    #[must_use]
    pub fn request(&self, delivery: &Delivery) -> Request {
        let auth = self.with(|b| b.auths.get(&delivery.task_id).cloned());
        request(delivery, auth.as_ref())
    }
}

/// The POST one delivery sends: the callback's path and query as the target, the content type,
/// the caller's credential when it gave one, and the body.
#[must_use]
pub fn request(delivery: &Delivery, auth: Option<&DeliveryAuth>) -> Request {
    let target = url::Url::parse(&delivery.url).map_or_else(
        |_| "/".to_string(),
        |u| match u.query() {
            Some(q) => format!("{}?{q}", u.path()),
            None => u.path().to_string(),
        },
    );
    let mut fields = vec![(
        CONTENT_TYPE.0.as_bytes().to_vec(),
        CONTENT_TYPE.1.as_bytes().to_vec(),
    )];
    if let Some(auth) = auth {
        fields.push((
            AUTHORIZATION.as_bytes().to_vec(),
            auth.header_value().into_bytes(),
        ));
    }
    Request {
        method: b"POST".to_vec(),
        target: target.into_bytes(),
        fields,
        body: delivery.body.clone(),
        timeout_ms: 0,
    }
}

/// BUSBAR'S OWN CALLBACK TOKENS: `<task-id>.<hex>`, one per task, from the kernel's random bytes.
/// A capability for that task alone; held in plane memory, so a restart refuses every earlier one.
#[derive(Debug, Default)]
pub struct Tokens {
    by_task: Keyed<String, String>,
}

impl Tokens {
    /// None minted.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The token for `task_id` over `random` ([`TOKEN_BYTES`] from `random.fill`): the one already
    /// held, or a new one; `None` past [`MAX_TOKENS`] or with too few bytes.
    #[must_use]
    pub fn mint(&self, task_id: &str, random: &[u8]) -> Option<String> {
        if task_id.is_empty() || random.len() < TOKEN_BYTES {
            return None;
        }
        let secret = self.by_task.with_all(|m| {
            if let Some(held) = m.get(task_id) {
                return Some(held.clone());
            }
            if m.len() >= MAX_TOKENS {
                return None;
            }
            let mut fresh = String::with_capacity(2 * TOKEN_BYTES);
            for b in &random[..TOKEN_BYTES] {
                let _ = write!(fresh, "{b:02x}");
            }
            m.insert(task_id.to_string(), fresh.clone());
            Some(fresh)
        })?;
        Some(format!("{task_id}.{secret}"))
    }

    /// The task a presented token names, or `None` for every way it can fail to name one (one
    /// answer for all, so a task id cannot be confirmed by probing). Compared in constant time.
    #[must_use]
    pub fn task_of(&self, presented: &str) -> Option<String> {
        let (task_id, secret) = presented.rsplit_once('.')?;
        let held = self.by_task.get(&task_id.to_string())?;
        busbar_contract::constant_time_eq(&held, secret).then(|| task_id.to_string())
    }

    /// The task an `Authorization` value (`Bearer <token>`, the scheme case-insensitive) names,
    /// or `None` for a missing, foreign-scheme or refused token ([`Tokens::task_of`]).
    #[must_use]
    pub fn task_of_authorization(&self, authorization: &str) -> Option<String> {
        let (scheme, token) = authorization.split_once(' ')?;
        if !scheme.eq_ignore_ascii_case(TOKEN_SCHEME) {
            return None;
        }
        self.task_of(token.trim())
    }

    /// Drop `task_id`'s token (its task reached a terminal state).
    pub fn forget(&self, task_id: &str) {
        self.by_task.remove(&task_id.to_string());
    }
}

#[cfg(test)]
#[path = "tests/push.rs"]
mod tests;
