// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;
use busbar_contract::abi::mechanism::KindCode;
use busbar_contract::abi::plane::{
    slot as plane_slot, OnPieceIn, OnPieceOut, EMIT_DONE, PIECE_FINAL, PIECE_REFUSED, VERDICT_RETRY,
};
use busbar_contract::plane_calls::Cancelled;
use tokio::sync::oneshot;

#[derive(Clone, Copy)]
enum End {
    Completed,
    Cancelled { disposition: u32 },
    Fault,
}

impl End {
    fn answer(self) -> Option<Cancelled> {
        match self {
            Self::Cancelled { disposition } => Some(Cancelled {
                disposition,
                writes: Vec::new(),
            }),
            Self::Completed | Self::Fault => None,
        }
    }

    fn crossed(self, timeout: Outcome) -> Crossed {
        match self {
            Self::Fault => Crossed::host(Outcome::Fault),
            Self::Completed => Crossed::host(timeout),
            Self::Cancelled { disposition } => Crossed {
                disposition: Some(disposition),
                ..Crossed::host(timeout)
            },
        }
    }
}

pub(super) struct Binding {
    instance: Arc<Instance>,
    unit: u64,
    end: Option<End>,
    final_answer: bool,
}

impl Binding {
    fn matches(&self, instance: &Arc<Instance>, unit: u64) -> bool {
        self.unit == unit && Arc::ptr_eq(&self.instance, instance)
    }

    pub(super) fn closed(&self) -> bool {
        self.end.is_some()
    }
}

impl Drop for Binding {
    fn drop(&mut self) {
        hold_past_lock(&self.instance);
    }
}

pub(crate) struct Waiter(Option<oneshot::Sender<Option<Cancelled>>>);

impl Waiter {
    fn closed(&self) -> bool {
        self.0.as_ref().is_none_or(oneshot::Sender::is_closed)
    }

    fn finish(mut self, answer: Option<Cancelled>) {
        if let Some(sender) = self.0.take() {
            drop_after_lock(Box::new(Completion {
                sender: Some(sender),
                answer,
            }));
        }
    }
}

impl Drop for Waiter {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            drop_after_lock(Box::new(Completion {
                sender: Some(sender),
                answer: None,
            }));
        }
    }
}

struct Completion {
    sender: Option<oneshot::Sender<Option<Cancelled>>>,
    answer: Option<Cancelled>,
}

impl Drop for Completion {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(self.answer.take());
        }
    }
}

pub(super) fn key<I: InFrame>(instance: &Instance, slot: u32, input: &I) -> Option<u64> {
    (instance.kind == KindCode::Plane)
        .then(|| (instance.unit_of)(slot, std::ptr::from_ref(input).cast(), size_of::<I>()))
        .flatten()
        .filter(|unit| *unit != 0)
}

pub(super) fn final_piece<I: InFrame>(instance: &Instance, slot: u32, input: &I) -> bool {
    if instance.kind != KindCode::Plane
        || slot != plane_slot::ON_PIECE
        || size_of::<I>() < size_of::<OnPieceIn>()
    {
        return false;
    }
    // SAFETY: this is the host-owned complete input frame, not a plugin-reported pointer.
    unsafe {
        std::ptr::from_ref(input)
            .cast::<OnPieceIn>()
            .read_unaligned()
    }
    .flags
        & PIECE_FINAL
        != 0
}

pub(super) fn closes<I: InFrame, O: OutFrame>(
    instance: &Instance,
    slot: u32,
    frame: &Frame<I, O>,
    final_answer: bool,
) -> bool {
    if instance.kind != KindCode::Plane
        || slot != plane_slot::ON_PIECE
        || size_of::<I>() < size_of::<OnPieceIn>()
        || size_of::<O>() < size_of::<OnPieceOut>()
    {
        return false;
    }
    // SAFETY: only called after the crossing returned and its complete answer was validated.
    let input = unsafe {
        std::ptr::from_ref(&frame.input)
            .cast::<OnPieceIn>()
            .read_unaligned()
    };
    let out = unsafe {
        std::ptr::from_ref(&frame.out)
            .cast::<OnPieceOut>()
            .read_unaligned()
    };
    out.flags & EMIT_DONE != 0
        && out.more == 0
        && input.flags & PIECE_REFUSED == 0
        && (out.verdict != VERDICT_RETRY || final_answer)
}

impl Worker {
    pub(super) fn bind_unit_entry(
        &self,
        st: &mut WorkerState,
        ticket: Ticket,
        instance: &Arc<Instance>,
        unit: u64,
    ) -> bool {
        if instance.kind != KindCode::Plane || unit == 0 {
            return false;
        }
        let (end, final_answer) = st
            .entries
            .iter()
            .filter_map(|e| e.unit_binding.as_ref())
            .filter(|b| b.matches(instance, unit))
            .fold((None, false), |(end, final_answer), b| {
                (end.or(b.end), final_answer || b.final_answer)
            });
        let Some((_, entry)) = self.entry(st, ticket) else {
            return false;
        };
        if let Some(binding) = &entry.unit_binding {
            return binding.matches(instance, unit);
        }
        entry.unit_binding = Some(Binding {
            instance: Arc::clone(instance),
            unit,
            end,
            final_answer,
        });
        true
    }

    pub(super) fn accept_unit(&self, st: &mut WorkerState, ticket: Ticket, meta: &Meta) -> bool {
        let Some(unit) = meta.unit_key else {
            return true;
        };
        if !self.bind_unit_entry(st, ticket, &meta.instance, unit) {
            return false;
        }
        if meta.unit_final {
            for entry in &mut st.entries {
                if let Some(binding) = entry
                    .unit_binding
                    .as_mut()
                    .filter(|b| b.matches(&meta.instance, unit))
                {
                    binding.final_answer = true;
                }
            }
        }
        self.entry(st, ticket)
            .is_some_and(|(_, e)| e.unit_binding.as_ref().is_some_and(|b| !b.closed()))
    }

    pub(super) fn request_unit_cancel(
        &self,
        st: &mut WorkerState,
        ticket: Ticket,
        instance: &Arc<Instance>,
        unit: u64,
        waiter: Waiter,
    ) {
        let Some((idx, entry)) = self.entry(st, ticket) else {
            waiter.finish(None);
            return;
        };
        let Some(binding) = entry
            .unit_binding
            .as_ref()
            .filter(|b| b.matches(instance, unit))
        else {
            waiter.finish(None);
            return;
        };
        if let Some(end) = binding.end {
            waiter.finish(end.answer());
            return;
        }
        entry.unit_waiters.push(waiter);
        Self::schedule(st, idx, Action::Cancel);
    }

    fn unit_members(&self, st: &WorkerState, instance: &Arc<Instance>, unit: u64) -> Vec<u32> {
        st.entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.live
                    && entry
                        .unit_binding
                        .as_ref()
                        .is_some_and(|b| b.matches(instance, unit))
            })
            .map(|(idx, _)| idx as u32)
            .collect()
    }

    fn retire_unit(
        &self,
        st: &mut WorkerState,
        members: &[u32],
        primary: u32,
        retirement: (End, Vec<busbar_contract::plane_calls::CancelWrite>),
        keep_primary: bool,
        env: &Env,
    ) {
        let (end, mut writes) = retirement;
        let mut waiters = Vec::new();
        for &idx in members {
            let entry = &mut st.entries[idx as usize];
            if let Some(binding) = &mut entry.unit_binding {
                binding.end = Some(end);
            }
            entry.latched = false;
            entry.next = None;
            entry.short_slot = None;
            entry.short_reply = None;
            waiters.append(&mut entry.unit_waiters);
        }
        let owner = waiters.iter().position(|w| !w.closed());
        for (position, waiter) in waiters.into_iter().enumerate() {
            let mut answer = end.answer();
            if owner == Some(position) {
                if let Some(answer) = &mut answer {
                    answer.writes = std::mem::take(&mut writes);
                }
            }
            waiter.finish(answer);
        }
        let mut primary_written = owner.is_some();
        for &idx in members {
            let queued = std::mem::take(&mut st.entries[idx as usize].queue);
            let has_current = st.entries[idx as usize].current.is_some();
            if has_current && !(keep_primary && idx == primary) {
                let timeout = st.entries[idx as usize]
                    .current
                    .as_ref()
                    .expect("current unit op")
                    .meta
                    .instance
                    .timeout;
                let mut crossed = end.crossed(timeout);
                if idx == primary && !primary_written {
                    crossed.cancel_writes = std::mem::take(&mut writes);
                    primary_written = true;
                }
                self.end(st, idx, crossed, env);
            }
            for (mut meta, job) in queued {
                meta.give_back();
                let mut crossed = end.crossed(meta.instance.timeout);
                if idx == primary && !primary_written {
                    crossed.cancel_writes = std::mem::take(&mut writes);
                    primary_written = true;
                }
                job.finish(crossed, None);
                drop(meta);
            }

            if st.entries[idx as usize].current.is_none()
                && st.entries[idx as usize].recycle_when_idle
            {
                self.recycle_now(st, idx, env);
            }
        }
    }

    pub(super) fn cancel_unit_group<'a>(
        &'a self,
        mut st: MutexGuard<'a, WorkerState>,
        primary: u32,
        env: &Env,
    ) -> Option<MutexGuard<'a, WorkerState>> {
        let binding = st.entries[primary as usize].unit_binding.as_ref()?;
        let instance = Arc::clone(&binding.instance);
        let unit = binding.unit;
        let members = self.unit_members(&st, &instance, unit);
        if let Some(end) = binding.end {
            self.retire_unit(&mut st, &members, primary, (end, Vec::new()), false, env);
            return Some(st);
        }
        let ticket = self.ticket(primary, st.entries[primary as usize].generation);
        let framing = st.entries[primary as usize]
            .current
            .as_ref()
            .and_then(|c| c.meta.framing.clone());
        let class = st.entries[primary as usize]
            .current
            .as_ref()
            .map_or(DeadlineClass::Stream, |c| c.meta.class);
        let mut jobs = Vec::new();
        let mut loans = Vec::new();
        for &idx in &members {
            let entry = &mut st.entries[idx as usize];
            entry.unit_binding.as_mut().expect("bound unit").end = Some(End::Fault);
            entry.next = None;
            entry.latched = false;
            if let Some(current) = &mut entry.current {
                current.pending = false;
                if let Some(job) = current.job.take() {
                    jobs.push((idx, job));
                }
            }

            loans.extend(entry.queue.iter().filter_map(|(_, job)| job.keep_lent()));
        }
        let mut frame = (instance.cancel_frame)();
        frame.name_unit(unit);
        let heads = frame.prepare(ticket, class as u8);
        let crossed = if instance.faulted.load(Ordering::Acquire) {
            Crossed::host(Outcome::Fault)
        } else {
            let (back, crossed) = self.cross(
                st,
                &instance,
                slot::CANCEL,
                heads,
                env.budgets.of(slot::CANCEL, class),
                framing.clone(),
            )?;
            st = back;
            crossed
        };
        let _lease = UnhandedLease::new(&instance, framing, crossed.lease);
        let end = if crossed.outcome == Outcome::Ready {
            End::Cancelled {
                disposition: frame.disposition(),
            }
        } else {
            End::Fault
        };
        let writes = if crossed.outcome == Outcome::Ready {
            frame.writes()
        } else {
            Vec::new()
        };
        for (idx, job) in jobs {
            if let Some(current) = st.entries[idx as usize].current.as_mut() {
                current.job = Some(job);
            } else {
                drop_after_lock(Box::new(job));
            }
        }
        drop_after_lock(Box::new(loans));
        drop_after_lock(Box::new(frame));
        self.retire_unit(&mut st, &members, primary, (end, writes), false, env);
        hold_past_lock(&instance);
        Some(st)
    }

    pub(super) fn finish_unit_answer(
        &self,
        st: &mut WorkerState,
        primary: u32,
        crossed: &Crossed,
        env: &Env,
    ) {
        let Some(binding) = st.entries[primary as usize].unit_binding.as_ref() else {
            return;
        };
        let instance = Arc::clone(&binding.instance);
        let unit = binding.unit;
        let members = self.unit_members(st, &instance, unit);
        let final_answer = members.iter().any(|&idx| {
            st.entries[idx as usize]
                .unit_binding
                .as_ref()
                .is_some_and(|b| b.final_answer)
        });
        let terminal = crossed.outcome == Outcome::Ready
            && st.entries[primary as usize]
                .current
                .as_ref()
                .and_then(|c| c.job.as_ref().map(|job| (c.meta.slot, job)))
                .is_some_and(|(slot, job)| job.closes_unit(slot, final_answer));
        if !terminal {
            return;
        }
        self.retire_unit(
            st,
            &members,
            primary,
            (End::Completed, Vec::new()),
            true,
            env,
        );
        hold_past_lock(&instance);
    }
}

#[cfg(test)]
#[path = "worker_unit_cancel_tests.rs"]
mod tests;

pub(super) fn group_orphans(
    worker: &Worker,
    gone: Vec<Entry>,
    wedged: &Arc<Instance>,
) -> (Vec<Orphan>, Vec<Entry>) {
    let mut entries: Vec<_> = gone
        .into_iter()
        .enumerate()
        .map(|(idx, entry)| Some((worker.ticket(idx as u32, entry.generation), entry)))
        .collect();
    let mut orphans = Vec::new();
    for idx in 0..entries.len() {
        let Some((_, entry)) = &entries[idx] else {
            continue;
        };
        let pending = entry.driver.is_none()
            && entry.current.as_ref().is_some_and(|current| {
                current.pending
                    && current.job.is_some()
                    && !Arc::ptr_eq(&current.meta.instance, wedged)
                    && !current.meta.instance.faulted.load(Ordering::Acquire)
            });
        if !pending {
            continue;
        }
        let key = entry
            .unit_binding
            .as_ref()
            .map(|binding| (Arc::clone(&binding.instance), binding.unit));
        let mut group = vec![entries[idx].take().expect("pending orphan")];
        if let Some((instance, unit)) = key {
            for sibling in &mut entries {
                if sibling.as_ref().is_some_and(|(_, entry)| {
                    entry
                        .unit_binding
                        .as_ref()
                        .is_some_and(|b| b.matches(&instance, unit))
                }) {
                    group.push(sibling.take().expect("bound sibling"));
                }
            }
        }
        orphans.push(Orphan { entries: group });
    }
    let rest = entries
        .into_iter()
        .flatten()
        .map(|(ticket, entry)| {
            for id in &entry.conns {
                drop(crate::dispatch::conn_services::forget(*id, ticket));
            }
            entry
        })
        .collect();
    (orphans, rest)
}

pub(super) fn cancel_orphan(mut orphan: Orphan) {
    let (ticket, entry) = &mut orphan.entries[0];
    let Some(current) = entry.current.as_mut() else {
        return;
    };
    let instance = Arc::clone(&current.meta.instance);
    let unit = entry.unit_binding.as_ref().map(|b| b.unit).or_else(|| {
        current.job.as_mut().and_then(|job| {
            let (input, _, _) = job.heads();
            (instance.unit_of)(
                current.meta.slot,
                input.cast_const(),
                current.meta.in_size as usize,
            )
        })
    });
    let cancel = || {
        instance.cancel_abandoned(
            *ticket,
            current.meta.class,
            unit,
            current.meta.framing.clone(),
        )
    };
    let crossed = match &current.meta.tracing {
        Some(tracing) => tracing.in_scope(cancel),
        None => cancel(),
    };
    if crossed.outcome != Outcome::Ready {
        tracing::warn!(plugin = %instance.name(), outcome = ?crossed.outcome,
            "the cancel of a unit orphaned by a replaced worker did not answer READY");
    }
    let end = if crossed.outcome == Outcome::Ready {
        End::Cancelled {
            disposition: crossed.disposition.unwrap_or(0),
        }
    } else {
        End::Fault
    };
    let mut writes = crossed.cancel_writes;
    let mut primary = true;
    for (_, entry) in &mut orphan.entries {
        for waiter in std::mem::take(&mut entry.unit_waiters) {
            waiter.finish(None);
        }
        if let Some(mut current) = entry.current.take() {
            current.meta.give_back();
            if let Some(job) = current.job.take() {
                let mut answer = end.crossed(Outcome::Fault);
                if primary {
                    answer.cancel_writes = std::mem::take(&mut writes);
                    primary = false;
                }
                job.finish(answer, None);
            }
        }
        for (mut meta, job) in std::mem::take(&mut entry.queue) {
            meta.give_back();
            job.finish(end.crossed(Outcome::Fault), None);
        }
    }
}

pub(super) fn fault_orphan_replies(orphan: &mut Orphan) {
    for (_, entry) in &mut orphan.entries {
        if let Some(current) = &entry.current {
            current.meta.reply.settle(Outcome::Fault, false);
        }
        for (meta, _) in &entry.queue {
            meta.reply.settle(Outcome::Fault, false);
        }
        for waiter in std::mem::take(&mut entry.unit_waiters) {
            waiter.finish(None);
        }
    }
}

impl Dispatcher {
    pub(crate) fn bind_plane_unit<K: Kind>(&self, plugin: &Plugin<K>, ticket: Ticket, unit: u64) {
        if !self.adopt(&plugin.inner) {
            return;
        }
        self.pool.send(
            ticket,
            Msg::BindUnit {
                ticket,
                instance: Arc::clone(&plugin.inner),
                unit,
            },
        );
    }

    pub(crate) fn cancel_plane_unit<K: Kind>(
        &self,
        plugin: &Plugin<K>,
        ticket: Ticket,
        unit: u64,
    ) -> Pin<Box<dyn Future<Output = Option<Cancelled>> + Send>> {
        if !self.adopt(&plugin.inner) {
            return Box::pin(async { None });
        }
        let (sender, receiver) = oneshot::channel();
        self.pool.send(
            ticket,
            Msg::CancelUnit {
                ticket,
                instance: Arc::clone(&plugin.inner),
                unit,
                waiter: Waiter(Some(sender)),
            },
        );
        Box::pin(async move { receiver.await.unwrap_or(None) })
    }
}
