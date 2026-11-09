// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Typed pre-open Store session adoption. All native work stays in the existing
//! ticket/connection owner; completed SHORT results are never executed again.

use super::*;
use crate::abi::mechanism::call::{
    Blob, BLOB_ABSENT, BLOB_JSON, BLOB_OCTETS, BLOB_SECRET, FLAG_RESUME,
};
use crate::abi::mechanism::lifecycle::{OpenIn, OpenOut};
use crate::abi::mechanism::ticket::HostTables;
use crate::persistence::lifecycle::{self as native, codec, OpenBinding, Request, Response};
use crate::Secret;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub(super) struct Preparation {
    birth: Option<[u8; 32]>,
    begin_body: Option<[u8; 32]>,
    phase: native::Phase,
    inspected: Option<native::InspectionState>,
    source: Option<native::SourceIdentity>,
    marker: Option<[u8; 32]>,
    upgrade: Option<[u8; 16]>,
    target: Option<owned::BackendInfo>,
    planned_target: Option<owned::BackendInfo>,
    recovery: Option<native::RecoveryReady>,
    recovered: Option<native::RecoveryReady>,
}
impl Default for Preparation {
    fn default() -> Self {
        Self {
            birth: None,
            begin_body: None,
            phase: native::Phase::Bound,
            inspected: None,
            source: None,
            marker: None,
            upgrade: None,
            target: None,
            planned_target: None,
            recovery: None,
            recovered: None,
        }
    }
}
impl Preparation {
    pub(super) fn primitive_allowed(&self) -> bool {
        self.phase == native::Phase::Open
            || self.target.is_some()
            || (self.phase == native::Phase::RecoveryReady
                && self.recovered.as_ref().is_some_and(|confirmed| {
                    self.recovery.as_ref() == Some(confirmed)
                        && self
                            .planned_target
                            .is_some_and(|info| info.dataset == confirmed.target)
                }))
    }
    pub(super) fn ordinary_opened(&mut self) {
        self.phase = native::Phase::Open;
    }
    fn permits<O>(&self, request: &Request<O>, body: [u8; 32]) -> bool {
        match request {
            Request::Inspect { .. } => {
                matches!(self.phase, native::Phase::Bound | native::Phase::Prepared)
            }
            Request::BeginOrResume {
                expected_source, ..
            } => {
                matches!(
                    self.phase,
                    native::Phase::Prepared | native::Phase::Upgrading
                ) && self.source.as_ref() == Some(expected_source)
                    && self.begin_body.is_none_or(|prior| prior == body)
            }
            Request::SourcePage { upgrade, .. }
            | Request::Target { upgrade }
            | Request::CheckFence { upgrade }
            | Request::Finish { upgrade, .. } => self.upgrade == Some(upgrade.id),
        }
    }
    fn answered<O>(
        &mut self,
        request: &Request<O>,
        response: &Response<O>,
    ) -> Result<(), native::Error> {
        match (request, response) {
            (Request::Inspect { .. }, Response::Inspected(answer)) => {
                self.phase = native::Phase::Prepared;
                self.inspected = Some(answer.state);
                self.source = answer.source.clone();
                self.marker = answer
                    .admission_marker
                    .as_ref()
                    .map(|marker| crate::persistence::archive::digest(&marker.0));
            }
            (
                Request::BeginOrResume {
                    expected_source, ..
                },
                Response::Begun(answer),
            ) if &answer.source == expected_source => {
                self.phase = native::Phase::Upgrading;
                self.upgrade = Some(answer.reference.id);
                self.planned_target = Some(answer.target);
            }
            (
                Request::SourcePage {
                    snapshot, family, ..
                },
                Response::SourcePage(page),
            ) if snapshot == &page.snapshot && family == &page.family => {}
            (Request::Target { upgrade }, Response::Target(target))
                if upgrade.id == target.upgrade && self.planned_target == Some(target.info) =>
            {
                self.target = Some(target.info);
            }
            (Request::CheckFence { upgrade }, Response::Fence(fence))
                if upgrade.id == fence.upgrade && self.source.as_ref() == Some(&fence.source) => {}
            (
                Request::Finish {
                    upgrade,
                    activation_receipt,
                },
                Response::RecoveryReady(ready),
            ) if upgrade.id == ready.upgrade
                && activation_receipt.phase == native::CompletionPhase::Activation =>
            {
                self.phase = native::Phase::RecoveryReady;
                self.recovery = Some(ready.clone());
            }
            (
                Request::Finish {
                    upgrade,
                    activation_receipt,
                },
                Response::ServingReady(ready),
            ) if upgrade.id == ready.recovery.upgrade
                && self.recovered.as_ref() == Some(&ready.recovery)
                && self.recovery.as_ref() == Some(&ready.recovery)
                && activation_receipt.phase == native::CompletionPhase::Complete =>
            {
                self.phase = native::Phase::Open;
            }
            _ => return Err(native::Error::Corrupt),
        }
        Ok(())
    }
    // Called only after the retained native connect_prepared has succeeded and
    // its metadata has passed validation. Recovery access carries the exact
    // activation proof and target metadata, without requiring a prior Target call.
    fn connected(
        &mut self,
        binding: &OpenBinding,
        info: owned::BackendInfo,
    ) -> Result<(), native::Error> {
        if let OpenBinding::Recovery(ready) = binding {
            if !self.may_open(binding)
                || self.planned_target != Some(info)
                || ready.target != info.dataset
            {
                return Err(native::Error::SourceChanged);
            }
            self.recovered = Some(ready.clone());
        } else {
            self.phase = native::Phase::Open;
        }
        Ok(())
    }
    fn may_open(&self, binding: &OpenBinding) -> bool {
        match binding {
            OpenBinding::Empty => {
                self.phase == native::Phase::Prepared
                    && self.inspected == Some(native::InspectionState::Empty)
            }
            OpenBinding::Current {
                source,
                admission_marker_digest,
            } => {
                self.phase == native::Phase::Prepared
                    && self.inspected == Some(native::InspectionState::Current)
                    && self.source.as_ref() == Some(source)
                    && self.marker == Some(*admission_marker_digest)
            }
            OpenBinding::Recovery(ready) => {
                self.phase == native::Phase::RecoveryReady
                    && self.recovered.is_none()
                    && self.recovery.as_ref() == Some(ready)
            }
        }
    }
}

fn span<T>(ptr: *const T, count: usize) -> bool {
    count
        .checked_mul(core::mem::size_of::<T>())
        .is_some_and(|bytes| {
            bytes <= isize::MAX as usize
                && (count == 0 || !ptr.is_null())
                && (ptr.is_null() || (ptr as usize).is_multiple_of(core::mem::align_of::<T>()))
                && (ptr as usize).checked_add(bytes).is_some()
        })
}
fn overlap(ptr: *const u8, len: usize, out: crate::abi::store::HostBuf) -> bool {
    len != 0
        && out.cap != 0
        && (ptr as usize) < (out.ptr as usize).saturating_add(out.cap)
        && (out.ptr as usize) < (ptr as usize).saturating_add(len)
}
unsafe fn bytes<'a>(blob: Blob) -> Option<&'a [u8]> {
    if !span(blob.ptr, blob.len)
        || blob.flags & !BLOB_SECRET != 0
        || !matches!(blob.fmt, BLOB_ABSENT | BLOB_OCTETS | BLOB_JSON)
        || (blob.fmt == BLOB_ABSENT && blob.len != 0)
    {
        return None;
    }
    Some(if blob.len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(blob.ptr, blob.len) }
    })
}
struct Loan<'a> {
    settings: &'a [u8],
    secrets: &'a [Blob],
    request: &'a [u8],
    host: Option<Host>,
    birth: [u8; 32],
}
unsafe fn preflight<'a>(input: &wire::BootstrapIn, allocation_bytes: usize) -> Option<Loan<'a>> {
    if input.head.size as usize != core::mem::size_of::<wire::BootstrapIn>()
        || input.head.flags & !FLAG_RESUME != 0
        || input.head._reserved != [0; 3]
        || crate::abi::mechanism::call::DeadlineClass::from_raw(input.head.deadline_class).is_none()
        || !span(input.result.ptr, input.result.cap)
        || !span(input.secrets, input.secrets_len)
    {
        return None;
    }
    let settings = unsafe { bytes(input.settings) }?;
    let request = unsafe { bytes(input.request) }?;
    if input.request.fmt != BLOB_OCTETS || input.request.flags & BLOB_SECRET == 0 {
        return None;
    }
    let secrets = if input.secrets_len == 0 {
        &[]
    } else {
        unsafe { core::slice::from_raw_parts(input.secrets, input.secrets_len) }
    };
    let mut aggregate = settings.len().checked_add(request.len())?.checked_add(
        input
            .secrets_len
            .checked_mul(core::mem::size_of::<Blob>())?,
    )?;
    let mut hash = Sha256::new();
    hash.update(b"busbar.store.bootstrap.birth/1\0");
    hash.update(input.generation.to_le_bytes());
    hash.update((settings.len() as u64).to_le_bytes());
    hash.update(settings);
    for blob in secrets {
        let secret = unsafe { bytes(*blob) }?;
        if blob.flags & BLOB_SECRET == 0 || overlap(blob.ptr, blob.len, input.result) {
            return None;
        }
        aggregate = aggregate.checked_add(secret.len())?;
        hash.update((secret.len() as u64).to_le_bytes());
        hash.update(secret);
    }
    if aggregate > allocation_bytes
        || overlap(input.settings.ptr, input.settings.len, input.result)
        || overlap(input.request.ptr, input.request.len, input.result)
        || overlap(
            input.secrets.cast(),
            input
                .secrets_len
                .checked_mul(core::mem::size_of::<Blob>())?,
            input.result,
        )
    {
        return None;
    }
    let host = if input.host.is_null() {
        None
    } else {
        if !span(input.host, 1)
            || overlap(
                input.host.cast(),
                core::mem::size_of::<HostTables>(),
                input.result,
            )
        {
            return None;
        }
        let size = unsafe { core::ptr::addr_of!((*input.host).size).read_unaligned() } as usize;
        if size < core::mem::size_of::<HostTables>() {
            return None;
        }
        let tables = unsafe { input.host.read() };
        if tables._reserved != 0 || tables.ctx.handle != input.head.host.handle {
            return None;
        }
        hash.update(tables.ctx.handle.to_le_bytes());
        hash.update((tables.wake.map_or(0, |f| f as usize) as u64).to_le_bytes());
        hash.update((tables.conns as usize as u64).to_le_bytes());
        hash.update((tables.services as usize as u64).to_le_bytes());
        hash.update((tables.io as usize as u64).to_le_bytes());
        Some(unsafe { Host::from_raw(&tables) })
    };
    Some(Loan {
        settings,
        secrets,
        request,
        host,
        birth: hash.finalize().into(),
    })
}
fn bounds<B: Backend>(backend: &B) -> native::Bounds {
    native::Bounds {
        items: u32::MAX,
        bytes: u32::try_from(backend.input_budget()).unwrap_or(u32::MAX),
    }
}
struct Progress<B: Backend> {
    source: Request<B::Owner>,
    canonical: Secret<Vec<u8>>,
    answer: Option<Secret<Vec<u8>>>,
    parked: Option<Parked>,
}
fn write(
    encoded: &Secret<Vec<u8>>,
    input: &wire::BootstrapIn,
    out: &mut wire::BootstrapOut,
) -> Outcome {
    if encoded.0.len() > input.result.cap {
        out.needed = encoded.0.len() as u64;
        return Outcome::Failed;
    }
    if !encoded.0.is_empty() {
        unsafe {
            core::ptr::copy_nonoverlapping(encoded.0.as_ptr(), input.result.ptr, encoded.0.len());
        }
    }
    out.written = encoded.0.len() as u64;
    Outcome::Ready
}
fn run<B: Backend>(
    held: &Held<Served<B>>,
    mut progress: Progress<B>,
    input: &wire::BootstrapIn,
) -> (Progress<B>, Outcome, u64) {
    let served = held.life();
    if progress.answer.is_none() {
        let body = crate::persistence::archive::digest(&progress.canonical.0);
        let permitted = {
            let mut preparation = served
                .preparation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let permitted = preparation.permits(&progress.source, body);
            if permitted && matches!(progress.source, Request::BeginOrResume { .. }) {
                preparation.begin_body = Some(body);
            }
            permitted
        };
        if !permitted {
            progress.answer = codec::encode_response::<B::Owner>(
                &Err(native::Error::Refused),
                bounds(&served.backend),
            )
            .ok();
        } else {
            let mut op = Op::enter(
                input.head.ticket,
                held.host(),
                progress.parked.take(),
                Some(&served.reads),
            );
            match served.backend.bootstrap(&mut op, &progress.source) {
                Step::Pending { wake_at_ns } => {
                    let Some(parked) = park(op, wake_at_ns) else {
                        return (progress, Outcome::Fault, 0);
                    };
                    progress.parked = Some(parked);
                    return (progress, Outcome::Pending, wake_at_ns);
                }
                Step::Ready(mut answer) => {
                    drop(op.into_parked());
                    // An answer that cannot be encoded within the bounds is never committed:
                    // the caller gets the error and the phase stays where it was.
                    if answer.is_ok()
                        && codec::encode_response(&answer, bounds(&served.backend)).is_err()
                    {
                        answer = Err(native::Error::Bounds);
                    }
                    if let Ok(response) = &answer {
                        let mut preparation = served
                            .preparation
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        if let Err(error) = preparation.answered(&progress.source, response) {
                            answer = Err(error);
                        }
                        if let Some(info) = preparation.target {
                            if let Some(prior) = served.info.get() {
                                if prior != &info {
                                    answer = Err(native::Error::SourceChanged);
                                }
                            } else {
                                let _ = served.info.set(info);
                            }
                        }
                    }
                    progress.answer = codec::encode_response(&answer, bounds(&served.backend)).ok();
                }
            }
        }
    }
    (progress, Outcome::Ready, 0)
}
/// The mandatory native BOOTSTRAP slot, legal before ordinary OPEN.
#[derive(Debug)]
pub struct Bootstrap<B>(PhantomData<B>);
impl<B: Backend> SafeSlot for Bootstrap<B> {
    type Kind = crate::plugin::markers::StoreKind;
    type In = wire::BootstrapIn;
    type Out = wire::BootstrapOut;
    type State = Held<Served<B>>;
    fn call(
        instance: Instance<'_, Self::State>,
        input: Lent<'_, Self::In>,
        mut out: Out<'_, Self::Out>,
    ) -> Outcome {
        let raw = input.get();
        let allocation_bytes = if let Some(held) = instance.get() {
            held.life().backend.input_budget()
        } else {
            // The only allocating initial operation is Inspect. Its explicit
            // declared aggregate bound is readable before creating a session.
            let Some(request) = (unsafe { bytes(raw.request) }) else {
                return Outcome::Fault;
            };
            let Some(bound) = codec::inspect_allocation_bound(request) else {
                return Outcome::Fault;
            };
            bound
        };
        let Some(loan) = (unsafe { preflight(raw, allocation_bytes) }) else {
            return Outcome::Fault;
        };
        if let Some(held) = instance.get() {
            let served = held.life();
            if !instance.resuming() && instance.current_parked() {
                return Outcome::Fault;
            }
            if served
                .preparation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .birth
                != Some(loan.birth)
            {
                return Outcome::Fault;
            }
            let key = ReplyKey::of(instance.ticket());
            let mut progress = if instance.resuming() {
                let Some(progress) = instance.resume_value::<Progress<B>>() else {
                    return Outcome::Fault;
                };
                progress
            } else if let Some((ticket, progress)) = served.replies.take(key) {
                if ticket != instance.ticket() {
                    served.replies.insert(key, (ticket, progress));
                    return Outcome::Fault;
                }
                let Ok(progress) = progress.downcast::<Progress<B>>() else {
                    return Outcome::Fault;
                };
                *progress
            } else {
                let Ok(source) =
                    codec::decode_request_owned::<B::Owner>(loan.request, bounds(&served.backend))
                else {
                    return Outcome::Fault;
                };
                let Ok(canonical) = codec::encode_request(&source, bounds(&served.backend)) else {
                    return Outcome::Fault;
                };
                Progress {
                    source,
                    canonical,
                    answer: None,
                    parked: None,
                }
            };
            if !crate::redacted::constant_time_eq(&progress.canonical.0, loan.request) {
                if progress.parked.is_some() {
                    instance.park(progress);
                } else {
                    served
                        .replies
                        .insert(key, (instance.ticket(), Box::new(progress)));
                }
                return Outcome::Fault;
            }
            let outcome;
            let wake;
            (progress, outcome, wake) = run(held, progress, raw);
            if outcome == Outcome::Pending {
                out.raw().head.wake_at_ns = wake;
                instance.park(progress);
                return outcome;
            }
            if outcome == Outcome::Fault {
                return outcome;
            }
            let Some(encoded) = &progress.answer else {
                return Outcome::Fault;
            };
            let result = write(encoded, raw, out.raw());
            if result == Outcome::Failed {
                served
                    .replies
                    .insert(key, (instance.ticket(), Box::new(progress)));
            }
            result
        } else {
            // The only first operation is bounded, read-only Inspect. Reject every
            // other tag/version before constructing the native session owner.
            if instance.resuming() || loan.request.get(13) != Some(&0) {
                return Outcome::Fault;
            }
            let initial = native::Bounds {
                items: 1,
                bytes: u32::try_from(
                    loan.request
                        .len()
                        .saturating_add(core::mem::size_of::<Request<B::Owner>>()),
                )
                .unwrap_or(u32::MAX),
            };
            let Ok(source) = codec::decode_request_owned::<B::Owner>(loan.request, initial) else {
                return Outcome::Fault;
            };
            if !matches!(source, Request::Inspect { .. }) {
                return Outcome::Fault;
            }
            if B::validate(loan.settings).is_err() {
                return Outcome::Refused;
            }
            let mut secret_refs = Vec::new();
            if secret_refs.try_reserve_exact(loan.secrets.len()).is_err() {
                return Outcome::Refused;
            }
            for secret in loan.secrets {
                secret_refs.push(unsafe { bytes(*secret) }.expect("preflight"));
            }
            let Ok(served) = Served::<B>::open_on(
                loan.settings,
                &secret_refs,
                raw.generation,
                loan.host.as_ref(),
            ) else {
                return Outcome::Refused;
            };
            served
                .preparation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .birth = Some(loan.birth);
            let canonical = codec::encode_request(&source, bounds(&served.backend));
            let held = Held::new(served, loan.host);
            let Ok(canonical) = canonical else {
                instance.bootstrap_store::<Progress<B>>(held, None);
                return Outcome::Refused;
            };
            let (progress, outcome, wake) = run(
                &held,
                Progress {
                    source,
                    canonical,
                    answer: None,
                    parked: None,
                },
                raw,
            );
            if outcome == Outcome::Pending {
                out.raw().head.wake_at_ns = wake;
                instance.bootstrap_store(held, Some(progress));
                return outcome;
            }
            let result = progress
                .answer
                .as_ref()
                .map_or(Outcome::Fault, |encoded| write(encoded, raw, out.raw()));
            if result == Outcome::Failed {
                held.life().replies.insert(
                    ReplyKey::of(instance.ticket()),
                    (instance.ticket(), Box::new(progress)),
                );
            }
            instance.bootstrap_store::<Progress<B>>(held, None);
            result
        }
    }
}

fn binding_value(mut bytes: &[u8]) -> Result<Option<&[u8]>, native::Error> {
    let mut found = None;
    while !bytes.is_empty() {
        let n = u16::from_le_bytes(
            bytes
                .get(..2)
                .ok_or(native::Error::Corrupt)?
                .try_into()
                .map_err(|_| native::Error::Corrupt)?,
        ) as usize;
        let key_end = 2usize.checked_add(n).ok_or(native::Error::Bounds)?;
        let key = bytes.get(2..key_end).ok_or(native::Error::Corrupt)?;
        let length_end = key_end.checked_add(4).ok_or(native::Error::Bounds)?;
        let n = u32::from_le_bytes(
            bytes
                .get(key_end..length_end)
                .ok_or(native::Error::Corrupt)?
                .try_into()
                .map_err(|_| native::Error::Corrupt)?,
        ) as usize;
        let end = length_end.checked_add(n).ok_or(native::Error::Bounds)?;
        let value = bytes.get(length_end..end).ok_or(native::Error::Corrupt)?;
        if key == native::OPEN_BINDING.as_bytes() {
            if found.is_some() {
                return Err(native::Error::Corrupt);
            }
            found = Some(value);
        }
        bytes = bytes.get(end..).ok_or(native::Error::Corrupt)?;
    }
    Ok(found)
}
struct OpeningProgress {
    binding: OpenBinding,
    parked: Option<Parked>,
}
/// OPEN adopts the exact prepared Store instance instead of allocating another.
#[derive(Debug)]
pub struct Open<B>(PhantomData<B>);
impl<B: Backend> SafeSlot for Open<B> {
    type Kind = crate::plugin::markers::StoreKind;
    type In = OpenIn;
    type Out = OpenOut;
    type State = Held<Served<B>>;
    fn call(
        instance: Instance<'_, Self::State>,
        input: Lent<'_, OpenIn>,
        mut out: Out<'_, OpenOut>,
    ) -> Outcome {
        let Some(held) = instance.get() else {
            return crate::abi::sdk::life::Open::<Served<B>>::call(instance, input, out);
        };
        let served = held.life();
        let birth = served
            .preparation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .birth;
        if birth.is_none() {
            // An ordinary OPEN may already be parked by the existing lifecycle;
            // only a BOOTSTRAP-minted instance uses prepared adoption below.
            return crate::abi::sdk::life::Open::<Served<B>>::call(instance, input, out);
        }
        let original = input.get();
        if original.head.size as usize != core::mem::size_of::<OpenIn>() {
            return Outcome::Fault;
        }
        let mut head = original.head;
        head.size = core::mem::size_of::<wire::BootstrapIn>() as u32;
        let check = wire::BootstrapIn {
            head,
            host: original.host,
            settings: original.settings,
            secrets: original.secrets,
            secrets_len: original.secrets_len,
            generation: original.generation,
            request: Blob {
                ptr: b"x".as_ptr(),
                len: 1,
                fmt: BLOB_OCTETS,
                flags: BLOB_SECRET,
            },
            result: crate::abi::store::HostBuf {
                ptr: core::ptr::null_mut(),
                cap: 0,
            },
        };
        if unsafe { preflight(&check, served.backend.input_budget()) }
            .is_none_or(|loan| Some(loan.birth) != birth)
        {
            return Outcome::Fault;
        }
        let bytes = input.field(|i| &i.head.extensions).bytes();
        let Ok(Some(binding)) = binding_value(bytes) else {
            return Outcome::Refused;
        };
        let Ok(binding) = codec::decode_open_binding(binding, bounds(&served.backend)) else {
            return Outcome::Refused;
        };
        let mut progress = if instance.resuming() {
            let Some(progress) = instance.resume_value::<OpeningProgress>() else {
                return Outcome::Fault;
            };
            if progress.binding != binding {
                instance.park(progress);
                return Outcome::Fault;
            }
            progress
        } else {
            if !served
                .preparation
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .may_open(&binding)
            {
                return Outcome::Refused;
            }
            OpeningProgress {
                binding,
                parked: None,
            }
        };
        let mut op = Op::enter(
            instance.ticket(),
            held.host(),
            progress.parked.take(),
            Some(&served.reads),
        );
        match served.backend.connect_prepared(&mut op, &progress.binding) {
            Step::Pending { wake_at_ns } => {
                let Some(parked) = park(op, wake_at_ns) else {
                    return Outcome::Fault;
                };
                progress.parked = Some(parked);
                out.raw().head.wake_at_ns = wake_at_ns;
                instance.park(progress);
                Outcome::Pending
            }
            Step::Ready(result) => {
                drop(op.into_parked());
                if result.is_err() {
                    return Outcome::Failed;
                }
                let info = served.backend.info();
                if metadata::encode(info).is_err() {
                    return Outcome::Fault;
                }
                if let Some(prior) = served.info.get() {
                    if prior != &info {
                        return Outcome::Fault;
                    }
                } else {
                    let _ = served.info.set(info);
                }
                let mut state = served
                    .preparation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.connected(&progress.binding, info).is_err() {
                    return Outcome::Fault;
                }
                let head = &mut out.raw().head;
                head.extensions = held.leases().blob(head, served.extensions(), BLOB_OCTETS);
                Outcome::Ready
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_recovery_primitives_require_verified_open_and_exact_activation_target() {
        let info = owned::BackendInfo {
            dataset: owned::DatasetId([1; 16]),
            atomic_domain: [2; 16],
            clock_authority: [3; 16],
            physical_version: 1,
            durability: owned::Durability::Ephemeral,
        };
        let ready = native::RecoveryReady {
            upgrade: [4; 16],
            target: info.dataset,
            activation_receipt_digest: [5; 32],
            selector_digest: [6; 32],
        };
        let binding = OpenBinding::Recovery(ready.clone());
        let mut state = Preparation {
            phase: native::Phase::RecoveryReady,
            planned_target: Some(info),
            recovery: Some(ready.clone()),
            ..Preparation::default()
        };
        assert!(
            state.target.is_none(),
            "fresh session never requested Target"
        );
        assert!(
            !state.primitive_allowed(),
            "activation alone cannot issue reads"
        );
        let mut wrong_info = info;
        wrong_info.atomic_domain = [7; 16];
        assert!(state.connected(&binding, wrong_info).is_err());
        assert!(!state.primitive_allowed());
        let mut wrong_ready = ready.clone();
        wrong_ready.selector_digest = [8; 32];
        assert!(state
            .connected(&OpenBinding::Recovery(wrong_ready), info)
            .is_err());
        assert!(!state.primitive_allowed());
        state.connected(&binding, info).unwrap();
        assert!(state.primitive_allowed());
        assert_eq!(state.phase, native::Phase::RecoveryReady);
        assert!(!state.may_open(&binding), "same session cannot OPEN twice");
        state.recovery.as_mut().unwrap().selector_digest = [9; 32];
        assert!(
            !state.primitive_allowed(),
            "proof changes revoke recovery access"
        );
    }
}
