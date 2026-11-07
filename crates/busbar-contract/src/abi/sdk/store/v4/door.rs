// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Native primitive Store door over the shared lifecycle and connection machinery.
//!
//! The ABI caller lends live initialized, nonoverlapping output allocations and
//! immutable input allocations with valid provenance. Input bytes remain unchanged
//! across pending resumes and exact-ticket short-buffer retries; only output buffer
//! addresses/capacities may change. No output loan is retained between crossings.

use std::any::Any;
use std::marker::PhantomData;
use std::sync::OnceLock;

use super::backend::{Backend, Committed};
use super::{decode, encode, metadata};
use crate::abi::mechanism::call::Outcome;
use crate::abi::mechanism::ticket::Ticket;
use crate::abi::sdk::conn::Host;
use crate::abi::sdk::door::{KindOps, KindSlot, Lifecycle};
use crate::abi::sdk::life::{Held, Life, Opening, Refusal};
use crate::abi::sdk::out::{Replies, ReplyKey};
use crate::abi::sdk::store::op::Parked;
use crate::abi::sdk::store::{Op, Step};
use crate::abi::sdk::{Instance, Lent, Out, SafeSlot};
use crate::abi::store::v4 as wire;
use crate::persistence as owned;

// SAFETY: this table leads with OpsHead and appends exactly five Option<Op>s.
unsafe impl KindOps for wire::Ops {
    const KIND: crate::abi::mechanism::KindCode = crate::abi::mechanism::KindCode::Store;
    const ABI_VERSION: u32 = wire::ABI_VERSION;
    const LAYOUT_FINGERPRINT: u64 = wire::LAYOUT_FINGERPRINT;
    type Lifecycle = Lifecycle;
}
macro_rules! kind_slot {
    ($slot:ident, $input:ty, $output:ty) => {
        // SAFETY: the v4 table declares this exact input and output at this slot.
        unsafe impl KindSlot<{ wire::slot::$slot }> for wire::Ops {
            type In = $input;
            type Out = $output;
        }
    };
}
kind_slot!(READ, wire::ReadIn, wire::ReadOut);
kind_slot!(SCAN, wire::ScanIn, wire::ScanOut);
kind_slot!(COMMIT, wire::CommitIn, wire::CommitOut);
kind_slot!(CLOCK, wire::ClockIn, wire::ClockOut);
kind_slot!(BOOTSTRAP, wire::BootstrapIn, wire::BootstrapOut);

#[path = "bootstrap_door.rs"]
mod preparation;
pub use preparation::{Bootstrap, Open};

/// An instance's backend, fixed metadata, and completed short-buffer answers.
pub struct Served<B: Backend> {
    backend: B,
    preparation: std::sync::Mutex<preparation::Preparation>,
    reads: crate::abi::sdk::store::wire::ReadBufs,
    info: OnceLock<owned::BackendInfo>,
    replies: Replies<(Ticket, Box<dyn Any + Send + Sync>)>,
}
impl<B: Backend> std::fmt::Debug for Served<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Served")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}
impl<B: Backend> Served<B> {
    /// This opened instance's implementation.
    pub fn backend(&self) -> &B {
        &self.backend
    }
}

impl<B: Backend> Life for Served<B> {
    const CANCEL: u32 = crate::abi::store::CANCEL_UNKNOWN;
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        B::validate(settings).map_err(Refusal::failed)
    }
    fn open(settings: &[u8], secrets: &[&[u8]], generation: u64) -> Result<Self, Refusal> {
        Self::open_on(settings, secrets, generation, None)
    }
    fn open_on(
        settings: &[u8],
        secrets: &[&[u8]],
        _: u64,
        host: Option<&Host>,
    ) -> Result<Self, Refusal> {
        Ok(Self {
            backend: B::open(settings, secrets, host.copied()).map_err(Refusal::failed)?,
            preparation: std::sync::Mutex::new(preparation::Preparation::default()),
            reads: Default::default(),
            info: OnceLock::new(),
            replies: Replies::default(),
        })
    }
    fn opening(
        &self,
        host: Option<&Host>,
        ticket: Ticket,
        parked: Option<Box<dyn Any + Send + Sync>>,
    ) -> Opening {
        let parked = match parked.map(|value| value.downcast::<Parked>()) {
            None => None,
            Some(Ok(value)) => Some(*value),
            Some(Err(_)) => return Opening::Fault,
        };
        let mut op = Op::enter(ticket, host, parked, None);
        match self.backend.connect(&mut op) {
            Step::Pending { wake_at_ns } => match park(op, wake_at_ns) {
                Some(parked) => Opening::Pending {
                    wake_at_ns,
                    parked: Box::new(parked),
                },
                None => Opening::Fault,
            },
            Step::Ready(result) => {
                drop(op.into_parked());
                if let Err(error) = result {
                    return Opening::Failed(Refusal::failed(error));
                }
                let info = self.backend.info();
                if metadata::encode(info).is_err() {
                    return Opening::Failed(Refusal::failed("invalid persistence metadata"));
                }
                if self.info.set(info).is_err() {
                    return Opening::Fault;
                }
                self.preparation
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .ordinary_opened();
                Opening::Ready
            }
        }
    }
    fn extensions(&self) -> Vec<u8> {
        self.info
            .get()
            .and_then(|info| metadata::encode(*info).ok())
            .map(|bytes| {
                crate::abi::mechanism::extensions::encode(&[(metadata::EXTENSION, &bytes)])
            })
            .unwrap_or_default()
    }
    fn cancel(&self, ticket: Ticket) -> u32 {
        let key = ReplyKey::of(ticket);
        if let Some((stored, value)) = self.replies.take(key) {
            if stored != ticket {
                self.replies.insert(ReplyKey::of(stored), (stored, value));
            }
        }
        Self::CANCEL
    }
}
pub(crate) fn park(op: Op<'_>, wake_at_ns: u64) -> Option<Parked> {
    if !op.can_pend() || (wake_at_ns == 0 && !op.made_a_service()) {
        drop(op.into_parked());
        None
    } else {
        Some(op.into_parked())
    }
}

struct Progress<Q, A> {
    source: Q,
    answer: Option<A>,
    parked: Option<Parked>,
}

trait Primitive<B: Backend>: Send + Sync + 'static {
    type In: crate::abi::sdk::door::AbiIn;
    type Out: crate::abi::sdk::door::AbiOut;
    type Source: Send + Sync + 'static;
    type Answer: Send + Sync + 'static;
    fn decode(backend: &B, input: Lent<'_, Self::In>) -> Result<Self::Source, decode::DecodeError>;
    fn same(_: &Self::Source, _: &Self::Source) -> bool {
        true
    }
    fn valid_outputs(_: Lent<'_, Self::In>) -> bool {
        true
    }
    fn run(backend: &B, op: &mut Op<'_>, source: &Self::Source) -> Step<Self::Answer>;
    fn encode(
        source: &Self::Source,
        answer: &Self::Answer,
        input: Lent<'_, Self::In>,
    ) -> Result<(Self::Out, bool), encode::EncodeError>;
}
fn invoke<B: Backend, P: Primitive<B>>(
    instance: Instance<'_, Held<Served<B>>>,
    input: Lent<'_, P::In>,
    mut out: Out<'_, P::Out>,
) -> Outcome {
    let Some(held) = instance.get() else {
        return out.fail(Refusal::refused(crate::abi::sdk::life::NO_INSTANCE));
    };
    if !P::valid_outputs(input) {
        return Outcome::Fault;
    }
    let served = held.life();
    if !served
        .preparation
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .primitive_allowed()
    {
        return out.fail(Refusal::refused("native target capability not issued"));
    }
    if served.info.get().is_none() {
        return Outcome::Fault;
    }
    let ticket = instance.ticket();
    let key = ReplyKey::of(ticket);
    type State<B, P> = Progress<<P as Primitive<B>>::Source, <P as Primitive<B>>::Answer>;
    let mut progress: State<B, P> = if instance.resuming() {
        let Some(progress) = instance.resume_value::<State<B, P>>() else {
            return Outcome::Fault;
        };
        progress
    } else if let Some((stored_ticket, value)) = served.replies.take(key) {
        if stored_ticket == ticket {
            let Ok(progress) = value.downcast::<State<B, P>>() else {
                return Outcome::Fault;
            };
            let checked = P::decode(&served.backend, input);
            if !checked
                .as_ref()
                .is_ok_and(|source| P::same(&progress.source, source))
            {
                served.replies.insert(key, (ticket, progress));
                return out.fail(Refusal::refused(
                    "short-buffer retry changed persistence input",
                ));
            }
            *progress
        } else {
            drop(value);
            match P::decode(&served.backend, input) {
                Ok(source) => Progress {
                    source,
                    answer: None,
                    parked: None,
                },
                Err(_) => return out.fail(Refusal::refused("invalid primitive persistence input")),
            }
        }
    } else {
        match P::decode(&served.backend, input) {
            Ok(source) => Progress {
                source,
                answer: None,
                parked: None,
            },
            Err(_) => return out.fail(Refusal::refused("invalid primitive persistence input")),
        }
    };
    if progress.answer.is_none() {
        let mut op = Op::enter(
            ticket,
            held.host(),
            progress.parked.take(),
            Some(&served.reads),
        );
        match P::run(&served.backend, &mut op, &progress.source) {
            Step::Pending { wake_at_ns } => {
                let Some(parked) = park(op, wake_at_ns) else {
                    return Outcome::Fault;
                };
                progress.parked = Some(parked);
                // Every ABI output leads with the shared head.
                // SAFETY: AbiOut guarantees a leading shared head, uniquely lent here.
                unsafe {
                    (*core::ptr::from_mut(out.raw())
                        .cast::<crate::abi::mechanism::call::OutHead>())
                    .wake_at_ns = wake_at_ns;
                }
                instance.park(progress);
                return Outcome::Pending;
            }
            Step::Ready(answer) => {
                drop(op.into_parked());
                progress.answer = Some(answer);
            }
        }
    }
    match P::encode(
        &progress.source,
        progress.answer.as_ref().expect("completed primitive"),
        input,
    ) {
        Ok((value, short)) => {
            // SAFETY: AbiOut's leading head is guaranteed by the trait contract.
            let outcome = unsafe {
                (*core::ptr::from_ref(&value).cast::<crate::abi::mechanism::call::OutHead>())
                    .outcome
            };
            *out.raw() = value;
            if short {
                served.replies.insert(key, (ticket, Box::new(progress)));
            }
            outcome.outcome()
        }
        Err(_) => Outcome::Fault,
    }
}

/// Coherent read slot.
#[derive(Debug)]
pub struct Read<B>(PhantomData<B>);
/// Namespace page slot.
#[derive(Debug)]
pub struct Scan<B>(PhantomData<B>);
/// Atomic commit slot.
#[derive(Debug)]
pub struct Commit<B>(PhantomData<B>);
/// Dataset clock slot.
#[derive(Debug)]
pub struct Clock<B>(PhantomData<B>);

impl<B: Backend> Primitive<B> for Read<B> {
    type In = wire::ReadIn;
    type Out = wire::ReadOut;
    type Source = owned::Read;
    type Answer = Result<owned::ReadResult<B::Owner>, owned::Failure>;
    fn decode(backend: &B, input: Lent<'_, Self::In>) -> Result<Self::Source, decode::DecodeError> {
        // SAFETY: the ABI loan guarantees all nested immutable allocation spans.
        unsafe { decode::read(input.get(), backend.input_budget()) }
    }
    fn same(a: &Self::Source, b: &Self::Source) -> bool {
        a.dataset == b.dataset && a.addresses == b.addresses && a.time == b.time
    }
    fn valid_outputs(input: Lent<'_, Self::In>) -> bool {
        // SAFETY: this temporary preflight loan ends before backend or encoding.
        unsafe { input.v4_outputs().is_some() }
    }
    fn run(backend: &B, op: &mut Op<'_>, source: &Self::Source) -> Step<Self::Answer> {
        backend.read(op, source)
    }
    fn encode(
        _: &Self::Source,
        answer: &Self::Answer,
        input: Lent<'_, Self::In>,
    ) -> Result<(Self::Out, bool), encode::EncodeError> {
        // SAFETY: invoked once for this crossing; no output references are retained.
        let (items, bytes) = unsafe { input.v4_outputs() }.ok_or(encode::EncodeError::Buffer)?;
        let out = encode::read(
            input.get(),
            answer.as_ref().map_err(|error| *error),
            items,
            bytes,
        )?;
        let short = out.needed_items != 0 || out.needed_bytes != 0;
        Ok((out, short))
    }
}
impl<B: Backend> Primitive<B> for Scan<B> {
    type In = wire::ScanIn;
    type Out = wire::ScanOut;
    type Source = owned::Scan;
    type Answer = Result<owned::Page<B::Owner>, owned::Failure>;
    fn decode(backend: &B, input: Lent<'_, Self::In>) -> Result<Self::Source, decode::DecodeError> {
        // SAFETY: the ABI loan guarantees nested immutable allocation spans.
        unsafe { decode::scan(input.get(), backend.input_budget()) }
    }
    fn same(a: &Self::Source, b: &Self::Source) -> bool {
        a.dataset == b.dataset
            && a.namespace == b.namespace
            && a.prefix == b.prefix
            && a.after == b.after
            && a.generation == b.generation
            && a.allow_change == b.allow_change
            && a.max_items == b.max_items
            && a.max_bytes == b.max_bytes
    }
    fn valid_outputs(input: Lent<'_, Self::In>) -> bool {
        // SAFETY: this temporary preflight loan ends before backend or encoding.
        unsafe { input.v4_outputs().is_some() }
    }
    fn run(backend: &B, op: &mut Op<'_>, source: &Self::Source) -> Step<Self::Answer> {
        backend.scan(op, source)
    }
    fn encode(
        source: &Self::Source,
        answer: &Self::Answer,
        input: Lent<'_, Self::In>,
    ) -> Result<(Self::Out, bool), encode::EncodeError> {
        // SAFETY: unique initialized output loans, used only in this crossing.
        let (items, bytes) = unsafe { input.v4_outputs() }.ok_or(encode::EncodeError::Buffer)?;
        // The decoder copied the caller's selectors into retained native custody.
        // Encode against that checked owner, not the caller's different allocation;
        // the common primitive path already compared every selector on a recall.
        // Output spans remain the caller's validated loans.
        let mut encoding = *input.get();
        encoding.prefix = super::bytes(&source.prefix);
        encoding.after = super::bytes(source.after.as_deref().unwrap_or_default());
        let out = encode::scan(
            source,
            &encoding,
            answer.as_ref().map_err(|error| *error),
            items,
            bytes,
        )?;
        let short = out.needed_items != 0 || out.needed_bytes != 0;
        Ok((out, short))
    }
}
impl<B: Backend> Primitive<B> for Commit<B> {
    type In = wire::CommitIn;
    type Out = wire::CommitOut;
    type Source = owned::PreparedCandidate<B::Owner>;
    type Answer = Result<Committed<B::Owner>, owned::Failure>;
    fn decode(backend: &B, input: Lent<'_, Self::In>) -> Result<Self::Source, decode::DecodeError> {
        // SAFETY: immutable nested spans are guaranteed by the ABI loan.
        unsafe {
            decode::candidate_owned(&input.candidate, backend.input_budget(), backend.owner())
        }
    }
    fn same(a: &Self::Source, b: &Self::Source) -> bool {
        a.fingerprint() == b.fingerprint()
    }
    fn valid_outputs(input: Lent<'_, Self::In>) -> bool {
        // SAFETY: this temporary preflight loan ends before backend or encoding.
        unsafe { input.v4_output().is_some() }
    }
    fn run(backend: &B, op: &mut Op<'_>, source: &Self::Source) -> Step<Self::Answer> {
        backend.commit(op, source)
    }
    fn encode(
        _: &Self::Source,
        answer: &Self::Answer,
        input: Lent<'_, Self::In>,
    ) -> Result<(Self::Out, bool), encode::EncodeError> {
        // SAFETY: unique initialized output loan, used only in this crossing.
        let bytes = unsafe { input.v4_output() }.ok_or(encode::EncodeError::Buffer)?;
        let observed_at =
            answer
                .as_ref()
                .map(|value| value.observed_at)
                .unwrap_or(owned::ClockObservation {
                    unix_seconds: 0,
                    authority: [0; 16],
                });
        let out = encode::commit(
            input.get(),
            observed_at,
            answer
                .as_ref()
                .map(|value| &value.decision)
                .map_err(|error| *error),
            bytes,
        )?;
        let short = out.needed != 0;
        Ok((out, short))
    }
}
impl<B: Backend> Primitive<B> for Clock<B> {
    type In = wire::ClockIn;
    type Out = wire::ClockOut;
    type Source = owned::DatasetId;
    type Answer = Result<owned::ClockObservation, owned::Failure>;
    fn decode(_: &B, input: Lent<'_, Self::In>) -> Result<Self::Source, decode::DecodeError> {
        if input.dataset == [0; 16] {
            Err(decode::DecodeError::Identity)
        } else {
            Ok(owned::DatasetId(input.dataset))
        }
    }
    fn run(backend: &B, op: &mut Op<'_>, source: &Self::Source) -> Step<Self::Answer> {
        backend.clock(op, *source)
    }
    fn encode(
        _: &Self::Source,
        answer: &Self::Answer,
        _: Lent<'_, Self::In>,
    ) -> Result<(Self::Out, bool), encode::EncodeError> {
        Ok((encode::clock(*answer)?, false))
    }
}
macro_rules! safe_slot {
    ($name:ident, $input:ty, $output:ty) => {
        impl<B: Backend> SafeSlot for $name<B> {
            type In = $input;
            type Out = $output;
            type State = Held<Served<B>>;
            fn call(
                instance: Instance<'_, Self::State>,
                input: Lent<'_, Self::In>,
                out: Out<'_, Self::Out>,
            ) -> Outcome {
                invoke::<B, Self>(instance, input, out)
            }
        }
    };
}
safe_slot!(Read, wire::ReadIn, wire::ReadOut);
safe_slot!(Scan, wire::ScanIn, wire::ScanOut);
safe_slot!(Commit, wire::CommitIn, wire::CommitOut);
safe_slot!(Clock, wire::ClockIn, wire::ClockOut);

/// Emit a primitive v4 table with the shared lifecycle and ordinary declarations.
/// Optional arguments, in order: `needs`, `extensions`, `secret_refs`, `settings_schema`, `migrate`.
#[macro_export]
macro_rules! store_v4_door {
    ($store:ty, $name:expr, $version:expr, $max:expr
        $(, needs: $needs:expr)? $(, extensions: $extensions:expr)?
        $(, secret_refs: $refs:expr)? $(, settings_schema: $schema:expr)? $(, migrate: $migrate:ty)? $(,)?) => {
        const __BUSBAR_V4_NEEDS: &[$crate::abi::host::conn::connector::Need] = $crate::store_v4_door!(@default &[] $(, $needs)?);
        const __BUSBAR_V4_REFS: &[$crate::abi::mechanism::call::AbiStr] = $crate::store_v4_door!(@default &[] $(, $refs)?);
        $crate::plugin_door! {
            ops: $crate::abi::store::v4::Ops,
            statement: $crate::abi::mechanism::door::Statement {
                needs: __BUSBAR_V4_NEEDS.as_ptr(), needs_len: __BUSBAR_V4_NEEDS.len(),
                secret_refs: __BUSBAR_V4_REFS.as_ptr(), secret_refs_len: __BUSBAR_V4_REFS.len(),
                extensions: $crate::store_v4_door!(@default $crate::abi::mechanism::call::Blob::ABSENT $(, $extensions)?),
                settings_schema: $crate::store_v4_door!(@default $crate::abi::mechanism::call::Blob::ABSENT $(, $schema)?),
                ..$crate::abi::sdk::door::statement($name, $version, $max)
            },
            lifecycle: {
                validate: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Validate<$crate::abi::sdk::store::v4::door::Served<$store>>>,
                open: $crate::abi::sdk::Safe<$crate::abi::sdk::store::v4::door::Open<$store>>,
                refresh: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Refresh<$crate::abi::sdk::store::v4::door::Served<$store>>>,
                retire: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Retire<$crate::abi::sdk::store::v4::door::Served<$store>>>,
                tick: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Tick<$crate::abi::sdk::store::v4::door::Served<$store>>>,
                drive: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Drive<$crate::abi::sdk::store::v4::door::Served<$store>>>,
                cancel: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Cancel<$crate::abi::sdk::store::v4::door::Served<$store>>>,
                release: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Release<$crate::abi::sdk::store::v4::door::Served<$store>>>,
                close: $crate::abi::sdk::Safe<$crate::abi::sdk::life::Close<$crate::abi::sdk::store::v4::door::Served<$store>>>,
            },
            $(migrate: $migrate,)?
            kind_ops: {
                read: $crate::abi::sdk::Safe<$crate::abi::sdk::store::v4::door::Read<$store>>,
                scan: $crate::abi::sdk::Safe<$crate::abi::sdk::store::v4::door::Scan<$store>>,
                commit: $crate::abi::sdk::Safe<$crate::abi::sdk::store::v4::door::Commit<$store>>,
                clock: $crate::abi::sdk::Safe<$crate::abi::sdk::store::v4::door::Clock<$store>>,
                bootstrap: $crate::abi::sdk::Safe<$crate::abi::sdk::store::v4::door::Bootstrap<$store>>,
            },
        }
    };
    (@default $default:expr) => { $default };
    (@default $default:expr, $value:expr) => { $value };
}

#[cfg(test)]
#[path = "tests/door_tests.rs"]
mod tests;
