// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE LIFECYCLE, ONCE FOR EVERY PLANE: the nine lifecycle slots of a plane's door over the
//! plane's widened shapes (`abi::plane::PlaneLifecycle`: `open` and `refresh` publish a
//! generation's snapshot, `drive` and `cancel` carry the plane's session and record buffers), as
//! [`SafeSlot`]s over the plane's own state `P:` [`PlaneLife`]. A plane states what is its own:
//! how its settings read, what a generation publishes, and its `tick`/`drive`/`cancel`.
//! [`plugin_door!`](crate::plugin_door) names the nine at once: `lifecycle: plane_life(P)`.
//!
//! What every plane shares, here once:
//!
//! * `open` publishes the first generation's snapshot and holds the state; `refresh` publishes the
//!   next one over the same state; `retire` drops a generation's snapshot ([`Generations`]);
//! * a FAILED or REFUSED `validate`/`open`/`refresh` answers its [`Refusal`]'s text;
//! * `release` and `close` answer READY: a plane answers under no lease, and the SDK drops the state
//!   and every snapshot it still holds.

use std::ffi::c_void;
use std::marker::PhantomData;

use crate::abi::mechanism::call::{InHead, OutHead, Outcome};
use crate::abi::mechanism::lifecycle::{GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn};
use crate::abi::plane::{
    PlaneCancelIn, PlaneCancelOut, PlaneDriveIn, PlaneDriveOut, PlaneOpenIn, PlaneOpenOut,
    PlaneRefreshOut, PlaneSnapshot, ServeIn, ServeOut,
};
use crate::abi::sdk::door::Slot;
use crate::abi::sdk::lent::Lent;
use crate::abi::sdk::life::{settings_object, Refusal};
use crate::abi::sdk::out::Out;
use crate::abi::sdk::publish::{Generations, SnapshotSpec};
use crate::abi::sdk::safe::{Instance, SafeSlot};

/// What one generation publishes: its snapshot, and what the plane holds beside it until that
/// generation retires.
#[derive(Debug)]
pub struct Published<H> {
    /// The snapshot the host reads for the generation.
    pub spec: SnapshotSpec,
    /// The plane's own value for the generation ([`Generations::current`] answers the newest).
    pub held: H,
}

/// A plane's door state, opened: what `open` answers.
pub struct Opened<P: PlaneLife> {
    /// The state the instance holds.
    pub plane: P,
    /// The first generation's snapshot and value.
    pub first: Published<P::Held>,
}

impl<P: PlaneLife> std::fmt::Debug for Opened<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened").finish_non_exhaustive()
    }
}

/// A PLANE'S LIFECYCLE: implement it for the plane's door state and name the door's lifecycle
/// `plane_life(P)`. Every slot without a plane-specific answer has its default here.
pub trait PlaneLife: Send + Sync + Sized + 'static {
    /// What each generation holds beside its snapshot.
    type Held: Send + Sync + 'static;

    /// The generations this state publishes.
    fn generations(&self) -> &Generations<PlaneSnapshot, Self::Held>;

    /// `validate`: whether `settings` open an instance. The default is the SDK's object check.
    ///
    /// # Errors
    /// Why not.
    fn validate(settings: &[u8]) -> Result<(), Refusal> {
        settings_object(settings).map(|_| ())
    }

    /// `open`: the state, and the first generation's snapshot, from the plane's `open` `in`.
    ///
    /// # Errors
    /// Why it will not open.
    fn open(input: &Lent<'_, PlaneOpenIn>) -> Result<Opened<Self>, Refusal>;

    /// `refresh` to `generation` with `settings`: that generation's snapshot.
    ///
    /// # Errors
    /// Why the refresh did not apply.
    fn refresh(&self, settings: &[u8], generation: u64) -> Result<Published<Self::Held>, Refusal>;

    /// `refresh` from the whole lent `in`: what the slot calls. By default [`PlaneLife::refresh`]
    /// with the settings and the generation alone. A plane that judges the applied owned sections
    /// (`abi::plane::EXT_OWNED` on the head's extensions, the refresh-time twin of
    /// `PlaneOpenIn::owned`) or the re-resolved secrets overrides this, as `open` reads the whole
    /// `PlaneOpenIn`.
    ///
    /// # Errors
    /// Why the refresh did not apply.
    fn refresh_in(&self, input: &Lent<'_, RefreshIn>) -> Result<Published<Self::Held>, Refusal> {
        self.refresh(input.settings().bytes(), input.generation())
    }

    /// After `generation` was published, by `open` or `refresh`. Nothing by default.
    fn published(&self, generation: u64) {
        let _ = generation;
    }

    /// `retire` of `generation`, after its snapshot is dropped. Nothing more by default.
    fn retire(&self, generation: u64) {
        let _ = generation;
    }

    /// `tick`. By default no tick is wanted.
    fn tick(
        instance: Instance<'_, Self>,
        input: Lent<'_, TickIn>,
        mut out: Out<'_, TickOut>,
    ) -> Outcome {
        let _ = (instance, input);
        out.set(|o| &o.next_tick_ns, 0);
        Outcome::Ready
    }

    /// `drive`. By default no session has unsolicited output.
    fn drive(
        instance: Instance<'_, Self>,
        input: Lent<'_, PlaneDriveIn>,
        out: Out<'_, PlaneDriveOut>,
    ) -> Outcome {
        let _ = (instance, input, out);
        Outcome::Ready
    }

    /// `cancel`: the plane's disposition of the cancelled unit, and the rows it writes.
    fn cancel(
        instance: Instance<'_, Self>,
        input: Lent<'_, PlaneCancelIn>,
        out: Out<'_, PlaneCancelOut>,
    ) -> Outcome;
}

macro_rules! plane_slot {
    ($(#[$doc:meta])* $name:ident($in:ty => $out:ty) |$inst:pat_param, $input:pat_param, $o:ident| $body:block) => {
        $(#[$doc])*
        #[derive(Debug)]
        pub struct $name<P>(PhantomData<P>);
        impl<P: PlaneLife> SafeSlot for $name<P> {
            type In = $in;
            type Out = $out;
            type State = P;
            fn call(
                $inst: Instance<'_, P>,
                $input: Lent<'_, $in>,
                #[allow(unused_mut)] mut $o: Out<'_, $out>,
            ) -> Outcome {
                $body
            }
        }
    };
}

plane_slot!(
    /// `validate`: [`PlaneLife::validate`].
    Validate(ValidateIn => OutHead) |_, input, out| {
        match P::validate(input.settings().bytes()) {
            Ok(()) => Outcome::Ready,
            Err(r) => out.fail(r),
        }
    }
);

plane_slot!(
    /// `open`: [`PlaneLife::open`]; the first generation is published and the state held.
    Open(PlaneOpenIn => PlaneOpenOut) |instance, input, out| {
        let generation = input.open().generation();
        match P::open(&input) {
            Ok(Opened { plane, first }) => {
                out.publish_with(
                    |o| &o.snapshot,
                    plane.generations(),
                    generation,
                    &first.spec,
                    first.held,
                );
                plane.published(generation);
                instance.open(plane);
                Outcome::Ready
            }
            Err(r) => out.fail(r),
        }
    }
);

plane_slot!(
    /// `refresh`: [`PlaneLife::refresh_in`]; its generation is published. FAILED with no instance.
    Refresh(RefreshIn => PlaneRefreshOut) |instance, input, out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        let generation = input.generation();
        match plane.refresh_in(&input) {
            Ok(next) => {
                out.publish_with(|o| &o.snapshot, plane.generations(), generation, &next.spec, next.held);
                plane.published(generation);
                Outcome::Ready
            }
            Err(r) => out.fail(r),
        }
    }
);

plane_slot!(
    /// `retire`: the generation's snapshot is dropped, then [`PlaneLife::retire`].
    Retire(GenIn => OutHead) |instance, input, _out| {
        if let Some(plane) = instance.get() {
            plane.generations().retire(input.generation());
            plane.retire(input.generation());
        }
        Outcome::Ready
    }
);

plane_slot!(
    /// `tick`: [`PlaneLife::tick`].
    Tick(TickIn => TickOut) |instance, input, out| { P::tick(instance, input, out) }
);

plane_slot!(
    /// `drive`: [`PlaneLife::drive`].
    Drive(PlaneDriveIn => PlaneDriveOut) |instance, input, out| { P::drive(instance, input, out) }
);

plane_slot!(
    /// `cancel`: [`PlaneLife::cancel`].
    Cancel(PlaneCancelIn => PlaneCancelOut) |instance, input, out| { P::cancel(instance, input, out) }
);

plane_slot!(
    /// `release`: READY; a plane answers under no lease.
    Release(ReleaseIn => OutHead) |_, _, _out| { Outcome::Ready }
);

plane_slot!(
    /// `close`: READY; the SDK drops the state and every snapshot it still holds.
    Close(InHead => OutHead) |_, _, _out| { Outcome::Ready }
);

/// `hydrate` or `start` for a plane that names none (`export_plugin!`'s `plane` arm): READY, there
/// is nothing to warm or start.
#[derive(Debug)]
pub struct Inert;

impl Slot for Inert {
    type In = GenIn;
    type Out = OutHead;
    fn call(_: *mut c_void, _: &GenIn, _: &mut OutHead) -> Outcome {
        Outcome::Ready
    }
}

/// `serve` for a plane that names none (`export_plugin!`'s `plane` arm): REFUSED, a plane with no
/// routes serves no request (never an open default).
#[derive(Debug)]
pub struct NoServe;

impl Slot for NoServe {
    type In = ServeIn;
    type Out = ServeOut;
    fn call(_: *mut c_void, _: &ServeIn, _: &mut ServeOut) -> Outcome {
        Outcome::Refused
    }
}

#[cfg(test)]
#[path = "tests/plane_life_tests.rs"]
mod tests;
