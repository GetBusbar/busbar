// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S DOOR, SERVED: the slots the kernel calls over the plane ABI, on the SDK's safe
//! surface. [`door`] is the LINKED door; the same function is the DROPPED door once a `cdylib`
//! exports it (`busbar_contract::export_door!`), so the two cannot answer differently.
//!
//! The lifecycle is this plane's own:
//!
//! * `validate` reads the settings blob as the `tools:` section ([`door::read_settings`]) and
//!   refuses in the grammar's words;
//! * `open` judges the same section, reads the deployment's public base URL and publishes the
//!   first generation's snapshot ([`door::snapshot_spec`]); `refresh` judges the new section and
//!   publishes the next generation over the base URL `open` was given; `retire` drops a
//!   generation's snapshot. The section each generation serves is held once the request path
//!   reads it;
//! * `tick` wants no tick, `drive` has no session with unsolicited output, `cancel` finds nothing
//!   in flight, and `release`/`close` hold nothing the SDK does not already drop.

use busbar_contract::abi::mechanism::call::{InHead, OutHead, Outcome};
use busbar_contract::abi::mechanism::door::{KindTailHead, Statement};
use busbar_contract::abi::mechanism::lifecycle::{
    CancelIn, CancelOut, GenIn, RefreshIn, ReleaseIn, TickIn, TickOut, ValidateIn,
};
use busbar_contract::abi::plane::{
    ArriveIn, ArriveOut, OnPieceIn, OnPieceOut, PlaneDriveIn, PlaneDriveOut, PlaneOpenIn,
    PlaneOpenOut, PlaneRefreshOut, PlaneSnapshot, ProjectIn, ProjectOut, RefusalIn, RefusalOut,
    ServeIn, ServeOut, CANCEL_ABORTED,
};
use busbar_contract::abi::sdk::door::statement;
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::publish::Generations;
use busbar_contract::abi::sdk::{Instance, Lent, Out, Safe, SafeSlot};

use crate::door;

/// The most calls the kernel keeps in flight on one instance, as the transport doors state it.
const MAX_INFLIGHT: u32 = 64;

/// The version the Statement names: the crate's (a test pins the two equal).
pub const VERSION: &str = "1.6.0";

/// THE STATEMENT: the plane's name and version, and its tail ([`door::TAIL`]).
pub const STATEMENT: Statement = Statement {
    kind_tail: (door::TAIL as *const busbar_contract::abi::plane::PlaneTail).cast::<KindTailHead>(),
    ..statement(crate::PLANE_KEY, VERSION, MAX_INFLIGHT)
};

/// One instance: the public base URL `open` was given, and every live generation's snapshot.
pub struct McpDoor {
    public_url: Option<String>,
    generations: Generations<PlaneSnapshot>,
}

/// The settings blob read as the `tools:` section, or the refusal in the grammar's words.
fn section(bytes: &[u8]) -> Result<(), Refusal> {
    door::read_settings(bytes)
        .map(|_| ())
        .map_err(Refusal::refused)
}

/// The public base URL the host lent, when it states one.
fn public_url(bytes: &[u8]) -> Option<String> {
    std::str::from_utf8(bytes)
        .ok()
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// One slot body on the SDK's safe surface, over this plane's [`McpDoor`].
macro_rules! slot {
    ($(#[$doc:meta])* $name:ident, $in:ty, $out:ty,
     |$inst:pat_param, $input:pat_param, $o:pat_param| $body:block) => {
        $(#[$doc])*
        pub struct $name;
        impl SafeSlot for $name {
            type In = $in;
            type Out = $out;
            type State = McpDoor;
            fn call($inst: Instance<'_, McpDoor>, $input: Lent<'_, $in>, $o: Out<'_, $out>)
                -> Outcome $body
        }
    };
}

slot!(
    /// `validate`: the settings read as the section, or refused in the grammar's words.
    Validate, ValidateIn, OutHead, |_, input, mut out| {
        match section(input.field(|i| &i.settings).bytes()) {
            Ok(_) => Outcome::Ready,
            Err(refusal) => out.fail(refusal),
        }
    }
);

slot!(
    /// `open`: the instance over the section and the public base URL, and the first generation's
    /// snapshot.
    Open, PlaneOpenIn, PlaneOpenOut, |instance, input, mut out| {
        if let Err(refusal) = section(input.field(|i| &i.open.settings).bytes()) {
            return out.fail(refusal);
        }
        let generation = input.get().open.generation;
        let plane = McpDoor {
            public_url: public_url(input.field(|i| &i.public_url).bytes()),
            generations: Generations::new(),
        };
        let spec = door::snapshot_spec(plane.public_url.as_deref());
        out.publish(|o| &o.snapshot, &plane.generations, generation, &spec);
        instance.open(plane);
        Outcome::Ready
    }
);

slot!(
    /// `refresh`: the new section judged, and the next generation's snapshot over the same public base
    /// URL.
    Refresh, RefreshIn, PlaneRefreshOut, |instance, input, mut out| {
        let Some(plane) = instance.get() else {
            return Outcome::Failed;
        };
        if let Err(refusal) = section(input.field(|i| &i.settings).bytes()) {
            return out.fail(refusal);
        }
        let spec = door::snapshot_spec(plane.public_url.as_deref());
        out.publish(|o| &o.snapshot, &plane.generations, input.get().generation, &spec);
        Outcome::Ready
    }
);

slot!(
    /// `retire`: the generation's snapshot is dropped.
    Retire, GenIn, OutHead, |instance, input, _| {
        if let Some(plane) = instance.get() {
            plane.generations.retire(input.get().generation);
        }
        Outcome::Ready
    }
);

slot!(
    /// `tick`: none wanted.
    Tick, TickIn, TickOut, |_, _, mut out| {
        out.set(|o| &o.next_tick_ns, 0);
        Outcome::Ready
    }
);

slot!(
    /// `drive`: no session has unsolicited output.
    Drive, PlaneDriveIn, PlaneDriveOut, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `cancel`: nothing is in flight, so nothing moved.
    Cancel, CancelIn, CancelOut, |_, _, mut out| {
        out.set(|o| &o.disposition, CANCEL_ABORTED);
        Outcome::Ready
    }
);

slot!(
    /// `release`: this plane answers under no lease.
    Release, ReleaseIn, OutHead, |_, _, _| { Outcome::Ready }
);

slot!(
    /// `close`: the SDK drops the instance and every snapshot it still holds.
    Close, InHead, OutHead, |_, _, _| { Outcome::Ready }
);

// ── the request path ──────────────────────────────────────────────────────────────────────────
//
// Nothing routes to these before the flip: the engine still serves every request, and no
// production path loads this door (`tests/door_unrouted.rs` holds that). Each is REFUSED.

slot!(
    /// `arrive`. TRANSITIONAL: filled when the kernel's plane driver serves the door's request path.
    Arrive, ArriveIn, ArriveOut, |_, _, _| { Outcome::Refused }
);

slot!(
    /// `on_piece`. TRANSITIONAL: filled when the kernel's plane driver serves the door's request path.
    OnPiece, OnPieceIn, OnPieceOut, |_, _, _| { Outcome::Refused }
);

slot!(
    /// `refusal`. TRANSITIONAL: filled when the kernel's plane driver serves the door's request path.
    RefusalSlot, RefusalIn, RefusalOut, |_, _, _| { Outcome::Refused }
);

slot!(
    /// `serve`. TRANSITIONAL: filled when the kernel's plane driver serves the door's request path.
    Serve, ServeIn, ServeOut, |_, _, _| { Outcome::Refused }
);

slot!(
    /// `hydrate`. TRANSITIONAL: filled when the kernel's plane driver serves the door's request path.
    Hydrate, GenIn, OutHead, |_, _, _| { Outcome::Refused }
);

slot!(
    /// `start`. TRANSITIONAL: filled when the kernel's plane driver serves the door's request path.
    Start, GenIn, OutHead, |_, _, _| { Outcome::Refused }
);

slot!(
    /// `project`. TRANSITIONAL: filled when the kernel's plane driver serves the door's request path.
    Project, ProjectIn, ProjectOut, |_, _, _| { Outcome::Refused }
);

busbar_contract::plugin_door! {
    ops: busbar_contract::abi::plane::Ops,
    statement: STATEMENT,
    lifecycle: {
        validate: Safe<Validate>, open: Safe<Open>, refresh: Safe<Refresh>, retire: Safe<Retire>,
        tick: Safe<Tick>, drive: Safe<Drive>, cancel: Safe<Cancel>, release: Safe<Release>,
        close: Safe<Close>,
    },
    kind_ops: {
        arrive: Safe<Arrive>, on_piece: Safe<OnPiece>, refusal: Safe<RefusalSlot>,
        serve: Safe<Serve>, hydrate: Safe<Hydrate>, start: Safe<Start>, project: Safe<Project>,
    },
}
