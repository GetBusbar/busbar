// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! A plane-kind SDK witness: static metadata and owned generation snapshots, without a protocol.

use busbar_contract::abi::host::conn::connector::{Need, DIRECTION_OUTBOUND, EGRESS_PROVIDER};
use busbar_contract::abi::mechanism::call::{AbiStr, Outcome};
use busbar_contract::abi::mechanism::door::{Section, Statement, SECTION_DECLARING};
use busbar_contract::abi::plane::*;
use busbar_contract::abi::sdk::door::{abi_str, statement, AbiIn, AbiOut};
use busbar_contract::abi::sdk::life::Refusal;
use busbar_contract::abi::sdk::plane_life::{Opened, PlaneLife, Published};
use busbar_contract::abi::sdk::publish::{AdminRouteSpec, Generations, SnapshotSpec};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};

pub const NAME: &str = "neutral-plane-witness";
pub const SECTION: &str = "witness_entries";
const SECTIONS: &[Section] = &[Section {
    name: abi_str(SECTION),
    flags: SECTION_DECLARING,
    ..Section::ZERO
}];
const DIALECTS: &[AbiStr] = &[abi_str("witness-wire")];
const SCOPES: &[AbiStr] = &[abi_str("witness_scope")];
const CLASSES: &[OpClass] = &[OpClass {
    op: abi_str("witness_call"),
    name: abi_str("Witness call"),
}];
const RECORDS: &[AbiStr] = &[abi_str("witness_record"), abi_str("witness_history")];
const NEEDS: &[Need] = &[{
    let mut need = Need::EMPTY;
    need.direction = DIRECTION_OUTBOUND;
    need.egress_class = EGRESS_PROVIDER;
    need.transport = abi_str("witness-carrier");
    need.target_from = abi_str("settings.*.target");
    need
}];
const ROUTES: &[AdminRoute] = &[
    AdminRoute {
        verb: abi_str("POST"),
        target: abi_str("/witness/{name}/update"),
        flags: 0,
        _reserved: 0,
        audit_verb: abi_str("update"),
    },
    AdminRoute {
        verb: abi_str("GET"),
        target: abi_str("/witness/{name}/status"),
        flags: 0,
        _reserved: 0,
        audit_verb: abi_str(""),
    },
];
const TAIL: &PlaneTail = &{
    let mut tail = PlaneTail::EMPTY
        .with_dialects(DIALECTS)
        .with_scope_kinds(SCOPES)
        .with_op_classes(CLASSES)
        .with_record_kinds(RECORDS)
        .with_admin_routes(ROUTES);
    tail.ingress = INGRESS_REQUEST_RESPONSE;
    tail.dispatch_shape = SHAPE_PIECEWISE;
    tail.answer_layout = ANSWER_LAYOUT;
    tail.scope = abi_str("witness_scope");
    tail.label = abi_str("Witness");
    tail.subject_noun = abi_str("witness entry");
    tail.admin_noun = abi_str("witness-entry");
    tail.audit_kind = abi_str("witness_entry");
    tail.signing_domain = abi_str("witness/state/v1");
    tail.signing_kid_prefix = abi_str("witness-key-");
    tail.caller_credential_refusal = abi_str("witness refuses caller credentials");
    tail
};
const STATEMENT: Statement = statement(NAME, "1.6.0", 64)
    .with_sections(SECTIONS)
    .with_needs(NEEDS)
    .with_kind_tail(TAIL);

#[derive(Default)]
pub struct Witness {
    generations: Generations<PlaneSnapshot>,
}
fn published() -> Published<()> {
    Published {
        spec: SnapshotSpec {
            admin_routes: vec![
                AdminRouteSpec::new("POST", "/witness/{name}/update", 0).audited("update"),
                AdminRouteSpec::new("GET", "/witness/{name}/status", 0),
            ],
            ..SnapshotSpec::default()
        },
        held: (),
    }
}
impl PlaneLife for Witness {
    type Held = ();
    fn generations(&self) -> &Generations<PlaneSnapshot> {
        &self.generations
    }
    fn open(
        _: &Lent<'_, PlaneOpenIn>,
        _: Option<
            busbar_contract::abi::sdk::lent::KindHostLoan<
                '_,
                busbar_contract::plugin::markers::PlaneKind,
            >,
        >,
    ) -> Result<Opened<Self>, Refusal> {
        Ok(Opened {
            plane: Self::default(),
            first: published(),
        })
    }
    fn refresh(&self, settings: &[u8], _: u64) -> Result<Published<()>, Refusal> {
        Self::validate(settings)?;
        Ok(published())
    }
    fn cancel(
        _: Instance<'_, Self, busbar_contract::plugin::markers::PlaneKind>,
        _: Lent<'_, PlaneCancelIn>,
        mut out: Out<'_, PlaneCancelOut>,
    ) -> Outcome {
        out.set(|o| &o.cancel.disposition, CANCEL_ABORTED);
        Outcome::Ready
    }
}

pub struct Refuses<I, O>(std::marker::PhantomData<(I, O)>);
impl<I: AbiIn, O: AbiOut> SafeSlot for Refuses<I, O> {
    type Kind = busbar_contract::plugin::markers::PlaneKind;
    type In = I;
    type Out = O;
    type State = Witness;
    fn call(_: Instance<'_, Witness, Self::Kind>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}
type Refuse<I, O> = busbar_contract::abi::sdk::Safe<Refuses<I, O>>;
busbar_contract::plugin_door! {
    ops: Ops,
    statement: STATEMENT,
    lifecycle: plane_life(Witness),
    kind_ops: {
        arrive: Refuse<ArriveIn, ArriveOut>,
        on_piece: Refuse<OnPieceIn, OnPieceOut>,
        refusal: Refuse<RefusalIn, RefusalOut>,
        project: Refuse<ProjectIn, ProjectOut>,
        serve: Refuse<ServeIn, ServeOut>,
        hydrate: busbar_contract::abi::sdk::plane_life::Inert,
        start: busbar_contract::abi::sdk::plane_life::Inert,
    },
}
