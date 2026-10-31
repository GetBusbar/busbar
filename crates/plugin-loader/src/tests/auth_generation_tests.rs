// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

use super::*;

#[test]
fn existing_units_keep_their_generation_at_all_three_services_but_new_requests_cannot_use_it() {
    let (d, side) = served_double();
    let old_generation = generation().wrapping_sub(1);
    let auth = mint_auth_ref(owner(&d), old_generation, 3).unwrap();
    let unit = mint_unit_ref(SIDE_SECRET, old_generation, owner(&d), 2, 9).unwrap();
    side.units.lock().unwrap().push((
        owner(&d),
        unit.id,
        UnitSecret {
            secret: SIDE_SECRET,
            generation: old_generation,
            line: 2,
        },
    ));
    let mut answer = answer_slot();
    let (mut bytes, mut spans) = ([0u8; 64], [NO_FIELD_SPAN; 4]);
    let mut call = auth_call_into(auth, &mut answer, &mut bytes, &mut spans);
    call.unit = unit;
    let (ret, out) = call_auth(d.ctx, &call);
    assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&out));
    assert_eq!(side.calls.lock().unwrap()[0].generation, old_generation);

    call.unit = UnitRef::NONE;
    call.head.handle.seq = 1;
    let (ret, out) = call_auth(d.ctx, &call);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&out), REF_NOT_MINTED);
    call.unit = UnitRef {
        mac: unit.mac ^ 1,
        ..unit
    };
    call.head.handle.seq = 2;
    let (ret, out) = call_auth(d.ctx, &call);
    assert_eq!(ret.outcome(), Outcome::Refused);
    assert_eq!(error(&out), REF_NOT_MINTED);
    assert_eq!(side.calls.lock().unwrap().len(), 1);

    let hand = UnitHandInIn {
        head: head(op::UNIT_HAND_IN, Ticket::NONE, 0, size_of::<UnitHandInIn>()),
        auth,
        unit,
        line: 2,
        _reserved: 0,
        conn: 1,
        stream: 1,
        request: get_view(),
        answer: &mut answer,
    };
    let mut out = blank();
    let ret = HOST_SLOTS.unit_hand_in.unwrap()(d.ctx, std::ptr::from_ref(&hand).cast(), &mut out);
    assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&out));
    assert_eq!(side.hands.lock().unwrap()[0].generation, old_generation);

    let mut refusal = RefusalAnswer {
        size: size_of::<RefusalAnswer>() as u32,
        status: 0,
        _reserved: 0,
        fields: std::ptr::null(),
        fields_len: 0,
        body: no_blob(),
    };
    let refuse = UnitRefuseIn {
        head: head(op::UNIT_REFUSE, Ticket::NONE, 0, size_of::<UnitRefuseIn>()),
        unit,
        cause: REFUSE_NO_ROUTE,
        line: LINE_NONE,
        conn: 1,
        stream: 1,
        answer: &mut refusal,
        request: get_view(),
    };
    let mut out = blank();
    let ret = HOST_SLOTS.unit_refuse.unwrap()(d.ctx, std::ptr::from_ref(&refuse).cast(), &mut out);
    assert_eq!(ret.outcome(), Outcome::Ready, "{}", error(&out));
    assert_eq!(side.refusals.lock().unwrap()[0].generation, old_generation);
}
