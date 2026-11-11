/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors */
#include "busbar_plugin.h"
#define TEXT(s) {(const uint8_t *)(s), sizeof(s)-1}
#ifndef WITNESS_MECHANISM
#define WITNESS_MECHANISM BB_MECH_MECHANISM_VERSION
#endif
static _Thread_local bb_measurement_UnitCount count;
static bb_mech_RawOutcome validate(void *instance, const void *input, void *output) {
    (void)instance;
    const bb_mech_InHead *in = input;
    bb_mech_OutHead *out = output;
    count = (bb_measurement_UnitCount){0, BB_MEASUREMENT_UNITS_REPORTED_MICROS, UINT64_C(1500001)};
    out->envelope.measurements = (bb_measurement_MeasurementBatch){in->measurement_revision, &count, 1};
    out->outcome = BB_MECH_Outcome_Ready;
    return out->outcome;
}
static const bb_measurement_BillableClass classes[] = {{TEXT("raw"), TEXT("units")}};
static const bb_mech_Statement statement = {
    .size = sizeof(bb_mech_Statement), .kind = BB_MECH_KindCode_Secret,
    .kind_abi = BB_SECRET_ABI_VERSION, .max_inflight = 1,
    .name = TEXT("native-measurement"), .version = TEXT("1.0.0"),
    .measurement_classes = classes, .measurement_classes_len = 1,
};
static const bb_secret_Ops ops = {
    .head = {.size=sizeof(bb_secret_Ops), .slots=11,
        .validate=validate, .open=validate, .refresh=validate, .retire=validate,
        .tick=validate, .drive=validate, .cancel=validate, .release=validate, .close=validate},
    .resolve=validate, .check=validate,
};
static const bb_mech_Door door = {
    .magic=BB_MECH_DOOR_MAGIC, .mechanism_version=WITNESS_MECHANISM, .size=sizeof(bb_mech_Door),
    .kind=BB_MECH_KindCode_Secret, .kind_abi=BB_SECRET_ABI_VERSION,
    .statement=&statement, .ops=&ops.head, .layout=BB_SECRET_LAYOUT_FINGERPRINT,
};
const bb_mech_Door *busbar_plugin_door(void) {return &door;}
