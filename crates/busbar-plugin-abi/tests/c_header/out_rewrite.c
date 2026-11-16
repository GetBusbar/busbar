/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors */
/* The C-OUT-REWRITE fixture (ABI-MIN3-INTERFACE §2 RawOut, §5 grow, §14; W1-H1): a secret plugin built from
 * busbar_plugin.h alone that rewrites out->ptr and out->cap, which only a C plugin can do (a Rust plugin never
 * sees the raw channel). The host keeps the real pointer, capacity and max_out in its own OutBuf. References
 * (the `settings` object, byte for byte):
 *   {"name":"ptr"}     writes VALUE "kept" into the host buffer, then points out->ptr at a decoy holding a framed
 *                      VALUE "decoy" of the same length
 *   {"name":"cap"}     sets out->cap to SIZE_MAX and asks grow for max_out + 1 bytes, then for 64; then sets
 *                      out->cap to 0 and writes VALUE = the two grow answers as two bytes (0/1)
 *   {"name":"regrow"}  points out->ptr at the decoy with out->cap 0 and asks grow for 24 bytes (the host buffer
 *                      already holds them); VALUE = grow's answer, out->ptr == the host pointer, out->cap == the
 *                      host capacity, as three bytes (0/1), written after putting the host's ptr/cap back
 *   any other object   REFUSED NOT_FOUND; not an object: REFUSED INVALID */
#include <stdlib.h>
#include "busbar_plugin.h"

#ifndef BB_FIXTURE_TARGET
#define BB_FIXTURE_TARGET "" /* the arm passes the host's <arch>-<os>-<env> */
#endif
#define FIXTURE_MAX_OUT ((size_t)1 << 20) /* the max_out the arm's lease grants */

static const bb_stamp STAMP = {
    .magic = "BUSBAR\0PLUGSTAMP", .format = 2, .size = sizeof(bb_stamp), .kind = BB_KIND_SECRET,
    .kind_abi = BB_SECRET_ABI, .mechanism = BB_MECHANISM, .flags = 1 /* STAMP_LOCAL_BUILD: build_id zero */,
    .layout = BB_SECRET_FP, .mechanism_layout = BB_CORE_FP, .semantic = BB_SECRET_FP,
    .mechanism_semantic = BB_CORE_FP, .engine_min = {1, 6, 0, 0}, .engine_max = {1, 6, 0xFFFF, 0},
    .name = "busbar-out-rewrite-c-fixture", .version = "1.6.0", .target = BB_FIXTURE_TARGET, .crypto = "external",
};
static const char SCHEMA[] = "{\"type\":\"object\",\"additionalProperties\":false}";
static const char REF_SCHEMA[] = "{\"type\":\"object\",\"required\":[\"name\"],\"additionalProperties\":false,"
                                 "\"properties\":{\"name\":{\"type\":\"string\"}}}";

/* A buffer the plugin owns; the host must never read an answer from it. */
static uint8_t decoy[4096];

static bool is(bb_bytes b, const char *s) { return b.len == strlen(s) && (!b.len || !memcmp(b.ptr, s, b.len)); }

static bb_status describe(const bb_host *h, bb_raw_out *out) {
    bb_mask_rec m = {BB_SECRET_REQUIRED};
    if (!bb_put(h, out, BB_TAG_D_METHODS, &m, sizeof m) || !bb_put(h, out, BB_TAG_D_SCHEMA, SCHEMA, sizeof SCHEMA - 1)
        || !bb_put(h, out, BB_TAG_SECRET_D_REF_SCHEMA, REF_SCHEMA, sizeof REF_SCHEMA - 1))
        return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, "describe does not fit");
    return BB_OK;
}

static bb_status open_(const bb_host *h, bb_bytes config, uint32_t flags, bb_raw_out *out) {
    if (!config.len || config.ptr[0] != '{') return bb_fail(h, out, BB_REFUSED, BB_R_CONFIG, "config is not an object");
    if (flags & BB_OPEN_DRY_RUN) return BB_OK;
    uint8_t *state = malloc(1);
    if (!state) return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, "out of memory");
    bb_instance_rec inst = {(uint64_t)(uintptr_t)state};
    if (!bb_put(h, out, BB_TAG_INSTANCE, &inst, sizeof inst)) {
        free(state);
        return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, "instance does not fit");
    }
    return BB_OK;
}

static bb_status rewrite_ptr(const bb_host *h, bb_raw_out *out) {
    if (!bb_put(h, out, BB_TAG_SECRET_VALUE, "kept", 4))
        return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, "value does not fit");
    bb_raw_out fake = {decoy, 0, sizeof decoy};
    (void)bb_put(h, &fake, BB_TAG_SECRET_VALUE, "decoy", 5); /* fits: grow is never asked for the decoy */
    out->ptr = decoy;
    out->cap = sizeof decoy;
    return BB_OK;
}

static bb_status rewrite_cap(const bb_host *h, bb_raw_out *out) {
    out->cap = SIZE_MAX;
    uint8_t seen[2];
    seen[0] = h->grow(h->ctx, out, FIXTURE_MAX_OUT + 1) ? 1 : 0;
    seen[1] = h->grow(h->ctx, out, 64) ? 1 : 0;
    out->cap = 0; /* bb_put now asks grow for its record: the host buffer has the room */
    if (!bb_put(h, out, BB_TAG_SECRET_VALUE, seen, sizeof seen))
        return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, "value does not fit");
    return BB_OK;
}

static bb_status regrow(const bb_host *h, bb_raw_out *out) {
    uint8_t *real = out->ptr;
    size_t real_cap = out->cap;
    out->ptr = decoy;
    out->cap = 0;
    uint8_t seen[3];
    seen[0] = h->grow(h->ctx, out, 24) ? 1 : 0;
    seen[1] = out->ptr == real ? 1 : 0;
    seen[2] = out->cap == real_cap ? 1 : 0;
    out->ptr = real; /* whatever grow did, the report goes into the host buffer */
    out->cap = real_cap;
    if (!bb_put(h, out, BB_TAG_SECRET_VALUE, seen, sizeof seen))
        return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, "value does not fit");
    return BB_OK;
}

static bb_status resolve(const void *inst, const bb_host *h, bb_bytes reference, bb_raw_out *out) {
    (void)inst;
    if (!reference.len || reference.ptr[0] != '{') return bb_fail(h, out, BB_REFUSED, BB_R_INVALID, "not an object");
    if (is(reference, "{\"name\":\"ptr\"}")) return rewrite_ptr(h, out);
    if (is(reference, "{\"name\":\"cap\"}")) return rewrite_cap(h, out);
    if (is(reference, "{\"name\":\"regrow\"}")) return regrow(h, out);
    return bb_fail(h, out, BB_REFUSED, BB_R_NOT_FOUND, "no such name");
}

static bb_status resume(const void *inst, const bb_host *h, bb_token tok, bb_bytes results, bb_raw_out *out) {
    (void)inst;
    (void)h;
    (void)tok;
    (void)results;
    (void)out;
    return BB_FAULT; /* it never answers NEED */
}
static bb_status cancel(const void *inst, bb_token tok) {
    (void)inst;
    (void)tok;
    return BB_OK;
}
static bb_status close_(const void *inst) {
    free((void *)inst);
    return BB_OK;
}

static const bb_secret_vt VT = {resolve};
static const bb_plugin PLUGIN = {
    &STAMP, &VT, describe, open_, resume, cancel, close_, {(const uint8_t *)"out-rewrite-c", 13},
};
const bb_plugin *busbar_plugin(void);
const bb_plugin *busbar_plugin(void) { return &PLUGIN; }
