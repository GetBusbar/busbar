/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors */
/* The C-HEADER fixture (ABI-MIN3-INTERFACE §7.8, §14; owner W1-A13): a secret plugin built from busbar_plugin.h
 * alone, giving the normative C answers of §7.8. References (the `settings` object, byte for byte):
 *   {"name":"db"}          VALUE "s3cret"
 *   {"name":"numbered"}    writes a VALUE, logs once with bb_log and once with bb_log_error, then answers
 *                          bb_fail_numbered (C-ERROR-RECORDS; bb_fail's zeroing is C-ZEROIZE-SYNC's check)
 *   {"name":"arena"}       C-HEADER's arena arm inside one entry: VALUE "ok", or FAILED naming the broken check
 *   {"name":"null-empty"}  C-NULL-EMPTY (a): {NULL, 0} in every crypto field its row allows empty; VALUE = per
 *                          call, status and out.len as two u32 LE
 *   any other object       REFUSED NOT_FOUND; not an object: REFUSED INVALID */
#include <stdlib.h>
#include "busbar_plugin.h"

#ifndef BB_FIXTURE_TARGET
#define BB_FIXTURE_TARGET "" /* the admit arm passes the host's <arch>-<os>-<env> */
#endif
#define FIXTURE_ERROR 7071u /* the one number this image declares in D_ERRORS */
/* abi::host::alg and crypto_status: the header carries none, the fixture names the four it calls. */
enum { ALG_SHA256 = 1, ALG_HMAC_SHA256 = 16, ALG_AEAD_SEAL = 96, CRYPTO_LIMIT = 4 };

static const bb_stamp STAMP = {
    .magic = "BUSBAR\0PLUGSTAMP", .format = BB_STAMP_FORMAT, .size = sizeof(bb_stamp), .kind = BB_KIND_SECRET,
    .kind_abi = BB_SECRET_ABI, .core_abi = BB_CORE, .flags = 1 /* STAMP_LOCAL_BUILD: build_id zero */,
    .layout = BB_SECRET_FP, .core_layout = BB_CORE_FP, .kind_minor = BB_SECRET_MINOR,
    .core_minor = BB_CORE_MINOR, .engine_min = {0, 0, 0, 0}, .engine_max = {0xFFFF, 0xFFFF, 0xFFFF, 0},
    .name = "busbar-secret-c-fixture", .version = "1.6.0", .target = BB_FIXTURE_TARGET, .crypto = "external",
};
static const char SCHEMA[] = "{\"type\":\"object\",\"additionalProperties\":false}";
static const char REF_SCHEMA[] = "{\"type\":\"object\",\"required\":[\"name\"],\"additionalProperties\":false,"
                                 "\"properties\":{\"name\":{\"type\":\"string\"}}}";

static bool is(bb_bytes b, const char *s) { return b.len == strlen(s) && (!b.len || !memcmp(b.ptr, s, b.len)); }
static bool apart(bb_bytes a, bb_bytes b) { return a.ptr + a.len <= b.ptr || b.ptr + b.len <= a.ptr; }

static bb_status describe(const void *inst, const bb_host *h, const bb_call *call, bb_raw_out *out) {
    (void)inst;
    (void)call;
    bb_mask_rec m = {BB_SECRET_REQUIRED};
    uint8_t errors[2] = {FIXTURE_ERROR & 0xFFu, FIXTURE_ERROR >> 8};
    if (!bb_put(h, out, BB_TAG_D_METHODS, &m, sizeof m) || !bb_put(h, out, BB_TAG_D_SCHEMA, SCHEMA, sizeof SCHEMA - 1)
        || !bb_put(h, out, BB_TAG_SECRET_D_REF_SCHEMA, REF_SCHEMA, sizeof REF_SCHEMA - 1)
        || !bb_put(h, out, BB_TAG_D_ERRORS, errors, sizeof errors))
        return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, "describe does not fit");
    return BB_OK;
}

static bb_status open_(const void *inst, const bb_host *h, const bb_call *call, bb_raw_out *out) {
    (void)inst;
    bb_bytes config = bb_call_blob(call, 0); /* blob 0 = the bound config */
    uint32_t flags = 0;                      /* head = flags (u32) */
    if (!bb_call_u32(call, 0, &flags)) return BB_FAULT;
    if (!config.len || config.ptr[0] != '{') return bb_fail(h, out, BB_REFUSED, BB_R_CONFIG, "config is not an object");
    if (flags & BB_OPEN_DRY_RUN) return BB_OK;
    uint8_t *state = malloc(1);
    if (!state) return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, "out of memory");
    bb_instance_rec rec = {(uint64_t)(uintptr_t)state};
    if (!bb_put(h, out, BB_TAG_INSTANCE, &rec, sizeof rec)) {
        free(state);
        return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, "instance does not fit");
    }
    return BB_OK;
}

/* C-HEADER arena arm (r4 H3): two HMACs in one entry land apart and stay intact; random lands after both; a call
 * past 1 MiB + 64 is LIMIT with out empty and both HMACs intact. */
static const char *arena(const bb_host *h) {
    static const uint8_t kat[32] = {0x92, 0x70, 0x81, 0x32, 0xe3, 0x01, 0xb7, 0x88, 0xc6, 0x8f, 0xb7,
                                    0x65, 0x2f, 0x96, 0xdd, 0xce, 0x09, 0x72, 0xee, 0x26, 0xf3, 0xe3,
                                    0xaf, 0xed, 0x2e, 0x7e, 0xe5, 0xf6, 0xd9, 0xe3, 0xea, 0x45};
    bb_crypto_req r = {ALG_HMAC_SHA256, 0, 0, {(const uint8_t *)"Jefe", 4}, {(const uint8_t *)"expected", 8}};
    bb_crypto_ret d1 = h->crypto(h->ctx, &r);
    r.data = (bb_bytes){(const uint8_t *)"provided", 8};
    bb_crypto_ret d2 = h->crypto(h->ctx, &r);
    if (d1.status || d2.status || d1.out.len != 32 || d2.out.len != 32) return "hmac answered";
    uint8_t second[32];
    memcpy(second, d2.out.ptr, 32);
    if (!apart(d1.out, d2.out)) return "hmac outputs overlap";
    if (memcmp(d1.out.ptr, kat, 32)) return "first hmac is not the KAT";
    if (!memcmp(d1.out.ptr, d2.out.ptr, 32)) return "both hmacs equal";
    bb_crypto_ret rnd = h->random(h->ctx, 64);
    if (rnd.status || rnd.out.len != 64 || !apart(rnd.out, d1.out) || !apart(rnd.out, d2.out)) return "random";
    for (int i = 0; i < 17; i++) {
        bb_crypto_ret big = h->random(h->ctx, 65536);
        if (big.status == CRYPTO_LIMIT) {
            if (big.out.len) return "LIMIT with output";
            if (memcmp(d1.out.ptr, kat, 32) || memcmp(d2.out.ptr, second, 32)) return "hmac changed at LIMIT";
            return NULL;
        }
        if (big.status) return "random 65536 answered";
    }
    return "no LIMIT past 1 MiB + 64";
}

/* C-NULL-EMPTY (a): {NULL, 0} wherever the row allows an empty field. */
static bb_status null_empty(const bb_host *h, bb_raw_out *out) {
    static const uint8_t key[16];
    const bb_bytes none = {NULL, 0};
    bb_crypto_req reqs[3] = {
        {ALG_SHA256, 0, 0, none, none, none, none},
        {ALG_HMAC_SHA256, 0, 0, {key, sizeof key}, none, none, none},
        {ALG_AEAD_SEAL, 0, 0, {key, sizeof key}, none, none, none},
    };
    uint32_t seen[6];
    for (int i = 0; i < 3; i++) {
        bb_crypto_ret ret = h->crypto(h->ctx, &reqs[i]);
        seen[2 * i] = ret.status;
        seen[2 * i + 1] = (uint32_t)ret.out.len;
    }
    if (!bb_put(h, out, BB_TAG_SECRET_VALUE, seen, sizeof seen))
        return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, "value does not fit");
    return BB_OK;
}

static bb_status resolve(const void *inst, const bb_host *h, const bb_call *call, bb_raw_out *out) {
    bb_bytes reference = bb_call_blob(call, 0); /* the secret kind's `resolve`: blob 0 = the reference */
    (void)inst;
    if (!reference.len || reference.ptr[0] != '{') return bb_fail(h, out, BB_REFUSED, BB_R_INVALID, "not an object");
    if (is(reference, "{\"name\":\"db\"}")) {
        if (!bb_put(h, out, BB_TAG_SECRET_VALUE, "s3cret", 6))
            return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, "value does not fit");
        return BB_OK;
    }
    if (is(reference, "{\"name\":\"numbered\"}")) {
        static const char WIPE[] = "a value the failure must wipe, longer than the FAIL and ERROR records written over it";
        (void)bb_put(h, out, BB_TAG_SECRET_VALUE, WIPE, sizeof WIPE - 1);
        bb_str msg = {(const uint8_t *)"numbered", 8};
        bb_log(h, BB_LOG_INFO, msg);
        bb_log_error(h, BB_LOG_WARN, FIXTURE_ERROR, msg);
        return bb_fail_numbered(h, out, BB_FAILED, BB_F_INTERNAL, FIXTURE_ERROR, "numbered failure");
    }
    if (is(reference, "{\"name\":\"arena\"}")) {
        const char *broken = arena(h);
        if (broken) return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, broken);
        if (!bb_put(h, out, BB_TAG_SECRET_VALUE, "ok", 2))
            return bb_fail(h, out, BB_FAILED, BB_F_INTERNAL, "value does not fit");
        return BB_OK;
    }
    if (is(reference, "{\"name\":\"null-empty\"}")) return null_empty(h, out);
    return bb_fail(h, out, BB_REFUSED, BB_R_NOT_FOUND, "no such name");
}

static bb_status resume(const void *inst, const bb_host *h, const bb_call *call, bb_raw_out *out) {
    (void)inst;
    (void)h;
    (void)call; /* call->session = the chain token; blob 0 = the results */
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

static const bb_entry TABLE[BB_SECRET_ENTRIES] = {resolve};
static const bb_plugin PLUGIN = {
    sizeof(bb_plugin), BB_SECRET_ENTRIES, &STAMP, TABLE, describe, open_, resume, cancel, close_, {(const uint8_t *)"secret-c", 8},
};
const bb_plugin *busbar_plugin(void);
const bb_plugin *busbar_plugin(void) { return &PLUGIN; }
