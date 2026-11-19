/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors */
/* C-SCRUB-CUT's C arm (ABI-MIN3-INTERFACE §4.1, §7.8, §14; owner W1-A13): a host written against busbar_plugin.h
 * alone that answers bb_fail(BB_FAILED, BB_F_INTERNAL, text) for each command-line argument, in order, into a
 * fresh 4 KiB answer buffer (the first buffer a chain gets), and prints one line per answer:
 *   fail <status> <answer hex>
 * The Rust side compares each answer with the Rust shim's FAIL for the same text (the char-boundary cut at
 * BB_FAIL_TEXT_WIRE_MAX) and scrubs the detail as core does. Its grow moves to a larger zeroed block and wipes
 * the old one, as the host does (I11); bb_fail never needs it. */
#include <stdio.h>
#include <stdlib.h>
#include "busbar_plugin.h"

static void hex(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}
static uint64_t zero(const void *ctx) { (void)ctx; return 0; }
static bb_crypto_ret no_crypto(const void *ctx) {
    (void)ctx;
    bb_crypto_ret r = {2 /* INVALID */, 0, {NULL, 0}};
    return r;
}
static bb_crypto_ret random_(const void *ctx, size_t len) { (void)len; return no_crypto(ctx); }
static bb_crypto_ret crypto(const void *ctx, const bb_crypto_req *req) { (void)req; return no_crypto(ctx); }
static void log_(const void *ctx, uint32_t level, uint32_t error, bb_str msg) {
    (void)ctx;
    (void)level;
    (void)error;
    (void)msg;
}
static uint32_t log_level(const void *ctx) { (void)ctx; return BB_LOG_TRACE; }
static bool grow(const void *ctx, bb_raw_out *o, size_t need) {
    (void)ctx;
    if (need > SIZE_MAX - o->len) return false;
    size_t cap = o->len + need > 2 * o->cap ? o->len + need : 2 * o->cap;
    uint8_t *b = calloc(cap, 1);
    if (!b) return false;
    memcpy(b, o->ptr, o->len);
    memset(o->ptr, 0, o->cap);
    free(o->ptr);
    o->ptr = b;
    o->cap = cap;
    return true;
}
static bb_deployment_id deployment(const void *ctx) {
    (void)ctx;
    bb_deployment_id d = {{0}};
    return d;
}
static bb_status migrate_admit(const void *ctx, uint64_t recoverable) {
    (void)ctx;
    (void)recoverable;
    return BB_FAULT;
}

int main(int argc, char **argv) {
    const bb_host host = {NULL, zero, zero, random_, crypto, log_, log_level, grow, deployment, migrate_admit};
    for (int i = 1; i < argc; i++) {
        bb_raw_out o = {calloc(4096, 1), 0, 4096};
        if (!o.ptr) return 2;
        /* Something written before the Fail, which bb_fail wipes. */
        memset(o.ptr, 0xAB, 64);
        o.len = 64;
        bb_status s = bb_fail(&host, &o, BB_FAILED, BB_F_INTERNAL, argv[i]);
        printf("fail %u ", (unsigned)s);
        hex(o.ptr, o.len);
        printf("\n");
        free(o.ptr);
    }
    return 0;
}
