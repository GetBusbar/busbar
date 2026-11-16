/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors */
/* C-ERROR-RECORDS' C arm (ABI-MIN3-INTERFACE §7.8, §14; owner W1-A13): a host written against busbar_plugin.h
 * that drives the fixture out of process and prints what it saw, one line each, for the Rust side to compare
 * with the Rust shim's bytes and arguments:
 *   log <level> <error> <msg hex>              every log call, in order
 *   describe <status> <answer hex>
 *   numbered <status> <zeroed|residue> <answer hex>   residue = a byte past the answer is not zero
 * Its grow moves to a larger zeroed block and wipes the old one, as the host does (I11). */
#include <stdio.h>
#include <stdlib.h>
#include "busbar_plugin.h"

const bb_plugin *busbar_plugin(void);

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
    printf("log %u %u ", (unsigned)level, (unsigned)error);
    hex(msg.ptr, msg.len);
    printf("\n");
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
    return BB_FAULT; /* a secret's open never calls it */
}

static bb_raw_out fresh(size_t cap) {
    bb_raw_out o = {calloc(cap, 1), 0, cap};
    if (!o.ptr) exit(2);
    return o;
}

int main(void) {
    const bb_host host = {NULL, zero, zero, random_, crypto, log_, log_level, grow, deployment, migrate_admit};
    const bb_plugin *p = busbar_plugin();
    bb_raw_out o = fresh(16); /* small, so describe grows */
    bb_status s = p->describe(&host, &o);
    printf("describe %u ", (unsigned)s);
    hex(o.ptr, o.len);
    printf("\n");
    free(o.ptr);

    o = fresh(4096);
    bb_bytes config = {(const uint8_t *)"{}", 2};
    if (p->open(&host, config, 0, &o) != BB_OK || o.len != sizeof(bb_rec_head) + sizeof(bb_instance_rec)) return 3;
    bb_instance_rec inst;
    memcpy(&inst, o.ptr + sizeof(bb_rec_head), sizeof inst);
    free(o.ptr);

    o = fresh(4096);
    const bb_secret_vt *vt = p->kind_vt;
    bb_bytes reference = {(const uint8_t *)"{\"name\":\"numbered\"}", 19};
    s = vt->resolve((const void *)(uintptr_t)inst.inst, &host, reference, &o);
    bool zeroed = true;
    for (size_t i = o.len; i < o.cap; i++) zeroed = zeroed && !o.ptr[i];
    printf("numbered %u %s ", (unsigned)s, zeroed ? "zeroed" : "residue");
    hex(o.ptr, o.len);
    printf("\n");
    free(o.ptr);
    return p->close((const void *)(uintptr_t)inst.inst) == BB_OK ? 0 : 4;
}
