/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors */
/* busbar_plugin.h: plugin surface for C (core contract 3.0, secret kind 3.0). Little-endian, LP64/LLP64-safe
 * (every field is fixed-width or a pointer/size_t, as the Rust #[repr(C)] side). Frozen: ABI-MIN3-INTERFACE §7.8.
 * Hand-written (§16.103); C-HEADER (§14, tests/c_header) asserts every size, offset and constant below against
 * the Rust items, so a change on either side fails CI until both move in one MR (owner W1-A13). */
#ifndef BUSBAR_PLUGIN_H
#define BUSBAR_PLUGIN_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* A version is first.second per contract: the first number moves when something is changed or removed, the
 * second when something is added. An image carries the core's and its kind's (interface revision C.4). */
#define BB_CORE 3u
#define BB_CORE_MINOR 0u
#define BB_SECRET_ABI 3u
#define BB_SECRET_MINOR 0u
#define BB_KIND_SECRET 2u
#define BB_CORE_FP   0x3b0e1903e87c9e9cull /* versions::CORE_CONTRACT.wire; C-HEADER asserts == CORE_FP */
#define BB_SECRET_FP 0x35486c566edc8f6eull /* C-HEADER asserts == secret::FP */

/* §2 */
typedef struct { const uint8_t *ptr; size_t len; } bb_bytes;  /* ptr may be NULL only when len == 0; {NULL,0} is empty everywhere (round 17, C-NULL-EMPTY) */
typedef bb_bytes bb_str;                                       /* UTF-8 */
/* The answer block. It is the caller's: at least BB_RAW_OUT_MIN bytes, NOT pre-filled. Write only [len, cap),
 * state what you wrote in len, ask h->grow for more. Never read bytes you did not write. */
typedef struct { uint8_t *ptr; size_t len; size_t cap; } bb_raw_out;
#define BB_RAW_OUT_MIN 80u
typedef uint32_t bb_status;
enum { BB_OK = 0, BB_REFUSED = 1, BB_FAILED = 2, BB_NEED = 3, BB_FAULT = 4 };
typedef uint64_t bb_token;

/* The one call record (core 3.0). Every method of every kind, and describe, open and resume, cross as
 * entry(inst, host, &call, &out). Read by prefix and by position: a field added later goes at the end of head,
 * texts or blobs, where an older image never looks. A pair list crosses as ONE blob lending a bb_pair array
 * (len = n * sizeof(bb_pair)). */
typedef struct { const bb_str *ptr; size_t len; } bb_strs;
typedef struct { const bb_bytes *ptr; size_t len; } bb_blobs;
typedef struct {
    uint64_t session;                          /* the session or chain token; 0 for a plain call */
    uint64_t mono_ns;                          /* the host's one clock reading for this operation; 0 = not given */
    bb_bytes head;                             /* the method's numbers: little-endian, natural alignment */
    bb_strs texts;                             /* borrowed UTF-8 fields, by position */
    bb_blobs blobs;                            /* borrowed byte fields, by position */
} bb_call;
struct bb_host;
/* The only entry type. Every kind table is an array of these. */
typedef bb_status (*bb_entry)(const void *inst, const struct bb_host *h, const bb_call *call, bb_raw_out *out);
static inline bb_bytes bb_call_blob(const bb_call *c, size_t i) {
    bb_bytes none = { NULL, 0 };
    return i < c->blobs.len ? c->blobs.ptr[i] : none;
}
static inline bool bb_call_u32(const bb_call *c, size_t at, uint32_t *v) {
    if (at + 4 > c->head.len) return false;
    memcpy(v, c->head.ptr + at, 4);
    return true;
}

/* §5 */
typedef struct { uint32_t alg, key_form; uint64_t param; bb_bytes key, data, aux, aad; } bb_crypto_req;
typedef struct { uint32_t status, _r; bb_bytes out; } bb_crypto_ret;
typedef struct { uint8_t bytes[16]; } bb_deployment_id;            /* round 28, §5 DeploymentId */
typedef struct bb_host {
    uint32_t size, count;                      /* core 3.0: this table's size in bytes and its number of entries (9); entries are only appended */
    const void *ctx;
    uint64_t      (*now)(const void *ctx);
    uint64_t      (*mono)(const void *ctx);
    bb_crypto_ret (*random)(const void *ctx, size_t len);              /* out: see crypto (r4 H3) */
    bb_crypto_ret (*crypto)(const void *ctx, const bb_crypto_req *req); /* out valid, unchanged, until this entry returns: append-only, a later call never reuses or zeroes it; zeroed after; LIMIT when full */
    void          (*log)(const void *ctx, uint32_t level, uint32_t error, bb_str msg); /* round 34: error = a D_ERRORS number, 0 = none */
    uint32_t      (*log_level)(const void *ctx);
    bool          (*grow)(const void *ctx, bb_raw_out *out, size_t need);
    bb_deployment_id (*deployment)(const void *ctx);                  /* round 28: all zero until boot has the row */
    bb_status (*service)(const void *ctx, uint64_t id, const bb_call *call, bb_raw_out *out); /* core 3.0: a kind's own host service; id = kind code << 32 | n (store service 1 = the recoverable gate, head = count u64) */
} bb_host;
enum { BB_LOG_ERROR = 1, BB_LOG_WARN = 2, BB_LOG_INFO = 3, BB_LOG_DEBUG = 4, BB_LOG_TRACE = 5 };

/* Core host services (core 3.0): ids with no kind code in the high 32 bits, served through bb_host.service.
 * BB_SERVICE_HMAC_PARTS: HMAC over parts (E.1). call.head = alg (uint32, a BB_ALG HMAC number: 16 SHA-256);
 * call.blobs[0] = the key, call.blobs[1..] = the message parts in order (0 to BB_HMAC_PARTS_MAX of them); the
 * message is their concatenation and the host copies none. out (at least BB_RAW_OUT_MIN bytes) receives a
 * uint32 crypto status (little-endian; 0 OK, 2 INVALID, 3 UNAVAILABLE, 4 LIMIT, 5 RNG) and, only when it is 0,
 * the tag. BB_FAULT: the call could not be read; nothing was written. */
#define BB_SERVICE_HMAC_PARTS 1ull
#define BB_HMAC_PARTS_MAX 8u

/* #408: native plane resource facts. These records grant no execution authority. */
/* Plane 2.0: fact bit 3 (FB_RESOURCE_ADMISSION) is retired. */
#define BB_PLANE_FB_CHANNEL_OPEN (1ull << 4)
#define BB_PLANE_M_SELECT_RESOURCES (1ull << 9)
#define BB_PLANE_M_CHANNEL (1ull << 10)
#define BB_RESOURCE_INVENTORY 1u
#define BB_RESOURCE_SELECT 2u
#define BB_TAG_RESOURCE_ENTRY 0x0168u
#define BB_TAG_RESOURCE_DESCRIPTOR 0x0169u
#define BB_TAG_RESOURCE_KIND 0x016Au
#define BB_TAG_RESOURCE_VALUE 0x016Bu
#define BB_TAG_RESOURCE_FORWARD 0x016Cu
#define BB_TAG_RESOURCE_UPSTREAM 0x016Du
#define BB_TAG_RESOURCE_DIALECT 0x016Eu
#define BB_TAG_RESOURCE_MODEL 0x016Fu
#define BB_TAG_RESOURCE_SELECTED 0x0170u
#define BB_TAG_RESOURCE_ECHO 0x0171u
#define BB_TAG_RESOURCE_POOL 0x0172u
#define BB_TAG_RESOURCE_MEMBER 0x0173u
#define BB_TAG_D_ROUTE_RESOURCES 0x0199u

typedef struct { bb_str name; bb_bytes value; } bb_pair;
/* Core 3.0: there are no per-kind view structs and no per-kind table types. A kind's table is an array of
 * bb_entry in the kind's method order, and each method's head / texts / blobs layout is the kind contract's
 * (the interface revision's LAYOUT table). The plane's table has 11 entries: request, upstream, piece, end,
 * rewrite, render, admin, probe, demux, select_resources, channel. */
typedef struct { uint64_t invocation, generation; uint32_t route, descriptor; } bb_resource_echo_rec;

/* §3: records. [bb_rec_head][body][zero pad to 8]. */
typedef struct { uint16_t tag; uint16_t _r; uint32_t len; } bb_rec_head;
enum {
    BB_TAG_TEXT = 0x0001, BB_TAG_FAIL = 0x0002, BB_TAG_INSTANCE = 0x0009,
    /* round 31: 0x000A (MIGRATED) retired */ BB_TAG_CONFIG = 0x000B,
    BB_TAG_ERROR = 0x000D, /* round 34 */
    BB_TAG_D_METHODS = 0x0040, BB_TAG_D_SCHEMA = 0x0042, BB_TAG_D_ERRORS = 0x004C, /* round 34 */
    BB_TAG_ENDPOINT = 0x0075, /* round 32: `check`'s answer, bb_endpoint_rec + dest (TRANSPORT-SECURITY-POLICY §2) */
    BB_TAG_SECRET_VALUE = 0x0100, BB_TAG_SECRET_D_REF_SCHEMA = 0x0181
};
typedef struct { uint32_t status, code; } bb_fail_rec;       /* + UTF-8 detail <= BB_FAIL_TEXT_WIRE_MAX bytes */
#define BB_FAIL_TEXT_WIRE_MAX 3072u /* = abi::FAIL_TEXT_WIRE_MAX (round 15); core scrubs, then cuts to 512 */
typedef struct { uint64_t inst; } bb_instance_rec;
typedef struct { uint64_t mask; } bb_mask_rec;
typedef struct { uint32_t value, _r; } bb_u32_rec;      /* round 34: the ERROR body (U32Rec) */
typedef struct { uint32_t op, flags; } bb_endpoint_rec; /* round 32: + dest tail; op OPEN | FETCH, flags = NeedRec.flags */
enum { BB_R_UNSUPPORTED = 1, BB_R_INVALID = 2, BB_R_NOT_FOUND = 3, BB_R_DENIED = 4, BB_R_CONFIG = 5,
       BB_R_VERSION = 17 };
#define BB_F_INTERNAL 4u /* = failed::F_INTERNAL (§4.1); C-HEADER asserts every value in this file */
#define BB_SECRET_REQUIRED 0x1ull /* M_RESOLVE */

/* §7.3/§7.4 */
typedef struct { uint16_t major, minor, patch, _reserved; } bb_engine_version;
typedef struct {
    uint8_t magic[16]; uint32_t format, size, kind, kind_abi, core_abi, flags;
    uint64_t layout, core_layout;              /* the kind's and the core's wire fingerprints at exactly these versions */
    uint32_t kind_minor, core_minor;           /* the second numbers */
    uint8_t _reserved2[8];                     /* 0 */
    bb_engine_version engine_min, engine_max;  /* any engine: {0,0,0,0} and {65535,65535,65535,0} */
    uint8_t name[64], version[32], target[32], build_id[32], crypto[8], _reserved[16];
} bb_stamp;                                    /* 272 bytes, format 3; crypto = "external" */
#define BB_STAMP_FORMAT 3u

/* The secret table: one entry, `resolve`. Its call: no head, no texts, blob 0 = the reference
 * (bb_call_blob(call, 0)). The C plugin answers synchronously and never NEEDs. */
#define BB_SECRET_ENTRIES 1u

/* The header `busbar_plugin` returns. It begins with its own size and the number of table entries. */
typedef struct {
    uint32_t size, entries;                    /* sizeof(bb_plugin); BB_SECRET_ENTRIES */
    const bb_stamp *stamp;
    const bb_entry *table;                     /* `entries` entries, the kind's method order */
    bb_entry describe;                         /* inst NULL; the call's fields are empty */
    bb_entry open;                             /* inst NULL; head = flags (u32); blob 0 = the bound config */
    bb_entry resume;                           /* call->session = the chain token; blob 0 = the results */
    bb_status (*cancel)(const void *inst, bb_token tok);
    bb_status (*close)(const void *inst);
    bb_str former_names;                       /* "secret-c" for busbar-secret-c (§12.10 item 2) */
} bb_plugin;
#define BB_OPEN_DRY_RUN 1u
/* The one exported symbol: const bb_plugin *busbar_plugin(void); */

/* Record writer. Appends one record; grows through h->grow (never realloc: the host zeroes the old block).
 * Returns false when the record does not fit under max_out (answer FAILED with bb_fail). */
static inline bool bb_put2(const bb_host *h, bb_raw_out *o, uint16_t tag,
                           const void *a, uint32_t alen, const void *b, uint32_t blen) {
    size_t body = (size_t)alen + blen, need = sizeof(bb_rec_head) + ((body + 7u) & ~(size_t)7u);
    if (o->cap - o->len < need && !h->grow(h->ctx, o, need)) return false;
    bb_rec_head hd = { tag, 0, (uint32_t)body };
    uint8_t *p = o->ptr + o->len;
    memcpy(p, &hd, sizeof hd); p += sizeof hd;
    if (alen) memcpy(p, a, alen);
    if (blen) memcpy(p + alen, b, blen);
    memset(p + body, 0, need - sizeof hd - body);
    o->len += need;
    return true;
}
static inline bool bb_put(const bb_host *h, bb_raw_out *o, uint16_t tag, const void *b, uint32_t len) {
    return bb_put2(h, o, tag, NULL, 0, b, len);
}
/* I11 + §6.4 step 2: zero everything written, then write exactly one FAIL record. Returns status.
   Round 21: a C plugin writes no FAIL facts (none needs one); BB_TAG_FACT after bb_fail is not offered. */
static inline bb_status bb_fail(const bb_host *h, bb_raw_out *o, bb_status status, uint32_t code, const char *text) {
    volatile uint8_t *p = o->ptr; for (size_t i = 0; i < o->len; i++) p[i] = 0;
    o->len = 0;
    bb_fail_rec f = { status, code };
    size_t n = text ? strlen(text) : 0;
    if (n > BB_FAIL_TEXT_WIRE_MAX) { n = BB_FAIL_TEXT_WIRE_MAX; while (n && (((const uint8_t *)text)[n] & 0xC0u) == 0x80u) n--; }
    (void)bb_put2(h, o, BB_TAG_FAIL, &f, sizeof f, text, (uint32_t)n); /* a short text fits BB_RAW_OUT_MIN; a long one grows */
    return status;
}
/* Round 34 (PLUGIN-ERROR-CODES): a numbered Fail = bb_fail, then one ERROR record when number != 0 (16 bytes; FAIL +
   ERROR still fits the first buffer). number is one of this image's D_ERRORS numbers. */
static inline bb_status bb_fail_numbered(const bb_host *h, bb_raw_out *o, bb_status status, uint32_t code,
                                         uint16_t number, const char *text) {
    (void)bb_fail(h, o, status, code, text);
    bb_u32_rec e = { number, 0 };
    if (number) (void)bb_put(h, o, BB_TAG_ERROR, &e, sizeof e);
    return status;
}
/* Round 34: the one log entry; bb_log passes error 0, bb_log_error one declared number. */
static inline void bb_log(const bb_host *h, uint32_t level, bb_str msg) { h->log(h->ctx, level, 0, msg); }
static inline void bb_log_error(const bb_host *h, uint32_t level, uint16_t error, bb_str msg) {
    h->log(h->ctx, level, error, msg);
}
#endif
