/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors */
/* busbar_plugin.h: the plugin surface for C (core contract 3, secret kind 3: one call shape). Little-endian, LP64/LLP64-safe
 * (every field is fixed-width or a pointer/size_t, as the Rust #[repr(C)] side). Frozen: ABI-MIN3-INTERFACE §7.8.
 * Hand-written (§16.103); C-HEADER (§14, tests/c_header) asserts every size, offset and constant below against
 * the Rust items, so a change on either side fails CI until both move in one MR (owner W1-A13). */
#ifndef BUSBAR_PLUGIN_H
#define BUSBAR_PLUGIN_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BB_MECHANISM 2u
#define BB_SECRET_ABI 2u
#define BB_KIND_SECRET 2u
#define BB_CORE_FP   0x6ee412921500eb10ull /* A13 fills from ci/abi.pin; C-HEADER asserts == CORE_FP */
#define BB_SECRET_FP 0x0e394099f69dffb0ull /* A13 fills from ci/abi.pin; C-HEADER asserts == secret::FP */

/* §2 */
typedef struct { const uint8_t *ptr; size_t len; } bb_bytes;  /* ptr may be NULL only when len == 0; {NULL,0} is empty everywhere (round 17, C-NULL-EMPTY) */
typedef bb_bytes bb_str;                                       /* UTF-8 */
typedef struct { uint8_t *ptr; size_t len; size_t cap; } bb_raw_out;
/* The least answer storage a host hands an entry: out->cap >= BB_OUT_MIN on every call, before any grow. A
 * plugin may write BB_OUT_MIN bytes without calling h->grow; one byte more goes through h->grow. It is what
 * makes bb_fail total (a FAIL record with BB_FAIL_TEXT_WIRE_MAX of text, and the ERROR record after it, fit
 * with room to spare: 8 + 8 + 3072 + 8 + 8 <= 4096). The host's first buffer and every test host's are sized
 * from this name, never from a number of their own. C-HEADER asserts it == the Rust side's OUT_MIN. */
#define BB_OUT_MIN 4096u
typedef uint32_t bb_status;
enum { BB_OK = 0, BB_REFUSED = 1, BB_FAILED = 2, BB_NEED = 3, BB_FAULT = 4 };
typedef uint64_t bb_token;

/* §5 */
typedef struct { uint32_t alg, key_form; uint64_t param; bb_bytes key, data, aux, aad; } bb_crypto_req;
typedef struct { uint32_t status, _r; bb_bytes out; } bb_crypto_ret;
typedef struct { uint8_t bytes[16]; } bb_deployment_id;            /* round 28, §5 DeploymentId */
typedef struct bb_host {
    const void *ctx;
    uint64_t      (*now)(const void *ctx);
    uint64_t      (*mono)(const void *ctx);
    bb_crypto_ret (*random)(const void *ctx, size_t len);              /* out: see crypto (r4 H3) */
    bb_crypto_ret (*crypto)(const void *ctx, const bb_crypto_req *req); /* out valid, unchanged, until this entry returns: append-only, a later call never reuses or zeroes it; zeroed after; LIMIT when full */
    void          (*log)(const void *ctx, uint32_t level, uint32_t error, bb_str msg); /* round 34: error = a D_ERRORS number, 0 = none */
    uint32_t      (*log_level)(const void *ctx);
    bool          (*grow)(const void *ctx, bb_raw_out *out, size_t need);
    bb_deployment_id (*deployment)(const void *ctx);                  /* round 28: all zero until boot has the row */
    bb_status (*migrate_admit)(const void *ctx, uint64_t recoverable); /* round 31: store open only (§5) */
} bb_host;
enum { BB_LOG_ERROR = 1, BB_LOG_WARN = 2, BB_LOG_INFO = 3, BB_LOG_DEBUG = 4, BB_LOG_TRACE = 5 };

/* THE ONE CALL SHAPE (core 3.0). Every method of every kind, and describe, open and resume, crosses as
 *     bb_status entry(const void *inst, const bb_host *h, const bb_call *call, bb_raw_out *out);
 * The call record is the host's, built on its stack and passed by address; it and everything it points at
 * are borrowed for the call (for an async start: until the chain retires). A method reads what its kind's
 * layout names: numbers from `head` (little-endian, each at its natural alignment from the start of head), then
 * texts and blobs by position. Reading is by prefix: a head longer than the fields a plugin knows, or more
 * texts or blobs than it knows, are fields added by a later second number and are never looked at; a head
 * shorter, or a missing text or blob, is a host defect and the entry answers BB_FAULT, writing nothing.
 * session = the session or chain token (0 for a plain call). mono_ns = the host's one clock reading for the
 * operation (0 = not given: h->mono is the fallback). 64 bytes on LP64; C-HEADER asserts every offset. */
typedef struct { const bb_str *ptr; size_t len; } bb_strs;
typedef struct { const bb_bytes *ptr; size_t len; } bb_blobs;
typedef struct {
    uint64_t session, mono_ns;
    bb_bytes head;
    bb_strs texts;
    bb_blobs blobs;
} bb_call;
typedef bb_status (*bb_entry)(const void *inst, const bb_host *h, const bb_call *call, bb_raw_out *out);
/* Blob `i` of a call, or false when the call does not carry it (answer BB_FAULT). */
static inline bool bb_call_blob(const bb_call *c, size_t i, bb_bytes *out) {
    if (c == NULL || c->blobs.ptr == NULL || i >= c->blobs.len) return false;
    *out = c->blobs.ptr[i];
    return true;
}
/* Text `i` of a call, or false when the call does not carry it (answer BB_FAULT). */
static inline bool bb_call_text(const bb_call *c, size_t i, bb_str *out) {
    if (c == NULL || c->texts.ptr == NULL || i >= c->texts.len) return false;
    *out = c->texts.ptr[i];
    return true;
}
/* The u32 at byte `at` of the head (at % 4 == 0), or false when the head is shorter (answer BB_FAULT). */
static inline bool bb_call_u32(const bb_call *c, size_t at, uint32_t *out) {
    if (c == NULL || c->head.ptr == NULL || c->head.len < at + sizeof *out) return false;
    memcpy(out, c->head.ptr + at, sizeof *out);
    return true;
}
/* The u64 at byte `at` of the head (at % 8 == 0), or false when the head is shorter (answer BB_FAULT). */
static inline bool bb_call_u64(const bb_call *c, size_t at, uint64_t *out) {
    if (c == NULL || c->head.ptr == NULL || c->head.len < at + sizeof *out) return false;
    memcpy(out, c->head.ptr + at, sizeof *out);
    return true;
}

/* #408: native plane resource facts. These records grant no execution authority. */
#define BB_PLANE_FB_RESOURCE_ADMISSION (1ull << 3)
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
typedef struct { const bb_pair *ptr; size_t len; } bb_pairs;
typedef struct {
    uint32_t route, flags, auth, _r;
    bb_str method, path, query;
    bb_pairs headers;
    bb_bytes identity;
    uint64_t request_id, carrier;
    bb_str work;
    bb_bytes ticket_record;
} bb_plane_req;
typedef struct {
    uint32_t attempt, flags;
    bb_str dialect, model, base_path, upstream, provider;
    bb_pairs params;
    bb_bytes admission;
} bb_target;
typedef struct { uint64_t invocation, generation; uint32_t route, descriptor; } bb_resource_echo_rec;
typedef struct {
    bb_status (*request)(const void *, const bb_host *, const bb_plane_req *, bb_bytes, bb_raw_out *);
    bb_status (*upstream)(const void *, const bb_host *, uint64_t, const bb_target *, bb_raw_out *);
    bb_status (*piece)(const void *, const bb_host *, uint64_t, uint32_t, uint32_t, uint32_t, bb_bytes, bb_raw_out *);
    bb_status (*end)(const void *, const bb_host *, uint64_t, bb_raw_out *);
    bb_status (*rewrite)(const void *, const bb_host *, uint64_t, bb_bytes, bb_raw_out *);
    bb_status (*render)(const void *, const bb_host *, const bb_plane_req *, uint32_t, bb_bytes, bb_raw_out *);
    bb_status (*admin)(const void *, const bb_host *, uint32_t, bb_bytes, bb_raw_out *);
    bb_status (*probe)(const void *, const bb_host *, const bb_target *, bb_raw_out *);
    bb_status (*demux)(const void *, const bb_host *, bb_str, bb_bytes, bb_raw_out *);
    bb_status (*select_resources)(const void *, const bb_host *, uint32_t, const bb_plane_req *, bb_bytes, bb_raw_out *);
    bb_status (*channel)(const void *, const bb_host *, uint64_t, const bb_target *, bb_raw_out *); /* slot 10, BB_PLANE_M_CHANNEL */
} bb_plane_vt;

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
    uint8_t magic[16]; uint32_t format, size, kind, kind_abi, mechanism, flags;
    uint64_t layout, mechanism_layout, semantic, mechanism_semantic;
    bb_engine_version engine_min, engine_max;
    uint8_t name[64], version[32], target[32], build_id[32], crypto[8], _reserved[16];
} bb_stamp;                                    /* 272 bytes, format 2 (round 28); crypto = "external" */

/* The secret table: an array of bb_entry, one entry (secret 3.0). resolve: head none, texts none,
 * blobs[0] = the reference's settings. The C plugin answers synchronously and never NEEDs. The struct names
 * the array's one position; its layout is bb_entry[BB_SECRET_ENTRIES]. */
enum { BB_SECRET_RESOLVE = 0, BB_SECRET_ENTRIES = 1 };
typedef struct {
    bb_entry resolve;
} bb_secret_vt;

/* The header `busbar_plugin` returns (core 3.0). It begins with its own size and the number of entries its
 * table holds, so the host reads both by prefix: a header field or a method added by a later second number
 * is one the host does not look for in an older image. describe, open and resume are entries of the one
 * shape, called with inst NULL (resume: NULL for an open chain):
 *   describe  no head, no texts, no blobs
 *   open      head: flags u32 (BB_OPEN_DRY_RUN); blobs[0] = the bound settings
 *   resume    call->session = the chain token; blobs[0] = the results */
typedef struct {
    uint32_t size, entries;                    /* sizeof(bb_plugin); BB_SECRET_ENTRIES */
    const bb_stamp *stamp;
    const bb_entry *table;                     /* (const bb_entry *)&the bb_secret_vt */
    bb_entry describe;
    bb_entry open;
    bb_entry resume;
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
    (void)bb_put2(h, o, BB_TAG_FAIL, &f, sizeof f, text, (uint32_t)n); /* always fits in the first buffer */
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
