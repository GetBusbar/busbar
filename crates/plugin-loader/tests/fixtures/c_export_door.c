/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors
 *
 * A busbar EXPORT plugin written in C from the generated header ALONE (BUSBAR-1.6.0.md decision
 * #84, THE DESIGN section 11.5: "the generated C header is the only artifact an author needs").
 * It includes busbar_plugin.h and nothing else: no Rust, no busbar crate, no libc header. The test
 * `tests/c_header_door.rs` compiles it with the system C compiler into a shared library and loads
 * it through the loader's one dropped-in path (`load_dropped`).
 *
 * What it does, per op of the export table:
 *   validate / open / refresh  settings must be one JSON object; anything else FAILS with a reason.
 *   deliver   a JSONL batch of the one declared stream (logs) is counted, line by line, and the
 *             count is REPORTED on the reply's #85 envelope (a counter family the Statement
 *             declares); another stream is REFUSED, a batch that is not JSON lines FAILS.
 *   scrape    renders its own one-family exposition into the host's buffer; too small a buffer
 *             answers the short-buffer FAILED with `needed`.
 *   status    the lines seen so far as a JSON blob, held under a lease until `release`.
 *   check     no findings.
 *   serve     REFUSED: the Statement declares no routes.
 *   release   READY for the outstanding lease, REFUSED for any other.
 *   the rest of the lifecycle answers READY.
 *
 * BB_C_DOOR_KIND_ABI (default BB_EXPORT_ABI_VERSION) is the kind ABI the door and its Statement
 * state. The RED arm builds the same source with another value: the loader must refuse it.
 *
 * At most one instance (MARK_ONE_INSTANCE): its state is static, so the plugin needs no allocator.
 */
#include "busbar_plugin.h"

#ifndef BB_C_DOOR_KIND_ABI
#define BB_C_DOOR_KIND_ABI BB_EXPORT_ABI_VERSION
#endif

#define STR(s) { (const uint8_t *)(s), sizeof(s) - 1 }

/* ---- the Statement ---- */

static const bb_mech_MetricFamily FAMILIES[1] = {{
    STR("c_export_lines_total"),
    STR("JSON lines the C export plugin was handed."),
    { 0, 0 },
    0,
    0,
    BB_MECH_FAMILY_COUNTER,
    { 0, 0, 0, 0, 0, 0, 0 },
}};

static const uint8_t STREAMS[1] = { BB_EXPORT_ExportStream_Logs };

static const bb_export_Tail TAIL = {
    { (uint32_t)sizeof(bb_export_Tail), 0 },
    STREAMS,
    1,
    0,
    0,
};

static const bb_mech_Statement STATEMENT = {
    .size = (uint32_t)sizeof(bb_mech_Statement),
    .kind = (uint32_t)BB_MECH_KindCode_Export,
    .kind_abi = BB_C_DOOR_KIND_ABI,
    .max_inflight = 1,
    .name = STR("c-export"),
    .version = STR("1.0.0"),
    .families = FAMILIES,
    .families_len = 1,
    .kind_tail = (const bb_mech_KindTailHead *)&TAIL,
    .marks = BB_MECH_MARK_ONE_INSTANCE,
};

/* ---- the one instance ---- */

struct instance {
    int open;
    uint64_t lines;
    uint64_t lease;     /* the outstanding status lease; 0 = none */
    uint64_t next_lease;
    bb_mech_MetricEntry metric;
    uint8_t status[64];
};

static struct instance THE_INSTANCE;

/* ---- helpers: no libc ---- */

/* Answer `outcome`: the plugin writes back its own `out` size (never more than the host's) and
 * mirrors the outcome it returns. */
static bb_mech_RawOutcome answer(bb_mech_OutHead *head, size_t own, bb_mech_Outcome outcome) {
    if (head->size > own) {
        head->size = (uint32_t)own;
    }
    head->outcome = (bb_mech_RawOutcome)outcome;
    return (bb_mech_RawOutcome)outcome;
}

/* A FAILED or REFUSED answer naming `text` (static) in `head.error`. */
static bb_mech_RawOutcome say(bb_mech_OutHead *head, size_t own, bb_mech_Outcome outcome,
                              const char *text) {
    size_t n = 0;
    while (text[n]) {
        n++;
    }
    head->error.ptr = (const uint8_t *)text;
    head->error.len = n;
    return answer(head, own, outcome);
}

static int space(uint8_t c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

/* Whether `b` is one JSON object (by its outer braces: this plugin reads no key). */
static int one_object(const bb_mech_Blob *b) {
    size_t lo = 0, hi;
    if (b->ptr == 0 || b->len == 0) {
        return 0;
    }
    hi = b->len;
    while (lo < hi && space(b->ptr[lo])) {
        lo++;
    }
    while (hi > lo && space(b->ptr[hi - 1])) {
        hi--;
    }
    return hi - lo >= 2 && b->ptr[lo] == '{' && b->ptr[hi - 1] == '}';
}

/* Copy `text` into a lent buffer of `cap` bytes; answers how many bytes were written. */
static size_t lend(uint8_t *buf, size_t cap, const char *text) {
    size_t n = 0;
    if (buf == 0) {
        return 0;
    }
    while (text[n] && n < cap) {
        buf[n] = (uint8_t)text[n];
        n++;
    }
    return n;
}

/* `v` in decimal at `at`; answers the digits written. `at` holds at least 20 bytes. */
static size_t decimal(uint8_t *at, uint64_t v) {
    uint8_t rev[20];
    size_t n = 0, i;
    do {
        rev[n++] = (uint8_t)('0' + v % 10);
        v /= 10;
    } while (v);
    for (i = 0; i < n; i++) {
        at[i] = rev[n - 1 - i];
    }
    return n;
}

/* `text` then `v` then `tail` at `at` (room for all of them); answers the length. */
static size_t line_of(uint8_t *at, const char *text, uint64_t v, const char *tail) {
    size_t n = 0, i = 0;
    while (text[i]) {
        at[n++] = (uint8_t)text[i++];
    }
    n += decimal(at + n, v);
    for (i = 0; tail[i]; i++) {
        at[n++] = (uint8_t)tail[i];
    }
    return n;
}

static const char SETTINGS_REASON[] = "settings must be one JSON object";

/* ---- the lifecycle ---- */

static bb_mech_RawOutcome op_validate(void *inst, const void *in, void *out) {
    const bb_mech_ValidateIn *v = in;
    bb_mech_OutHead *o = out;
    size_t n;
    (void)inst;
    if (v->head.size < sizeof *v) {
        return say(o, sizeof *o, BB_MECH_Outcome_Refused, "validate: short in");
    }
    if (one_object(&v->settings)) {
        return answer(o, sizeof *o, BB_MECH_Outcome_Ready);
    }
    /* No instance holds the reason past the call: it goes into the host's lent buffer. */
    n = lend(v->err_buf, v->err_cap, SETTINGS_REASON);
    o->error.ptr = v->err_buf;
    o->error.len = n;
    return answer(o, sizeof *o, BB_MECH_Outcome_Failed);
}

static bb_mech_RawOutcome op_open(void *inst, const void *in, void *out) {
    const bb_mech_OpenIn *i = in;
    bb_mech_OpenOut *o = out;
    (void)inst;
    if (i->head.size < sizeof *i || o->head.size < sizeof *o) {
        return say(&o->head, sizeof *o, BB_MECH_Outcome_Refused, "open: short frame");
    }
    if (!one_object(&i->settings)) {
        o->err_len = lend(i->err_buf, i->err_cap, SETTINGS_REASON);
        return answer(&o->head, sizeof *o, BB_MECH_Outcome_Failed);
    }
    if (THE_INSTANCE.open) {
        o->err_len = lend(i->err_buf, i->err_cap, "one instance only");
        return answer(&o->head, sizeof *o, BB_MECH_Outcome_Failed);
    }
    THE_INSTANCE.open = 1;
    THE_INSTANCE.lines = 0;
    THE_INSTANCE.lease = 0;
    THE_INSTANCE.next_lease = 1;
    o->instance = &THE_INSTANCE;
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_refresh(void *inst, const void *in, void *out) {
    const bb_mech_RefreshIn *r = in;
    bb_mech_OutHead *o = out;
    (void)inst;
    if (r->head.size < sizeof *r) {
        return say(o, sizeof *o, BB_MECH_Outcome_Refused, "refresh: short in");
    }
    if (!one_object(&r->settings)) {
        return say(o, sizeof *o, BB_MECH_Outcome_Failed, SETTINGS_REASON);
    }
    return answer(o, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_ready(void *inst, const void *in, void *out) {
    (void)inst;
    (void)in;
    return answer(out, sizeof(bb_mech_OutHead), BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_tick(void *inst, const void *in, void *out) {
    bb_mech_TickOut *o = out;
    (void)inst;
    (void)in;
    if (o->head.size >= sizeof *o) {
        o->next_tick_ns = 0;
    }
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_cancel(void *inst, const void *in, void *out) {
    bb_mech_CancelOut *o = out;
    (void)inst;
    (void)in;
    if (o->head.size >= sizeof *o) {
        o->disposition = BB_EXPORT_CANCEL_ABORTED;
    }
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_release(void *inst, const void *in, void *out) {
    struct instance *s = inst;
    const bb_mech_ReleaseIn *r = in;
    bb_mech_OutHead *o = out;
    if (r->head.size < sizeof *r) {
        return say(o, sizeof *o, BB_MECH_Outcome_Refused, "release: short in");
    }
    if (r->lease == 0 || r->lease != s->lease) {
        return say(o, sizeof *o, BB_MECH_Outcome_Refused, "no such lease");
    }
    s->lease = 0;
    return answer(o, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_close(void *inst, const void *in, void *out) {
    struct instance *s = inst;
    (void)in;
    s->open = 0;
    s->lease = 0;
    return answer(out, sizeof(bb_mech_OutHead), BB_MECH_Outcome_Ready);
}

/* ---- the export ops ---- */

static bb_mech_RawOutcome op_deliver(void *inst, const void *in, void *out) {
    struct instance *s = inst;
    const bb_export_DeliverIn *d = in;
    bb_mech_OutHead *o = out;
    uint64_t lines = 0;
    size_t i;
    if (d->head.size < sizeof *d) {
        return say(o, sizeof *o, BB_MECH_Outcome_Refused, "deliver: short in");
    }
    if (d->stream != BB_EXPORT_ExportStream_Logs) {
        return say(o, sizeof *o, BB_MECH_Outcome_Refused, "stream not declared");
    }
    if (d->batch.fmt != BB_MECH_BLOB_JSONL || (d->batch.ptr == 0 && d->batch.len != 0)) {
        return say(o, sizeof *o, BB_MECH_Outcome_Failed, "batch is not JSON lines");
    }
    for (i = 0; i < d->batch.len; i++) {
        if (d->batch.ptr[i] == '\n' || i + 1 == d->batch.len) {
            lines++;
        }
    }
    s->lines += lines;
    /* REPORT, never increment: the host folds the delta (#85). Valid until the next op. */
    s->metric.family_idx = 0;
    s->metric.kind = BB_MECH_METRIC_ADD;
    s->metric.value = (double)lines;
    s->metric.label_vals = 0;
    s->metric.label_vals_len = 0;
    o->envelope.metrics = &s->metric;
    o->envelope.metrics_len = 1;
    return answer(o, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_scrape(void *inst, const void *in, void *out) {
    struct instance *s = inst;
    const bb_export_ScrapeIn *i = in;
    bb_export_ScrapeOut *o = out;
    uint8_t text[96];
    size_t n, k;
    if (i->head.size < sizeof *i || o->head.size < sizeof *o) {
        return say(&o->head, sizeof *o, BB_MECH_Outcome_Refused, "scrape: short frame");
    }
    n = line_of(text, "# TYPE c_export_lines_total counter\nc_export_lines_total ", s->lines,
                "\n");
    if (i->buf == 0 || i->cap < n) {
        /* THE SHORT-BUFFER ANSWER: nothing written, `needed` above the capacity given. */
        o->written = 0;
        o->needed = n;
        return answer(&o->head, sizeof *o, BB_MECH_Outcome_Failed);
    }
    for (k = 0; k < n; k++) {
        i->buf[k] = text[k];
    }
    o->written = n;
    o->needed = 0;
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_status(void *inst, const void *in, void *out) {
    struct instance *s = inst;
    bb_export_StatusOut *o = out;
    (void)in;
    if (o->head.size < sizeof *o) {
        return say(&o->head, sizeof *o, BB_MECH_Outcome_Refused, "status: short out");
    }
    if (s->lease != 0) {
        return say(&o->head, sizeof *o, BB_MECH_Outcome_Refused, "the last status is unreleased");
    }
    o->status.ptr = s->status;
    o->status.len = line_of(s->status, "{\"lines\":", s->lines, "}");
    o->status.fmt = BB_MECH_BLOB_JSON;
    s->lease = s->next_lease++;
    o->head.lease = s->lease;
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_check(void *inst, const void *in, void *out) {
    bb_export_CheckOut *o = out;
    (void)inst;
    (void)in;
    return answer(&o->head, sizeof *o, BB_MECH_Outcome_Ready);
}

static bb_mech_RawOutcome op_serve(void *inst, const void *in, void *out) {
    bb_export_ServeOut *o = out;
    (void)inst;
    (void)in;
    return say(&o->head, sizeof *o, BB_MECH_Outcome_Refused, "no routes are declared");
}

/* ---- the table and the door ---- */

static const bb_export_Ops OPS = {
    {
        (uint32_t)sizeof(bb_export_Ops),
        BB_EXPORT_SLOTS,
        op_validate,
        op_open,
        op_refresh,
        op_ready,   /* retire */
        op_tick,
        op_ready,   /* drive */
        op_cancel,
        op_release,
        op_close,
    },
    op_deliver,
    op_scrape,
    op_status,
    op_check,
    op_serve,
};

static const bb_mech_Door DOOR = {
    BB_MECH_DOOR_MAGIC,
    BB_MECH_MECHANISM_VERSION,
    (uint32_t)sizeof(bb_mech_Door),
    (uint32_t)BB_MECH_KindCode_Export,
    BB_C_DOOR_KIND_ABI,
    &STATEMENT,
    (const bb_mech_OpsHead *)&OPS,
};

/* THE ONE SYMBOL (BB_MECH_DOOR_SYMBOL). */
const bb_mech_Door *busbar_plugin_door(void) {
    return &DOOR;
}
