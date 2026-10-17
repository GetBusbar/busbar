/* SPDX-License-Identifier: Apache-2.0
 * Copyright (C) 2026 Busbar Inc and contributors
 *
 * A wall-clock shift a script cell preloads into the binary under test, so the cell can put one
 * request's arrival epoch in an EARLIER billing window than the one a previous request already
 * rolled the window cell to. That is the order a concurrent window straddle produces (request A
 * reads the clock before request B, but B reaches the window cell first); the shift reproduces it
 * deterministically, without a race.
 *
 * Only the REALTIME clock read through clock_gettime(2) moves (the call the binary's wall clock
 * uses), by the whole number of seconds held in the file named by
 * ORACLE_CLOCK_SHIFT_FILE (re-read on every call, so the driving script can step it between
 * requests). The monotonic clocks are untouched, so timeouts and timers behave normally. An unset
 * variable, an unreadable file or unparsable contents shift nothing.
 *
 * Linux: LD_PRELOAD, forwarding to the next definition via dlsym(RTLD_NEXT).
 * macOS: DYLD_INSERT_LIBRARIES, through the __interpose section.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static long long clock_shift_secs(void) {
    const char *path = getenv("ORACLE_CLOCK_SHIFT_FILE");
    if (path == NULL || *path == '\0') {
        return 0;
    }
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        return 0;
    }
    long long v = 0;
    if (fscanf(f, "%lld", &v) != 1) {
        v = 0;
    }
    fclose(f);
    return v;
}

static int is_realtime(clockid_t id) {
#ifdef CLOCK_REALTIME_COARSE
    if (id == CLOCK_REALTIME_COARSE) {
        return 1;
    }
#endif
    return id == CLOCK_REALTIME;
}

#if defined(__APPLE__)

static int shifted_clock_gettime(clockid_t id, struct timespec *ts) {
    int r = clock_gettime(id, ts);
    if (r == 0 && ts != NULL && is_realtime(id)) {
        ts->tv_sec += (time_t)clock_shift_secs();
    }
    return r;
}

__attribute__((used)) static const struct {
    const void *replacement;
    const void *original;
} interposers[] __attribute__((section("__DATA,__interpose"))) = {
    {(const void *)shifted_clock_gettime, (const void *)clock_gettime},
};

#else

#include <dlfcn.h>

int clock_gettime(clockid_t id, struct timespec *ts) {
    static int (*real)(clockid_t, struct timespec *) = NULL;
    if (real == NULL) {
        real = (int (*)(clockid_t, struct timespec *))dlsym(RTLD_NEXT, "clock_gettime");
    }
    int r = real(id, ts);
    if (r == 0 && ts != NULL && is_realtime(id)) {
        ts->tv_sec += (time_t)clock_shift_secs();
    }
    return r;
}

#endif
