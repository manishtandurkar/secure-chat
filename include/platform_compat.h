#ifndef PLATFORM_COMPAT_H
#define PLATFORM_COMPAT_H

/* Linux-specific compatibility shims */
#define _POSIX_C_SOURCE 200809L
#include <time.h>
#include <stdint.h>

static inline uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static inline void sleep_ms(int ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

#endif /* PLATFORM_COMPAT_H */
