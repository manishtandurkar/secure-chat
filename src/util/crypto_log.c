#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include "crypto_log.h"

volatile int g_crypto_verbose = 1;

static void print_prefix(const char *color, const char *cat) {
    time_t now = time(NULL);
    char tbuf[12];
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", localtime(&now));
    fprintf(stderr, "%s%s %-14s" CL_RESET " ", color, tbuf, cat);
}

void crypto_log(const char *color, const char *cat, const char *fmt, ...) {
    if (!g_crypto_verbose) return;
    print_prefix(color, cat);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

void crypto_log_hex(const char *color, const char *cat,
                    const char *label, const uint8_t *buf, size_t len, size_t show) {
    if (!g_crypto_verbose) return;
    if (show == 0 || show > len) show = (len < 32 ? len : 32);
    print_prefix(color, cat);
    fprintf(stderr, "%s", label);
    for (size_t i = 0; i < show; i++) fprintf(stderr, "%02x", buf[i]);
    if (len > show) fprintf(stderr, "...[%zu B total]", len);
    fprintf(stderr, "\n");
}
