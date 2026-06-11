#ifndef CRYPTO_LOG_H
#define CRYPTO_LOG_H

#include <stdint.h>
#include <stddef.h>

/* ANSI color codes */
#define CL_RESET   "\033[0m"
#define CL_GREEN   "\033[32m"
#define CL_YELLOW  "\033[33m"
#define CL_CYAN    "\033[36m"
#define CL_RED     "\033[31m"
#define CL_BOLD    "\033[1m"
#define CL_MAGENTA "\033[35m"

/* Master verbose flag — 1 by default; pass --quiet-crypto to server to silence */
extern volatile int g_crypto_verbose;

/* Print a timestamped, color-coded crypto event line to stderr */
void crypto_log(const char *color, const char *cat, const char *fmt, ...);

/* Print a timestamped hex dump; show = how many bytes to display (0 = up to 32) */
void crypto_log_hex(const char *color, const char *cat,
                    const char *label, const uint8_t *buf, size_t len, size_t show);

#endif
