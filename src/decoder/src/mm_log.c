#include "mm_log.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#ifndef MM_LOG_PATH
/* Match SDR-Tetra-Plugin5 */
#define MM_LOG_PATH "mm_messages.log"
#endif

static void write_line_raw(const char *line)
{
    if (!line || !*line) return;

    FILE *f = fopen(MM_LOG_PATH, "ab");
    if (!f) return;

    fwrite(line, 1, strlen(line), f);
    fwrite("\n", 1, 1, f);
    fclose(f);
}

static void make_prefix(char *out, size_t out_sz, int la)
{
    if (!out || out_sz == 0) return;

    time_t t = time(NULL);
    struct tm tmv;
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif

    char tbuf[32];
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", &tmv);

    if (la > 0) {
        /* EXACT formatting from Plugin5:
           "HH:mm:ss  [LA: ####]   "  (2 spaces after time, 3 after bracket) */
        snprintf(out, out_sz, "%s  [LA: %4d]   ", tbuf, la);
    } else {
        snprintf(out, out_sz, "%s  [LA:    ]   ", tbuf);
    }
}

void mm_log_ctx(uint32_t issi, int la, const char *line)
{
    (void)issi; /* Plugin5 does not prefix ISSI automatically */
    if (!line || !*line) return;

    char prefix[64];
    make_prefix(prefix, sizeof(prefix), la);

    char full[1400];
    snprintf(full, sizeof(full), "%s%s", prefix, line);
    write_line_raw(full);
}

void mm_logf_ctx(uint32_t issi, int la, const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    char msg[1100];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    mm_log_ctx(issi, la, msg);
}

/* Backwards-compatible API used by older decoder code paths */
void mm_log(const char *line)
{
    mm_log_ctx(0, 0, line);
}

void mm_logf(const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    char msg[1100];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    mm_log_ctx(0, 0, msg);
}
