#include "mm_log.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#ifndef MM_LOG_PATH
#define MM_LOG_PATH "mm_log.txt"
#endif

#define MM_BROADCAST_ISSI 0xFFFFFFu

static void mm_write_line(const char *line)
{
    if (!line || !*line) return;

    FILE *f = fopen(MM_LOG_PATH, "a");
    if (!f) return;

    time_t t = time(NULL);
    struct tm tmv;
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    tmv = *localtime(&t);
#endif

    char ts[32];
    snprintf(ts, sizeof(ts), "%04d-%02d-%02d %02d:%02d:%02d",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);

    fprintf(f, "[%s] %s\n", ts, line);
    fflush(f);
    fclose(f);
}

void mm_log(const char *line)
{
    /* Ongefilterd: laat alles door zolang callers nog oud zijn */
    mm_write_line(line);
}

void mm_logf(const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    mm_write_line(buf);
}

void mm_log_with_ctx(uint32_t issi, const char *line)
{
    if (!line || !*line) return;

    /* Hier filteren we streng: 0xFFFFFF = weg */
    if ((issi & 0xFFFFFFu) == MM_BROADCAST_ISSI) return;

    mm_write_line(line);
}

void mm_logf_with_ctx(uint32_t issi, const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    /* Hier filteren we streng: 0xFFFFFF = weg */
    if ((issi & 0xFFFFFFu) == MM_BROADCAST_ISSI) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    mm_write_line(buf);
}
