#include "mm_log.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#ifndef MM_LOG_PATH
/* Pas dit pad aan als je ergens anders wil loggen */
#define MM_LOG_PATH "mm_log.txt"
#endif

/* 0xFFFFFF = 16777215 -> vaak broadcast/unknown placeholder */
#ifndef MM_BROADCAST_ISSI
#define MM_BROADCAST_ISSI 0xFFFFFFu
#endif

/* Default: drop spam met 0xFFFFFF */
static int g_drop_broadcast_issi = 1;

void mm_log_set_drop_broadcast_issi(int drop)
{
    g_drop_broadcast_issi = (drop ? 1 : 0);
}

int mm_log_get_drop_broadcast_issi(void)
{
    return g_drop_broadcast_issi;
}

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
    if (g_drop_broadcast_issi && issi == MM_BROADCAST_ISSI) {
        /* Drop spam */
        return;
    }
    mm_write_line(line);
}

void mm_logf_with_ctx(uint32_t issi, const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    if (g_drop_broadcast_issi && issi == MM_BROADCAST_ISSI) {
        /* Drop spam */
        return;
    }

    char buf[512];

    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    mm_write_line(buf);
}
