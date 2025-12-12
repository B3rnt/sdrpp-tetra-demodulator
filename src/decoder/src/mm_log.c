#include "mm_log.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#ifndef MM_LOG_PATH
/* Pas dit pad aan als je ergens anders wil loggen */
#define MM_LOG_PATH "mm_log.txt"
#endif

void mm_log(const char *line)
{
    if (!line || !*line) return;

    FILE *f = fopen(MM_LOG_PATH, "a");
    if (!f) return;

    /* timestamp (optioneel) */
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
