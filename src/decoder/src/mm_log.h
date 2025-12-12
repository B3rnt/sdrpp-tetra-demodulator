#pragma once
#include <stdio.h>

/* simpele append-logger voor MM PDUs */
static inline void mm_log(const char *line)
{
    FILE *f = fopen("tetra_mm.log", "a");
    if (!f) return;
    fprintf(f, "%s\n", line);
    fclose(f);
}
