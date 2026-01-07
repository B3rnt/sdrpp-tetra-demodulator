#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Plugin5-compatible MM message log.
   Writes to "mm_messages.log" in the SDR++ working directory. */

/* Write one MM log line (body text). Prefix (time + LA) is added automatically. */
void mm_log_ctx(uint32_t issi, int la, const char *line);

/* printf-style wrapper */
void mm_logf_ctx(uint32_t issi, int la, const char *fmt, ...);

#ifdef __cplusplus
}
#endif
