#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Writes a line as-is (no ISSI filtering here) */
void mm_log(const char *line);
void mm_logf(const char *fmt, ...);

/* Preferred: includes real ISSI, filters 0xFFFFFF, adds LA when known (la=-1 if unknown) */
void mm_log_ctx(uint32_t issi, int la, const char *line);
void mm_logf_ctx(uint32_t issi, int la, const char *fmt, ...);

/* Backward-compatible helpers (older code expects these names).
   These ALSO filter 0xFFFFFF. LA is unknown (-1). */
void mm_log_with_ctx(uint32_t issi, const char *line);
void mm_logf_with_ctx(uint32_t issi, const char *fmt, ...);

#ifdef __cplusplus
}
#endif
