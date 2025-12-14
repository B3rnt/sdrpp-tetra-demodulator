#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Minimal MM logger.
 *
 * - mm_log/mm_logf: legacy API (probeert ISSI=0xFFFFFF te droppen als dat in de tekst voorkomt).
 * - mm_log*_ctx: preferred API wanneer je ISSI + LA al weet.
 */
void mm_log(const char *line);
void mm_logf(const char *fmt, ...);

void mm_log_ctx(uint32_t issi, int la, const char *line);
void mm_logf_ctx(uint32_t issi, int la, const char *fmt, ...);

#ifdef __cplusplus
}
#endif

/* Backward compatibility (oude namen die je al gebruikte) */
#define mm_log_with_ctx  mm_log_ctx
#define mm_logf_with_ctx mm_logf_ctx
