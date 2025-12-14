#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Thread-local LA (per decoder thread) */
void mm_set_thread_la(int la);
int  mm_get_thread_la(void);

/* Backwards compatible simple loggers */
void mm_log(const char *line);
void mm_logf(const char *fmt, ...);

/* Context-aware: filters 0xFFFFFF automatisch weg, voegt LA toe als la>=0 */
void mm_log_ctx(uint32_t issi, int la, const char *line);
void mm_logf_ctx(uint32_t issi, int la, const char *fmt, ...);

/* Backward compatibility for older names you used earlier */
#define mm_log_with_ctx  mm_log_ctx
#define mm_logf_with_ctx mm_logf_ctx

#ifdef __cplusplus
}
#endif
