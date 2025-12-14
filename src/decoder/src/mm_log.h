#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Plain logger: writes exactly what you pass (no filtering) */
void mm_log(const char *line);
void mm_logf(const char *fmt, ...);

/* Context logger: drops broadcast/unknown ISSI, prefixes LA/ISSI */
void mm_log_ctx(uint32_t issi, int la, const char *line);
void mm_logf_ctx(uint32_t issi, int la, const char *fmt, ...);

/* Optional: if you want to set current LA per thread (useful when LA is known in C++ land) */
void mm_log_set_thread_la(int la);
int  mm_log_get_thread_la(void);

#ifdef __cplusplus
}
#endif

/* Backwards compatibility (old names you used earlier) */
#define mm_log_with_ctx  mm_log_ctx
#define mm_logf_with_ctx mm_logf_ctx
