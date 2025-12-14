#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void mm_log(const char *line);
void mm_logf(const char *fmt, ...);

void mm_log_with_ctx(uint32_t issi, const char *line);
void mm_logf_with_ctx(uint32_t issi, const char *fmt, ...);

#ifdef __cplusplus
}
#endif
