#pragma once
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void mm_log(const char *line);
void mm_logf(const char *fmt, ...);

void mm_log_ctx(uint32_t issi, int la, const char *line);
void mm_logf_ctx(uint32_t issi, int la, const char *fmt, ...);

#ifdef __cplusplus
}
#endif
