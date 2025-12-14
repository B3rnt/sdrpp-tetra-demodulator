#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Simple file logger for MM/MLE debug
 *
 * mm_log():  log 1 line
 * mm_logf(): printf-style logging
 *
 * Optional filtering:
 *  - if you call mm_log_*_with_ctx() the ISSI=0xFFFFFF spam can be filtered here.
 */

void mm_log(const char *line);
void mm_logf(const char *fmt, ...);

/* Optional context-aware logging helpers */
void mm_log_with_ctx(uint32_t issi, const char *line);
void mm_logf_with_ctx(uint32_t issi, const char *fmt, ...);

/* Runtime control (optional) */
void mm_log_set_drop_broadcast_issi(int drop);   /* default: 1 */
int  mm_log_get_drop_broadcast_issi(void);

#ifdef __cplusplus
}
#endif
