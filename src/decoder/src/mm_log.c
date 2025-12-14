#include "mm_log.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdint.h>

#ifndef MM_LOG_PATH
/* Relative to the SDR++ working directory */
#define MM_LOG_PATH "mm_log.txt"
#endif

/* 24-bit broadcast / "no ISSI" used widely in TETRA (0xFFFFFF == 16777215) */
#define MM_BCAST_ISSI 0xFFFFFFu

#if defined(_WIN32)
  #include <io.h>
  #include <fcntl.h>
  #include <sys/stat.h>
  static int append_write_all(const char *data, size_t len)
  {
      int fd = _open(MM_LOG_PATH, _O_WRONLY | _O_CREAT | _O_APPEND, _S_IREAD | _S_IWRITE);
      if (fd < 0) return 0;

      const char *p = data;
      while (len > 0) {
          int n = _write(fd, p, (unsigned)len);
          if (n <= 0) break;
          p += n;
          len -= (size_t)n;
      }
      _close(fd);
      return (len == 0);
  }
#else
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/stat.h>
  static int append_write_all(const char *data, size_t len)
  {
      int fd = open(MM_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
      if (fd < 0) return 0;

      const char *p = data;
      while (len > 0) {
          ssize_t n = write(fd, p, len);
          if (n <= 0) break;
          p += (size_t)n;
          len -= (size_t)n;
      }
      close(fd);
      return (len == 0);
  }
#endif

static void make_timestamp(char out[64])
{
    time_t t = time(NULL);
    struct tm tmv;

#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif

    /* 19 chars + NUL => 20; we use 64 to silence truncation warnings */
    snprintf(out, 64, "%04d-%02d-%02d %02d:%02d:%02d",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
}

/* Best-effort: parse "ISSI=12345" from legacy text lines */
static int parse_issi_from_line(const char *line, uint32_t *out_issi)
{
    if (!line || !out_issi) return 0;

    const char *p = strstr(line, "ISSI=");
    if (!p) return 0;
    p += 5;

    uint32_t v = 0;
    int digits = 0;
    while (*p >= '0' && *p <= '9') {
        v = (v * 10u) + (uint32_t)(*p - '0');
        p++;
        digits++;
        if (digits > 10) break;
    }
    if (digits == 0) return 0;

    *out_issi = v & 0xFFFFFFu;
    return 1;
}

static int is_bcast(uint32_t issi)
{
    issi &= 0xFFFFFFu;
    return (issi == MM_BCAST_ISSI);
}

/* One OS write per line => safe(ish) for multiple plugins simultaneously */
static void write_line_raw(const char *payload)
{
    if (!payload || !*payload) return;

    char ts[64];
    make_timestamp(ts);

    char out[1400];
    int n = snprintf(out, sizeof(out), "[%s] %s\n", ts, payload);
    if (n <= 0) return;

    if ((size_t)n >= sizeof(out)) {
        out[sizeof(out) - 2] = '\n';
        out[sizeof(out) - 1] = '\0';
        append_write_all(out, strlen(out));
        return;
    }

    append_write_all(out, (size_t)n);
}

/* Legacy API: drop ISSI=0xFFFFFF only if we can parse it from the line.
 * IMPORTANT: If we cannot parse ISSI, we still write the line (so we never “lose” data).
 */
void mm_log(const char *line)
{
    if (!line || !*line) return;

    uint32_t issi = 0;
    if (parse_issi_from_line(line, &issi)) {
        if (is_bcast(issi)) return;
    }

    write_line_raw(line);
}

void mm_logf(const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    char buf[900];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    mm_log(buf);
}

/* Preferred API: we already know ISSI and LA, so we can filter correctly (no text parsing). */
void mm_log_ctx(uint32_t issi, int la, const char *line)
{
    if (!line || !*line) return;

    issi &= 0xFFFFFFu;
    if (is_bcast(issi) || issi == 0) return;

    char payload[1100];
    if (la >= 0) {
        snprintf(payload, sizeof(payload),
                 "LA=%d ISSI=%u (0x%06X) %s",
                 la, (unsigned)issi, (unsigned)issi, line);
    } else {
        snprintf(payload, sizeof(payload),
                 "ISSI=%u (0x%06X) %s",
                 (unsigned)issi, (unsigned)issi, line);
    }

    write_line_raw(payload);
}

void mm_logf_ctx(uint32_t issi, int la, const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    char msg[900];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    mm_log_ctx(issi, la, msg);
}
