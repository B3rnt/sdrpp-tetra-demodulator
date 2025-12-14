#include "mm_log.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdint.h>

#ifndef MM_LOG_PATH
#define MM_LOG_PATH "mm_log.txt"
#endif

#define MM_BROADCAST_ISSI 0xFFFFFFu

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

static void make_timestamp(char out[32])
{
    time_t t = time(NULL);
    struct tm tmv;
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    tmv = *localtime(&t);
#endif
    snprintf(out, 32, "%04d-%02d-%02d %02d:%02d:%02d",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
}

/* Parse ISSI from text lines like "ISSI=3360454 ..." */
static int parse_issi_from_line(const char *line, uint32_t *out_issi)
{
    if (!line) return 0;
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

static int should_drop_issi(uint32_t issi)
{
    return ((issi & 0xFFFFFFu) == MM_BROADCAST_ISSI);
}

/* Writes exactly ONE line (single OS write) */
static void write_one_line(const char *line)
{
    if (!line || !*line) return;

    /* Only keep real ISSI lines */
    uint32_t issi = 0;
    if (!parse_issi_from_line(line, &issi)) return;
    if (should_drop_issi(issi)) return;

    char ts[32];
    make_timestamp(ts);

    char out[1024];
    int n = snprintf(out, sizeof(out), "[%s] %s\n", ts, line);
    if (n <= 0) return;
    if ((size_t)n >= sizeof(out)) {
        /* truncate safely */
        out[sizeof(out)-2] = '\n';
        out[sizeof(out)-1] = '\0';
        append_write_all(out, strlen(out));
        return;
    }

    append_write_all(out, (size_t)n);
}

/* Preferred: ctx logging, no parsing, adds LA automatically */
static void write_one_line_ctx(uint32_t issi, int la, const char *payload)
{
    if (!payload || !*payload) return;

    issi &= 0xFFFFFFu;
    if (should_drop_issi(issi)) return;

    char ts[32];
    make_timestamp(ts);

    char out[1024];
    int n;
    if (la >= 0) {
        n = snprintf(out, sizeof(out),
                     "[%s] LA=%d ISSI=%u (0x%06X) %s\n",
                     ts, la, (unsigned)issi, (unsigned)issi, payload);
    } else {
        n = snprintf(out, sizeof(out),
                     "[%s] ISSI=%u (0x%06X) %s\n",
                     ts, (unsigned)issi, (unsigned)issi, payload);
    }

    if (n <= 0) return;
    if ((size_t)n >= sizeof(out)) {
        out[sizeof(out)-2] = '\n';
        out[sizeof(out)-1] = '\0';
        append_write_all(out, strlen(out));
        return;
    }

    append_write_all(out, (size_t)n);
}

void mm_log(const char *line)
{
    write_one_line(line);
}

void mm_logf(const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    write_one_line(buf);
}

void mm_log_ctx(uint32_t issi, int la, const char *line)
{
    write_one_line_ctx(issi, la, line);
}

void mm_logf_ctx(uint32_t issi, int la, const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    write_one_line_ctx(issi, la, buf);
}
