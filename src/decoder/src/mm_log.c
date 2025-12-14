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

/* ---------------------------------------
   Cross-platform append write (1 OS write)
   --------------------------------------- */

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

static int should_drop_issi(uint32_t issi)
{
    return ((issi & 0xFFFFFFu) == MM_BROADCAST_ISSI);
}

/* ---------------------------------------
   Core writers
   --------------------------------------- */

/* Unfiltered write (used by mm_log/mm_logf) */
static void write_one_line_unfiltered(const char *line)
{
    if (!line || !*line) return;

    char ts[32];
    make_timestamp(ts);

    char out[1024];
    int n = snprintf(out, sizeof(out), "[%s] %s\n", ts, line);
    if (n <= 0) return;

    if ((size_t)n >= sizeof(out)) {
        out[sizeof(out) - 2] = '\n';
        out[sizeof(out) - 1] = '\0';
        append_write_all(out, strlen(out));
        return;
    }

    append_write_all(out, (size_t)n);
}

/* Context write (filters 0xFFFFFF; adds LA automatically) */
static void write_one_line_ctx(uint32_t issi, int la, const char *payload)
{
    if (!payload || !*payload) return;

    issi &= 0xFFFFFFu;
    if (should_drop_issi(issi)) return; /* <-- your requirement */

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
        out[sizeof(out) - 2] = '\n';
        out[sizeof(out) - 1] = '\0';
        append_write_all(out, strlen(out));
        return;
    }

    append_write_all(out, (size_t)n);
}

/* ---------------------------------------
   Public API
   --------------------------------------- */

void mm_log(const char *line)
{
    write_one_line_unfiltered(line);
}

void mm_logf(const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    write_one_line_unfiltered(buf);
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

/* Backward compatible wrappers: LA unknown (-1) */
void mm_log_with_ctx(uint32_t issi, const char *line)
{
    mm_log_ctx(issi, -1, line);
}

void mm_logf_with_ctx(uint32_t issi, const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    mm_log_ctx(issi, -1, buf);
}
