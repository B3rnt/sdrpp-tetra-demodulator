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

/* ---------- thread-local LA (optional) ---------- */
#if defined(_MSC_VER)
  __declspec(thread) static int g_tls_la = -1;
#elif defined(__GNUC__) || defined(__clang__)
  static __thread int g_tls_la = -1;   /* <-- correct order for GCC/clang */
#else
  static int g_tls_la = -1;            /* fallback (not truly TLS) */
#endif

void mm_log_set_thread_la(int la) { g_tls_la = la; }
int  mm_log_get_thread_la(void) { return g_tls_la; }

/* ---------- atomic-ish append write (single write per line) ---------- */
#if defined(_WIN32)
  #include <io.h>
  #include <fcntl.h>
  #include <sys/stat.h>

  static int append_write_once(const char *data, size_t len)
  {
      int fd = _open(MM_LOG_PATH, _O_WRONLY | _O_CREAT | _O_APPEND, _S_IREAD | _S_IWRITE);
      if (fd < 0) return 0;

      /* write full buffer (can loop on partial writes) */
      const char *p = data;
      size_t left = len;
      while (left > 0) {
          int n = _write(fd, p, (unsigned)left);
          if (n <= 0) break;
          p += n;
          left -= (size_t)n;
      }

      _close(fd);
      return (left == 0);
  }
#else
  #include <unistd.h>
  #include <fcntl.h>
  #include <sys/stat.h>

  static int append_write_once(const char *data, size_t len)
  {
      int fd = open(MM_LOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0644);
      if (fd < 0) return 0;

      const char *p = data;
      size_t left = len;
      while (left > 0) {
          ssize_t n = write(fd, p, left);
          if (n <= 0) break;
          p += (size_t)n;
          left -= (size_t)n;
      }

      close(fd);
      return (left == 0);
  }
#endif

static void make_timestamp(char out[64])
{
    time_t t = time(NULL);
    struct tm tmv;
#if defined(_WIN32)
    localtime_s(&tmv, &t);
#else
    tmv = *localtime(&t);
#endif
    /* 64 bytes avoids the warning you saw */
    snprintf(out, 64, "%04d-%02d-%02d %02d:%02d:%02d",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
}

static int issi_is_real(uint32_t issi)
{
    issi &= 0xFFFFFFu;
    if (issi == 0) return 0;
    if (issi == MM_BROADCAST_ISSI) return 0;
    return 1;
}

/* Plain line write: no filtering */
static void write_plain_line(const char *payload)
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
        append_write_once(out, strlen(out));
        return;
    }

    append_write_once(out, (size_t)n);
}

/* Context write: filters 0xFFFFFF/0 and prefixes */
static void write_ctx_line(uint32_t issi, int la, const char *payload)
{
    if (!payload || !*payload) return;

    issi &= 0xFFFFFFu;
    if (!issi_is_real(issi)) return;

    if (la < 0) {
        /* if caller doesn't know, use TLS if set */
        la = mm_log_get_thread_la();
    }

    char ts[64];
    make_timestamp(ts);

    char out[1400];
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
        append_write_once(out, strlen(out));
        return;
    }

    append_write_once(out, (size_t)n);
}

/* ---------- public API ---------- */

void mm_log(const char *line)
{
    write_plain_line(line);
}

void mm_logf(const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    char buf[900];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    write_plain_line(buf);
}

void mm_log_ctx(uint32_t issi, int la, const char *line)
{
    write_ctx_line(issi, la, line);
}

void mm_logf_ctx(uint32_t issi, int la, const char *fmt, ...)
{
    if (!fmt || !*fmt) return;

    char buf[900];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    write_ctx_line(issi, la, buf);
}
