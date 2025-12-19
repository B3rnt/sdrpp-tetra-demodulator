#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
#include "mm_sdr_rules.h"
#include "crypto/tetra_crypto.h"

/*
 * Debug switches:
 * - MM_DUMP_RAW_BYTES: hexdump van de volledige TL-SDU bytes (buf/len)
 * - MM_DUMP_BITS:      bitdump van de volledige bits[] buffer (nbits)
 *
 * Zet alles op 1 om "alles" te zien.
 */
#define MM_DUMP_RAW_BYTES 1
#define MM_DUMP_BITS      0

/* ===================== HEX/BIT DUMP HELPERS ===================== */

static void mm_log_hexdump_ctx(uint32_t issi, uint16_t la,
                               const char *prefix,
                               const uint8_t *buf, unsigned int len)
{
    if (!buf || len == 0) {
        mm_logf_ctx(issi, la, "%s <empty>", prefix ? prefix : "hexdump");
        return;
    }

    for (unsigned int i = 0; i < len; i += 16) {
        char line[256];
        char hex[16 * 3 + 1];
        char asc[16 + 1];

        unsigned int n = (len - i > 16) ? 16 : (len - i);

        for (unsigned int j = 0; j < n; j++) {
            uint8_t c = buf[i + j];
            snprintf(&hex[j * 3], 4, "%02X ", c);
            asc[j] = (c >= 32 && c <= 126) ? (char)c : '.';
        }
        hex[n * 3] = '\0';
        asc[n] = '\0';

        snprintf(line, sizeof(line), "%s +%04u: %-48s |%s|",
                 prefix ? prefix : "hexdump", i, hex, asc);

        mm_logf_ctx(issi, la, "%s", line);
    }
}

static void mm_log_bitdump_ctx(uint32_t issi, uint16_t la,
                               const char *prefix,
                               const uint8_t *bits, unsigned int nbits)
{
    if (!bits || nbits == 0) {
        mm_logf_ctx(issi, la, "%s <empty>", prefix ? prefix : "bitdump");
        return;
    }

    /* 64 bits per regel */
    for (unsigned int i = 0; i < nbits; i += 64) {
        char line[128];
        unsigned int n = (nbits - i > 64) ? 64 : (nbits - i);
        unsigned int p = 0;

        p += snprintf(line + p, sizeof(line) - p, "%s +%04u: ",
                      prefix ? prefix : "bitdump", i);

        for (unsigned int j = 0; j < n && p + 2 < sizeof(line); j++)
            line[p++] = bits[i + j] ? '1' : '0';

        line[p] = '\0';
        mm_logf_ctx(issi, la, "%s", line);
    }
}

/* ---------- BIT HELPERS ---------- */

static uint32_t get_bits(const uint8_t *bits, unsigned int len,
                         unsigned int pos, unsigned int n)
{
    if (!bits || n == 0 || pos + n > len)
        return 0;

    uint32_t val = 0;
    for (unsigned int i = 0; i < n; i++)
        val = (val << 1) | (bits[pos + i] & 1u);
    return val;
}

/* ===================== STATE ===================== */

static uint32_t g_last_auth_issi = 0;
static uint8_t  g_last_auth_ok   = 0;

/* ===================== TLV PARSER ===================== */

struct t34_result {
    uint32_t gssi_list[8];
    uint8_t  gssi_count;

    uint8_t  have_cck;
    uint8_t  cck;

    uint8_t  have_roam;
    uint8_t  roam;

    uint8_t  have_itsi;
    uint8_t  itsi;

    uint8_t  have_srv_rest;
    uint8_t  srv_rest;

    uint8_t  seen_known_tid;
    unsigned int bits_consumed;
};

static void t34_result_init(struct t34_result *r)
{
    memset(r, 0, sizeof(*r));
}

static void add_gssi(uint32_t gssi, struct t34_result *out)
{
    if (gssi == 0 || out->gssi_count >= 8)
        return;

    for (int i = 0; i < out->gssi_count; i++)
        if (out->gssi_list[i] == gssi)
            return;

    out->gssi_list[out->gssi_count++] = gssi;
}

/* ---------- TID 5 ---------- */

static void parse_tid5(const uint8_t *bits, unsigned int nbits,
                       unsigned int offset, unsigned int len,
                       struct t34_result *out)
{
    unsigned int p = 0;

    while (p + 3 <= len) {
        p += 1; /* Mode */

        uint8_t type = (uint8_t)get_bits(bits, nbits, offset + p, 2);
        p += 2;

        if (type == 3)
            break;

        if (type == 0 && p + 24 <= len) {
            add_gssi(get_bits(bits, nbits, offset + p, 24), out);
            p += 24;
        } else if (type == 1 && p + 48 <= len) {
            add_gssi(get_bits(bits, nbits, offset + p, 24), out);
            p += 24;
            add_gssi(get_bits(bits, nbits, offset + p, 24), out);
            p += 24;
        } else if (type == 2 && p + 24 <= len) {
            add_gssi(get_bits(bits, nbits, offset + p, 24), out);
            p += 24;
        } else {
            break;
        }
    }
}

/* ---------- TLV CHAIN ---------- */

static int t34_try_parse(const uint8_t *bits, unsigned int nbits,
                         unsigned int start_pos, struct t34_result *out)
{
    t34_result_init(out);
    unsigned int pos = start_pos;

    if (pos + 16 > nbits)
        return 0;

    if (get_bits(bits, nbits, pos, 1) != 1)
        return 0;

    while (pos + 16 <= nbits) {
        uint8_t m = get_bits(bits, nbits, pos, 1);
        pos++;

        if (m == 0) {
            if (!out->seen_known_tid)
                return 0;
            out->bits_consumed = pos - start_pos;
            return 1;
        }

        uint8_t tid = get_bits(bits, nbits, pos, 4);
        pos += 4;
        uint16_t li = get_bits(bits, nbits, pos, 11);
        pos += 11;

        if (li > 2048 || pos + li > nbits)
            return 0;

        unsigned int v = pos;

        if (tid == 0x5) {
            out->seen_known_tid = 1;
            parse_tid5(bits, nbits, v, li, out);
        } else if (tid == 0x6 && li >= 8) {
            out->seen_known_tid = 1;
            out->cck = get_bits(bits, nbits, v, 8);
            out->have_cck = 1;
        } else if (tid == 0x2) {
            out->seen_known_tid = 1;
            unsigned int lp = 0;
            if (li > lp) { out->roam = get_bits(bits, nbits, v + lp++, 1); out->have_roam = 1; }
            if (li > lp) { out->itsi = get_bits(bits, nbits, v + lp++, 1); out->have_itsi = 1; }
            if (li > lp) { out->srv_rest = get_bits(bits, nbits, v + lp++, 1); out->have_srv_rest = 1; }
        } else if (tid == 0x7 && li >= 24) {
            out->seen_known_tid = 1;
            add_gssi(get_bits(bits, nbits, v, 24), out);
        }

        pos += li;
    }

    return 0;
}

/* ===================== LOGGING ===================== */

static void mm_log_result(uint32_t issi, uint16_t la,
                          const struct t34_result *r)
{
    char tail[512] = {0};

    if (g_last_auth_ok && g_last_auth_issi == issi) {
        strcat(tail, " - Authentication successful or no authentication currently in progress");
        g_last_auth_ok = 0;
    }

    if (r->have_cck) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), " - CCK_identifier: %u", r->cck);
        strcat(tail, tmp);
    }

    if (r->have_itsi && r->itsi)
        strcat(tail, " - ITSI attach");
    else if (r->have_roam && r->roam)
        strcat(tail, r->have_srv_rest && r->srv_rest ?
                     " - Service restoration roaming location updating" :
                     " - Roaming location updating");

    if (r->gssi_count > 0)
        mm_logf_ctx(issi, la,
            "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %u%s",
            issi, r->gssi_list[0], tail);
    else
        mm_logf_ctx(issi, la,
            "MS request for registration/authentication ACCEPTED for SSI: %u%s",
            issi, tail);
}

/* ===================== DECODER ===================== */

static int try_decode_mm_from_bits(struct tetra_mac_state *tms,
                                   const uint8_t *bits, unsigned int nbits,
                                   uint32_t issi, uint16_t la)
{
    (void)tms;

    unsigned int scan_limit = (nbits < 512) ? nbits : 512;

    for (unsigned int off = 0; off + 16 <= scan_limit; off++) {
        if (get_bits(bits, nbits, off, 3) != TMLE_PDISC_MM)
            continue;

        unsigned int type_offs[2] = { off + 3, off + 4 };

        for (int i = 0; i < 2; i++) {
            unsigned int toff = type_offs[i];
            if (toff + 4 > nbits) continue;

            uint8_t type = get_bits(bits, nbits, toff, 4);

            if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
                unsigned int scan_start = toff + 30;
                unsigned int scan_end = (nbits < 256) ? nbits : 256;

                struct t34_result best;
                t34_result_init(&best);
                int best_score = -1;

                for (unsigned int p = scan_start; p < scan_end; p++) {
                    struct t34_result r;
                    if (t34_try_parse(bits, nbits, p, &r)) {
                        int score = 0;
                        if (r.gssi_count) score += 60;
                        if (r.have_cck)   score += 40;
                        if (r.have_roam || r.have_itsi) score += 20;
                        if (score > best_score) {
                            best_score = score;
                            best = r;
                        }
                    }
                }

                mm_log_result(issi, la, &best);
                return 1;
            }
        }
    }
    return 0;
}

/* ===================== ENTRY ===================== */

int rx_tl_sdu(struct tetra_mac_state *tms,
              struct msgb *msg, unsigned int len)
{
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len == 0)
        return (int)len;

    uint32_t issi = tms ? tms->ssi : 0;
    uint16_t la   = (tms && tms->tcs) ? (uint16_t)tms->tcs->la : 0;

#if MM_DUMP_RAW_BYTES
    /* Dump altijd alles wat binnenkomt op TL-SDU niveau */
    mm_logf_ctx(issi, la, "=== RX TL-SDU len=%u ===", len);
    mm_log_hexdump_ctx(issi, la, "TL-SDU", buf, len);
#endif

    static uint8_t bits[4096];
    unsigned int nbits = 0;

    unsigned int max = (len * 8 > 4096) ? 4096 / 8 : len;

    for (unsigned int i = 0; i < max; i++) {
        uint8_t b = buf[i];
        for (int k = 7; k >= 0; k--)
            bits[nbits++] = (b >> k) & 1u;
    }

#if MM_DUMP_BITS
    mm_logf_ctx(issi, la, "=== RX BITSTREAM nbits=%u (from len=%u) ===", nbits, len);
    mm_log_bitdump_ctx(issi, la, "BITS", bits, nbits);
#endif

    /* Decode (en bestaande mm_log_result output) */
    try_decode_mm_from_bits(tms, bits, nbits, issi, la);

    return (int)len;
}
