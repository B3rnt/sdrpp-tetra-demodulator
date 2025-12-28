/*
 * tetra_mle.c (MM-level decoder + TL-SDU dump + TLV GSSI + FULL heuristic fallback)
 *
 *
 * Drop-in replacement for tetra_mle.c in sdrpp-tetra-demodulator.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
#include "mm_sdr_rules.h"
#include "crypto/tetra_crypto.h"

/* ===================== FEATURE SWITCHES ===================== */

#define ENABLE_TL_SDU_DUMP             1   /* prints TL-SDU HEX + BITS in logfile */
#define ENABLE_GSSI_HEURISTIC_FALLBACK 1   /* prints GSSI even when no valid T.34 TLV exists */

/* ---------- BIT HELPERS ---------- */

static uint32_t get_bits(const uint8_t *bits, unsigned int len, unsigned int pos, unsigned int n)
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
static uint8_t  g_last_auth_ok = 0;

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

    uint8_t  valid_structure;
    unsigned int bits_consumed;

    uint8_t  recognized_tlvs;
};

static void t34_result_init(struct t34_result *r)
{
    if (!r) return;
    memset(r, 0, sizeof(*r));
}

static void add_gssi(uint32_t gssi, struct t34_result *out)
{
    if (!out) return;
    gssi &= 0xFFFFFFu;
    if (gssi == 0 || out->gssi_count >= 8) return;

    for (int i = 0; i < out->gssi_count; i++) {
        if (out->gssi_list[i] == gssi)
            return;
    }
    out->gssi_list[out->gssi_count++] = gssi;
}

/*
 * TID 0x5 (Group identity list)
 * Extract multiple 24-bit values where possible (real-world tolerant).
 */
static void parse_tid5_group_identity_list(const uint8_t *bits, unsigned int bitlen,
                                           unsigned int offset, unsigned int li,
                                           struct t34_result *out)
{
    if (!bits || !out || li < 3) return;

    unsigned int p = 0;
    while (p + 3 <= li) {
        /* Mode (1) */
        p += 1;

        /* Type (2) */
        uint8_t type = (uint8_t)get_bits(bits, bitlen, offset + p, 2);
        p += 2;

        if (type == 3) /* end marker seen in deployments */
            break;

        if (type == 0) {
            if (p + 24 > li) break;
            add_gssi(get_bits(bits, bitlen, offset + p, 24), out);
            p += 24;
        } else if (type == 1) {
            if (p + 24 > li) break;
            add_gssi(get_bits(bits, bitlen, offset + p, 24), out);
            p += 24;
            if (p + 24 > li) break;
            add_gssi(get_bits(bits, bitlen, offset + p, 24), out);
            p += 24;
        } else if (type == 2) {
            if (p + 24 > li) break;
            add_gssi(get_bits(bits, bitlen, offset + p, 24), out);
            p += 24;
        } else {
            break;
        }
    }
}

static int t34_try_parse(const uint8_t *bits, unsigned int nbits,
                         unsigned int start_pos, struct t34_result *out)
{
    t34_result_init(out);
    if (!bits || !out) return 0;

    unsigned int pos = start_pos;

    /* Need at least one TLV header */
    if (pos + 16 > nbits) return 0;

    while (pos + 16 <= nbits) {
        uint32_t m_bit = get_bits(bits, nbits, pos, 1);
        pos += 1;

        uint32_t tid = get_bits(bits, nbits, pos, 4);
        pos += 4;

        uint32_t li = get_bits(bits, nbits, pos, 11);
        pos += 11;

        if (pos + li > nbits)
            return 0;

        unsigned int val_start = pos;

        if (tid == 0x5) {
            parse_tid5_group_identity_list(bits, nbits, val_start, li, out);
            if (out->gssi_count > 0)
                out->recognized_tlvs++;
        } else if (tid == 0x7) {
            if (li >= 24) {
                add_gssi(get_bits(bits, nbits, val_start + (li - 24), 24), out);
                out->recognized_tlvs++;
            }
        } else if (tid == 0x6) {
            if (li >= 8) {
                out->cck = (uint8_t)get_bits(bits, nbits, val_start, 8);
                out->have_cck = 1;
                out->recognized_tlvs++;
            }
        } else if (tid == 0x2) {
            unsigned int lp = 0;
            if (li > lp) { out->roam = (uint8_t)get_bits(bits, nbits, val_start + lp, 1); out->have_roam = 1; lp++; }
            if (li > lp) { out->itsi = (uint8_t)get_bits(bits, nbits, val_start + lp, 1); out->have_itsi = 1; lp++; }
            if (li > lp) { out->srv_rest = (uint8_t)get_bits(bits, nbits, val_start + lp, 1); out->have_srv_rest = 1; lp++; }
            out->recognized_tlvs++;
        }

        pos += li;

        /* Terminate strictly on M=0 */
        if (m_bit == 0) {
            if (out->recognized_tlvs == 0)
                return 0;

            out->valid_structure = 1;
            out->bits_consumed = pos - start_pos;
            return 1;
        }
    }

    return 0;
}

/* ===================== LOGGING ===================== */

static void mm_log_result(uint32_t issi, uint16_t la, const struct t34_result *r)
{
    if (r && r->gssi_count > 0) {
        mm_logf_ctx(issi, la,
            "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %u",
            issi, r->gssi_list[0]);
    } else {
        mm_logf_ctx(issi, la,
            "MS request for registration/authentication ACCEPTED for SSI: %u",
            issi);
    }

    /* Authentication correlation: single-use for next matching accept */
    if (g_last_auth_ok && g_last_auth_issi == issi) {
        mm_logf_ctx(issi, la,
            "- Authentication successful or no authentication currently in progress");
        g_last_auth_ok = 0;
    }

    if (r && r->have_cck) {
        mm_logf_ctx(issi, la, "- CCK_identifier: %u", r->cck);
    }

    if (r && r->have_roam && r->roam) {
        mm_logf_ctx(issi, la, "- Roaming location updating");
    }
}

/* ===================== TL-SDU LOGGING ===================== */

#if ENABLE_TL_SDU_DUMP
static void mm_log_tl_sdu(uint32_t issi, uint16_t la, const uint8_t *buf, unsigned int len)
{
    if (!buf || len == 0) return;

    /* Hex dump (grouped) */
    char hex_line[256];
    for (unsigned int i = 0; i < len; i += 16) {
        unsigned int chunk = (len - i > 16) ? 16 : (len - i);
        int pos = 0;
        pos += snprintf(hex_line + pos, sizeof(hex_line) - pos, "TL-SDU HEX: ");
        for (unsigned int j = 0; j < chunk; j++) {
            pos += snprintf(hex_line + pos, sizeof(hex_line) - pos, "%02X ", buf[i + j]);
            if (pos >= (int)sizeof(hex_line) - 4) break;
        }
        mm_logf_ctx(issi, la, "%s", hex_line);
    }

    /* Bit dump (MSB-first bytes) */
    char bit_line[256];
    for (unsigned int i = 0; i < len; i += 8) {
        unsigned int chunk = (len - i > 8) ? 8 : (len - i);
        int pos = 0;
        pos += snprintf(bit_line + pos, sizeof(bit_line) - pos, "TL-SDU BITS: ");
        for (unsigned int j = 0; j < chunk; j++) {
            for (int k = 7; k >= 0; k--) {
                pos += snprintf(bit_line + pos, sizeof(bit_line) - pos, "%d", (buf[i + j] >> k) & 1);
                if (pos >= (int)sizeof(bit_line) - 4) break;
            }
            pos += snprintf(bit_line + pos, sizeof(bit_line) - pos, " ");
            if (pos >= (int)sizeof(bit_line) - 4) break;
        }
        mm_logf_ctx(issi, la, "%s", bit_line);
    }
}
#endif

/* ===================== GSSI HEURISTIC FALLBACK ===================== */

#if ENABLE_GSSI_HEURISTIC_FALLBACK
/*
 * Heuristic: find a stable 24-bit candidate across FULL TL-SDU.
 * We pick the most frequent 24-bit value (excluding zero).
 */
static int heuristic_find_gssi_24_full(const uint8_t *bits, unsigned int nbits, uint32_t *out_gssi)
{
    if (!bits || !out_gssi || nbits < 24) return 0;

    uint32_t cand[64];
    uint16_t cnt[64];
    unsigned int n_cand = 0;

    for (unsigned int p = 0; p + 24 <= nbits; p++) {
        uint32_t v = get_bits(bits, nbits, p, 24) & 0xFFFFFFu;
        if (v == 0) continue;

        unsigned int found = 0;
        for (unsigned int i = 0; i < n_cand; i++) {
            if (cand[i] == v) {
                if (cnt[i] < 65535) cnt[i]++;
                found = 1;
                break;
            }
        }
        if (!found && n_cand < (sizeof(cand) / sizeof(cand[0]))) {
            cand[n_cand] = v;
            cnt[n_cand] = 1;
            n_cand++;
        }
    }

    if (n_cand == 0) return 0;

    unsigned int best = 0;
    for (unsigned int i = 1; i < n_cand; i++) {
        if (cnt[i] > cnt[best])
            best = i;
    }

    *out_gssi = cand[best];
    return 1;
}
#endif

/* ===================== DECODER ===================== */

static int try_decode_mm_from_bits(struct tetra_mac_state *tms,
                                   const uint8_t *bits, unsigned int nbits,
                                   uint32_t issi, uint16_t la)
{
    (void)tms;
    if (!bits || nbits < 32) return 0;

    /* Conservative scan region for MM PDU start */
    unsigned int scan_limit = (nbits < 96) ? nbits : 96;

    for (unsigned int off = 0; off + 16 <= scan_limit; off++) {
        uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
        if (pdisc != TMLE_PDISC_MM) continue;

        /* MM type nibble drift tolerance */
        unsigned int type_offsets[] = { 3, 4, 5, 6 };

        for (unsigned int ti = 0; ti < (sizeof(type_offsets) / sizeof(type_offsets[0])); ti++) {
            unsigned int toff = off + type_offsets[ti];
            if (toff + 4 > nbits) continue;

            uint8_t type = (uint8_t)get_bits(bits, nbits, toff, 4);

            if (type == TMM_PDU_T_D_AUTH) {
                if (toff + 6 <= nbits) {
                    uint8_t st = (uint8_t)get_bits(bits, nbits, toff + 4, 2);
                    if (st == 0) {
                        mm_logf_ctx(issi, la, "BS demands authentication: SSI: %u", issi);
                    } else if (st == 2) {
                        mm_logf_ctx(issi, la,
                            "BS result to MS authentication: Authentication successful or no authentication currently in progress");
                        g_last_auth_issi = issi;
                        g_last_auth_ok = 1;
                    }
                    return 1;
                }
            } else if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
                unsigned int scan_start = toff + 4;
                if (scan_start >= nbits)
                    continue;

                unsigned int scan_end = scan_start + 64;
                if (scan_end > nbits) scan_end = nbits;

                struct t34_result r;
                int found_tlv = 0;

                for (unsigned int p = scan_start; p + 16 <= scan_end; p++) {
                    if (t34_try_parse(bits, nbits, p, &r)) {
                        found_tlv = 1;
                        break;
                    }
                }

                if (found_tlv) {
                    mm_log_result(issi, la, &r);
                } else {
                    struct t34_result out;
                    t34_result_init(&out);

#if ENABLE_GSSI_HEURISTIC_FALLBACK
                    /* FINAL FIX: scan FULL TL-SDU, not a short window */
                    uint32_t hgssi = 0;
                    if (heuristic_find_gssi_24_full(bits, nbits, &hgssi)) {
                        add_gssi(hgssi, &out);
                    }
#endif
                    mm_log_result(issi, la, &out);
                }
                return 1;
            } else if (type == TMM_PDU_T_D_LOC_UPD_CMD) {
                mm_logf_ctx(issi, la, "SwMI sent LOCATION UPDATE COMMAND for SSI: %u", issi);
                return 1;
            } else if (type == TMM_PDU_T_D_LOC_UPD_REJ) {
                mm_logf_ctx(issi, la, "SwMI sent LOCATION UPDATE REJECT for SSI: %u", issi);
                return 1;
            }
        }
    }

    return 0;
}

/* ===================== ENTRY ===================== */

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len < 1) return (int)len;

    uint32_t issi = tms ? (uint32_t)tms->ssi : 0;
    int la_i = (tms && tms->tcs) ? (int)tms->tcs->la : -1;
    uint16_t la = (uint16_t)la_i;

#if ENABLE_TL_SDU_DUMP
    mm_log_tl_sdu(issi, la, buf, len);
#endif

    static uint8_t bits_packed[4096];
    unsigned int nbits_p = 0;

    /* Auto-detect bit-per-byte (0x00/0x01) vs packed MSB-first */
    int bit_per_byte = 1;
    unsigned int probe = (len < 32U) ? len : 32U;
    for (unsigned int i = 0; i < probe; i++) {
        if (buf[i] != 0x00 && buf[i] != 0x01) {
            bit_per_byte = 0;
            break;
        }
    }

    if (bit_per_byte) {
        unsigned int max_bits = len;
        if (max_bits > (unsigned int)sizeof(bits_packed))
            max_bits = (unsigned int)sizeof(bits_packed);

        for (unsigned int i = 0; i < max_bits; i++)
            bits_packed[nbits_p++] = (uint8_t)(buf[i] & 1u);
    } else {
        unsigned int max_p_bytes = len;
        if (max_p_bytes * 8U > (unsigned int)sizeof(bits_packed))
            max_p_bytes = (unsigned int)sizeof(bits_packed) / 8U;

        for (unsigned int i = 0; i < max_p_bytes; i++) {
            uint8_t b = buf[i];
            for (int k = 7; k >= 0; k--)
                bits_packed[nbits_p++] = (uint8_t)((b >> k) & 1u);
        }
    }

    try_decode_mm_from_bits(tms, bits_packed, nbits_p, issi, la);

    return (int)len;
}
