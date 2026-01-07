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

static const char *plugin5_mm_type_name(uint8_t type)
{
    switch (type) {
    case TMM_PDU_T_D_OTAR:            return "D_OTAR";
    case TMM_PDU_T_D_AUTH:            return "D_AUTHENTICATION";
    case TMM_PDU_T_D_CK_CHG_DEM:      return "D_CK_CHANGE_DEMAND";
    case TMM_PDU_T_D_DISABLE:         return "D_DISABLE";
    case TMM_PDU_T_D_ENABLE:          return "D_ENABLE";
    case TMM_PDU_T_D_LOC_UPD_ACC:     return "D_LOCATION_UPDATE_ACCEPT";
    case TMM_PDU_T_D_LOC_UPD_CMD:     return "D_LOCATION_UPDATE_COMMAND";
    case TMM_PDU_T_D_LOC_UPD_REJ:     return "D_LOCATION_UPDATE_REJECT";
    case TMM_PDU_T_D_LOC_UPD_PROC:    return "D_LOCATION_UPDATE_PROCEEDING";
    case TMM_PDU_T_D_ATT_DET_GRP:     return "D_ATTACH_DETACH_GROUP_IDENTITY";
    case TMM_PDU_T_D_ATT_DET_GRP_ACK: return "D_ATTACH_DETACH_GROUP_IDENTITY_ACKNOWLEDGEMENT";
    case TMM_PDU_T_D_MM_STATUS:       return "D_MM_STATUS";
    case TMM_PDU_T_D_MM_PDU_NOTSUPP:  return "MM_PDU_FUNCTION_NOT_SUPPORTED";
    default:                          return NULL;
    }
}

static uint8_t read_byte_at_bit(const uint8_t *bits, unsigned int nbits, unsigned int bit_offset)
{
    uint8_t v = 0;
    for (unsigned int i = 0; i < 8; i++) {
        unsigned int b = bit_offset + i;
        uint8_t bit = (b < nbits) ? (bits[b] & 1u) : 0u;
        v |= (uint8_t)(bit << (7 - i));
    }
    return v;
}

static void bits_to_hex(const uint8_t *bits, unsigned int nbits,
                        unsigned int bit_offset, unsigned int bit_length,
                        char *out, size_t out_sz)
{
    static const char hex[] = "0123456789ABCDEF";
    if (!out || out_sz == 0) return;
    out[0] = 0;

    size_t w = 0;
    for (unsigned int i = 0; i < bit_length; i += 8) {
        uint8_t v = 0;
        for (unsigned int j = 0; j < 8; j++) {
            unsigned int b = bit_offset + i + j;
            uint8_t bit = (b < nbits && (i + j) < bit_length) ? (bits[b] & 1u) : 0u;
            v |= (uint8_t)(bit << (7 - j));
        }
        if (w + 2 >= out_sz) break;
        out[w++] = hex[(v >> 4) & 0xF];
        out[w++] = hex[v & 0xF];
        out[w] = 0;
    }
}

static int g_last_auth_status = -1;
static int g_last_auth_ssi = -1;
static time_t g_last_auth_time = 0;

static const char *plugin5_auth_status_to_string(int status)
{
    /* Plugin5 implementation */
    if (status >= 0)
        return "Authentication successful or no authentication currently in progress";
    return "Authentication status unknown";
}

static int try_decode_mm_from_bits(struct tetra_mac_state *tms,
                                   const uint8_t *bits, unsigned int nbits,
                                   uint32_t issi, uint16_t la)
{
    if (!bits || nbits < 16) return 0;

    /* If caller didn't pass LA, try pull from state (like Plugin5 uses runtime) */
    if ((int)la <= 0 && tms && tms->tcs)
        la = (uint16_t)tms->tcs->la;

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
            const char *tname = plugin5_mm_type_name(type);

            unsigned int pdu_start = off;
            unsigned int body = toff + 4;
            unsigned int pdu_len = (nbits > pdu_start) ? (nbits - pdu_start) : 0;

            /* Plugin5 aligns within first byte to detect ITSI / roaming markers (0x57 / 0x51) */
            int align = 0;
            for (int a = 0; a < 8; a++) {
                if (pdu_start + (unsigned int)a + 8 > nbits) break;
                uint8_t b = read_byte_at_bit(bits, nbits, pdu_start + (unsigned int)a);
                if (b == 0x57 || b == 0x51) { align = a; break; }
            }
            uint8_t luFirst = read_byte_at_bit(bits, nbits, pdu_start + (unsigned int)align);
            int isItsi = (luFirst == 0x57);
            int isRoam = (luFirst == 0x51);

            /* RAW logging types in Plugin5 */
            int want_raw = (type == TMM_PDU_T_D_MM_STATUS) ||
                           (type == TMM_PDU_T_D_LOC_UPD_CMD) ||
                           (type == TMM_PDU_T_D_ENABLE);

            char rawhex[1100];
            rawhex[0] = 0;
            if (want_raw && pdu_len > 0)
                bits_to_hex(bits, nbits, pdu_start, pdu_len, rawhex, sizeof(rawhex));

            if (type == TMM_PDU_T_D_AUTH) {
                /* sub-type: 2 bits */
                if (body + 2 > nbits) return 1;
                int sub = (int)get_bits(bits, nbits, body, 2);
                body += 2;

                if (sub == 0) { /* Demand */
                    /* Plugin5: "BS demands authentication" + optional SSI */
                    if (issi > 0)
                        mm_logf_ctx(issi, la, "BS demands authentication: SSI: %u", (unsigned)issi);
                    else
                        mm_logf_ctx(issi, la, "BS demands authentication");
                    return 1;
                }

                if ((sub == 2 || sub == 3) && (body + 6 <= nbits)) { /* Result or Reject */
                    int status = (int)get_bits(bits, nbits, body, 6);
                    g_last_auth_status = status;
                    g_last_auth_ssi = (issi > 0) ? (int)issi : -1;
                    g_last_auth_time = time(NULL);

                    const char *st = plugin5_auth_status_to_string(status);
                    if (issi > 0)
                        mm_logf_ctx(issi, la, "BS result to MS authentication: %s SSI: %u - %s",
                                    st, (unsigned)issi, st);
                    else
                        mm_logf_ctx(issi, la, "BS result to MS authentication: %s - %s", st, st);
                    return 1;
                }

                /* Fallback */
                if (issi > 0)
                    mm_logf_ctx(issi, la, "MM D_AUTHENTICATION auth_sub=%d SSI: %u", sub, (unsigned)issi);
                else
                    mm_logf_ctx(issi, la, "MM D_AUTHENTICATION auth_sub=%d", sub);
                return 1;
            }

            if (type == TMM_PDU_T_D_MM_STATUS) {
                if (body + 6 <= nbits) {
                    int st = (int)get_bits(bits, nbits, body, 6);
                    /* Plugin5 reads MM_SSI after status, but logging uses SSI variable; use issi as SSI. */
                    if (issi > 0)
                        mm_logf_ctx(issi, la, "MM D_MM_STATUS status=%d SSI: %u%s%s",
                                    st, (unsigned)issi,
                                    want_raw ? "  raw=" : "",
                                    want_raw ? rawhex : "");
                    else
                        mm_logf_ctx(issi, la, "MM D_MM_STATUS status=%d%s%s",
                                    st,
                                    want_raw ? "  raw=" : "",
                                    want_raw ? rawhex : "");
                } else {
                    mm_logf_ctx(issi, la, "MM D_MM_STATUS%s%s",
                                want_raw ? "  raw=" : "",
                                want_raw ? rawhex : "");
                }
                return 1;
            }

            if (type == TMM_PDU_T_D_ENABLE) {
                if (issi > 0)
                    mm_logf_ctx(issi, la, "MM D_ENABLE SSI: %u%s%s",
                                (unsigned)issi,
                                want_raw ? "  raw=" : "",
                                want_raw ? rawhex : "");
                else
                    mm_logf_ctx(issi, la, "MM D_ENABLE%s%s",
                                want_raw ? "  raw=" : "",
                                want_raw ? rawhex : "");
                return 1;
            }

            if (type == TMM_PDU_T_D_LOC_UPD_CMD) {
                if (issi > 0)
                    mm_logf_ctx(issi, la, "MM D_LOCATION_UPDATE_COMMAND SSI: %u%s%s",
                                (unsigned)issi,
                                want_raw ? "  raw=" : "",
                                want_raw ? rawhex : "");
                else
                    mm_logf_ctx(issi, la, "MM D_LOCATION_UPDATE_COMMAND%s%s",
                                want_raw ? "  raw=" : "",
                                want_raw ? rawhex : "");
                return 1;
            }

            if (type == TMM_PDU_T_D_LOC_UPD_PROC) {
                if (issi > 0)
                    mm_logf_ctx(issi, la, "MM D_LOCATION_UPDATE_PROCEEDING SSI: %u", (unsigned)issi);
                else
                    mm_logf_ctx(issi, la, "MM D_LOCATION_UPDATE_PROCEEDING");
                return 1;
            }

            if (type == TMM_PDU_T_D_LOC_UPD_REJ) {
                if (issi > 0)
                    mm_logf_ctx(issi, la, "MM D_LOCATION_UPDATE_REJECT SSI: %u", (unsigned)issi);
                else
                    mm_logf_ctx(issi, la, "MM D_LOCATION_UPDATE_REJECT");
                return 1;
            }

            if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
                /* Decode accept_type if present via SDR rules */
                mm_field_store fs;
                memset(&fs, 0, sizeof(fs));
                mm_rules_decode(bits, nbits, body, mm_rules_loc_upd_accept, mm_rules_loc_upd_accept_count, &fs);

                int acc = -1;
                if (fs.present[GN_Location_update_accept_type])
                    acc = (int)fs.value[GN_Location_update_accept_type];

                /* Parse TLVs to recover GSSI/CCK (Plugin5 logic) */
                struct t34_result r;
                t34_result_init(&r);

                unsigned int scan_start = body;
                unsigned int scan_end = (nbits < body + 512) ? nbits : (body + 512);

                for (unsigned int p = scan_start; p + 16 <= scan_end; p++) {
                    if (t34_try_parse(bits, nbits, p, &r)) break;
                }

                int gssi = (r.gssi_count > 0) ? (int)r.gssi[0] : 0;
                int gssiVerified = (r.gssi_count > 0) ? 1 : 0;
                int cckId = (r.have_cck) ? (int)r.cck : 0;

                /* Build EXACT Plugin5 text */
                char line[1100];
                size_t w = 0;

                w += (size_t)snprintf(line + w, sizeof(line) - w, "MS request for registration");

                double dt = difftime(time(NULL), g_last_auth_time);
                int recentAuth = (g_last_auth_ssi > 0 && (issi > 0) && (g_last_auth_ssi == (int)issi) && dt <= 3.0);

                if (acc == 0 || recentAuth) {
                    w += (size_t)snprintf(line + w, sizeof(line) - w, "/authentication ACCEPTED");
                } else {
                    w += (size_t)snprintf(line + w, sizeof(line) - w, " ACCEPTED");
                }

                if (issi > 0) {
                    w += (size_t)snprintf(line + w, sizeof(line) - w, " for SSI: %u", (unsigned)issi);
                }

                if (acc == 0) {
                    if (gssi > 0) {
                        w += (size_t)snprintf(line + w, sizeof(line) - w, " GSSI: %d", gssi);
                    }
                } else {
                    if (gssiVerified > 0 && gssi > 0) {
                        w += (size_t)snprintf(line + w, sizeof(line) - w, " GSSI: %d", gssi);
                    }
                }

                if (g_last_auth_status >= 0 && (g_last_auth_ssi <= 0 || (issi > 0 && g_last_auth_ssi == (int)issi))) {
                    w += (size_t)snprintf(line + w, sizeof(line) - w, " - %s", plugin5_auth_status_to_string(g_last_auth_status));
                    g_last_auth_status = -1;
                    g_last_auth_ssi = -1;
                }

                if (cckId > 0) {
                    w += (size_t)snprintf(line + w, sizeof(line) - w, " - CCK_identifier: %d", cckId);
                }

                if (isItsi) {
                    w += (size_t)snprintf(line + w, sizeof(line) - w, " - ITSI attach");
                } else if (isRoam) {
                    w += (size_t)snprintf(line + w, sizeof(line) - w, " - Roaming location updating");
                }

                mm_logf_ctx(issi, la, "%s", line);
                return 1;
            }

            /* OTAR has its own string in Plugin5 */
            if (type == TMM_PDU_T_D_OTAR) {
                mm_logf_ctx(issi, la, "MM D_OTAR");
                return 1;
            }

            /* Default formatting like Plugin5:
               "MM <enumName> SSI: <ssi>" when name known; otherwise numeric. */
            if (tname) {
                if (issi > 0)
                    mm_logf_ctx(issi, la, "MM %s SSI: %u", tname, (unsigned)issi);
                else
                    mm_logf_ctx(issi, la, "MM %s", tname);
            } else {
                if (issi > 0)
                    mm_logf_ctx(issi, la, "MM %u SSI: %u", (unsigned)type, (unsigned)issi);
                else
                    mm_logf_ctx(issi, la, "MM %u", (unsigned)type);
            }
            return 1;
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
