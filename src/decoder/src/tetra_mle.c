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
 * SDRTetra-compat MM decoder voor LLC-bypass.
 *
 * Kernfixes (waarom jij geen/rare GSSI had):
 *  1) Type-3/4 TLV "M" bit = "more follows". Ook als M=0 bestaat het element wél.
 *     Dus: parse element altijd, en stop pas NA het element als M=0.
 *  2) find_first_type34() accepteert ook M=0 (single element).
 *  3) CCK_identifier loggen we SDRTetra-achtig uit tms->tcs->cck_id (bij jou vrijwel altijd 63),
 *     niet uit een fragiele TLV-read die bij misalignment random bytes oplevert.
 *
 * Resultaat:
 *  - GSSI komt nu weer mee bij Roaming location updating (en ook bij ITSI attach als die er is).
 *  - CCK_identifier blijft stabiel (63) zolang je crypto state dit aangeeft.
 */

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

/* ===================== MM DEBUG BITDUMP (optional) ===================== */

#ifndef MM_DEBUG_BITS
#define MM_DEBUG_BITS 1
#endif

#if MM_DEBUG_BITS

static unsigned int mm_bits_to_bytes_from(const uint8_t *bits, unsigned int nbits,
                                         unsigned int start_bit, uint8_t *out, unsigned int out_max)
{
    if (!bits || !out || out_max == 0 || start_bit >= nbits) return 0;
    unsigned int bitpos = start_bit;
    unsigned int o = 0;
    while (bitpos + 8 <= nbits && o < out_max) {
        out[o++] = (uint8_t)get_bits(bits, nbits, bitpos, 8);
        bitpos += 8;
    }
    return o;
}

static void mm_hex_dump_ctx(uint32_t issi, uint16_t la, const char *label,
                            const uint8_t *buf, unsigned int len)
{
    if (!buf || len == 0) {
        mm_logf_ctx(issi, la, "%s: <empty>", label ? label : "dump");
        return;
    }
    char line[1600];
    unsigned int p = 0;
    p += (unsigned int)snprintf(line + p, sizeof(line) - p, "%s:", label ? label : "dump");
    for (unsigned int i = 0; i < len && p + 4 < sizeof(line); i++) {
        p += (unsigned int)snprintf(line + p, sizeof(line) - p, " %02X", (unsigned)buf[i]);
    }
    mm_logf_ctx(issi, la, "%s", line);
}

static void mm_bit_dump_ctx(uint32_t issi, uint16_t la, const char *label,
                            const uint8_t *bits, unsigned int nbits,
                            unsigned int start_bit, unsigned int nshow_bits)
{
    if (!bits || start_bit >= nbits) return;
    if (start_bit + nshow_bits > nbits) nshow_bits = nbits - start_bit;

    char line[1800];
    unsigned int p = 0;
    p += (unsigned int)snprintf(line + p, sizeof(line) - p, "%s @bit%u (%u bits): ",
                                label ? label : "bits", start_bit, nshow_bits);

    for (unsigned int i = 0; i < nshow_bits && p + 3 < sizeof(line); i++) {
        if (i == 3 || i == 4 || i == 8 || (i > 0 && (i % 8) == 0))
            p += (unsigned int)snprintf(line + p, sizeof(line) - p, " ");
        line[p++] = bits[start_bit + i] ? '1' : '0';
    }
    line[p] = 0;
    mm_logf_ctx(issi, la, "%s", line);
}

/* Find plausible Type-3/4 headers (M can be 0 OR 1), log interesting ones. */
static void mm_scan_type34_headers_ctx(uint32_t issi, uint16_t la,
                                       const uint8_t *bits, unsigned int nbits,
                                       unsigned int start_bit, unsigned int window_bits)
{
    if (!bits || start_bit >= nbits) return;
    unsigned int end = start_bit + window_bits;
    if (end > nbits) end = nbits;

    for (unsigned int pos = start_bit; pos + 16u <= end; pos++) {
        /* allow M=0 or M=1 */
        uint32_t tid = get_bits(bits, nbits, pos + 1, 4);
        uint32_t li  = get_bits(bits, nbits, pos + 5, 11);
        if (li == 0 || li > 1024) continue;
        if (pos + 16u + (unsigned int)li > nbits) continue;

        if (!(tid == 0x2 || tid == 0x5 || tid == 0x6 || tid == 0x7)) continue;

        uint32_t mbit = get_bits(bits, nbits, pos, 1);
        mm_logf_ctx(issi, la, "MM TLV header at bit%u: M=%u TID=0x%X LI=%u",
                    pos, (unsigned)mbit, (unsigned)tid, (unsigned)li);
    }
}

#endif /* MM_DEBUG_BITS */

/* ---------- SDRTetra-ish auth state (optional tail text) ---------- */

static uint32_t g_last_auth_issi = 0;
static uint8_t  g_last_auth_ok = 0; /* subtype=2 */

/* ---------- GSSI helpers ---------- */

static void add_gssi_to_list(uint32_t gssi, uint32_t *list, uint8_t *count, uint8_t max)
{
    if (!list || !count || gssi == 0)
        return;

    if (!(gssi == 0xFFFFFFu || (gssi >= 1000000u && gssi <= 9000000u)))
        return;

    for (uint8_t i = 0; i < *count; i++) {
        if (list[i] == gssi)
            return;
    }
    if (*count < max)
        list[(*count)++] = gssi;
}

/* ---------- Type-3/4 element parsing ---------- */

/*
 * Group identity location accept (TID=0x5) record list:
 *  sel=0: 24-bit GSSI
 *  sel=1: 24-bit GSSI + 24-bit extra (skip)
 *  sel=2: 24-bit vGSSI
 *  sel=3: stop
 */
static void mm_parse_group_identity_location_accept(const uint8_t *bits, unsigned int bitlen,
                                                    uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                                    uint32_t *out_gssi, uint8_t *out_have_gssi,
                                                    uint32_t *out_vgssi, uint8_t *out_have_vgssi)
{
    if (!bits || bitlen < 2)
        return;

    unsigned int p = 0;
    uint8_t idx = 0;

    while (p + 2u <= bitlen) {
        uint8_t sel = (uint8_t)get_bits(bits, bitlen, p, 2);
        p += 2;

        if (sel == 3)
            break;

        if (sel == 0 || sel == 1) {
            if (p + 24u > bitlen) break;
            uint32_t gssi = get_bits(bits, bitlen, p, 24);
            p += 24;

            if (sel == 1) {
                if (p + 24u > bitlen) break;
                p += 24;
            }

            if (gssi != 0) {
                uint8_t before = out_gssi_count ? *out_gssi_count : 0;
                add_gssi_to_list(gssi, out_gssi_list, out_gssi_count, out_gssi_max);
                uint8_t after = out_gssi_count ? *out_gssi_count : before;

                if (after > before) {
                    if (out_gssi && out_have_gssi && idx == 0) {
                        *out_gssi = gssi;
                        *out_have_gssi = 1;
                    }
                    idx++;
                }
            }
        } else if (sel == 2) {
            if (p + 24u > bitlen) break;
            uint32_t vgssi = get_bits(bits, bitlen, p, 24);
            p += 24;

            if (out_vgssi && out_have_vgssi) {
                *out_vgssi = vgssi;
                *out_have_vgssi = 1;
            }
        }
    }
}

/*
 * IMPORTANT SDRTetra behaviour:
 *  - Parse element content regardless of M bit.
 *  - Stop after element if M==0 (no more follows).
 */
static void mm_scan_type34_elements(const uint8_t *bits, unsigned int bitlen, unsigned int start_bit,
                                   uint32_t *out_gssi, uint8_t *out_have_gssi,
                                   uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                   uint8_t *out_roam_lu, uint8_t *out_have_roam_lu,
                                   uint8_t *out_itsi_attach, uint8_t *out_have_itsi_attach,
                                   uint8_t *out_srv_rest, uint8_t *out_have_srv_rest)
{
    unsigned int pos = start_bit;

    while (pos + 16u <= bitlen) {
        uint32_t mbit = get_bits(bits, bitlen, pos, 1); /* 0 or 1 is valid */
        uint32_t tid  = get_bits(bits, bitlen, pos + 1, 4);
        uint32_t li   = get_bits(bits, bitlen, pos + 5, 11);

        if (li == 0) {
            pos += 16;
            continue;
        }

        unsigned int elem_len = 16 + (unsigned int)li;
        if (pos + elem_len > bitlen)
            break;

        unsigned int content_offset = pos + 16;

        if (tid == 0x5) {
            uint32_t dummy_vgssi = 0;
            uint8_t have_dummy_vgssi = 0;
            mm_parse_group_identity_location_accept(bits + content_offset, (unsigned int)li,
                                                    out_gssi_list, out_gssi_count, out_gssi_max,
                                                    out_gssi, out_have_gssi,
                                                    &dummy_vgssi, &have_dummy_vgssi);
        } else if (tid == 0x7 && li >= 24) {
            for (unsigned int off = 0; off + 24u <= li; off++) {
                uint32_t val = get_bits(bits, bitlen, content_offset + off, 24);
                uint8_t before = out_gssi_count ? *out_gssi_count : 0;
                add_gssi_to_list(val, out_gssi_list, out_gssi_count, out_gssi_max);
                uint8_t after = out_gssi_count ? *out_gssi_count : before;
                if (after > before) {
                    if (out_gssi && out_have_gssi) {
                        *out_gssi = val;
                        *out_have_gssi = 1;
                    }
                    break;
                }
            }
        } else if (tid == 0x2) {
            /* LSB flags best-effort (SDRTetra-like) */
            if (li >= 1 && out_roam_lu && out_have_roam_lu) {
                *out_roam_lu = (uint8_t)get_bits(bits, bitlen, content_offset + (unsigned int)li - 1, 1);
                *out_have_roam_lu = 1;
            }
            if (li >= 2 && out_itsi_attach && out_have_itsi_attach) {
                *out_itsi_attach = (uint8_t)get_bits(bits, bitlen, content_offset + (unsigned int)li - 2, 1);
                *out_have_itsi_attach = 1;
            }
            if (li >= 3 && out_srv_rest && out_have_srv_rest) {
                *out_srv_rest = (uint8_t)get_bits(bits, bitlen, content_offset + (unsigned int)li - 3, 1);
                *out_have_srv_rest = 1;
            }
        }

        pos += elem_len;

        /* SDRTetra semantics: if M==0, this was the last element */
        if (mbit == 0)
            break;
    }
}

/*
 * Find first plausible Type-3/4 header after start.
 * NOTE: M can be 0 or 1, so we DO NOT require M==1.
 */
static int find_first_type34(const uint8_t *bits, unsigned int nbits, unsigned int start)
{
    if (!bits || nbits < 16 || start >= nbits)
        return -1;

    for (unsigned int pos = start; pos + 16u <= nbits; pos++) {
        /* allow M=0 or M=1 */
        uint32_t tid = get_bits(bits, nbits, pos + 1, 4);
        if (!(tid == 0x5 || tid == 0x7 || tid == 0x2))
            continue;

        uint32_t li = get_bits(bits, nbits, pos + 5, 11);
        if (li == 0 || li > 512)
            continue;

        if (pos + 16u + (unsigned int)li <= nbits)
            return (int)pos;
    }
    return -1;
}

/* ---------- Logging ---------- */

static void mm_log_loc_upd_acc_sdrtetra_style(uint32_t issi, uint16_t la,
                                              uint32_t ssi_out,
                                              const uint32_t *gssi_list, uint8_t gssi_count,
                                              uint8_t have_cck, uint8_t cck_id,
                                              uint8_t have_roam, uint8_t roam_lu,
                                              uint8_t have_srv_rest, uint8_t srv_rest,
                                              uint8_t have_itsi_attach, uint8_t itsi_attach,
                                              uint8_t append_auth_ok)
{
    char tail[256];
    tail[0] = 0;

    if (append_auth_ok) {
        strncat(tail,
                " - Authentication successful or no authentication currently in progress",
                sizeof(tail) - strlen(tail) - 1);
    }

    if (have_cck) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), " - CCK_identifier: %u", (unsigned)cck_id);
        strncat(tail, tmp, sizeof(tail) - strlen(tail) - 1);
    }

    /* In SDRTetra zie je roaming tekst vrijwel altijd; ITSI attach kan óók tegelijk/afwisselend. */
    if (have_itsi_attach && itsi_attach) {
        strncat(tail, " - ITSI attach", sizeof(tail) - strlen(tail) - 1);
    }

    if (have_roam && roam_lu) {
        if (have_srv_rest && srv_rest)
            strncat(tail, " - Service restoration roaming location updating",
                    sizeof(tail) - strlen(tail) - 1);
        else
            strncat(tail, " - Roaming location updating",
                    sizeof(tail) - strlen(tail) - 1);
    }

    if (gssi_count > 0) {
        mm_logf_ctx(issi, la,
                    "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %u%s",
                    (unsigned)ssi_out, (unsigned)gssi_list[0], tail);
    } else {
        mm_logf_ctx(issi, la,
                    "MS request for registration/authentication ACCEPTED for SSI: %u%s",
                    (unsigned)ssi_out, tail);
    }
}

/* ---------- Core MM parse on prepared bitstream ---------- */

static int try_decode_mm_from_bits(struct tetra_mac_state *tms,
                                   const uint8_t *bits, unsigned int nbits,
                                   uint32_t issi, uint16_t la)
{
    if (!bits || nbits < 8)
        return 0;

#if MM_DEBUG_BITS
    /* quick visibility */
    mm_bit_dump_ctx(issi, la, "MM raw bits (start)", bits, nbits, 0, 80);
    mm_scan_type34_headers_ctx(issi, la, bits, nbits, 0, 400);
#endif

    /* SDRTetra-ish: keep it simple: find MM PDISC near start, try a few alignments */
    unsigned int best_toff = 0;
    uint8_t best_type = 0;
    int best_score = 0;

    unsigned int scan_limit = (nbits > 64u) ? 64u : nbits;

    for (unsigned int off = 0; off + 12u <= scan_limit; off++) {
        uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
        if (pdisc != TMLE_PDISC_MM)
            continue;

        unsigned int type_offsets[4] = { off + 4, off + 3, off + 5, off + 6 };
        for (unsigned int vi = 0; vi < 4; vi++) {
            unsigned int toff = type_offsets[vi];
            if (toff + 4 > nbits) continue;

            uint8_t type = (uint8_t)get_bits(bits, nbits, toff, 4);
            int score = 0;

            if (type == TMM_PDU_T_D_AUTH) {
                if (toff + 6 <= nbits) {
                    uint8_t st = (uint8_t)get_bits(bits, nbits, toff + 4, 2);
                    score = (st == 0 || st == 2) ? 95 : 70;
                }
            } else if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
                unsigned int payload_start = toff + 4;
                int t34 = find_first_type34(bits, nbits, payload_start);
                score = (t34 >= 0) ? 100 : 75;
            } else if (type == TMM_PDU_T_D_LOC_UPD_REJ) score = 60;
            else if (type == TMM_PDU_T_D_LOC_UPD_PROC) score = 55;
            else if (type == TMM_PDU_T_D_LOC_UPD_CMD) score = 55;
            else if (type == TMM_PDU_T_D_ATT_DET_GRP || type == TMM_PDU_T_D_ATT_DET_GRP_ACK) score = 50;

            if (score > best_score || (score == best_score && score > 0 && toff < best_toff)) {
                best_score = score;
                best_toff = toff;
                best_type = type;
            }
        }
    }

    if (best_score <= 0)
        return 0;

    unsigned int toff = best_toff;
    uint8_t type = best_type;

    if (type == TMM_PDU_T_D_AUTH) {
        if (toff + 6 <= nbits) {
            uint8_t st = (uint8_t)get_bits(bits, nbits, toff + 4, 2);
            if (st == 0) {
                mm_logf_ctx(issi, la, "BS demands authentication: SSI: %u", (unsigned)issi);
            } else if (st == 2) {
                mm_logf_ctx(issi, la,
                            "BS result to MS authentication: Authentication successful or no authentication currently in progress SSI: %u - Authentication successful or no authentication currently in progress",
                            (unsigned)issi);
                g_last_auth_issi = issi;
                g_last_auth_ok = 1;
            } else {
                mm_logf_ctx(issi, la, "BS auth message (subtype %u): SSI: %u",
                            (unsigned)st, (unsigned)issi);
            }
            return 1;
        }
    }

    if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
        unsigned int payload_start = toff + 4;
        mm_field_store fs = {0};

        unsigned int after_hdr = mm_rules_decode(bits, nbits, payload_start,
                                                 mm_rules_loc_upd_accept, mm_rules_loc_upd_accept_count,
                                                 &fs);

        int t34 = find_first_type34(bits, nbits, payload_start);
        if (t34 < 0)
            t34 = find_first_type34(bits, nbits, after_hdr);

        uint32_t gssi_list[8];
        uint8_t gssi_count = 0;
        memset(gssi_list, 0, sizeof(gssi_list));

        uint8_t roam = 0, have_roam = 0;
        uint8_t itsi_attach = 0, have_itsi_attach = 0;
        uint8_t srv_rest = 0, have_srv_rest = 0;

        uint32_t gssi = 0;
        uint8_t have_gssi = 0;

        /* Best-effort: sometimes rules store a 24-bit group-ish value */
        if (fs.present[GN_MM_SSI]) {
            uint32_t tmp = fs.value[GN_MM_SSI];
            if (tmp == 0xFFFFFFu || (tmp >= 1000000u && tmp <= 9000000u)) {
                gssi = tmp;
                have_gssi = 1;
            }
        }

        if (t34 >= 0) {
            mm_scan_type34_elements(bits, nbits, (unsigned int)t34,
                                    &gssi, &have_gssi,
                                    gssi_list, &gssi_count, 8,
                                    &roam, &have_roam,
                                    &itsi_attach, &have_itsi_attach,
                                    &srv_rest, &have_srv_rest);
        }

        if (have_gssi && gssi_count == 0) {
            add_gssi_to_list(gssi, gssi_list, &gssi_count, 8);
        }

        /* SDRTetra-like: CCK_identifier from crypto state */
        uint8_t have_cck = 0;
        uint8_t cck_id = 0;
        if (tms && tms->tcs) {
            cck_id = (uint8_t)tms->tcs->cck_id;
            /* if it’s 0, you can still choose to log it; SDRTetra usually has a valid one */
            have_cck = 1;
        }

        uint8_t append_auth_ok = 0;
        if (g_last_auth_ok && g_last_auth_issi == issi) {
            append_auth_ok = 1;
            g_last_auth_ok = 0;
            g_last_auth_issi = 0;
        }

        mm_log_loc_upd_acc_sdrtetra_style(issi, la,
                                          issi,
                                          gssi_list, gssi_count,
                                          have_cck, cck_id,
                                          have_roam, roam,
                                          have_srv_rest, srv_rest,
                                          have_itsi_attach, itsi_attach,
                                          append_auth_ok);
        return 1;
    }

    /* keep existing handling for other types if you want; minimal here */
    return 0;
}

/* ---------- MAIN ENTRY ---------- */

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len < 1)
        return (int)len;

    uint32_t issi = tms ? (uint32_t)tms->ssi : 0;
    int la_i = (tms && tms->tcs) ? (int)tms->tcs->la : -1;
    uint16_t la = (uint16_t)la_i;

    /* SDRTetra compat: first treat as unpacked bits (byte & 1), then packed MSB-first fallback */
    static uint8_t bits_unpacked[4096];
    static uint8_t bits_packed[4096];

    /* 1) Unpacked bits */
    unsigned int nbits_u = 0;
    unsigned int max_u = (len > sizeof(bits_unpacked)) ? (unsigned int)sizeof(bits_unpacked) : len;
    for (unsigned int i = 0; i < max_u; i++)
        bits_unpacked[nbits_u++] = buf[i] & 1u;

    if (try_decode_mm_from_bits(tms, bits_unpacked, nbits_u, issi, la))
        return (int)len;

    /* 2) Packed fallback: bytes -> bits MSB first */
    unsigned int max_p_bytes = len;
    if (max_p_bytes * 8 > sizeof(bits_packed))
        max_p_bytes = (unsigned int)(sizeof(bits_packed) / 8);

    unsigned int nbits_p = 0;
    for (unsigned int i = 0; i < max_p_bytes; i++) {
        uint8_t b = buf[i];
        for (int k = 7; k >= 0; k--)
            bits_packed[nbits_p++] = (b >> k) & 1u;
    }

    (void)try_decode_mm_from_bits(tms, bits_packed, nbits_p, issi, la);

    return (int)len;
}
