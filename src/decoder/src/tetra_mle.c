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
 * Robuuste MM decoder voor LLC-bypass (SDRTetra-style).
 *
 * Belangrijkste fix (waarom je geen GSSI zag):
 *  - Je parseerde TID=0x5 (Group identity location accept) met een "bits+content_offset"
 *    alsof content_offset een byte offset was in een packed buffer. Maar content_offset is
 *    een BIT offset in een array die 1-byte-per-bit representeert. Daardoor liep je record-
 *    parser structureel scheef t.o.v. de element boundaries en vond je geen GSSI.
 *
 * Fix:
 *  - Parse TID=0x5 altijd met ABSOLUTE bitpos in de originele bitstream.
 *    Dus: start_of_element_content_bit + p, met p in [0..LI).
 *
 * SDRTetra compat:
 *  - Eerst unpacked interpretatie (byte & 1), daarna packed fallback (MSB first).
 *  - Type offset varianten: +3/+4/+5/+6.
 *  - TLV (Type-3/4) scanning vanaf payload_start (direct na PDU-type) en fallback na rules.
 *  - ITSI attach kan WEL een GSSI hebben (SDR logs tonen dat): we suppressen GSSI niet.
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
#define MM_DEBUG_BITS 0
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
    char line[1400];
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

    char line[1600];
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

static void mm_debug_dump_mm_ctx(uint32_t issi, uint16_t la,
                                 const uint8_t *bits, unsigned int nbits,
                                 unsigned int pdisc_off)
{
    if (!bits || pdisc_off >= nbits) return;

    uint8_t pdisc = (uint8_t)get_bits(bits, nbits, pdisc_off, 3);
    unsigned int type_offsets[4] = { pdisc_off + 4, pdisc_off + 3, pdisc_off + 5, pdisc_off + 6 };

    mm_logf_ctx(issi, la, "MM DEBUG: pdisc_off=%u PDISC=%u", pdisc_off, (unsigned)pdisc);

    for (unsigned int i = 0; i < 4; i++) {
        unsigned int toff = type_offsets[i];
        if (toff + 4 > nbits) continue;
        uint8_t type = (uint8_t)get_bits(bits, nbits, toff, 4);

        mm_logf_ctx(issi, la, "MM DEBUG: candidate toff=%u (delta=%u) type=0x%X",
                    toff, toff - pdisc_off, (unsigned)type);

        mm_bit_dump_ctx(issi, la, "MM bits", bits, nbits, pdisc_off, 64);

        unsigned int after_type = toff + 4;
        const unsigned int starts[4] = { after_type, after_type + 8, after_type + 16, after_type + 24 };
        for (unsigned int s = 0; s < 4; s++) {
            uint8_t tmp[80];
            unsigned int blen = mm_bits_to_bytes_from(bits, nbits, starts[s], tmp, sizeof(tmp));
            char lbl[64];
            snprintf(lbl, sizeof(lbl), "MM hex from bit%u", starts[s]);
            mm_hex_dump_ctx(issi, la, lbl, tmp, blen);
        }
    }
}
#endif /* MM_DEBUG_BITS */

/* ---------- SDRTetra-ish auth state ---------- */

static uint32_t g_last_auth_issi = 0;
static uint8_t  g_last_auth_ok = 0; /* subtype=2 */

/* ---------- GSSI helpers ---------- */

static void add_gssi_to_list(uint32_t gssi, uint32_t *list, uint8_t *count, uint8_t max)
{
    if (!list || !count || gssi == 0)
        return;

    /* SDRTetra lijkt niet extreem te filteren; maar we voorkomen grove onzin */
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
 * SDR# / SDRTetra stijl record parser voor TID=0x5 "Group identity location accept":
 * binnen de element payload (LI bits) zitten records:
 *   sel=0: 24-bit GSSI
 *   sel=1: 24-bit GSSI + 24-bit extra (skip)
 *   sel=2: 24-bit vGSSI
 *   sel=3: stop/padding
 *
 * BELANGRIJK: we lezen op ABSOLUTE bitpos in de originele bits[] stream.
 */
static void mm_parse_group_identity_location_accept_abs(const uint8_t *bits,
                                                        unsigned int nbits,
                                                        unsigned int elem_content_start_bit,
                                                        unsigned int elem_li_bits,
                                                        uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                                        uint32_t *out_first_gssi, uint8_t *out_have_first_gssi,
                                                        uint32_t *out_vgssi, uint8_t *out_have_vgssi)
{
    if (!bits || elem_content_start_bit >= nbits || elem_li_bits < 2)
        return;

    unsigned int p = 0;
    uint8_t idx = 0;

    while (p + 2u <= elem_li_bits) {
        unsigned int abs = elem_content_start_bit + p;
        if (abs + 2u > nbits) break;

        uint8_t sel = (uint8_t)get_bits(bits, nbits, abs, 2);
        p += 2;

        if (sel == 3)
            break;

        if (sel == 0 || sel == 1) {
            if (p + 24u > elem_li_bits) break;
            abs = elem_content_start_bit + p;
            if (abs + 24u > nbits) break;

            uint32_t gssi = get_bits(bits, nbits, abs, 24);
            p += 24;

            if (sel == 1) {
                if (p + 24u > elem_li_bits) break;
                p += 24; /* skip extra 24 bits */
            }

            if (gssi != 0) {
                uint8_t before = out_gssi_count ? *out_gssi_count : 0;
                add_gssi_to_list(gssi, out_gssi_list, out_gssi_count, out_gssi_max);
                uint8_t after = out_gssi_count ? *out_gssi_count : before;

                if (after > before) {
                    if (out_first_gssi && out_have_first_gssi && idx == 0) {
                        *out_first_gssi = gssi;
                        *out_have_first_gssi = 1;
                    }
                    idx++;
                }
            }
        } else if (sel == 2) {
            if (p + 24u > elem_li_bits) break;
            abs = elem_content_start_bit + p;
            if (abs + 24u > nbits) break;

            uint32_t vgssi = get_bits(bits, nbits, abs, 24);
            p += 24;

            if (out_vgssi && out_have_vgssi) {
                *out_vgssi = vgssi;
                *out_have_vgssi = 1;
            }
        }
    }
}

static void mm_scan_type34_elements(const uint8_t *bits, unsigned int nbits, unsigned int start_bit,
                                    uint32_t *out_first_gssi, uint8_t *out_have_first_gssi,
                                    uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                    uint8_t *out_cck_id, uint8_t *out_have_cck,
                                    uint8_t *out_roam_lu, uint8_t *out_have_roam_lu,
                                    uint8_t *out_itsi_attach, uint8_t *out_have_itsi_attach,
                                    uint8_t *out_srv_rest, uint8_t *out_have_srv_rest)
{
    unsigned int pos = start_bit;

    while (pos + 16u <= nbits) {
        uint32_t mbit = get_bits(bits, nbits, pos, 1);
        if (mbit == 0)
            break;

        uint32_t tid = get_bits(bits, nbits, pos + 1, 4);
        uint32_t li  = get_bits(bits, nbits, pos + 5, 11);
        if (li == 0) {
            pos += 16;
            continue;
        }

        unsigned int elem_len = 16u + (unsigned int)li;
        if (pos + elem_len > nbits)
            break;

        unsigned int content = pos + 16u;

        if (tid == 0x5) {
            uint32_t dummy_vgssi = 0;
            uint8_t have_dummy_vgssi = 0;

            mm_parse_group_identity_location_accept_abs(bits, nbits,
                                                        content, (unsigned int)li,
                                                        out_gssi_list, out_gssi_count, out_gssi_max,
                                                        out_first_gssi, out_have_first_gssi,
                                                        &dummy_vgssi, &have_dummy_vgssi);
        }
        else if (tid == 0x7 && li >= 24) {
            /* legacy single GSSI: scan within element for a plausible 24-bit */
            for (unsigned int off = 0; off + 24u <= li; off++) {
                uint32_t v = get_bits(bits, nbits, content + off, 24);
                uint8_t before = out_gssi_count ? *out_gssi_count : 0;
                add_gssi_to_list(v, out_gssi_list, out_gssi_count, out_gssi_max);
                uint8_t after = out_gssi_count ? *out_gssi_count : before;
                if (after > before) {
                    if (out_first_gssi && out_have_first_gssi && !*out_have_first_gssi) {
                        *out_first_gssi = v;
                        *out_have_first_gssi = 1;
                    }
                    break;
                }
            }
        }
        else if (tid == 0x6 && li >= 8 && out_cck_id && out_have_cck) {
            *out_cck_id = (uint8_t)get_bits(bits, nbits, content + (unsigned int)li - 8u, 8);
            *out_have_cck = 1;
        }
        else if (tid == 0x2) {
            /* LSB flags best-effort */
            if (li >= 1 && out_roam_lu && out_have_roam_lu) {
                *out_roam_lu = (uint8_t)get_bits(bits, nbits, content + (unsigned int)li - 1u, 1);
                *out_have_roam_lu = 1;
            }
            if (li >= 2 && out_itsi_attach && out_have_itsi_attach) {
                *out_itsi_attach = (uint8_t)get_bits(bits, nbits, content + (unsigned int)li - 2u, 1);
                *out_have_itsi_attach = 1;
            }
            if (li >= 3 && out_srv_rest && out_have_srv_rest) {
                *out_srv_rest = (uint8_t)get_bits(bits, nbits, content + (unsigned int)li - 3u, 1);
                *out_have_srv_rest = 1;
            }
        }

        pos += elem_len;
    }
}

static int find_first_type34(const uint8_t *bits, unsigned int nbits, unsigned int start)
{
    if (!bits || nbits < 16 || start >= nbits)
        return -1;

    for (unsigned int pos = start; pos + 16u <= nbits; pos++) {
        if (get_bits(bits, nbits, pos, 1) != 1)
            continue;

        uint32_t tid = get_bits(bits, nbits, pos + 1, 4);
        if (!(tid == 0x5 || tid == 0x6 || tid == 0x2 || tid == 0x7))
            continue;

        uint32_t li = get_bits(bits, nbits, pos + 5, 11);
        if (li == 0 || li > 512)
            continue;

        if (pos + 16u + (unsigned int)li <= nbits)
            return (int)pos;
    }
    return -1;
}

/* ---------- SDRTetra-ish log formatting ---------- */

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
        strncat(tail, " - Authentication successful or no authentication currently in progress",
                sizeof(tail) - strlen(tail) - 1);
    }

    if (have_cck) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), " - CCK_identifier: %u", (unsigned)cck_id);
        strncat(tail, tmp, sizeof(tail) - strlen(tail) - 1);
    }

    /* SDRTetra: ITSI attach en roaming kunnen beiden bestaan; logs tonen vaak ITSI attach apart,
       maar jouw SDR logs tonen bij roaming regels. We volgen: eerst ITSI attach label, anders roaming label. */
    if (have_itsi_attach && itsi_attach) {
        strncat(tail, " - ITSI attach", sizeof(tail) - strlen(tail) - 1);
    } else if (have_roam && roam_lu) {
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

/* ---------- Core decoder over bitstream ---------- */

static int try_decode_mm_from_bits(struct tetra_mac_state *tms,
                                   const uint8_t *bits, unsigned int nbits,
                                   uint32_t issi, uint16_t la)
{
    (void)tms;

    if (!bits || nbits < 8)
        return 0;

#if MM_DEBUG_BITS
    static int dbg_once = 0;
#endif

    unsigned int best_toff = 0;
    uint8_t best_type = 0;
    int best_score = 0;

    for (unsigned int off = 0; off + 12u <= nbits; off++) {
        uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
        if (pdisc != TMLE_PDISC_MM)
            continue;

#if MM_DEBUG_BITS
        if (!dbg_once) {
            mm_debug_dump_mm_ctx(issi, la, bits, nbits, off);
            dbg_once = 1;
        }
#endif

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
                score = (t34 >= 0) ? 100 : 80;
            } else if (type == TMM_PDU_T_D_LOC_UPD_REJ) {
                score = 60;
            } else if (type == TMM_PDU_T_D_LOC_UPD_PROC) {
                score = 55;
            } else if (type == TMM_PDU_T_D_LOC_UPD_CMD) {
                score = 55;
            } else if (type == TMM_PDU_T_D_ATT_DET_GRP || type == TMM_PDU_T_D_ATT_DET_GRP_ACK) {
                score = 50;
            }

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

        uint8_t cck_id = 0, have_cck = 0;
        uint8_t roam = 0, have_roam = 0;
        uint8_t itsi_attach = 0, have_itsi_attach = 0;
        uint8_t srv_rest = 0, have_srv_rest = 0;

        uint32_t first_gssi = 0;
        uint8_t have_first_gssi = 0;

        /* Best-effort: sommige builds stoppen een 24b waarde in GN_MM_SSI; neem hem mee als fallback */
        if (fs.present[GN_MM_SSI]) {
            uint32_t tmp = fs.value[GN_MM_SSI];
            if (tmp == 0xFFFFFFu || (tmp >= 1000000u && tmp <= 9000000u)) {
                first_gssi = tmp;
                have_first_gssi = 1;
            }
        }

        if (t34 >= 0) {
            mm_scan_type34_elements(bits, nbits, (unsigned int)t34,
                                    &first_gssi, &have_first_gssi,
                                    gssi_list, &gssi_count, 8,
                                    &cck_id, &have_cck,
                                    &roam, &have_roam,
                                    &itsi_attach, &have_itsi_attach,
                                    &srv_rest, &have_srv_rest);
        }

        if (have_first_gssi && gssi_count == 0) {
            add_gssi_to_list(first_gssi, gssi_list, &gssi_count, 8);
        }

        uint32_t ssi_out = issi;

        uint8_t append_auth_ok = 0;
        if (g_last_auth_ok && g_last_auth_issi == issi) {
            append_auth_ok = 1;
            g_last_auth_ok = 0;
            g_last_auth_issi = 0;
        }

        mm_log_loc_upd_acc_sdrtetra_style(issi, la,
                                          ssi_out,
                                          gssi_list, gssi_count,
                                          have_cck, cck_id,
                                          have_roam, roam,
                                          have_srv_rest, srv_rest,
                                          have_itsi_attach, itsi_attach,
                                          append_auth_ok);
        return 1;
    }

    /* overige types (optioneel; houdt je tekst consistent) */
    if (type == TMM_PDU_T_D_LOC_UPD_CMD) {
        mm_logf_ctx(issi, la, "SwMI sent LOCATION UPDATE COMMAND for SSI: %u", (unsigned)issi);
        return 1;
    }
    if (type == TMM_PDU_T_D_LOC_UPD_PROC) {
        mm_logf_ctx(issi, la, "SwMI sent LOCATION UPDATE PROCEEDING for SSI: %u", (unsigned)issi);
        return 1;
    }
    if (type == TMM_PDU_T_D_LOC_UPD_REJ) {
        mm_logf_ctx(issi, la, "SwMI sent LOCATION UPDATE REJECT for SSI: %u", (unsigned)issi);
        return 1;
    }
    if (type == TMM_PDU_T_D_ATT_DET_GRP) {
        mm_logf_ctx(issi, la, "SwMI sent ATTACH/DETACH GROUP IDENTITY for SSI: %u", (unsigned)issi);
        return 1;
    }
    if (type == TMM_PDU_T_D_ATT_DET_GRP_ACK) {
        mm_logf_ctx(issi, la, "SwMI sent ATTACH/DETACH GROUP IDENTITY ACK for SSI: %u", (unsigned)issi);
        return 1;
    }

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

    /* 1) Unpacked bits: altijd eerst (SDRTetra-style chain) */
    static uint8_t bits_unpacked[4096];
    unsigned int nbits_u = 0;
    unsigned int max_u = (len > sizeof(bits_unpacked)) ? (unsigned int)sizeof(bits_unpacked) : len;
    for (unsigned int i = 0; i < max_u; i++)
        bits_unpacked[nbits_u++] = buf[i] & 1u;

    if (try_decode_mm_from_bits(tms, bits_unpacked, nbits_u, issi, la))
        return (int)len;

    /* 2) Packed fallback: bytes -> bits MSB first */
    static uint8_t bits_packed[4096];
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
