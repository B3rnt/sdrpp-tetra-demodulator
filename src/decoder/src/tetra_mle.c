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
 * MM decoder (LLC-bypass) – SDRTetra-achtig.
 *
 * BELANGRIJKSTE FIX:
 *  - parse Type-3/4 content met absolute bitposities (geen bits+offset pointer slicing).
 *    Daardoor werkte TID=0x5 (Group identity location accept) onbetrouwbaar
 *    en miste je GSSI bij roaming/accept.
 *
 * EXTRA:
 *  - ITSI attach kan WEL een GSSI bevatten => niet weggooien.
 */

static uint32_t get_bits(const uint8_t *bits, unsigned int len, unsigned int pos, unsigned int n)
{
    if (!bits || n == 0 || pos + n > len)
        return 0;

    uint32_t val = 0;
    for (unsigned int i = 0; i < n; i++)
        val = (val << 1) | (bits[pos + i] & 1u);
    return val;
}

/* ---------- SDRTetra-ish auth state ---------- */
static uint32_t g_last_auth_issi = 0;
static uint8_t  g_last_auth_ok = 0; /* subtype=2 */

/* ---------- GSSI helpers ---------- */
static void add_gssi_to_list(uint32_t gssi, uint32_t *list, uint8_t *count, uint8_t max)
{
    if (!list || !count || gssi == 0)
        return;

    /* SDRTetra-like plausibility */
    if (!(gssi == 0xFFFFFFu || (gssi >= 1000000u && gssi <= 9000000u)))
        return;

    for (uint8_t i = 0; i < *count; i++) {
        if (list[i] == gssi)
            return;
    }
    if (*count < max)
        list[(*count)++] = gssi;
}

/* ---------- Type-3/4 parsing ---------- */

/*
 * SDR# / SDRTetra record format for TID=0x5:
 *   sel=0: 24-bit GSSI
 *   sel=1: 24-bit GSSI + 24-bit extra (skip)
 *   sel=2: 24-bit vGSSI
 *   sel=3: stop/padding
 *
 * FIX: we lezen altijd via absolute bitposities:
 *   bits[] = volledige bitstream
 *   nbits  = totale lengte bitstream
 *   start_bit = begin van dit element-content (direct na type3/4 header)
 *   bitlen = LI (content length in bits)
 */
static void mm_parse_group_identity_location_accept_abs(const uint8_t *bits,
                                                        unsigned int nbits,
                                                        unsigned int start_bit,
                                                        unsigned int bitlen,
                                                        uint32_t *out_gssi_list,
                                                        uint8_t *out_gssi_count,
                                                        uint8_t out_gssi_max)
{
    if (!bits || bitlen < 2)
        return;

    unsigned int p = 0;

    while (p + 2u <= bitlen) {
        uint8_t sel = (uint8_t)get_bits(bits, nbits, start_bit + p, 2);
        p += 2;

        if (sel == 3)
            break;

        if (sel == 0 || sel == 1) {
            if (p + 24u > bitlen)
                break;
            uint32_t gssi = get_bits(bits, nbits, start_bit + p, 24);
            p += 24;

            if (sel == 1) {
                if (p + 24u > bitlen)
                    break;
                p += 24;
            }

            if (gssi != 0) {
                add_gssi_to_list(gssi, out_gssi_list, out_gssi_count, out_gssi_max);
            }
        } else if (sel == 2) {
            /* vGSSI aanwezig maar we gebruiken hem niet voor logging */
            if (p + 24u > bitlen)
                break;
            p += 24;
        }
    }
}

static void mm_scan_type34_elements_abs(const uint8_t *bits, unsigned int nbits,
                                        unsigned int start_bit,
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

        unsigned int content_start = pos + 16u;

        if (tid == 0x5) {
            /* Group identity location accept (record list) */
            mm_parse_group_identity_location_accept_abs(bits, nbits, content_start, (unsigned int)li,
                                                        out_gssi_list, out_gssi_count, out_gssi_max);
        }
        else if (tid == 0x7 && li >= 24) {
            /* legacy single 24-bit value; scan within element */
            for (unsigned int off = 0; off + 24u <= li; off++) {
                uint32_t v = get_bits(bits, nbits, content_start + off, 24);
                uint8_t before = *out_gssi_count;
                add_gssi_to_list(v, out_gssi_list, out_gssi_count, out_gssi_max);
                if (*out_gssi_count > before)
                    break;
            }
        }
        else if (tid == 0x6 && li >= 8 && out_cck_id && out_have_cck) {
            *out_cck_id = (uint8_t)get_bits(bits, nbits, content_start + (unsigned int)li - 8u, 8);
            *out_have_cck = 1;
        }
        else if (tid == 0x2) {
            /* LSB flags */
            if (li >= 1 && out_roam_lu && out_have_roam_lu) {
                *out_roam_lu = (uint8_t)get_bits(bits, nbits, content_start + (unsigned int)li - 1u, 1);
                *out_have_roam_lu = 1;
            }
            if (li >= 2 && out_itsi_attach && out_have_itsi_attach) {
                *out_itsi_attach = (uint8_t)get_bits(bits, nbits, content_start + (unsigned int)li - 2u, 1);
                *out_have_itsi_attach = 1;
            }
            if (li >= 3 && out_srv_rest && out_have_srv_rest) {
                *out_srv_rest = (uint8_t)get_bits(bits, nbits, content_start + (unsigned int)li - 3u, 1);
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
        uint32_t mbit = get_bits(bits, nbits, pos, 1);
        if (mbit != 1)
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
static int try_decode_mm_from_bits(const uint8_t *bits, unsigned int nbits,
                                   uint32_t issi, uint16_t la)
{
    if (!bits || nbits < 8)
        return 0;

    unsigned int best_toff = 0;
    uint8_t best_type = 0;
    int best_score = 0;

    for (unsigned int off = 0; off + 12u <= nbits; off++) {
        uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
        if (pdisc != TMLE_PDISC_MM)
            continue;

        unsigned int type_offsets[4] = { off + 4, off + 3, off + 5, off + 6 };
        for (unsigned int vi = 0; vi < 4; vi++) {
            unsigned int toff = type_offsets[vi];
            if (toff + 4 > nbits)
                continue;

            uint8_t type = (uint8_t)get_bits(bits, nbits, toff, 4);
            int score = 0;

            if (type == TMM_PDU_T_D_AUTH) {
                score = 90;
            } else if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
                unsigned int payload_start = toff + 4;
                int t34 = find_first_type34(bits, nbits, payload_start);
                score = (t34 >= 0) ? 100 : 70;
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
        return 0;
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

        if (t34 >= 0) {
            mm_scan_type34_elements_abs(bits, nbits, (unsigned int)t34,
                                        gssi_list, &gssi_count, 8,
                                        &cck_id, &have_cck,
                                        &roam, &have_roam,
                                        &itsi_attach, &have_itsi_attach,
                                        &srv_rest, &have_srv_rest);
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

    /* eerst unpacked bits (byte&1), daarna packed fallback */
    static uint8_t bits_unpacked[4096];
    static uint8_t bits_packed[4096];

    unsigned int nbits_u = 0;
    unsigned int max_u = (len > sizeof(bits_unpacked)) ? (unsigned int)sizeof(bits_unpacked) : len;
    for (unsigned int i = 0; i < max_u; i++)
        bits_unpacked[nbits_u++] = buf[i] & 1u;

    if (try_decode_mm_from_bits(bits_unpacked, nbits_u, issi, la))
        return (int)len;

    unsigned int max_p_bytes = len;
    if (max_p_bytes * 8 > sizeof(bits_packed))
        max_p_bytes = (unsigned int)(sizeof(bits_packed) / 8);

    unsigned int nbits_p = 0;
    for (unsigned int i = 0; i < max_p_bytes; i++) {
        uint8_t b = buf[i];
        for (int k = 7; k >= 0; k--)
            bits_packed[nbits_p++] = (b >> k) & 1u;
    }

    (void)try_decode_mm_from_bits(bits_packed, nbits_p, issi, la);
    return (int)len;
}
