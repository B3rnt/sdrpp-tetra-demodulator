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
 * SDRTetra-compatible MM decoder voor LLC-bypass.
 *
 * Belangrijkste bugfix t.o.v. jouw versie:
 *  - TID=0x5 (Group identity location accept) werd verkeerd geparsed:
 *    je deed bits + content_offset, maar content_offset is in BITS.
 *    Daardoor schoof je in BYTES i.p.v. bits -> altijd misaligned -> geen GSSI.
 *
 * Deze file parse't TID=0x5 nu zoals SDRTetra (Class18):
 *  - zelfde base pointer, alleen bitpos verschuiven.
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

/* ---------- SDRTetra-ish auth state (append on LOC_UPD_ACC line) ---------- */

static uint32_t g_last_auth_issi = 0;
static uint8_t  g_last_auth_ok = 0; /* subtype=2 */

/* ---------- GSSI helpers ---------- */

static void add_gssi_to_list(uint32_t gssi, uint32_t *list, uint8_t *count, uint8_t max)
{
    /* SDRTetra accepteert o.a. 0xFFFFFF (OPEN) en normale 24-bit groepen. */
    if (!list || !count || gssi == 0)
        return;

    /* Plausibiliteit: laat 0xFFFFFF toe, plus realistische range */
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
 * SDRTetra (Class18) leest Group_identity_location_accept (TID=0x5) als:
 *   2-bit selector:
 *     0: 24-bit GSSI
 *     1: 24-bit GSSI + 24-bit extra (skip)
 *     2: 24-bit vGSSI
 *     3: stop/padding
 *
 * CRUCIAAL: parse op basis van (bits, nbits, start_bit), NIET bits+offset pointer.
 */
static void mm_parse_group_identity_location_accept(const uint8_t *bits, unsigned int nbits,
                                                    unsigned int start_bit, unsigned int bitlen,
                                                    uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                                    uint32_t *out_vgssi, uint8_t *out_have_vgssi)
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
                p += 24; /* skip extra */
            }

            if (gssi != 0) {
                add_gssi_to_list(gssi, out_gssi_list, out_gssi_count, out_gssi_max);
            }
        } else if (sel == 2) {
            if (p + 24u > bitlen)
                break;

            uint32_t vgssi = get_bits(bits, nbits, start_bit + p, 24);
            p += 24;

            if (out_vgssi && out_have_vgssi) {
                *out_vgssi = vgssi;
                *out_have_vgssi = 1;
            }
        }
    }
}

static void mm_scan_type34_elements(const uint8_t *bits, unsigned int nbits, unsigned int start_bit,
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

        unsigned int elem_len = 16 + (unsigned int)li;
        if (pos + elem_len > nbits)
            break;

        unsigned int content_offset = pos + 16;

        if (tid == 0x5) {
            /* FIX: parse vanaf base bits + bit-start (content_offset), niet bits+content_offset */
            uint32_t dummy_vgssi = 0;
            uint8_t have_dummy_vgssi = 0;
            mm_parse_group_identity_location_accept(bits, nbits,
                                                    content_offset, (unsigned int)li,
                                                    out_gssi_list, out_gssi_count, out_gssi_max,
                                                    &dummy_vgssi, &have_dummy_vgssi);
        }
        else if (tid == 0x6 && li >= 8 && out_cck_id && out_have_cck) {
            *out_cck_id = (uint8_t)get_bits(bits, nbits, content_offset + (unsigned int)li - 8, 8);
            *out_have_cck = 1;
        }
        else if (tid == 0x2) {
            /* LSB flags (best-effort SDRTetra-like) */
            if (li >= 1 && out_roam_lu && out_have_roam_lu) {
                *out_roam_lu = (uint8_t)get_bits(bits, nbits, content_offset + (unsigned int)li - 1, 1);
                *out_have_roam_lu = 1;
            }
            if (li >= 2 && out_itsi_attach && out_have_itsi_attach) {
                *out_itsi_attach = (uint8_t)get_bits(bits, nbits, content_offset + (unsigned int)li - 2, 1);
                *out_have_itsi_attach = 1;
            }
            if (li >= 3 && out_srv_rest && out_have_srv_rest) {
                *out_srv_rest = (uint8_t)get_bits(bits, nbits, content_offset + (unsigned int)li - 3, 1);
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

/* ---------- SDRTetra-ish log formatting for LOC_UPD_ACC ---------- */

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

    /* SDRTetra: ITSI attach is just a tag; GSSI kan er wel degelijk naast bestaan */
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

/* ---------- Core decoder: run MM parse on prepared bitstream ---------- */

static int try_decode_mm_from_bits(struct tetra_mac_state *tms,
                                   const uint8_t *bits, unsigned int nbits,
                                   uint32_t issi, uint16_t la, unsigned int len)
{
    (void)tms;
    (void)len;

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

        if (t34 >= 0) {
            mm_scan_type34_elements(bits, nbits, (unsigned int)t34,
                                    gssi_list, &gssi_count, 8,
                                    &cck_id, &have_cck,
                                    &roam, &have_roam,
                                    &itsi_attach, &have_itsi_attach,
                                    &srv_rest, &have_srv_rest);
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

    /* overige types: laat je bestaande logs/rules staan als je wil, of voeg ze hier toe */
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

    /* SDRTetra compat: eerst unpacked bits (byte&1), daarna packed fallback */
    static uint8_t bits_unpacked[4096];
    static uint8_t bits_packed[4096];

    /* 1) Unpacked bits */
    unsigned int nbits_u = 0;
    unsigned int max_u = (len > sizeof(bits_unpacked)) ? (unsigned int)sizeof(bits_unpacked) : len;
    for (unsigned int i = 0; i < max_u; i++)
        bits_unpacked[nbits_u++] = buf[i] & 1u;

    if (try_decode_mm_from_bits(tms, bits_unpacked, nbits_u, issi, la, len))
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

    (void)try_decode_mm_from_bits(tms, bits_packed, nbits_p, issi, la, len);

    return (int)len;
}
