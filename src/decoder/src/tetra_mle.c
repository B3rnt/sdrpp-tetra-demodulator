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
 * Robuuste MM decoder voor LLC-bypass.
 *
 * Wat er mis ging in de eerdere versie:
 *  - De code nam aan dat na PDISC(3) meteen de PDU-type(4) komt.
 *    In praktijk zit er vaak een 1-bit "spare/skip" tussen (PDISC=3, spare=1, type=4).
 *    Daardoor las je altijd het verkeerde type en zag je nooit D-LOC-UPD-ACC.
 *  - De header van D-LOC-UPD-ACC is variabel (meerdere type-2 velden optioneel).
 *    In plaats van exact alle C/O-velden te rekenen (wat afhankelijk is van LU-type etc.),
 *    is het betrouwbaarder om de Type-3/4 elementen te zoeken via hun eigen TLV header.
 *
 * Resultaat:
 *  - Detecteer MM PDISC met 3 bits.
 *  - Probeer meerdere varianten voor PDU-type offset: +3/+4/+5/+6.
 *  - Voor D-LOC-UPD-ACC: zoek Type-3/4 elementen via TLV headers.
 *
 * SDRTetra compat aanvullingen:
 *  - SDRTetra levert vaak bits als "1 byte per bit" (0x00/0xFF/...) => bit = (byte & 1).
 *    Daarom proberen we altijd eerst deze unpacked interpretatie en pas daarna packed.
 *  - SDRTetra vindt TLV’s vaak door te scannen vanaf direct na PDU-type (payload_start),
 *    niet vanaf een afgeleide after_hdr. Daarom doen we dat nu ook (payload_start first).
 *  - SDRTetra plakt vaak de auth-result tekst aan de LOC_UPD_ACC regel.
 *    We onthouden de laatste auth-result subtype=2 per ISSI en plakken die erbij als het past.
 *  - SDRTetra toont soms “Service restoration roaming location updating”. Dit lijkt een extra flagbit
 *    in TID=0x2 (naast roaming / itsi_attach). We lezen daarom ook een derde bit (indien aanwezig).
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

/* ===================== MM DEBUG BITDUMP (SDR#-style tracing) ===================== */

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

static void mm_scan_24bit_candidates_ctx(uint32_t issi, uint16_t la,
                                        const uint8_t *buf, unsigned int len,
                                        unsigned int base_bit)
{
    if (!buf || len < 3) return;
    for (unsigned int i = 0; i + 2 < len; i++) {
        uint32_t v = ((uint32_t)buf[i] << 16) | ((uint32_t)buf[i+1] << 8) | (uint32_t)buf[i+2];
        if (v >= 1000000 && v <= 9000000) {
            mm_logf_ctx(issi, la,
                        "MM 24-bit candidate at byte+%u (bit+%u): %u (0x%06X) bytes=%02X %02X %02X",
                        i, base_bit + i*8, (unsigned)v, (unsigned)v,
                        (unsigned)buf[i], (unsigned)buf[i+1], (unsigned)buf[i+2]);
        }
    }
}

static void mm_scan_type34_headers_ctx(uint32_t issi, uint16_t la,
                                      const uint8_t *bits, unsigned int nbits,
                                      unsigned int start_bit, unsigned int window_bits)
{
    if (!bits || start_bit >= nbits) return;
    unsigned int end = start_bit + window_bits;
    if (end > nbits) end = nbits;

    for (unsigned int pos = start_bit; pos + 16u <= end; pos++) {
        if (get_bits(bits, nbits, pos, 1) != 1) continue;
        uint32_t tid = get_bits(bits, nbits, pos + 1, 4);
        uint32_t li  = get_bits(bits, nbits, pos + 5, 11);
        if (li == 0 || li > 1024) continue;
        if (pos + 16u + (unsigned int)li > nbits) continue;

        if (!(tid == 0x2 || tid == 0x5 || tid == 0x6 || tid == 0x7)) continue;

        mm_logf_ctx(issi, la, "MM Type3/4 header at bit%u: M=1 TID=0x%X LI=%u (ends bit%u)",
                    pos, (unsigned)tid, (unsigned)li, pos + 16u + (unsigned)li);
    }
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

            mm_scan_24bit_candidates_ctx(issi, la, tmp, blen, starts[s]);
            mm_scan_type34_headers_ctx(issi, la, bits, nbits, starts[s], 256);
        }
    }
}

#endif /* MM_DEBUG_BITS */

/* ===================== end MM DEBUG ===================== */

/* ---------- SDRTetra-ish auth state (to append on LOC_UPD_ACC line) ---------- */

static uint32_t g_last_auth_issi = 0;
static uint8_t  g_last_auth_ok = 0; /* subtype=2 */

/* ---------- GSSI helpers ---------- */

static void add_gssi_to_list(uint32_t gssi, uint32_t *list, uint8_t *count, uint8_t max)
{
    /*
     * In praktijk geeft een "blind" 24-bit read vaak vals-positieven.
     * SDR# lijkt (impliciet) alleen plausibele 24-bit groeps-ID's te accepteren.
     * Heuristiek:
     *  - 0xFFFFFF is "open" SSI in ETSI context (niet wegfilteren)
     *  - anders: 1.000.000 .. 9.000.000
     */
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
            if (p + 24u > bitlen)
                break;
            uint32_t gssi = get_bits(bits, bitlen, p, 24);
            p += 24;

            if (sel == 1) {
                if (p + 24u > bitlen)
                    break;
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
            if (p + 24u > bitlen)
                break;
            uint32_t vgssi = get_bits(bits, bitlen, p, 24);
            p += 24;

            if (out_vgssi && out_have_vgssi) {
                *out_vgssi = vgssi;
                *out_have_vgssi = 1;
            }
        }
    }
}

static void mm_scan_type34_elements(const uint8_t *bits, unsigned int bitlen, unsigned int start_bit,
                                    uint32_t *out_gssi, uint8_t *out_have_gssi,
                                    uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                    uint8_t *out_cck_id, uint8_t *out_have_cck,
                                    uint8_t *out_roam_lu, uint8_t *out_have_roam_lu,
                                    uint8_t *out_itsi_attach, uint8_t *out_have_itsi_attach,
                                    uint8_t *out_srv_rest, uint8_t *out_have_srv_rest)
{
    unsigned int pos = start_bit;

    while (pos + 16u <= bitlen) {
        uint32_t mbit = get_bits(bits, bitlen, pos, 1);
        if (mbit == 0)
            break;

        uint32_t tid = get_bits(bits, bitlen, pos + 1, 4);
        uint32_t li  = get_bits(bits, bitlen, pos + 5, 11);

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
        }
        else if (tid == 0x7 && li >= 24) {
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
        }
        else if (tid == 0x6 && li >= 8 && out_cck_id && out_have_cck) {
            *out_cck_id = (uint8_t)get_bits(bits, bitlen, content_offset + (unsigned int)li - 8, 8);
            *out_have_cck = 1;
        }
        else if (tid == 0x2) {
            /* LSB flags (best-effort, SDRTetra-like) */
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
    }
}

/*
 * Zoek in de bitstream naar een plausibele Type-3/4 element header:
 *   M(1)=1, TID(4), LI(11) met LI > 0 en pos+16+LI <= nbits.
 */
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
        /* SDRTetra toont bij jou één GSSI; we printen de eerste */
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

#if MM_DEBUG_BITS
    static int mm_debug_done = 0;
#endif

    unsigned int best_off = 0, best_toff = 0;
    uint8_t best_type = 0;
    int best_score = 0;

    for (unsigned int off = 0; off + 12u <= nbits; off++) {
        uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
        if (pdisc != TMLE_PDISC_MM)
            continue;

#if MM_DEBUG_BITS
        if (!mm_debug_done) {
            mm_debug_dump_mm_ctx(issi, la, bits, nbits, off);
            mm_debug_done = 1;
        }
#endif

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
                /* SDRTetra-like validation: TLVs soon after payload_start */
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
                best_off = off;
                best_toff = toff;
                best_type = type;
            }
        }
    }

    (void)best_off;

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

    if (type == TMM_PDU_T_D_LOC_UPD_CMD) {
        unsigned int payload_start = toff + 4;
        mm_field_store fs = {0};
        (void)mm_rules_decode(bits, nbits, payload_start,
                              mm_rules_loc_upd_command, mm_rules_loc_upd_command_count,
                              &fs);
        mm_logf_ctx(issi, la, "SwMI sent LOCATION UPDATE COMMAND for SSI: %u", (unsigned)issi);
        return 1;
    }

    if (type == TMM_PDU_T_D_ATT_DET_GRP) {
        unsigned int payload_start = toff + 4;
        mm_field_store fs = {0};
        (void)mm_rules_decode(bits, nbits, payload_start,
                              mm_rules_att_det_grp, mm_rules_att_det_grp_count,
                              &fs);
        mm_logf_ctx(issi, la, "SwMI sent ATTACH/DETACH GROUP IDENTITY for SSI: %u", (unsigned)issi);
        return 1;
    }

    if (type == TMM_PDU_T_D_ATT_DET_GRP_ACK) {
        unsigned int payload_start = toff + 4;
        mm_field_store fs = {0};
        (void)mm_rules_decode(bits, nbits, payload_start,
                              mm_rules_att_det_grp_ack, mm_rules_att_det_grp_ack_count,
                              &fs);
        mm_logf_ctx(issi, la, "SwMI sent ATTACH/DETACH GROUP IDENTITY ACK for SSI: %u", (unsigned)issi);
        return 1;
    }

    if (type == TMM_PDU_T_D_LOC_UPD_PROC) {
        unsigned int payload_start = toff + 4;
        mm_field_store fs = {0};
        (void)mm_rules_decode(bits, nbits, payload_start,
                              mm_rules_loc_upd_proceeding, mm_rules_loc_upd_proceeding_count,
                              &fs);
        mm_logf_ctx(issi, la, "SwMI sent LOCATION UPDATE PROCEEDING for SSI: %u", (unsigned)issi);
        return 1;
    }

    if (type == TMM_PDU_T_D_LOC_UPD_REJ) {
        unsigned int payload_start = toff + 4;
        mm_field_store fs = {0};
        (void)mm_rules_decode(bits, nbits, payload_start,
                              mm_rules_loc_upd_reject, mm_rules_loc_upd_reject_count,
                              &fs);
        mm_logf_ctx(issi, la, "SwMI sent LOCATION UPDATE REJECT for SSI: %u (cause=%u)",
                    (unsigned)issi,
                    (unsigned)(fs.present[GN_Reject_cause] ? fs.value[GN_Reject_cause] : 0));
        return 1;
    }

    if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
        unsigned int payload_start = toff + 4;
        mm_field_store fs = {0};

        unsigned int after_hdr = mm_rules_decode(bits, nbits, payload_start,
                                                 mm_rules_loc_upd_accept, mm_rules_loc_upd_accept_count,
                                                 &fs);

        /* SDRTetra-like: TLVs from payload_start first */
        int t34 = find_first_type34(bits, nbits, payload_start);
        if (t34 < 0)
            t34 = find_first_type34(bits, nbits, after_hdr);

        uint32_t gssi_list[8];
        uint8_t gssi_count = 0;
        memset(gssi_list, 0, sizeof(gssi_list));

        uint8_t cck_id = 0;
        uint8_t have_cck = 0;
        uint8_t roam = 0;
        uint8_t have_roam = 0;
        uint8_t itsi_attach = 0;
        uint8_t have_itsi_attach = 0;
        uint8_t srv_rest = 0;
        uint8_t have_srv_rest = 0;

        uint32_t gssi = 0;
        uint8_t have_gssi = 0;

        /* best-effort from rules decode (if present) */
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
                                    &cck_id, &have_cck,
                                    &roam, &have_roam,
                                    &itsi_attach, &have_itsi_attach,
                                    &srv_rest, &have_srv_rest);

            /* SDRTetra: bij ITSI attach geen GSSI tonen */
            if (have_itsi_attach && itsi_attach) {
                have_gssi = 0;
                gssi_count = 0;
            }
        }

        if (have_gssi && gssi_count == 0) {
            add_gssi_to_list(gssi, gssi_list, &gssi_count, 8);
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

    /* SDRTetra compat: eerst altijd "unpacked bits" (byte & 1), daarna packed fallback */
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
