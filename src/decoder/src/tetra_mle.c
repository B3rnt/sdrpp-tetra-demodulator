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
 *  - Probeer 2 varianten voor PDU-type offset: +3 (oude) en +4 (met spare bit).
 *  - Voor D-LOC-UPD-ACC: zoek Type-3/4 elementen anywhere na het type.
 *
 * Dit matcht beter wat SDR# laat zien: "MS request for registration ACCEPTED ... GSSI ... CCK_identifier ..."
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

/* Set to 1 for verbose bit/hex dumps to diagnose alignment + locate GSSI/CCK/flags */
#ifndef MM_DEBUG_BITS
/* Default: keep user logs clean. Enable at compile time with -DMM_DEBUG_BITS=1 */
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

    /* print grouped: 3 | 1 | 4 | (rest octets) */
    for (unsigned int i = 0; i < nshow_bits && p + 3 < sizeof(line); i++) {
        /* separators: after 3,4,8,16... */
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

/* Find plausible Type-3/4 headers (M=1, TID, LI) and print them for context. */
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

        /* restrict to interesting tids to avoid log spam */
        if (!(tid == 0x2 || tid == 0x5 || tid == 0x6 || tid == 0x7)) continue;

        mm_logf_ctx(issi, la, "MM Type3/4 header at bit%u: M=1 TID=0x%X LI=%u (ends bit%u)",
                    pos, (unsigned)tid, (unsigned)li, pos + 16u + (unsigned)li);
    }
}

/* Main debug hook: show offsets + bit/hex windows for candidate MM PDUs */
static void mm_debug_dump_mm_ctx(uint32_t issi, uint16_t la,
                                 const uint8_t *bits, unsigned int nbits,
                                 unsigned int pdisc_off)
{
    if (!bits || pdisc_off >= nbits) return;

    uint8_t pdisc = (uint8_t)get_bits(bits, nbits, pdisc_off, 3);
    /* try multiple type offsets like the decoder */
    unsigned int type_offsets[4] = { pdisc_off + 4, pdisc_off + 3, pdisc_off + 5, pdisc_off + 6 };

    mm_logf_ctx(issi, la, "MM DEBUG: pdisc_off=%u PDISC=%u", pdisc_off, (unsigned)pdisc);

    for (unsigned int i = 0; i < 4; i++) {
        unsigned int toff = type_offsets[i];
        if (toff + 4 > nbits) continue;
        uint8_t type = (uint8_t)get_bits(bits, nbits, toff, 4);

        mm_logf_ctx(issi, la, "MM DEBUG: candidate toff=%u (delta=%u) type=0x%X",
                    toff, toff - pdisc_off, (unsigned)type);

        /* bit view around pdisc/type */
        mm_bit_dump_ctx(issi, la, "MM bits", bits, nbits, pdisc_off, 64);

        /* hex views at several byte alignments after the type */
        unsigned int after_type = toff + 4;
        const unsigned int starts[4] = { after_type, after_type + 8, after_type + 16, after_type + 24 };
        for (unsigned int s = 0; s < 4; s++) {
            uint8_t tmp[80];
            unsigned int blen = mm_bits_to_bytes_from(bits, nbits, starts[s], tmp, sizeof(tmp));
            char lbl[64];
            snprintf(lbl, sizeof(lbl), "MM hex from bit%u", starts[s]);
            mm_hex_dump_ctx(issi, la, lbl, tmp, blen);

            /* candidates + type3/4 headers in same window */
            mm_scan_24bit_candidates_ctx(issi, la, tmp, blen, starts[s]);
            mm_scan_type34_headers_ctx(issi, la, bits, nbits, starts[s], 256);
        }
    }
}

#endif /* MM_DEBUG_BITS */

/* ===================== end MM DEBUG ===================== */


static void add_gssi_to_list(uint32_t gssi, uint32_t *list, uint8_t *count, uint8_t max)
{
    /* 0xFFFFFF is "open" SSI in ETSI context (veel netten sturen dit). Niet wegfilteren. */
    if (!list || !count || gssi == 0)
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
 * SDR#-compatibele parser voor "Group identity location accept" (TID=0x5).
 *
 * De SDR# code (Class18) leest dit als een reeks records met een 2-bit selector:
 *   sel=0: 24-bit GSSI
 *   sel=1: 24-bit GSSI + 24-bit extra (wordt overgeslagen)
 *   sel=2: 24-bit vGSSI
 *   sel=3: stop/padding
 *
 * Dit matcht jouw debug-vondst waarbij de GSSI octet-aligned in de payload zit
 * (bijv. ... 64 67 E8 ...).
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
            if (p + 24u > bitlen)
                break;
            uint32_t gssi = get_bits(bits, bitlen, p, 24);
            p += 24;

            /* sel==1 heeft nog 24 bits extra; SDR# leest ze maar gebruikt ze niet voor de GSSI */
            if (sel == 1) {
                if (p + 24u > bitlen)
                    break;
                p += 24;
            }

            if (gssi != 0) {
                add_gssi_to_list(gssi, out_gssi_list, out_gssi_count, out_gssi_max);
                if (out_gssi && out_have_gssi && idx == 0) {
                    *out_gssi = gssi;
                    *out_have_gssi = 1;
                }
                idx++;
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
                                    uint8_t *out_itsi_attach, uint8_t *out_have_itsi_attach)
{
    unsigned int pos = start_bit;

    while (pos + 16u <= bitlen) {
        uint32_t mbit = get_bits(bits, bitlen, pos, 1);
        if (mbit == 0)
            break; /* geen elementen meer */

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

        /* tid 0x5: Group identity location accept (SDR# record-structuur) */
        if (tid == 0x5) {
            uint32_t dummy_vgssi = 0;
            uint8_t have_dummy_vgssi = 0;
            mm_parse_group_identity_location_accept(bits + content_offset, (unsigned int)li,
                                                    out_gssi_list, out_gssi_count, out_gssi_max,
                                                    out_gssi, out_have_gssi,
                                                    &dummy_vgssi, &have_dummy_vgssi);
        }
        /* tid 0x7: legacy single GSSI (24 bits) */
        else if (tid == 0x7 && li >= 24) {
            uint32_t val = get_bits(bits, bitlen, content_offset, 24);
            add_gssi_to_list(val, out_gssi_list, out_gssi_count, out_gssi_max);
            if (out_gssi && out_have_gssi) {
                *out_gssi = val;
                *out_have_gssi = 1;
            }
        }
        /* tid 0x6: CCK identifier (vaak laatste 8 bits van element) */
        else if (tid == 0x6 && li >= 8 && out_cck_id && out_have_cck) {
            *out_cck_id = (uint8_t)get_bits(bits, bitlen, content_offset + (unsigned int)li - 8, 8);
            *out_have_cck = 1;
        }
        /* tid 0x2: flags (roaming / itsi attach etc; netwerk-specifiek, maar vaak LSB’s) */
        else if (tid == 0x2) {
            if (li >= 1 && out_roam_lu && out_have_roam_lu) {
                *out_roam_lu = (uint8_t)get_bits(bits, bitlen, content_offset + (unsigned int)li - 1, 1);
                *out_have_roam_lu = 1;
            }
            if (li >= 2 && out_itsi_attach && out_have_itsi_attach) {
                *out_itsi_attach = (uint8_t)get_bits(bits, bitlen, content_offset + (unsigned int)li - 2, 1);
                *out_have_itsi_attach = 1;
            }
        }

        pos += elem_len;
    }
}

/*
 * Zoek in de bitstream naar een plausibele Type-3/4 element header:
 *   M(1)=1, TID(4), LI(11) met LI > 0 en pos+16+LI <= nbits.
 * En liefst TID in een set die we echt gebruiken (0x5 GSSI list, 0x6 CCK, 0x2 flags, 0x7 single GSSI).
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
        if (li == 0)
            continue;

        /* sanity: li niet absurd groot */
        if (li > 512)
            continue;

        if (pos + 16u + (unsigned int)li <= nbits)
            return (int)pos;
    }

    return -1;
}

/* ---------- Logging helpers ---------- */

static void log_loc_upd_accept_like_sdrsharp(uint32_t issi, int la,
                                             const uint32_t *gssi_list, uint8_t gssi_count,
                                             uint8_t have_cck, uint8_t cck_id,
                                             uint8_t have_roam, uint8_t roam_lu)
{
    char gbuf[128];
    gbuf[0] = 0;

    if (gssi_list && gssi_count > 0) {
        size_t o = 0;
        for (uint8_t i = 0; i < gssi_count; i++) {
            char tmp[32];
            if (gssi_list[i] == 0xFFFFFFu)
                snprintf(tmp, sizeof(tmp), "%sOPEN(0xFFFFFF)", (i ? ", " : ""));
            else
                snprintf(tmp, sizeof(tmp), "%s%u", (i ? ", " : ""), (unsigned)gssi_list[i]);

            size_t tl = strlen(tmp);
            if (o + tl + 1 < sizeof(gbuf)) {
                memcpy(gbuf + o, tmp, tl);
                o += tl;
                gbuf[o] = 0;
            }
        }
    }

    char tail[256];
    tail[0] = 0;

    if (have_cck) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), " - CCK_identifier: %u", (unsigned)cck_id);
        strncat(tail, tmp, sizeof(tail) - strlen(tail) - 1);
    }
    if (have_roam && roam_lu) {
        strncat(tail, " - Roaming location updating", sizeof(tail) - strlen(tail) - 1);
    }

    if (gssi_count > 0) {
        mm_logf_ctx(issi, (uint16_t)la,
                    "MS request for registration ACCEPTED for SSI: %u GSSI: %s%s",
                    (unsigned)issi, gbuf, tail);
    } else {
        mm_logf_ctx(issi, (uint16_t)la,
                    "MS request for registration ACCEPTED for SSI: %u%s",
                    (unsigned)issi, tail);
    }
}

/* ---------- MAIN ENTRY ---------- */

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len < 1)
        return (int)len;

    uint32_t issi = tms ? (uint32_t)tms->ssi : 0;
    int la = (tms && tms->tcs) ? (int)tms->tcs->la : -1;
    int mm_debug_done = 0;

    /* Detecteer packed vs unpacked */
    int is_packed = 0;
    for (unsigned int i = 0; i < len; i++) {
        if (buf[i] > 1) { is_packed = 1; break; }
    }

    /* Maak bitstream */
    static uint8_t bits[4096];
    unsigned int nbits = 0;

    if (is_packed) {
        /* Packed: bytes -> bits (MSB first) */
        if (len * 8 > sizeof(bits))
            len = (unsigned int)(sizeof(bits) / 8);

        for (unsigned int i = 0; i < len; i++) {
            uint8_t b = buf[i];
            for (int k = 7; k >= 0; k--)
                bits[nbits++] = (b >> k) & 1u;
        }
    } else {
        /* Unpacked: 1 byte = 1 bit */
        if (len > sizeof(bits))
            len = (unsigned int)sizeof(bits);
        for (unsigned int i = 0; i < len; i++)
            bits[nbits++] = buf[i] & 1u;
    }

    if (nbits < 8)
        return (int)len;

    /*
     * Oude aanpak ("scan en pak de eerste match") gaf false positives: we konden een random
     * bitpatroon als MM-type herkennen, meteen loggen en returnen, waardoor de échte MM PDU
     * (met GSSI/roaming/etc) gemist werd.
     *
     * Daarom scoren we nu alle candidates en kiezen de beste match.
     */
    unsigned int best_off = 0, best_toff = 0;
    uint8_t best_type = 0;
    int best_score = 0;

    for (unsigned int off = 0; off + 12u <= nbits; off++) {
        uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
        if (pdisc != TMLE_PDISC_MM)
            continue;

#if MM_DEBUG_BITS
        if (!mm_debug_done) {
            mm_debug_dump_mm_ctx(issi, (uint16_t)la, bits, nbits, off);
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
                /* Validate by checking we can find at least one sane Type-3/4 element after rules_0 */
                unsigned int payload_start = toff + 4;
                mm_field_store tmp = {0};
                unsigned int after_hdr = mm_rules_decode(bits, nbits, payload_start,
                                                        mm_rules_loc_upd_accept, mm_rules_loc_upd_accept_count,
                                                        &tmp);
                int t34 = -1;
                if (after_hdr + 16u <= nbits) {
                    uint32_t mbit = get_bits(bits, nbits, after_hdr, 1);
                    uint32_t tid  = get_bits(bits, nbits, after_hdr + 1, 4);
                    uint32_t li   = get_bits(bits, nbits, after_hdr + 5, 11);
                    if (mbit == 1 && li > 0 && li <= 512 &&
                        (tid == 0x5 || tid == 0x6 || tid == 0x2 || tid == 0x7) &&
                        after_hdr + 16u + (unsigned int)li <= nbits) {
                        t34 = (int)after_hdr;
                    }
                }
                if (t34 < 0)
                    t34 = find_first_type34(bits, nbits, after_hdr);
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

    (void)best_off; /* reserved for future heuristics / diagnostics */

    if (best_score > 0) {
        unsigned int toff = best_toff;
        uint8_t type = best_type;

        if (type == TMM_PDU_T_D_AUTH) {
            if (toff + 6 <= nbits) {
                uint8_t st = (uint8_t)get_bits(bits, nbits, toff + 4, 2);
                if (st == 0)
                    mm_logf_ctx(issi, (uint16_t)la, "BS demands authentication: SSI: %u", (unsigned)issi);
                else if (st == 2)
                    mm_logf_ctx(issi, (uint16_t)la,
                                "BS result to MS authentication: Authentication successful or no authentication currently in progress SSI: %u - Authentication successful or no authentication currently in progress",
                                (unsigned)issi);
                else
                    mm_logf_ctx(issi, (uint16_t)la, "BS auth message (subtype %u): SSI: %u", (unsigned)st, (unsigned)issi);
                return (int)len;
            }
        }

        if (type == TMM_PDU_T_D_LOC_UPD_CMD) {
            unsigned int payload_start = toff + 4;
            mm_field_store fs = {0};
            (void)mm_rules_decode(bits, nbits, payload_start,
                                  mm_rules_loc_upd_command, mm_rules_loc_upd_command_count,
                                  &fs);
            mm_logf_ctx(issi, (uint16_t)la, "SwMI sent LOCATION UPDATE COMMAND for SSI: %u", (unsigned)issi);
            return (int)len;
        }

        if (type == TMM_PDU_T_D_ATT_DET_GRP) {
            unsigned int payload_start = toff + 4;
            mm_field_store fs = {0};
            (void)mm_rules_decode(bits, nbits, payload_start,
                                  mm_rules_att_det_grp, mm_rules_att_det_grp_count,
                                  &fs);
            mm_logf_ctx(issi, (uint16_t)la, "SwMI sent ATTACH/DETACH GROUP IDENTITY for SSI: %u", (unsigned)issi);
            return (int)len;
        }

        if (type == TMM_PDU_T_D_ATT_DET_GRP_ACK) {
            unsigned int payload_start = toff + 4;
            mm_field_store fs = {0};
            (void)mm_rules_decode(bits, nbits, payload_start,
                                  mm_rules_att_det_grp_ack, mm_rules_att_det_grp_ack_count,
                                  &fs);
            mm_logf_ctx(issi, (uint16_t)la, "SwMI sent ATTACH/DETACH GROUP IDENTITY ACK for SSI: %u", (unsigned)issi);
            return (int)len;
        }

        if (type == TMM_PDU_T_D_LOC_UPD_PROC) {
            unsigned int payload_start = toff + 4;
            mm_field_store fs = {0};
            (void)mm_rules_decode(bits, nbits, payload_start,
                                  mm_rules_loc_upd_proceeding, mm_rules_loc_upd_proceeding_count,
                                  &fs);
            mm_logf_ctx(issi, (uint16_t)la, "SwMI sent LOCATION UPDATE PROCEEDING for SSI: %u", (unsigned)issi);
            return (int)len;
        }

        if (type == TMM_PDU_T_D_LOC_UPD_REJ) {
            unsigned int payload_start = toff + 4;
            mm_field_store fs = {0};
            (void)mm_rules_decode(bits, nbits, payload_start,
                                  mm_rules_loc_upd_reject, mm_rules_loc_upd_reject_count,
                                  &fs);
            mm_logf_ctx(issi, (uint16_t)la, "SwMI sent LOCATION UPDATE REJECT for SSI: %u (cause=%u)",
                        (unsigned)issi,
                        (unsigned)(fs.present[GN_Reject_cause] ? fs.value[GN_Reject_cause] : 0));
            return (int)len;
        }

        if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
            unsigned int payload_start = toff + 4; /* directly after PDU-type */
            mm_field_store fs = {0};

            unsigned int after_hdr = mm_rules_decode(bits, nbits, payload_start,
                                                    mm_rules_loc_upd_accept, mm_rules_loc_upd_accept_count,
                                                    &fs);

            int t34 = -1;
            if (after_hdr + 16u <= nbits) {
                uint32_t mbit = get_bits(bits, nbits, after_hdr, 1);
                uint32_t tid  = get_bits(bits, nbits, after_hdr + 1, 4);
                uint32_t li   = get_bits(bits, nbits, after_hdr + 5, 11);
                if (mbit == 1 && li > 0 && li <= 512 &&
                    (tid == 0x5 || tid == 0x6 || tid == 0x2 || tid == 0x7) &&
                    after_hdr + 16u + (unsigned int)li <= nbits) {
                    t34 = (int)after_hdr;
                }
            }
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
            uint32_t gssi = 0;
            uint8_t have_gssi = 0;

            if (t34 >= 0) {
                mm_scan_type34_elements(bits, nbits, (unsigned int)t34,
                                        &gssi, &have_gssi,
                                        gssi_list, &gssi_count, 8,
                                        &cck_id, &have_cck,
                                        &roam, &have_roam,
                                        &itsi_attach, &have_itsi_attach);
            }

            uint32_t ssi_out = issi;
            if (fs.present[GN_MM_SSI]) ssi_out = fs.value[GN_MM_SSI];

            if (gssi_count > 0) {
                char gbuf[128]; gbuf[0] = 0;
                size_t o = 0;
                for (uint8_t i = 0; i < gssi_count; i++) {
                    char tmp[32];
                    snprintf(tmp, sizeof(tmp), "%s%u", (i ? ", " : ""), (unsigned)gssi_list[i]);
                    size_t tl = strlen(tmp);
                    if (o + tl + 1 < sizeof(gbuf)) { memcpy(gbuf + o, tmp, tl); o += tl; gbuf[o] = 0; }
                }
                if (have_cck) {
                    if (have_roam && roam) {
                        mm_logf_ctx(issi, (uint16_t)la,
                                    "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %s - CCK_identifier: %u - Roaming location updating",
                                    (unsigned)ssi_out, gbuf, (unsigned)cck_id);
                    } else {
                        mm_logf_ctx(issi, (uint16_t)la,
                                    "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %s - CCK_identifier: %u",
                                    (unsigned)ssi_out, gbuf, (unsigned)cck_id);
                    }
                } else {
                    mm_logf_ctx(issi, (uint16_t)la,
                                "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %s",
                                (unsigned)ssi_out, gbuf);
                }
            } else {
                if (have_cck) {
                    if (have_roam && roam) {
                        mm_logf_ctx(issi, (uint16_t)la,
                                    "MS request for registration/authentication ACCEPTED for SSI: %u - CCK_identifier: %u - Roaming location updating",
                                    (unsigned)ssi_out, (unsigned)cck_id);
                    } else {
                        mm_logf_ctx(issi, (uint16_t)la,
                                    "MS request for registration/authentication ACCEPTED for SSI: %u - CCK_identifier: %u",
                                    (unsigned)ssi_out, (unsigned)cck_id);
                    }
                } else {
                    mm_logf_ctx(issi, (uint16_t)la,
                                "MS request for registration/authentication ACCEPTED for SSI: %u",
                                (unsigned)ssi_out);
                }
            }
            return (int)len;
        }
    }

    return (int)len;
}
