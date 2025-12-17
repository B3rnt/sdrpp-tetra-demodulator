#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* * Zorg dat deze headers beschikbaar zijn in je project, 
 * of vervang ze door je eigen definities als ze ontbreken.
 */
#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
#include "mm_sdr_rules.h"
#include "crypto/tetra_crypto.h"

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

/* ===================== MM DEBUG (optional) ===================== */

#ifndef MM_DEBUG_BITS
#define MM_DEBUG_BITS 0
#endif

#if MM_DEBUG_BITS
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
#endif

/* ---------- SDRTetra-ish auth state (to append on LOC_UPD_ACC line) ---------- */

static uint32_t g_last_auth_issi = 0;
static uint8_t  g_last_auth_ok = 0; /* subtype=2 */

/* ---------- GSSI helpers ---------- */

static void add_gssi_to_list(uint32_t gssi, uint32_t *list, uint8_t *count, uint8_t max)
{
    if (!list || !count || max == 0)
        return;
    if (gssi == 0)
        return;

    for (uint8_t i = 0; i < *count; i++) {
        if (list[i] == gssi)
            return;
    }
    if (*count < max)
        list[(*count)++] = gssi;
}

/* ---------- Type-3/4 element parsing (MATCHING CLASS18.CS) ---------- */

/*
 * Group identity location accept (TID=0x5)
 * Logic derived strictly from Class18.cs (Case 32U):
 * It reads 2 bits for Type directly. It does NOT skip a Mode bit in this loop.
 * * 2 bits: Group identity type
 * 00: GSSI (24 bits)
 * 01: GSSI (24 bits) + Extension (24 bits)
 * 10: Visitor GSSI (24 bits)
 * 11: Reserved / Stop
 */
static void mm_parse_group_identity_location_accept(const uint8_t *bits, unsigned int bitlen,
                                                    uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                                    uint32_t *out_gssi0, uint8_t *out_have_gssi0)
{
    if (!bits || bitlen < 2)
        return;

    unsigned int p = 0;
    
    // We need at least 2 bits for Type to start
    while (p + 2u <= bitlen) {
        
        // --- Read 2 bits Type ---
        // Class18.cs: int num20 = Class34.smethod_3(..., 2);
        uint8_t type = (uint8_t)get_bits(bits, bitlen, p, 2);
        p += 2;

        if (type == 3) {
            // Reserved / Stop condition
            break; 
        }

        if (type == 0) {
            // --- Type 0: Single GSSI (24 bits) ---
            if (p + 24u > bitlen) break;
            uint32_t gssi = get_bits(bits, bitlen, p, 24);
            p += 24;

            if (gssi) {
                add_gssi_to_list(gssi, out_gssi_list, out_gssi_count, out_gssi_max);
                if (out_gssi0 && out_have_gssi0 && !*out_have_gssi0) {
                    *out_gssi0 = gssi;
                    *out_have_gssi0 = 1;
                }
            }
        } 
        else if (type == 1) {
            // --- Type 1: GSSI (24 bits) + Extension (24 bits) ---
            if (p + 48u > bitlen) break;
            
            // First 24 bits: GSSI
            uint32_t gssi = get_bits(bits, bitlen, p, 24);
            p += 24;
            
            if (gssi) {
                add_gssi_to_list(gssi, out_gssi_list, out_gssi_count, out_gssi_max);
                if (out_gssi0 && out_have_gssi0 && !*out_have_gssi0) {
                    *out_gssi0 = gssi;
                    *out_have_gssi0 = 1;
                }
            }

            // Second 24 bits: Extension (or secondary GSSI)
            uint32_t ext_gssi = get_bits(bits, bitlen, p, 24);
            p += 24;
            
            if (ext_gssi) {
                add_gssi_to_list(ext_gssi, out_gssi_list, out_gssi_count, out_gssi_max);
            }
        } 
        else if (type == 2) {
            // --- Type 2: Visitor GSSI (24 bits) ---
            if (p + 24u > bitlen) break;
            
            uint32_t vgssi = get_bits(bits, bitlen, p, 24);
            p += 24;

            if (vgssi) {
                add_gssi_to_list(vgssi, out_gssi_list, out_gssi_count, out_gssi_max);
            }
        }
    }
}

/* ---------- TLV chain search/parsing (SDRTetra-like) ---------- */

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

    uint8_t  valid_end;      /* chain ended on M=0 */
    unsigned int end_pos;    /* bit position where M=0 was observed */
};

static void t34_result_init(struct t34_result *r)
{
    if (!r) return;
    memset(r, 0, sizeof(*r));
}

static int t34_parse_chain(const uint8_t *bits, unsigned int nbits, unsigned int start_pos,
                           unsigned int max_bits_from_start, struct t34_result *out)
{
    if (!bits || !out) return 0;
    t34_result_init(out);

    unsigned int pos = start_pos;
    unsigned int limit = start_pos + max_bits_from_start;
    if (limit > nbits) limit = nbits;

    /* sanity: must have at least one header (1 bit M + 4 bit TID + 11 bit LI = 16 bits) */
    if (pos + 16u > limit) return 0;

    /* first header must have M-bit = 1 to exist */
    if (get_bits(bits, nbits, pos, 1) != 1) return 0;

    while (pos + 16u <= limit) {
        uint32_t mbit = get_bits(bits, nbits, pos, 1);
        if (mbit == 0) {
            out->valid_end = 1;
            out->end_pos = pos;
            return 1;
        }

        uint32_t tid = get_bits(bits, nbits, pos + 1, 4);
        uint32_t li  = get_bits(bits, nbits, pos + 5, 11);
        
        /* Sanity check LI */
        if (li > 2048) return 0;

        unsigned int elem_len = 16u + (unsigned int)li;
        if (pos + elem_len > limit) return 0;

        unsigned int content = pos + 16u;

        if (tid == 0x5) {
            uint32_t g0 = 0;
            uint8_t have_g0 = 0;
            mm_parse_group_identity_location_accept(bits + content, (unsigned int)li,
                                                    out->gssi_list, &out->gssi_count, 8,
                                                    &g0, &have_g0);
        } else if (tid == 0x7 && li >= 24) {
            /* legacy single GSSI (best-effort: first 24 bits) */
            uint32_t g = get_bits(bits, nbits, content, 24);
            add_gssi_to_list(g, out->gssi_list, &out->gssi_count, 8);
        } else if (tid == 0x6 && li >= 8) {
            out->cck = (uint8_t)get_bits(bits, nbits, content + (unsigned int)li - 8u, 8u);
            out->have_cck = 1;
        } else if (tid == 0x2) {
            if (li >= 1) {
                out->roam = (uint8_t)get_bits(bits, nbits, content + (unsigned int)li - 1u, 1u);
                out->have_roam = 1;
            }
            if (li >= 2) {
                out->itsi = (uint8_t)get_bits(bits, nbits, content + (unsigned int)li - 2u, 1u);
                out->have_itsi = 1;
            }
            if (li >= 3) {
                out->srv_rest = (uint8_t)get_bits(bits, nbits, content + (unsigned int)li - 3u, 1u);
                out->have_srv_rest = 1;
            }
        }

        pos += elem_len;
    }

    return 0;
}

static int t34_is_plausible_header(const uint8_t *bits, unsigned int nbits, unsigned int pos)
{
    if (!bits) return 0;
    if (pos + 16u > nbits) return 0;
    if (get_bits(bits, nbits, pos, 1) != 1) return 0;

    uint32_t tid = get_bits(bits, nbits, pos + 1, 4);
    uint32_t li  = get_bits(bits, nbits, pos + 5, 11);
    if (li == 0 || li > 1024) return 0;

    /* SDRTetra gebruikt meer TIDs, maar voor LOC_UPD_ACC zijn dit de relevante */
    if (!(tid == 0x5 || tid == 0x6 || tid == 0x2 || tid == 0x7))
        return 0;

    if (pos + 16u + (unsigned int)li > nbits) return 0;
    return 1;
}

static int find_best_t34_chain(const uint8_t *bits, unsigned int nbits,
                               unsigned int search_from, unsigned int search_window_bits,
                               unsigned int max_chain_bits,
                               struct t34_result *best_out)
{
    if (!bits || !best_out) return -1;

    int best_score = -999999;
    int best_pos = -1;
    struct t34_result best_r;
    t34_result_init(&best_r);

    unsigned int end = search_from + search_window_bits;
    if (end > nbits) end = nbits;

    for (unsigned int pos = search_from; pos + 16u <= end; pos++) {
        if (!t34_is_plausible_header(bits, nbits, pos))
            continue;

        struct t34_result r;
        if (!t34_parse_chain(bits, nbits, pos, max_chain_bits, &r))
            continue;

        /* score: prefer a chain that looks like LOC_UPD_ACC extensions */
        int score = 0;

        /* byte alignment helps a lot in practice (reduces false positives) */
        if ((pos % 8u) == 0) score += 10;

        if (r.valid_end) score += 20;
        if (r.have_cck) score += 35;
        if (r.gssi_count > 0) score += 25;
        if (r.have_roam) score += 5;
        if (r.have_itsi) score += 5;

        /* extra: CCK 63 is extremely common in your logs; give it a strong boost */
        if (r.have_cck && r.cck == 63) score += 25;

        /* penalize clearly bogus chains (no useful fields) */
        if (!r.have_cck && r.gssi_count == 0 && !r.have_roam && !r.have_itsi)
            score -= 50;

        if (score > best_score) {
            best_score = score;
            best_pos = (int)pos;
            best_r = r;
        }
    }

    if (best_pos >= 0) {
        *best_out = best_r;
        return best_pos;
    }
    return -1;
}

/* ---------- Logging ---------- */

static void mm_log_loc_upd_acc_sdrtetra_style(uint32_t issi, uint16_t la,
                                              uint32_t ssi_out,
                                              const struct t34_result *r,
                                              uint8_t append_auth_ok)
{
    char tail[512];
    tail[0] = 0;

    if (append_auth_ok) {
        strncat(tail,
                " - Authentication successful or no authentication currently in progress",
                500);
    }

    if (r && r->have_cck) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), " - CCK_identifier: %u", (unsigned)r->cck);
        strncat(tail, tmp, 500 - strlen(tail));
    }

    if (r) {
        /* SDRTetra: in jouw logs zie je vaak roaming. ITSI attach kan ook voorkomen. */
        if (r->have_itsi && r->itsi) {
            strncat(tail, " - ITSI attach", 500 - strlen(tail));
        } else if (r->have_roam && r->roam) {
            if (r->have_srv_rest && r->srv_rest) {
                strncat(tail, " - Service restoration roaming location updating", 500 - strlen(tail));
            } else {
                strncat(tail, " - Roaming location updating", 500 - strlen(tail));
            }
        }
    }

    if (r && r->gssi_count > 0) {
        mm_logf_ctx(issi, la,
                    "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %u%s",
                    (unsigned)ssi_out, (unsigned)r->gssi_list[0], tail);
    } else {
        mm_logf_ctx(issi, la,
                    "MS request for registration/authentication ACCEPTED for SSI: %u%s",
                    (unsigned)ssi_out, tail);
    }
}

/* ---------- Core decoder: run MM parse on prepared bitstream ---------- */

static int try_decode_mm_from_bits(struct tetra_mac_state *tms,
                                   const uint8_t *bits, unsigned int nbits,
                                   uint32_t issi, uint16_t la)
{
    (void)tms;

    if (!bits || nbits < 16)
        return 0;

    /* SDRTetra-like: MM PDU start is usually very early. We search close to the start first. */
    const unsigned int pass_limits[2] = { 64u, nbits };

    unsigned int best_off = 0, best_toff = 0;
    uint8_t best_type = 0;
    int best_score = 0;

    for (unsigned int pass = 0; pass < 2; pass++) {
        unsigned int limit = pass_limits[pass];
        if (limit > nbits) limit = nbits;

        best_score = 0;
        best_off = best_toff = 0;
        best_type = 0;

        for (unsigned int off = 0; off + 12u <= limit; off++) {
            uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
            if (pdisc != TMLE_PDISC_MM)
                continue;

            /* PDU-type might be at +3 (no spare) or +4 (with spare), and some captures are off by 1 */
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
                    /*
                     * START OFFSET FIX:
                     * Start searching for TLVs well after the header to avoid the ISSI (24 bits)
                     * masquerading as a GSSI or CCK header.
                     * Header(4) + Type(3) + SSI(24) = 31 bits. 
                     * So toff + 32 is a safe starting point to scan for optional elements.
                     */
                    unsigned int payload_start = toff + 32;

                    /* Find best TLV chain soon after payload_start */
                    struct t34_result r;
                    int t34 = find_best_t34_chain(bits, nbits, payload_start, 1024u, 2048u, &r);
                    if (t34 >= 0) {
                        score = 110;
                        if (r.have_cck) score += 20; /* High boost for CCK presence */
                        if (r.gssi_count > 0) score += 10;
                    } else {
                        score = 80;
                    }
                } else if (type == TMM_PDU_T_D_LOC_UPD_REJ) score = 60;
                else if (type == TMM_PDU_T_D_LOC_UPD_PROC) score = 55;
                else if (type == TMM_PDU_T_D_LOC_UPD_CMD) score = 55;
                else if (type == TMM_PDU_T_D_ATT_DET_GRP || type == TMM_PDU_T_D_ATT_DET_GRP_ACK) score = 50;

                if (score > best_score || (score == best_score && score > 0 && toff < best_toff)) {
                    best_score = score;
                    best_off = off;
                    best_toff = toff;
                    best_type = type;
                }
            }
        }

        if (best_score > 0)
            break;
    }

    (void)best_off;

    if (best_score <= 0)
        return 0;

    unsigned int toff = best_toff;
    uint8_t type = best_type;

#if MM_DEBUG_BITS
    mm_bit_dump_ctx(issi, la, "MM chosen header bits", bits, nbits, best_off, 64);
    mm_logf_ctx(issi, la, "MM chosen: off=%u toff=%u type=0x%X", best_off, best_toff, (unsigned)best_type);
#endif

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
        /* * FIX: Start scanning for TLVs after the mandatory fields + ISSI.
         * Header (4) + LocUpdType (3) + ISSI (24) = 31 bits. 
         * Safest start is 32 bits after type offset.
         */
        unsigned int payload_start = toff + 32;

        /* decode fixed header fields (optional, for future); we mainly want TLVs */
        mm_field_store fs = {0};
        (void)mm_rules_decode(bits, nbits, toff + 4,
                              mm_rules_loc_upd_accept, mm_rules_loc_upd_accept_count,
                              &fs);

        struct t34_result r;
        int t34 = find_best_t34_chain(bits, nbits, payload_start, 1024u, 2048u, &r);
        if (t34 < 0) {
            /* fallback: no TLVs found; still log basic line */
            struct t34_result empty;
            t34_result_init(&empty);
            uint8_t append_auth_ok = 0;
            if (g_last_auth_ok && g_last_auth_issi == issi) {
                append_auth_ok = 1;
                g_last_auth_ok = 0;
                g_last_auth_issi = 0;
            }
            mm_log_loc_upd_acc_sdrtetra_style(issi, la, issi, &empty, append_auth_ok);
            return 1;
        }

#if MM_DEBUG_BITS
        mm_logf_ctx(issi, la, "MM LOC_UPD_ACC TLV start @bit%u: gssi_count=%u have_cck=%u cck=%u roam=%u itsi=%u",
                    (unsigned)t34, (unsigned)r.gssi_count, (unsigned)r.have_cck, (unsigned)r.cck,
                    (unsigned)(r.have_roam ? r.roam : 0), (unsigned)(r.have_itsi ? r.itsi : 0));
#endif

        uint8_t append_auth_ok = 0;
        if (g_last_auth_ok && g_last_auth_issi == issi) {
            append_auth_ok = 1;
            g_last_auth_ok = 0;
            g_last_auth_issi = 0;
        }

        mm_log_loc_upd_acc_sdrtetra_style(issi, la, issi, &r, append_auth_ok);
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

    /* SDRTetra compat: eerst altijd unpacked bits (byte & 1), daarna packed fallback */
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
