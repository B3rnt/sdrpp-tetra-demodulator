// (generated) tetra_mle.c - SDRTetra-compatible MM decode for LLC-bypass
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
 * Kernproblemen die jouw logs laten zien:
 *  - Type-3/4 “TLV” headers hebben een M-bit (1 bit) dat in de praktijk 0 óf 1 kan zijn.
 *    In eerdere versies werd M==0 als “einde” gezien -> je mist daarna CCK/flags/GSSI.
 *  - De start van de Type-3/4 set is niet altijd exact na de vaste header; je moet resync’en:
 *    scan bit-voor-bit tot je een plausibele (M,TID,LI) header vindt, en parse dan sequentieel.
 *  - Omdat de LLC-bypass chain vrijwel altijd *unpacked bits* (1 byte = 1 bit) geeft,
 *    mag je geen packed fallback doen tenzij er écht bytes > 1 aanwezig zijn (anders false positives).
 *
 * Dit bestand doet daarom:
 *  - Detecteert inputvorm: unpacked-bits (0/1) vs packed (bytes).
 *  - Lockt op PDISC/MM in de eerste ~32 bits, en probeert type offsets (+3/+4/+5/+6).
 *  - Voor LOC_UPD_ACC: resync-scan vanaf payload_start om Type-3/4 elementen te vinden,
 *    zonder M-bit te gebruiken als terminator.
 *  - Decodeert uit Type-3/4: GSSI (TID=0x5/0x7), CCK_id (TID=0x6), flags (TID=0x2).
 *  - Log output blijft SDRTetra-stijl.
 */

/* ===================== compile-time debug ===================== */
/* Enable with:  -DMM_DEBUG_BITS=1 */
#ifndef MM_DEBUG_BITS
#define MM_DEBUG_BITS 1
#endif

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

static void mm_log_tlv_hdr(uint32_t issi, uint16_t la, unsigned int pos, unsigned int m, unsigned int tid, unsigned int li)
{
    mm_logf_ctx(issi, la, "MM TLV header at bit%u: M=%u TID=0x%X LI=%u", pos, m, tid, li);
}
#endif

/* ---------- SDRTetra-ish auth state (to append on LOC_UPD_ACC line) ---------- */

static uint32_t g_last_auth_issi = 0;
static uint8_t  g_last_auth_ok = 0; /* subtype=2 */

/* ---------- GSSI helpers ---------- */

static void add_gssi_to_list(uint32_t gssi, uint32_t *list, uint8_t *count, uint8_t max)
{
    if (!list || !count || gssi == 0)
        return;

    /* coarse plausibility: keep OPEN + typical 24-bit groups seen in SDRTetra logs */
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
                                                    uint32_t *out_gssi, uint8_t *out_have_gssi)
{
    if (!bits || bitlen < 2)
        return;

    unsigned int p = 0;
    uint8_t first_written = 0;

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
                p += 24; /* skip extra 24 bits */
            }

            if (gssi != 0) {
                uint8_t before = *out_gssi_count;
                add_gssi_to_list(gssi, out_gssi_list, out_gssi_count, out_gssi_max);
                if (!first_written && *out_gssi_count > before) {
                    if (out_gssi && out_have_gssi) {
                        *out_gssi = gssi;
                        *out_have_gssi = 1;
                    }
                    first_written = 1;
                }
            }
        } else if (sel == 2) {
            /* vGSSI present but not used in logs; skip */
            if (p + 24u > bitlen) break;
            p += 24;
        }
    }
}

/*
 * Resync-scan for Type-3/4 elements:
 *  - Start at `start_bit`.
 *  - Slide bit-by-bit until a plausible header is found.
 *  - Once found: parse sequentially (advance by 16+LI), collecting fields.
 *
 * Crucial: M-bit may be 0 or 1; it is NOT an end-marker.
 */
static void mm_parse_type34_resync(const uint8_t *bits, unsigned int nbits,
                                  unsigned int start_bit, unsigned int scan_window_bits,
                                  uint32_t *gssi_list, uint8_t *gssi_count, uint8_t gssi_max,
                                  uint8_t *cck_id, uint8_t *have_cck,
                                  uint8_t *roam_lu, uint8_t *have_roam,
                                  uint8_t *itsi_attach, uint8_t *have_itsi,
                                  uint8_t *srv_rest, uint8_t *have_srv,
                                  uint32_t *single_gssi, uint8_t *have_single_gssi,
                                  uint32_t issi, uint16_t la)
{
    if (!bits || nbits < 16 || start_bit >= nbits)
        return;

    unsigned int end = start_bit + scan_window_bits;
    if (end > nbits) end = nbits;

    /* 1) find first plausible TLV header */
    int found = 0;
    unsigned int pos = start_bit;

    for (; pos + 16u <= end; pos++) {
        uint32_t m  = get_bits(bits, nbits, pos, 1);
        uint32_t tid = get_bits(bits, nbits, pos + 1, 4);
        uint32_t li  = get_bits(bits, nbits, pos + 5, 11);

        if (li == 0 || li > 1024) continue;
        if (pos + 16u + (unsigned int)li > nbits) continue;

        /* Soft filter: only accept if it looks like something we care about OR it is followed by another plausible header */
        if (tid == 0x2 || tid == 0x5 || tid == 0x6 || tid == 0x7) {
            found = 1;
#if MM_DEBUG_BITS
            mm_log_tlv_hdr(issi, la, pos, (unsigned)m, (unsigned)tid, (unsigned)li);
#endif
            break;
        }
        /* if unknown tid, keep scanning */
    }

    if (!found)
        return;

    /* 2) parse sequentially from first TLV header */
    unsigned int safety = 0;
    while (pos + 16u <= nbits && safety++ < 64) {
        uint32_t m  = get_bits(bits, nbits, pos, 1);
        uint32_t tid = get_bits(bits, nbits, pos + 1, 4);
        uint32_t li  = get_bits(bits, nbits, pos + 5, 11);

        if (li == 0 || li > 2048) break;
        unsigned int elem_len = 16u + (unsigned int)li;
        if (pos + elem_len > nbits) break;

#if MM_DEBUG_BITS
        mm_log_tlv_hdr(issi, la, pos, (unsigned)m, (unsigned)tid, (unsigned)li);
#endif

        unsigned int content = pos + 16u;

        if (tid == 0x5) {
            /* Group identity location accept */
            mm_parse_group_identity_location_accept(bits + content, (unsigned int)li,
                                                    gssi_list, gssi_count, gssi_max,
                                                    single_gssi, have_single_gssi);
        } else if (tid == 0x7 && li >= 24) {
            /* Legacy single GSSI somewhere in element: scan for plausible 24-bit value */
            for (unsigned int off = 0; off + 24u <= li; off++) {
                uint32_t v = get_bits(bits, nbits, content + off, 24);
                uint8_t before = *gssi_count;
                add_gssi_to_list(v, gssi_list, gssi_count, gssi_max);
                if (*gssi_count > before) {
                    if (single_gssi && have_single_gssi) {
                        *single_gssi = v;
                        *have_single_gssi = 1;
                    }
                    break;
                }
            }
        } else if (tid == 0x6 && li >= 8) {
            /* CCK id is typically the last 8 bits of this element in practice */
            if (cck_id && have_cck) {
                *cck_id = (uint8_t)get_bits(bits, nbits, content + (unsigned int)li - 8u, 8u);
                *have_cck = 1;
            }
        } else if (tid == 0x2) {
            /* Flags: best-effort interpret LSBs */
            if (li >= 1 && roam_lu && have_roam) {
                *roam_lu = (uint8_t)get_bits(bits, nbits, content + (unsigned int)li - 1u, 1u);
                *have_roam = 1;
            }
            if (li >= 2 && itsi_attach && have_itsi) {
                *itsi_attach = (uint8_t)get_bits(bits, nbits, content + (unsigned int)li - 2u, 1u);
                *have_itsi = 1;
            }
            if (li >= 3 && srv_rest && have_srv) {
                *srv_rest = (uint8_t)get_bits(bits, nbits, content + (unsigned int)li - 3u, 1u);
                *have_srv = 1;
            }
        }

        pos += elem_len;

        /* Optional: allow a small gap / padding and resync if next header looks invalid */
        if (pos + 16u <= nbits) {
            uint32_t li2 = get_bits(bits, nbits, pos + 5, 11);
            if (li2 == 0 || li2 > 2048 || pos + 16u + (unsigned int)li2 > nbits) {
                /* resync within next 32 bits */
                unsigned int res_end = pos + 32u;
                if (res_end > nbits) res_end = nbits;
                int re_found = 0;
                for (unsigned int p2 = pos; p2 + 16u <= res_end; p2++) {
                    uint32_t tid2 = get_bits(bits, nbits, p2 + 1, 4);
                    uint32_t li3  = get_bits(bits, nbits, p2 + 5, 11);
                    if (li3 == 0 || li3 > 1024) continue;
                    if (p2 + 16u + (unsigned int)li3 > nbits) continue;
                    if (tid2 == 0x2 || tid2 == 0x5 || tid2 == 0x6 || tid2 == 0x7) {
                        pos = p2;
                        re_found = 1;
                        break;
                    }
                }
                if (!re_found) break;
            }
        }
    }
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

    /* SDRTetra output: roaming message OR ITSI attach; keep same order as SDRTetra logs */
    if (have_roam && roam_lu) {
        if (have_srv_rest && srv_rest)
            strncat(tail, " - Service restoration roaming location updating",
                    sizeof(tail) - strlen(tail) - 1);
        else
            strncat(tail, " - Roaming location updating",
                    sizeof(tail) - strlen(tail) - 1);
    }
    if (have_itsi_attach && itsi_attach) {
        strncat(tail, " - ITSI attach", sizeof(tail) - strlen(tail) - 1);
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
    mm_bit_dump_ctx(issi, la, "MM input bits", bits, nbits, 0, (nbits > 96 ? 96 : nbits));
#endif

    const uint8_t expected_cck = (tms && tms->tcs) ? (uint8_t)tms->tcs->cck_id : 0xFF;

    /* Search only near the beginning (SDRTetra-like), to avoid random matches in long bitstreams */
    unsigned int search_limit = (nbits > 48u) ? 48u : nbits;

    unsigned int best_off = 0, best_toff = 0;
    uint8_t best_type = 0;
    int best_score = 0;

    for (unsigned int off = 0; off + 12u <= search_limit; off++) {
        uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
        if (pdisc != TMLE_PDISC_MM)
            continue;

        /* try common alignments */
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
                    score = (st == 0 || st == 2) ? 95 : 60;
                }
            } else if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
                /* Score based on whether we can extract a sane CCK and/or GSSI */
                unsigned int payload_start = toff + 4;

                uint32_t gssi_list[4]; uint8_t gssi_count = 0;
                uint8_t cck = 0, have_cck = 0;
                uint8_t roam = 0, have_roam = 0;
                uint8_t itsi = 0, have_itsi = 0;
                uint8_t srv = 0, have_srv = 0;
                uint32_t single_gssi = 0; uint8_t have_single_gssi = 0;

                memset(gssi_list, 0, sizeof(gssi_list));

                mm_parse_type34_resync(bits, nbits, payload_start, 512u,
                                       gssi_list, &gssi_count, 4,
                                       &cck, &have_cck,
                                       &roam, &have_roam,
                                       &itsi, &have_itsi,
                                       &srv, &have_srv,
                                       &single_gssi, &have_single_gssi,
                                       issi, la);

                score = 70;
                if (have_cck) score += 20;
                if (gssi_count > 0 || have_single_gssi) score += 20;
                if (have_roam && roam) score += 5;

                if (expected_cck != 0xFF && have_cck) {
                    if (cck == expected_cck) score += 15;
                    else score -= 15;
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

        /* decode fixed header fields (keeps your text/log behavior stable) */
        mm_field_store fs = {0};
        (void)mm_rules_decode(bits, nbits, payload_start,
                              mm_rules_loc_upd_accept, mm_rules_loc_upd_accept_count,
                              &fs);

        uint32_t gssi_list[8];
        uint8_t gssi_count = 0;
        memset(gssi_list, 0, sizeof(gssi_list));

        uint8_t cck_id = 0, have_cck = 0;
        uint8_t roam = 0, have_roam = 0;
        uint8_t itsi_attach = 0, have_itsi = 0;
        uint8_t srv_rest = 0, have_srv = 0;
        uint32_t single_gssi = 0; uint8_t have_single_gssi = 0;

        /* Resync parse of Type-3/4 elements */
        mm_parse_type34_resync(bits, nbits, payload_start, 1024u,
                               gssi_list, &gssi_count, 8,
                               &cck_id, &have_cck,
                               &roam, &have_roam,
                               &itsi_attach, &have_itsi,
                               &srv_rest, &have_srv,
                               &single_gssi, &have_single_gssi,
                               issi, la);

        /* If we only got a single GSSI, promote it into list */
        if (have_single_gssi && gssi_count == 0) {
            add_gssi_to_list(single_gssi, gssi_list, &gssi_count, 8);
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
                                          have_srv, srv_rest,
                                          have_itsi, itsi_attach,
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

    /* Detect if buffer is unpacked bits (common in this pipeline) */
    int unpacked = 1;
    for (unsigned int i = 0; i < len; i++) {
        if (buf[i] > 1) { unpacked = 0; break; }
    }

    static uint8_t bits[4096];
    unsigned int nbits = 0;

    if (unpacked) {
        /* Here len is already "number of bits" carried as bytes. */
        unsigned int max = (len > sizeof(bits)) ? (unsigned int)sizeof(bits) : len;
        for (unsigned int i = 0; i < max; i++)
            bits[nbits++] = buf[i] & 1u;

        (void)try_decode_mm_from_bits(tms, bits, nbits, issi, la);
        return (int)len;
    }

    /* Packed fallback: bytes -> bits MSB first */
    unsigned int max_bytes = len;
    if (max_bytes * 8 > sizeof(bits))
        max_bytes = (unsigned int)(sizeof(bits) / 8);

    for (unsigned int i = 0; i < max_bytes; i++) {
        uint8_t b = buf[i];
        for (int k = 7; k >= 0; k--)
            bits[nbits++] = (b >> k) & 1u;
    }

    (void)try_decode_mm_from_bits(tms, bits, nbits, issi, la);
    return (int)len;
}
