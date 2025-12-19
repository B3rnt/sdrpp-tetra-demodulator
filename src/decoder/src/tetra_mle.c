#include <stdint.h>
#include <stdio.h>
#include <string.h>

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
    
    /* Internal metrics for scoring */
    uint8_t  valid_structure; 
    unsigned int bits_consumed;
};

static void t34_result_init(struct t34_result *r)
{
    if (!r) return;
    memset(r, 0, sizeof(*r));
}

static void add_gssi(uint32_t gssi, struct t34_result *out)
{
    if (gssi == 0 || out->gssi_count >= 8) return;
    for(int i=0; i<out->gssi_count; i++) if(out->gssi_list[i] == gssi) return;
    out->gssi_list[out->gssi_count++] = gssi;
}

/* Parse TID 5 (Group identity location accept) */
static void parse_tid5(const uint8_t *bits, unsigned int bitlen, unsigned int offset, unsigned int len, struct t34_result *out)
{
    unsigned int p = 0;
    while (p + 3 <= len) {
        // 1. Mode (1 bit)
        p += 1; 

        // 2. Type (2 bits)
        uint8_t type = (uint8_t)get_bits(bits, bitlen, offset + p, 2);
        p += 2;

        if (type == 3) break; // Stop

        if (type == 0) { // GSSI (24)
            if (p + 24 > len) break;
            add_gssi(get_bits(bits, bitlen, offset + p, 24), out);
            p += 24;
        } else if (type == 1) { // GSSI(24) + Ext(24)
            if (p + 48 > len) break;
            add_gssi(get_bits(bits, bitlen, offset + p, 24), out);
            p += 24;
            add_gssi(get_bits(bits, bitlen, offset + p, 24), out);
            p += 24;
        } else if (type == 2) { // Visitor GSSI (24)
            if (p + 24 > len) break;
            add_gssi(get_bits(bits, bitlen, offset + p, 24), out);
            p += 24;
        }
    }
}

static int t34_try_parse(const uint8_t *bits, unsigned int nbits, unsigned int start_pos, struct t34_result *out)
{
    t34_result_init(out);
    unsigned int pos = start_pos;

    if (pos + 16 > nbits) return 0;
    if (get_bits(bits, nbits, pos, 1) != 1) return 0; // First M-bit must be 1

    while (pos + 16 <= nbits) {
        uint32_t m_bit = get_bits(bits, nbits, pos, 1);
        pos += 1;

        if (m_bit == 0) {
            out->valid_structure = 1;
            out->bits_consumed = pos - start_pos;
            return 1;
        }

        uint32_t tid = get_bits(bits, nbits, pos, 4);
        pos += 4;
        uint32_t li = get_bits(bits, nbits, pos, 11);
        pos += 11;

        if (li > 2048 || pos + li > nbits) return 0;

        unsigned int val_start = pos;

        if (tid == 0x5) {
            parse_tid5(bits, nbits, val_start, li, out);
        } else if (tid == 0x6 && li >= 8) {
            out->cck = (uint8_t)get_bits(bits, nbits, val_start, 8);
            out->have_cck = 1;
        } else if (tid == 0x2) {
            unsigned int lp = 0;
            if (li > lp) { out->roam = (uint8_t)get_bits(bits, nbits, val_start+lp++, 1); out->have_roam = 1; }
            if (li > lp) { out->itsi = (uint8_t)get_bits(bits, nbits, val_start+lp++, 1); out->have_itsi = 1; }
            if (li > lp) { out->srv_rest = (uint8_t)get_bits(bits, nbits, val_start+lp++, 1); out->have_srv_rest = 1; }
        } else if (tid != 0x7) {
            // Unknown TID, skip
        } else if (tid == 0x7 && li >= 24) {
             add_gssi(get_bits(bits, nbits, val_start, 24), out);
        }

        pos += li;
    }
    
    return 0;
}

/* ===================== LOGGING ===================== */

static void mm_log_result(uint32_t issi, uint16_t la, const struct t34_result *r)
{
    char tail[512];
    tail[0] = 0;

    if (g_last_auth_ok && g_last_auth_issi == issi) {
        strncat(tail, " - Authentication successful or no authentication currently in progress", 500);
        g_last_auth_ok = 0;
    }

    if (r->have_cck) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), " - CCK_identifier: %u", r->cck);
        strncat(tail, tmp, 500 - strlen(tail));
    }

    if (r->have_itsi && r->itsi) {
        strncat(tail, " - ITSI attach", 500);
    } else if (r->have_roam && r->roam) {
        if (r->have_srv_rest && r->srv_rest) 
            strncat(tail, " - Service restoration roaming location updating", 500);
        else 
            strncat(tail, " - Roaming location updating", 500);
    }

    if (r->gssi_count > 0) {
        mm_logf_ctx(issi, la, "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %u%s",
                    issi, r->gssi_list[0], tail);
    } else {
        mm_logf_ctx(issi, la, "MS request for registration/authentication ACCEPTED for SSI: %u%s",
                    issi, tail);
    }
}

/* ===================== DECODER ===================== */

static int try_decode_mm_from_bits(struct tetra_mac_state *tms,
                                   const uint8_t *bits, unsigned int nbits,
                                   uint32_t issi, uint16_t la)
{
    (void)tms;
    if (!bits || nbits < 32) return 0;

    unsigned int scan_limit = (nbits < 64) ? nbits : 64;

    for (unsigned int off = 0; off + 16 <= scan_limit; off++) {
        uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
        if (pdisc != TMLE_PDISC_MM) continue;

        unsigned int type_offs[] = { off + 4, off + 3 };
        
        for (int i = 0; i < 2; i++) {
            unsigned int toff = type_offs[i];
            if (toff + 4 > nbits) continue;
            
            uint8_t type = (uint8_t)get_bits(bits, nbits, toff, 4);

            if (type == TMM_PDU_T_D_AUTH) {
                if (toff + 6 <= nbits) {
                    uint8_t st = (uint8_t)get_bits(bits, nbits, toff + 4, 2);
                    if (st == 0) mm_logf_ctx(issi, la, "BS demands authentication: SSI: %u", issi);
                    else if (st == 2) {
                        mm_logf_ctx(issi, la, "BS result to MS authentication: Authentication successful or no authentication currently in progress SSI: %u - Authentication successful or no authentication currently in progress", issi);
                        g_last_auth_issi = issi;
                        g_last_auth_ok = 1;
                    }
                    return 1;
                }
            }
            else if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
                unsigned int scan_start = toff + 16;
                unsigned int scan_end = (nbits > 128) ? 128 : nbits;
                if (scan_start >= scan_end) continue;

                struct t34_result best_r;
                t34_result_init(&best_r);
                int best_score = -1;

                for (unsigned int p = scan_start; p < scan_end; p++) {
                    struct t34_result r;
                    if (t34_try_parse(bits, nbits, p, &r)) {
                        int score = 0;
                        if (r.have_cck) score += 50;
                        if (r.gssi_count > 0) score += 30;
                        if (r.have_roam || r.have_itsi) score += 20;
                        if (r.have_cck && r.cck == 63) score += 10;
                        if (r.bits_consumed > 500) score = -1;

                        if (score > best_score) {
                            best_score = score;
                            best_r = r;
                        }
                    }
                }

                if (best_score > 0) {
                    mm_log_result(issi, la, &best_r);
                    return 1;
                } else {
                    struct t34_result empty; t34_result_init(&empty);
                    mm_log_result(issi, la, &empty);
                    return 1;
                }
            }
            else if (type == TMM_PDU_T_D_LOC_UPD_CMD) {
                 mm_logf_ctx(issi, la, "SwMI sent LOCATION UPDATE COMMAND for SSI: %u", issi);
                 return 1;
            }
            else if (type == TMM_PDU_T_D_LOC_UPD_REJ) {
                 mm_logf_ctx(issi, la, "SwMI sent LOCATION UPDATE REJECT for SSI: %u", issi);
                 return 1;
            }
        }
    }
    return 0;
}

/* ---------- ENTRY ---------- */

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len < 1) return (int)len;

    uint32_t issi = tms ? (uint32_t)tms->ssi : 0;
    int la_i = (tms && tms->tcs) ? (int)tms->tcs->la : -1;
    uint16_t la = (uint16_t)la_i;

    static uint8_t bits_packed[4096];

    /* Packed MSB-first bitstream (correct for TETRA) */
    unsigned int max_p_bytes = len;
    if (max_p_bytes * 8 > 4096) max_p_bytes = 4096 / 8;
    unsigned int nbits_p = 0;
    for (unsigned int i = 0; i < max_p_bytes; i++) {
        uint8_t b = buf[i];
        for (int k = 7; k >= 0; k--)
            bits_packed[nbits_p++] = (b >> k) & 1u;
    }

    try_decode_mm_from_bits(tms, bits_packed, nbits_p, issi, la);

    return (int)len;
}
