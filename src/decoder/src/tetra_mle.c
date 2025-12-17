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

/* ---------- DEBUG ---------- */
#ifndef MM_DEBUG_BITS
#define MM_DEBUG_BITS 0
#endif

#if MM_DEBUG_BITS
static void mm_log_debug(uint32_t issi, const char *msg) {
    // printf("[MM DEBUG ISSI=%u] %s\n", issi, msg);
}
#endif

/* ---------- STATE ---------- */

static uint32_t g_last_auth_issi = 0;
static uint8_t  g_last_auth_ok = 0;

/* ---------- RESULT STRUCTURE ---------- */

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
};

static void t34_result_init(struct t34_result *r)
{
    if (!r) return;
    memset(r, 0, sizeof(*r));
}

static void add_gssi_to_list(uint32_t gssi, struct t34_result *out)
{
    if (!out || gssi == 0) return;
    for (uint8_t i = 0; i < out->gssi_count; i++) {
        if (out->gssi_list[i] == gssi) return;
    }
    if (out->gssi_count < 8)
        out->gssi_list[out->gssi_count++] = gssi;
}

/* ---------- PARSING LOGIC ---------- */

/*
 * TID 5: Group identity location accept
 * Structure: Loop [Mode(1) + Type(2) + Value(24/48)]
 */
static void parse_tid5_group_identity(const uint8_t *bits, unsigned int nbits, unsigned int offset, unsigned int len, struct t34_result *out)
{
    unsigned int p = 0;
    
    // We need at least 3 bits (1 Mode + 2 Type)
    while (p + 3 <= len) {
        
        // 1. Attachment Mode (1 bit)
        // We read and skip this bit to stay aligned.
        // uint8_t mode = get_bits(bits, nbits, offset + p, 1);
        p += 1;

        // 2. Group identity type (2 bits)
        uint8_t type = (uint8_t)get_bits(bits, nbits, offset + p, 2);
        p += 2;

        if (type == 3) break; // Stop/Reserved

        if (type == 0) { // GSSI (24)
            if (p + 24 > len) break;
            uint32_t gssi = get_bits(bits, nbits, offset + p, 24);
            add_gssi_to_list(gssi, out);
            p += 24;
        } 
        else if (type == 1) { // GSSI (24) + Ext (24)
            if (p + 48 > len) break;
            uint32_t gssi = get_bits(bits, nbits, offset + p, 24);
            add_gssi_to_list(gssi, out);
            p += 24;
            
            uint32_t ext = get_bits(bits, nbits, offset + p, 24);
            add_gssi_to_list(ext, out); // SDRTetra treats ext as secondary GSSI
            p += 24;
        } 
        else if (type == 2) { // Visitor GSSI (24)
            if (p + 24 > len) break;
            uint32_t vgssi = get_bits(bits, nbits, offset + p, 24);
            add_gssi_to_list(vgssi, out);
            p += 24;
        }
    }
}

/*
 * TLV Chain Parser (Type 3/4)
 * Starts at 'pos' (which should be the first M-bit).
 */
static void parse_tlv_chain(const uint8_t *bits, unsigned int nbits, unsigned int *pos_ptr, struct t34_result *out)
{
    unsigned int pos = *pos_ptr;
    
    while (pos + 16 <= nbits) { // Header overhead: M(1) + Type(4) + Len(11) = 16 bits
        
        // M-bit
        uint32_t m_bit = get_bits(bits, nbits, pos, 1);
        pos += 1;

        if (m_bit == 0) {
            break; // End of chain
        }

        // Type (4 bits)
        uint32_t tid = get_bits(bits, nbits, pos, 4);
        pos += 4;

        // Length (11 bits)
        uint32_t li = get_bits(bits, nbits, pos, 11);
        pos += 11;

        if (li > 2048 || pos + li > nbits) break;

        unsigned int val_start = pos;

        if (tid == 0x5) { 
            // Group identity location accept
            parse_tid5_group_identity(bits, nbits, val_start, li, out);
        }
        else if (tid == 0x6) { 
            // CCK identifier (usually 8 bits, often at the end of the LI block)
            if (li >= 8) {
                // Class18 reads it directly. Usually it's just 8 bits payload.
                out->cck = (uint8_t)get_bits(bits, nbits, val_start, 8);
                out->have_cck = 1;
            }
        }
        else if (tid == 0x2) { 
            // Info (Roaming / ITSI attach)
            unsigned int local_p = 0;
            if (li > local_p) { out->roam = (uint8_t)get_bits(bits, nbits, val_start + local_p++, 1); out->have_roam = 1; }
            if (li > local_p) { out->itsi = (uint8_t)get_bits(bits, nbits, val_start + local_p++, 1); out->have_itsi = 1; }
            if (li > local_p) { out->srv_rest = (uint8_t)get_bits(bits, nbits, val_start + local_p++, 1); out->have_srv_rest = 1; }
        }

        pos += li;
    }
    
    *pos_ptr = pos;
}

/*
 * HEADER PARSER
 * Parses the D-LOCATION UPDATE ACCEPT header exactly according to Class18.cs rules_0.
 * This ensures we land on the exact correct bit for the TLV chain.
 */
static int parse_loc_upd_acc(const uint8_t *bits, unsigned int nbits, unsigned int start_off, struct t34_result *out)
{
    unsigned int p = start_off;

    // 1. Location update accept type (3 bits)
    if (p + 3 > nbits) return 0;
    p += 3;

    // 2. Options bit (1 bit) - Crucial! Determines if TLV follows.
    if (p + 1 > nbits) return 0;
    uint8_t has_tlv = (uint8_t)get_bits(bits, nbits, p, 1);
    p += 1;

    // --- Fixed Optional Fields (Presence Bits) ---
    // Rule 1: SSI (24 bits)
    if (p + 1 > nbits) return 0;
    if (get_bits(bits, nbits, p++, 1)) {
        if (p + 24 > nbits) return 0;
        p += 24; 
    }

    // Rule 2: Address Extension (24 bits)
    if (p + 1 > nbits) return 0;
    if (get_bits(bits, nbits, p++, 1)) {
        if (p + 24 > nbits) return 0;
        p += 24;
    }

    // Rule 3: Subscriber Class (16 bits)
    if (p + 1 > nbits) return 0;
    if (get_bits(bits, nbits, p++, 1)) {
        if (p + 16 > nbits) return 0;
        p += 16;
    }

    // Rule 4: Energy Saving (14 bits)
    if (p + 1 > nbits) return 0;
    if (get_bits(bits, nbits, p++, 1)) {
        if (p + 14 > nbits) return 0;
        p += 14;
    }

    // Rule 5: Reserved (6 bits) - Matches Class18.cs rules_0 last entry
    if (p + 1 > nbits) return 0;
    if (get_bits(bits, nbits, p++, 1)) {
        if (p + 6 > nbits) return 0;
        p += 6;
    }

    // --- End of Header ---
    
    // If Options bit was 1, the Type 3/4 TLV chain starts here.
    if (has_tlv) {
        parse_tlv_chain(bits, nbits, &p, out);
    }

    return 1; // Success
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
        strncat(tail, " - Authentication successful or no authentication currently in progress", 500);
    }

    if (r && r->have_cck) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), " - CCK_identifier: %u", (unsigned)r->cck);
        strncat(tail, tmp, 500 - strlen(tail));
    }

    if (r) {
        if (r->have_itsi && r->itsi) {
            strncat(tail, " - ITSI attach", 500 - strlen(tail));
        } else if (r->have_roam && r->roam) {
            if (r->have_srv_rest && r->srv_rest) 
                strncat(tail, " - Service restoration roaming location updating", 500 - strlen(tail));
            else 
                strncat(tail, " - Roaming location updating", 500 - strlen(tail));
        }
    }

    if (r && r->gssi_count > 0) {
        mm_logf_ctx(issi, la, "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %u%s",
                    (unsigned)ssi_out, (unsigned)r->gssi_list[0], tail);
    } else {
        mm_logf_ctx(issi, la, "MS request for registration/authentication ACCEPTED for SSI: %u%s",
                    (unsigned)ssi_out, tail);
    }
}

/* ---------- Core Decoder ---------- */

static int try_decode_mm_from_bits(struct tetra_mac_state *tms,
                                   const uint8_t *bits, unsigned int nbits,
                                   uint32_t issi, uint16_t la)
{
    (void)tms;
    if (!bits || nbits < 16) return 0;

    // Scan window: start looking near the beginning
    unsigned int limit = (nbits < 64) ? nbits : 64;

    for (unsigned int off = 0; off + 16u <= limit; off++) {
        uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
        if (pdisc != TMLE_PDISC_MM) continue;

        unsigned int type_off = off + 4; // Skip spare bit
        if (type_off + 4 > nbits) continue;
        
        uint8_t type = (uint8_t)get_bits(bits, nbits, type_off, 4);

        if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
            // Payload starts after Type (4 bits)
            unsigned int payload_start = type_off + 4;
            
            struct t34_result r;
            t34_result_init(&r);

            // Parse EXACTLY using Class18 rules to find TLV start
            if (parse_loc_upd_acc(bits, nbits, payload_start, &r)) {
                
                uint8_t append_auth = 0;
                if (g_last_auth_ok && g_last_auth_issi == issi) {
                    append_auth = 1;
                    g_last_auth_ok = 0;
                }
                mm_log_loc_upd_acc_sdrtetra_style(issi, la, issi, &r, append_auth);
                return 1;
            }
        }
        else if (type == TMM_PDU_T_D_AUTH) {
            if (type_off + 6 <= nbits) {
                uint8_t st = (uint8_t)get_bits(bits, nbits, type_off + 4, 2);
                if (st == 0) {
                    mm_logf_ctx(issi, la, "BS demands authentication: SSI: %u", issi);
                    return 1;
                } else if (st == 2) {
                    mm_logf_ctx(issi, la, "BS result to MS authentication: Authentication successful or no authentication currently in progress SSI: %u - Authentication successful or no authentication currently in progress", issi);
                    g_last_auth_issi = issi;
                    g_last_auth_ok = 1;
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* ---------- MAIN ENTRY ---------- */

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len < 1) return (int)len;

    uint32_t issi = tms ? (uint32_t)tms->ssi : 0;
    int la_i = (tms && tms->tcs) ? (int)tms->tcs->la : -1;
    uint16_t la = (uint16_t)la_i;

    static uint8_t bits_unpacked[4096];
    static uint8_t bits_packed[4096];

    /* 1) Unpacked bits */
    unsigned int nbits_u = 0;
    unsigned int max_u = (len > sizeof(bits_unpacked)) ? sizeof(bits_unpacked) : len;
    for (unsigned int i = 0; i < max_u; i++) bits_unpacked[nbits_u++] = buf[i] & 1u;

    if (try_decode_mm_from_bits(tms, bits_unpacked, nbits_u, issi, la)) return (int)len;

    /* 2) Packed bits (fallback) */
    unsigned int max_p_bytes = len;
    if (max_p_bytes * 8 > sizeof(bits_packed)) max_p_bytes = sizeof(bits_packed) / 8;
    unsigned int nbits_p = 0;
    for (unsigned int i = 0; i < max_p_bytes; i++) {
        uint8_t b = buf[i];
        for (int k = 7; k >= 0; k--) bits_packed[nbits_p++] = (b >> k) & 1u;
    }

    (void)try_decode_mm_from_bits(tms, bits_packed, nbits_p, issi, la);
    return (int)len;
}
