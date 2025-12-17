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

/* ===================== MM DEBUG ===================== */

#ifndef MM_DEBUG_BITS
#define MM_DEBUG_BITS 0
#endif

#if MM_DEBUG_BITS
static void mm_log_debug(const char *msg) {
    // Implementeer indien nodig, of gebruik printf
    // printf("[DEBUG] %s\n", msg);
}
#endif

/* ---------- STATE ---------- */

static uint32_t g_last_auth_issi = 0;
static uint8_t  g_last_auth_ok = 0;

/* ---------- OUTPUT STRUCTURE ---------- */

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

/* ---------- 1:1 LOGIC VAN CLASS18.CS ---------- */

/*
 * TID 5 Parsing (Group identity location accept)
 * Gebaseerd op Class18.cs method_1 (loop logic):
 * 1. Lees Mode (1 bit) - Case 25U
 * 2. Lees Type (2 bits) - Case 32U
 * 3. Lees GSSI (24 bits) - Case 93U/etc
 */
static void parse_tid5_group_identity(const uint8_t *bits, unsigned int nbits, unsigned int offset, unsigned int len, struct t34_result *out)
{
    unsigned int p = 0;
    
    // Zolang er bits over zijn in dit element voor Mode(1) + Type(2)
    while (p + 3 <= len) {
        
        // 1. Group identity attachment mode (1 bit) - Class18 Case 25U
        // uint8_t mode = get_bits(bits, nbits, offset + p, 1);
        p += 1;

        // 2. Group identity type (2 bits) - Class18 Case 32U
        uint8_t type = (uint8_t)get_bits(bits, nbits, offset + p, 2);
        p += 2;

        if (type == 3) {
            // Stop / Reserved
            break;
        }

        if (type == 0) {
            // GSSI (24 bits)
            if (p + 24 > len) break;
            uint32_t gssi = get_bits(bits, nbits, offset + p, 24);
            add_gssi_to_list(gssi, out);
            p += 24;
        } 
        else if (type == 1) {
            // GSSI (24) + Extension (24)
            if (p + 48 > len) break;
            uint32_t gssi = get_bits(bits, nbits, offset + p, 24);
            add_gssi_to_list(gssi, out);
            p += 24;
            
            uint32_t ext = get_bits(bits, nbits, offset + p, 24);
            add_gssi_to_list(ext, out);
            p += 24;
        } 
        else if (type == 2) {
            // Visitor GSSI (24)
            if (p + 24 > len) break;
            uint32_t vgssi = get_bits(bits, nbits, offset + p, 24);
            add_gssi_to_list(vgssi, out);
            p += 24;
        }
    }
}

/*
 * TLV Chain Parser
 * Start direct na de O-bit van de header.
 * Verwerkt Type 3/4 elementen (M-bit, Type, Length, Value).
 */
static void parse_tlv_chain(const uint8_t *bits, unsigned int nbits, unsigned int *pos_ptr, struct t34_result *out)
{
    unsigned int pos = *pos_ptr;
    
    // De loop stopt als M-bit 0 is of bits op zijn
    while (pos + 16 <= nbits) { // Minimaal M(1)+Type(4)+Len(11) nodig
        
        // M-bit (More bit)
        uint32_t m_bit = get_bits(bits, nbits, pos, 1);
        pos += 1;

        if (m_bit == 0) {
            break; // Einde keten
        }

        // Type (4 bits)
        uint32_t tid = get_bits(bits, nbits, pos, 4);
        pos += 4;

        // Length (11 bits)
        uint32_t li = get_bits(bits, nbits, pos, 11);
        pos += 11;

        if (li > 2048 || pos + li > nbits) {
            // Sanity check fail, stop
            break;
        }

        unsigned int val_start = pos;

        // Verwerk specifieke TIDs zoals Class18.cs
        if (tid == 0x5) { 
            // Group identity location accept
            parse_tid5_group_identity(bits, nbits, val_start, li, out);
        }
        else if (tid == 0x6) { 
            // CCK identifier
            if (li >= 8) {
                out->cck = (uint8_t)get_bits(bits, nbits, val_start + li - 8u, 8u); // Laatste 8 bits?
                // Class18 Case 65U: gewoon lezen. 
                // Meestal is LI=8 voor CCK. We lezen gewoon de eerste 8 als LI=8.
                // SDRSharp leest vaak 'bits' uit de stream. 
                // Laten we aannemen dat CCK aan het begin of einde staat.
                // In D-Location Update Accept is CCK vaak 8 bits.
                out->cck = (uint8_t)get_bits(bits, nbits, val_start, 8);
                out->have_cck = 1;
            }
        }
        else if (tid == 0x2) { 
            // Info (Roaming / ITSI attach)
            // Structuur is vaak: Length geeft aan hoeveel bits.
            // Als LI=1: Roam. LI=2: Roam+ITSI?
            // Class18 leest bits sequentieel.
            // We lezen ze op volgorde.
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
 * HEADER PARSER (RULES 0)
 * Dit is de sleutel tot succes. We moeten exact de juiste bits overslaan
 * op basis van de "Presence bits" om bij de start van de TLV's te komen.
 * * Rules_0 uit Class18.cs:
 * 1. Type (3)
 * 2. Options (1)
 * 3. P-bit -> SSI (24)
 * 4. P-bit -> Addr Ext (24)
 * 5. P-bit -> Sub Class (16)
 * 6. P-bit -> Energy (14)
 * 7. P-bit -> Reserved (6)
 */
static int parse_loc_upd_acc_header_and_tlvs(const uint8_t *bits, unsigned int nbits, unsigned int start_off, struct t34_result *out)
{
    unsigned int p = start_off;

    // 1. Location update accept type (3 bits)
    if (p + 3 > nbits) return 0;
    p += 3;

    // 2. Options bit (1 bit)
    if (p + 1 > nbits) return 0;
    p += 1;

    // 3. Presence: SSI (24 bits)
    if (p + 1 > nbits) return 0;
    uint8_t p_ssi = (uint8_t)get_bits(bits, nbits, p, 1);
    p += 1;
    if (p_ssi) {
        if (p + 24 > nbits) return 0;
        p += 24; 
    }

    // 4. Presence: Address extension (24 bits)
    if (p + 1 > nbits) return 0;
    uint8_t p_ext = (uint8_t)get_bits(bits, nbits, p, 1);
    p += 1;
    if (p_ext) {
        if (p + 24 > nbits) return 0;
        p += 24;
    }

    // 5. Presence: Subscriber class (16 bits)
    if (p + 1 > nbits) return 0;
    uint8_t p_class = (uint8_t)get_bits(bits, nbits, p, 1);
    p += 1;
    if (p_class) {
        if (p + 16 > nbits) return 0;
        p += 16;
    }

    // 6. Presence: Energy saving (14 bits)
    if (p + 1 > nbits) return 0;
    uint8_t p_energy = (uint8_t)get_bits(bits, nbits, p, 1);
    p += 1;
    if (p_energy) {
        if (p + 14 > nbits) return 0;
        p += 14;
    }

    // 7. Presence: Reserved (6 bits) - Volgens Class18.cs rules_0
    if (p + 1 > nbits) return 0;
    uint8_t p_res = (uint8_t)get_bits(bits, nbits, p, 1);
    p += 1;
    if (p_res) {
        if (p + 6 > nbits) return 0;
        p += 6;
    }

    // Nu zijn we bij de "Optional elements" (O-bit)
    if (p + 1 > nbits) return 0;
    uint8_t o_bit = (uint8_t)get_bits(bits, nbits, p, 1);
    p += 1;

    if (o_bit) {
        parse_tlv_chain(bits, nbits, &p, out);
    }

    return 1; // Succes
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
        if (r->have_itsi && r->itsi) strncat(tail, " - ITSI attach", 500 - strlen(tail));
        else if (r->have_roam && r->roam) {
            if (r->have_srv_rest && r->srv_rest) strncat(tail, " - Service restoration roaming location updating", 500 - strlen(tail));
            else strncat(tail, " - Roaming location updating", 500 - strlen(tail));
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

    // We scannen alleen in het begin, PDU start is meestal direct na MAC header
    unsigned int limit = (nbits < 64) ? nbits : 64;

    for (unsigned int off = 0; off + 16u <= limit; off++) {
        uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
        if (pdisc != TMLE_PDISC_MM) continue;

        unsigned int type_offsets[4] = { off + 4, off + 3, off + 5, off + 6 };
        
        for (unsigned int vi = 0; vi < 4; vi++) {
            unsigned int toff = type_offsets[vi];
            if (toff + 4 > nbits) continue;

            uint8_t type = (uint8_t)get_bits(bits, nbits, toff, 4);

            if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
                struct t34_result r;
                t34_result_init(&r);
                
                // Parse EXACT volgens Class18 rules_0 header definitie
                // Payload start direct na Type (toff + 4)
                if (parse_loc_upd_acc_header_and_tlvs(bits, nbits, toff + 4, &r)) {
                    
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
                if (toff + 6 <= nbits) {
                    uint8_t st = (uint8_t)get_bits(bits, nbits, toff + 4, 2);
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
            // Voeg hier eventueel andere types toe (CMD, REJ, etc)
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

    /* 1) Unpacked bits (byte & 1) */
    unsigned int nbits_u = 0;
    unsigned int max_u = (len > sizeof(bits_unpacked)) ? sizeof(bits_unpacked) : len;
    for (unsigned int i = 0; i < max_u; i++) bits_unpacked[nbits_u++] = buf[i] & 1u;

    if (try_decode_mm_from_bits(tms, bits_unpacked, nbits_u, issi, la)) return (int)len;

    /* 2) Packed bits (MSB first) */
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
