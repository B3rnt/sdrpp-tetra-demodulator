#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
#include "tetra_cmce_pdu.h"
#include "tetra_sndcp_pdu.h"
#include "crypto/tetra_crypto.h"

/* ---------- Helpers ---------- */

/* Debug functie: Dump bits als hex string in de log */
static void log_debug_bits(uint32_t issi, const uint8_t *bits, unsigned int len_bits, const char *msg) {
    char hexbuf[256] = {0};
    unsigned int bytes = (len_bits + 7) / 8;
    if (bytes > 64) bytes = 64; // Cap op 64 bytes voor log leesbaarheid

    for (unsigned int i = 0; i < bytes; i++) {
        uint8_t val = 0;
        for (int k = 0; k < 8; k++) {
            if ((i * 8 + k) < len_bits) {
                if (bits[i * 8 + k]) val |= (1 << (7 - k));
            }
        }
        char tmp[4];
        snprintf(tmp, sizeof(tmp), "%02X", val);
        strncat(hexbuf, tmp, sizeof(hexbuf) - strlen(hexbuf) - 1);
    }
    mm_logf_ctx(issi, 0, "[DEBUG] %s: %s (len=%u bits)", msg, hexbuf, len_bits);
}

static uint32_t get_bits(const uint8_t *bits, unsigned int len, unsigned int pos, unsigned int n) {
    if (pos + n > len) return 0;
    return bits_to_uint(bits + pos, n);
}

static int issi_is_real(uint32_t issi) {
    issi &= 0xFFFFFFu;
    return (issi != 0 && issi != 0xFFFFFFu);
}

static void add_gssi_to_list(uint32_t gssi, uint32_t *list, uint8_t *count, uint8_t max) {
    if (!list || !count) return;
    if (gssi == 0 || gssi == 0xFFFFFFu) return;
    for (uint8_t i = 0; i < *count; i++) { if (list[i] == gssi) return; }
    if (*count < max) list[(*count)++] = gssi;
}

/* Parse de interne lijst van Group Identity (Type 3, ID 0x5) */
static void mm_parse_group_list_content(const uint8_t *bits, unsigned int bitlen, unsigned int offset,
                                        uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                        uint32_t *out_gssi, uint8_t *out_have_gssi) 
{
    unsigned int p = offset;
    
    /* 1. Accept/Reject (1) */
    if (p + 1 > bitlen) return; 
    p++;
    
    /* 2. Reserved (1) */
    if (p + 1 > bitlen) return; 
    p++;
    
    /* 3. Count (3) */
    if (p + 3 > bitlen) return;
    uint8_t count = (uint8_t)get_bits(bits, bitlen, p, 3);
    p += 3;

    for (uint8_t i = 0; i < count; i++) {
        if (p + 3 > bitlen) break;
        p++; // Unexchangeable
        p++; // Visitor
        uint8_t gtype = (uint8_t)get_bits(bits, bitlen, p, 1);
        p++;

        uint32_t val = 0;
        if (gtype == 0) { // Normal
            if (p + 24 > bitlen) break;
            val = get_bits(bits, bitlen, p, 24);
            p += 24;
        } else { // Extended
            if (p + 48 > bitlen) break;
            val = get_bits(bits, bitlen, p, 24); // GSSI part
            p += 48; // Skip GSSI + MCC + MNC
        }

        if (p + 4 > bitlen) break;
        p++; // Attach
        p += 3; // Class of usage

        if (val != 0) {
            add_gssi_to_list(val, out_gssi_list, out_gssi_count, out_gssi_max);
            if (out_gssi && out_have_gssi) { *out_gssi = val; *out_have_gssi = 1; }
        }
    }
}

/* Universele Scanner voor Type 3/4 elementen */
static void mm_scan_type34_elements(const uint8_t *bits, unsigned int bitlen, unsigned int start_bit,
                                   uint32_t *out_gssi, uint8_t *out_have_gssi,
                                   uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                   uint8_t *out_cck_id, uint8_t *out_have_cck,
                                   uint8_t *out_roam_lu, uint8_t *out_have_roam_lu)
{
    unsigned int pos = start_bit;
    int iterations = 0;

    /* Veiligheidslimiet: max 50 elementen om loop te voorkomen */
    while (pos + 16 <= bitlen && iterations++ < 50) {
        uint32_t mbit = bits_to_uint(bits + pos, 1);
        if (mbit != 1) break; // Geen optionele elementen meer

        uint32_t tid = bits_to_uint(bits + pos + 1, 4);
        uint32_t li  = bits_to_uint(bits + pos + 5, 11);

        if (li == 0) { pos += 16; continue; } // Leeg element?
        if (pos + 16 + li > bitlen) break;    // Truncated

        /* Parse Specifieke IDs */
        if (tid == 0x5) { // Group Identity
            mm_parse_group_list_content(bits, bitlen, pos + 16, 
                                        out_gssi_list, out_gssi_count, out_gssi_max,
                                        out_gssi, out_have_gssi);
        }
        else if (tid == 0x6 && out_cck_id) { // CCK
            if (li >= 8) {
                *out_cck_id = (uint8_t)get_bits(bits, bitlen, pos + 16 + li - 8, 8);
                *out_have_cck = 1;
            }
        }
        else if (tid == 0x2 && out_roam_lu) { // Flags (SCCH info etc)
            if (li >= 1) {
                *out_roam_lu = (uint8_t)get_bits(bits, bitlen, pos + 16 + li - 1, 1);
                *out_have_roam_lu = 1;
            }
        }

        pos += 16 + li;
    }
}

/* BRUTE FORCE SCANNER: Negeert headers, zoekt bit-voor-bit naar patronen */
static int mm_scan_best_effort(const uint8_t *bits, unsigned int bitlen,
                               uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                               uint8_t *out_cck_id, uint8_t *out_have_cck)
{
    /* We zoeken naar het patroon:
       M-bit (1) + TID (0101 voor Group of 0110 voor CCK)
       Binair: 10101 (0x15) of 10110 (0x16)
    */
    int found_something = 0;

    for (unsigned int p = 0; p < bitlen - 20; p++) {
        uint8_t signature = (uint8_t)get_bits(bits, bitlen, p, 5);
        
        /* Check Group Identity (TID 5) -> Patroon 1 0101 */
        if (signature == 0x15) {
            uint32_t li = get_bits(bits, bitlen, p + 5, 11);
            if (li > 5 && li < 256 && (p + 16 + li <= bitlen)) {
                // Lijkt geldig, probeer te parsen
                uint8_t old_cnt = *out_gssi_count;
                mm_parse_group_list_content(bits, bitlen, p + 16, 
                                            out_gssi_list, out_gssi_count, out_gssi_max,
                                            NULL, NULL);
                if (*out_gssi_count > old_cnt) found_something = 1;
            }
        }

        /* Check CCK (TID 6) -> Patroon 1 0110 */
        if (signature == 0x16) {
            uint32_t li = get_bits(bits, bitlen, p + 5, 11);
            if (li >= 8 && li < 128 && (p + 16 + li <= bitlen)) {
                *out_cck_id = (uint8_t)get_bits(bits, bitlen, p + 16 + li - 8, 8);
                *out_have_cck = 1;
                found_something = 1;
            }
        }
    }
    return found_something;
}

/* Main Parsing Logic voor D-LOCATION UPDATE ACCEPT */
static int mm_find_and_log_loc_upd_acc(uint32_t issi, uint16_t la,
                                      const uint8_t *mm_bits, unsigned int mm_len_bits)
{
    if (!mm_bits || mm_len_bits < 12) return 0;
    
    unsigned int pos = 0;
    uint8_t pdu_type = (uint8_t)get_bits(mm_bits, mm_len_bits, pos, 4);
    pos += 4;

    if (pdu_type != 0x5) return 0; // Niet D-LOC-UPD-ACC

    // Debug raw data om te zien wat er mis gaat
    log_debug_bits(issi, mm_bits, mm_len_bits, "D-LOC-UPD-ACC Raw");

    /* Standaard Header Parsing */
    pos += 3; // LocUpdType
    
    uint8_t ssi_present = (uint8_t)get_bits(mm_bits, mm_len_bits, pos, 1);
    pos += 1;
    
    if (ssi_present) pos += 24; // SSI
    
    pos += 2; // Validity
    pos += 1; // Reserved
    
    uint8_t o_bit = (uint8_t)get_bits(mm_bits, mm_len_bits, pos, 1);
    pos += 1;

    /* Variabelen voor resultaten */
    uint32_t gssi_list[8] = {0};
    uint8_t  gssi_count = 0;
    uint32_t single_gssi = 0;
    uint8_t  have_single_gssi = 0;
    uint8_t  cck_id = 0;
    uint8_t  have_cck = 0;
    uint8_t  roam_lu = 0;
    uint8_t  have_roam_lu = 0;

    int scan_success = 0;

    /* POGING 1: Standaard via de O-bit en berekende offset */
    if (o_bit) {
        mm_scan_type34_elements(mm_bits, mm_len_bits, pos,
                                &single_gssi, &have_single_gssi,
                                gssi_list, &gssi_count, 8,
                                &cck_id, &have_cck,
                                &roam_lu, &have_roam_lu);
        if (gssi_count > 0 || have_cck) scan_success = 1;
    }

    /* POGING 2: Als O-bit 0 was, of parsing faalde -> BRUTE FORCE SCAN */
    if (!scan_success) {
        // mm_logf_ctx(issi, la, "[DEBUG] Standard scan failed (O-bit=%d, SSI_Pres=%d). Trying Best-Effort...", o_bit, ssi_present);
        mm_scan_best_effort(mm_bits, mm_len_bits, 
                           gssi_list, &gssi_count, 8,
                           &cck_id, &have_cck);
    }

    /* Output Genereren */
    char tail[256] = {0};
    if (have_cck) {
        char tmp[64]; snprintf(tmp, sizeof(tmp), " - CCK:%u", cck_id);
        strncat(tail, tmp, sizeof(tail) - strlen(tail) - 1);
    }
    if (have_roam_lu && roam_lu) strncat(tail, " - Roaming", 64);

    char gbuf[128] = {0};
    if (gssi_count > 0) {
        size_t o2 = 0;
        for (uint8_t i = 0; i < gssi_count; i++) {
            char tmp[24]; snprintf(tmp, sizeof(tmp), "%s%u", (i ? "," : ""), gssi_list[i]);
            size_t tl = strlen(tmp);
            if (o2 + tl + 1 >= sizeof(gbuf)) break;
            memcpy(gbuf + o2, tmp, tl);
            o2 += tl; gbuf[o2] = 0;
        }
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u GSSI(s):%s%s", issi, gbuf, tail);
    } 
    else if (have_single_gssi) {
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u GSSI:%u%s", issi, single_gssi, tail);
    }
    else {
        /* Als we nog steeds niets hebben, loggen we gewoon clean */
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u%s", issi, tail);
    }

    return 1;
}

static void mm_try_pretty_log(uint32_t issi, uint16_t la, const uint8_t *mm_bits, unsigned int mm_len_bits)
{
    if (!mm_bits || mm_len_bits < 4) return;

    uint8_t pdu_type = (uint8_t)get_bits(mm_bits, mm_len_bits, 0, 4);

    if (pdu_type == 0x5) {
        mm_find_and_log_loc_upd_acc(issi, la, mm_bits, mm_len_bits);
        return;
    }
    
    if (pdu_type == 0x1) { // D-AUTH
        uint8_t st = (uint8_t)get_bits(mm_bits, mm_len_bits, 4, 2);
        if (st == 0) mm_logf_ctx(issi, la, "BS demands authentication: SSI: %u", issi);
        else if (st == 2) mm_logf_ctx(issi, la, "BS result to MS authentication (Result) SSI: %u", issi);
        return;
    }
}

/* ---------- Main Entry ---------- */

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len < 1) return (int)len;

    uint32_t issi = 0;
    if (tms) issi = (uint32_t)tms->ssi;

    int la = -1;
    if (tms && tms->tcs) la = tms->tcs->la;

    if (!issi_is_real(issi)) return (int)len;

    /* Detect unpacked vs packed bits */
    int unpacked = 1;
    for (unsigned int i = 0; i < len; i++) { if (buf[i] > 1) { unpacked = 0; break; } }

    if (unpacked) {
        /* Unpacked path: 1 byte = 1 bit */
        /* Zoek naar PDISC MM (001) */
        unsigned int best_off = 0;
        int found = 0;

        for (unsigned int off = 0; off < 8 && off + 3 <= len; off++) {
            uint8_t pdisc = (buf[off] << 2) | (buf[off+1] << 1) | buf[off+2];
            if (pdisc == TMLE_PDISC_MM) { best_off = off; found = 1; break; }
        }

        if (found) {
            /* Skip PDISC (3 bits) -> Start MM PDU */
            unsigned int start = best_off + 3;
            if (len > start) {
                /* Converteer unpacked buf naar packed voor debugging/helpers als nodig,
                   maar onze helpers werken nu op unpacked arrays? Nee, get_bits verwacht unpacked 
                   alleen als we dat zo configureren.
                   Mijn get_bits hierboven werkt op PACKED bytes (standaard). 
                   Als 'buf' unpacked is, moeten we het packen voor de helpers! */
                   
                uint8_t packed_bits[512];
                memset(packed_bits, 0, sizeof(packed_bits));
                unsigned int bit_len = len - start;
                if (bit_len > 4096) bit_len = 4096; // safety

                /* Packen: bit 0 in byte is MSB (0x80) */
                for(unsigned int i=0; i<bit_len; i++) {
                    if (buf[start+i] & 1) packed_bits[i/8] |= (1 << (7 - (i%8)));
                }
                
                mm_try_pretty_log(issi, la, packed_bits, bit_len);
            }
        }
        return (int)len;
    }

    /* Packed path (Standaard TETRA frames) */
    const uint8_t *oct = buf;
    
    /* MLE PDISC check (eerste 3 bits van byte 0) */
    /* Byte 0: [PDISC(3)][MM-TYPE-HIGH(5?)] -> Nee, TETRA bits zijn MSB aligned */
    uint8_t pdisc = (oct[0] >> 5) & 0x07; // Bits 7,6,5
    
    /* Als dat niet klopt, check nibble swap (soms gebeurt dat in SDRs) */
    if (pdisc != TMLE_PDISC_MM) {
        // Probeer lower nibble?
        // uint8_t alt = oct[0] & 0x07; ... riskant.
        // Laten we aannemen dat PDISC MM is als we hier zijn, of 'best effort'
        if ((oct[0] & 0x07) == TMLE_PDISC_MM) {
            // Nibble swapped case? Niet ondersteund in deze cleanup.
        }
    }

    /* Unpack alles naar een bitstream array (1 bit per byte) om makkelijk te debuggen? 
       Nee, mijn get_bits hierboven werkt op PACKED bytes. Dus we sturen 'oct' door,
       maar we moeten 3 bits offsetten. */
    
    /* Oplossing: Maak een nieuwe buffer die begint bij bit 3 (na PDISC) */
    /* Dit is makkelijk: shift alles 3 bits naar links */
    
    uint8_t mm_frame[512];
    unsigned int total_bits = len * 8;
    if (total_bits > sizeof(mm_frame)*8) total_bits = sizeof(mm_frame)*8;
    
    memset(mm_frame, 0, sizeof(mm_frame));
    
    // Shift bits: Bit 3 van oct[0] wordt Bit 0 van mm_frame[0]
    for (unsigned int i = 3; i < total_bits; i++) {
        unsigned int byte_idx = i / 8;
        unsigned int bit_idx  = 7 - (i % 8);
        int bit = (oct[byte_idx] >> bit_idx) & 1;
        
        unsigned int target_i = i - 3;
        if (bit) mm_frame[target_i/8] |= (1 << (7 - (target_i%8)));
    }

    mm_try_pretty_log(issi, la, mm_frame, total_bits - 3);

    return (int)len;
}
