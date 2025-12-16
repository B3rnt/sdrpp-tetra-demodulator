#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
#include "crypto/tetra_crypto.h"

/* ---------- DEBUG HELPERS ---------- */

/* Interne veilige bit-reader om externe dependencies uit te sluiten */
static uint32_t get_bits_local(const uint8_t *bits, unsigned int len, unsigned int pos, unsigned int n) {
    if (pos + n > len) return 0;
    uint32_t val = 0;
    for (unsigned int i = 0; i < n; i++) {
        val = (val << 1) | (bits[pos + i] & 1);
    }
    return val;
}

/* Dump de eerste N bits naar de log voor analyse */
static void debug_dump_bits(uint32_t issi, const uint8_t *bits, unsigned int len) {
    char buf[128];
    unsigned int n = (len > 64) ? 64 : len; /* Log eerste 64 bits */
    unsigned int p = 0;
    for (unsigned int i = 0; i < n; i++) {
        p += snprintf(buf + p, sizeof(buf) - p, "%u", bits[i] & 1);
        if (i % 8 == 7) p += snprintf(buf + p, sizeof(buf) - p, " ");
    }
    mm_logf_ctx(issi, 0, "[DEBUG] Bits: %s...", buf);
}

/* ---------- PARSERS ---------- */

static void add_gssi_to_list(uint32_t gssi, uint32_t *list, uint8_t *count, uint8_t max) {
    if (!list || !count || gssi == 0 || gssi == 0xFFFFFFu) return;
    for (uint8_t i = 0; i < *count; i++) if (list[i] == gssi) return;
    if (*count < max) list[(*count)++] = gssi;
}

static void mm_parse_group_list(const uint8_t *bits, unsigned int bitlen,
                                uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                uint32_t *out_gssi, uint8_t *out_have_gssi) 
{
    unsigned int p = 0;
    p += 1; /* Accept/Reject */
    p += 1; /* Reserved */
    
    if (p + 3 > bitlen) return;
    uint8_t count = (uint8_t)get_bits_local(bits, bitlen, p, 3);
    p += 3;

    for (uint8_t i = 0; i < count; i++) {
        if (p + 3 > bitlen) break;
        p += 2; /* Unexchangeable + Visitor */
        
        uint8_t gtype = (uint8_t)get_bits_local(bits, bitlen, p, 1);
        p += 1;

        uint32_t current_gssi = 0;
        if (gtype == 0) { /* Normal GSSI */
            if (p + 24 > bitlen) break;
            current_gssi = get_bits_local(bits, bitlen, p, 24);
            p += 24;
        } else { /* Extended */
            if (p + 48 > bitlen) break;
            current_gssi = get_bits_local(bits, bitlen, p, 24);
            p += 48;
        }
        
        /* Attachment (1) + Class (3) */
        p += 4; 

        if (current_gssi != 0) {
            add_gssi_to_list(current_gssi, out_gssi_list, out_gssi_count, out_gssi_max);
            if (out_gssi && out_have_gssi) { *out_gssi = current_gssi; *out_have_gssi = 1; }
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
        uint32_t mbit = get_bits_local(bits, bitlen, pos, 1);
        if (mbit != 1) break; /* Stop als M-bit 0 is */

        uint32_t tid = get_bits_local(bits, bitlen, pos + 1, 4);
        uint32_t li  = get_bits_local(bits, bitlen, pos + 5, 11);
        
        if (li == 0) { pos += 16; continue; }
        if (pos + 16 + li > bitlen) break;

        const uint8_t *edata = bits; /* We gebruiken absolute posities in get_bits_local */
        unsigned int e_offset = pos + 16;

        /* DEBUG LOG VOOR ELK ELEMENT */
        // mm_logf_ctx(0, 0, "[DEBUG] Element Type=0x%X Len=%u", tid, li);

        if (tid == 0x5) { /* Group identity location accept */
            /* We geven een pointer naar de start van de bits array, maar offset + len */
            /* Omdat get_bits_local absolute positie verwacht, moeten we een sub-slice simuleren
               of de functie aanpassen. Hier passen we de slice aan: */
            /* Quick fix: we geven de hele array mee maar de functie moet de offset erbij optellen.
               Echter, mm_parse_group_list verwacht start op 0. We geven (bits + e_offset) mee. */
            mm_parse_group_list(bits + e_offset, li, out_gssi_list, out_gssi_count, out_gssi_max, out_gssi, out_have_gssi);
        }
        else if (tid == 0x7 && li >= 24) { /* Legacy Group Downlink */
             uint32_t val = get_bits_local(edata, bitlen, e_offset, 24);
             add_gssi_to_list(val, out_gssi_list, out_gssi_count, out_gssi_max);
             if (out_gssi) { *out_gssi = val; *out_have_gssi = 1; }
        }
        else if (tid == 0x6 && li >= 8 && out_cck_id) { /* CCK */
             *out_cck_id = (uint8_t)get_bits_local(edata, bitlen, e_offset + li - 8, 8);
             *out_have_cck = 1;
        }
        else if (tid == 0x2) { /* Flags (Best effort) */
            if (li >= 1 && out_roam_lu) { *out_roam_lu = (uint8_t)get_bits_local(edata, bitlen, e_offset + li - 1, 1); *out_have_roam_lu = 1; }
            if (li >= 2 && out_itsi_attach) { *out_itsi_attach = (uint8_t)get_bits_local(edata, bitlen, e_offset + li - 2, 1); *out_have_itsi_attach = 1; }
        }
        pos += 16 + li;
    }
}

static int mm_find_and_log_loc_upd_acc(uint32_t issi, uint16_t la, const uint8_t *mm_bits, unsigned int mm_len_bits)
{
    unsigned int pos = 0;
    /* PDU Type (4) */
    uint8_t pdu_type = (uint8_t)get_bits_local(mm_bits, mm_len_bits, pos, 4);
    if (pdu_type != 0x5) return 0;
    pos += 4;

    /* Debug dump van header velden */
    debug_dump_bits(issi, mm_bits, mm_len_bits);

    /* Header velden lezen */
    uint8_t loc_type = (uint8_t)get_bits_local(mm_bits, mm_len_bits, pos, 3);
    pos += 3;
    
    uint8_t ssi_pres = (uint8_t)get_bits_local(mm_bits, mm_len_bits, pos, 1);
    pos += 1;

    unsigned int ssi_start_pos = pos;
    if (ssi_pres) pos += 24;

    uint8_t valid = (uint8_t)get_bits_local(mm_bits, mm_len_bits, pos, 2);
    pos += 2;
    
    uint8_t res = (uint8_t)get_bits_local(mm_bits, mm_len_bits, pos, 1);
    pos += 1;
    
    uint8_t o_bit = (uint8_t)get_bits_local(mm_bits, mm_len_bits, pos, 1);
    unsigned int o_bit_pos = pos;
    pos += 1;

    /* PRINT HEADER ANALYSE */
    mm_logf_ctx(issi, la, "[DEBUG] Header: LocT=%u SSIPres=%u Valid=%u Res=%u Obit=%u (Obit@%u)", 
                loc_type, ssi_pres, valid, res, o_bit, o_bit_pos);

    if (!o_bit) {
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u (No Type3/4 elements)", (unsigned)issi);
        return 1;
    }

    /* Parsing Elements */
    uint32_t gssi = 0;
    uint8_t  have_gssi = 0;
    uint32_t gssi_list[8];
    uint8_t  gssi_count = 0;
    uint8_t  cck_id = 0;
    uint8_t  have_cck = 0;
    uint8_t  roam_lu = 0;
    uint8_t  have_roam_lu = 0;
    uint8_t  itsi_attach = 0;
    uint8_t  have_itsi_attach = 0;
    memset(gssi_list, 0, sizeof(gssi_list));

    mm_scan_type34_elements(mm_bits, mm_len_bits, pos,
                            &gssi, &have_gssi, gssi_list, &gssi_count, 8,
                            &cck_id, &have_cck, &roam_lu, &have_roam_lu,
                            &itsi_attach, &have_itsi_attach);

    char tail[256]; tail[0] = 0;
    if (have_cck) { char tmp[64]; snprintf(tmp, sizeof(tmp), " - CCK:%u", cck_id); strncat(tail, tmp, 200); }
    if (have_roam_lu && roam_lu) strncat(tail, " - Roaming", 200);

    char gbuf[128]; gbuf[0] = 0;
    if (gssi_count > 0) {
        size_t o2 = 0;
        for (uint8_t i=0; i<gssi_count; i++) {
            char tmp[24]; snprintf(tmp, sizeof(tmp), "%s%u", (i?",":""), gssi_list[i]);
            size_t tl = strlen(tmp);
            if(o2+tl+1 < sizeof(gbuf)) { memcpy(gbuf+o2, tmp, tl); o2+=tl; gbuf[o2]=0; }
        }
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u GSSI(s):%s%s", (unsigned)issi, gbuf, tail);
    } else {
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u%s", (unsigned)issi, tail);
    }
    return 1;
}

/* ---------- MAIN HOOK ---------- */

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len < 1) return (int)len;

    uint32_t issi = tms ? (uint32_t)tms->ssi : 0;
    int la = (tms && tms->tcs) ? tms->tcs->la : -1;

    /* Converteer ALLES naar bits (MSB first) */
    if (len * 8 > 4096) return (int)len;
    uint8_t mm_bits[4096];
    unsigned int o = 0;
    for (unsigned int bi = 0; bi < len; bi++) {
        uint8_t b = buf[bi];
        for(int k=7; k>=0; k--) mm_bits[o++] = (b >> k) & 1u;
    }
    unsigned int total_bits = o;

    /* PDISC check & Offset bepalen */
    /* TETRA MM PDISC is 3 bits. We proberen te vinden waar de MM PDU (Type 0x5) begint. */
    
    /* OFFSET TEST: We proberen zowel offset 3 (standaard) als offset 4 (nibble aligned) */
    
    /* Test Offset 3 (Standard) */
    if (total_bits > 7) {
        uint8_t type = (uint8_t)get_bits_local(mm_bits, total_bits, 3, 4);
        if (type == 0x5) {
            mm_find_and_log_loc_upd_acc(issi, la, mm_bits + 3, total_bits - 3);
            return (int)len;
        }
    }
    
    /* Test Offset 4 (Nibble Aligned - Mogelijk de oorzaak!) */
    if (total_bits > 8) {
        uint8_t type = (uint8_t)get_bits_local(mm_bits, total_bits, 4, 4);
        if (type == 0x5) {
            mm_logf_ctx(issi, la, "[DEBUG] FOUND TYPE 5 AT OFFSET 4 (Nibble Aligned!)");
            mm_find_and_log_loc_upd_acc(issi, la, mm_bits + 4, total_bits - 4);
            return (int)len;
        }
    }

    /* Fallback logica voor Authenticatie berichten (Type 1) */
    if (total_bits > 7) {
        uint8_t type = (uint8_t)get_bits_local(mm_bits, total_bits, 3, 4);
        if (type == 0x1) {
             uint8_t st = (uint8_t)get_bits_local(mm_bits, total_bits, 3+4, 2);
             mm_logf_ctx(issi, la, "D-AUTH Type=1 Subtype=%u", st);
        }
    }

    return (int)len;
}
