#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
#include "crypto/tetra_crypto.h"

/* ---------- ROBUUSTE HELPERS ---------- */

/* Leest N bits uit een bitstream array */
static uint32_t get_bits(const uint8_t *bits, unsigned int len, unsigned int pos, unsigned int n) {
    if (pos + n > len) return 0;
    uint32_t val = 0;
    for (unsigned int i = 0; i < n; i++) {
        val = (val << 1) | (bits[pos + i] & 1);
    }
    return val;
}

/* Helper om GSSI uniek toe te voegen */
static void add_gssi_to_list(uint32_t gssi, uint32_t *list, uint8_t *count, uint8_t max) {
    /*
     * NB: 0xFFFFFF wordt in ETSI-contexten gebruikt als "open" / wildcard SSI.
     * Veel netten signaleren (G)SSI=0xFFFFFF, dus dit NIET wegfilteren.
     */
    if (!list || !count || gssi == 0) return;
    for (uint8_t i = 0; i < *count; i++) if (list[i] == gssi) return;
    if (*count < max) list[(*count)++] = gssi;
}

/* ---------- ETSI CONFORME PARSERS ---------- */

/*
 * Parseer de "Group identity location accept" lijst.
 * Dit is de crux: dit is een LIJST structuur, geen standaard TLV.
 */
static void mm_parse_group_list(const uint8_t *bits, unsigned int bitlen,
                                uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                uint32_t *out_gssi, uint8_t *out_have_gssi) 
{
    unsigned int p = 0;
    
    /* Header van de Group Identity structuur */
    if (p + 5 > bitlen) return;
    p += 1; /* Accept/Reject */
    p += 1; /* Reserved */
    
    uint8_t count = (uint8_t)get_bits(bits, bitlen, p, 3);
    p += 3;

    for (uint8_t i = 0; i < count; i++) {
        /* Group element headers */
        if (p + 3 > bitlen) break;
        p += 2; /* Unexchangeable(1) + Visitor(1) */
        
        uint8_t gtype = (uint8_t)get_bits(bits, bitlen, p, 1);
        p += 1;

        uint32_t current_gssi = 0;
        
        if (gtype == 0) { 
            /* Normal GSSI (24 bits) */
            if (p + 24 > bitlen) break;
            current_gssi = get_bits(bits, bitlen, p, 24);
            p += 24;
        } else { 
            /* Extended (GSSI + MCC + MNC) -> Wij pakken alleen GSSI */
            if (p + 48 > bitlen) break;
            current_gssi = get_bits(bits, bitlen, p, 24);
            p += 48;
        }
        
        /* Attachment Mode (1) + Class of Usage (3) */
        if (p + 4 > bitlen) break;
        p += 4; 

        /* Store result */
        if (current_gssi != 0) {
            add_gssi_to_list(current_gssi, out_gssi_list, out_gssi_count, out_gssi_max);
            if (out_gssi && out_have_gssi) { *out_gssi = current_gssi; *out_have_gssi = 1; }
        }
    }
}

/* Scanner voor Type 3/4 Elementen (de optionele staart van het bericht) */
static void mm_scan_type34_elements(const uint8_t *bits, unsigned int bitlen, unsigned int start_bit,
                                   uint32_t *out_gssi, uint8_t *out_have_gssi,
                                   uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                   uint8_t *out_cck_id, uint8_t *out_have_cck,
                                   uint8_t *out_roam_lu, uint8_t *out_have_roam_lu,
                                   uint8_t *out_itsi_attach, uint8_t *out_have_itsi_attach)
{
    unsigned int pos = start_bit;

    while (pos + 16u <= bitlen) {
        /* Check M-bit */
        uint32_t mbit = get_bits(bits, bitlen, pos, 1);
        if (mbit == 0) break; /* Geen elementen meer */

        uint32_t tid = get_bits(bits, bitlen, pos + 1, 4);
        uint32_t li  = get_bits(bits, bitlen, pos + 5, 11);
        
        if (li == 0) { pos += 16; continue; }
        
        unsigned int elem_len = 16 + li;
        if (pos + elem_len > bitlen) break;

        /* Pointer logica simuleren door offset mee te geven */
        unsigned int content_offset = pos + 16;
        
        if (tid == 0x5) { 
            /* GSSI LIJST: Hier roepen we de speciale parser aan! */
            /* We geven de pointer naar start bits mee, maar offset is content_offset */
            /* Omdat mm_parse_group_list op index 0 begint, tellen we de offset er bij op */
            mm_parse_group_list(bits + content_offset, li, 
                                out_gssi_list, out_gssi_count, out_gssi_max, 
                                out_gssi, out_have_gssi);
        }
        else if (tid == 0x7 && li >= 24) { /* Legacy Single GSSI */
             uint32_t val = get_bits(bits, bitlen, content_offset, 24);
             add_gssi_to_list(val, out_gssi_list, out_gssi_count, out_gssi_max);
             if (out_gssi) { *out_gssi = val; *out_have_gssi = 1; }
        }
        else if (tid == 0x6 && li >= 8 && out_cck_id) { /* CCK */
             *out_cck_id = (uint8_t)get_bits(bits, bitlen, content_offset + li - 8, 8);
             *out_have_cck = 1;
        }
        else if (tid == 0x2) { /* Flags */
            if (li >= 1 && out_roam_lu) { 
                *out_roam_lu = (uint8_t)get_bits(bits, bitlen, content_offset + li - 1, 1); 
                *out_have_roam_lu = 1; 
            }
            if (li >= 2 && out_itsi_attach) { 
                *out_itsi_attach = (uint8_t)get_bits(bits, bitlen, content_offset + li - 2, 1); 
                *out_have_itsi_attach = 1; 
            }
        }
        pos += elem_len;
    }
}

/* Verwerkt de inhoud van D-LOCATION UPDATE ACCEPT */
static void handle_loc_upd_acc(uint32_t issi, uint16_t la, const uint8_t *mm_bits, unsigned int len, unsigned int offset)
{
    unsigned int pos = offset; // Start na PDU Type
    
    /* Header velden (Tabel 16.10.2) */
    if (pos + 8 > len) return;
    
    // uint8_t loc_type = get_bits(mm_bits, len, pos, 3);
    pos += 3;
    
    uint8_t ssi_pres = (uint8_t)get_bits(mm_bits, len, pos, 1);
    pos += 1;

    /* CRUCIAAL: Als SSI aanwezig is, moeten we 24 bits opschuiven! */
    if (ssi_pres) {
        if (pos + 24 > len) return;
        pos += 24; 
    }

    /* Validity (2) + Reserved (1) */
    if (pos + 3 > len) return;
    pos += 3;

    /* O-bit (Optional elements) */
    if (pos + 1 > len) return;
    uint8_t o_bit = (uint8_t)get_bits(mm_bits, len, pos, 1);
    pos += 1;

    if (!o_bit) {
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u (No GSSI info)", (unsigned)issi);
        return;
    }

    /* Start scanning Type 3/4 elements */
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

    mm_scan_type34_elements(mm_bits, len, pos,
                            &gssi, &have_gssi, gssi_list, &gssi_count, 8,
                            &cck_id, &have_cck, &roam_lu, &have_roam_lu,
                            &itsi_attach, &have_itsi_attach);

    /* Formatteer output */
    char tail[256]; tail[0] = 0;
    if (have_cck) { char tmp[64]; snprintf(tmp, sizeof(tmp), " - CCK:%u", cck_id); strncat(tail, tmp, 200); }
    if (have_roam_lu && roam_lu) strncat(tail, " - Roaming", 200);
    if (have_itsi_attach && itsi_attach) strncat(tail, " - Attach", 200);

    char gbuf[128]; gbuf[0] = 0;
    if (gssi_count > 0) {
        size_t o2 = 0;
        for (uint8_t i=0; i<gssi_count; i++) {
            char tmp[32];
            if (gssi_list[i] == 0xFFFFFFu)
                snprintf(tmp, sizeof(tmp), "%sOPEN(0xFFFFFF)", (i?",":""));
            else
                snprintf(tmp, sizeof(tmp), "%s%u", (i?",":""), gssi_list[i]);
            size_t tl = strlen(tmp);
            if(o2+tl+1 < sizeof(gbuf)) { memcpy(gbuf+o2, tmp, tl); o2+=tl; gbuf[o2]=0; }
        }
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u GSSI(s):%s%s", (unsigned)issi, gbuf, tail);
    } else {
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u%s", (unsigned)issi, tail);
    }
}

/* ---------- MAIN ENTRY ---------- */

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len < 1) return (int)len;

    uint32_t issi = tms ? (uint32_t)tms->ssi : 0;
    int la = (tms && tms->tcs) ? tms->tcs->la : -1;

    /* * STAP 1: Detecteer data formaat (Packed vs Unpacked)
     * Als er bytes > 1 zijn, is het zeker Packed.
     */
    int is_packed = 0;
    for(unsigned int i=0; i<len; i++) {
        if(buf[i] > 1) { is_packed = 1; break; }
    }

    /* * STAP 2: Maak een schone bitstream array
     */
    static uint8_t bits[4096];
    unsigned int nbits = 0;

    if (is_packed) {
        /* Packed: 1 byte = 8 bits. Uitpakken. */
        if (len * 8 > 4096) len = 512;
        for (unsigned int i = 0; i < len; i++) {
            uint8_t b = buf[i];
            for (int k = 7; k >= 0; k--) bits[nbits++] = (b >> k) & 1u;
        }
    } else {
        /* Unpacked: 1 byte = 1 bit. Direct kopiëren. */
        if (len > 4096) len = 4096;
        for (unsigned int i = 0; i < len; i++) bits[nbits++] = buf[i] & 1u;
    }

    /* * STAP 3: SCANNER - Vind de juiste offset
     * We zoeken naar PDISC=1 (MM). De bit-alignment kan variëren.
     */
    int found = 0;
    
    /*
     * We proberen ALLE offsets (niet alleen 0..7).
     * Bij LLC-bypass / variërende headers kan de PDISC alignment veel verder opschuiven.
     */
    for (unsigned int off = 0; off + 7u <= nbits; off++) {
        /* Hebben minstens PDISC(3)+TYPE(4) nodig */
        if (nbits < off + 7u) break;

        /* Check PDISC (3 bits) */
        uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
        
        /* We zoeken specifiek MM protocol (1) */
        if (pdisc != TMLE_PDISC_MM) continue;

        /* PDISC klopt, check nu Type (4 bits) */
        uint8_t type = (uint8_t)get_bits(bits, nbits, off + 3, 4);

        /* Is het een bekend type? */
        if (type == 0x5) { /* D-LOCATION UPDATE ACCEPT */
            // mm_logf_ctx(issi, la, "[DEBUG] MM Detect: Type 5 at offset %u", off);
            handle_loc_upd_acc(issi, la, bits, nbits, off + 3 + 4);
            found = 1;
            break; /* Gevonden! */
        }
        else if (type == 0x1) { /* D-AUTH */
             /* Check subtype om zeker te zijn */
             if (nbits >= off + 7 + 2) {
                 uint8_t st = (uint8_t)get_bits(bits, nbits, off + 7, 2);
                 if (st == 0) mm_logf_ctx(issi, la, "BS demands authentication: SSI: %u", (unsigned)issi);
                 else if (st == 2) mm_logf_ctx(issi, la, "BS result to MS auth: Result SSI: %u", (unsigned)issi);
                 // else mm_logf_ctx(issi, la, "D-AUTH subtype %u", st);
                 found = 1;
                 break;
             }
        }
    }

    /* Als we niks specifieks vonden, doet de oude logica (buiten deze functie) de rest */
    return (int)len;
}
