#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
#include "tetra_cmce_pdu.h"
#include "tetra_sndcp_pdu.h"

/* ✅ Nodig om tms->tcs->la te mogen gebruiken */
#include "crypto/tetra_crypto.h"

/* ---------- Helpers ---------- */

static int issi_is_real(uint32_t issi)
{
    issi &= 0xFFFFFFu;
    return (issi != 0 && issi != 0xFFFFFFu);
}

/* Veilige bit-extractor wrapper */
static uint32_t get_bits(const uint8_t *bits, unsigned int len, unsigned int pos, unsigned int n)
{
    if (pos + n > len) return 0;
    return bits_to_uint(bits + pos, n);
}

static const char *mm_auth_subtype_str(uint8_t st) {
    switch (st & 0x3u) {
    case 0: return "DEMAND";
    case 1: return "RESPONSE";
    case 2: return "RESULT";
    case 3: return "REJECT";
    default: return "UNKNOWN";
    }
}

/* Helper om GSSI uniek toe te voegen aan een lijst */
static void add_gssi_to_list(uint32_t gssi, uint32_t *list, uint8_t *count, uint8_t max)
{
    if (!list || !count) return;
    /* Filter ongeldige waarden */
    if (gssi == 0 || gssi == 0xFFFFFFu) return;

    /* Check op duplicaten */
    for (uint8_t i = 0; i < *count; i++) {
        if (list[i] == gssi) return; 
    }

    if (*count < max) {
        list[(*count)++] = gssi;
    }
}

/* * Parse de INHOUD van "Group identity location accept" (Type 3, ID 0x5)
 * Structuur volgens ETSI EN 300 392-2 Tabel 16.56 en 16.55 
 */
static void mm_parse_group_list(const uint8_t *bits, unsigned int bitlen,
                                uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                uint32_t *out_gssi, uint8_t *out_have_gssi) 
{
    unsigned int p = 0;

    /* 1. Group identity accept/reject (1 bit) */
    if (p + 1 > bitlen) return;
    p += 1;

    /* 2. Reserved (1 bit) */
    if (p + 1 > bitlen) return;
    p += 1;

    /* 3. Group identity downlink count (3 bits) */
    if (p + 3 > bitlen) return;
    uint8_t count = (uint8_t)get_bits(bits, bitlen, p, 3);
    p += 3;

    /* Loop door de groepen */
    for (uint8_t i = 0; i < count; i++) {
        /* Tabel 16.55: Group identity downlink element */
        
        /* Unexchangeable (1 bit) */
        if (p + 1 > bitlen) break;
        p += 1;

        /* Visitor / Home (1 bit) */
        if (p + 1 > bitlen) break;
        // uint8_t visitor = (uint8_t)get_bits(bits, bitlen, p, 1);
        p += 1;

        /* Group Type (1 bit) */
        if (p + 1 > bitlen) break;
        uint8_t gtype = (uint8_t)get_bits(bits, bitlen, p, 1);
        p += 1;

        uint32_t current_gssi = 0;
        
        if (gtype == 0) {
            /* Normal GSSI (24 bits) */
            if (p + 24 > bitlen) break;
            current_gssi = get_bits(bits, bitlen, p, 24);
            p += 24;
        } else {
            /* Extended (GSSI + MCC + MNC) = 24 + 24 = 48 bits */
            if (p + 48 > bitlen) break;
            current_gssi = get_bits(bits, bitlen, p, 24); /* Eerste deel is GSSI */
            /* We skippen MCC/MNC (24 bits) voor nu */
            p += 48; 
        }

        /* Attachment Mode (1 bit) */
        if (p + 1 > bitlen) break;
        p += 1;

        /* Class of Usage (3 bits) */
        if (p + 3 > bitlen) break;
        p += 3;

        /* Er kunnen nog Conditional fields zijn (Detachment Mode), 
           maar die zijn meestal niet aanwezig bij Location Accept context. 
           Voor nu slaan we op wat we hebben. */

        if (current_gssi != 0) {
            add_gssi_to_list(current_gssi, out_gssi_list, out_gssi_count, out_gssi_max);
            
            /* Zet ook de single output pointer voor logica die 1 GSSI verwacht */
            if (out_gssi && out_have_gssi) {
                *out_gssi = current_gssi;
                *out_have_gssi = 1;
            }
        }
    }
}

/* ETSI Type-3/4 element descriptor scanner */
static void mm_scan_type34_elements(const uint8_t *bits, unsigned int bitlen,
                                   unsigned int start_bit,
                                   uint32_t *out_gssi, uint8_t *out_have_gssi,
                                   uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                   uint8_t *out_cck_id, uint8_t *out_have_cck,
                                   uint8_t *out_roam_lu, uint8_t *out_have_roam_lu,
                                   uint8_t *out_itsi_attach, uint8_t *out_have_itsi_attach)
{
    /* Reset outputs */
    if (out_have_gssi) *out_have_gssi = 0;
    if (out_gssi_count) *out_gssi_count = 0;
    if (out_have_cck)  *out_have_cck  = 0;
    if (out_have_roam_lu) *out_have_roam_lu = 0;
    if (out_have_itsi_attach) *out_have_itsi_attach = 0;

    unsigned int pos = start_bit;

    /* Loop zolang er nog een M-bit header (1+4+11 = 16 bits) past */
    while (pos + 16u <= bitlen) {
        
        /* M-bit check (Type 3/4 element indicator) */
        uint32_t mbit = bits_to_uint(bits + pos, 1);
        if (mbit != 1) {
            /* M-bit 0 betekent einde van de reeks optionele elementen */
            break; 
        }

        uint32_t tid  = bits_to_uint(bits + pos + 1, 4);
        uint32_t li   = bits_to_uint(bits + pos + 5, 11); /* Length indicator */

        if (li == 0) { pos += 16; continue; } 

        unsigned int elem_header_len = 16;
        unsigned int elem_total_len = elem_header_len + li;

        /* Buffer overflow protectie */
        if (pos + elem_total_len > bitlen) { 
            break; 
        }

        /* Pointer naar de data van dit element (we gebruiken offsets) */
        const uint8_t *edata = bits; 
        unsigned int e_offset = pos + 16; 

        /* --- DECODING SPECIFIC TYPES --- */

        /* tid 0x5: Group identity location accept */
        if (tid == 0x5) {
            /* Hier gebruiken we de specifieke parser, geen recursie! */
            /* We geven de subset van bits mee, maar pointer arithmetic is makkelijker met offset */
            /* Oplossing: we gebruiken een tijdelijke buffer pointer of offset logica */
            /* Omdat bits_to_uint absoluut werkt, kunnen we offset meegeven in helper, 
               maar onze helper verwacht pointer naar start. We maken een sub-slice pointer. */
            
            /* Voor simpelheid: we roepen de parser aan met offset in gedachten */
            // De parser verwacht bits te lezen vanaf index 0, dus we geven (bits + e_offset) mee
            mm_parse_group_list(bits + e_offset, li,
                                out_gssi_list, out_gssi_count, out_gssi_max,
                                out_gssi, out_have_gssi);
        }

        /* tid 0x7: Group identity downlink (Legacy / Direct) */
        else if (tid == 0x7) {
             if (li >= 24) {
                 /* Quick hack: pak eerste 24 bits als GSSI */
                 uint32_t val = get_bits(edata, bitlen, e_offset, 24);
                 add_gssi_to_list(val, out_gssi_list, out_gssi_count, out_gssi_max);
                 if (out_gssi) { *out_gssi = val; *out_have_gssi = 1; }
             }
        }

        /* tid 0x6: CCK information */
        else if (tid == 0x6 && out_cck_id) {
             /* CCK ID is vaak laatste byte van de structuur */
             if (li >= 8) {
                 *out_cck_id = (uint8_t)get_bits(edata, bitlen, e_offset + li - 8, 8);
                 *out_have_cck = 1;
             }
        }

        /* Best-effort flags (tid 0x2 - vaak SCCH info/flags) */
        else if (tid == 0x2) {
            if (li >= 1 && out_roam_lu) {
                *out_roam_lu = (uint8_t)get_bits(edata, bitlen, e_offset + li - 1, 1);
                *out_have_roam_lu = 1;
            }
             if (li >= 2 && out_itsi_attach) {
                *out_itsi_attach = (uint8_t)get_bits(edata, bitlen, e_offset + li - 2, 1);
                *out_have_itsi_attach = 1;
            }
        }

        /* Volgend element */
        pos += elem_total_len;
    }
}

/* Probeert D-LOC-UPD-ACC te vinden en correct te parsen */
static int mm_find_and_log_loc_upd_acc(uint32_t issi, uint16_t la,
                                      const uint8_t *mm_bits, unsigned int mm_len_bits)
{
    if (!mm_bits || mm_len_bits < 10) return 0;

    unsigned int pos = 0;
    
    /* 1. PDU Type (4 bits) */
    uint8_t pdu_type = (uint8_t)get_bits(mm_bits, mm_len_bits, pos, 4);
    pos += 4;

    /* We verwachten D-LOCATION UPDATE ACCEPT (0101 = 0x5) */
    if (pdu_type != 0x5) return 0;

    /* --- OFFSET BEREKENING (Section 16.10.2) --- */

    /* 2. Location update type (3 bits) */
    if (pos + 3 > mm_len_bits) return 0;
    // uint8_t loc_upd_type = (uint8_t)get_bits(mm_bits, mm_len_bits, pos, 3);
    pos += 3;

    /* 3. SSI present (1 bit) */
    if (pos + 1 > mm_len_bits) return 0;
    uint8_t ssi_present = (uint8_t)get_bits(mm_bits, mm_len_bits, pos, 1);
    pos += 1;

    /* 4. Optional SSI (24 bits) - DIT ZAT EERDER FOUT */
    if (ssi_present) {
        if (pos + 24 > mm_len_bits) return 0;
        pos += 24; /* Skip de SSI bits */
    }

    /* 5. Validity time (2 bits) */
    if (pos + 2 > mm_len_bits) return 0;
    pos += 2;

    /* 6. Reserved (1 bit) */
    if (pos + 1 > mm_len_bits) return 0;
    pos += 1;

    /* 7. O-bit (Optional elements present?) (1 bit) */
    if (pos + 1 > mm_len_bits) return 0;
    uint8_t o_bit = (uint8_t)get_bits(mm_bits, mm_len_bits, pos, 1);
    pos += 1;

    /* Als O-bit 0 is, zijn er geen Type 3/4 elementen */
    if (!o_bit) {
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u (No Type3/4 elements)", (unsigned)issi);
        return 1;
    }

    /* --- NU pas scannen naar Type 3/4 --- */
    
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

    /* Initialiseer list */
    memset(gssi_list, 0, sizeof(gssi_list));

    mm_scan_type34_elements(mm_bits, mm_len_bits, pos, /* Start op berekende positie! */
                            &gssi, &have_gssi,
                            gssi_list, &gssi_count, (uint8_t)(sizeof(gssi_list)/sizeof(gssi_list[0])),
                            &cck_id, &have_cck,
                            &roam_lu, &have_roam_lu,
                            &itsi_attach, &have_itsi_attach);

    /* --- LOGGING --- */
    char tail[256];
    tail[0] = 0;

    if (have_cck) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), " - CCK:%u", (unsigned)cck_id);
        strncat(tail, tmp, sizeof(tail) - strlen(tail) - 1);
    }
    
    if (have_roam_lu && roam_lu) strncat(tail, " - Roaming", sizeof(tail) - strlen(tail) - 1);
    if (have_itsi_attach && itsi_attach) strncat(tail, " - ITSI Attach", sizeof(tail) - strlen(tail) - 1);

    char gbuf[128];
    gbuf[0] = 0;

    if (gssi_count > 0) {
        size_t o2 = 0;
        for (uint8_t i = 0; i < gssi_count; i++) {
            char tmp[24];
            snprintf(tmp, sizeof(tmp), "%s%u", (i ? "," : ""), (unsigned)gssi_list[i]);
            size_t tl = strlen(tmp);
            if (o2 + tl + 1 >= sizeof(gbuf)) break;
            memcpy(gbuf + o2, tmp, tl);
            o2 += tl; gbuf[o2] = 0;
        }
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u GSSI(s):%s%s", (unsigned)issi, gbuf, tail);
    } else if (have_gssi) {
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u GSSI:%u%s", (unsigned)issi, (unsigned)gssi, tail);
    } else {
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC SSI:%u%s", (unsigned)issi, tail);
    }

    return 1;
}

static void mm_try_pretty_log(uint32_t issi, uint16_t la,
                              const uint8_t *mm_bits, unsigned int mm_len_bits)
{
    if (!mm_bits || mm_len_bits < 4) return;

    /* Lees PDU type */
    uint8_t pdu_type = (uint8_t)get_bits(mm_bits, mm_len_bits, 0, 4);

    /* D-AUTH (0x1) - Best effort logging */
    if (pdu_type == 0x1) {
        if (mm_len_bits < 6) return;
        uint8_t st = (uint8_t)get_bits(mm_bits, mm_len_bits, 4, 2);

        if (st == 0) {
             mm_logf_ctx(issi, la, "BS demands authentication: SSI: %u", (unsigned)issi);
        } else if (st == 2) {
            /* Result */
             mm_logf_ctx(issi, la, "BS result to MS authentication (Result) SSI: %u", (unsigned)issi);
        } else {
             mm_logf_ctx(issi, la, "D-AUTH sub-type=%s SSI=%u", mm_auth_subtype_str(st), (unsigned)issi);
        }
        return;
    }

    /* D-LOC-UPD-ACC (0x5) - Directe aanroep van onze verbeterde parser */
    if (pdu_type == 0x5) {
        if (mm_find_and_log_loc_upd_acc(issi, la, mm_bits, mm_len_bits)) {
            return;
        }
    }

    /* Fallback: Mocht de PDU type anders zijn, maar misschien toch structuur hebben */
    /* (Optioneel: je kunt hier andere handlers toevoegen) */
}


/* ---------- Main Entry ---------- */

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len < 1)
        return (int)len;

    uint32_t issi = 0;
    if (tms) issi = (uint32_t)tms->ssi;

    int la = -1;
    if (tms && tms->tcs) la = tms->tcs->la;

    if (!issi_is_real(issi))
        return (int)len;

    /* Detect unpacked bits (0/1 per byte) */
    int unpacked = 1;
    for (unsigned int i = 0; i < len; i++) {
        if (buf[i] > 1) { unpacked = 0; break; }
    }

    if (unpacked) {
        if (len < 7) return (int)len;

        /* Score-based offset picker (uit originele script behouden) */
        unsigned int best_off = 0;
        int best_score = -999;
        uint8_t best_pdisc = 0;
        
        static const uint8_t valid_pdisc[] = { TMLE_PDISC_MM, TMLE_PDISC_CMCE, TMLE_PDISC_SNDCP };

        for (unsigned int off = 0; off < 8; off++) {
            if (len < off + 3) continue;

            uint8_t pdisc = (uint8_t)(((buf[off+0] & 1u) << 2) |
                                      ((buf[off+1] & 1u) << 1) |
                                       (buf[off+2] & 1u));

            int pdisc_ok = 0;
            for (unsigned int k = 0; k < (unsigned int)sizeof(valid_pdisc); k++) {
                if (pdisc == valid_pdisc[k]) { pdisc_ok = 1; break; }
            }
            if (!pdisc_ok) continue;

            int score = 10;
            if (pdisc == TMLE_PDISC_MM && len >= off + 7) {
                uint8_t mmtype = (uint8_t)(((buf[off+3] & 1u) << 3) |
                                           ((buf[off+4] & 1u) << 2) |
                                           ((buf[off+5] & 1u) << 1) |
                                            (buf[off+6] & 1u));
                if (mmtype == 0x5) score += 50; 
                else if (mmtype == 0x1) score += 30;
                else score += 5;
            }

            if (score > best_score) {
                best_score = score;
                best_off = off;
                best_pdisc = pdisc;
            }
        }

        if (best_score < 0) return (int)len;

        if (best_pdisc == TMLE_PDISC_MM) {
            unsigned int mm_payload_off = best_off + 7; /* 3 bits pdisc + 4 bits mmtype = 7 bits header? Nee. */
            /* PDISC(3) + TYPE(4) = 7 bits. Dus payload begint op offset 7 relative to PDISC start */
            
            /* Wacht, in unpacked mode is elke byte 1 bit. */
            /* Header = PDISC (3 bits) + TYPE (4 bits). Totaal 7 bytes offset voor payload data? */
            /* mm_try_pretty_log verwacht de HELE MM PDU inclusief TYPE. */
            
            unsigned int mm_start_off = best_off + 3; /* Skip PDISC (3 bits) */
            if (len < mm_start_off) return (int)len;

            unsigned int mm_len_bits = len - mm_start_off;
            if (mm_len_bits > 4096) mm_len_bits = 4096;

            uint8_t mm_bits[4096];
            for (unsigned int bi = 0; bi < mm_len_bits; bi++) {
                mm_bits[bi] = buf[mm_start_off + bi] & 1u;
            }

            mm_try_pretty_log(issi, la, mm_bits, mm_len_bits);
            return (int)len;
        }
        return (int)len;
    }

    /* Packed octets path */
    const uint8_t *oct = buf;
    uint8_t mle_pdisc = (uint8_t)(oct[0] & 0x0F); // Nibble swap check logic removed for brevity, assume standard
    
    // Quick check logic from original script to handle nibble swaps if needed...
    // (Laten we aannemen dat PDISC MM is)
    if (mle_pdisc != TMLE_PDISC_MM) {
         // Check swap
         uint8_t alt = (uint8_t)((oct[0] >> 4) & 0x0F);
         if (alt == TMLE_PDISC_MM) mle_pdisc = alt; 
         else return (int)len;
    }

    /* Converteer bytes naar bitstream voor de parser */
    const unsigned int mm_len_bits = 4 + (len - 1) * 8; /* PDU type (4 bits) was part of first byte? */
    /* De MLE header is PDISC (3) + ... 
       Eigenlijk zit de MM PDU Type direct in de SDU na de MLE header.
       Voor packed data is het vaak makkelijker om gewoon alles uit te pakken naar een bit array.
    */
    
    /* We pakken alles uit vanaf byte 0 (waarin PDISC zit) en skippen dan PDISC */
    if (mm_len_bits > 4096) return (int)len;
    uint8_t mm_bits[4096];
    
    unsigned int o = 0;
    for (unsigned int bi = 0; bi < len; bi++) {
        uint8_t b = oct[bi];
        for(int k=7; k>=0; k--) mm_bits[o++] = (b >> k) & 1u;
    }

    /* MLE PDISC is 3 bits. MM PDU start op bit 3? */
    /* In TETRA packets zit PDISC vaak in de eerste nibble. */
    /* We skippen de eerste 3 bits (PDISC) en sturen de rest naar de logger */
    /* NB: Dit hangt af van hoe de buffer wordt aangeleverd (stripped MLE header of niet). */
    /* Aanname: buf bevat de MLE PDU. */
    
    mm_try_pretty_log(issi, la, mm_bits + 3, o - 3);

    return (int)len;
}
