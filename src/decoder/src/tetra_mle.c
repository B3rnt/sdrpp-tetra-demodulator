#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
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

/* ===================== MM debugging helpers (octet dumps + TLV probing) ===================== */

static unsigned int bits_to_bytes_from(const uint8_t *bits, unsigned int nbits,
                                       unsigned int start_bit, uint8_t *out, unsigned int out_max)
{
    if (!bits || !out || out_max == 0 || start_bit >= nbits)
        return 0;

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

    char line[1024];
    unsigned int p = 0;
    p += (unsigned int)snprintf(line + p, sizeof(line) - p, "%s:", label ? label : "dump");
    for (unsigned int i = 0; i < len && p + 4 < sizeof(line); i++) {
        p += (unsigned int)snprintf(line + p, sizeof(line) - p, " %02X", (unsigned)buf[i]);
    }
    mm_logf_ctx(issi, la, "%s", line);
}

typedef struct {
    unsigned int start_bit;
    unsigned int parsed_bytes;
    unsigned int consumed_bytes;
    uint8_t roam;
    uint8_t have_roam;
    uint8_t cck_id;
    uint8_t have_cck;
    uint32_t gssi_candidate;
    uint8_t have_gssi_candidate;
} mm_probe_result;

static void mm_scan_24bit_candidates_ctx(uint32_t issi, uint16_t la,
                                        const uint8_t *buf, unsigned int len)
{
    /* Scan overlappende 3-byte windows als 24-bit getallen. Filter op 'realistische' range,
       want anders spam je logs. Tune deze range als je wilt. */
    if (!buf || len < 3) return;

    for (unsigned int i = 0; i + 2 < len; i++) {
        uint32_t v = ((uint32_t)buf[i] << 16) | ((uint32_t)buf[i+1] << 8) | (uint32_t)buf[i+2];
        if (v >= 1000000 && v <= 9000000) {
            mm_logf_ctx(issi, la, "MM 24-bit candidate at +%u: %u (0x%06X) bytes=%02X %02X %02X",
                        i, (unsigned)v, (unsigned)v,
                        (unsigned)buf[i], (unsigned)buf[i+1], (unsigned)buf[i+2]);
        }
    }
}

static mm_probe_result mm_probe_tlv(const uint8_t *buf, unsigned int len, unsigned int start_bit)
{
    mm_probe_result r;
    memset(&r, 0, sizeof(r));
    r.start_bit = start_bit;

    unsigned int pos = 0;
    while (pos + 2 <= len) {
        uint8_t iei = buf[pos++];
        uint8_t ilen = buf[pos++];

        /* Stop als de lengte over de payload heen gaat: vanaf hier is het geen TLV meer of offset fout */
        if (pos + ilen > len) {
            r.consumed_bytes = pos - 2;
            return r;
        }

        /* Accumulate stats */
        r.parsed_bytes += (unsigned int)(2 + ilen);
        r.consumed_bytes = pos + ilen;

        /* Heuristiek: roaming flag (jouw log laat IEI=0x09 len=1 data=0x80 zien) */
        if (iei == 0x09 && ilen == 1) {
            r.roam = buf[pos];
            r.have_roam = 1;
        }

        /* Heuristiek: oude sample had IEI=0x54 len=9 waar CCK id in de laatste 6 bits zat.
           (Dit blijft een heuristiek, maar matchte jouw eerdere logs goed.) */
        if (iei == 0x54 && ilen >= 2) {
            uint8_t b0 = buf[pos + ilen - 2];
            uint8_t b1 = buf[pos + ilen - 1];
            uint8_t cck = (uint8_t)(((b0 & 0x80) ? 32 : 0) | (b1 & 0x1F));
            r.cck_id = cck;
            r.have_cck = 1;
        }

        /* 24-bit candidate inside TLV data: als er exact 3 bytes zijn, log als mogelijk SSI/GSSI */
        if (ilen == 3 && !r.have_gssi_candidate) {
            uint32_t v = ((uint32_t)buf[pos] << 16) | ((uint32_t)buf[pos+1] << 8) | (uint32_t)buf[pos+2];
            if (v >= 1000000 && v <= 9000000) {
                r.gssi_candidate = v;
                r.have_gssi_candidate = 1;
            }
        }

        pos += ilen;
    }

    r.consumed_bytes = pos;
    return r;
}

static mm_probe_result mm_choose_best_probe(uint32_t issi, uint16_t la,
                                            const uint8_t *bits, unsigned int nbits,
                                            unsigned int base_bit, const unsigned int *offsets, unsigned int n_offsets)
{
    mm_probe_result best;
    memset(&best, 0, sizeof(best));
    unsigned int best_score = 0;

    for (unsigned int i = 0; i < n_offsets; i++) {
        unsigned int start_bit = base_bit + offsets[i];

        uint8_t tmp[128];
        unsigned int blen = bits_to_bytes_from(bits, nbits, start_bit, tmp, sizeof(tmp));

        char lbl[64];
        snprintf(lbl, sizeof(lbl), "MM raw payload (from bit %u)", offsets[i]);
        mm_hex_dump_ctx(issi, la, lbl, tmp, blen);

        mm_probe_result r = mm_probe_tlv(tmp, blen, start_bit);

        /* Log parsed TLVs (totdat het stopt) */
        unsigned int pos = 0;
        while (pos + 2 <= blen) {
            uint8_t iei = tmp[pos++];
            uint8_t ilen = tmp[pos++];
            if (pos + ilen > blen) {
                mm_logf_ctx(issi, la, "MM TLV parse stopped (IEI=0x%02X len=%u overruns payload)", (unsigned)iei, (unsigned)ilen);
                break;
            }
            /* log TLV */
            char line[512];
            unsigned int p = 0;
            p += (unsigned int)snprintf(line + p, sizeof(line) - p, "MM TLV IEI=0x%02X len=%u data=", (unsigned)iei, (unsigned)ilen);
            for (unsigned int j = 0; j < ilen && p + 4 < sizeof(line); j++) {
                p += (unsigned int)snprintf(line + p, sizeof(line) - p, "%s%02X", (j ? " " : ""), (unsigned)tmp[pos + j]);
            }
            mm_logf_ctx(issi, la, "%s", line);
            pos += ilen;
        }

        /* Score: hoeveel bytes TLV we netjes konden consumeren (meer = waarschijnlijk juiste offset) */
        unsigned int score = r.parsed_bytes;

        if (score > best_score) {
            best_score = score;
            best = r;
        }
    }

    /* Extra: dump candidates op de best gekozen start (ook buiten TLV) */
    uint8_t bestbuf[256];
    unsigned int bestlen = bits_to_bytes_from(bits, nbits, best.start_bit, bestbuf, sizeof(bestbuf));
    mm_scan_24bit_candidates_ctx(issi, la, bestbuf, bestlen);

    return best;
}

/* ===================== end helpers ===================== */


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
 * Parseer "Group identity location accept" (speciale lijst-structuur).
 * Verwacht bits pointer naar begin van de lijst (dus direct NA de type-3 header),
 * en bitlen = LI van de type-3 header.
 */
static void mm_parse_group_list(const uint8_t *bits, unsigned int bitlen,
                                uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                uint32_t *out_gssi, uint8_t *out_have_gssi)
{
    unsigned int p = 0;

    /* Accept/Reject (1) + reserved (1) + count (3) */
    if (p + 5 > bitlen)
        return;

    p += 1; /* accept/reject */
    p += 1; /* reserved */
    uint8_t count = (uint8_t)get_bits(bits, bitlen, p, 3);
    p += 3;

    for (uint8_t i = 0; i < count; i++) {
        if (p + 3 > bitlen)
            break;

        p += 2; /* unexchangeable + visitor */
        uint8_t gtype = (uint8_t)get_bits(bits, bitlen, p, 1);
        p += 1;

        uint32_t current_gssi = 0;

        if (gtype == 0) {
            /* Normal GSSI (24 bits) */
            if (p + 24 > bitlen)
                break;
            current_gssi = get_bits(bits, bitlen, p, 24);
            p += 24;
        } else {
            /* Extended: GSSI(24) + MCC/MNC etc (extra 24) -> total 48; we pakken alleen GSSI */
            if (p + 48 > bitlen)
                break;
            current_gssi = get_bits(bits, bitlen, p, 24);
            p += 48;
        }

        /* Attachment mode (1) + class of usage (3) */
        if (p + 4 > bitlen)
            break;
        p += 4;

        if (current_gssi != 0) {
            add_gssi_to_list(current_gssi, out_gssi_list, out_gssi_count, out_gssi_max);
            if (out_gssi && out_have_gssi) {
                *out_gssi = current_gssi;
                *out_have_gssi = 1;
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

        /* tid 0x5: Group identity location accept (lijst) */
        if (tid == 0x5) {
            mm_parse_group_list(bits + content_offset, (unsigned int)li,
                                out_gssi_list, out_gssi_count, out_gssi_max,
                                out_gssi, out_have_gssi);
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

    /* Zoek MM PDUs: PDISC is 3 bits, maar type-offset kan +3 of +4 zijn */
    for (unsigned int off = 0; off + 12u <= nbits; off++) {
        uint8_t pdisc = (uint8_t)get_bits(bits, nbits, off, 3);
        if (pdisc != TMLE_PDISC_MM)
            continue;

        /* Probeer beide layouts */
        unsigned int type_offsets[2] = { off + 3, off + 4 };

        for (unsigned int vi = 0; vi < 2; vi++) {
            unsigned int toff = type_offsets[vi];
            if (toff + 4 > nbits)
                continue;

            uint8_t type = (uint8_t)get_bits(bits, nbits, toff, 4);

            /* D-AUTH: subtype zit direct daarna; die logging had je al werkend */
            if (type == TMM_PDU_T_D_AUTH) {
                if (toff + 4 + 2 <= nbits) {
                    uint8_t st = (uint8_t)get_bits(bits, nbits, toff + 4, 2);
                    if (st == 0)
                        mm_logf_ctx(issi, (uint16_t)la, "BS demands authentication: SSI: %u", (unsigned)issi);
                    else if (st == 2)
                        mm_logf_ctx(issi, (uint16_t)la, "BS result to MS auth: Result SSI: %u", (unsigned)issi);
                    else
                        mm_logf_ctx(issi, (uint16_t)la, "BS auth message (subtype %u): SSI: %u", (unsigned)st, (unsigned)issi);
                    return (int)len;
                }
            }

            /* D-LOCATION UPDATE ACCEPT: hier zit de GSSI/CCK/flags in type-3/4 elementen */
            if (type == TMM_PDU_T_D_LOC_UPD_ACC) {
                /* We weten niet exact waar de variabele header eindigt, dus:
                 * zoek de eerste Type-3/4 TLV header ergens na 'type' */
                unsigned int scan_start = toff + 4; /* na PDU-type */

                /* Parsed / derived fields for this MM PDU (filled by TLV probing and/or type3/4 scan) */


                /* --- SDR#-achtige octet/TLV probing (lost 'bit offset' en format-switch issues op) --- */
                {
                    const unsigned int probe_offsets[4] = { 0, 8, 16, 24 };
                    mm_probe_result pr = mm_choose_best_probe(issi, (uint16_t)la, bits, nbits, scan_start, probe_offsets, 4);

                    /* Koppel heuristiek-resultaten alvast aan bestaande flags (als aanwezig) */
                    if (pr.have_roam) { roam = pr.roam; have_roam = 1; }
                    if (pr.have_cck)  { cck_id = pr.cck_id; have_cck = 1; }

                    /* Als we nog geen GSSI uit type3/4 halen, maar wel een 24-bit candidate zagen in TLV: gebruik die */
                    if (!have_gssi && pr.have_gssi_candidate) {
                        gssi = pr.gssi_candidate;
                        have_gssi = 1;
                    }
                }
                int t34 = find_first_type34(bits, nbits, scan_start);

                uint32_t gssi_list[8];
                uint8_t gssi_count = 0;
                memset(gssi_list, 0, sizeof(gssi_list));

                uint32_t gssi = 0;
                uint8_t have_gssi = 0;
                uint8_t cck_id = 0;
                uint8_t have_cck = 0;
                uint8_t roam = 0;
                uint8_t have_roam = 0;
                uint8_t itsi_attach = 0;
                uint8_t have_itsi_attach = 0;

                if (t34 >= 0) {
                    mm_scan_type34_elements(bits, nbits, (unsigned int)t34,
                                            &gssi, &have_gssi,
                                            gssi_list, &gssi_count, 8,
                                            &cck_id, &have_cck,
                                            &roam, &have_roam,
                                            &itsi_attach, &have_itsi_attach);

                    /* Log in SDR# stijl */
                    log_loc_upd_accept_like_sdrsharp(issi, la, gssi_list, gssi_count,
                                                     have_cck, cck_id,
                                                     have_roam, roam);
                } else {
                    /* Geen type3/4 gevonden -> toch melden dat accept is gezien */
                    mm_logf_ctx(issi, (uint16_t)la, "MS request for registration ACCEPTED for SSI: %u", (unsigned)issi);
                }

                return (int)len;
            }

            /* Andere MM types kun je later toevoegen (LOC_UPD_PROC, LOC_UPD_REJ, ...). */
        }
    }

    return (int)len;
}
