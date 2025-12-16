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

/* --- MM IE (TLV) parsing helpers ---------------------------------------
 * SDR# gebruikt een rule-engine (presence/optional/switch) om MM velden te decoderen.
 * In de praktijk betekent dat: na PDISC/MM-type volgt meestal een reeks IE's (octet-gebaseerd),
 * met optionele velden die je NIET op vaste bitposities mag lezen.
 *
 * Deze helpers geven ons een robuuste baseline:
 *  - Start op een octet boundary
 *  - Lees IEI (8) + LEN (8) + DATA(LEN*8)
 *  - Log onbekende IE's (handig debuggen)
 *  - Heuristiek: 24-bit waarden (len==3) behandelen als kandidaat SSI/GSSI
 *    (veel MM IE's gebruiken 24-bit SSI/GSSI of lijsten daarvan)
 */

static unsigned int align_to_octet(unsigned int bitoff)
{
    return (bitoff + 7u) & ~7u;
}

static uint8_t get_u8_aligned(const uint8_t *bits, unsigned int nbits, unsigned int bitoff)
{
    /* bitoff moet op octet boundary zitten */
    return (uint8_t)get_bits(bits, nbits, bitoff, 8);
}

static uint32_t get_u24_aligned(const uint8_t *bits, unsigned int nbits, unsigned int bitoff)
{
    return (uint32_t)get_bits(bits, nbits, bitoff, 24);
}

static void hex_snip(char *out, size_t out_sz, const uint8_t *bits, unsigned int nbits,
                     unsigned int bitoff, unsigned int nbytes, unsigned int max_bytes)
{
    /* Zet een stukje data om naar hex (max_bytes), voor logging/debugging */
    if (!out || out_sz == 0) return;
    out[0] = '\0';

    unsigned int show = (nbytes > max_bytes) ? max_bytes : nbytes;
    size_t pos = 0;
    for (unsigned int i = 0; i < show; i++) {
        if (bitoff + (i+1u)*8u > nbits) break;
        uint8_t b = get_u8_aligned(bits, nbits, bitoff + i*8u);
        int w = snprintf(out + pos, (pos < out_sz) ? (out_sz - pos) : 0, "%02X", b);
        if (w < 0) break;
        pos += (size_t)w;
        if (i + 1 < show) {
            if (pos + 1 < out_sz) { out[pos++] = ' '; out[pos] = '\0'; }
        }
    }
    if (nbytes > show && pos + 4 < out_sz) {
        snprintf(out + pos, out_sz - pos, " ...");
    }
}

/* Parse TLV IE's uit een MM PDU payload.
 * - payload_bitoff: start van IE stream (liefst aligned)
 * - payload_bitlen: totale lengte in bits vanaf payload_bitoff
 *
 * Outputs:
 * - vult eventueel GSSI lijst/een enkele GSSI via heuristiek (len==3)
 * - kan LA kandidaten herkennen (len==2 en <= 14 bits)
 */
static void mm_parse_tlv_ies(const uint8_t *bits, unsigned int nbits,
                            uint32_t issi, int la, uint8_t mm_type,
                            unsigned int payload_bitoff, unsigned int payload_bitlen,
                            uint32_t *out_gssi, int *out_have_gssi,
                            uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                            uint16_t *out_la_candidate, int *out_have_la_candidate)
{
    unsigned int off = align_to_octet(payload_bitoff);
    unsigned int end = payload_bitoff + payload_bitlen;
    if (end > nbits) end = nbits;

    /* Loop IEI/LEN/DATA */
    while (off + 16u <= end) {
        uint8_t iei = get_u8_aligned(bits, nbits, off);
        uint8_t len = get_u8_aligned(bits, nbits, off + 8u);
        off += 16u;

        unsigned int data_bits = (unsigned int)len * 8u;
        if (off + data_bits > end) break;

        /* Heuristieken voor veel voorkomende velden */
        if (len == 3) {
            uint32_t v = get_u24_aligned(bits, nbits, off);
            /* Dit kan SSI of GSSI zijn. In praktijk wil je vooral GSSI's zien. */
            add_gssi_to_list(v, out_gssi_list, out_gssi_count, out_gssi_max);
            if (out_gssi && out_have_gssi && !*out_have_gssi) {
                *out_gssi = v;
                *out_have_gssi = 1;
            }
        } else if (len == 2) {
            uint16_t v16 = (uint16_t)get_bits(bits, nbits, off, 16);
            /* LA is 14 bits; veel implementaties sturen het als 2 octets met leading zeros */
            if (v16 <= 0x3FFFu && out_la_candidate && out_have_la_candidate && !*out_have_la_candidate) {
                *out_la_candidate = v16;
                *out_have_la_candidate = 1;
            }
        }

        /* Debug logging: laat onbekende IE's zien om mapping te kunnen toevoegen */
        {
            char hx[128];
            hex_snip(hx, sizeof(hx), bits, nbits, off, len, 10);
            mm_logf_ctx(issi, (uint16_t)la, "MM type=0x%X IEI=0x%02X len=%u data=%s",
                        (unsigned)mm_type, (unsigned)iei, (unsigned)len, hx);
        }

        off += data_bits;
        /* Sommige stacks voegen padding toe tot octet boundary: forceer aligned */
        off = align_to_octet(off);
    }
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

            /* Payload start: na type veld (en evt. spare) kan er nog padding zitten.
             * We nemen een octet-aligned start zodat TLV IE parsing stabiel blijft. */
            unsigned int payload_off_bits = toff + 4u;
            unsigned int payload_off_aligned = align_to_octet(payload_off_bits);
            unsigned int payload_len_bits = (off + len) > payload_off_aligned ? (off + len - payload_off_aligned) : 0;

            /* Verzamel TLV IE info voor debugging + heuristische SSI/GSSI/LA */
            uint32_t tlv_gssi = 0;
            int have_tlv_gssi = 0;
            uint32_t tlv_gssi_list[16];
            uint8_t tlv_gssi_cnt = 0;
            uint16_t tlv_la = 0;
            int have_tlv_la = 0;

            if (payload_len_bits >= 16u) {
                mm_parse_tlv_ies(bits, nbits, issi, la, type,
                                 payload_off_aligned, payload_len_bits,
                                 &tlv_gssi, &have_tlv_gssi,
                                 tlv_gssi_list, &tlv_gssi_cnt, 16,
                                 &tlv_la, &have_tlv_la);
            }

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
                    if (have_tlv_la)
                        mm_logf_ctx(issi, (uint16_t)la, "MS request for registration ACCEPTED (LA=%u) for SSI: %u", (unsigned)tlv_la, (unsigned)issi);
                    else
                        mm_logf_ctx(issi, (uint16_t)la, "MS request for registration ACCEPTED for SSI: %u", (unsigned)issi);
                    if (have_tlv_gssi)
                        mm_logf_ctx(issi, (uint16_t)la, "MM TLV: candidate GSSI=%u (0x%06X)", (unsigned)tlv_gssi, (unsigned)tlv_gssi);
                }

                return (int)len;
            }


            /* D-LOCATION UPDATE COMMAND / PROCEEDING / REJECT / MM STATUS:
             * Deze waren vaak 'stil' in jouw output. We loggen ze nu altijd,
             * en gebruiken TLV heuristieken om o.a. LA/GSSI te tonen.
             */
            if (type == TMM_PDU_T_D_LOC_UPD_CMD) {
                if (have_tlv_la)
                    mm_logf_ctx(issi, (uint16_t)la, "SwMI sent LOCATION UPDATE COMMAND (new LA=%u) for SSI: %u", (unsigned)tlv_la, (unsigned)issi);
                else
                    mm_logf_ctx(issi, (uint16_t)la, "SwMI sent LOCATION UPDATE COMMAND for SSI: %u", (unsigned)issi);
                if (have_tlv_gssi)
                    mm_logf_ctx(issi, (uint16_t)la, "MM TLV: candidate GSSI=%u (0x%06X)", (unsigned)tlv_gssi, (unsigned)tlv_gssi);
                return (int)len;
            }

            if (type == TMM_PDU_T_D_LOC_UPD_PROC) {
                if (have_tlv_la)
                    mm_logf_ctx(issi, (uint16_t)la, "SwMI sent LOCATION UPDATE PROCEEDING (LA=%u) for SSI: %u", (unsigned)tlv_la, (unsigned)issi);
                else
                    mm_logf_ctx(issi, (uint16_t)la, "SwMI sent LOCATION UPDATE PROCEEDING for SSI: %u", (unsigned)issi);
                return (int)len;
            }

            if (type == TMM_PDU_T_D_LOC_UPD_REJ) {
                /* reject cause is vaak 5 bits; sommige implementaties stoppen 'm in 1 octet */
                mm_logf_ctx(issi, (uint16_t)la, "SwMI sent LOCATION UPDATE REJECT for SSI: %u", (unsigned)issi);
                return (int)len;
            }

            if (type == TMM_PDU_T_D_MM_STATUS) {
                mm_logf_ctx(issi, (uint16_t)la, "MM STATUS for SSI: %u", (unsigned)issi);
                return (int)len;
            }
            /* Andere MM types kun je later toevoegen (LOC_UPD_PROC, LOC_UPD_REJ, ...). */
        }
    }

    return (int)len;
}
