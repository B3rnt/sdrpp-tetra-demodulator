#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
#include "tetra_cmce_pdu.h"
#include "tetra_sndcp_pdu.h"

/* ✅ nodig om tms->tcs->la te mogen gebruiken */
#include "crypto/tetra_crypto.h"

/*
 * ETSI-aligned improvements:
 *  - Type-3/4 element descriptor parsing: M(1) + ID(4) + LI(11), LI is in bits, user data right-aligned to octets.
 *  - Group identity location accept (tid 0x5) can contain nested type3/4 elements such as Group identity downlink (tid 0x7):
 *    -> recurse into payload of 0x5, scan for 0x7 inside.
 *  - Authentication result should be decoded from D-AUTH (MM pdu_type 0x1) sub-type + R1 bit,
 *    NOT from a made-up Type-3 element (removes tid==0xA auth heuristic).
 */

static const char *mm_auth_subtype_str(uint8_t st) {
    switch (st & 0x3u) {
    case 0: return "DEMAND";
    case 1: return "RESPONSE";
    case 2: return "RESULT";
    case 3: return "REJECT";
    default: return "UNKNOWN";
    }
}

/* Forward */
static void mm_try_pretty_log(uint32_t issi, uint16_t la,
                              const uint8_t *mm_bits, unsigned int mm_len_bits);

/*
 * Decode Type-3/4 MM elements using ETSI descriptor:
 *   M-bit (1) + Type-3/4 element identifier (4) + LI (11) => 16 bits total
 *   followed by LI bits of user data, right-aligned to whole octets.
 *
 * Robust scan: sliding window on bit offsets, accept only plausible descriptors (M=1, 0<LI<=2047),
 * then jump over element.
 *
 * Important: tid==0x5 (Group identity location accept) can CONTAIN nested type3/4 elements like tid==0x7,
 * so we recurse into its payload to find 0x7 and extract GSSI(s).
 */
static void mm_scan_type34_elements(const uint8_t *bits, unsigned int bitlen,
                                   unsigned int start_bit,
                                   uint32_t *out_gssi, uint8_t *out_have_gssi,
                                   uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                   uint8_t *out_cck_id, uint8_t *out_have_cck,
                                   uint8_t *out_roam_lu, uint8_t *out_have_roam_lu,
                                   uint8_t *out_itsi_attach, uint8_t *out_have_itsi_attach)
{
    if (out_have_gssi) *out_have_gssi = 0;
    if (out_gssi_count) *out_gssi_count = 0;
    if (out_have_cck)  *out_have_cck  = 0;
    if (out_have_roam_lu) *out_have_roam_lu = 0;
    if (out_have_itsi_attach) *out_have_itsi_attach = 0;

    if (!bits || bitlen <= start_bit) return;

    /* helper: add unique GSSI into caller list */
    #define ADD_GSSI(_g) do { \
        uint32_t __g = (_g) & 0x00FFFFFFu; \
        if (__g != 0u && __g != 0x00FFFFFFu && out_gssi_list && out_gssi_count && out_gssi_max) { \
            uint8_t __n = *out_gssi_count; \
            uint8_t __dup = 0; \
            for (uint8_t __i = 0; __i < __n; __i++) { if (out_gssi_list[__i] == __g) { __dup = 1; break; } } \
            if (!__dup && __n < out_gssi_max) { out_gssi_list[__n++] = __g; *out_gssi_count = __n; } \
        } \
    } while (0)

    unsigned int pos = start_bit;

    while (pos + 16u <= bitlen) {
        uint32_t mbit = bits_to_uint(bits + pos, 1);
        uint32_t tid  = bits_to_uint(bits + pos + 1, 4);
        uint32_t li   = bits_to_uint(bits + pos + 5, 11);

        /* plausibility */
        if (mbit != 1u || li == 0u || li > 2047u) { pos += 1; continue; }

        unsigned int elem_octets = 1u + (unsigned int)((li - 1u) / 8u);
        unsigned int elem_bits_total = 16u + elem_octets * 8u;
        if (pos + elem_bits_total > bitlen) { pos += 1; continue; }

        /* user data right-aligned inside elem_octets */
        unsigned int unused = (elem_octets * 8u) - (unsigned int)li;
        const uint8_t *edata = bits + pos + 16u + unused;

        /*
         * tid 0x5: Group identity location accept
         * Often contains nested type3/4 descriptors (e.g. tid 0x7) inside its payload.
         * Recurse into its LI-bit payload (edata points to start of LI bits).
         */
        if (tid == 0x5 && li >= 16u) {
            mm_scan_type34_elements(edata, li, 0,
                                    out_gssi, out_have_gssi,
                                    out_gssi_list, out_gssi_count, out_gssi_max,
                                    out_cck_id, out_have_cck,
                                    out_roam_lu, out_have_roam_lu,
                                    out_itsi_attach, out_have_itsi_attach);
        }

        /*
         * tid 0x7: Group identity downlink
         * GSSI is 24 bits inside the group identity structure; many implementations carry
         * the group identity in 32 bits with upper bits being type/flags.
         *
         * Because user data is right-aligned to octets, prefer 32-bit windows that end on octet boundaries.
         */
        if (tid == 0x7 && li >= 24u) {
            /* We search inside LI bits on octet boundaries */
            unsigned int scan_start = 0;
            while (scan_start + 32u <= li) {
                if ((scan_start % 8u) == 0u) {
                    uint32_t v32 = bits_to_uint(edata + scan_start, 32);
                    ADD_GSSI(v32);

                    /* also try exact 24-bit window at end of that dword */
                    uint32_t v24 = bits_to_uint(edata + scan_start + 8u, 24);
                    ADD_GSSI(v24);
                }
                scan_start += 8u;
            }

            if (out_gssi && out_have_gssi && out_gssi_count && *out_gssi_count) {
                *out_gssi = out_gssi_list[0] & 0x00FFFFFFu;
                *out_have_gssi = 1;
            }
        }

        /*
         * tid 0x6: CCK information (best-effort; take last octet)
         */
        if (tid == 0x6 && li >= 8u && out_cck_id && out_have_cck) {
            uint32_t v = bits_to_uint(edata + (li - 8u), 8);
            *out_cck_id = (uint8_t)v;
            *out_have_cck = 1;
        }

        /*
         * Roaming / ITSI attach flags:
         * Keep best-effort heuristics. (Networks vary; without a bitdump we cannot be fully normative here.)
         */
        if (tid == 0x2 && li >= 1u && out_roam_lu && out_have_roam_lu) {
            uint32_t v = bits_to_uint(edata + (li - 1u), 1);
            *out_roam_lu = (uint8_t)(v & 1u);
            *out_have_roam_lu = 1;
        }
        if (tid == 0x2 && li >= 2u && out_itsi_attach && out_have_itsi_attach) {
            uint32_t v = bits_to_uint(edata + (li - 2u), 1);
            *out_itsi_attach = (uint8_t)(v & 1u);
            *out_have_itsi_attach = 1;
        }

        pos += elem_bits_total;
    }

    #undef ADD_GSSI
}

/*
 * Pretty logging aligned with what SDR-TETRA shows:
 *  - D-AUTH (0x1): log DEMAND and RESULT using Authentication sub-type + 1-bit result
 *  - D-LOC-UPD-ACC (0x5): scan type3/4 elements, including nested 0x5->0x7, to extract GSSI and CCK/flags
 */
static void mm_try_pretty_log(uint32_t issi, uint16_t la,
                              const uint8_t *mm_bits, unsigned int mm_len_bits)
{
    if (!mm_bits || mm_len_bits < 4) return;

    unsigned int pos = 0;
    #define HAVE(N) (pos + (N) <= mm_len_bits)
    #define GET(N)  (HAVE(N) ? bits_to_uint(mm_bits + pos, (N)) : 0)
    #define ADV(N)  do { pos += (N); } while (0)

    uint8_t pdu_type = (uint8_t)GET(4);
    ADV(4);

    /* --- ETSI: D-AUTHENTICATION (0x1) --- */
    if (pdu_type == 0x1) {
        if (!HAVE(2)) { #undef HAVE #undef GET #undef ADV return; }
        uint8_t st = (uint8_t)GET(2);
        ADV(2);

        if (st == 0) {
            mm_logf_ctx(issi, la, "BS demands authentication: SSI: %u", (unsigned)issi);
            #undef HAVE #undef GET #undef ADV
            return;
        }

        if (st == 2 /* RESULT */ && HAVE(1)) {
            uint8_t r1 = (uint8_t)GET(1); /* Authentication result flag */
            mm_logf_ctx(issi, la,
                        "BS result to MS authentication: %s SSI: %u - %s",
                        r1 ? "Authentication successful or no authentication currently in progress"
                           : "Authentication failed or rejected",
                        (unsigned)issi,
                        r1 ? "Authentication successful or no authentication currently in progress"
                           : "Authentication failed or rejected");
            #undef HAVE #undef GET #undef ADV
            return;
        }

        /* optional: trace other subtypes very lightly */
        mm_logf_ctx(issi, la, "D-AUTH sub-type=%s SSI=%u",
                    mm_auth_subtype_str(st), (unsigned)issi);

        #undef HAVE
        #undef GET
        #undef ADV
        return;
    }

    /* --- D-LOC-UPD-ACC (0x5) --- */
    if (pdu_type == 0x5) {
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

        mm_scan_type34_elements(mm_bits, mm_len_bits, 4,
                                &gssi, &have_gssi,
                                gssi_list, &gssi_count, (uint8_t)(sizeof(gssi_list)/sizeof(gssi_list[0])),
                                &cck_id, &have_cck,
                                &roam_lu, &have_roam_lu,
                                &itsi_attach, &have_itsi_attach);

        /* Build tail similar to SDR-TETRA */
        char tail[192];
        tail[0] = 0;

        if (have_cck) {
            char tmp[64];
            snprintf(tmp, sizeof(tmp), " - CCK_identifier: %u", (unsigned)cck_id);
            strncat(tail, tmp, sizeof(tail) - strlen(tail) - 1);
        }

        if (have_roam_lu && roam_lu) {
            strncat(tail, " - Roaming location updating", sizeof(tail) - strlen(tail) - 1);
        } else if (have_itsi_attach && itsi_attach) {
            strncat(tail, " - ITSI attach", sizeof(tail) - strlen(tail) - 1);
        }

        if (have_gssi) {
            if (gssi_count > 1) {
                char gbuf[128]; gbuf[0] = 0;
                size_t o2 = 0;
                for (uint8_t i = 0; i < gssi_count; i++) {
                    char tmp[24];
                    snprintf(tmp, sizeof(tmp), "%s%u", (i ? "," : ""), (unsigned)gssi_list[i]);
                    size_t tl = strlen(tmp);
                    if (o2 + tl + 1 >= sizeof(gbuf)) break;
                    memcpy(gbuf + o2, tmp, tl);
                    o2 += tl; gbuf[o2] = 0;
                }
                mm_logf_ctx(issi, la,
                            "MS request for registration/authentication ACCEPTED for SSI: %u GSSI(s): %s%s",
                            (unsigned)issi, gbuf, tail);
            } else {
                mm_logf_ctx(issi, la,
                            "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %u%s",
                            (unsigned)issi, (unsigned)gssi, tail);
            }
        } else {
            /* still useful to show this line; tells you you *did* catch 0x5 but no GSSI parsed */
            mm_logf_ctx(issi, la,
                        "MS request for registration/authentication ACCEPTED for SSI: %u (no GSSI decoded)%s",
                        (unsigned)issi, tail);
        }

        #undef HAVE
        #undef GET
        #undef ADV
        return;
    }

    #undef HAVE
    #undef GET
    #undef ADV
}

/* Receive TL-SDU (LLC SDU == MLE PDU) */

static int ubits_to_hex(char *dst, size_t dst_len, const uint8_t *ubits, unsigned int nbits)
{
    if (!dst || dst_len == 0) return 0;
    dst[0] = '\0';
    if (!ubits || nbits == 0) return 0;

    unsigned int nbytes = (nbits + 7u) / 8u;
    if (dst_len < (size_t)(nbytes * 2u + 1u)) {
        nbytes = (unsigned int)((dst_len - 1u) / 2u);
    }

    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    for (unsigned int bi = 0; bi < nbytes; bi++) {
        uint8_t v = 0;
        for (unsigned int bit = 0; bit < 8; bit++) {
            unsigned int src = bi * 8u + bit;
            if (src >= nbits) break;
            v = (uint8_t)((v << 1) | (ubits[src] ? 1u : 0u));
        }
        dst[o++] = hex[(v >> 4) & 0xF];
        dst[o++] = hex[v & 0xF];
        if (o + 2 >= dst_len) break;
    }
    dst[o] = '\0';
    return (int)o;
}

static int issi_is_real(uint32_t issi)
{
    issi &= 0xFFFFFFu;
    return (issi != 0 && issi != 0xFFFFFFu);
}

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len < 1)
        return (int)len;

    uint32_t issi = 0;
    if (tms) issi = (uint32_t)tms->ssi;

    int la = -1;
    if (tms && tms->tcs) la = tms->tcs->la;

    /* Drop broadcast/unknown ISSI noise (0xFFFFFF) */
    if (!issi_is_real(issi))
        return (int)len;

    /* Detect "unpacked bits" representation: all bytes are 0/1 */
    int unpacked = 1;
    for (unsigned int i = 0; i < len; i++) {
        if (buf[i] > 1) { unpacked = 0; break; }
    }

    if (unpacked) {
        if (len < 3)
            return (int)len;

        unsigned int pdisc_off = 0;
        uint8_t mle_pdisc = 0;
        int found = 0;

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

            /* If MM, ensure we can read 4 bits for type (keep permissive) */
            if (pdisc == TMLE_PDISC_MM) {
                if (len < off + 3 + 4) continue;
                uint8_t mt = (uint8_t)(((buf[off+3] & 1u) << 3) | ((buf[off+4] & 1u) << 2) |
                                       ((buf[off+5] & 1u) << 1) |  (buf[off+6] & 1u));
                if (mt > 0xF) continue;
            }

            pdisc_off = off;
            mle_pdisc = pdisc;
            found = 1;
            break;
        }

        if (!found) {
            char dump[256]; dump[0] = '\0';
            unsigned int n = (len > 32) ? 32 : len;
            for (unsigned int i = 0; i < n; i++) {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%u", (unsigned)(buf[i] & 1u));
                strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
            }
#ifdef TETRA_VERBOSE_MLE
            mm_logf_ctx(issi, la, "MLE PDISC=%u reserved/unknown, bits[0..%u]=%s",
                        (unsigned)mle_pdisc, n ? (n - 1) : 0, dump);
#endif
            return (int)len;
        }

        if (pdisc_off != 0) {
            mm_logf_ctx(issi, la, "MLE bit-align shift=%u", pdisc_off);
        }

        mm_logf_ctx(issi, la, "MLE PDISC=%u (%s) [bits]",
                    (unsigned)mle_pdisc,
                    tetra_get_mle_pdisc_name(mle_pdisc));

        if (mle_pdisc == 0 || tetra_get_mle_pdisc_name(mle_pdisc) == NULL) {
            char dump[256]; dump[0] = '\0';
            unsigned int n = (len > 32) ? 32 : len;
            for (unsigned int i = 0; i < n; i++) {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%u", (unsigned)(buf[i] & 1u));
                strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
            }
#ifdef TETRA_VERBOSE_MLE
            mm_logf_ctx(issi, la, "MLE PDISC=%u reserved/unknown, bits[0..%u]=%s",
                        (unsigned)mle_pdisc, n ? (n - 1) : 0, dump);
#endif
            return (int)len;
        }

        /* MM: next 4 bits are the MM PDU type */
        if (mle_pdisc == TMLE_PDISC_MM) {
            unsigned int mm_type_off = pdisc_off + 3;
            unsigned int mm_payload_off = pdisc_off + 7;

            if (len < mm_payload_off) {
                mm_logf_ctx(issi, la, "MM too short (%u bits), skip", (unsigned)len);
                return (int)len;
            }

            uint8_t pdu_type = (uint8_t)(((buf[mm_type_off + 0] & 1u) << 3) |
                                         ((buf[mm_type_off + 1] & 1u) << 2) |
                                         ((buf[mm_type_off + 2] & 1u) << 1) |
                                          (buf[mm_type_off + 3] & 1u));

            unsigned int mm_len_bits = 4 + (len - mm_payload_off);
            if (mm_len_bits > 4096) {
                mm_logf_ctx(issi, la, "MM too long (%u bits), skip", mm_len_bits);
                return (int)len;
            }

            uint8_t mm_bits[4096];
            mm_bits[0] = (pdu_type >> 3) & 1u;
            mm_bits[1] = (pdu_type >> 2) & 1u;
            mm_bits[2] = (pdu_type >> 1) & 1u;
            mm_bits[3] = (pdu_type >> 0) & 1u;

            unsigned int o = 4;
            for (unsigned int bi = mm_payload_off; bi < len; bi++)
                mm_bits[o++] = (buf[bi] & 1u);

            const char *mm_short = tetra_get_mm_pdut_name(pdu_type, 0);
            mm_logf_ctx(issi, la, "MM type=0x%X (%s) [bits]",
                        (unsigned)pdu_type,
                        mm_short ? mm_short : "D-UNKNOWN");

            /* ETSI-aligned pretty logging for D-AUTH (0x1) and D-LOC-UPD-ACC (0x5) */
            mm_try_pretty_log(issi, la, mm_bits, mm_len_bits);

            if (!mm_short) {
                char dump[256]; dump[0] = '\0';
                unsigned int n = (len > 32) ? 32 : len;
                for (unsigned int i = 0; i < n; i++) {
                    char tmp[4];
                    snprintf(tmp, sizeof(tmp), "%u", (unsigned)(buf[i] & 1u));
                    strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
                }
                mm_logf_ctx(issi, la, "MM unknown, bits[0..%u]=%s", n ? (n - 1) : 0, dump);
            }
            return (int)len;
        }

        /* Non-MM PDISC (CMCE/SNDCP/etc.) not decoded in this fork */
        return (int)len;
    }

    /* ----- Packed octets path ----- */
    const uint8_t *oct = buf;

    /* Primary interpretation: low nibble is PDISC, high nibble is PDU type */
    uint8_t mle_pdisc = (uint8_t)(oct[0] & 0x0F);
    uint8_t pdu_type  = (uint8_t)((oct[0] >> 4) & 0x0F);

    /* Sanity fallback: some stacks swap nibbles */
    uint8_t mle_pdisc_alt = (uint8_t)((oct[0] >> 4) & 0x0F);
    uint8_t pdu_type_alt  = (uint8_t)(oct[0] & 0x0F);

    int used_alt = 0;
    if ((mle_pdisc == 0 || tetra_get_mle_pdisc_name(mle_pdisc) == NULL) &&
        (mle_pdisc_alt != 0 && tetra_get_mle_pdisc_name(mle_pdisc_alt) != NULL)) {
        mle_pdisc = mle_pdisc_alt;
        pdu_type  = pdu_type_alt;
        used_alt = 1;
    }

    mm_logf_ctx(issi, la, "MLE PDISC=%u (%s)%s [octets]",
                (unsigned)mle_pdisc,
                tetra_get_mle_pdisc_name(mle_pdisc),
                used_alt ? " [nibble-swap]" : "");

    if (mle_pdisc == 0 || tetra_get_mle_pdisc_name(mle_pdisc) == NULL) {
        char dump[256]; dump[0] = '\0';
        unsigned int n = (len > 16) ? 16 : len;
        for (unsigned int i = 0; i < n; i++) {
            char tmp[8];
            snprintf(tmp, sizeof(tmp), "%02X", oct[i]);
            strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
            if (i + 1 < n) strncat(dump, " ", sizeof(dump) - strlen(dump) - 1);
        }
        mm_logf_ctx(issi, la, "MLE PDISC=%u reserved/unknown, octets[0..%u]=%s",
                    (unsigned)mle_pdisc, n ? (n - 1) : 0, dump);
        return (int)len;
    }

    switch (mle_pdisc) {
    case TMLE_PDISC_MM: {
        const unsigned int mm_len_bits = 4 + (len - 1) * 8;
        if (mm_len_bits > 4096) {
            mm_logf_ctx(issi, la, "MM too long (%u bits), skip", mm_len_bits);
            return (int)len;
        }
        uint8_t mm_bits[4096];
        mm_bits[0] = (pdu_type >> 3) & 1u;
        mm_bits[1] = (pdu_type >> 2) & 1u;
        mm_bits[2] = (pdu_type >> 1) & 1u;
        mm_bits[3] = (pdu_type >> 0) & 1u;

        unsigned int o = 4;
        for (unsigned int bi = 1; bi < len; bi++) {
            uint8_t b = oct[bi];
            mm_bits[o++] = (b >> 7) & 1u;
            mm_bits[o++] = (b >> 6) & 1u;
            mm_bits[o++] = (b >> 5) & 1u;
            mm_bits[o++] = (b >> 4) & 1u;
            mm_bits[o++] = (b >> 3) & 1u;
            mm_bits[o++] = (b >> 2) & 1u;
            mm_bits[o++] = (b >> 1) & 1u;
            mm_bits[o++] = (b >> 0) & 1u;
        }

        const char *mm_short = tetra_get_mm_pdut_name(pdu_type, 0);
        mm_logf_ctx(issi, la, "MM type=0x%X (%s) [octets]",
                    (unsigned)pdu_type,
                    mm_short ? mm_short : "D-UNKNOWN");

        mm_try_pretty_log(issi, la, mm_bits, mm_len_bits);

        if (!mm_short) {
            char dump[256]; dump[0] = '\0';
            unsigned int n = (len > 16) ? 16 : len;
            for (unsigned int i = 0; i < n; i++) {
                char tmp[8];
                snprintf(tmp, sizeof(tmp), "%02X", oct[i]);
                strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
                if (i + 1 < n) strncat(dump, " ", sizeof(dump) - strlen(dump) - 1);
            }
            mm_logf_ctx(issi, la, "MM unknown, octets[0..%u]=%s", n ? (n - 1) : 0, dump);
        }

        return (int)len;
    }
    default:
        break;
    }

    return (int)len;
}
