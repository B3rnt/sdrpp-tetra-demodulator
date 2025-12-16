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


static const char *mm_auth_subtype_str(uint8_t st) {
    switch (st & 0x3u) {
    case 0: return "DEMAND";
    case 1: return "RESPONSE";
    case 2: return "RESULT";
    case 3: return "REJECT";
    default: return "UNKNOWN";
    }
}

/*
 * Some MM PDUs (notably D-LOC-UPD-ACC / D-LOC-UPD-PROC) carry so-called
 * "Type-34" elements. Different networks/PDUs place these at slightly
 * different offsets; to be robust we scan the bitstream for known element
 * headers instead of relying on a single fixed layout.
 *
 * Element header: elementType (2 bits) + elementId (4 bits)
 * We care about (elementType==3):
 *   - eid 0x5 : Group identity location accept (GSSI list)
 *   - eid 0x6 : CCK information (CCK_identifier)
 *   - eid 0xA : Authentication downlink (auth result)
 */

static void mm_scan_type34_elements(const uint8_t *bits, unsigned int bitlen,
                                   unsigned int start_bit,
                                   uint32_t *out_gssi, uint8_t *out_have_gssi,
                                   uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                   uint8_t *out_cck_id, uint8_t *out_have_cck,
                                   uint8_t *out_auth_ok, uint8_t *out_have_auth,
                                   uint8_t *out_roam_lu, uint8_t *out_have_roam_lu,
                                   uint8_t *out_itsi_attach, uint8_t *out_have_itsi_attach)
{
    /* This function decodes *Type-3* MM elements as defined by the ETSI "type 3 element descriptor":
       M-bit (1) + Type 3 MM element identifier (4) + Length Indicator (11)  => 16 bits,
       followed by the element user data right-aligned to whole octets.
       (See TS 100 392-5, clause describing figure "Structure of type 3 Element Identifier"). */

    if (out_have_gssi) *out_have_gssi = 0;
    if (out_gssi_count) *out_gssi_count = 0;
    if (out_have_cck)  *out_have_cck  = 0;
    if (out_have_auth) *out_have_auth = 0;
    if (out_have_roam_lu) *out_have_roam_lu = 0;
    if (out_have_itsi_attach) *out_have_itsi_attach = 0;

    if (!bits || bitlen <= start_bit) return;

    /*
     * Robust scanning strategy:
     * Some networks do *not* place Type-3 elements immediately after the MM PDU type field.
     * Instead of assuming a contiguous list of descriptors, we do a sliding-window scan
     * for plausible Type-3 descriptors (M=1, LI sane) and then jump over the element.
     */
    unsigned int pos = start_bit;

    while (pos + 16 <= bitlen) {
        /* Peek descriptor at current bit offset (do NOT advance unless it's plausible) */
        uint32_t mbit = bits_to_uint(bits + pos, 1);
        uint32_t tid  = bits_to_uint(bits + pos + 1, 4);
        uint32_t li   = bits_to_uint(bits + pos + 5, 11);

        /* Quick plausibility checks to avoid false positives */
        if (mbit != 1u || li == 0u || li > 2047u) {
            pos += 1;
            continue;
        }

        unsigned int elem_octets = 1u + (unsigned int)((li - 1u) / 8u);
        unsigned int elem_bits_total = 16u + elem_octets * 8u;
        if (pos + elem_bits_total > bitlen) {
            pos += 1;
            continue;
        }

        /* User data is right-aligned within elem_octets octets */
        unsigned int unused = (elem_octets * 8u) - (unsigned int)li;
        const uint8_t *edata = bits + pos + 16u + unused;

        /* Best-effort extraction of the fields SDR-TETRA shows in the summary line. */
        if ((tid == 0x5 || tid == 0x7) && li >= 32) {
            /*
             * 0x5: Group identity location accept (can embed one or more 32-bit "group identity downlink" items)
             * 0x7: Group identity downlink (often exactly 32 bits)
             *
             * ETSI describes GSSI as 24 bits inside the group identity. In practice we:
             *  - Prefer the LAST 32 bits (matches many traces)
             *  - Also scan for any other 32-bit-aligned chunks and keep a small unique list.
             */
            /* helper: add unique GSSI into caller-provided list */
            #define ADD_GSSI(_g) do { \
                uint32_t __g = (_g) & 0x00FFFFFFu; \
                if (__g != 0u && out_gssi_list && out_gssi_count && out_gssi_max) { \
                    uint8_t __n = *out_gssi_count; \
                    uint8_t __dup = 0; \
                    for (uint8_t __i = 0; __i < __n; __i++) { if (out_gssi_list[__i] == __g) { __dup = 1; break; } } \
                    if (!__dup && __n < out_gssi_max) { out_gssi_list[__n++] = __g; *out_gssi_count = __n; } \
                } \
            } while (0)

            /* preferred: last 32 bits */
            uint32_t v_last = bits_to_uint(edata + (li - 32), 32);
            ADD_GSSI(v_last);

            /* scan other 32-bit windows on byte boundaries */
            unsigned int scan_bits = li;
            unsigned int scan_start = 0;
            while (scan_start + 32u <= scan_bits) {
                if ((scan_start % 8u) == 0u) {
                    uint32_t v = bits_to_uint(edata + scan_start, 32);
                    ADD_GSSI(v);
                }
                scan_start += 8u;
            }

            #undef ADD_GSSI

            /* keep legacy single-value outputs (first item in list) */
            if (out_gssi && out_have_gssi && out_gssi_count && *out_gssi_count) {
                *out_gssi = out_gssi_list[0] & 0x00FFFFFFu;
                *out_have_gssi = 1;
            }
        } else if (tid == 0x6 && li >= 8 && out_cck_id && out_have_cck) {
            /* CCK information: CCK_identifier (we take the last octet) */
            uint32_t v = bits_to_uint(edata + (li - 8), 8);
            *out_cck_id = (uint8_t)v;
            *out_have_cck = 1;
        } else if (tid == 0xA && li >= 1 && out_auth_ok && out_have_auth) {
            /* Authentication downlink: treat LSB as auth_ok flag (network specific); still useful. */
            uint32_t v = bits_to_uint(edata + (li - 1), 1);
            *out_auth_ok = (uint8_t)(v & 1u);
            *out_have_auth = 1;
        }

        /* Heuristics for roaming / ITSI attach flags:
           Some networks include these as 1-bit flags inside the same type-3 element payload.
           We keep the older "best-effort" semantics: if present, take the last bit(s). */
        if (tid == 0x2 && li >= 1 && out_roam_lu && out_have_roam_lu) {
            uint32_t v = bits_to_uint(edata + (li - 1), 1);
            *out_roam_lu = (uint8_t)(v & 1u);
            *out_have_roam_lu = 1;
        }
        if (tid == 0x2 && li >= 2 && out_itsi_attach && out_have_itsi_attach) {
            /* Often encoded as a separate flag bit; take second-last as a fallback. */
            uint32_t v = bits_to_uint(edata + (li - 2), 1);
            *out_itsi_attach = (uint8_t)(v & 1u);
            *out_have_itsi_attach = 1;
        }

        /* Jump over the element we just consumed */
        pos += elem_bits_total;
    }
}


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

    /* We only pretty-log the "registration/authentication accepted" style lines for
       D-LOC-UPD-ACC (0x5). This is where SDR-TETRA prints GSSI/CCK/roaming flags. */
    if (pdu_type != 0x5) {
#undef HAVE
#undef GET
#undef ADV
        return;
    }

    uint32_t gssi = 0;
    uint8_t  have_gssi = 0;
    uint32_t gssi_list[8];
    uint8_t  gssi_count = 0;
    uint8_t  cck_id = 0;
    uint8_t  have_cck = 0;
    uint8_t  auth_ok = 0;
    uint8_t  have_auth = 0;
    uint8_t  roam_lu = 0;
    uint8_t  have_roam_lu = 0;
    uint8_t  itsi_attach = 0;
    uint8_t  have_itsi_attach = 0;

    mm_scan_type34_elements(mm_bits, mm_len_bits, 4,
                           &gssi, &have_gssi,
                           gssi_list, &gssi_count, (uint8_t)(sizeof(gssi_list) / sizeof(gssi_list[0])),
                           &cck_id, &have_cck,
                           &auth_ok, &have_auth,
                           &roam_lu, &have_roam_lu,
                           &itsi_attach, &have_itsi_attach);

    /* "BS result ..." */
    if (have_auth) {
        mm_logf_ctx(issi, la,
            "BS result to MS authentication: %s SSI: %u - %s",
            auth_ok ? "Authentication successful or no authentication currently in progress"
                    : "Authentication failed or rejected",
            issi,
            auth_ok ? "Authentication successful or no authentication currently in progress"
                    : "Authentication failed or rejected");
    }

    /* "MS request ..." (only when auth_ok=true, to avoid garbage hits) */
    if (have_auth && auth_ok) {
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
            char gbuf[128];
            gbuf[0] = 0;
            if (gssi_count > 1) {
                /* show a short list of unique GSSI values we detected */
                size_t o = 0;
                for (uint8_t i = 0; i < gssi_count; i++) {
                    char tmp[24];
                    snprintf(tmp, sizeof(tmp), "%s%u", (i ? "," : ""), (unsigned)(gssi_list[i] & 0x00FFFFFFu));
                    size_t tl = strlen(tmp);
                    if (o + tl + 1 >= sizeof(gbuf)) break;
                    memcpy(gbuf + o, tmp, tl);
                    o += tl;
                    gbuf[o] = 0;
                }
                mm_logf_ctx(issi, la,
                    "MS request for registration/authentication accepted - location update/registration successful or no authentication currently in progress - GSSI(s): %s%s",
                    gbuf, tail);
            } else {
                mm_logf_ctx(issi, la,
                    "MS request for registration/authentication accepted - location update/registration successful or no authentication currently in progress - GSSI: %u%s",
                    (unsigned)gssi, tail);
            }
        } else {
            mm_logf_ctx(issi, la,
                "MS request for registration/authentication accepted - location update/registration successful or no authentication currently in progress%s",
                tail);
        }
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
    /* NOTE:
     * In this project the TL-SDU sometimes arrives as:
     *   A) unpacked bits: each byte is 0/1 (len == number of bits)
     *   B) octets/bytes: regular packed bytes (len == number of bytes)
     *
     * Older forks assumed (B) and masked nibbles, which fails hard if (A) is actually passed in.
     * This function now auto-detects and handles BOTH formats robustly.
     */
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

    /* ----- Helper lambdas (C89-friendly) ----- */
    /* Detect "unpacked bits" representation: all bytes are 0/1 */
    int unpacked = 1;
    for (unsigned int i = 0; i < len; i++) {
        if (buf[i] > 1) { unpacked = 0; break; }
    }

    if (unpacked) {
        /* buf[] is bits (0/1). MLE protocol discriminator is 3 bits at offset 0. */
        if (len < 3)
            return (int)len;

        /* MSB-first bit accumulation, same semantics as osmo-tetra bits_to_uint() */
        unsigned int pdisc_off = 0;
        uint8_t mle_pdisc = 0;
        int found = 0;

        /* In unpacked-bits mode we sometimes see a small bit-shift (0..7).
         * Search for a plausible PDISC (and for MM also a plausible MM type). */
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

            /* If MM, ensure we can read 4 bits for type and that it is at least somewhat sane. */
            if (pdisc == TMLE_PDISC_MM) {
                if (len < off + 3 + 4) continue;
                uint8_t mt = (uint8_t)(((buf[off+3] & 1u) << 3) | ((buf[off+4] & 1u) << 2) |
                                       ((buf[off+5] & 1u) << 1) |  (buf[off+6] & 1u));
                /* Common MM types we care about; keep this permissive. */
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

/* MM: next 4 bits are the MM PDU type (message type) */
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

            /* Build MM bitstream for mm_try_pretty_log():
             * [0..3]  = MM type bits
             * [4..]   = remaining MM bits
             */
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
	            const char *mm_short = NULL;
	            mm_short = tetra_get_mm_pdut_name(pdu_type, 0);
	            mm_logf_ctx(issi, la, "MM type=0x%X (%s) [bits]",
	                        (unsigned)pdu_type,
	                        mm_short ? mm_short : "D-UNKNOWN");

	            /* Produce SDR-TETRA-like summary lines (GSSI/CCK/auth result, etc.) when present */
	            mm_try_pretty_log(issi, la, mm_bits, mm_len_bits);

            /* Diagnostics for reserved/unknown types */
            if (!mm_short) {
                char dump[256]; dump[0] = '\0';
                unsigned int n = (len > 32) ? 32 : len;
                for (unsigned int i = 0; i < n; i++) {
                    char tmp[4];
                    snprintf(tmp, sizeof(tmp), "%u", (unsigned)(buf[i] & 1u));
                    strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
                }
                mm_logf_ctx(issi, la, "MM unknown, bits[0..%u]=%s",
                            n ? (n - 1) : 0, dump);
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

    /* Sanity fallback: some stacks swap nibbles; auto-detect if it makes the packet plausible. */
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
        /* Build MM bitstream: first 4 bits are pdu_type (high nibble of octet0),
         * followed by all bits of subsequent octets (MSB-first). Low nibble (PDISC) is excluded.
         */
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
