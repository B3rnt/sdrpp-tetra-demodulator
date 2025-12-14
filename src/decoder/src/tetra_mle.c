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

static void mm_try_pretty_log(uint32_t issi, uint32_t la, const uint8_t *mm_bits, unsigned int mm_len_bits)
{
    if (!mm_bits || mm_len_bits < 4) return;
    uint8_t pdu_type = (uint8_t)bits_to_uint(mm_bits, 4);

    /* D-AUTHENTICATION = 0x1 */
    if (pdu_type == 0x1 && mm_len_bits >= 6) {
        uint8_t sub = (uint8_t)bits_to_uint(mm_bits + 4, 2);
        const char *s = mm_auth_subtype_str(sub);
        if (sub == 0) {
            mm_logf_ctx(issi, la, "Status: Authenticatie vereist (D-AUTHENTICATION %s)", s);
        } else {
            mm_logf_ctx(issi, la, "D-AUTHENTICATION %s", s);
        }
        return;
    }

    /* Location update / roaming-ish hints */
    if (pdu_type == 0x5) { /* D-LOC-UPD-ACC */
        mm_logf_ctx(issi, la, "Status: Location update accept (mogelijk roaming)");
        return;
    }
    if (pdu_type == 0x9) { /* D-LOC-UPD-PROC */
        mm_logf_ctx(issi, la, "Status: Roaming / Location update");
        return;
    }
    if (pdu_type == 0x7) { /* D-LOC-UPD-REJ */
        mm_logf_ctx(issi, la, "Status: Location update reject");
        return;
    }
    if (pdu_type == 0xC) { /* D-MM-STATUS */
        mm_logf_ctx(issi, la, "Status: MM status");
        return;
    }
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
        uint8_t mle_pdisc = (uint8_t)(((buf[0] & 1u) << 2) | ((buf[1] & 1u) << 1) | (buf[2] & 1u));

        mm_logf_ctx(issi, la, "MLE PDISC=%u (%s) [bits]",
                    (unsigned)mle_pdisc,
                    tetra_get_mle_pdisc_name(mle_pdisc));

        /* PDISC=0 is RESERVED in TETRA MLE. Treat as decode error and dump bits. */
        if (mle_pdisc == 0 || tetra_get_mle_pdisc_name(mle_pdisc) == NULL) {
            char dump[256]; dump[0] = '\0';
            unsigned int n = (len > 32) ? 32 : len;
            for (unsigned int i = 0; i < n; i++) {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%u", (unsigned)(buf[i] & 1u));
                strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
            }
            mm_logf_ctx(issi, la, "MLE PDISC=%u reserved/unknown, bits[0..%u]=%s",
                        (unsigned)mle_pdisc, n ? (n - 1) : 0, dump);
            return (int)len;
        }

        /* MM: next 4 bits are the MM PDU type (message type) */
        if (mle_pdisc == TMLE_PDISC_MM) {
            if (len < 7) {
                mm_logf_ctx(issi, la, "MM too short (%u bits), skip", (unsigned)len);
                return (int)len;
            }

            uint8_t pdu_type = (uint8_t)(((buf[3] & 1u) << 3) | ((buf[4] & 1u) << 2) |
                                         ((buf[5] & 1u) << 1) |  (buf[6] & 1u));

            /* Build MM bitstream for mm_try_pretty_log():
             * [0..3]  = MM type bits (from buf[3..6])
             * [4..]   = remaining MM bits (from buf[7..])
             */
            unsigned int mm_len_bits = 4 + (len - 7);
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
            for (unsigned int bi = 7; bi < len; bi++)
                mm_bits[o++] = (buf[bi] & 1u);

            const char *mm_short = tetra_get_mm_pdut_name(pdu_type, 0);
            mm_logf_ctx(issi, la, "MM type=0x%X (%s) [bits]",
                        (unsigned)pdu_type,
                        mm_short ? mm_short : "D-UNKNOWN");

            mm_try_pretty_log(issi, la, mm_bits, mm_len_bits);

            /* Diagnostics for reserved/unknown types */
            if (!mm_short) {
                char dump[256]; dump[0] = '\0';
                unsigned int n = (len > 64) ? 64 : len;
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

