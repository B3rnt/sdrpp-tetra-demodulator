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
    /* In this fork, msg->l3h points to octets (not unpacked bits). The first octet contains:
     *   high nibble: MM/CMCE/etc PDU type (if applicable)
     *   low  nibble: MLE protocol discriminator (PDISC)
     */
    const uint8_t *oct = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!oct || len < 1)
        return (int)len;

    uint32_t issi = 0;
    if (tms) issi = (uint32_t)tms->ssi;

    int la = -1;
    if (tms && tms->tcs) la = tms->tcs->la;

    /* Drop broadcast/unknown ISSI noise (0xFFFFFF) */
    if (!issi_is_real(issi))
        return (int)len;

    /* Primary interpretation (as used by tetra_upper_mac.c debug): low nibble is PDISC */
    uint8_t mle_pdisc = (uint8_t)(oct[0] & 0x0F);
    uint8_t pdu_type  = (uint8_t)((oct[0] >> 4) & 0x0F);

    /* Sanity fallback: some stacks swap nibbles; auto-detect if it makes the packet plausible. */
    uint8_t mle_pdisc_alt = (uint8_t)((oct[0] >> 4) & 0x0F);
    uint8_t pdu_type_alt  = (uint8_t)(oct[0] & 0x0F);

    int used_alt = 0;
    if ((mle_pdisc == 0 || tetra_get_mle_pdisc_name(mle_pdisc) == NULL) &&
        (mle_pdisc_alt != 0 && tetra_get_mle_pdisc_name(mle_pdisc_alt) != NULL)) {
        /* Prefer alt if it yields a known discriminator */
        mle_pdisc = mle_pdisc_alt;
        pdu_type  = pdu_type_alt;
        used_alt = 1;
    }

    mm_logf_ctx(issi, la, "MLE PDISC=%u (%s)%s",
                (unsigned)mle_pdisc,
                tetra_get_mle_pdisc_name(mle_pdisc),
                used_alt ? " [nibble-swap]" : "");

    /* If PDISC is reserved/unknown, log a short dump to help debug bit-slip/FEC issues */
    if (mle_pdisc == 0 || tetra_get_mle_pdisc_name(mle_pdisc) == NULL) {
        char dump[256];
        dump[0] = '\0';
        /* dump first up to 16 bytes */
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
        /* cap to avoid huge stack allocations if something goes wrong */
        if (mm_len_bits > 4096) {
            mm_logf_ctx(issi, la, "MM too long (%u bits), skip", mm_len_bits);
            return (int)len;
        }
        uint8_t mm_bits[4096];
        /* pdu_type bits MSB-first */
        mm_bits[0] = (pdu_type >> 3) & 1;
        mm_bits[1] = (pdu_type >> 2) & 1;
        mm_bits[2] = (pdu_type >> 1) & 1;
        mm_bits[3] = (pdu_type >> 0) & 1;

        unsigned int o = 4;
        for (unsigned int bi = 1; bi < len; bi++) {
            uint8_t b = oct[bi];
            mm_bits[o++] = (b >> 7) & 1;
            mm_bits[o++] = (b >> 6) & 1;
            mm_bits[o++] = (b >> 5) & 1;
            mm_bits[o++] = (b >> 4) & 1;
            mm_bits[o++] = (b >> 3) & 1;
            mm_bits[o++] = (b >> 2) & 1;
            mm_bits[o++] = (b >> 1) & 1;
            mm_bits[o++] = (b >> 0) & 1;
        }

        const char *mm_short = tetra_get_mm_pdut_name(pdu_type, 0);
        mm_logf_ctx(issi, la, "MM type=0x%X (%s)",
                    (unsigned)pdu_type,
                    mm_short ? mm_short : "D-UNKNOWN");

        /* Pretty SDR#-style status logs (authentication/roaming/etc.) */
        mm_try_pretty_log(issi, la, mm_bits, mm_len_bits);

        /* If type is reserved/unknown, dump first bytes for diagnostics */
        if (!mm_short || !strcmp(mm_short, "D-UNKNOWN") || pdu_type == 0x8 || pdu_type == 0xD || pdu_type == 0xE) {
            char dump[256];
            dump[0] = '\0';
            unsigned int n = (len > 16) ? 16 : len;
            for (unsigned int i = 0; i < n; i++) {
                char tmp[8];
                snprintf(tmp, sizeof(tmp), "%02X", oct[i]);
                strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
                if (i + 1 < n) strncat(dump, " ", sizeof(dump) - strlen(dump) - 1);
            }
            mm_logf_ctx(issi, la, "MM diag octets[0..%u]=%s", n ? (n - 1) : 0, dump);
        }

        return (int)len;
    }

    case TMLE_PDISC_CMCE:
        /* TODO: add CMCE pretty logging if desired */
        break;

    case TMLE_PDISC_SNDCP:
        /* TODO: add SNDCP pretty logging if desired */
        break;

    default:
        break;
    }

    return (int)len;
}
