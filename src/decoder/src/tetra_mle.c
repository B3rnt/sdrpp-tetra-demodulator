#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
#include "tetra_cmce_pdu.h"
#include "tetra_sndcp_pdu.h"

/* Receive TL-SDU (LLC SDU == MLE PDU) */

static int ubits_to_hex(char *dst, size_t dst_len, const uint8_t *ubits, unsigned int nbits)
{
    if (!dst || dst_len == 0) return 0;
    dst[0] = '\0';
    if (!ubits || nbits == 0) return 0;

    unsigned int nbytes = (nbits + 7u) / 8u;
    /* Each byte => 2 hex chars, plus NUL */
    if (dst_len < (size_t)(nbytes * 2u + 1u)) {
        /* best effort: truncate output */
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
    uint8_t *bits = msg->l3h;
    uint8_t mle_pdisc = bits_to_uint(bits, 3);

    /* Prefer the MAC-level addressed SSI (24-bit). */
    uint32_t issi = 0;
    if (tms) issi = (uint32_t)tms->ssi;

    /* LA is maintained by the decoder state (set from SYSINFO). */
    int la = -1;
    if (tms && tms->tcs) la = tms->tcs->la;

    /* Drop broadcast / unknown ISSI noise (0xFFFFFF). */
    if (!issi_is_real(issi)) {
        return len;
    }

    mm_logf_ctx(issi, la, "MLE PDISC=%u (%s)",
                (unsigned)mle_pdisc, tetra_get_mle_pdisc_name(mle_pdisc));

    switch (mle_pdisc) {
    case TMLE_PDISC_MM: {
        /* MM PDU type is 4 bits starting at bit 3 */
        uint8_t mm_type = bits_to_uint(bits + 3, 4);
        const char *mm_short = tetra_get_mm_pdut_name(mm_type, 0);

        mm_logf_ctx(issi, la, "MM type=0x%X (%s)",
                    (unsigned)mm_type,
                    mm_short ? mm_short : "D-UNKNOWN");

        /* Log the raw MM PDU payload (everything after pdisc+type) */
        if (len > 7) {
            unsigned int payload_bits = len - 7;
            const uint8_t *payload = bits + 7;

            char hexbuf[768];
            ubits_to_hex(hexbuf, sizeof(hexbuf), payload, payload_bits);

            mm_logf_ctx(issi, la, "MM payloadbits=%u hex=%s", payload_bits, hexbuf);
        }
        break;
    }

    case TMLE_PDISC_CMCE:
        break;

    case TMLE_PDISC_SNDCP:
        break;

    default:
        break;
    }

    return len;
}
