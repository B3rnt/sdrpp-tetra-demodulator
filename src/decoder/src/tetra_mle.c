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
    uint8_t *bits = msg->l3h;
    uint8_t mle_pdisc = bits_to_uint(bits, 3);

    uint32_t issi = 0;
    if (tms) issi = (uint32_t)tms->ssi;

    int la = -1;
    if (tms && tms->tcs) la = tms->tcs->la;

    /* Drop broadcast/unknown ISSI noise (0xFFFFFF) */
    if (!issi_is_real(issi)) {
        return len;
    }

    mm_logf_ctx(issi, la, "MLE PDISC=%u (%s)",
                (unsigned)mle_pdisc, tetra_get_mle_pdisc_name(mle_pdisc));

    switch (mle_pdisc) {
    case TMLE_PDISC_MM: {
        uint8_t mm_type = bits_to_uint(bits + 3, 4);
        const char *mm_short = tetra_get_mm_pdut_name(mm_type, 0);

        mm_logf_ctx(issi, la, "MM type=0x%X (%s)",
                    (unsigned)mm_type,
                    mm_short ? mm_short : "D-UNKNOWN");

        
        /* Add a few human-friendly status messages (SDR#-style) */
        mm_try_pretty_log(issi, la, bits + 3, len - 3);
/* Log raw MM payload (everything after pdisc+type) */
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
