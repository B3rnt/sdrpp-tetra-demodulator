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

static int issi_is_real(uint32_t issi)
{
    issi &= 0xFFFFFFu;
    return (issi != 0 && issi != 0xFFFFFFu);
}

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    uint8_t *bits = msg->l3h;
    uint8_t mle_pdisc = bits_to_uint(bits, 3);

    /* We only log when we have a real ISSI */
    uint32_t issi = 0;
    if (tms) issi = (uint32_t)tms->ssi;

    if (!issi_is_real(issi)) {
        return len; /* drop broadcast/unknown noise */
    }

    /* LA is unknown here in pure C decoder: pass -1 (mm_log will use TLS if you set it from C++) */
    int la = -1;

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
        break;
    }

    case TMLE_PDISC_CMCE:
        /* optional: add CMCE logs later */
        break;

    case TMLE_PDISC_SNDCP:
        /* optional */
        break;

    default:
        break;
    }

    return len;
}
