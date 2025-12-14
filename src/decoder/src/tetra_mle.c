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
int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    uint8_t *bits = msg->l3h;
    uint8_t mle_pdisc = bits_to_uint(bits, 3);

    /* Alleen loggen als er een echte ISSI/SSI is */
    uint32_t issi = 0;
    if (tms) {
        issi = (uint32_t)tms->ssi;
    }
    issi &= 0xFFFFFFu;

    /* Drop unknown/ broadcast */
    if (issi == 0 || issi == 0xFFFFFFu) {
        return len;
    }

    /* MLE PDISC */
    mm_logf_with_ctx(issi,
                     "MLE PDISC=%u (%s)",
                     (unsigned)mle_pdisc,
                     tetra_get_mle_pdisc_name(mle_pdisc));

    switch (mle_pdisc) {
    case TMLE_PDISC_MM: {
        /* MM PDU type is 4 bits starting at bit 3 */
        uint8_t mm_type = bits_to_uint(bits + 3, 4);
        const char *mm_name = tetra_get_mm_pdut_name(mm_type, 0);

        mm_logf_with_ctx(issi,
                         "MM type=0x%X (%s)",
                         (unsigned)mm_type,
                         mm_name ? mm_name : "D-UNKNOWN");
        break;
    }

    case TMLE_PDISC_CMCE:
        /* optioneel: later uitbreiden */
        break;

    case TMLE_PDISC_SNDCP:
        /* optioneel: later uitbreiden */
        break;

    default:
        break;
    }

    return len;
}
