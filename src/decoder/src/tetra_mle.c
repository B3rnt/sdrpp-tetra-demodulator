#include <stdint.h>
#include <stdio.h>
// #include <unistd.h>
#include <string.h>

// #include <osmocom/core/msgb.h>
// #include <osmocom/core/talloc.h>
// #include <osmocom/core/bits.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
#include "tetra_cmce_pdu.h"
#include "tetra_sndcp_pdu.h"
#include "tetra_mle_pdu.h"


//TODO: stole D-* parser from sq5bpf

/* Receive TL-SDU (LLC SDU == MLE PDU) */

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    uint8_t *bits = msg->l3h;
    uint8_t mle_pdisc = bits_to_uint(bits, 3);

    /* Log altijd PDISC + SSI context */
    {
        char b[128];

        if (tms && tms->ssi) {
            snprintf(b, sizeof(b),
                     "ISSI=%u (0x%06X) MLE PDISC=%u (%s)",
                     (unsigned)tms->ssi, (unsigned)tms->ssi,
                     (unsigned)mle_pdisc, tetra_get_mle_pdisc_name(mle_pdisc));
        } else {
            snprintf(b, sizeof(b),
                     "ISSI=UNKNOWN MLE PDISC=%u (%s)",
                     (unsigned)mle_pdisc, tetra_get_mle_pdisc_name(mle_pdisc));
        }

        mm_log(b);
    }

    switch (mle_pdisc) {
    case TMLE_PDISC_MM: {
        /* MM PDU type is 4 bits starting at bit 3 */
        uint8_t mm_type = bits_to_uint(bits + 3, 4);
        const char *mm_name = tetra_get_mm_pdut_name(mm_type, 0);

        char b[160];
        if (tms && tms->ssi) {
            snprintf(b, sizeof(b),
                     "ISSI=%u (0x%06X) MM type=0x%X (%s)",
                     (unsigned)tms->ssi, (unsigned)tms->ssi,
                     (unsigned)mm_type, mm_name);
        } else {
            snprintf(b, sizeof(b),
                     "ISSI=UNKNOWN MM type=0x%X (%s)",
                     (unsigned)mm_type, mm_name);
        }
        mm_log(b);
        break;
    }

    case TMLE_PDISC_CMCE:
        /* optioneel */
        break;

    case TMLE_PDISC_SNDCP:
        /* optioneel */
        break;

    default:
        break;
    }

    return len;
}
