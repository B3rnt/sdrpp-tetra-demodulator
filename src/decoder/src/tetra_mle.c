#include <stdint.h>
#include <stdio.h>
// #include <unistd.h>
#include <string.h>

// #include <osmocom/core/msgb.h>
// #include <osmocom/core/talloc.h>
// #include <osmocom/core/bits.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "tetra_mm_pdu.h"
#include "tetra_cmce_pdu.h"
#include "tetra_sndcp_pdu.h"
#include "tetra_mle_pdu.h"
#include "mm_log.h"   // toevoegen bovenin

//TODO: stole D-* parser from sq5bpf

/* Receive TL-SDU (LLC SDU == MLE PDU) */

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    uint8_t *bits = msg->l3h;
    uint8_t mle_pdisc = bits_to_uint(bits, 3);

    // debug: laat zien welke PDISC je überhaupt krijgt
    {
        char b[64];
        snprintf(b, sizeof(b), "MLE PDISC=%u (%s)", mle_pdisc, tetra_get_mle_pdisc_name(mle_pdisc));
        mm_log(b);
    }

    switch (mle_pdisc) {
    case TMLE_PDISC_MM:
        tetra_get_mm_pdut_name(bits_to_uint(bits+3, 4), 0);
        break;
    case TMLE_PDISC_CMCE:
        // eventueel ook loggen
        // tetra_get_cmce_pdut_name(bits_to_uint(bits+3, 5), 0);
        break;
    case TMLE_PDISC_SNDCP:
        // dit bevestigt “ik zat op een data kanaal”
        // mm_log("SNDCP TL-SDU");
        break;
    default:
        break;
    }
    return len;
}
