#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
#include "tetra_cmce_pdu.h"
#include "tetra_sndcp_pdu.h"
#include "tetra_mle_pdu.h"

/* Receive TL-SDU (LLC SDU == MLE PDU) */
int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    uint8_t *bits = msg->l3h;
    uint8_t mle_pdisc = bits_to_uint(bits, 3);

    /* Log altijd PDISC + SSI context */
    {
        if (tms && tms->ssi) {
            // LA ophalen (bijvoorbeeld van de decoder of uit context)
            int la = _this->osmotetradecoder.getLA(); // Zorg ervoor dat la echt wordt ingevuld

            // Log MLE PDISC met echte ISSI
            mm_logf_with_ctx(tms->ssi, la, "MLE PDISC=%u (%s) ISSI=%u (0x%06X)",
                             (unsigned)mle_pdisc, tetra_get_mle_pdisc_name(mle_pdisc),
                             (unsigned)tms->ssi, (unsigned)tms->ssi);
        } else {
            // Als ISSI onbekend is
            mm_logf_with_ctx(0, -1, "MLE PDISC=%u (%s) ISSI=UNKNOWN",
                             (unsigned)mle_pdisc, tetra_get_mle_pdisc_name(mle_pdisc));
        }
    }

    switch (mle_pdisc) {
    case TMLE_PDISC_MM: {
        /* MM PDU type is 4 bits starting at bit 3 */
        uint8_t mm_type = bits_to_uint(bits + 3, 4);
        const char *mm_name = tetra_get_mm_pdut_name(mm_type, 0);

        if (tms && tms->ssi) {
            // LA ophalen (optioneel)
            int la = _this->osmotetradecoder.getLA(); // Zorg ervoor dat la echt wordt ingevuld

            // Log MM type met echte ISSI
            mm_logf_with_ctx(tms->ssi, la, "MM type=0x%X (%s) ISSI=%u (0x%06X)",
                             (unsigned)mm_type, mm_name,
                             (unsigned)tms->ssi, (unsigned)tms->ssi);
        } else {
            // Als ISSI onbekend is
            mm_logf_with_ctx(0, -1, "MM type=0x%X (%s) ISSI=UNKNOWN",
                             (unsigned)mm_type, mm_name);
        }
        break;
    }

    case TMLE_PDISC_CMCE:
        // Optioneel logging, voeg hier toe als gewenst
        break;

    case TMLE_PDISC_SNDCP:
        // Optioneel logging, voeg hier toe als gewenst
        break;

    default:
        break;
    }

    return len;
}
