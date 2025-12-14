/* Implementation of TETRA MM PDU parsing */

#include "tetra_common.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"

static const struct value_string mm_pdut_d_names[] = {
    { TMM_PDU_T_D_OTAR,             "D-OTAR" },
    { TMM_PDU_T_D_AUTH,             "D-AUTHENTICATION" },
    { TMM_PDU_T_D_CK_CHG_DEM,       "D-CK CHANGE DEMAND" },
    { TMM_PDU_T_D_DISABLE,          "D-DISABLE" },
    { TMM_PDU_T_D_ENABLE,           "D-ENABLE" },
    { TMM_PDU_T_D_LOC_UPD_ACC,      "D-LOCATION UPDATE ACCEPT" },
    { TMM_PDU_T_D_LOC_UPD_CMD,      "D-LOCATION UPDATE COMMAND" },
    { TMM_PDU_T_D_LOC_UPD_REJ,      "D-LOCATION UPDATE REJECT" },
    { TMM_PDU_T_D_LOC_UPD_PROC,     "D-LOCATION UPDATE PROCEEDING" },
    { TMM_PDU_T_D_ATT_DET_GRP,      "D-ATTACH/DETACH GROUP ID" },
    { TMM_PDU_T_D_ATT_DET_GRP_ACK,  "D-ATTACH/DETACH GROUP ID ACK" },
    { TMM_PDU_T_D_MM_STATUS,        "D-MM STATUS" },
    { TMM_PDU_T_D_MM_PDU_NOTSUPP,   "MM PDU/FUNCTION NOT SUPPORTED" },
    { 0, NULL }
};

/* IMPORTANT: no logging here; just return name. */
const char *tetra_mm_pdu_get_name(uint8_t pdu_type)
{
    return get_value_string(mm_pdut_d_names, pdu_type);
}

/* Optional: basic single-line log for a MM PDU type */
void tetra_mm_pdu_log_basic(uint32_t issi, uint8_t pdu_type)
{
    const char *short_name = tetra_get_mm_pdut_name(pdu_type, 0);

    /* mm_logf_with_ctx filters out ISSI==0xFFFFFF automatically */
    mm_logf_with_ctx(issi,
                     "MM: %s (type=0x%X)",
                     short_name ? short_name : "D-UNKNOWN",
                     (unsigned)pdu_type);
}
