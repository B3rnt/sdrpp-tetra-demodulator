/* Implementation of TETRA MM PDU parsing */

/* (C) 2011 by Harald Welte <laforge@gnumonks.org>
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

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

/* Optional: basic single-line log for a MM PDU type (still no SSI/GSSI/CAUSE). */
void tetra_mm_pdu_log_basic(uint32_t issi, uint8_t pdu_type)
{
    const char *short_name = tetra_get_mm_pdut_name(pdu_type, 0);
    /* This uses context-aware filter: drops 0xFFFFFF by default */
    mm_logf_with_ctx(issi, "MM: %s (type=0x%X) ISSI=%u (0x%06X)",
                     short_name ? short_name : "D-UNKNOWN",
                     (unsigned)pdu_type,
                     (unsigned)issi, (unsigned)(issi & 0xFFFFFFu));
}
