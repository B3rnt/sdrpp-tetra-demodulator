#ifndef TETRA_MM_PDU_H
#define TETRA_MM_PDU_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum tetra_mm_pdu_type_d {
    TMM_PDU_T_D_OTAR            = 0x0,
    TMM_PDU_T_D_AUTH            = 0x1,
    TMM_PDU_T_D_CK_CHG_DEM      = 0x2,
    TMM_PDU_T_D_DISABLE         = 0x3,
    TMM_PDU_T_D_ENABLE          = 0x4,
    TMM_PDU_T_D_LOC_UPD_ACC     = 0x5,
    TMM_PDU_T_D_LOC_UPD_CMD     = 0x6,
    TMM_PDU_T_D_LOC_UPD_REJ     = 0x7,
    TMM_PDU_T_D_LOC_UPD_PROC    = 0x9,
    TMM_PDU_T_D_ATT_DET_GRP     = 0xa,
    TMM_PDU_T_D_ATT_DET_GRP_ACK = 0xb,
    TMM_PDU_T_D_MM_STATUS       = 0xc,
    TMM_PDU_T_D_MM_PDU_NOTSUPP  = 0xf
};

static inline const char *tetra_get_mm_pdut_name(uint8_t pdu_type, int uplink)
{
    (void)uplink;

    switch (pdu_type) {
    case TMM_PDU_T_D_OTAR:            return "D-OTAR";
    case TMM_PDU_T_D_AUTH:            return "D-AUTH";
    case TMM_PDU_T_D_CK_CHG_DEM:      return "D-CK-CHG-DEM";
    case TMM_PDU_T_D_DISABLE:         return "D-DISABLE";
    case TMM_PDU_T_D_ENABLE:          return "D-ENABLE";
    case TMM_PDU_T_D_LOC_UPD_ACC:     return "D-LOC-UPD-ACC";
    case TMM_PDU_T_D_LOC_UPD_CMD:     return "D-LOC-UPD-CMD";
    case TMM_PDU_T_D_LOC_UPD_REJ:     return "D-LOC-UPD-REJ";
    case TMM_PDU_T_D_LOC_UPD_PROC:    return "D-LOC-UPD-PROC";
    case TMM_PDU_T_D_ATT_DET_GRP:     return "D-ATT-DET-GRP";
    case TMM_PDU_T_D_ATT_DET_GRP_ACK: return "D-ATT-DET-GRP-ACK";
    case TMM_PDU_T_D_MM_STATUS:       return "D-MM-STATUS";
    case TMM_PDU_T_D_MM_PDU_NOTSUPP:  return "D-MM-PDU-NOTSUPP";
    default:                          return "D-UNKNOWN";
    }
}

/* name lookup only (no logging) */
const char *tetra_mm_pdu_get_name(uint8_t pdu_type);

#ifdef __cplusplus
}
#endif

#endif /* TETRA_MM_PDU_H */
