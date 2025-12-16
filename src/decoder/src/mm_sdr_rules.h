
#ifndef MM_SDR_RULES_H
#define MM_SDR_RULES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Subset of SDR# GlobalNames indices (from GlobalNames.cs enum order) */
#define GN_Options_bit 2
#define GN_Presence_bit 3
#define GN_Reserved 14
#define GN_Location_update_accept_type 383
#define GN_Location_update_type 387
#define GN_Reject_cause 388
#define GN_Cipher_control 389
#define GN_Ciphering_parameters 390
#define GN_MM_Address_extension 391
#define GN_Group_identity_report 392
#define GN_Group_identity_acknowledgement_request 393
#define GN_Group_identity_attach_detach_mode 394
#define GN_Group_identity_accept_reject 395
#define GN_MM_SSI 397

/* Subset of SDR# RulesType */
typedef enum {
    MMRT_Direct = 0,
    MMRT_Options_bit = 1,
    MMRT_Presence_bit = 2,
    MMRT_More_bit = 3,
    MMRT_Switch = 4,
    MMRT_SwitchNot = 5,
    MMRT_Reserved = 6,
} mm_rules_type;

/* Equivalent to SDR# Rules struct (GlobalName, Length, Type, Ext1, Ext2, Ext3) */
typedef struct {
    uint16_t global_name;
    uint16_t length_bits;
    uint8_t  type;
    int32_t  ext1;
    int32_t  ext2;
    int32_t  ext3;
} mm_rule;

/* Field store: like SDR# dictionary of GlobalNames -> value */
typedef struct {
    uint32_t value[640];
    uint8_t  present[640];
} mm_field_store;

/* Decode rules starting at bitpos. Returns new bitpos (>= start) */
unsigned int mm_rules_decode(const uint8_t *bits, unsigned int nbits,
                             unsigned int bitpos,
                             const mm_rule *rules, size_t rule_count,
                             mm_field_store *fs);

/* Rules tables ported from SDR# Class18.cs */
extern const mm_rule mm_rules_loc_upd_accept[];
extern const size_t  mm_rules_loc_upd_accept_count;

extern const mm_rule mm_rules_loc_upd_command[];
extern const size_t  mm_rules_loc_upd_command_count;

extern const mm_rule mm_rules_loc_upd_proceeding[];
extern const size_t  mm_rules_loc_upd_proceeding_count;

extern const mm_rule mm_rules_loc_upd_reject[];
extern const size_t  mm_rules_loc_upd_reject_count;

extern const mm_rule mm_rules_att_det_grp[];
extern const size_t  mm_rules_att_det_grp_count;

extern const mm_rule mm_rules_att_det_grp_ack[];
extern const size_t  mm_rules_att_det_grp_ack_count;

#ifdef __cplusplus
}
#endif
#endif
