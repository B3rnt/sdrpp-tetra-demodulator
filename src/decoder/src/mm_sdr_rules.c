
#include "mm_sdr_rules.h"

/* Basic bit helpers (bits[] are 0/1 values) */
static inline uint32_t get_bits_u32(const uint8_t *bits, unsigned int nbits, unsigned int pos, unsigned int n)
{
    if (!bits || n == 0 || pos + n > nbits) return 0;
    uint32_t v = 0;
    for (unsigned int i = 0; i < n; i++) {
        v = (v << 1) | (bits[pos + i] & 1u);
    }
    return v;
}

unsigned int mm_rules_decode(const uint8_t *bits, unsigned int nbits,
                             unsigned int bitpos,
                             const mm_rule *rules, size_t rule_count,
                             mm_field_store *fs)
{
    if (!bits || !rules || rule_count == 0) return bitpos;
    if (!fs) return bitpos;

    /* SDR#-achtig: Presence_bit beïnvloedt of direct volgende veld bestaat. */
    int skip_next = 0;

    for (size_t i = 0; i < rule_count; i++) {
        const mm_rule *r = &rules[i];

        if (skip_next) {
            /* Sla de volgende rule volledig over (consumeer geen bits) */
            skip_next = 0;
            continue;
        }

        if (bitpos >= nbits) break;

        switch ((mm_rules_type)r->type) {
        case MMRT_Direct: {
            if (r->length_bits == 0 || bitpos + r->length_bits > nbits) return bitpos;
            uint32_t v = get_bits_u32(bits, nbits, bitpos, r->length_bits);
            if (r->global_name < 640) {
                fs->value[r->global_name] = v;
                fs->present[r->global_name] = 1;
            }
            bitpos += r->length_bits;
            break;
        }
        case MMRT_Reserved: {
            if (r->length_bits == 0 || bitpos + r->length_bits > nbits) return bitpos;
            bitpos += r->length_bits;
            break;
        }
        case MMRT_Options_bit: {
            if (bitpos + 1 > nbits) return bitpos;
            uint32_t v = get_bits_u32(bits, nbits, bitpos, 1);
            if (r->global_name < 640) {
                fs->value[r->global_name] = v;
                fs->present[r->global_name] = 1;
            }
            bitpos += 1;
            /* Options_bit in SDR# wordt vooral gebruikt voor latere branch; hier slaan we hem op. */
            break;
        }
        case MMRT_Presence_bit: {
            if (bitpos + 1 > nbits) return bitpos;
            uint32_t v = get_bits_u32(bits, nbits, bitpos, 1);
            if (r->global_name < 640) {
                fs->value[r->global_name] = v;
                fs->present[r->global_name] = 1;
            }
            bitpos += 1;
            if (v == 0) {
                /* Als presence bit 0 is, bestaat het volgende veld niet (SDR# patroon) */
                skip_next = 1;
            }
            break;
        }
        case MMRT_Switch:
        case MMRT_SwitchNot: {
            /* SDR# pattern in Class18: Ciphering_parameters (10 bits) met Switch op Cipher_control==1.
               Ext1=depGlobalName, Ext2=expectedValue. */
            int dep = r->ext1;
            int expected = r->ext2;
            uint32_t depv = 0;
            if (dep >= 0 && dep < 640 && fs->present[dep]) depv = fs->value[dep];

            int cond = ((int)depv == expected);
            if ((mm_rules_type)r->type == MMRT_SwitchNot) cond = !cond;

            if (cond) {
                if (r->length_bits == 0 || bitpos + r->length_bits > nbits) return bitpos;
                uint32_t v = get_bits_u32(bits, nbits, bitpos, r->length_bits);
                if (r->global_name < 640) {
                    fs->value[r->global_name] = v;
                    fs->present[r->global_name] = 1;
                }
                bitpos += r->length_bits;
            } else {
                /* Switch false: veld bestaat niet, consumeer geen bits */
            }
            break;
        }
        default:
            /* Onbekend: stop veilig */
            return bitpos;
        }
    }

    return bitpos;
}

/* ===== Rules arrays (ported 1:1 from SDR# Class18.cs rules_0..rules_2) ===== */

/* rules_0: Location Update ACCEPT header */
const mm_rule mm_rules_loc_upd_accept[] = {
    { GN_Location_update_accept_type, 3, MMRT_Direct, 0, 0, 0 },
    { GN_Options_bit,                 1, MMRT_Options_bit, 0, 0, 0 },
    { GN_Presence_bit,                1, MMRT_Presence_bit, 1, 0, 0 },
    { GN_MM_SSI,                      24, MMRT_Direct, 0, 0, 0 },
    { GN_Presence_bit,                1, MMRT_Presence_bit, 1, 0, 0 },
    { GN_Reserved,                    24, MMRT_Reserved, 0, 0, 0 },
    { GN_Presence_bit,                1, MMRT_Presence_bit, 1, 0, 0 },
    { GN_Reserved,                    16, MMRT_Reserved, 0, 0, 0 },
    { GN_Presence_bit,                1, MMRT_Presence_bit, 1, 0, 0 },
    { GN_Reserved,                    14, MMRT_Reserved, 0, 0, 0 },
    { GN_Presence_bit,                1, MMRT_Presence_bit, 1, 0, 0 },
    { GN_Reserved,                    6,  MMRT_Reserved, 0, 0, 0 },
};
const size_t mm_rules_loc_upd_accept_count = sizeof(mm_rules_loc_upd_accept)/sizeof(mm_rules_loc_upd_accept[0]);

/* rules_1: Location Update COMMAND (Group identity report + cipher fields) */
const mm_rule mm_rules_loc_upd_command[] = {
    { GN_Group_identity_report,   1,  MMRT_Direct, 0, 0, 0 },
    { GN_Cipher_control,          1,  MMRT_Direct, 0, 0, 0 },
    { GN_Ciphering_parameters,    10, MMRT_Switch, GN_Cipher_control, 1, 0 },
    { GN_Options_bit,             1,  MMRT_Options_bit, 0, 0, 0 },
    { GN_Presence_bit,            1,  MMRT_Presence_bit, 1, 0, 0 },
    { GN_MM_Address_extension,    24, MMRT_Direct, 0, 0, 0 },
};
const size_t mm_rules_loc_upd_command_count = sizeof(mm_rules_loc_upd_command)/sizeof(mm_rules_loc_upd_command[0]);

/* rules_3: Location Update PROCEEDING */
const mm_rule mm_rules_loc_upd_proceeding[] = {
    { GN_MM_SSI,                  24, MMRT_Direct, 0, 0, 0 },
    { GN_MM_Address_extension,    24, MMRT_Direct, 0, 0, 0 },
    { GN_Options_bit,             1,  MMRT_Options_bit, 0, 0, 0 },
};
const size_t mm_rules_loc_upd_proceeding_count = sizeof(mm_rules_loc_upd_proceeding)/sizeof(mm_rules_loc_upd_proceeding[0]);

/* rules_2: Location Update REJECT (update type + reject cause + cipher fields) */
const mm_rule mm_rules_loc_upd_reject[] = {
    { GN_Location_update_type,    3,  MMRT_Direct, 0, 0, 0 },
    { GN_Reject_cause,            5,  MMRT_Direct, 0, 0, 0 },
    { GN_Cipher_control,          1,  MMRT_Direct, 0, 0, 0 },
    { GN_Ciphering_parameters,    10, MMRT_Switch, GN_Cipher_control, 1, 0 },
    { GN_Options_bit,             1,  MMRT_Options_bit, 0, 0, 0 },
    { GN_Presence_bit,            1,  MMRT_Presence_bit, 1, 0, 0 },
    { GN_MM_Address_extension,    24, MMRT_Direct, 0, 0, 0 },
};
const size_t mm_rules_loc_upd_reject_count = sizeof(mm_rules_loc_upd_reject)/sizeof(mm_rules_loc_upd_reject[0]);

/* rules_4: Attach/Detach Group Identity */
const mm_rule mm_rules_att_det_grp[] = {
    { GN_Group_identity_report,                    1, MMRT_Direct, 0, 0, 0 },
    { GN_Group_identity_acknowledgement_request,   1, MMRT_Direct, 0, 0, 0 },
    { GN_Group_identity_attach_detach_mode,        1, MMRT_Direct, 0, 0, 0 },
    { GN_Options_bit,                              1, MMRT_Options_bit, 0, 0, 0 },
};
const size_t mm_rules_att_det_grp_count = sizeof(mm_rules_att_det_grp)/sizeof(mm_rules_att_det_grp[0]);

/* rules_5: Attach/Detach Group Identity ACK */
const mm_rule mm_rules_att_det_grp_ack[] = {
    { GN_Group_identity_accept_reject, 1, MMRT_Direct, 0, 0, 0 },
    { GN_Reserved,                     1, MMRT_Reserved, 0, 0, 0 },
    { GN_Options_bit,                  1, MMRT_Options_bit, 0, 0, 0 },
};
const size_t mm_rules_att_det_grp_ack_count = sizeof(mm_rules_att_det_grp_ack)/sizeof(mm_rules_att_det_grp_ack[0]);
