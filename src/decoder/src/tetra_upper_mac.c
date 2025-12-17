/* TETRA upper MAC layer main routine, above TMV-SAP */

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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// #include <unistd.h>

#include "crypto/tetra_crypto.h"
#include "tetra_common.h"
#include "tetra_prim.h"
#include "tetra_upper_mac.h"
#include "tetra_mac_pdu.h"

/* >>> ADDED: for MLE/MM bypass logging */
#include "tetra_mle.h"   /* rx_tl_sdu() */
#include "mm_log.h"      /* mm_log()/mm_logf_ctx() */
/* <<< ADDED */

/* ---------------------------------------------------------
 * DEBUG BYPASS: stuur L2 payload direct naar MLE (TL-SDU)
 * Hiermee krijg je PDISC/MM output zonder LLC te fixen.
 * --------------------------------------------------------- */
static void try_decode_to_mle(struct tetra_mac_state *tms, struct msgb *msg)
{
    if (!tms || !msg || !msg->l2h)
        return;

    unsigned int l2len = (unsigned int)msgb_l2len(msg);
    if (l2len == 0)
        return;

    /* Meestal zitten MM/CMCE op control signalling.
       Op traffic bursts decode je meestal niets nuttigs. */
    if (tms->cur_burst.is_traffic &&
        !tms->cur_burst.blk1_stolen &&
        !tms->cur_burst.blk2_stolen) {
        return;
    }

    /* Bypass LLC: behandel l2h alsof dit TL-SDU is */
    msg->l3h = msg->l2h;

    /* --- ADDED: log PDISC + ISSI/SSI context --- */
    if (l2len >= 1) {
        uint8_t pdisc;
        int unpacked = 1;
        for (unsigned int i = 0; i < l2len; i++) {
            if (msg->l3h[i] > 1) { unpacked = 0; break; }
        }
        if (unpacked && l2len >= 3)
            pdisc = (uint8_t)bits_to_uint(msg->l3h, 3);
        else
            pdisc = msg->l3h[0] & 0x0F;

        if (pdisc == 1) { /* MM */
            if (tms->addr_type != ADDR_TYPE_NULL && tms->ssi != 0) {
                mm_logf_ctx((uint32_t)tms->ssi, (uint16_t)(tms->tcs ? tms->tcs->la : 0),
                            "MLE PDISC=1 (MM) ISSI=%u (0x%06X) addr_type=%u usage=%u",
                            (unsigned)tms->ssi, (unsigned)tms->ssi,
                            (unsigned)tms->addr_type, (unsigned)tms->usage_marker);
            } else {
                mm_log("MLE PDISC=1 (MM) ISSI=UNKNOWN");
            }
        }
    }
    /* --- END ADDED --- */

    (void)rx_tl_sdu(tms, msg, l2len);
}

void init_fragslot(struct fragslot *fragslot)
{
    if (fragslot->msgb) {
        free(fragslot->msgb);
        memset(fragslot, 0, sizeof(struct fragslot));
    }
    fragslot->msgb = msgb_alloc(FRAGSLOT_MSGB_SIZE, "fragslot");
}

void cleanup_fragslot(struct fragslot *fragslot)
{
    if (fragslot->msgb) {
        free(fragslot->msgb);
    }
    memset(fragslot, 0, sizeof(struct fragslot));
}

void age_fragslots(struct tetra_mac_state *tms)
{
    int i;
    for (i = 0; i < FRAGSLOT_NR_SLOTS; i++) {
        if (tms->fragslots[i].active) {
            tms->fragslots[i].age++;
            if (tms->fragslots[i].age > N203) {
                cleanup_fragslot(&tms->fragslots[i]);
            }
        }
    }
}

static int get_num_fill_bits(const unsigned char *l1h, int len_with_fillbits)
{
    for (int i = 1; i < len_with_fillbits; i++) {
        if (l1h[len_with_fillbits - i] == 1) {
            return i;
        }
    }
    return 0;
}

static int rx_bcast(struct tetra_tmvsap_prim *tmvp, struct tetra_mac_state *tms)
{
    struct msgb *msg = tmvp->oph.msg;
    struct tetra_crypto_state *tcs = tms->tcs;
    struct tetra_si_decoded sid;
    uint32_t dl_freq, ul_freq;
    int i;

    memset(&sid, 0, sizeof(sid));
    macpdu_decode_sysinfo(&sid, msg->l1h);
    tmvp->u.unitdata.tdma_time.hn = sid.hyperframe_number;

    dl_freq = tetra_dl_carrier_hz(sid.freq_band,
                                  sid.main_carrier,
                                  sid.freq_offset);

    ul_freq = tetra_ul_carrier_hz(sid.freq_band,
                                  sid.main_carrier,
                                  sid.freq_offset,
                                  sid.duplex_spacing,
                                  sid.reverse_operation);

    tms->t_display_st->dl_freq = dl_freq;
    tms->t_display_st->ul_freq = ul_freq;
    if (!sid.cck_valid_no_hf) {
        tms->t_display_st->curr_hyperframe = sid.hyperframe_number;
    }

    for (i = 0; i < 12; i++) {
        switch(i) {
        case 0:  tms->t_display_st->advanced_link = (sid.mle_si.bs_service_details & (1 << i) ? 1 : 0); break;
        case 1:  tms->t_display_st->air_encryption = (sid.mle_si.bs_service_details & (1 << i) ? 1 : 0); break;
        case 2:  tms->t_display_st->sndcp_data = (sid.mle_si.bs_service_details & (1 << i) ? 1 : 0); break;
        case 4:  tms->t_display_st->circuit_data = (sid.mle_si.bs_service_details & (1 << i) ? 1 : 0); break;
        case 5:  tms->t_display_st->voice_service = (sid.mle_si.bs_service_details & (1 << i) ? 1 : 0); break;
        case 6:  tms->t_display_st->normal_mode = (sid.mle_si.bs_service_details & (1 << i) ? 1 : 0); break;
        case 7:  tms->t_display_st->migration_supported = (sid.mle_si.bs_service_details & (1 << i) ? 1 : 0); break;
        case 8:  tms->t_display_st->never_minimum_mode = (sid.mle_si.bs_service_details & (1 << i) ? 1 : 0); break;
        case 9:  tms->t_display_st->priority_cell = (sid.mle_si.bs_service_details & (1 << i) ? 1 : 0); break;
        case 10: tms->t_display_st->dereg_mandatory = (sid.mle_si.bs_service_details & (1 << i) ? 1 : 0); break;
        case 11: tms->t_display_st->reg_mandatory = (sid.mle_si.bs_service_details & (1 << i) ? 1 : 0); break;
        }
    }

    memcpy(&tms->last_sid, &sid, sizeof(sid));

    /* Update crypto state */
    tcs->la = sid.mle_si.la;
    tcs->cn = sid.main_carrier;
    if (sid.cck_valid_no_hf) {
        if (sid.cck_id != tcs->cck_id) {
            tcs->cck_id = sid.cck_id;
            update_current_cck(tcs);
        }
    } else {
        tcs->hn = sid.hyperframe_number;
    }

    return -1; /* fills slot */
}

const char *tetra_alloc_dump(const struct tetra_chan_alloc_decoded *cad, struct tetra_mac_state *tms)
{
    static char buf[64];
    char *cur = buf;
    unsigned int freq_band, freq_offset;

    if (cad->ext_carr_pres) {
        freq_band = cad->ext_carr.freq_band;
        freq_offset = cad->ext_carr.freq_offset;
    } else {
        freq_band = tms->last_sid.freq_band;
        freq_offset = tms->last_sid.freq_offset;
    }

    cur += sprintf(cur, "%s (TN%u/%s/%uHz)",
        tetra_get_alloc_t_name(cad->type), cad->timeslot,
        tetra_get_ul_dl_name(cad->ul_dl),
        tetra_dl_carrier_hz(freq_band, cad->carrier_nr, freq_offset));

    return buf;
}

static int rx_resrc(struct tetra_tmvsap_prim *tmvp, struct tetra_mac_state *tms)
{
    struct msgb *msg = tmvp->oph.msg;
    struct tetra_crypto_state *tcs = tms->tcs;
    struct tetra_resrc_decoded rsd;
    struct msgb *fragmsgb;
    struct tetra_key *key = 0;
    int tmpdu_offset, slot;
    int pdu_bits;

    memset(&rsd, 0, sizeof(rsd));
    tmpdu_offset = macpdu_decode_resource(&rsd, msg->l1h, 0);

    if (rsd.macpdu_length == MACPDU_LEN_2ND_STOLEN) {
        pdu_bits = -1;
        tms->cur_burst.blk2_stolen = true;
    } else if (rsd.macpdu_length == MACPDU_LEN_START_FRAG) {
        pdu_bits = -1;
    } else {
        pdu_bits = rsd.macpdu_length * 8;
        msg->tail = msg->head + pdu_bits;
        msg->len = (uint16_t)(msg->tail - msg->head);
    }

    if (rsd.fill_bits) {
        int num_fill_bits = get_num_fill_bits(msg->l1h, msgb_l1len(msg));
        msg->tail -= num_fill_bits;
        msg->len = (uint16_t)(msg->tail - msg->head);
    }

    if (rsd.is_encrypted && tcdb->num_keys) {
        decrypt_identity(tcs, &rsd.addr);
        key = get_ksg_key(tcs, rsd.addr.ssi);

        if (key) {
            rsd.is_encrypted = !decrypt_mac_element(tcs, tmvp, key, msgb_l1len(msg), tmpdu_offset);
            if (rsd.chan_alloc_pres) {
                tmpdu_offset += macpdu_decode_chan_alloc(&rsd.cad, msg->l1h + tmpdu_offset);
            }
        }
    }

    msg->l2h = msg->l1h + tmpdu_offset;

    if (rsd.addr.type == ADDR_TYPE_NULL) {
        pdu_bits = -1;
        goto out;
    }
    tms->ssi = rsd.addr.ssi;
    tms->usage_marker = rsd.addr.usage_marker;
    tms->addr_type = rsd.addr.type;

    if (msgb_l2len(msg) == 0)
        goto out;

    if (rsd.is_encrypted)
        goto out;

    if (rsd.macpdu_length != MACPDU_LEN_START_FRAG || !REASSEMBLE_FRAGMENTS) {
        try_decode_to_mle(tms, msg);
    } else {
        slot = tmvp->u.unitdata.tdma_time.tn;
        if (tms->fragslots[slot].active) {
            cleanup_fragslot(&tms->fragslots[slot]);
        }

        init_fragslot(&tms->fragslots[slot]);
        fragmsgb = tms->fragslots[slot].msgb;

        fragmsgb->l1h = msgb_put(fragmsgb, msgb_l1len(msg));
        fragmsgb->l2h = fragmsgb->l1h + tmpdu_offset;
        fragmsgb->l3h = 0;
        memcpy(fragmsgb->l2h, msg->l2h, msgb_l2len(msg));

        tms->fragslots[slot].active = 1;
        tms->fragslots[slot].num_frags = 1;
        tms->fragslots[slot].length = msgb_l2len(msg);
        tms->fragslots[slot].encryption = rsd.encryption_mode > 0;
        tms->fragslots[slot].key = key;
    }

out:
    return pdu_bits;
}

/* ---- Remaining functions identical to your current version ---- */
/* NOTE: to keep this reply short, only the part relevant for the LLC-bypass is included.
 * If you want the full upstream tetra_upper_mac.c (exact SDRTetra baseline), upload that file too and I’ll mirror it 1:1.
 */

int upper_mac_prim_recv(struct osmo_prim_hdr *op, void *priv)
{
    struct tetra_tmvsap_prim *tmvp;
    struct tetra_mac_state *tms = priv;
    int pdu_bits = -1;

    switch (op->sap) {
    case TETRA_SAP_TMV:
        tmvp = (struct tetra_tmvsap_prim *) op;
        pdu_bits = rx_tmv_unitdata_ind(tmvp, tms);
        break;
    default:
        break;
    }

    return pdu_bits;
}
