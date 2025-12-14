/* Implementation of TETRA Physical Layer, i.e. what is _below_
 * CRC, FEC, Interleaving and Scrambling */

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

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "tetra_common.h"
#include <phy/tetra_burst.h>

#define DQPSK4_BITS_PER_SYM	2

#define SB_BLK1_OFFSET	((6+1+40)*DQPSK4_BITS_PER_SYM)
#define SB_BBK_OFFSET	((6+1+40+60+19)*DQPSK4_BITS_PER_SYM)
#define SB_BLK2_OFFSET	((6+1+40+60+19+15)*DQPSK4_BITS_PER_SYM)

#define SB_BLK1_BITS	(60*DQPSK4_BITS_PER_SYM)
#define SB_BBK_BITS	(15*DQPSK4_BITS_PER_SYM)
#define SB_BLK2_BITS	(108*DQPSK4_BITS_PER_SYM)

#define NDB_BLK1_OFFSET ((5+1+1)*DQPSK4_BITS_PER_SYM)
#define NDB_BBK1_OFFSET	((5+1+1+108)*DQPSK4_BITS_PER_SYM)
#define NDB_BBK2_OFFSET	((5+1+1+108+7+11)*DQPSK4_BITS_PER_SYM)
#define NDB_BLK2_OFFSET	((5+1+1+108+7+11+8)*DQPSK4_BITS_PER_SYM)

#define NDB_BBK1_BITS	(7*DQPSK4_BITS_PER_SYM)
#define NDB_BBK2_BITS	(8*DQPSK4_BITS_PER_SYM)
#define NDB_BLK_BITS	(108*DQPSK4_BITS_PER_SYM)
#define NDB_BBK_BITS	SB_BBK_BITS


/* ---------- Robust training sequence matching helpers (NEW) ---------- */

static inline unsigned int train_seq_bit_errors(const uint8_t *a, const uint8_t *b, unsigned int len)
{
	unsigned int e = 0;
	for (unsigned int i = 0; i < len; i++) {
		/* bits are 0/1 */
		e += (unsigned int)((a[i] ^ b[i]) & 1u);
	}
	return e;
}

/* Accept a limited number of bit errors in training sequences.
 * This greatly improves burst sync on weaker signals (vs exact memcmp). */
static inline unsigned int train_seq_max_errors(unsigned int len)
{
	/* Conservative: ~14% allowed, capped to avoid false positives */
	unsigned int m = (len + 6u) / 7u; /* ~14% */
	if (m < 1u) m = 1u;
	if (m > 4u) m = 4u;
	return m;
}


/* 9.4.4.3.1 Frequency Correction Field */
static const uint8_t f_bits[80] = {
	/* f1 .. f8 = 1 */
	1, 1, 1, 1, 1, 1, 1, 1,
	/* f73..f80 = 1*/
	[72] = 1, [73] = 1, [74] = 1, [75] = 1,
	[76] = 1, [77] = 1, [78] = 1, [79] = 1 };

/* 9.4.4.3.2 Normal Training Sequence */
static const uint8_t n_bits[22] = { 1,1, 0,1, 0,0, 0,0, 1,1, 1,0, 1,0, 0,1, 1,1, 0,1, 0,0 };
static const uint8_t p_bits[22] = { 0,1, 1,1, 1,0, 1,0, 0,1, 0,0, 0,0, 1,1, 0,1, 1,1, 1,0 };
static const uint8_t q_bits[22] = { 1,0, 1,1, 0,1, 1,1, 0,0, 0,0, 0,1, 1,0, 1,0, 1,1, 0,1 };
static const uint8_t N_bits[33] = { 1,1,1, 0,0,1, 1,0,1, 1,1,1, 0,0,0, 1,1,1, 1,0,0, 0,1,1, 1,1,0, 0,0,0, 0,0,0 };
static const uint8_t P_bits[33] = { 1,0,1, 0,1,1, 1,1,1, 1,0,1, 0,1,0, 1,0,1, 1,1,0, 0,0,1, 1,0,0, 0,1,0, 0,1,0 };

/* 9.4.4.3.3 Extended training sequence */
static const uint8_t x_bits[30] = { 1,0, 0,1, 1,1, 0,1, 0,0, 0,0, 1,1, 1,0, 1,0, 0,1, 1,1, 0,1, 0,0, 0,0, 1,1 };
static const uint8_t X_bits[45] = { 0,1,1,1,0,0,1,1,0,1,0,0,0,0,1,0,0,0,1,1,1,0,1,1,0,1,0,1,0,1,1,1,1,1,0,1,0,0,0,0,0,1,1,1,0 };

/* 9.4.4.3.4 Synchronization training sequence */
static const uint8_t y_bits[38] = { 1,1, 0,0, 0,0, 0,1, 1,0, 0,1, 1,1, 0,0, 1,1, 1,0, 1,0, 0,1, 1,1, 0,0, 0,0, 0,1, 1,0, 0,1, 1,1 };

/* 9.4.4.3.5 Tail bits */
static const uint8_t t_bits[4] = { 1, 1, 0, 0 };
static const uint8_t T_bits[6] = { 1, 1, 1, 0, 0, 0 };

/* 9.4.4.3.6 Phase adjustment bits */
enum phase_adj_bits { HA, HB, HC, HD, HE, HF, HG, HH, HI, HJ };
struct phase_adj_n {
	uint16_t n1;
	uint16_t n2;
};

/* Table 8.14 */
static const struct phase_adj_n phase_adj_n[] = {
	[HA] = { .n1 = 8,	.n2 = 122 },
	[HB] = { .n1 = 123,	.n2 = 249 },
	[HC] = { .n1 = 8,	.n2 = 108 },
	[HD] = { .n1 = 109,	.n2 = 249 },
	[HE] = { .n1 = 112,	.n2 = 230 },
	[HF] = { .n1 = 1,	.n2 = 111 },
	[HG] = { .n1 = 3,	.n2 = 117 },
	[HH] = { .n1 = 118,	.n2 = 224 },
	[HI] = { .n1 = 3,	.n2 = 103 },
	[HJ] = { .n1 = 104,	.n2 = 224 },
};

static const int8_t bits2phase[] = {
	[0]	= 1,		/* +pi/4 needs to become -pi/4 */
	[1]	= -1,		/* -pi/4 needs to become +pi/4 */
	[2]	= +3,		/* +3pi/4 needs to become -3pi/4 */
	[3]	= -3,		/* -3pi/4 needs to become +3pi/4 */
};

/* offset everything by 3 in order to get positive array index */
#define PHASE(x)	((x)+3)

struct phase2bits {
	int8_t phase;
	uint8_t bits[2];
};

static const struct phase2bits phase2bits[] = {
	[PHASE(-3)]	= { -3, {1, 1} },
	[PHASE(-1)]	= { -1, {0, 1} },
	[PHASE( 1)]	= {  1, {0, 0} },
	[PHASE( 3)]	= {  3, {1, 0} },
};

static int32_t calc_phase_adj(int32_t phase)
{
	int32_t adj_phase = -(phase % 8);

	/* 'wrap around' to get a value in the range between +3 / -3 */
	if (adj_phase > 3)
		adj_phase -= 8;
	else if (adj_phase < -3)
		adj_phase += 8;

	return adj_phase;
}

/* return the cumulative phase shift of all bits (in units of pi/4) */
int32_t sum_up_phase(const uint8_t *bits, unsigned int sym_count)
{
	uint8_t sym_in;
	int32_t sum_phase = 0;
	unsigned int n;

	for (n = 0; n < sym_count; n++) {
		/* offset '-1' due to array-index starting at 0 */
		uint32_t bn = 2*n;
		sym_in = bits[bn];
		sym_in |= (uint8_t)(bits[bn+1] << 1);

		sum_phase += bits2phase[sym_in & 3u];
	}

	return sum_phase;
}

/* compute phase adjustment bits according to 'pa' and write them to {out, out+2} */
void put_phase_adj_bits(const uint8_t *bits, enum phase_adj_bits pa, uint8_t *out)
{
	int32_t sum_phase, adj_phase;
	const struct phase_adj_n *pan = &phase_adj_n[pa];
	const struct phase2bits *p2b;

	/* offset '-1' due to array-index starting at 0 */
	sum_phase = sum_up_phase(bits + 2*(pan->n1-1), 1 + pan->n2 - pan->n1);
	adj_phase = calc_phase_adj(sum_phase);

	/* PHASE() maps [-3..+3] => [0..6] */
	p2b = &phase2bits[PHASE(adj_phase)];

	*out++ = p2b->bits[0];
	*out++ = p2b->bits[1];
}

/* 9.4.4.2.6 Synchronization continuous downlink burst */
int build_sync_c_d_burst(uint8_t *buf, const uint8_t *sb, const uint8_t *bb, const uint8_t *bkn)
{
	uint8_t *cur = buf;
	uint8_t *hc, *hd;

	/* Normal Training Sequence: q11 to q22 */
	memcpy(cur, q_bits+10, 12);
	cur += 12;

	/* Phase adjustment bits: hc1 to hc2 */
	hc = cur;
	cur += 2;

	/* Frequency correction: f1 to f80 */
	memcpy(cur, f_bits, 80);
	cur += 80;

	/* Scrambled synchronization block 1 bits: sb(1) to sb(120) */
	memcpy(cur, sb, 120);
	cur += 120;

	/* Synchronization training sequence: y1 to y38 */
	memcpy(cur, y_bits, 38);
	cur += 38;

	/* Scrambled broadcast bits: bb(1) to bb(30) */
	memcpy(cur, bb, 30);
	cur += 30;

	/* Scrambled block2 bits: bkn2(1) to bkn2(216) */
	memcpy(cur, bkn, 216);
	cur += 216;

	/* Phase adjustment bits: hd1 to hd2 */
	hd = cur;
	cur += 2;

	/* Normal training sequence 3: q1 to q10 */
	memcpy(cur, q_bits, 10);
	cur += 10;

	/* put in the phase adjustment bits */
	put_phase_adj_bits(buf, HC, hc);
	put_phase_adj_bits(buf, HD, hd);

	return (int)(cur - buf);
}

/* 9.4.4.2.5 Normal continuous downlink burst */
int build_norm_c_d_burst(uint8_t *buf, const uint8_t *bkn1, const uint8_t *bb, const uint8_t *bkn2, int two_log_chan)
{
	uint8_t *cur = buf;
	uint8_t *ha, *hb;

	/* Normal Training Sequence: q11 to q22 */
	memcpy(cur, q_bits+10, 12);
	cur += 12;

	/* Phase adjustment bits: hc1 to hc2 */
	ha = cur;
	cur += 2;

	/* Scrambled block 1 bits: bkn1(1) to bkn1(216) */
	memcpy(cur, bkn1, 216);
	cur += 216;

	/* Scrambled broadcast bits: bb(1) to bb(14) */
	memcpy(cur, bb, 14);
	cur += 14;

	/* Normal training sequence: n1 to n22 or p1 to p22 */
	if (two_log_chan)
		memcpy(cur, p_bits, 22);
	else
		memcpy(cur, n_bits, 22);
	cur += 22;

	/* Scrambled broadcast bits: bb(15) to bb(30) */
	memcpy(cur, bb+14, 16);
	cur += 16;

	/* Scrambled block2 bits: bkn2(1) to bkn2(216) */
	memcpy(cur, bkn2, 216);
	cur += 216;

	/* Phase adjustment bits: hd1 to hd2 */
	hb = cur;
	cur += 2;

	/* Normal training sequence 3: q1 to q10 */
	memcpy(cur, q_bits, 10);
	cur += 10;

	/* put in the phase adjustment bits */
	put_phase_adj_bits(buf, HA, ha);
	put_phase_adj_bits(buf, HB, hb);

	return (int)(cur - buf);
}

int tetra_find_train_seq(const uint8_t *in, unsigned int end_of_in,
			 uint32_t mask_of_train_seq, unsigned int *offset)
{
	static uint32_t tsq_bytes[5];

	if (tsq_bytes[0] == 0) {
#define FILTER_LOOKAHEAD_LEN 22
#define FILTER_LOOKAHEAD_MASK ((1u<<FILTER_LOOKAHEAD_LEN)-1u)
		for (int i = 0; i < FILTER_LOOKAHEAD_LEN; i++) {
			tsq_bytes[0] = (tsq_bytes[0] << 1) | y_bits[i];
			tsq_bytes[1] = (tsq_bytes[1] << 1) | n_bits[i];
			tsq_bytes[2] = (tsq_bytes[2] << 1) | p_bits[i];
			tsq_bytes[3] = (tsq_bytes[3] << 1) | q_bits[i];
			tsq_bytes[4] = (tsq_bytes[4] << 1) | x_bits[i];
		}
	}

	uint32_t filter = 0;

	for (int i = 0; i < FILTER_LOOKAHEAD_LEN-2; i++)
		filter = (filter << 1) | in[i];

	const uint8_t *cur;

	for (cur = in; cur < in + end_of_in; cur++) {
		filter = ((filter << 1) | cur[FILTER_LOOKAHEAD_LEN-1]) & FILTER_LOOKAHEAD_MASK;

		int match = 0;
		for (int i = 0; i < 5; i++)
			if (filter == tsq_bytes[i])
				match = 1;

		if (!match)
			continue;

		unsigned remain_len = (unsigned int)((in + end_of_in) - cur);

		/* best match at this position */
		enum tetra_train_seq best_type = (enum tetra_train_seq)-1;
		unsigned int best_err = 0xffffffff;
		unsigned int off = (unsigned int)(cur - in);

		/* Allow a small number of bit errors (robust on weak signals) */
		if ((mask_of_train_seq & (1u << TETRA_TRAIN_SYNC)) &&
		    remain_len >= sizeof(y_bits)) {
			unsigned int e = train_seq_bit_errors(cur, y_bits, (unsigned int)sizeof(y_bits));
			if (e < best_err && e <= train_seq_max_errors((unsigned int)sizeof(y_bits))) {
				best_err = e; best_type = TETRA_TRAIN_SYNC;
			}
		}
		if ((mask_of_train_seq & (1u << TETRA_TRAIN_NORM_1)) &&
		    remain_len >= sizeof(n_bits)) {
			unsigned int e = train_seq_bit_errors(cur, n_bits, (unsigned int)sizeof(n_bits));
			if (e < best_err && e <= train_seq_max_errors((unsigned int)sizeof(n_bits))) {
				best_err = e; best_type = TETRA_TRAIN_NORM_1;
			}
		}
		if ((mask_of_train_seq & (1u << TETRA_TRAIN_NORM_2)) &&
		    remain_len >= sizeof(p_bits)) {
			unsigned int e = train_seq_bit_errors(cur, p_bits, (unsigned int)sizeof(p_bits));
			if (e < best_err && e <= train_seq_max_errors((unsigned int)sizeof(p_bits))) {
				best_err = e; best_type = TETRA_TRAIN_NORM_2;
			}
		}
		if ((mask_of_train_seq & (1u << TETRA_TRAIN_NORM_3)) &&
		    remain_len >= sizeof(q_bits)) {
			unsigned int e = train_seq_bit_errors(cur, q_bits, (unsigned int)sizeof(q_bits));
			if (e < best_err && e <= train_seq_max_errors((unsigned int)sizeof(q_bits))) {
				best_err = e; best_type = TETRA_TRAIN_NORM_3;
			}
		}
		if ((mask_of_train_seq & (1u << TETRA_TRAIN_EXT)) &&
		    remain_len >= sizeof(x_bits)) {
			unsigned int e = train_seq_bit_errors(cur, x_bits, (unsigned int)sizeof(x_bits));
			if (e < best_err && e <= train_seq_max_errors((unsigned int)sizeof(x_bits))) {
				best_err = e; best_type = TETRA_TRAIN_EXT;
			}
		}

		if (best_type != (enum tetra_train_seq)-1) {
			*offset = off;
			return best_type;
		}
	}
	return -1;
}

/* ---------- Timeslot content smoothing (anti-flap) ---------- */

static inline void push_ts_content(struct tetra_mac_state *tms, unsigned int tn_idx, uint8_t val)
{
	if (!tms || !tms->t_display_st || tn_idx >= 4)
		return;

	/* ringbuffer index */
	uint8_t idx = (uint8_t)(tms->t_display_st->ts_hist_idx[tn_idx] % 5u);
	tms->t_display_st->ts_hist[tn_idx][idx] = val;
	tms->t_display_st->ts_hist_idx[tn_idx] = (uint8_t)((idx + 1u) % 5u);

	/* majority vote over last 5 */
	unsigned int counts[5] = {0,0,0,0,0};
	for (unsigned int i = 0; i < 5u; i++) {
		uint8_t v = tms->t_display_st->ts_hist[tn_idx][i];
		if (v < 5u) counts[v]++;
	}

	uint8_t best = val;
	unsigned int bestc = 0;
	for (uint8_t v = 0; v < 5u; v++) {
		if (counts[v] > bestc) { bestc = counts[v]; best = v; }
	}

	tms->t_display_st->timeslot_content[tn_idx] = best;
}

void tetra_burst_rx_cb(const uint8_t *burst, unsigned int len, enum tetra_train_seq type, void *priv)
{
	uint8_t bbk_buf[NDB_BBK_BITS];
	uint8_t ndbf_buf[2*NDB_BLK_BITS];
	struct tetra_mac_state *tms = (struct tetra_mac_state *)priv;

	(void)len;

	if (!tms || !tms->t_display_st)
		return;

	tms->t_display_st->curr_multiframe = t_phy_state.time.mn;
	tms->t_display_st->curr_frame = t_phy_state.time.fn;

	switch (type) {
	case TETRA_TRAIN_SYNC:
		/* Split SB1, SB2 and Broadcast Block */
		tp_sap_udata_ind(TPSAP_T_SB1, BLK_1, burst+SB_BLK1_OFFSET, SB_BLK1_BITS, priv);
		tp_sap_udata_ind(TPSAP_T_BBK, 0,     burst+SB_BBK_OFFSET, SB_BBK_BITS, priv);
		tp_sap_udata_ind(TPSAP_T_SB2, BLK_2, burst+SB_BLK2_OFFSET, SB_BLK2_BITS, priv);
		push_ts_content(tms, t_phy_state.time.tn-1, 3);
		break;

	case TETRA_TRAIN_NORM_2:
		/* re-combine the broadcast block */
		memcpy(bbk_buf, burst+NDB_BBK1_OFFSET, NDB_BBK1_BITS);
		memcpy(bbk_buf+NDB_BBK1_BITS, burst+NDB_BBK2_OFFSET, NDB_BBK2_BITS);

		tp_sap_udata_ind(TPSAP_T_BBK, 0, bbk_buf, NDB_BBK_BITS, priv);
		tp_sap_udata_ind(TPSAP_T_NDB, BLK_1, burst+NDB_BLK1_OFFSET, NDB_BLK_BITS, priv);
		tp_sap_udata_ind(TPSAP_T_NDB, BLK_2, burst+NDB_BLK2_OFFSET, NDB_BLK_BITS, priv);
		push_ts_content(tms, t_phy_state.time.tn-1, 2);
		break;

	case TETRA_TRAIN_NORM_1:
		/* re-combine the broadcast block */
		memcpy(bbk_buf, burst+NDB_BBK1_OFFSET, NDB_BBK1_BITS);
		memcpy(bbk_buf+NDB_BBK1_BITS, burst+NDB_BBK2_OFFSET, NDB_BBK2_BITS);

		/* re-combine the two parts */
		memcpy(ndbf_buf, burst+NDB_BLK1_OFFSET, NDB_BLK_BITS);
		memcpy(ndbf_buf+NDB_BLK_BITS, burst+NDB_BLK2_OFFSET, NDB_BLK_BITS);

		tp_sap_udata_ind(TPSAP_T_BBK, 0, bbk_buf, NDB_BBK_BITS, priv);
		tp_sap_udata_ind(TPSAP_T_SCH_F, 0, ndbf_buf, 2*NDB_BLK_BITS, priv);

		if (!tms->cur_burst.is_traffic)
			push_ts_content(tms, t_phy_state.time.tn-1, 1);
		else
			push_ts_content(tms, t_phy_state.time.tn-1, 4);
		break;

	case TETRA_TRAIN_NORM_3:
	case TETRA_TRAIN_EXT:
	default:
		/* uplink training sequences, should not be encountered, ignore */
		push_ts_content(tms, t_phy_state.time.tn-1, 0);
		break;
	}
}
