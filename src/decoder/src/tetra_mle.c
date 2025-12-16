#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "tetra_mle_pdu.h"
#include "tetra_mle.h"
#include "mm_log.h"
#include "tetra_mm_pdu.h"
#include "tetra_cmce_pdu.h"
#include "tetra_sndcp_pdu.h"

/* ✅ nodig om tms->tcs->la te mogen gebruiken */
#include "crypto/tetra_crypto.h"


/* ---------- helpers ---------- */

static int issi_is_real(uint32_t issi)
{
    issi &= 0xFFFFFFu;
    return (issi != 0 && issi != 0xFFFFFFu);
}

static const char *mm_auth_subtype_str(uint8_t st) {
    switch (st & 0x3u) {
    case 0: return "DEMAND";
    case 1: return "RESPONSE";
    case 2: return "RESULT";
    case 3: return "REJECT";
    default: return "UNKNOWN";
    }
}

/* ETSI Type-3/4 element descriptor: M(1) + ID(4) + LI(11) */
static void mm_scan_type34_elements(const uint8_t *bits, unsigned int bitlen,
                                   unsigned int start_bit,
                                   uint32_t *out_gssi, uint8_t *out_have_gssi,
                                   uint32_t *out_gssi_list, uint8_t *out_gssi_count, uint8_t out_gssi_max,
                                   uint8_t *out_cck_id, uint8_t *out_have_cck,
                                   uint8_t *out_roam_lu, uint8_t *out_have_roam_lu,
                                   uint8_t *out_itsi_attach, uint8_t *out_have_itsi_attach)
{
    if (out_have_gssi) *out_have_gssi = 0;
    if (out_gssi_count) *out_gssi_count = 0;
    if (out_have_cck)  *out_have_cck  = 0;
    if (out_have_roam_lu) *out_have_roam_lu = 0;
    if (out_have_itsi_attach) *out_have_itsi_attach = 0;

    if (!bits || bitlen <= start_bit) return;

#define ADD_GSSI(_g) do { \
        uint32_t __g = (_g) & 0x00FFFFFFu; \
        if (__g != 0u && __g != 0x00FFFFFFu && out_gssi_list && out_gssi_count && out_gssi_max) { \
            uint8_t __n = *out_gssi_count; \
            uint8_t __dup = 0; \
            for (uint8_t __i = 0; __i < __n; __i++) { if (out_gssi_list[__i] == __g) { __dup = 1; break; } } \
            if (!__dup && __n < out_gssi_max) { out_gssi_list[__n++] = __g; *out_gssi_count = __n; } \
        } \
    } while (0)

    unsigned int pos = start_bit;

    while (pos + 16u <= bitlen) {
        uint32_t mbit = bits_to_uint(bits + pos, 1);
        uint32_t tid  = bits_to_uint(bits + pos + 1, 4);
        uint32_t li   = bits_to_uint(bits + pos + 5, 11);

        if (mbit != 1u || li == 0u || li > 2047u) { pos += 1; continue; }

        unsigned int elem_octets = 1u + (unsigned int)((li - 1u) / 8u);
        unsigned int elem_bits_total = 16u + elem_octets * 8u;
        if (pos + elem_bits_total > bitlen) { pos += 1; continue; }

        unsigned int unused = (elem_octets * 8u) - (unsigned int)li;
        const uint8_t *edata = bits + pos + 16u + unused;

        /* tid 0x5: Group identity location accept (can embed nested type3/4 like 0x7) */
        if (tid == 0x5 && li >= 16u) {
            mm_scan_type34_elements(edata, li, 0,
                                    out_gssi, out_have_gssi,
                                    out_gssi_list, out_gssi_count, out_gssi_max,
                                    out_cck_id, out_have_cck,
                                    out_roam_lu, out_have_roam_lu,
                                    out_itsi_attach, out_have_itsi_attach);
        }

        /* tid 0x7: Group identity downlink -> derive GSSI best-effort */
        if (tid == 0x7 && li >= 24u) {
            /* scan 32-bit windows on octet boundaries */
            unsigned int scan_start = 0;
            while (scan_start + 32u <= li) {
                if ((scan_start % 8u) == 0u) {
                    uint32_t v32 = bits_to_uint(edata + scan_start, 32);
                    ADD_GSSI(v32);

                    /* also try a 24-bit window inside the 32-bit chunk */
                    uint32_t v24 = bits_to_uint(edata + scan_start + 8u, 24);
                    ADD_GSSI(v24);
                }
                scan_start += 8u;
            }

            if (out_gssi && out_have_gssi && out_gssi_count && *out_gssi_count) {
                *out_gssi = out_gssi_list[0] & 0x00FFFFFFu;
                *out_have_gssi = 1;
            }
        }

        /* tid 0x6: CCK information (best-effort: last octet) */
        if (tid == 0x6 && li >= 8u && out_cck_id && out_have_cck) {
            uint32_t v = bits_to_uint(edata + (li - 8u), 8);
            *out_cck_id = (uint8_t)v;
            *out_have_cck = 1;
        }

        /* best-effort flags */
        if (tid == 0x2 && li >= 1u && out_roam_lu && out_have_roam_lu) {
            uint32_t v = bits_to_uint(edata + (li - 1u), 1);
            *out_roam_lu = (uint8_t)(v & 1u);
            *out_have_roam_lu = 1;
        }
        if (tid == 0x2 && li >= 2u && out_itsi_attach && out_have_itsi_attach) {
            uint32_t v = bits_to_uint(edata + (li - 2u), 1);
            *out_itsi_attach = (uint8_t)(v & 1u);
            *out_have_itsi_attach = 1;
        }

        pos += elem_bits_total;
    }

#undef ADD_GSSI
}

/* Try to find an embedded 0x5 (D-LOC-UPD-ACC) inside MM bitstream and extract type3/4 elements */
static int mm_find_and_log_loc_upd_acc(uint32_t issi, uint16_t la,
                                      const uint8_t *mm_bits, unsigned int mm_len_bits)
{
    if (!mm_bits || mm_len_bits < 8) return 0;

    /* scan for a 4-bit nibble == 0x5 in a reasonable window */
    unsigned int start = 0;
    unsigned int end = mm_len_bits;

    /* don’t scan the whole world; this is TL-SDU sized anyway */
    if (end > 512) end = 512;

    for (unsigned int p = start; p + 4 <= end; p++) {
        uint8_t t = (uint8_t)bits_to_uint(mm_bits + p, 4);
        if (t != 0x5) continue;

        /* After pdu_type(4), we expect type3/4 descriptors somewhere.
           Try scanning type3/4 from p+4. If we find any gssi/cck => log and return. */
        uint32_t gssi = 0;
        uint8_t  have_gssi = 0;
        uint32_t gssi_list[8];
        uint8_t  gssi_count = 0;
        uint8_t  cck_id = 0;
        uint8_t  have_cck = 0;
        uint8_t  roam_lu = 0;
        uint8_t  have_roam_lu = 0;
        uint8_t  itsi_attach = 0;
        uint8_t  have_itsi_attach = 0;

        mm_scan_type34_elements(mm_bits + p, mm_len_bits - p, 4,
                                &gssi, &have_gssi,
                                gssi_list, &gssi_count, (uint8_t)(sizeof(gssi_list)/sizeof(gssi_list[0])),
                                &cck_id, &have_cck,
                                &roam_lu, &have_roam_lu,
                                &itsi_attach, &have_itsi_attach);

        if (have_gssi || have_cck || have_roam_lu || have_itsi_attach) {
            char tail[192];
            tail[0] = 0;

            if (have_cck) {
                char tmp[64];
                snprintf(tmp, sizeof(tmp), " - CCK_identifier: %u", (unsigned)cck_id);
                strncat(tail, tmp, sizeof(tail) - strlen(tail) - 1);
            }
            if (have_roam_lu && roam_lu) {
                strncat(tail, " - Roaming location updating", sizeof(tail) - strlen(tail) - 1);
            } else if (have_itsi_attach && itsi_attach) {
                strncat(tail, " - ITSI attach", sizeof(tail) - strlen(tail) - 1);
            }

            if (have_gssi) {
                if (gssi_count > 1) {
                    char gbuf[128];
                    gbuf[0] = 0;
                    size_t o2 = 0;
                    for (uint8_t i = 0; i < gssi_count; i++) {
                        char tmp[24];
                        snprintf(tmp, sizeof(tmp), "%s%u", (i ? "," : ""), (unsigned)gssi_list[i]);
                        size_t tl = strlen(tmp);
                        if (o2 + tl + 1 >= sizeof(gbuf)) break;
                        memcpy(gbuf + o2, tmp, tl);
                        o2 += tl; gbuf[o2] = 0;
                    }
                    mm_logf_ctx(issi, la,
                                "MS request for registration/authentication ACCEPTED for SSI: %u GSSI(s): %s%s",
                                (unsigned)issi, gbuf, tail);
                } else {
                    mm_logf_ctx(issi, la,
                                "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %u%s",
                                (unsigned)issi, (unsigned)gssi, tail);
                }
            } else {
                mm_logf_ctx(issi, la,
                            "MS request for registration/authentication ACCEPTED for SSI: %u (no GSSI decoded)%s",
                            (unsigned)issi, tail);
            }
            return 1;
        }
    }

    return 0;
}

static void mm_try_pretty_log(uint32_t issi, uint16_t la,
                              const uint8_t *mm_bits, unsigned int mm_len_bits)
{
    if (!mm_bits || mm_len_bits < 4) return;

    unsigned int pos = 0;

#define HAVE(N) (pos + (N) <= mm_len_bits)
#define GET(N)  (HAVE(N) ? bits_to_uint(mm_bits + pos, (N)) : 0)
#define ADV(N)  do { pos += (N); } while (0)

    uint8_t pdu_type = (uint8_t)GET(4);
    ADV(4);

    /* D-AUTH (0x1): log DEMAND/RESULT best-effort */
    if (pdu_type == 0x1) {
        if (!HAVE(2)) goto out;
        uint8_t st = (uint8_t)GET(2);
        ADV(2);

        if (st == 0) {
            mm_logf_ctx(issi, la, "BS demands authentication: SSI: %u", (unsigned)issi);
            goto out;
        }

        if (st == 2) {
            /* result bit position varies a bit across implementations.
               Try a few candidate positions (next bit, or next 8..16 bits). */
            uint8_t ok = 0;
            uint8_t have_ok = 0;

            if (HAVE(1)) {
                ok = (uint8_t)GET(1);
                have_ok = 1;
            } else if (HAVE(9)) {
                ok = (uint8_t)bits_to_uint(mm_bits + pos + 8, 1);
                have_ok = 1;
            } else if (HAVE(17)) {
                ok = (uint8_t)bits_to_uint(mm_bits + pos + 16, 1);
                have_ok = 1;
            }

            if (have_ok) {
                mm_logf_ctx(issi, la,
                            "BS result to MS authentication: %s SSI: %u - %s",
                            ok ? "Authentication successful or no authentication currently in progress"
                               : "Authentication failed or rejected",
                            (unsigned)issi,
                            ok ? "Authentication successful or no authentication currently in progress"
                               : "Authentication failed or rejected");
            } else {
                mm_logf_ctx(issi, la, "D-AUTH sub-type=RESULT SSI=%u", (unsigned)issi);
            }
            goto out;
        }

        mm_logf_ctx(issi, la, "D-AUTH sub-type=%s SSI=%u",
                    mm_auth_subtype_str(st), (unsigned)issi);
        goto out;
    }

    /* D-LOC-UPD-ACC direct */
    if (pdu_type == 0x5) {
        /* just use the embedded scanner on this (it will hit quickly) */
        (void)mm_find_and_log_loc_upd_acc(issi, la, mm_bits, mm_len_bits);
        goto out;
    }

    /* If not 0x5: STILL try to find embedded 0x5 somewhere */
    (void)mm_find_and_log_loc_upd_acc(issi, la, mm_bits, mm_len_bits);

out:
#undef HAVE
#undef GET
#undef ADV
    return;
}


/* ---------- main entry ---------- */

int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len < 1)
        return (int)len;

    uint32_t issi = 0;
    if (tms) issi = (uint32_t)tms->ssi;

    int la = -1;
    if (tms && tms->tcs) la = tms->tcs->la;

    if (!issi_is_real(issi))
        return (int)len;

    /* Detect unpacked bits (0/1 per byte) */
    int unpacked = 1;
    for (unsigned int i = 0; i < len; i++) {
        if (buf[i] > 1) { unpacked = 0; break; }
    }

    if (unpacked) {
        if (len < 7) return (int)len;

        /* score-based offset picker */
        unsigned int best_off = 0;
        int best_score = -999;
        uint8_t best_pdisc = 0;
        uint8_t best_mmtype = 0;

        static const uint8_t valid_pdisc[] = { TMLE_PDISC_MM, TMLE_PDISC_CMCE, TMLE_PDISC_SNDCP };

        for (unsigned int off = 0; off < 8; off++) {
            if (len < off + 3) continue;

            uint8_t pdisc = (uint8_t)(((buf[off+0] & 1u) << 2) |
                                      ((buf[off+1] & 1u) << 1) |
                                       (buf[off+2] & 1u));

            int pdisc_ok = 0;
            for (unsigned int k = 0; k < (unsigned int)sizeof(valid_pdisc); k++) {
                if (pdisc == valid_pdisc[k]) { pdisc_ok = 1; break; }
            }
            if (!pdisc_ok) continue;

            int score = 0;
            score += 10; /* valid pdisc */

            uint8_t mmtype = 0;
            if (pdisc == TMLE_PDISC_MM && len >= off + 7) {
                mmtype = (uint8_t)(((buf[off+3] & 1u) << 3) |
                                   ((buf[off+4] & 1u) << 2) |
                                   ((buf[off+5] & 1u) << 1) |
                                    (buf[off+6] & 1u));

                /* favor common types we care about */
                if (mmtype == 0x5) score += 50;
                else if (mmtype == 0x1) score += 30;
                else if (mmtype == 0x2) score += 25;
                else if (mmtype == 0x8) score += 15;
                else score += 5;

                /* check auth subtype plausibility if D-AUTH */
                if (mmtype == 0x1 && len >= off + 9) {
                    uint8_t st = (uint8_t)(((buf[off+7] & 1u) << 1) | (buf[off+8] & 1u));
                    if (st <= 3) score += 10;
                }
            } else {
                score += 1;
            }

            if (score > best_score) {
                best_score = score;
                best_off = off;
                best_pdisc = pdisc;
                best_mmtype = mmtype;
            }
        }

        if (best_score < 0) {
            return (int)len;
        }

        if (best_off != 0) {
            mm_logf_ctx(issi, la, "MLE bit-align shift=%u", best_off);
        }

        mm_logf_ctx(issi, la, "MLE PDISC=%u (%s) [bits]",
                    (unsigned)best_pdisc,
                    tetra_get_mle_pdisc_name(best_pdisc));

        if (best_pdisc == TMLE_PDISC_MM) {
            unsigned int mm_type_off = best_off + 3;
            unsigned int mm_payload_off = best_off + 7;
            if (len < mm_payload_off) return (int)len;

            uint8_t pdu_type = (uint8_t)(((buf[mm_type_off + 0] & 1u) << 3) |
                                         ((buf[mm_type_off + 1] & 1u) << 2) |
                                         ((buf[mm_type_off + 2] & 1u) << 1) |
                                          (buf[mm_type_off + 3] & 1u));

            unsigned int mm_len_bits = 4 + (len - mm_payload_off);
            if (mm_len_bits > 4096) return (int)len;

            uint8_t mm_bits[4096];
            mm_bits[0] = (pdu_type >> 3) & 1u;
            mm_bits[1] = (pdu_type >> 2) & 1u;
            mm_bits[2] = (pdu_type >> 1) & 1u;
            mm_bits[3] = (pdu_type >> 0) & 1u;

            unsigned int o = 4;
            for (unsigned int bi = mm_payload_off; bi < len; bi++)
                mm_bits[o++] = (buf[bi] & 1u);

            const char *mm_short = tetra_get_mm_pdut_name(pdu_type, 0);
            mm_logf_ctx(issi, la, "MM type=0x%X (%s) [bits]",
                        (unsigned)pdu_type,
                        mm_short ? mm_short : "D-UNKNOWN");

            mm_try_pretty_log(issi, la, mm_bits, mm_len_bits);
            return (int)len;
        }

        return (int)len;
    }

    /* Packed octets path: keep as before (your original logic), but pretty-log now can find embedded 0x5 too. */
    const uint8_t *oct = buf;

    uint8_t mle_pdisc = (uint8_t)(oct[0] & 0x0F);
    uint8_t pdu_type  = (uint8_t)((oct[0] >> 4) & 0x0F);

    uint8_t mle_pdisc_alt = (uint8_t)((oct[0] >> 4) & 0x0F);
    uint8_t pdu_type_alt  = (uint8_t)(oct[0] & 0x0F);

    int used_alt = 0;
    if ((mle_pdisc == 0 || tetra_get_mle_pdisc_name(mle_pdisc) == NULL) &&
        (mle_pdisc_alt != 0 && tetra_get_mle_pdisc_name(mle_pdisc_alt) != NULL)) {
        mle_pdisc = mle_pdisc_alt;
        pdu_type  = pdu_type_alt;
        used_alt = 1;
    }

    mm_logf_ctx(issi, la, "MLE PDISC=%u (%s)%s [octets]",
                (unsigned)mle_pdisc,
                tetra_get_mle_pdisc_name(mle_pdisc),
                used_alt ? " [nibble-swap]" : "");

    if (mle_pdisc != TMLE_PDISC_MM) return (int)len;

    const unsigned int mm_len_bits = 4 + (len - 1) * 8;
    if (mm_len_bits > 4096) return (int)len;

    uint8_t mm_bits[4096];
    mm_bits[0] = (pdu_type >> 3) & 1u;
    mm_bits[1] = (pdu_type >> 2) & 1u;
    mm_bits[2] = (pdu_type >> 1) & 1u;
    mm_bits[3] = (pdu_type >> 0) & 1u;

    unsigned int o = 4;
    for (unsigned int bi = 1; bi < len; bi++) {
        uint8_t b = oct[bi];
        mm_bits[o++] = (b >> 7) & 1u;
        mm_bits[o++] = (b >> 6) & 1u;
        mm_bits[o++] = (b >> 5) & 1u;
        mm_bits[o++] = (b >> 4) & 1u;
        mm_bits[o++] = (b >> 3) & 1u;
        mm_bits[o++] = (b >> 2) & 1u;
        mm_bits[o++] = (b >> 1) & 1u;
        mm_bits[o++] = (b >> 0) & 1u;
    }

    const char *mm_short = tetra_get_mm_pdut_name(pdu_type, 0);
    mm_logf_ctx(issi, la, "MM type=0x%X (%s) [octets]",
                (unsigned)pdu_type,
                mm_short ? mm_short : "D-UNKNOWN");

    mm_try_pretty_log(issi, la, mm_bits, mm_len_bits);
    return (int)len;
}
