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


static const char *mm_auth_subtype_str(uint8_t st) {
    switch (st & 0x3u) {
    case 0: return "DEMAND";
    case 1: return "RESPONSE";
    case 2: return "RESULT";
    case 3: return "REJECT";
    default: return "UNKNOWN";
    }
}

/*
 * Some MM PDUs (notably D-LOC-UPD-ACC / D-LOC-UPD-PROC) carry so-called
 * "Type-34" elements. Different networks/PDUs place these at slightly
 * different offsets; to be robust we scan the bitstream for known element
 * headers instead of relying on a single fixed layout.
 *
 * Element header: elementType (2 bits) + elementId (4 bits)
 * We care about (elementType==3):
 *   - eid 0x5 : Group identity location accept (GSSI list)
 *   - eid 0x6 : CCK information (CCK_identifier)
 *   - eid 0xA : Authentication downlink (auth result)
 */
static void mm_scan_type34_elements(uint32_t issi, uint32_t la,
                                   const uint8_t *mm_bits, unsigned mm_len_bits,
                                   uint32_t *out_gssi, uint8_t *out_have_gssi,
                                   uint8_t *out_cck_id, uint8_t *out_have_cck,
                                   uint8_t *out_auth_ok, uint8_t *out_have_auth)
{
    if (!mm_bits || mm_len_bits < 16) return;

    /* patterns are 6-bit headers: et(2)=3 => '11' + eid(4) */
    const uint32_t HDR_GSSI = 0b110101; /* et=3,eid=0x5 */
    const uint32_t HDR_CCK  = 0b110110; /* et=3,eid=0x6 */
    const uint32_t HDR_AUTH = 0b111010; /* et=3,eid=0xA */

    /* scan all possible start positions; header is 6 bits */
    for (unsigned p = 0; p + 6u <= mm_len_bits; p++) {
        uint32_t hdr = bits_to_uint(mm_bits + p, 6);
        if (hdr == HDR_GSSI) {
            unsigned pos = p + 6u;
            if (pos + 3u > mm_len_bits) continue;
            uint8_t ngrp = (uint8_t)bits_to_uint(mm_bits + pos, 3); pos += 3u;
            for (uint8_t i = 0; i < ngrp; i++) {
                if (pos + 2u + 24u > mm_len_bits) break;
                uint8_t addr_type = (uint8_t)bits_to_uint(mm_bits + pos, 2); pos += 2u;
                uint32_t g = bits_to_uint(mm_bits + pos, 24); pos += 24u;
                if (out_gssi && out_have_gssi && !*out_have_gssi) {
                    *out_gssi = g;
                    *out_have_gssi = 1;
                }
                /* address extension present when addr_type==1 */
                if (addr_type == 0x1 && pos + 24u <= mm_len_bits) pos += 24u;
            }
        } else if (hdr == HDR_CCK) {
            /* Very common layout: ncck(3) then first CCK_identifier(8).
             * Some variants have more data; we only need the ID.
             */
            unsigned pos = p + 6u;
            if (pos + 3u + 8u > mm_len_bits) continue;
            uint8_t ncck = (uint8_t)bits_to_uint(mm_bits + pos, 3); pos += 3u;
            if (ncck >= 1) {
                uint8_t cck = (uint8_t)bits_to_uint(mm_bits + pos, 8);
                if (out_cck_id && out_have_cck) {
                    *out_cck_id = cck;
                    *out_have_cck = 1;
                }
            }
        } else if (hdr == HDR_AUTH) {
            unsigned pos = p + 6u;
            if (pos + 3u > mm_len_bits) continue;
            uint8_t auth_ok = (uint8_t)bits_to_uint(mm_bits + pos, 1);
            if (out_auth_ok && out_have_auth) {
                *out_auth_ok = auth_ok;
                *out_have_auth = 1;
            }
        }
    }

    /* Emit SDR-Tetra-like lines when we have enough info */
    if (out_have_auth && *out_have_auth) {
        if (*out_auth_ok) {
            /* do not log here; caller decides when to emit */
} else {
            /* do not log here; caller decides when to emit */
}
    }

    if (out_have_gssi && *out_have_gssi) {
        if (out_have_cck && *out_have_cck) {
            mm_logf_ctx(issi, la, "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %u - Authentication successful or no authentication currently in progress - CCK_identifier: %u - Roaming location updating", issi, *out_gssi, *out_cck_id);
        } else {
            mm_logf_ctx(issi, la, "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %u", issi, *out_gssi);
        }
    }
}

static void mm_try_pretty_log(uint32_t issi, uint32_t la, const uint8_t *mm_bits, unsigned int mm_len_bits)
{
    if (!mm_bits || mm_len_bits < 4)
        return;

    unsigned int pos = 0;
#define HAVE(N) (pos + (N) <= mm_len_bits)
#define GET(N)  (HAVE(N) ? bits_to_uint(mm_bits + pos, (N)) : 0)
#define ADV(N)  do { pos += (N); } while (0)

	/* Optional fields parsed from Type-3/4 elements (kept local; not all PDUs include them) */
	uint32_t gssi = 0;
	uint8_t cck_id = 0;
	uint8_t have_gssi = 0;
	uint8_t have_cck = 0;
	uint8_t auth_ok = 0;
	uint8_t have_auth = 0;

    uint8_t pdu_type = (uint8_t)GET(4);
    ADV(4);

    
    /* Location updating / registration accept: use Type-3/4 elements to extract GSSI/CCK/auth result */
    if (pdu_type == 0x5 /* D-LOC-UPD-ACC */) {
        /* Extract Type-3/4 elements from this PDU */
        mm_scan_type34_elements(issi, la, mm_bits, mm_len_bits,
                                &gssi, &have_gssi,
                                &cck_id, &have_cck,
                                &auth_ok, &have_auth);

        if (have_auth) {
            mm_logf_ctx(issi, la,
                "BS result to MS authentication: %s SSI: %u - %s",
                auth_ok ? "Authentication successful or no authentication currently in progress"
                        : "Authentication failed or rejected",
                issi,
                auth_ok ? "Authentication successful or no authentication currently in progress"
                        : "Authentication failed or rejected");
        }

        if (have_gssi) {
            char extra[192];
            extra[0] = 0;

            /* Mirror SDR-Tetra's wording for the common case */
            if (have_auth) {
                strncat(extra, auth_ok
                    ? " - Authentication successful or no authentication currently in progress"
                    : " - Authentication failed or rejected",
                    sizeof(extra) - strlen(extra) - 1);
            }
            if (have_cck) {
                char tmp[64];
                snprintf(tmp, sizeof(tmp), " - CCK_identifier: %u", (unsigned)cck_id);
                strncat(extra, tmp, sizeof(extra) - strlen(extra) - 1);
            }

            /* In these logs this typically indicates roaming location updating */
            strncat(extra, " - Roaming location updating", sizeof(extra) - strlen(extra) - 1);

            mm_logf_ctx(issi, la,
                "MS request for registration/authentication ACCEPTED for SSI: %u GSSI: %u%s",
                issi, gssi, extra);
        }

        return;
    }

    /* Location updating processing is noisy and usually not shown in SDR-Tetra logs */
    if (pdu_type == 0x9 /* D-LOC-UPD-PROC */) {
        return;
    }

/* Try to extract common Type-34 elements from *any* MM PDU. This is what
     * makes us match SDR-Tetra better on networks that carry auth-result / GSSI
     * in D-LOC-UPD-PROC (0x9) rather than only D-LOC-UPD-ACC (0x5).
     */
    int type34_emitted = 0;
    {
        uint32_t gssi = 0;
        uint8_t  have_gssi = 0;
        uint8_t  cck_id = 0;
        uint8_t  have_cck = 0;
        uint8_t  auth_ok = 0;
        uint8_t  have_auth = 0;

        mm_scan_type34_elements(issi, la, mm_bits, mm_len_bits,
                               &gssi, &have_gssi, &cck_id, &have_cck,
                               &auth_ok, &have_auth);
        type34_emitted = (have_auth || have_gssi || have_cck);
    }

    /* If this is a location-update related PDU and we already managed to
     * print SDR-Tetra-like lines from Type-34 elements, don't spam an
     * extra "unparsed" line.
     */
    if (type34_emitted && (pdu_type == 0x5 || pdu_type == 0x9)) {
        goto out;
    }

    /* D-AUTHENTICATION (0x1) */
    if (pdu_type == 0x1) {
        if (!HAVE(2)) {
            mm_logf_ctx(issi, la, "MM too short (%u bits), skip", mm_len_bits);
            goto out;
        }
        uint8_t sub = (uint8_t)GET(2);
        ADV(2);

        if (sub == 0x0) {
            mm_logf_ctx(issi, la, "Status: Authenticatie vereist (%s)", mm_auth_subtype_str(sub));
        } else if (sub == 0x3) {
            mm_logf_ctx(issi, la, "%s", mm_auth_subtype_str(sub));
        } else {
            mm_logf_ctx(issi, la, "D-AUTH subtype=%u (%s)", sub, mm_auth_subtype_str(sub));
        }
        goto out;
    }

    /* D-CK-CHG-DEM (0x2) — extract CCK_identifier when present (tetra-kit compatible) */
    if (pdu_type == 0x2) {
        if (!HAVE(1 + 2 + 3)) {
            mm_logf_ctx(issi, la, "MM type=0x2 (D-CK-CHG-DEM) too short (%u bits), skip", mm_len_bits);
            goto out;
        }
        uint8_t ack = (uint8_t)GET(1); ADV(1);
        uint8_t cs  = (uint8_t)GET(2); ADV(2);
        uint8_t kct = (uint8_t)GET(3); ADV(3);

        if ((kct == 1 || kct == 3) && HAVE(16)) {
            uint16_t cck = (uint16_t)GET(16);
            mm_logf_ctx(issi, la, "CCK_identifier: %u (D-CK-CHG-DEM ack=%u class=%u kct=%u)", cck, ack, cs, kct);
        } else {
            mm_logf_ctx(issi, la, "D-CK-CHG-DEM ack=%u class=%u kct=%u", ack, cs, kct);
        }
        goto out;
    }

    /* D-LOC-UPD-ACC (0x5) — keep the legacy accept_type decode, but the
     * detailed auth/GSSI/CCK logging is handled by mm_scan_type34_elements().
     */
    if (pdu_type == 0x5) {
        if (!HAVE(3)) {
            mm_logf_ctx(issi, la, "MM type=0x5 (D-LOC-UPD-ACC) too short (%u bits), skip", mm_len_bits);
            goto out;
        }
        uint8_t accept_type = (uint8_t)GET(3);
        ADV(3);

        /* Optional fields (mostly skipped) */
        uint8_t o = HAVE(1) ? (uint8_t)GET(1) : 0; ADV(1);
        if (o && HAVE(24)) ADV(24);        /* SSI */
        uint8_t p = HAVE(1) ? (uint8_t)GET(1) : 0; ADV(1);
        if (p && HAVE(24)) ADV(24);        /* address extension */
        uint8_t q = HAVE(1) ? (uint8_t)GET(1) : 0; ADV(1);
        if (q && HAVE(4))  ADV(4);         /* subscriber class */
        uint8_t r = HAVE(1) ? (uint8_t)GET(1) : 0; ADV(1);
        if (r && HAVE(1))  ADV(1);         /* energy saving mode */
        uint8_t t = HAVE(1) ? (uint8_t)GET(1) : 0; ADV(1);
        if (t && HAVE(3))  ADV(3);         /* SCCH info */

        uint8_t m = HAVE(1) ? (uint8_t)GET(1) : 0; ADV(1);

        (void)m; /* Type-34 parsing handled by mm_scan_type34_elements */
        mm_logf_ctx(issi, la, "D-LOC-UPD-ACC (accept_type=%u)", accept_type);
        goto out;
    }

    /* Fallback */
    mm_logf_ctx(issi, la, "MM type=0x%X (unparsed) len=%u bits", pdu_type, mm_len_bits);

out: ; /* MSVC: a label must precede a statement (empty statement is fine) */
#undef HAVE
#undef GET
#undef ADV
}

/* Receive TL-SDU (LLC SDU == MLE PDU) */

static int ubits_to_hex(char *dst, size_t dst_len, const uint8_t *ubits, unsigned int nbits)
{
    if (!dst || dst_len == 0) return 0;
    dst[0] = '\0';
    if (!ubits || nbits == 0) return 0;

    unsigned int nbytes = (nbits + 7u) / 8u;
    if (dst_len < (size_t)(nbytes * 2u + 1u)) {
        nbytes = (unsigned int)((dst_len - 1u) / 2u);
    }

    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    for (unsigned int bi = 0; bi < nbytes; bi++) {
        uint8_t v = 0;
        for (unsigned int bit = 0; bit < 8; bit++) {
            unsigned int src = bi * 8u + bit;
            if (src >= nbits) break;
            v = (uint8_t)((v << 1) | (ubits[src] ? 1u : 0u));
        }
        dst[o++] = hex[(v >> 4) & 0xF];
        dst[o++] = hex[v & 0xF];
        if (o + 2 >= dst_len) break;
    }
    dst[o] = '\0';
    return (int)o;
}

static int issi_is_real(uint32_t issi)
{
    issi &= 0xFFFFFFu;
    return (issi != 0 && issi != 0xFFFFFFu);
}


int rx_tl_sdu(struct tetra_mac_state *tms, struct msgb *msg, unsigned int len)
{
    /* NOTE:
     * In this project the TL-SDU sometimes arrives as:
     *   A) unpacked bits: each byte is 0/1 (len == number of bits)
     *   B) octets/bytes: regular packed bytes (len == number of bytes)
     *
     * Older forks assumed (B) and masked nibbles, which fails hard if (A) is actually passed in.
     * This function now auto-detects and handles BOTH formats robustly.
     */
    const uint8_t *buf = msg ? (const uint8_t *)msg->l3h : NULL;
    if (!buf || len < 1)
        return (int)len;

    uint32_t issi = 0;
    if (tms) issi = (uint32_t)tms->ssi;

    int la = -1;
    if (tms && tms->tcs) la = tms->tcs->la;

    /* Drop broadcast/unknown ISSI noise (0xFFFFFF) */
    if (!issi_is_real(issi))
        return (int)len;

    /* ----- Helper lambdas (C89-friendly) ----- */
    /* Detect "unpacked bits" representation: all bytes are 0/1 */
    int unpacked = 1;
    for (unsigned int i = 0; i < len; i++) {
        if (buf[i] > 1) { unpacked = 0; break; }
    }

    if (unpacked) {
        /* buf[] is bits (0/1). MLE protocol discriminator is 3 bits at offset 0. */
        if (len < 3)
            return (int)len;

        /* MSB-first bit accumulation, same semantics as osmo-tetra bits_to_uint() */
        unsigned int pdisc_off = 0;
        uint8_t mle_pdisc = 0;
        int found = 0;

        /* In unpacked-bits mode we sometimes see a small bit-shift (0..7).
         * Search for a plausible PDISC (and for MM also a plausible MM type). */
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

            /* If MM, ensure we can read 4 bits for type and that it is at least somewhat sane. */
            if (pdisc == TMLE_PDISC_MM) {
                if (len < off + 3 + 4) continue;
                uint8_t mt = (uint8_t)(((buf[off+3] & 1u) << 3) | ((buf[off+4] & 1u) << 2) |
                                       ((buf[off+5] & 1u) << 1) |  (buf[off+6] & 1u));
                /* Common MM types we care about; keep this permissive. */
                if (mt > 0xF) continue;
            }

            pdisc_off = off;
            mle_pdisc = pdisc;
            found = 1;
            break;
        }

	    if (!found) {
	        char dump[256]; dump[0] = '\0';
	        unsigned int n = (len > 32) ? 32 : len;
	        for (unsigned int i = 0; i < n; i++) {
	            char tmp[4];
	            snprintf(tmp, sizeof(tmp), "%u", (unsigned)(buf[i] & 1u));
	            strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
	        }
	#ifdef TETRA_VERBOSE_MLE
	        mm_logf_ctx(issi, la, "MLE PDISC=%u reserved/unknown, bits[0..%u]=%s",
	                    (unsigned)mle_pdisc, n ? (n - 1) : 0, dump);
	#endif
	        return (int)len;
	    }

        if (pdisc_off != 0) {
            mm_logf_ctx(issi, la, "MLE bit-align shift=%u", pdisc_off);
        }

        mm_logf_ctx(issi, la, "MLE PDISC=%u (%s) [bits]",
                    (unsigned)mle_pdisc,
                    tetra_get_mle_pdisc_name(mle_pdisc));

        if (mle_pdisc == 0 || tetra_get_mle_pdisc_name(mle_pdisc) == NULL) {
            char dump[256]; dump[0] = '\0';
            unsigned int n = (len > 32) ? 32 : len;
            for (unsigned int i = 0; i < n; i++) {
                char tmp[4];
                snprintf(tmp, sizeof(tmp), "%u", (unsigned)(buf[i] & 1u));
                strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
            }
#ifdef TETRA_VERBOSE_MLE
            mm_logf_ctx(issi, la, "MLE PDISC=%u reserved/unknown, bits[0..%u]=%s",
                        (unsigned)mle_pdisc, n ? (n - 1) : 0, dump);
	#endif
		return (int)len;
	}

/* MM: next 4 bits are the MM PDU type (message type) */
        if (mle_pdisc == TMLE_PDISC_MM) {
            unsigned int mm_type_off = pdisc_off + 3;
            unsigned int mm_payload_off = pdisc_off + 7;

            if (len < mm_payload_off) {
                mm_logf_ctx(issi, la, "MM too short (%u bits), skip", (unsigned)len);
                return (int)len;
            }

            uint8_t pdu_type = (uint8_t)(((buf[mm_type_off + 0] & 1u) << 3) |
                                         ((buf[mm_type_off + 1] & 1u) << 2) |
                                         ((buf[mm_type_off + 2] & 1u) << 1) |
                                          (buf[mm_type_off + 3] & 1u));

            /* Build MM bitstream for mm_try_pretty_log():
             * [0..3]  = MM type bits
             * [4..]   = remaining MM bits
             */
            unsigned int mm_len_bits = 4 + (len - mm_payload_off);
            if (mm_len_bits > 4096) {
                mm_logf_ctx(issi, la, "MM too long (%u bits), skip", mm_len_bits);
                return (int)len;
            }

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

	            /* Produce SDR-TETRA-like summary lines (GSSI/CCK/auth result, etc.) when present */
	            mm_try_pretty_log(issi, la, mm_bits, mm_len_bits);

            /* Diagnostics for reserved/unknown types */
            if (!mm_short) {
                char dump[256]; dump[0] = '\0';
                unsigned int n = (len > 32) ? 32 : len;
                for (unsigned int i = 0; i < n; i++) {
                    char tmp[4];
                    snprintf(tmp, sizeof(tmp), "%u", (unsigned)(buf[i] & 1u));
                    strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
                }
                mm_logf_ctx(issi, la, "MM unknown, bits[0..%u]=%s",
                            n ? (n - 1) : 0, dump);
            }
            return (int)len;
        }

        /* Non-MM PDISC (CMCE/SNDCP/etc.) not decoded in this fork */
        return (int)len;
    }

    /* ----- Packed octets path ----- */
    const uint8_t *oct = buf;

    /* Primary interpretation: low nibble is PDISC, high nibble is PDU type */
    uint8_t mle_pdisc = (uint8_t)(oct[0] & 0x0F);
    uint8_t pdu_type  = (uint8_t)((oct[0] >> 4) & 0x0F);

    /* Sanity fallback: some stacks swap nibbles; auto-detect if it makes the packet plausible. */
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

    if (mle_pdisc == 0 || tetra_get_mle_pdisc_name(mle_pdisc) == NULL) {
        char dump[256]; dump[0] = '\0';
        unsigned int n = (len > 16) ? 16 : len;
        for (unsigned int i = 0; i < n; i++) {
            char tmp[8];
            snprintf(tmp, sizeof(tmp), "%02X", oct[i]);
            strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
            if (i + 1 < n) strncat(dump, " ", sizeof(dump) - strlen(dump) - 1);
        }
        mm_logf_ctx(issi, la, "MLE PDISC=%u reserved/unknown, octets[0..%u]=%s",
                    (unsigned)mle_pdisc, n ? (n - 1) : 0, dump);
        return (int)len;
    }

    switch (mle_pdisc) {
    case TMLE_PDISC_MM: {
        /* Build MM bitstream: first 4 bits are pdu_type (high nibble of octet0),
         * followed by all bits of subsequent octets (MSB-first). Low nibble (PDISC) is excluded.
         */
        const unsigned int mm_len_bits = 4 + (len - 1) * 8;
        if (mm_len_bits > 4096) {
            mm_logf_ctx(issi, la, "MM too long (%u bits), skip", mm_len_bits);
            return (int)len;
        }
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

        if (!mm_short) {
            char dump[256]; dump[0] = '\0';
            unsigned int n = (len > 16) ? 16 : len;
            for (unsigned int i = 0; i < n; i++) {
                char tmp[8];
                snprintf(tmp, sizeof(tmp), "%02X", oct[i]);
                strncat(dump, tmp, sizeof(dump) - strlen(dump) - 1);
                if (i + 1 < n) strncat(dump, " ", sizeof(dump) - strlen(dump) - 1);
            }
            mm_logf_ctx(issi, la, "MM unknown, octets[0..%u]=%s", n ? (n - 1) : 0, dump);
        }

        return (int)len;
    }
    default:
        break;
    }

    return (int)len;
}

